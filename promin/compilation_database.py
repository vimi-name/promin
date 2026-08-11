"""Read-only validation of a canonical C/C++ compilation database.

The validator deliberately consumes an existing database.  It never runs CMake,
compilers, clangd, clang-tidy, or a provider, so an absent database is reported
as ``UNAVAILABLE`` rather than replaced with guessed command lines.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shlex
import stat
from typing import Any, Mapping, Sequence

from .language_analysis import GateStatus


class CompilationDatabaseError(ValueError):
    """Raised when a caller attempts semantic tooling without a valid CompDB."""


@dataclass(frozen=True)
class CompilationCommand:
    source_path: str
    source_sha256: str
    directory: str
    driver_identity: str
    arguments: tuple[str, ...]
    digest: str


@dataclass(frozen=True)
class CompilationDatabaseReport:
    status: GateStatus
    database_path: str
    digest: str | None
    commands: tuple[CompilationCommand, ...]
    errors: tuple[str, ...]
    duplicate_rows_collapsed: int = 0
    pass_credit: bool = False
    acceptance_pass: bool = False
    product_acceptance_pass: bool = False
    database_bytes: int | None = None
    row_count: int = 0
    max_database_bytes: int | None = None
    max_rows: int | None = None
    allowed_source_extensions: tuple[str, ...] = ()

    @property
    def command_count(self) -> int:
        return len(self.commands)

    @property
    def source_paths(self) -> tuple[str, ...]:
        return tuple(command.source_path for command in self.commands)


_ROW_KEYS = frozenset({"directory", "file", "command", "arguments", "output"})


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.stat(follow_symlinks=False).st_mode) and not path.is_symlink()
    except OSError:
        return False


def _optional_positive_limit(value: int | None, label: str) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise CompilationDatabaseError(f"{label} must be a positive integer or None")
    return value


def _normalized_source_extensions(value: Sequence[str] | None) -> frozenset[str] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes)) or not value:
        raise CompilationDatabaseError("allowed_source_extensions must be a non-empty extension sequence or None")
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.startswith(".") or len(item) == 1 or "/" in item or "\\" in item:
            raise CompilationDatabaseError("allowed_source_extensions contains an invalid extension")
        normalized.append(item.casefold())
    if len(normalized) != len(set(normalized)):
        raise CompilationDatabaseError("allowed_source_extensions contains duplicate extensions")
    return frozenset(normalized)


def _resolve_directory(value: Any, root: Path) -> Path:
    if not isinstance(value, str) or not value:
        raise CompilationDatabaseError("compilation database row directory must be a non-empty string")
    raw = Path(value)
    candidate = raw if raw.is_absolute() else root / raw
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise CompilationDatabaseError("compilation database row directory is unavailable") from exc
    if not resolved.is_dir():
        raise CompilationDatabaseError("compilation database row directory is not a directory")
    return resolved


def _source_identity(
    value: Any,
    directory: Path,
    root: Path,
    allowed_source_extensions: frozenset[str] | None,
) -> tuple[Path, str, str]:
    if not isinstance(value, str) or not value:
        raise CompilationDatabaseError("compilation database row file must be a non-empty string")
    raw = Path(value)
    candidate = raw if raw.is_absolute() else directory / raw
    try:
        source = candidate.resolve(strict=True)
    except OSError as exc:
        raise CompilationDatabaseError("compilation database source is unavailable") from exc
    if not _is_regular_file(source):
        raise CompilationDatabaseError("compilation database source must be a physical regular file")
    try:
        relative = source.relative_to(root).as_posix()
    except ValueError as exc:
        raise CompilationDatabaseError("compilation database source is outside project root") from exc
    if not relative or relative.startswith("../"):
        raise CompilationDatabaseError("compilation database source has an invalid canonical identity")
    if allowed_source_extensions is not None and source.suffix.casefold() not in allowed_source_extensions:
        raise CompilationDatabaseError("compilation database source extension is not selected for this analysis")
    return source, relative, _sha256_file(source)


def _arguments_from_row(row: Mapping[str, Any]) -> tuple[str, ...]:
    has_command = "command" in row
    has_arguments = "arguments" in row
    if has_command == has_arguments:
        raise CompilationDatabaseError("compilation database row must contain exactly one of command or arguments")
    if has_arguments:
        values = row["arguments"]
        if not isinstance(values, list) or not values or any(not isinstance(item, str) or not item for item in values):
            raise CompilationDatabaseError("compilation database arguments must be a non-empty string array")
        return tuple(values)
    command = row["command"]
    if not isinstance(command, str) or not command.strip():
        raise CompilationDatabaseError("compilation database command must be a non-empty string")
    try:
        values = shlex.split(command, posix=True)
    except ValueError as exc:
        raise CompilationDatabaseError("compilation database command cannot be parsed") from exc
    if not values:
        raise CompilationDatabaseError("compilation database command has no driver")
    return tuple(values)


def _driver_identity(arguments: Sequence[str]) -> str:
    driver = arguments[0]
    if not driver or driver.startswith("-") or driver.startswith("/") and len(driver) == 2:
        raise CompilationDatabaseError("compilation database driver identity is invalid")
    candidate = Path(driver)
    if candidate.is_absolute():
        if not _is_regular_file(candidate):
            raise CompilationDatabaseError("compilation database absolute driver is not a physical regular file")
        identity: dict[str, str] = {"kind": "physical-driver", "path": str(candidate.resolve()), "sha256": _sha256_file(candidate)}
    else:
        if "/" in driver or "\\" in driver:
            raise CompilationDatabaseError("relative compilation database driver is ambiguous")
        identity = {"kind": "driver-token", "token": driver.casefold()}
    return hashlib.sha256(_canonical_bytes(identity)).hexdigest()


def _has_compile_intent(arguments: Sequence[str]) -> bool:
    return any(argument.casefold() in {"-c", "/c"} for argument in arguments[1:])


def _argument_names_source(arguments: Sequence[str], source: Path, directory: Path, root: Path) -> bool:
    for argument in arguments[1:]:
        if not argument or argument.startswith("-") or argument.startswith("/") and len(argument) <= 3:
            continue
        candidate = Path(argument)
        if not candidate.is_absolute():
            candidate = directory / candidate
        try:
            if candidate.resolve(strict=False) == source:
                return True
        except OSError:
            continue
        try:
            # Root-relative source spelling is common for out-of-tree build dirs.
            if (root / argument).resolve(strict=False) == source:
                return True
        except OSError:
            continue
    return False


def _canonical_argument(argument: str, source: Path, directory: Path, root: Path) -> str:
    """Normalize only a physical spelling of this row's source file."""

    if argument.startswith("-") or argument.startswith("/") and len(argument) <= 3:
        return argument
    candidate = Path(argument)
    candidates = [candidate] if candidate.is_absolute() else [directory / candidate, root / candidate]
    for item in candidates:
        try:
            if item.resolve(strict=False) == source:
                return "@source"
        except OSError:
            continue
    return argument


def _row_command(
    row: Any,
    root: Path,
    allowed_source_extensions: frozenset[str] | None,
) -> CompilationCommand:
    if not isinstance(row, Mapping):
        raise CompilationDatabaseError("compilation database row must be an object")
    unknown = set(row) - _ROW_KEYS
    if unknown:
        raise CompilationDatabaseError(f"compilation database row contains unknown fields: {sorted(unknown)}")
    if "directory" not in row or "file" not in row:
        raise CompilationDatabaseError("compilation database row requires directory and file")
    directory = _resolve_directory(row["directory"], root)
    source, source_path, source_sha256 = _source_identity(
        row["file"], directory, root, allowed_source_extensions
    )
    arguments = _arguments_from_row(row)
    driver_identity = _driver_identity(arguments)
    if not _has_compile_intent(arguments):
        raise CompilationDatabaseError("compilation database row lacks compile intent")
    if not _argument_names_source(arguments, source, directory, root):
        raise CompilationDatabaseError("compilation database row does not name its source identity")
    canonical_arguments = tuple(_canonical_argument(item, source, directory, root) for item in arguments)
    identity = {
        "source_path": source_path,
        "source_sha256": source_sha256,
        "directory": str(directory),
        "driver_identity": driver_identity,
        "arguments": canonical_arguments,
    }
    return CompilationCommand(
        source_path=source_path,
        source_sha256=source_sha256,
        directory=str(directory),
        driver_identity=driver_identity,
        arguments=canonical_arguments,
        digest=hashlib.sha256(_canonical_bytes(identity)).hexdigest(),
    )


def verify_compilation_database(
    database_path: Path | str,
    project_root: Path | str,
    *,
    max_database_bytes: int | None = None,
    max_rows: int | None = None,
    allowed_source_extensions: Sequence[str] | None = None,
) -> CompilationDatabaseReport:
    """Validate a CompDB without falling back to handwritten compiler commands.

    Optional size and row bounds are caller-owned analysis budgets.  Exceeding
    one leaves the database ``UNAVAILABLE`` to this bounded run rather than
    silently processing a partial input or constructing a guessed command.
    """

    byte_limit = _optional_positive_limit(max_database_bytes, "max_database_bytes")
    row_limit = _optional_positive_limit(max_rows, "max_rows")
    extensions = _normalized_source_extensions(allowed_source_extensions)
    rendered_extensions = () if extensions is None else tuple(sorted(extensions))
    path = Path(database_path)
    root = Path(project_root)
    try:
        root = root.resolve(strict=True)
    except OSError:
        return CompilationDatabaseReport(
            status=GateStatus.FAIL,
            database_path=str(path),
            digest=None,
            commands=(),
            errors=("project root is unavailable",),
            max_database_bytes=byte_limit,
            max_rows=row_limit,
            allowed_source_extensions=rendered_extensions,
        )
    if not root.is_dir():
        return CompilationDatabaseReport(
            status=GateStatus.FAIL,
            database_path=str(path),
            digest=None,
            commands=(),
            errors=("project root is not a directory",),
            max_database_bytes=byte_limit,
            max_rows=row_limit,
            allowed_source_extensions=rendered_extensions,
        )
    if not path.exists():
        return CompilationDatabaseReport(
            status=GateStatus.UNAVAILABLE,
            database_path=str(path),
            digest=None,
            commands=(),
            errors=("canonical compilation database is absent",),
            max_database_bytes=byte_limit,
            max_rows=row_limit,
            allowed_source_extensions=rendered_extensions,
        )
    if not _is_regular_file(path):
        return CompilationDatabaseReport(
            status=GateStatus.FAIL,
            database_path=str(path),
            digest=None,
            commands=(),
            errors=("canonical compilation database must be a physical regular file",),
            max_database_bytes=byte_limit,
            max_rows=row_limit,
            allowed_source_extensions=rendered_extensions,
        )
    try:
        database_bytes = path.stat(follow_symlinks=False).st_size
    except OSError as exc:
        return CompilationDatabaseReport(
            status=GateStatus.FAIL,
            database_path=str(path),
            digest=None,
            commands=(),
            errors=(f"canonical compilation database cannot be statted: {exc}",),
            max_database_bytes=byte_limit,
            max_rows=row_limit,
            allowed_source_extensions=rendered_extensions,
        )
    if byte_limit is not None and database_bytes > byte_limit:
        return CompilationDatabaseReport(
            status=GateStatus.UNAVAILABLE,
            database_path=str(path),
            digest=None,
            commands=(),
            errors=("canonical compilation database exceeds the caller-supplied byte bound",),
            database_bytes=database_bytes,
            max_database_bytes=byte_limit,
            max_rows=row_limit,
            allowed_source_extensions=rendered_extensions,
        )
    try:
        raw_bytes = path.read_bytes()
        rows = json.loads(raw_bytes.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return CompilationDatabaseReport(
            status=GateStatus.FAIL,
            database_path=str(path),
            digest=None,
            commands=(),
            errors=(f"canonical compilation database is invalid JSON: {exc}",),
            database_bytes=database_bytes,
            max_database_bytes=byte_limit,
            max_rows=row_limit,
            allowed_source_extensions=rendered_extensions,
        )
    actual_database_bytes = len(raw_bytes)
    digest = hashlib.sha256(raw_bytes).hexdigest()
    if byte_limit is not None and actual_database_bytes > byte_limit:
        return CompilationDatabaseReport(
            status=GateStatus.UNAVAILABLE,
            database_path=str(path),
            digest=digest,
            commands=(),
            errors=("canonical compilation database exceeds the caller-supplied byte bound while reading",),
            database_bytes=actual_database_bytes,
            max_database_bytes=byte_limit,
            max_rows=row_limit,
            allowed_source_extensions=rendered_extensions,
        )
    if not isinstance(rows, list) or not rows:
        return CompilationDatabaseReport(
            status=GateStatus.FAIL,
            database_path=str(path),
            digest=digest,
            commands=(),
            errors=("canonical compilation database must be a non-empty array",),
            database_bytes=actual_database_bytes,
            row_count=len(rows) if isinstance(rows, list) else 0,
            max_database_bytes=byte_limit,
            max_rows=row_limit,
            allowed_source_extensions=rendered_extensions,
        )
    if row_limit is not None and len(rows) > row_limit:
        return CompilationDatabaseReport(
            status=GateStatus.UNAVAILABLE,
            database_path=str(path),
            digest=digest,
            commands=(),
            errors=("canonical compilation database exceeds the caller-supplied row bound",),
            database_bytes=actual_database_bytes,
            row_count=len(rows),
            max_database_bytes=byte_limit,
            max_rows=row_limit,
            allowed_source_extensions=rendered_extensions,
        )

    errors: list[str] = []
    grouped: dict[str, CompilationCommand] = {}
    duplicates = 0
    for index, row in enumerate(rows):
        try:
            command = _row_command(row, root, extensions)
        except CompilationDatabaseError as exc:
            errors.append(f"row {index}: {exc}")
            continue
        previous = grouped.get(command.source_path)
        if previous is None:
            grouped[command.source_path] = command
        elif previous.digest == command.digest:
            duplicates += 1
        else:
            errors.append(f"row {index}: conflicting commands for source identity {command.source_path}")
    commands = tuple(grouped[path] for path in sorted(grouped))
    return CompilationDatabaseReport(
        status=GateStatus.FAIL if errors else GateStatus.PASS,
        database_path=str(path),
        digest=digest,
        commands=commands,
        errors=tuple(errors),
        duplicate_rows_collapsed=duplicates,
        database_bytes=actual_database_bytes,
        row_count=len(rows),
        max_database_bytes=byte_limit,
        max_rows=row_limit,
        allowed_source_extensions=rendered_extensions,
    )


def ensure_semantic_tool_precondition(
    report: CompilationDatabaseReport,
    tool_name: str,
) -> None:
    """Fail closed before any compiler-aware tool is selected."""

    if not isinstance(tool_name, str) or not tool_name:
        raise CompilationDatabaseError("semantic tool name must be non-empty")
    if report.status is not GateStatus.PASS or report.digest is None or not report.commands:
        raise CompilationDatabaseError(
            f"{tool_name} requires a PASS canonical compilation database; observed {report.status.value}"
        )
