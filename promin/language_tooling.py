"""Strict, non-executing plans for explicitly selected language tools.

This module only turns existing bundled profile declarations into a bounded
argv.  It never probes, installs, or invokes a host executable.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import threading
from typing import Final, Mapping

from .canonical import digest_bytes, digest_file, digest_value
from .language_catalog import LanguageCatalog, LanguageCapabilityProfile


class LanguageToolingError(ValueError):
    """Raised when a selected language-tool action is outside its contract."""


_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[\\/]")
_SHELL_METACHARACTERS: Final = frozenset(";&|><$`%\n\r\x00^!")
_FALSE_CLAIMS: Final = {
    "acceptance_pass": False,
    "pass_credit": False,
    "product_acceptance_pass": False,
    "release_approved": False,
}
_MAX_OUTPUT_FILES: Final = 4096
_MAX_OUTPUT_BYTES: Final = 64 * 1024 * 1024
_MAX_BOUNDARY_FILES: Final = 4096
_MAX_BOUNDARY_BYTES: Final = 64 * 1024 * 1024

# Exact IDs from the bundled catalog mapped to source-owned executable basenames.
_DECLARATION_EXECUTABLES: Final[dict[str, dict[str, str]]] = {
    "c-family": {
        "clang-tidy": "clang-tidy",
        "clangd": "clangd",
        "clang-check": "clang-check",
        "include-what-you-use": "include-what-you-use",
        "cppcheck": "cppcheck",
        "clang-doc": "clang-doc",
        "doxygen-html-xml": "doxygen",
    },
    "csharp": {
        "dotnet-compiler": "dotnet",
        "roslyn-analyzers": "dotnet",
        "docfx": "docfx",
    },
    "java": {
        "javac": "javac",
        "javadoc": "javadoc",
        "checkstyle": "checkstyle",
        "spotbugs": "spotbugs",
    },
    "javascript": {
        "eslint": "eslint",
        "typescript-compiler": "tsc",
        "typedoc": "typedoc",
    },
    "python": {
        "python-compileall": "python",
        "ruff": "ruff",
        "mypy": "mypy",
        "sphinx": "sphinx-build",
    },
}

_ACTION_GRAMMARS: Final[dict[str, tuple[str, int, tuple[str, ...]]]] = {
    "clang-tidy": ("static-analysis", 1, ("src", "--")),
    "clangd": ("toolchain-info", 0, ("--version",)),
    "clang-check": ("static-analysis", 1, ("src", "--")),
    "include-what-you-use": ("static-analysis", 1, ("src", "--")),
    "cppcheck": ("static-analysis", 1, ("src",)),
    "clang-doc": ("documentation", 1, ("src",)),
    "doxygen-html-xml": ("documentation", 1, ("Doxyfile",)),
    "dotnet-compiler": ("toolchain-info", 0, ("--info",)),
    "roslyn-analyzers": ("static-analysis", 0, ("format", "analyzers", "--verify-no-changes", "--no-restore")),
    "docfx": ("documentation", 1, ("docfx.json",)),
    "javac": ("toolchain-info", 0, ("-version",)),
    "javadoc": ("documentation", 1, ("src",)),
    "checkstyle": ("static-analysis", 2, ("checkstyle.xml", "src")),
    "spotbugs": ("static-analysis", 1, ("build",)),
    "eslint": ("static-analysis", 0, ("--config", "eslint.config.js", "src")),
    "typescript-compiler": ("static-analysis", 0, ("--noEmit", "--project", "tsconfig.json")),
    "typedoc": ("documentation", 0, ("--options", "typedoc.json", "--out", "host-local-diagnostics/typedoc")),
    "python-compileall": ("static-analysis", 0, ("-B", "-m", "compileall", "-q", "src")),
    "ruff": ("static-analysis", 0, ("check", "--config", "pyproject.toml", "src")),
    "mypy": ("static-analysis", 0, ("--config-file", "pyproject.toml", "src")),
    "sphinx": ("documentation", 0, ("-W", "-b", "html", "docs", "host-local-diagnostics/sphinx-html")),
}

_REQUIRED_CONFIGURATION_PATHS: Final[dict[str, tuple[str, ...]]] = {
    "eslint": ("eslint.config.js",),
    "typescript-compiler": ("tsconfig.json",),
    "typedoc": ("typedoc.json",),
    "ruff": ("pyproject.toml",),
    "mypy": ("pyproject.toml",),
    "sphinx": ("docs/conf.py",),
}


def _profile_for_language(
    catalog: LanguageCatalog, language_id: str
) -> tuple[LanguageCapabilityProfile, str]:
    if not isinstance(catalog, LanguageCatalog):
        raise LanguageToolingError("catalog must be a loaded LanguageCatalog")
    if not isinstance(language_id, str) or not language_id.strip():
        raise LanguageToolingError("language_id must be a non-empty identifier")
    normalized = language_id.casefold().strip()
    family = {
        "c": "c-family",
        "cpp": "c-family",
        "c++": "c-family",
        "c-family": "c-family",
        "csharp": "csharp",
        "c#": "csharp",
        "jvm": "java",
        "java": "java",
        "kotlin": "java",
        "scala": "java",
        "groovy": "java",
        "javascript": "javascript",
        "js": "javascript",
        "typescript": "javascript",
        "ts": "javascript",
        "python": "python",
        "py": "python",
    }.get(normalized)
    if family is None:
        raise LanguageToolingError(f"unknown language profile: {language_id}")
    matches = tuple(profile for profile in catalog.profiles if profile.language_family == family)
    if len(matches) != 1:
        raise LanguageToolingError(f"language profile is unavailable: {language_id}")
    return matches[0], family


def _validate_argument(value: object, index: int) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise LanguageToolingError(f"argument {index} is not a bounded relative value")
    if any(character in _SHELL_METACHARACTERS for character in value):
        raise LanguageToolingError(f"argument {index} contains forbidden shell syntax")
    if value.startswith("-"):
        raise LanguageToolingError(f"argument {index} is not an input path")
    if value.startswith(("/", "\\")) or _WINDOWS_ABSOLUTE.match(value):
        raise LanguageToolingError(f"argument {index} must be relative")
    parts = value.replace("\\", "/").split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise LanguageToolingError(f"argument {index} must not contain parent paths")
    return value


def _declared_tool(profile: LanguageCapabilityProfile, family: str, tool_id: str) -> bool:
    if tool_id not in _DECLARATION_EXECUTABLES[family]:
        return False
    declared = set(profile.static_capabilities)
    declared.update(profile.documentation_primary)
    declared.update(profile.documentation_optional)
    declared.update(profile.recommended_tools)
    declared.update(profile.optional_tools)
    return tool_id in declared


def _validated_configuration_paths(root: Path, tool_id: str) -> tuple[str, ...]:
    required = _REQUIRED_CONFIGURATION_PATHS.get(tool_id, ())
    for relative in required:
        parts = relative.replace("\\", "/").split("/")
        if not relative or any(part in {"", ".", ".."} for part in parts):
            raise LanguageToolingError("configuration path is not canonical")
        candidate = root.joinpath(*parts)
        try:
            canonical = candidate.resolve(strict=True)
            root_canonical = root.resolve(strict=True)
            canonical.relative_to(root_canonical)
            state = candidate.stat(follow_symlinks=False)
        except (OSError, ValueError) as exc:
            raise LanguageToolingError("required configuration is unavailable") from exc
        cursor = root
        for part in parts:
            cursor = cursor / part
            try:
                cursor_state = cursor.stat(follow_symlinks=False)
            except OSError as exc:
                raise LanguageToolingError("required configuration is unavailable") from exc
            if _is_link_or_reparse(cursor, cursor_state):
                raise LanguageToolingError("required configuration must not be a link or reparse point")
        if _is_link_or_reparse(candidate, state) or not stat.S_ISREG(state.st_mode):
            raise LanguageToolingError("required configuration must be a regular file")
    return required


@dataclass(frozen=True, slots=True)
class LanguageToolPlan:
    language_id: str
    capability_id: str
    action_id: str
    tool_id: str
    executable: str
    argv: tuple[str, ...]
    working_directory: str
    output_roots: tuple[str, ...]
    profile_digest: str
    required_configuration_paths: tuple[str, ...] = ()

    def to_record(self) -> dict[str, object]:
        return {
            "language_id": self.language_id,
            "capability_id": self.capability_id,
            "action_id": self.action_id,
            "tool_id": self.tool_id,
            "executable": self.executable,
            "argv": list(self.argv),
            "working_directory": self.working_directory,
            "output_roots": list(self.output_roots),
            "profile_digest": self.profile_digest,
            "required_configuration_paths": list(self.required_configuration_paths),
            "claims": dict(_FALSE_CLAIMS),
            "acceptance_pass": False,
            "pass_credit": False,
            "product_acceptance_pass": False,
            "release_approved": False,
        }


@dataclass(frozen=True, slots=True)
class LanguageToolReceipt:
    status: str
    plan_digest: str
    executable_sha256: str | None
    argv: tuple[str, ...]
    started_at: str | None
    completed_at: str | None
    exit_code: int | None
    stdout_sha256: str
    stdout_size_bytes: int
    stderr_sha256: str
    stderr_size_bytes: int
    invoked: bool
    stream_cleanup_completed: bool
    output_manifest: tuple[Mapping[str, object], ...]
    failure_detail: str | None
    claims: Mapping[str, bool]

    def to_record(self) -> dict[str, object]:
        return {
            "status": self.status,
            "plan_digest": self.plan_digest,
            "executable_sha256": self.executable_sha256,
            "argv": list(self.argv),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "exit_code": self.exit_code,
            "stdout_sha256": self.stdout_sha256,
            "stdout_size_bytes": self.stdout_size_bytes,
            "stderr_sha256": self.stderr_sha256,
            "stderr_size_bytes": self.stderr_size_bytes,
            "invoked": self.invoked,
            "stream_cleanup_completed": self.stream_cleanup_completed,
            "output_manifest": [dict(entry) for entry in self.output_manifest],
            "failure_detail": self.failure_detail,
            "claims": dict(self.claims),
        }


def _receipt_claims() -> dict[str, bool]:
    return dict(_FALSE_CLAIMS)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _resolve_executable(plan: LanguageToolPlan) -> Path | None:
    candidate = Path(plan.executable)
    if not candidate.is_absolute():
        found = shutil.which(plan.executable)
        if found is None:
            return None
        candidate = Path(found)
    try:
        resolved = candidate.resolve(strict=True)
        if not resolved.is_file():
            return None
        return resolved
    except OSError:
        return None


class _BoundedStreamDrainer:
    def __init__(self, stream: object, limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self.digest = hashlib.sha256()
        self.size = 0
        self.data = bytearray()
        self.overflow = False

    def drain(self) -> None:
        while True:
            chunk = self._stream.read(8192)
            if not chunk:
                return
            self.digest.update(chunk)
            self.size += len(chunk)
            if len(self.data) <= self._limit:
                remaining = self._limit + 1 - len(self.data)
                self.data.extend(chunk[:remaining])
            if self.size > self._limit:
                self.overflow = True

    def close(self) -> None:
        self._stream.close()


def probe_language_tool(
    plan: LanguageToolPlan,
    *,
    timeout_seconds: int,
    output_limit_bytes: int = 65_536,
) -> LanguageToolReceipt:
    """Invoke exactly one planned executable and return fail-closed identity evidence."""

    if not isinstance(plan, LanguageToolPlan):
        raise LanguageToolingError("plan must be a LanguageToolPlan")
    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
        raise LanguageToolingError("timeout_seconds must be a positive integer")
    if not isinstance(output_limit_bytes, int) or isinstance(output_limit_bytes, bool) or output_limit_bytes <= 0:
        raise LanguageToolingError("output_limit_bytes must be a positive integer")
    plan_digest = digest_value(plan.to_record())
    empty_digest = digest_bytes(b"")
    executable = _resolve_executable(plan)
    base = {
        "plan_digest": plan_digest,
        "executable_sha256": None,
        "argv": plan.argv,
        "started_at": None,
        "completed_at": None,
        "exit_code": None,
        "stdout_sha256": empty_digest,
        "stdout_size_bytes": 0,
        "stderr_sha256": empty_digest,
        "stderr_size_bytes": 0,
        "invoked": False,
        "stream_cleanup_completed": True,
        "output_manifest": (),
        "failure_detail": None,
        "claims": _receipt_claims(),
    }
    if executable is None:
        return LanguageToolReceipt(status="UNAVAILABLE", **base)
    argv_executable = _resolve_executable(
        LanguageToolPlan(
            language_id=plan.language_id, capability_id=plan.capability_id,
            action_id=plan.action_id, tool_id=plan.tool_id,
            executable=plan.argv[0] if plan.argv else "", argv=plan.argv,
            working_directory=plan.working_directory,
            output_roots=plan.output_roots, profile_digest=plan.profile_digest,
            required_configuration_paths=plan.required_configuration_paths,
        )
    ) if plan.argv else None
    if argv_executable is None or argv_executable != executable:
        return LanguageToolReceipt(status="FAILED", **base)
    try:
        before = digest_file(executable)
        working_directory = Path(plan.working_directory).resolve(strict=True)
        if not working_directory.is_dir():
            return LanguageToolReceipt(status="FAILED", **base)
    except OSError:
        return LanguageToolReceipt(status="UNAVAILABLE", **base)
    base["executable_sha256"] = before
    base["started_at"] = _timestamp()
    base["invoked"] = True
    environment = {"PATH": os.environ.get("PATH", "")}
    if os.name == "nt" and os.environ.get("SystemRoot"):
        environment["SystemRoot"] = os.environ["SystemRoot"]
    process = None
    stdout_capture = None
    stderr_capture = None
    status = "FAILED"
    try:
        invocation_argv = (str(executable), *plan.argv[1:])
        process = subprocess.Popen(
            list(invocation_argv),
            cwd=str(working_directory),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        stdout_capture = _BoundedStreamDrainer(process.stdout, output_limit_bytes)
        stderr_capture = _BoundedStreamDrainer(process.stderr, output_limit_bytes)
        stdout_thread = threading.Thread(target=stdout_capture.drain, daemon=True)
        stderr_thread = threading.Thread(target=stderr_capture.drain, daemon=True)
        stdout_thread.start(); stderr_thread.start()
        try:
            base["exit_code"] = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            status = "TIMED_OUT"
            process.kill()
            base["exit_code"] = None
            for capture in (stdout_capture, stderr_capture):
                try:
                    capture.close()
                except OSError:
                    pass
        join_timeout = 0.05 if status == "TIMED_OUT" else 0.25
        stdout_thread.join(timeout=join_timeout); stderr_thread.join(timeout=join_timeout)
        base["stream_cleanup_completed"] = not stdout_thread.is_alive() and not stderr_thread.is_alive()
        if status == "TIMED_OUT":
            try:
                process.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                base["failure_detail"] = "process_reap_timeout"
                base["stream_cleanup_completed"] = False
            else:
                base["stream_cleanup_completed"] = base["stream_cleanup_completed"] and process.returncode is not None
        base["stdout_sha256"] = stdout_capture.digest.hexdigest()
        base["stdout_size_bytes"] = stdout_capture.size
        base["stderr_sha256"] = stderr_capture.digest.hexdigest()
        base["stderr_size_bytes"] = stderr_capture.size
        if status != "TIMED_OUT":
            status = "AVAILABLE" if base["exit_code"] == 0 and not stdout_capture.overflow and not stderr_capture.overflow else "FAILED"
        elif base["failure_detail"] == "process_reap_timeout":
            status = "FAILED"
    except (OSError, ValueError):
        status = "FAILED"
    finally:
        if process is not None and base["exit_code"] is None:
            for capture in (stdout_capture, stderr_capture):
                if capture is not None:
                    try:
                        capture.close()
                    except OSError:
                        pass
        if process is not None and stdout_capture is not None and stderr_capture is not None:
            base["stream_cleanup_completed"] = base["stream_cleanup_completed"] and True
        if process is not None and base["exit_code"] is None:
            try:
                base["exit_code"] = process.poll()
            except OSError:
                pass
        try:
            after = digest_file(executable)
        except OSError:
            after = None
        if after != before:
            status = "FAILED"
        base["completed_at"] = _timestamp()
    return LanguageToolReceipt(status=status, **base)


def _is_link_or_reparse(path: Path, inspected: os.stat_result | None = None) -> bool:
    if path.is_symlink():
        return True
    try:
        state = inspected or path.stat(follow_symlinks=False)
    except OSError:
        return False
    attributes = getattr(state, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    return bool(attributes & reparse_flag)


def _host_path_guard_available() -> bool:
    """Whether stdlib descriptors can provide no-follow directory traversal."""
    return hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")


def _validated_output_roots(plan: LanguageToolPlan) -> tuple[Path, ...]:
    try:
        root = Path(plan.working_directory).resolve(strict=True)
        root_state = root.stat(follow_symlinks=False)
    except OSError as exc:
        raise LanguageToolingError("working directory is not canonical") from exc
    if _is_link_or_reparse(root, root_state) or not stat.S_ISDIR(root_state.st_mode):
        raise LanguageToolingError("working directory must not be a link or reparse point")
    if not isinstance(plan.output_roots, tuple) or not plan.output_roots:
        raise LanguageToolingError("output roots must be a non-empty tuple")
    result: list[Path] = []
    seen: set[str] = set()
    for index, value in enumerate(plan.output_roots):
        if not isinstance(value, str) or not value:
            raise LanguageToolingError(f"output root {index} must be non-empty")
        if value.startswith(("/", "\\")) or _WINDOWS_ABSOLUTE.match(value):
            raise LanguageToolingError(f"output root {index} must be relative")
        parts = value.replace("\\", "/").split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise LanguageToolingError(f"output root {index} must be canonical")
        candidate = root.joinpath(*parts)
        try:
            canonical = candidate.resolve(strict=False)
        except OSError as exc:
            raise LanguageToolingError(f"output root {index} is not canonical") from exc
        try:
            canonical.relative_to(root)
        except ValueError as exc:
            raise LanguageToolingError(f"output root {index} escapes project root") from exc
        cursor = root
        for part in parts:
            cursor = cursor / part
            if os.path.lexists(cursor):
                try:
                    state = cursor.stat(follow_symlinks=False)
                except OSError as exc:
                    raise LanguageToolingError(f"output root {index} cannot be inspected") from exc
                if _is_link_or_reparse(cursor, state):
                    raise LanguageToolingError(f"output root {index} contains a link or reparse point")
        key = str(canonical).casefold()
        if key in seen or any(
            key.startswith(existing + os.sep) or existing.startswith(key + os.sep)
            for existing in seen
        ):
            raise LanguageToolingError("output root path collision or overlap")
        seen.add(key)
        result.append(canonical)
    return tuple(result)


def _collect_output_manifest(plan: LanguageToolPlan, roots: tuple[Path, ...]) -> tuple[Mapping[str, object], ...]:
    root_path = Path(plan.working_directory).resolve(strict=True)
    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    total_bytes = 0
    def identity(state: os.stat_result) -> tuple[int, int]:
        return (state.st_dev, state.st_ino)

    def open_checked(path: Path, expected: os.stat_result, *, directory: bool) -> int:
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_DIRECTORY") and directory:
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
            actual = os.fstat(descriptor)
        except OSError as exc:
            raise LanguageToolingError("output cannot be opened safely") from exc
        if _is_link_or_reparse(path) or identity(actual) != identity(expected):
            os.close(descriptor)
            raise LanguageToolingError("output changed during safe open")
        return descriptor

    def walk(directory: Path, declared: str) -> None:
        nonlocal total_bytes
        before = directory.stat(follow_symlinks=False)
        descriptor = open_checked(directory, before, directory=True)
        try:
            current = directory.stat(follow_symlinks=False)
            if descriptor >= 0 and identity(current) != identity(os.fstat(descriptor)):
                raise LanguageToolingError("output directory changed before scan")
            try:
                children = sorted(os.scandir(directory), key=lambda entry: entry.name.encode("utf-8"))
            except OSError as exc:
                raise LanguageToolingError("output root cannot be enumerated") from exc
            for entry in children:
                child = Path(entry.path)
                try:
                    child_state = child.stat(follow_symlinks=False)
                except OSError as exc:
                    raise LanguageToolingError("output entry cannot be inspected") from exc
                if _is_link_or_reparse(child, child_state):
                    raise LanguageToolingError("output contains a link or reparse point")
                if stat.S_ISDIR(child_state.st_mode):
                    walk(child, declared)
                    continue
                if not stat.S_ISREG(child_state.st_mode):
                    raise LanguageToolingError("output contains a nonregular entry")
                relative = child.relative_to(root_path).as_posix()
                collision_key = relative.casefold()
                if collision_key in seen:
                    raise LanguageToolingError("output path collision")
                seen.add(collision_key)
                if len(entries) >= _MAX_OUTPUT_FILES:
                    raise LanguageToolingError("output file count exceeds bound")
                file_descriptor = open_checked(child, child_state, directory=False)
                try:
                    chunks: list[bytes] = []
                    while True:
                        chunk = os.read(file_descriptor, 1024 * 1024)
                        if not chunk:
                            break
                        chunks.append(chunk)
                    payload = b"".join(chunks)
                    after = child.stat(follow_symlinks=False)
                    if identity(after) != identity(os.fstat(file_descriptor)):
                        raise LanguageToolingError("output file changed during read")
                except OSError as exc:
                    raise LanguageToolingError("output file cannot be read safely") from exc
                finally:
                    os.close(file_descriptor)
                total_bytes += len(payload)
                if total_bytes > _MAX_OUTPUT_BYTES:
                    raise LanguageToolingError("output byte budget exceeded")
                entries.append({"path": relative, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
            after_directory = directory.stat(follow_symlinks=False)
            if descriptor >= 0 and identity(after_directory) != identity(os.fstat(descriptor)):
                raise LanguageToolingError("output directory changed during scan")
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    for declared, directory in zip(plan.output_roots, roots):
        if not os.path.lexists(directory):
            continue
        state = directory.stat(follow_symlinks=False)
        if _is_link_or_reparse(directory, state) or not stat.S_ISDIR(state.st_mode):
            raise LanguageToolingError("output root is not a regular directory")
        walk(directory, declared)
    entries.sort(key=lambda item: str(item["path"]).encode("utf-8"))
    return tuple(entries)


def _snapshot_project_boundary(root: Path, output_roots: tuple[Path, ...]) -> dict[str, tuple[int, str]]:
    snapshot: dict[str, tuple[int, str]] = {}
    total_bytes = 0
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(directories, key=lambda value: value.encode("utf-8"))
        files[:] = sorted(files, key=lambda value: value.encode("utf-8"))
        kept_directories: list[str] = []
        for name in directories:
            candidate = current_path / name
            if any(candidate == output or output in candidate.parents for output in output_roots):
                continue
            state = candidate.stat(follow_symlinks=False)
            if _is_link_or_reparse(candidate, state):
                raise LanguageToolingError("boundary snapshot contains a link or reparse point")
            kept_directories.append(name)
        directories[:] = kept_directories
        for name in files:
            candidate = current_path / name
            state = candidate.stat(follow_symlinks=False)
            if _is_link_or_reparse(candidate, state) or not stat.S_ISREG(state.st_mode):
                raise LanguageToolingError("boundary snapshot contains an unsafe entry")
            total_bytes += state.st_size
            if len(snapshot) >= _MAX_BOUNDARY_FILES or total_bytes > _MAX_BOUNDARY_BYTES:
                raise LanguageToolingError("boundary snapshot exceeds bounded limits")
            payload = candidate.read_bytes()
            snapshot[candidate.relative_to(root).as_posix()] = (len(payload), hashlib.sha256(payload).hexdigest())
    return snapshot


def _boundary_changed(before: dict[str, tuple[int, str]], after: dict[str, tuple[int, str]]) -> bool:
    return before != after


def run_language_tool(
    plan: LanguageToolPlan,
    *,
    timeout_seconds: int,
    output_limit_bytes: int = 65_536,
) -> LanguageToolReceipt:
    """Run a planned tool and collect only its declared, bounded outputs."""

    if not isinstance(plan, LanguageToolPlan):
        raise LanguageToolingError("plan must be a LanguageToolPlan")
    if not isinstance(timeout_seconds, int) or isinstance(timeout_seconds, bool) or timeout_seconds <= 0:
        raise LanguageToolingError("timeout_seconds must be a positive integer")
    if not isinstance(output_limit_bytes, int) or isinstance(output_limit_bytes, bool) or output_limit_bytes <= 0:
        raise LanguageToolingError("output_limit_bytes must be a positive integer")
    roots = _validated_output_roots(plan)
    project_root = Path(plan.working_directory).resolve(strict=True)
    before_boundary = _snapshot_project_boundary(project_root, roots)
    if not _host_path_guard_available():
        empty_digest = digest_bytes(b"")
        return LanguageToolReceipt(
            status="UNAVAILABLE_HOST_PATH_GUARD",
            plan_digest=digest_value(plan.to_record()),
            executable_sha256=None,
            argv=plan.argv,
            started_at=None,
            completed_at=None,
            exit_code=None,
            stdout_sha256=empty_digest,
            stdout_size_bytes=0,
            stderr_sha256=empty_digest,
            stderr_size_bytes=0,
            invoked=False,
            stream_cleanup_completed=True,
            output_manifest=(),
            failure_detail="host_path_guard_unavailable",
            claims=_receipt_claims(),
        )
    receipt = probe_language_tool(
        plan, timeout_seconds=timeout_seconds, output_limit_bytes=output_limit_bytes
    )
    if receipt.invoked and receipt.exit_code is not None and receipt.status != "TIMED_OUT":
        try:
            manifest = _collect_output_manifest(plan, roots)
            after_boundary = _snapshot_project_boundary(project_root, roots)
            if _boundary_changed(before_boundary, after_boundary):
                return replace(receipt, status="FAILED", output_manifest=(), failure_detail="project_mutation_outside_declared_roots")
        except LanguageToolingError:
            return replace(receipt, status="FAILED", output_manifest=(), failure_detail="output_collection_failed")
        return replace(receipt, output_manifest=manifest)
    return receipt


def plan_language_tool(
    catalog: LanguageCatalog,
    *,
    language_id: str,
    tool_id: str,
    action_id: str,
    root: Path,
    arguments: tuple[str, ...] = (),
) -> LanguageToolPlan:
    """Create a deterministic, allow-listed tool plan without execution."""

    profile, family = _profile_for_language(catalog, language_id)
    if not isinstance(tool_id, str) or tool_id not in _DECLARATION_EXECUTABLES[family]:
        raise LanguageToolingError(f"tool is not declared by selected profile: {tool_id}")
    if not _declared_tool(profile, family, tool_id):
        raise LanguageToolingError(f"tool is not declared by selected profile: {tool_id}")
    expected_action, argument_count, defaults = _ACTION_GRAMMARS[tool_id]
    if action_id != expected_action:
        raise LanguageToolingError(
            f"action {action_id!r} is not permitted for tool {tool_id}"
        )
    if not isinstance(root, Path):
        raise LanguageToolingError("root must be a pathlib.Path")
    root_path = root.resolve()
    if not root_path.is_dir():
        raise LanguageToolingError("root must be an existing directory")
    if not isinstance(arguments, tuple):
        raise LanguageToolingError("arguments must be a tuple")
    if len(arguments) > argument_count:
        raise LanguageToolingError("argument count exceeds the fixed action grammar")
    checked = tuple(_validate_argument(value, index) for index, value in enumerate(arguments))
    if argument_count == 0 and checked:
        raise LanguageToolingError("tool action does not accept arguments")
    action_arguments = checked + defaults[len(checked) :]
    executable = _DECLARATION_EXECUTABLES[family][tool_id]
    required_configuration_paths = _validated_configuration_paths(root_path, tool_id)
    artifact = profile.artifact_policy
    output_roots = tuple(
        str(artifact[key])
        for key in ("diagnosticRoot", "forensicRoot")
        if isinstance(artifact.get(key), str) and artifact[key]
    )
    if tool_id == "typedoc":
        output_roots = ("host-local-diagnostics/typedoc", "host-local-forensics")
    elif tool_id == "sphinx":
        output_roots = ("host-local-diagnostics/sphinx-html", "host-local-forensics")
    return LanguageToolPlan(
        language_id=family,
        capability_id=tool_id,
        action_id=action_id,
        tool_id=tool_id,
        executable=executable,
        argv=(executable, *action_arguments),
        working_directory=str(root_path),
        output_roots=output_roots,
        profile_digest=profile.profile_digest,
        required_configuration_paths=required_configuration_paths,
    )


__all__ = [
    "LanguageToolPlan", "LanguageToolReceipt", "LanguageToolingError",
    "plan_language_tool", "probe_language_tool",
    "run_language_tool",
]
