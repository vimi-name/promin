"""Deterministic, bounded static inspection of an arbitrary product tree.

The inspector is deliberately API-only: it does not configure, build, launch,
or mutate the inspected product.  It emits relative-path facts and bounded
lexical candidates for a client summary and a richer machine report.  Neither
surface is acceptance, runtime, release, or pass-credit evidence.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Final
import unicodedata

from .platform_paths import filesystem_path


class ProductInspectionError(ValueError):
    """Raised when a product-inspection request is malformed or unsafe."""


PRODUCT_INSPECTION_SCHEMA: Final = "promin.product-inspection.v1"
_PROFILE_ID = re.compile(r"^[a-z][a-z0-9-]{0,127}$")
_SOURCE_EXTENSIONS: Final = (
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".cxx",
    ".go",
    ".h",
    ".hpp",
    ".ixx",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".kts",
    ".m",
    ".mm",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
)
_DOCUMENTATION_EXTENSIONS: Final = (".adoc", ".md", ".mdc", ".rst", ".txt")
_DOCUMENTATION_DIRECTORIES: Final = ("doc", "docs", "documentation")
_TOOL_MARKERS: Final = (
    ("cargo", ("Cargo.toml",)),
    ("cmake", ("CMakeLists.txt",)),
    ("cmake-file-api-query", (".cmake/api/v1/query",)),
    ("cmake-file-api-reply", (".cmake/api/v1/reply",)),
    ("compilation-database", ("compile_commands.json",)),
    ("go", ("go.mod",)),
    ("node-packaging", ("package.json",)),
    ("python-packaging", ("pyproject.toml",)),
)
_RECOVERY_MARKERS: Final = (
    ".promin/docs",
    ".promin-host/recovery",
    "promin/recovery.py",
    "promin/revalidation.py",
)
_ADMINISTRATIVE_ROOTS: Final = frozenset({".git", ".hg", ".svn"})
_HOST_TRANSIENT_NAMES: Final = frozenset(
    {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".coverage", "htmlcov"}
)
_RISKY_SUFFIXES: Final = frozenset(
    {".a", ".dll", ".dylib", ".exe", ".jar", ".lib", ".so", ".tar", ".tgz", ".zip"}
)
_SENSITIVE_NAME_TOKENS: Final = frozenset(
    {"credential", "credentials", "password", "passwd", "private", "secret", "secrets", "token", "tokens"}
)
_REPARSE_POINT: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
_BRANCH_RE = re.compile(r"\b(?:case|catch|elif|else|except|for|if|switch|while)\b|&&|\|\|")
_PYTHON_IMPORT_RE = re.compile(r"^\s*(?:from\s+([.][\w.]*)\s+import\b|import\s+([\w.]+))", re.MULTILINE)
_INCLUDE_RE = re.compile(r"^\s*#\s*include\s*[<\"]([^>\"]+)[>\"]", re.MULTILINE)
_SCRIPT_IMPORT_RE = re.compile(
    r"\bimport\s+(?:[\w*${},\s]+\s+from\s+)?[\"']([^\"']+)[\"']"
)


@dataclass(frozen=True)
class InspectionLimits:
    """Finite limits that make source inspection safe on unknown product trees."""

    max_entries: int = 20_000
    max_total_bytes: int = 512 * 1024 * 1024
    max_file_bytes: int = 4 * 1024 * 1024
    max_hotspots: int = 32
    max_risk_samples: int = 32
    max_dependency_signals_per_file: int = 256

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ProductInspectionError(f"{name} must be a positive integer")
        if self.max_file_bytes > self.max_total_bytes:
            raise ProductInspectionError("max_file_bytes cannot exceed max_total_bytes")


@dataclass(frozen=True)
class ProductInspectionProfile:
    """Generic static-observation contour selected by caller or project policy."""

    profile_id: str
    source_extensions: tuple[str, ...]
    documentation_extensions: tuple[str, ...]
    documentation_directories: tuple[str, ...]
    tool_markers: tuple[tuple[str, tuple[str, ...]], ...]
    recovery_markers: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_profile_id(self.profile_id)
        object.__setattr__(
            self,
            "source_extensions",
            _require_extensions(self.source_extensions, "source_extensions"),
        )
        object.__setattr__(
            self,
            "documentation_extensions",
            _require_extensions(self.documentation_extensions, "documentation_extensions"),
        )
        object.__setattr__(
            self,
            "documentation_directories",
            _require_relative_values(self.documentation_directories, "documentation_directories"),
        )
        object.__setattr__(
            self,
            "recovery_markers",
            _require_relative_values(self.recovery_markers, "recovery_markers"),
        )
        seen_tools: set[str] = set()
        normalized_tools: list[tuple[str, tuple[str, ...]]] = []
        for tool_id, markers in self.tool_markers:
            _require_profile_id(tool_id)
            if tool_id in seen_tools:
                raise ProductInspectionError("tool_markers contains duplicate profile ids")
            seen_tools.add(tool_id)
            normalized_tools.append(
                (tool_id, _require_relative_values(markers, f"tool_markers.{tool_id}"))
            )
        object.__setattr__(
            self,
            "tool_markers",
            tuple(sorted(normalized_tools, key=lambda item: item[0].encode("utf-8"))),
        )

    def document(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "source_extensions": list(self.source_extensions),
            "documentation_extensions": list(self.documentation_extensions),
            "documentation_directories": list(self.documentation_directories),
            "tool_markers": {key: list(value) for key, value in self.tool_markers},
            "recovery_markers": list(self.recovery_markers),
        }


@dataclass(frozen=True)
class _FileFact:
    path: str
    bytes: int
    category: str
    suffix: str
    sha256: str | None
    lexical_branch_signals: int
    lexical_dependency_signals: int
    relative_dependency_signals: int
    analysis: str


@dataclass
class _ExcludedHostTransient:
    """Metadata-only accounting for exact host-generated transient roles."""

    entry_count: int = 0
    file_count: int = 0
    directory_count: int = 0
    total_bytes: int = 0
    unavailable_count: int = 0
    special_count: int = 0
    by_reason: dict[str, dict[str, int]] = field(default_factory=dict)

    def _row(self, reason: str) -> dict[str, int]:
        return self.by_reason.setdefault(
            reason,
            {
                "entry_count": 0,
                "file_count": 0,
                "directory_count": 0,
                "total_bytes": 0,
                "unavailable_count": 0,
                "special_count": 0,
            },
        )

    def record(self, reason: str, kind: str, *, size: int = 0) -> None:
        row = self._row(reason)
        self.entry_count += 1
        row["entry_count"] += 1
        if kind == "file":
            self.file_count += 1
            self.total_bytes += size
            row["file_count"] += 1
            row["total_bytes"] += size
        elif kind == "directory":
            self.directory_count += 1
            row["directory_count"] += 1
        elif kind == "unavailable":
            self.unavailable_count += 1
            row["unavailable_count"] += 1
        else:
            self.special_count += 1
            row["special_count"] += 1

    def report(self) -> dict[str, object]:
        return {
            "entry_count": self.entry_count,
            "file_count": self.file_count,
            "directory_count": self.directory_count,
            "total_bytes": self.total_bytes,
            "unavailable_count": self.unavailable_count,
            "special_count": self.special_count,
            "by_reason": {
                reason: self.by_reason[reason]
                for reason in sorted(self.by_reason, key=lambda item: item.encode("utf-8"))
            },
        }


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _require_profile_id(value: object) -> str:
    if not isinstance(value, str) or _PROFILE_ID.fullmatch(value) is None:
        raise ProductInspectionError("profile id must be a lowercase generic identifier")
    return value


def _safe_relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ProductInspectionError(f"{label} must be a safe relative path")
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value:
        raise ProductInspectionError(f"{label} must be NFC-normalized")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ProductInspectionError(f"{label} must be a safe relative path")
    if any(":" in part for part in path.parts):
        raise ProductInspectionError(f"{label} must be a safe relative path")
    return path.as_posix()


def _require_relative_values(values: object, label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ProductInspectionError(f"{label} must be a non-empty path array")
    try:
        result = tuple(_safe_relative(value, label) for value in values)
    except TypeError as error:
        raise ProductInspectionError(f"{label} must be a non-empty path array") from error
    if not result or len(result) != len(set(result)):
        raise ProductInspectionError(f"{label} must be non-empty and unique")
    return tuple(sorted(result, key=lambda item: item.encode("utf-8")))


def _require_extensions(values: object, label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ProductInspectionError(f"{label} must be a non-empty suffix array")
    try:
        result = tuple(values)
    except TypeError as error:
        raise ProductInspectionError(f"{label} must be a non-empty suffix array") from error
    if not result:
        raise ProductInspectionError(f"{label} must be a non-empty suffix array")
    normalized: list[str] = []
    for value in result:
        if (
            not isinstance(value, str)
            or not value.startswith(".")
            or len(value) == 1
            or "/" in value
            or "\\" in value
            or value != value.casefold()
        ):
            raise ProductInspectionError(f"{label} must contain lowercase filename suffixes")
        normalized.append(value)
    if len(normalized) != len(set(normalized)):
        raise ProductInspectionError(f"{label} must be unique")
    return tuple(sorted(normalized))


DEFAULT_INSPECTION_PROFILE = ProductInspectionProfile(
    profile_id="generic-static-inspection",
    source_extensions=_SOURCE_EXTENSIONS,
    documentation_extensions=_DOCUMENTATION_EXTENSIONS,
    documentation_directories=_DOCUMENTATION_DIRECTORIES,
    tool_markers=_TOOL_MARKERS,
    recovery_markers=_RECOVERY_MARKERS,
)


def _coerce_profile(value: ProductInspectionProfile | Mapping[str, object] | None) -> ProductInspectionProfile:
    if value is None:
        return DEFAULT_INSPECTION_PROFILE
    if isinstance(value, ProductInspectionProfile):
        return value
    if not isinstance(value, Mapping):
        raise ProductInspectionError("profile must be a ProductInspectionProfile or mapping")
    expected = {
        "profile_id",
        "source_extensions",
        "documentation_extensions",
        "documentation_directories",
        "tool_markers",
        "recovery_markers",
    }
    if set(value) != expected:
        raise ProductInspectionError("profile has an invalid key set")
    raw_tools = value["tool_markers"]
    if not isinstance(raw_tools, Mapping) or not raw_tools:
        raise ProductInspectionError("tool_markers must be a non-empty mapping")
    tools = tuple(
        (str(tool_id), _require_relative_values(markers, f"tool_markers.{tool_id}"))
        for tool_id, markers in sorted(raw_tools.items(), key=lambda item: str(item[0]).encode("utf-8"))
    )
    return ProductInspectionProfile(
        profile_id=_require_profile_id(value["profile_id"]),
        source_extensions=_require_extensions(value["source_extensions"], "source_extensions"),
        documentation_extensions=_require_extensions(value["documentation_extensions"], "documentation_extensions"),
        documentation_directories=_require_relative_values(
            value["documentation_directories"], "documentation_directories"
        ),
        tool_markers=tools,
        recovery_markers=_require_relative_values(value["recovery_markers"], "recovery_markers"),
    )


def _coerce_limits(value: InspectionLimits | Mapping[str, object] | None) -> InspectionLimits:
    if value is None:
        return InspectionLimits()
    if isinstance(value, InspectionLimits):
        return value
    if not isinstance(value, Mapping):
        raise ProductInspectionError("limits must be InspectionLimits or a mapping")
    defaults = asdict(InspectionLimits())
    if set(value) - set(defaults):
        raise ProductInspectionError("limits has an unknown key")
    defaults.update(value)
    return InspectionLimits(**defaults)


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_POINT)


def _host_transient_reason(name: str) -> str | None:
    """Classify only conventional host-generated names, never generic ``cache``."""

    folded = name.casefold()
    return folded if folded in _HOST_TRANSIENT_NAMES else None


def _measure_host_transient(
    root: Path,
    metadata: os.stat_result,
    reason: str,
    excluded: _ExcludedHostTransient,
) -> None:
    """Count an excluded transient tree without reading content or following links."""

    pending: list[tuple[Path, os.stat_result]] = [(root, metadata)]
    while pending:
        current, state = pending.pop()
        if _is_link_or_reparse(state):
            excluded.record(reason, "special")
            continue
        if stat.S_ISREG(state.st_mode):
            excluded.record(reason, "file", size=state.st_size)
            continue
        if not stat.S_ISDIR(state.st_mode):
            excluded.record(reason, "special")
            continue
        excluded.record(reason, "directory")
        try:
            with os.scandir(filesystem_path(current)) as directory:
                entries = sorted(directory, key=lambda item: item.name.encode("utf-8"))
        except OSError:
            excluded.record(reason, "unavailable")
            continue
        children: list[tuple[Path, os.stat_result]] = []
        for entry in entries:
            path = Path(entry.path)
            try:
                child_state = os.lstat(filesystem_path(path))
            except OSError:
                excluded.record(reason, "unavailable")
                continue
            children.append((path, child_state))
        pending.extend(reversed(children))


def _checked_root(value: str | os.PathLike[str]) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise ProductInspectionError("root must be a filesystem path")
    root = Path(value)
    try:
        metadata = os.lstat(filesystem_path(root))
    except OSError as error:
        raise ProductInspectionError(f"root is unavailable: {type(error).__name__}") from error
    if _is_link_or_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise ProductInspectionError("root must be a real directory, not a link or reparse point")
    return root


def _category(relative: str, suffix: str, profile: ProductInspectionProfile) -> str:
    parts = PurePosixPath(relative).parts
    if suffix in profile.source_extensions:
        return "source"
    if suffix in profile.documentation_extensions and (
        len(parts) == 1 or any(part in profile.documentation_directories for part in parts[:-1])
    ):
        return "documentation"
    return "other"


def _sensitive_name(relative: str) -> bool:
    filename = PurePosixPath(relative).name.casefold()
    if filename == ".env" or filename.startswith(".env."):
        return True
    words = tuple(part for part in re.split(r"[^a-z0-9]+", filename) if part)
    return bool(set(words) & _SENSITIVE_NAME_TOKENS)


def _lexical_signals(text: str, *, max_signals: int) -> tuple[int, int, int]:
    branches = len(_BRANCH_RE.findall(text))
    dependencies: list[str] = []
    for match in _PYTHON_IMPORT_RE.finditer(text):
        dependencies.append(next(item for item in match.groups() if item is not None))
    dependencies.extend(match.group(1) for match in _INCLUDE_RE.finditer(text))
    dependencies.extend(match.group(1) for match in _SCRIPT_IMPORT_RE.finditer(text))
    bounded = dependencies[:max_signals]
    return branches, len(bounded), sum(value.startswith(".") for value in bounded)


def _read_file_fact(
    path: Path,
    relative: str,
    metadata: os.stat_result,
    profile: ProductInspectionProfile,
    limits: InspectionLimits,
) -> tuple[_FileFact, list[tuple[str, str]]]:
    size = metadata.st_size
    suffix = PurePosixPath(relative).suffix.casefold()
    category = _category(relative, suffix, profile)
    risks: list[tuple[str, str]] = []
    if size > limits.max_file_bytes:
        risks.append(("oversized-file", relative))
        return (
            _FileFact(relative, size, category, suffix, None, 0, 0, 0, "metadata-only"),
            risks,
        )
    try:
        with open(filesystem_path(path), "rb") as stream:
            payload = stream.read()
    except OSError:
        risks.append(("unreadable-file", relative))
        return _FileFact(relative, size, category, suffix, None, 0, 0, 0, "unavailable"), risks
    digest = hashlib.sha256(payload).hexdigest()
    if b"\x00" in payload:
        risks.append(("binary-file", relative))
        return _FileFact(relative, size, category, suffix, digest, 0, 0, 0, "binary"), risks
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        risks.append(("non-utf8-text", relative))
        return _FileFact(relative, size, category, suffix, digest, 0, 0, 0, "metadata-only"), risks
    branches, dependencies, relative_dependencies = _lexical_signals(
        text, max_signals=limits.max_dependency_signals_per_file
    )
    return (
        _FileFact(
            relative,
            size,
            category,
            suffix,
            digest,
            branches,
            dependencies,
            relative_dependencies,
            "bounded-text",
        ),
        risks,
    )


def _risk_entry(code: str, relative: str) -> tuple[str, str]:
    return code, relative


def _profile_machine(profile: ProductInspectionProfile) -> dict[str, object]:
    document = profile.document()
    return {
        "id": profile.profile_id,
        "digest": _digest(document),
        "source_extension_count": len(profile.source_extensions),
        "documentation_extension_count": len(profile.documentation_extensions),
        "documentation_directory_count": len(profile.documentation_directories),
        "tool_profile_count": len(profile.tool_markers),
        "recovery_marker_count": len(profile.recovery_markers),
    }


def _status_for_presence(*, found: int, complete: bool) -> str:
    if found:
        return "DECLARED"
    return "UNAVAILABLE" if complete else "PARTIAL"


def _build_client_summary(machine: Mapping[str, object], claims: Mapping[str, bool]) -> dict[str, object]:
    inventory = machine["inventory"]
    architecture = machine["architecture"]
    documentation = machine["documentation"]
    recovery = machine["recovery_capability"]
    risk = machine["static_risk"]
    confidence = machine["evidence_confidence"]
    assert isinstance(inventory, Mapping)
    assert isinstance(architecture, Mapping)
    assert isinstance(documentation, Mapping)
    assert isinstance(recovery, Mapping)
    assert isinstance(risk, Mapping)
    assert isinstance(confidence, Mapping)
    return {
        "schema": PRODUCT_INSPECTION_SCHEMA,
        "record_type": "ProductInspectionClientSummary",
        "status": machine["status"],
        "summary": {
            "file_count": inventory["file_count"],
            "directory_count": inventory["directory_count"],
            "excluded_host_transient_file_count": inventory["excluded_host_transient"]["file_count"],  # type: ignore[index]
            "excluded_host_transient_bytes": inventory["excluded_host_transient"]["total_bytes"],  # type: ignore[index]
            "source_file_count": architecture["source_file_count"],
            "documentation_status": documentation["status"],
            "recovery_status": recovery["status"],
            "declared_tool_profile_count": sum(
                1
                for item in machine["tool_profiles"]  # type: ignore[index]
                if isinstance(item, Mapping) and item.get("status") == "DECLARED"
            ),
        },
        "static_risk_counts": dict(risk["by_code"]),
        "evidence_confidence": {
            "level": confidence["level"],
            "limitations": list(confidence["limitations"]),
        },
        "claims": dict(claims),
    }


def inspect_product(
    root: str | os.PathLike[str],
    *,
    profile: ProductInspectionProfile | Mapping[str, object] | None = None,
    limits: InspectionLimits | Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Return a bounded static product observation without operational effects.

    All paths in the resulting machine surface are normalized relative paths.
    Lexical dependency/branch observations are deliberately REVIEW-only
    candidates, never compiler, runtime, product, release, or pass-credit
    evidence.
    """

    inspected_root = _checked_root(root)
    selected_profile = _coerce_profile(profile)
    selected_limits = _coerce_limits(limits)
    pending: list[tuple[Path, str]] = [(inspected_root, "")]
    paths: set[str] = set()
    casefolded_paths: set[str] = set()
    file_facts: list[_FileFact] = []
    tree_rows: list[dict[str, object]] = []
    risks: list[tuple[str, str]] = []
    excluded_host_transient = _ExcludedHostTransient()
    entry_count = 0
    directory_count = 0
    total_bytes = 0
    complete = True
    scan_open = True

    while pending and scan_open:
        current, relative_current = pending.pop()
        try:
            with os.scandir(filesystem_path(current)) as directory:
                entries = sorted(directory, key=lambda item: item.name.encode("utf-8"))
        except OSError:
            risks.append(_risk_entry("unreadable-directory", relative_current or "."))
            complete = False
            continue
        children: list[tuple[Path, str]] = []
        for entry in entries:
            if not relative_current and entry.name in _ADMINISTRATIVE_ROOTS:
                continue
            transient_reason = _host_transient_reason(entry.name)
            if transient_reason is not None:
                path = Path(entry.path)
                try:
                    metadata = os.lstat(filesystem_path(path))
                except OSError:
                    excluded_host_transient.record(transient_reason, "unavailable")
                else:
                    _measure_host_transient(
                        path,
                        metadata,
                        transient_reason,
                        excluded_host_transient,
                    )
                continue
            entry_count += 1
            if entry_count > selected_limits.max_entries:
                risks.append(_risk_entry("tree-entry-budget-exceeded", relative_current or "."))
                complete = False
                scan_open = False
                break
            relative = f"{relative_current}/{entry.name}" if relative_current else entry.name
            relative = unicodedata.normalize("NFC", relative)
            if relative in paths:
                risks.append(_risk_entry("duplicate-relative-path", relative))
                complete = False
                continue
            paths.add(relative)
            folded = relative.casefold()
            if folded in casefolded_paths:
                risks.append(_risk_entry("casefold-collision", relative))
            casefolded_paths.add(folded)
            if relative != (f"{relative_current}/{entry.name}" if relative_current else entry.name):
                risks.append(_risk_entry("non-nfc-path", relative))
            path = Path(entry.path)
            try:
                metadata = os.lstat(filesystem_path(path))
            except OSError:
                risks.append(_risk_entry("unreadable-entry", relative))
                complete = False
                continue
            if _is_link_or_reparse(metadata):
                risks.append(_risk_entry("link-or-reparse-point", relative))
                complete = False
                continue
            if stat.S_ISDIR(metadata.st_mode):
                directory_count += 1
                tree_rows.append({"path": relative, "kind": "directory"})
                children.append((path, relative))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                risks.append(_risk_entry("non-regular-entry", relative))
                complete = False
                continue
            total_bytes += metadata.st_size
            if total_bytes > selected_limits.max_total_bytes:
                risks.append(_risk_entry("tree-byte-budget-exceeded", relative))
                complete = False
                scan_open = False
                break
            fact, file_risks = _read_file_fact(
                path, relative, metadata, selected_profile, selected_limits
            )
            file_facts.append(fact)
            risks.extend(file_risks)
            if fact.analysis in {"metadata-only", "unavailable"}:
                complete = False
            if _sensitive_name(relative):
                risks.append(_risk_entry("sensitive-name", relative))
            if fact.suffix in _RISKY_SUFFIXES:
                risks.append(_risk_entry("binary-or-archive-suffix", relative))
            tree_rows.append(
                {
                    "path": fact.path,
                    "kind": "file",
                    "bytes": fact.bytes,
                    "sha256": fact.sha256,
                }
            )
        pending.extend(reversed(children))

    file_facts.sort(key=lambda item: item.path.encode("utf-8"))
    tree_rows.sort(key=lambda item: str(item["path"]).encode("utf-8"))
    risks.sort(key=lambda item: (item[0], item[1].encode("utf-8")))
    extension_counts = Counter(item.suffix or "[no-suffix]" for item in file_facts)
    source_facts = [item for item in file_facts if item.category == "source"]
    documentation_facts = [item for item in file_facts if item.category == "documentation"]
    source_extensions = Counter(item.suffix for item in source_facts)
    dependency_files = sum(1 for item in source_facts if item.lexical_dependency_signals)
    dependency_total = sum(item.lexical_dependency_signals for item in source_facts)
    relative_dependency_total = sum(item.relative_dependency_signals for item in source_facts)
    empty_files = sum(1 for item in file_facts if item.bytes == 0)
    unavailable_source_files = sum(
        1 for item in source_facts if item.analysis != "bounded-text"
    )
    digest_groups: dict[tuple[int, str], list[_FileFact]] = {}
    for item in file_facts:
        if item.sha256 is not None and item.bytes:
            digest_groups.setdefault((item.bytes, item.sha256), []).append(item)
    duplicate_groups = [items for items in digest_groups.values() if len(items) > 1]
    duplicate_file_count = sum(len(items) for items in duplicate_groups)
    duplicate_bytes = sum(items[0].bytes * (len(items) - 1) for items in duplicate_groups)
    observed_paths = set(paths)
    tool_profiles: list[dict[str, object]] = []
    for tool_id, markers in selected_profile.tool_markers:
        found = sum(marker in observed_paths for marker in markers)
        tool_profiles.append(
            {
                "id": tool_id,
                "marker_count": found,
                "status": _status_for_presence(found=found, complete=complete),
            }
        )
    recovery_markers = sum(marker in observed_paths for marker in selected_profile.recovery_markers)
    hotspots = sorted(
        (
            {
                "path": item.path,
                "bytes": item.bytes,
                "category": item.category,
                "analysis": item.analysis,
                "lexical_branch_signals": item.lexical_branch_signals,
            }
            for item in file_facts
        ),
        key=lambda item: (
            -int(item["bytes"]),
            -int(item["lexical_branch_signals"]),
            str(item["path"]).encode("utf-8"),
        ),
    )[: selected_limits.max_hotspots]
    risk_counts = Counter(code for code, _path in risks)
    risk_samples = [
        {"code": code, "path": path}
        for code, path in risks[: selected_limits.max_risk_samples]
    ]
    inventory_status = "COMPLETE" if complete else "PARTIAL"
    tree_digest = _digest({"entries": tree_rows}) if complete and all(
        item.sha256 is not None for item in file_facts
    ) else None
    limitations = [
        "no-provider-execution",
        "no-configure-execution",
        "no-build-execution",
        "no-runtime-execution",
        "no-database-access",
        "lexical-dependency-signals-are-review-only",
    ]
    if not complete:
        limitations.append("tree-observation-is-partial")
    if unavailable_source_files:
        limitations.append("some-source-files-were-unavailable")
    confidence_level = "BOUNDED_STATIC" if complete else "LIMITED"
    claims = {
        "acceptance_pass": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
        "release_eligible": False,
        "runtime_validated": False,
    }
    machine: dict[str, object] = {
        "schema": PRODUCT_INSPECTION_SCHEMA,
        "record_type": "ProductInspectionMachineReport",
        "status": inventory_status,
        "profile": _profile_machine(selected_profile),
        "limits": asdict(selected_limits),
        "inventory": {
            "status": inventory_status,
            "entry_count": entry_count,
            "file_count": len(file_facts),
            "directory_count": directory_count,
            "total_bytes": total_bytes,
            "tree_digest": tree_digest,
            "extension_counts": {
                key: extension_counts[key] for key in sorted(extension_counts)
            },
            "excluded_administrative_roots": sorted(_ADMINISTRATIVE_ROOTS),
            "excluded_host_transient": excluded_host_transient.report(),
        },
        "architecture": {
            "source_file_count": len(source_facts),
            "source_extensions": {
                key: source_extensions[key] for key in sorted(source_extensions)
            },
            "dependency_signals": {
                "classification": "LEXICAL_CANDIDATE_ONLY",
                "files_with_signals": dependency_files,
                "lexical_candidate_count": dependency_total,
                "relative_candidate_count": relative_dependency_total,
                "analyzed_source_file_count": len(source_facts) - unavailable_source_files,
                "unavailable_source_file_count": unavailable_source_files,
            },
            "minimality": {
                "empty_file_count": empty_files,
                "duplicate_content_group_count": len(duplicate_groups),
                "duplicate_file_count": duplicate_file_count,
                "potential_duplicate_bytes": duplicate_bytes,
            },
        },
        "documentation": {
            "status": _status_for_presence(found=len(documentation_facts), complete=complete),
            "document_file_count": len(documentation_facts),
            "profile_driven": True,
            "generated_documentation_credit": False,
        },
        "tool_profiles": tool_profiles,
        "recovery_capability": {
            "status": _status_for_presence(found=recovery_markers, complete=complete),
            "marker_count": recovery_markers,
            "execution": "NOT_ATTEMPTED",
            "recovery_verified": False,
        },
        "static_risk": {
            "status": "REVIEW" if risks else "NO_STATIC_RISK_SIGNAL",
            "finding_count": len(risks),
            "by_code": {key: risk_counts[key] for key in sorted(risk_counts)},
            "sample_paths": risk_samples,
            "classification": "STATIC_REVIEW_ONLY",
        },
        "hotspots": {
            "classification": "SIZE_AND_LEXICAL_COMPLEXITY_REVIEW_ONLY",
            "items": hotspots,
            "truncated": len(file_facts) > len(hotspots),
        },
        "evidence_confidence": {
            "level": confidence_level,
            "limitations": limitations,
            "provider_execution": False,
            "configure_execution": False,
            "build_execution": False,
            "runtime_execution": False,
            "database_access": False,
        },
        "effects": {
            "filesystem_writes": 0,
            "provider_invocations": 0,
            "configure_invocations": 0,
            "build_invocations": 0,
            "runtime_invocations": 0,
            "sqlite_connections": 0,
        },
        "claims": claims,
    }
    client = _build_client_summary(machine, claims)
    return {
        "schema": PRODUCT_INSPECTION_SCHEMA,
        "record_type": "ProductInspection",
        "status": inventory_status,
        "machine": machine,
        "client": client,
        "claims": claims,
    }


def serialize_product_inspection(report: Mapping[str, object], *, audience: str) -> str:
    """Serialize only a safe report surface as canonical JSON plus one newline."""

    if not isinstance(report, Mapping) or report.get("schema") != PRODUCT_INSPECTION_SCHEMA:
        raise ProductInspectionError("report is not a product inspection")
    claims = report.get("claims")
    if not isinstance(claims, Mapping) or any(value is not False for value in claims.values()):
        raise ProductInspectionError("product inspection must not carry promoted claims")
    if audience not in {"client", "machine"}:
        raise ProductInspectionError("audience must be client or machine")
    selected = report.get(audience)
    if not isinstance(selected, Mapping):
        raise ProductInspectionError(f"product inspection lacks {audience} output")
    return _canonical_json(selected) + "\n"


__all__ = [
    "DEFAULT_INSPECTION_PROFILE",
    "InspectionLimits",
    "PRODUCT_INSPECTION_SCHEMA",
    "ProductInspectionError",
    "ProductInspectionProfile",
    "inspect_product",
    "serialize_product_inspection",
]
