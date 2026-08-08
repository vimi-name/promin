"""Typed, bounded publication policy for Promin control artifacts.

The policy deliberately separates the small tracked documentation boundary from
host-local operational output.  It is not an event/projection store and never
opens SQLite databases: callers supply bytes or filesystem paths and keep
authoritative mutations in their own normative routes.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from .platform_paths import filesystem_path


class ArtifactPolicyError(ValueError):
    """Raised when an artifact cannot enter its declared publication boundary."""


DOCS_ROOT = Path(".promin/docs")
EXTENSIONS_ROOT = DOCS_ROOT / "extensions"

ARTIFACT_CLASSES = (
    "portable-normative-doc",
    "compact-current-report",
    "diagnostic-inventory",
    "forensic-log",
    "runtime-evidence",
    "cache",
    "recovery-backup",
)
_TRACKED_CLASSES = frozenset({"portable-normative-doc", "compact-current-report"})
_ARTIFACT_MODES = frozenset({"minimal", "diagnostic", "forensic"})
_HOST_LOCAL_ROOTS = {
    "diagnostic-inventory": Path("builds/analysis"),
    "forensic-log": Path(".promin/logs"),
    "runtime-evidence": Path(".promin/evidence"),
    "cache": Path(".promin/cache"),
    "recovery-backup": Path(".promin/recovery"),
}
_TEXT_SUFFIXES = frozenset({".json", ".md", ".mdc", ".txt", ".toml", ".yaml", ".yml"})
_DETAILED_SUFFIXES = frozenset({".csv", ".db", ".html", ".jsonl", ".log", ".ndjson", ".sarif", ".sqlite", ".sqlite3", ".tsv", ".xml"})
_DETAILED_NAMES = frozenset(
    {
        "module-inventory.tsv",
        "module-normalization-report.json",
        "raw-diagnostics.json",
        "full-receipt.json",
        "process-transcript.log",
    }
)
_COMPACT_REPORT_NAMES = frozenset(
    {
        "commit-policy.json",
        "current-summary.json",
        "documentation-manifest.json",
        "extensions-manifest.json",
        "handoff.json",
        "team-seed.json",
    }
)
_WINDOWS_RESERVED = frozenset(
    {
        "con",
        "prn",
        "aux",
        "nul",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)
_EXTENSION_TOKEN = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


@dataclass(frozen=True)
class ArtifactBudget:
    """Independent limits for the only tracked artifact classes."""

    max_file_bytes: int = 512 * 1024
    max_file_count: int = 512
    max_compact_report_bytes: int = 256 * 1024
    max_total_bytes: int = 8 * 1024 * 1024

    def __post_init__(self) -> None:
        for field_name, value in vars(self).items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ArtifactPolicyError(f"{field_name} must be a positive integer")
        if self.max_compact_report_bytes > self.max_file_bytes:
            raise ArtifactPolicyError("compact report limit cannot exceed the per-file limit")

    def as_dict(self) -> dict[str, int]:
        return {
            "max_file_bytes": self.max_file_bytes,
            "max_file_count": self.max_file_count,
            "max_compact_report_bytes": self.max_compact_report_bytes,
            "max_total_bytes": self.max_total_bytes,
        }


@dataclass(frozen=True)
class ArtifactPolicy:
    """Generic artifact mode and publication boundary configuration."""

    default_mode: str = "minimal"
    tracked_budget: ArtifactBudget = ArtifactBudget()

    def __post_init__(self) -> None:
        validate_artifact_mode(self.default_mode)

    @property
    def tracked_classes(self) -> frozenset[str]:
        return _TRACKED_CLASSES

    def output_root(self, artifact_class: str, *, mode: str | None = None) -> Path:
        selected_mode = validate_artifact_mode(mode or self.default_mode)
        _require_artifact_class(artifact_class)
        if artifact_class in _TRACKED_CLASSES:
            # Diagnostic/forensic modes do not turn detailed output into a
            # tracked document.  They only enable the host-local classes.
            return DOCS_ROOT
        if selected_mode == "minimal":
            raise ArtifactPolicyError(
                f"{artifact_class} requires explicit diagnostic or forensic mode"
            )
        if artifact_class == "diagnostic-inventory" and selected_mode != "diagnostic":
            raise ArtifactPolicyError("diagnostic inventory requires diagnostic mode")
        if artifact_class == "forensic-log" and selected_mode != "forensic":
            raise ArtifactPolicyError("forensic log requires forensic mode")
        return _HOST_LOCAL_ROOTS[artifact_class]


def validate_artifact_mode(value: str) -> str:
    if not isinstance(value, str) or value not in _ARTIFACT_MODES:
        raise ArtifactPolicyError("artifact mode must be minimal, diagnostic, or forensic")
    return value


DEFAULT_ARTIFACT_POLICY = ArtifactPolicy()


def _require_artifact_class(value: str) -> None:
    if not isinstance(value, str) or value not in ARTIFACT_CLASSES:
        raise ArtifactPolicyError(f"unknown artifact class: {value!r}")


def _normal_relative_path(value: str | Path) -> PurePosixPath:
    raw = value.as_posix() if isinstance(value, Path) else value
    if not isinstance(raw, str) or not raw or "\\" in raw or raw.startswith("/") or ":" in raw:
        raise ArtifactPolicyError(f"artifact path is not portable relative text: {value!r}")
    if unicodedata.normalize("NFC", raw) != raw:
        raise ArtifactPolicyError(f"artifact path is not NFC-normalized: {raw!r}")
    result = PurePosixPath(raw)
    if any(part in {"", ".", ".."} for part in result.parts):
        raise ArtifactPolicyError(f"artifact path contains an unsafe segment: {raw!r}")
    for part in result.parts:
        stem = part.rstrip(" .").split(".", 1)[0].casefold()
        if part != part.rstrip(" .") or stem in _WINDOWS_RESERVED:
            raise ArtifactPolicyError(f"artifact path has a platform-unsafe segment: {raw!r}")
    return result


def _relative_to_docs(value: str | Path) -> PurePosixPath:
    normalized = _normal_relative_path(value)
    root_parts = DOCS_ROOT.parts
    if normalized.parts[: len(root_parts)] != root_parts:
        raise ArtifactPolicyError(f"tracked document must stay below {DOCS_ROOT.as_posix()}: {value!r}")
    relative = PurePosixPath(*normalized.parts[len(root_parts) :])
    if not relative.parts:
        raise ArtifactPolicyError("tracked document path must name a file")
    return relative


def _is_link_or_reparse(path: Path, inspected: os.stat_result | None = None) -> bool:
    state = inspected if inspected is not None else os.lstat(filesystem_path(path))
    if stat.S_ISLNK(state.st_mode):
        return True
    attributes = getattr(state, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    return bool(attributes & reparse_flag)


def classify_document_path(value: str | Path) -> str:
    """Classify a single tracked document without looking at project state."""

    relative = _relative_to_docs(value)
    name = relative.name.casefold()
    suffix = PurePosixPath(name).suffix
    if name in _DETAILED_NAMES or suffix in _DETAILED_SUFFIXES:
        raise ArtifactPolicyError(f"detailed operational artifact is forbidden in tracked docs: {value}")
    if suffix not in _TEXT_SUFFIXES:
        raise ArtifactPolicyError(f"tracked document has an unsupported text format: {value}")
    if (
        name in _COMPACT_REPORT_NAMES
        or name.startswith("current-")
        or name.endswith("-summary.json")
    ):
        return "compact-current-report"
    return "portable-normative-doc"


def validate_document_payloads(
    payloads: Mapping[Path, bytes],
    *,
    budget: ArtifactBudget = DEFAULT_ARTIFACT_POLICY.tracked_budget,
) -> list[dict[str, Any]]:
    """Validate generated/document-seed payloads before publication.

    The function intentionally works on supplied bytes so it cannot open a
    projection, SQLite database, provider receipt, or host-local evidence tree.
    """

    if not isinstance(payloads, Mapping):
        raise ArtifactPolicyError("tracked document payloads must be a mapping")
    if len(payloads) > budget.max_file_count:
        raise ArtifactPolicyError("tracked documentation exceeds the file-count budget")
    rows: list[dict[str, Any]] = []
    total = 0
    seen: set[str] = set()
    for path, payload in sorted(payloads.items(), key=lambda item: item[0].as_posix().encode("utf-8")):
        if not isinstance(path, Path) or not isinstance(payload, bytes):
            raise ArtifactPolicyError("tracked document payload entries require Path and bytes")
        relative = _relative_to_docs(path)
        normalized = (DOCS_ROOT / relative).as_posix()
        key = normalized.casefold()
        if key in seen:
            raise ArtifactPolicyError(f"tracked documentation has a casefold collision: {normalized}")
        seen.add(key)
        artifact_class = classify_document_path(normalized)
        size = len(payload)
        if size > budget.max_file_bytes:
            raise ArtifactPolicyError(f"tracked document exceeds the per-file budget: {normalized}")
        if artifact_class == "compact-current-report" and size > budget.max_compact_report_bytes:
            raise ArtifactPolicyError(f"compact current report exceeds its budget: {normalized}")
        if b"\0" in payload:
            raise ArtifactPolicyError(f"tracked document cannot contain binary NUL bytes: {normalized}")
        try:
            payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ArtifactPolicyError(f"tracked document must be UTF-8 text: {normalized}") from exc
        total += size
        if total > budget.max_total_bytes:
            raise ArtifactPolicyError("tracked documentation exceeds the total-byte budget")
        rows.append(
            {
                "path": normalized,
                "artifact_class": artifact_class,
                "bytes": size,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return rows


def build_document_manifest(
    payloads: Mapping[Path, bytes],
    *,
    budget: ArtifactBudget = DEFAULT_ARTIFACT_POLICY.tracked_budget,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a compact typed manifest for non-self-referential document payloads."""

    rows = validate_document_payloads(payloads, budget=budget)
    if metadata is not None and not isinstance(metadata, Mapping):
        raise ArtifactPolicyError("tracked document manifest metadata must be an object")
    identity = {
        "record_type": "TrackedDocumentationManifest",
        "schema": "promin.tracked-documentation.v1",
        "default_mode": "minimal",
        "budget": budget.as_dict(),
        "file_count": len(rows),
        "total_bytes": sum(int(row["bytes"]) for row in rows),
        "files": rows,
        "authoritative": False,
        "pass_credit": False,
    }
    if metadata:
        identity["metadata"] = dict(metadata)
    canonical = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {**identity, "manifest_digest": hashlib.sha256(canonical).hexdigest()}


def validate_tracked_docs(
    project_root: Path | str,
    *,
    budget: ArtifactBudget = DEFAULT_ARTIFACT_POLICY.tracked_budget,
) -> dict[str, Any]:
    """Fail closed on unsafe or oversized tracked document trees.

    This checks the documentation boundary only.  It does not read any
    projection or operational state and does not mutate the project.
    """

    root = Path(project_root).resolve()
    docs = root / DOCS_ROOT
    try:
        docs_state = os.lstat(filesystem_path(docs))
    except FileNotFoundError:
        return {
            "record_type": "TrackedDocumentationBoundary",
            "status": "absent",
            "file_count": 0,
            "total_bytes": 0,
            "within_budget": True,
            "files": [],
        }
    except OSError as exc:
        raise ArtifactPolicyError(f"tracked docs are unavailable: {exc}") from exc
    if _is_link_or_reparse(docs, docs_state) or not stat.S_ISDIR(docs_state.st_mode):
        raise ArtifactPolicyError("tracked docs root must be a real directory")

    payloads: dict[Path, bytes] = {}
    for directory, directories, filenames in os.walk(filesystem_path(docs), topdown=True, followlinks=False):
        current = Path(directory)
        for name in list(directories):
            child = current / name
            try:
                child_state = os.lstat(filesystem_path(child))
            except OSError as exc:
                raise ArtifactPolicyError(f"tracked docs directory is unavailable: {child}") from exc
            if _is_link_or_reparse(child, child_state) or not stat.S_ISDIR(child_state.st_mode):
                raise ArtifactPolicyError(f"tracked docs rejects a link or special directory: {child}")
            if current == docs and name == "extensions":
                # Typed extensions have their own independent byte/class
                # budget.  Do not reinterpret their tooling payload as a
                # portable normative document.
                directories.remove(name)
        for name in filenames:
            path = current / name
            try:
                path_state = os.lstat(filesystem_path(path))
            except OSError as exc:
                raise ArtifactPolicyError(f"tracked document is unavailable: {path}") from exc
            if _is_link_or_reparse(path, path_state) or not stat.S_ISREG(path_state.st_mode):
                raise ArtifactPolicyError(f"tracked docs rejects a link or special file: {path}")
            try:
                with open(filesystem_path(path), "rb") as stream:
                    payloads[path.relative_to(root)] = stream.read()
            except OSError as exc:
                raise ArtifactPolicyError(f"cannot read tracked document: {path}") from exc
    rows = validate_document_payloads(payloads, budget=budget)
    return {
        "record_type": "TrackedDocumentationBoundary",
        "status": "valid",
        "file_count": len(rows),
        "total_bytes": sum(int(row["bytes"]) for row in rows),
        "within_budget": True,
        "files": rows,
    }


def validate_control_docs_shell(control_root: Path | str) -> dict[str, Any]:
    """Validate a cloneable `.promin` shell containing docs and no local state."""

    control = Path(control_root).resolve()
    try:
        state = os.lstat(filesystem_path(control))
    except OSError as exc:
        raise ArtifactPolicyError(f"Promin docs shell is unavailable: {exc}") from exc
    if _is_link_or_reparse(control, state) or not stat.S_ISDIR(state.st_mode):
        raise ArtifactPolicyError("Promin docs shell must be a real directory")
    entries = {entry.name for entry in control.iterdir()}
    if not entries <= {".gitignore", "docs"}:
        raise ArtifactPolicyError("Promin docs shell contains host-local or operational roots")
    if "docs" not in entries:
        raise ArtifactPolicyError("Promin docs shell lacks the tracked docs root")
    ignore = control / ".gitignore"
    try:
        ignore_state = os.lstat(filesystem_path(ignore))
    except FileNotFoundError:
        ignore_state = None
    except OSError as exc:
        raise ArtifactPolicyError("Promin docs shell .gitignore is unavailable") from exc
    if ignore_state is not None:
        if _is_link_or_reparse(ignore, ignore_state) or not stat.S_ISREG(ignore_state.st_mode):
            raise ArtifactPolicyError("Promin docs shell .gitignore must be a regular file")
    result = validate_tracked_docs(control.parent)
    extensions = validate_tracked_extensions(control.parent)
    return {
        **result,
        "status": "valid",
        "control_root": ".promin",
        "extension_file_count": extensions["file_count"],
        "extension_total_bytes": extensions["total_bytes"],
    }


def artifact_output_path(
    project_root: Path | str,
    *,
    artifact_class: str,
    name: str | Path,
    mode: str = "minimal",
    policy: ArtifactPolicy = DEFAULT_ARTIFACT_POLICY,
) -> Path:
    """Return a safe output path without creating or modifying any artifact."""

    if not isinstance(policy, ArtifactPolicy):
        raise ArtifactPolicyError("artifact policy must be an ArtifactPolicy instance")
    relative = _normal_relative_path(name)
    root = policy.output_root(artifact_class, mode=mode)
    if artifact_class in policy.tracked_classes:
        declared = classify_document_path(DOCS_ROOT / Path(*relative.parts))
        if declared != artifact_class:
            raise ArtifactPolicyError(
                f"tracked artifact name declares {declared}, not {artifact_class}"
            )
    return Path(project_root).resolve() / root / Path(*relative.parts)


def classify_archive_path(value: str | Path) -> str:
    """Classify a path by its control boundary, never by incidental product names."""

    path = _normal_relative_path(value)
    parts = path.parts
    if parts[:3] == (".promin", "docs", "extensions"):
        return "tracked-extension"
    if parts[:2] == (".promin", "docs"):
        return "tracked-document"
    if parts[:1] != (".promin",):
        return "project-content"
    if parts[:1] == (".promin",):
        if len(parts) >= 2:
            root = parts[1]
            return {
                "cache": "cache",
                "evidence": "runtime-evidence",
                "logs": "forensic-log",
                "recovery": "recovery-backup",
            }.get(root, "operational-control")
        return "operational-control"
    return "project-content"


def validate_extension_descriptor(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a generic typed extension declaration without resolving it."""

    if not isinstance(value, Mapping):
        raise ArtifactPolicyError("tracked extension descriptor must be an object")
    required = {"extension_id", "extension_type", "root"}
    if set(value) != required:
        raise ArtifactPolicyError("tracked extension descriptor has an invalid key set")
    extension_id = value.get("extension_id")
    extension_type = value.get("extension_type")
    root = value.get("root")
    if not isinstance(extension_id, str) or _EXTENSION_TOKEN.fullmatch(extension_id) is None:
        raise ArtifactPolicyError("tracked extension id is invalid")
    if not isinstance(extension_type, str) or _EXTENSION_TOKEN.fullmatch(extension_type) is None:
        raise ArtifactPolicyError("tracked extension type is invalid")
    relative = _relative_to_docs(root if isinstance(root, str) else "")
    expected = PurePosixPath(*(EXTENSIONS_ROOT.parts[2:]), extension_id)
    if relative != expected:
        raise ArtifactPolicyError("tracked extension root must use the typed .promin/docs/extensions/<id> layout")
    return {
        "extension_id": extension_id,
        "extension_type": extension_type,
        "root": (DOCS_ROOT / Path(*relative.parts)).as_posix(),
    }


def host_local_roots() -> dict[str, str]:
    """Return non-trackable artifact roots for policy/report rendering."""

    return {artifact_class: root.as_posix() for artifact_class, root in _HOST_LOCAL_ROOTS.items()}


def iter_tracked_document_paths(project_root: Path | str) -> Iterable[Path]:
    """Yield validated tracked documents in deterministic byte-path order."""

    root = Path(project_root).resolve()
    result = validate_tracked_docs(root)
    for row in result["files"]:
        yield root / str(row["path"])


def validate_tracked_extensions(
    project_root: Path | str,
    *,
    budget: ArtifactBudget = DEFAULT_ARTIFACT_POLICY.tracked_budget,
) -> dict[str, Any]:
    """Fail closed on unsafe generic extension trees without loading their semantics."""

    root = Path(project_root).resolve()
    extensions = root / EXTENSIONS_ROOT
    try:
        root_state = os.lstat(filesystem_path(extensions))
    except FileNotFoundError:
        return {
            "record_type": "TrackedExtensionBoundary",
            "status": "absent",
            "file_count": 0,
            "total_bytes": 0,
            "within_budget": True,
            "files": [],
        }
    except OSError as exc:
        raise ArtifactPolicyError(f"tracked extension root is unavailable: {exc}") from exc
    if _is_link_or_reparse(extensions, root_state) or not stat.S_ISDIR(root_state.st_mode):
        raise ArtifactPolicyError("tracked extension root must be a real directory")

    rows: list[dict[str, Any]] = []
    total = 0
    seen: set[str] = set()
    try:
        extension_dirs = sorted(extensions.iterdir(), key=lambda item: item.name.encode("utf-8"))
    except OSError as exc:
        raise ArtifactPolicyError("tracked extension root cannot be enumerated") from exc
    for extension in extension_dirs:
        try:
            extension_state = os.lstat(filesystem_path(extension))
        except OSError as exc:
            raise ArtifactPolicyError(f"tracked extension is unavailable: {extension}") from exc
        if (
            _EXTENSION_TOKEN.fullmatch(extension.name) is None
            or _is_link_or_reparse(extension, extension_state)
            or not stat.S_ISDIR(extension_state.st_mode)
        ):
            raise ArtifactPolicyError("tracked extension root must be a real typed directory")
        for directory, directories, filenames in os.walk(filesystem_path(extension), topdown=True, followlinks=False):
            current = Path(directory)
            directories.sort(key=lambda item: item.encode("utf-8"))
            filenames.sort(key=lambda item: item.encode("utf-8"))
            for name in list(directories):
                child = current / name
                child_state = os.lstat(filesystem_path(child))
                if _is_link_or_reparse(child, child_state) or not stat.S_ISDIR(child_state.st_mode):
                    raise ArtifactPolicyError(f"tracked extension rejects a link or special directory: {child}")
            for name in filenames:
                path = current / name
                path_state = os.lstat(filesystem_path(path))
                if _is_link_or_reparse(path, path_state) or not stat.S_ISREG(path_state.st_mode):
                    raise ArtifactPolicyError(f"tracked extension rejects a link or special file: {path}")
                relative = _normal_relative_path(path.relative_to(root))
                key = relative.as_posix().casefold()
                if key in seen:
                    raise ArtifactPolicyError(f"tracked extension has a casefold collision: {relative}")
                seen.add(key)
                size = path_state.st_size
                if size > budget.max_file_bytes:
                    raise ArtifactPolicyError(f"tracked extension exceeds the per-file budget: {relative}")
                total += size
                if len(rows) + 1 > budget.max_file_count or total > budget.max_total_bytes:
                    raise ArtifactPolicyError("tracked extensions exceed their independent budget")
                try:
                    with open(filesystem_path(path), "rb") as stream:
                        payload = stream.read()
                except OSError as exc:
                    raise ArtifactPolicyError(f"tracked extension cannot be read: {path}") from exc
                rows.append(
                    {
                        "path": relative.as_posix(),
                        "artifact_class": "tracked-extension",
                        "extension_id": extension.name,
                        "bytes": size,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                )
    return {
        "record_type": "TrackedExtensionBoundary",
        "status": "valid",
        "file_count": len(rows),
        "total_bytes": total,
        "within_budget": True,
        "files": rows,
    }


def iter_tracked_extension_paths(project_root: Path | str) -> Iterable[Path]:
    """Yield validated generic extension files in deterministic byte-path order."""

    root = Path(project_root).resolve()
    result = validate_tracked_extensions(root)
    for row in result["files"]:
        yield root / str(row["path"])
