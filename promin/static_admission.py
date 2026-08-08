"""Bounded source-only admission for a package awaiting dynamic validation.

This module deliberately does not import operational Promin surfaces.  It only
reads directory metadata and validates a supplied, pending handoff contract.
It never invokes a provider, configures or builds a project, launches runtime
work, opens a database, writes an artifact, or awards acceptance credit.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import time
from typing import Final

from .dynamic_handoff import DynamicHandoffError, validate_dynamic_handoff


class StaticAdmissionError(ValueError):
    """Raised for an invalid static-admission invocation."""


STATIC_ADMISSION_SCHEMA: Final = "promin.final-static-admission.v1"
_ARTIFACT_MODES: Final = frozenset({"minimal", "diagnostic-host-local"})
_MAX_TREE_ENTRIES: Final = 10_000
_MAX_TREE_BYTES: Final = 128 * 1024 * 1024
_REPARSE_POINT: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
_WINDOWS_RESERVED_STEMS: Final = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
    }
)
_OPERATIONAL_DOC_DIRECTORIES: Final = frozenset(
    {"cache", "evidence", "leases", "locks", "providers", "state"}
)
_OPERATIONAL_DOC_FILENAMES: Final = frozenset(
    {
        "provider.json",
        "providers.json",
        "provider-receipt.json",
        "state.json",
    }
)
_OPERATIONAL_DOC_SUFFIXES: Final = frozenset(
    {".db", ".lease", ".lock", ".pid", ".sqlite", ".sqlite3"}
)


@dataclass(frozen=True)
class _TreeScan:
    entry_count: int
    file_count: int
    byte_count: int
    paths: tuple[str, ...]
    files: tuple[str, ...]
    violations: tuple[str, ...]


def _is_reparse_or_link(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_POINT)


def _scan_tree(root: Path, *, skipped_names: frozenset[str] = frozenset()) -> _TreeScan:
    """Inspect a tree without following link/reparse boundaries or reading bytes."""

    entry_count = 0
    file_count = 0
    byte_count = 0
    relative_paths: list[str] = []
    relative_files: list[str] = []
    violations: list[str] = []
    pending: list[tuple[Path, Path]] = [(root, Path("."))]

    while pending:
        current, relative_current = pending.pop()
        try:
            with os.scandir(current) as directory:
                entries = sorted(directory, key=lambda entry: (entry.name.casefold(), entry.name))
        except OSError as error:
            violations.append(f"unreadable-directory:{relative_current.as_posix()}:{type(error).__name__}")
            continue

        for entry in entries:
            if entry.name in skipped_names:
                continue
            entry_count += 1
            if entry_count > _MAX_TREE_ENTRIES:
                violations.append("entry-budget-exceeded")
                return _TreeScan(
                    entry_count,
                    file_count,
                    byte_count,
                    tuple(relative_paths),
                    tuple(relative_files),
                    tuple(violations),
                )

            child = Path(entry.path)
            relative_child = relative_current / entry.name
            relative_text = relative_child.as_posix()
            relative_paths.append(relative_text)
            try:
                metadata = child.lstat()
            except OSError as error:
                violations.append(f"unreadable-entry:{relative_text}:{type(error).__name__}")
                continue

            if _is_reparse_or_link(metadata):
                violations.append(f"link-or-reparse-point:{relative_text}")
                continue
            if stat.S_ISDIR(metadata.st_mode):
                pending.append((child, relative_child))
                continue
            if stat.S_ISREG(metadata.st_mode):
                file_count += 1
                byte_count += metadata.st_size
                relative_files.append(relative_text)
                if byte_count > _MAX_TREE_BYTES:
                    violations.append("byte-budget-exceeded")
                    return _TreeScan(
                        entry_count,
                        file_count,
                        byte_count,
                        tuple(relative_paths),
                        tuple(relative_files),
                        tuple(violations),
                    )
                continue
            violations.append(f"non-regular-entry:{relative_text}")

    return _TreeScan(
        entry_count,
        file_count,
        byte_count,
        tuple(relative_paths),
        tuple(relative_files),
        tuple(violations),
    )


def _check_root(root: object) -> Path:
    if not isinstance(root, (str, os.PathLike)):
        raise StaticAdmissionError("root must be a filesystem path")
    candidate = Path(root)
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise StaticAdmissionError(f"root is unavailable: {type(error).__name__}") from error
    if _is_reparse_or_link(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise StaticAdmissionError("root must be a real directory, not a link or reparse point")
    return candidate


def _check_profile(profile: object) -> str:
    if not isinstance(profile, str) or profile not in _ARTIFACT_MODES:
        values = ", ".join(sorted(_ARTIFACT_MODES))
        raise StaticAdmissionError(f"profile must be one of: {values}")
    return profile


def _scan_details(scan: _TreeScan) -> dict[str, object]:
    return {
        "entry_count": scan.entry_count,
        "file_count": scan.file_count,
        "byte_count": scan.byte_count,
        "bounded_by": {
            "max_entries": _MAX_TREE_ENTRIES,
            "max_bytes": _MAX_TREE_BYTES,
        },
        "violations": list(scan.violations),
    }


def _record(
    record_id: str,
    kind: str,
    status: str,
    artifact_mode: str,
    started: float,
    details: Mapping[str, object],
) -> dict[str, object]:
    return {
        "id": record_id,
        "kind": kind,
        "status": status,
        "elapsed_seconds": round(max(0.0, time.monotonic() - started), 6),
        "artifact_mode": artifact_mode,
        "details": dict(details),
    }


def _source_check(root: Path, artifact_mode: str) -> dict[str, object]:
    started = time.monotonic()
    scan = _scan_tree(root, skipped_names=frozenset({".git"}))
    return _record(
        "static-source-membership",
        "source",
        "PASS" if not scan.violations else "FAIL",
        artifact_mode,
        started,
        _scan_details(scan),
    )


def _documentation_payload_violations(scan: _TreeScan) -> list[str]:
    violations: list[str] = []
    for relative in scan.paths:
        components = relative.split("/")
        if any(component.casefold() in _OPERATIONAL_DOC_DIRECTORIES for component in components[:-1]):
            violations.append(f"operational-document-directory:{relative}")
    for relative in scan.files:
        filename = relative.rsplit("/", 1)[-1].casefold()
        suffix = Path(filename).suffix.casefold()
        if filename in _OPERATIONAL_DOC_FILENAMES or suffix in _OPERATIONAL_DOC_SUFFIXES:
            violations.append(f"operational-document-payload:{relative}")
    return violations


def _documentation_check(root: Path, artifact_mode: str) -> dict[str, object]:
    started = time.monotonic()
    documentation_root = root / ".promin" / "docs"
    try:
        metadata = documentation_root.lstat()
    except OSError as error:
        return _record(
            "static-documentation-boundary",
            "documentation",
            "FAIL",
            artifact_mode,
            started,
            {"reason": f"documentation-root-unavailable:{type(error).__name__}"},
        )
    if _is_reparse_or_link(metadata) or not stat.S_ISDIR(metadata.st_mode):
        return _record(
            "static-documentation-boundary",
            "documentation",
            "FAIL",
            artifact_mode,
            started,
            {"reason": "documentation-root-must-be-a-real-directory"},
        )

    scan = _scan_tree(documentation_root)
    details = _scan_details(scan)
    payload_violations = _documentation_payload_violations(scan)
    all_violations = [*scan.violations, *payload_violations]
    if not scan.files:
        all_violations.append("documentation-root-is-empty")
    details["violations"] = all_violations
    return _record(
        "static-documentation-boundary",
        "documentation",
        "PASS" if not all_violations else "FAIL",
        artifact_mode,
        started,
        details,
    )


def _portable_name_violation(relative_path: str) -> str | None:
    for component in relative_path.split("/"):
        if component.endswith((".", " ")):
            return f"non-portable-trailing-character:{relative_path}"
        stem = component.split(".", 1)[0].upper()
        if stem in _WINDOWS_RESERVED_STEMS:
            return f"windows-reserved-name:{relative_path}"
    return None


def _portability_check(root: Path, artifact_mode: str) -> dict[str, object]:
    started = time.monotonic()
    scan = _scan_tree(root, skipped_names=frozenset({".git"}))
    portability_violations = [
        violation
        for relative_path in scan.paths
        if (violation := _portable_name_violation(relative_path)) is not None
    ]
    all_violations = [*scan.violations, *portability_violations]
    details = _scan_details(scan)
    details["violations"] = all_violations
    return _record(
        "static-portability-boundary",
        "portability",
        "PASS" if not all_violations else "FAIL",
        artifact_mode,
        started,
        details,
    )


def _handoff_check(
    handoff: Mapping[str, object] | None, artifact_mode: str
) -> dict[str, object]:
    started = time.monotonic()
    if handoff is None:
        return _record(
            "static-dynamic-handoff",
            "handoff",
            "SKIPPED",
            artifact_mode,
            started,
            {"reason": "dynamic-handoff-not-supplied"},
        )
    try:
        normalized = validate_dynamic_handoff(handoff)
    except DynamicHandoffError as error:
        return _record(
            "static-dynamic-handoff",
            "handoff",
            "FAIL",
            artifact_mode,
            started,
            {"reason": f"invalid-dynamic-handoff:{error}"},
        )
    return _record(
        "static-dynamic-handoff",
        "handoff",
        "PASS",
        artifact_mode,
        started,
        {
            "id": normalized["id"],
            "status": normalized["status"],
            "invalidation_class": normalized["invalidation_class"],
        },
    )


def _overall_status(checks: list[dict[str, object]]) -> str:
    statuses = {str(check["status"]) for check in checks}
    for candidate in ("FAIL", "TIMEOUT", "UNAVAILABLE", "SKIPPED"):
        if candidate in statuses:
            return candidate
    return "PASS"


def run_static_admission(
    root: str | os.PathLike[str],
    *,
    profile: str = "minimal",
    handoff: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Run the bounded, static-only gate and explicitly retain false claims.

    A ``PASS`` here says only that the inspected static boundary is internally
    coherent.  It does not validate a compiler, runtime, product behavior,
    distribution installability, or release acceptance.
    """

    checked_root = _check_root(root)
    artifact_mode = _check_profile(profile)
    checks = [
        _source_check(checked_root, artifact_mode),
        _documentation_check(checked_root, artifact_mode),
        _portability_check(checked_root, artifact_mode),
        _handoff_check(handoff, artifact_mode),
    ]
    status = _overall_status(checks)
    claims = {
        "compiler_validated": False,
        "runtime_validated": False,
        "acceptance_pass": False,
        "pass_credit": False,
    }
    return {
        "schema": STATIC_ADMISSION_SCHEMA,
        "record_type": "FinalStaticAdmission",
        "profile": artifact_mode,
        "checks": checks,
        "status": status,
        "claims": claims,
        "effects": {
            "provider_invocations": 0,
            "configure_invocations": 0,
            "build_invocations": 0,
            "runtime_invocations": 0,
            "sqlite_connections": 0,
        },
        "product_acceptance_pass": False,
        "release_eligible": False,
        "pass_credit": False,
    }


__all__ = ["STATIC_ADMISSION_SCHEMA", "StaticAdmissionError", "run_static_admission"]
