from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True


TOOLS_ROOT = Path(__file__).resolve().parent
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
for entry in (str(TOOLS_ROOT), str(PACKAGE_ROOT)):
    while entry in sys.path:
        sys.path.remove(entry)
if os.environ.get("PROMIN_INSTALLED_TEST_MODE") == "1":
    sys.path.append(str(TOOLS_ROOT))
else:
    sys.path.insert(0, str(PACKAGE_ROOT))
    sys.path.insert(1, str(TOOLS_ROOT))

from promin.evidence import (
    EvidenceError,
    _validate_saturation_fresh_semantic_corpus,
    load_external_json_stable,
    read_external_bytes_stable,
    release_evidence_invocation,
    release_evidence_producer,
    seal_release_evidence,
    validate_release_evidence_producer_configuration,
    validate_saturation_audit,
    validate_saturation_evidence,
)
from promin.canonical import CanonicalError, ParseLimits, canonical_bytes, parse_json_strict

SATURATION_TOOL = Path(__file__).with_name("promin_saturation.py")
MAX_ITERATIONS = 18
EXACT_PHYSICAL_FILES = 100_000
EXACT_CORE_VALID_RELATIONS = 198_999
EXACT_PROJECTION_ENTITY_COUNT = 101_604
EXACT_PROJECTION_ENTITY_TYPE_COUNTS = {
    "Artifact": 100_000,
    "Candidate": 1,
    "Grant": 4,
    "Task": 1_599,
}
EXACT_SEMANTIC_COMMIT_COUNT = 1_604
EXACT_RUNTIME_QUERIES = 600
FOCUSED_MARKER = "not scale"
PHYSICAL_MARKER = "scale"
EVIDENCE_ENVIRONMENT_NAMES = (
    "PROMIN_EVIDENCE_PRIVATE_KEY",
    "PROMIN_EVIDENCE_TRUST_CONFIGURATION",
    "PROMIN_EVIDENCE_KEY_ID",
    "PROMIN_EVIDENCE_PRODUCER_ID",
)


def _load_saturation_tool() -> Any:
    spec = importlib.util.spec_from_file_location("promin_saturation_binding", SATURATION_TOOL)
    if spec is None or spec.loader is None:
        raise AuditError("physical saturation tool cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AuditError(RuntimeError):
    pass


def _without_evidence_configuration(environment: dict[str, str]) -> dict[str, str]:
    scrubbed = dict(environment)
    for name in EVIDENCE_ENVIRONMENT_NAMES:
        scrubbed.pop(name, None)
    return scrubbed


def _producer_boundary(
    environment: dict[str, str],
    *,
    platform_name: str,
    physical_private_key: Path | None,
    physical_trust_configuration: Path | None,
    physical_key_id: str | None,
    physical_producer_id: str | None,
) -> dict[str, Any] | None:
    outer_values = tuple(
        environment.get(name, "").strip()
        for name in EVIDENCE_ENVIRONMENT_NAMES[:3]
    )
    outer_producer_id = environment.get("PROMIN_EVIDENCE_PRODUCER_ID", "").strip()
    physical_values = (
        str(physical_private_key).strip() if physical_private_key is not None else "",
        (
            str(physical_trust_configuration).strip()
            if physical_trust_configuration is not None
            else ""
        ),
        (physical_key_id or "").strip(),
        (physical_producer_id or "").strip(),
    )
    if (any(outer_values) and not all(outer_values)) or (
        outer_producer_id and not all(outer_values)
    ):
        raise AuditError("outer saturation-audit producer configuration is partial")
    if any(physical_values) and not all(physical_values):
        raise AuditError("nested physical-scale producer configuration is partial")
    if bool(all(outer_values)) != bool(all(physical_values)):
        raise AuditError(
            "configured saturation audit requires both outer and nested producer configurations"
        )
    if not all(outer_values):
        return None
    outer = validate_release_evidence_producer_configuration(
        role="saturation-audit",
        platform_name=platform_name,
        private_key_path=outer_values[0],
        trust_configuration_path=outer_values[1],
        key_id=outer_values[2],
        producer_id=outer_producer_id or None,
    )
    physical = validate_release_evidence_producer_configuration(
        role="physical-scale",
        platform_name=platform_name,
        private_key_path=physical_values[0],
        trust_configuration_path=physical_values[1],
        key_id=physical_values[2],
        producer_id=physical_values[3],
    )
    if (
        outer["trust_configuration_sha256"] != physical["trust_configuration_sha256"]
        or outer["trust_root_id"] != physical["trust_root_id"]
    ):
        raise AuditError("outer and nested producers must use the exact same trust configuration bytes")
    if (
        outer["key_id"] == physical["key_id"]
        or outer["producer_id"] == physical["producer_id"]
        or outer["configured_public_key"] == physical["configured_public_key"]
    ):
        raise AuditError("outer and nested evidence producers must be distinct")
    return {
        "outer": outer,
        "physical": physical,
        "physical_environment": {
            "PROMIN_EVIDENCE_PRIVATE_KEY": str(Path(physical_values[0]).resolve()),
            "PROMIN_EVIDENCE_TRUST_CONFIGURATION": str(Path(physical_values[1]).resolve()),
            "PROMIN_EVIDENCE_KEY_ID": physical_values[2],
            "PROMIN_EVIDENCE_PRODUCER_ID": physical_values[3],
        },
    }


def _physical_evidence_environment(
    environment: dict[str, str],
    boundary: dict[str, Any] | None,
) -> dict[str, str]:
    child = _without_evidence_configuration(environment)
    if boundary is not None:
        child.update(boundary["physical_environment"])
    return child


def _require_planned_attestation(
    record: dict[str, Any],
    expected: dict[str, Any],
) -> None:
    attestation = record.get("producer_attestation")
    if (
        not isinstance(attestation, dict)
        or attestation.get("evidence_role") != expected["evidence_role"]
        or attestation.get("platform") != expected["platform"]
        or attestation.get("producer_id") != expected["producer_id"]
        or attestation.get("trust_root_id") != expected["trust_root_id"]
        or attestation.get("key_id") != expected["key_id"]
        or attestation.get("public_key") != expected["configured_public_key"]
    ):
        raise AuditError("release evidence was not signed by its preflighted producer")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _is_hex_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(_absolute_path(left))) == os.path.normcase(
        str(_absolute_path(right))
    )


def _is_within(path: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath((str(_absolute_path(path)), str(_absolute_path(root))))
    except ValueError:
        return False
    return os.path.normcase(common) == os.path.normcase(str(_absolute_path(root)))


def _is_link_or_reparse(path: Path, inspected: os.stat_result | None = None) -> bool:
    value = inspected if inspected is not None else path.lstat()
    if stat.S_ISLNK(value.st_mode) or path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    attributes = getattr(value, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400))


def _reject_reparse_ancestors(path: Path) -> None:
    absolute = _absolute_path(path)
    cursor = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        cursor = cursor / part
        try:
            inspected = cursor.lstat()
        except FileNotFoundError:
            break
        except OSError as exc:
            raise AuditError(f"path ancestor cannot be inspected: {cursor}: {exc}") from exc
        if _is_link_or_reparse(cursor, inspected):
            raise AuditError(f"symbolic link, junction, or reparse ancestor rejected: {cursor}")


def _require_real_directory(path: Path, *, label: str) -> Path:
    absolute = _absolute_path(path)
    _reject_reparse_ancestors(absolute)
    try:
        inspected = absolute.lstat()
    except OSError as exc:
        raise AuditError(f"{label} is unavailable: {absolute}: {exc}") from exc
    if _is_link_or_reparse(absolute, inspected) or not stat.S_ISDIR(inspected.st_mode):
        raise AuditError(f"{label} must be a real directory: {absolute}")
    return absolute


def _operational_state_parent(workspace: Path) -> Path:
    workspace = _absolute_path(workspace)
    return workspace.parent / f".{workspace.name}.promin-saturation-audit-state"


def _workspace_identity_digest(workspace: Path) -> str:
    workspace = _require_real_directory(workspace, label="physical workspace")
    inspected = workspace.lstat()
    return hashlib.sha256(
        _canonical(
            {
                "device": inspected.st_dev,
                "inode": inspected.st_ino,
                "path": os.path.normcase(str(workspace)),
            }
        )
    ).hexdigest()


def _validate_run_roots(package_root: Path, output: Path, workspace: Path) -> dict[str, Path]:
    package = _require_real_directory(package_root, label="package root")
    physical = _require_real_directory(workspace, label="physical workspace")
    control = physical / ".promin"
    if control.exists() or control.is_symlink():
        control = _require_real_directory(control, label="physical control root")
    else:
        _reject_reparse_ancestors(control)
    output_absolute = _absolute_path(output)
    state_parent = _operational_state_parent(physical)
    for candidate in (output_absolute, state_parent):
        _reject_reparse_ancestors(candidate)
    pairs = (
        (package, physical, "package root and physical workspace"),
        (package, output_absolute, "package root and audit output"),
        (physical, output_absolute, "physical workspace and audit output"),
        (package, state_parent, "package root and operational-state root"),
        (physical, state_parent, "physical workspace and operational-state root"),
        (output_absolute, state_parent, "audit output and operational-state root"),
    )
    for left, right, label in pairs:
        if _is_within(left, right) or _is_within(right, left):
            raise AuditError(f"{label} must be strictly disjoint")
    if (
        _is_within(output_absolute, control)
        or _is_within(output_absolute, state_parent)
        or _is_within(state_parent, control)
        or _is_within(control, state_parent)
    ):
        raise AuditError("audit output, .promin, and operational-state roots must be disjoint")
    return {
        "package": package,
        "output": output_absolute,
        "workspace": physical,
        "control": control,
        "state_parent": state_parent,
    }


def _durable_mkdir(path: Path, *, exist_ok: bool) -> None:
    absolute = _absolute_path(path)
    _reject_reparse_ancestors(absolute)
    missing: list[Path] = []
    cursor = absolute
    while not cursor.exists():
        missing.append(cursor)
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    if cursor.exists():
        _require_real_directory(cursor, label="directory ancestor")
    if not missing:
        if not exist_ok:
            raise FileExistsError(str(absolute))
        _require_real_directory(absolute, label="directory")
        return
    for directory in reversed(missing):
        directory.mkdir(exist_ok=False)
        _fsync_directory(directory.parent)


def _write(path: Path, value: Any) -> None:
    _durable_mkdir(path.parent, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("wb") as handle:
        handle.write(_canonical(value))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _write_bytes(path: Path, payload: bytes) -> None:
    _durable_mkdir(path.parent, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    _fsync_directory(path.parent)


def _write_text(path: Path, value: str) -> None:
    _write_bytes(path, value.encode("utf-8"))


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        if os.name == "nt":
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _move_real_directory(source: Path, destination: Path, *, label: str) -> None:
    source = _require_real_directory(source, label=label)
    _reject_reparse_ancestors(destination)
    if destination.exists() or destination.is_symlink():
        raise AuditError(f"{label} destination already exists: {destination}")
    _durable_mkdir(destination.parent, exist_ok=True)
    if source.drive.casefold() != destination.drive.casefold():
        raise AuditError(f"{label} move must remain on one filesystem volume")
    os.replace(source, destination)
    _fsync_directory(destination.parent)
    _fsync_directory(source.parent)
    _require_real_directory(destination, label=f"moved {label}")


def _move_control_state(source: Path, destination: Path) -> None:
    _move_real_directory(source, destination, label="Promin control state")


def _stable_file_identity(path: Path) -> tuple[str, int]:
    inspected = path.lstat()
    if _is_link_or_reparse(path, inspected) or not stat.S_ISREG(inspected.st_mode):
        raise AuditError(f"control-state entry must be a real regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    observed = 0
    try:
        before = os.fstat(descriptor)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            observed += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    current = path.lstat()
    identity_current = (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
    )
    if (
        identity_before != identity_after
        or identity_after != identity_current
        or observed != after.st_size
        or _is_link_or_reparse(path, current)
    ):
        raise AuditError(f"control-state file changed during identity read: {path}")
    return digest.hexdigest(), observed


def _control_state_identity(control: Path) -> dict[str, Any]:
    root = _require_real_directory(control, label="Promin control state")
    digest = hashlib.sha256()
    files = 0
    directories = 1
    total_bytes = 0
    seen: set[str] = set()

    def visit(directory: Path, relative: Path) -> None:
        nonlocal files, directories, total_bytes
        before = directory.lstat()
        if _is_link_or_reparse(directory, before) or not stat.S_ISDIR(before.st_mode):
            raise AuditError(f"control-state directory is not real: {directory}")
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise AuditError(f"control-state directory cannot be enumerated: {directory}: {exc}") from exc
        for entry in entries:
            path = directory / entry.name
            child_relative = relative / entry.name
            canonical_relative = child_relative.as_posix()
            folded = canonical_relative.casefold()
            if folded in seen:
                raise AuditError("control-state paths collide after casefold")
            seen.add(folded)
            inspected = path.lstat()
            if _is_link_or_reparse(path, inspected):
                raise AuditError(f"control-state link or reparse entry rejected: {path}")
            if stat.S_ISDIR(inspected.st_mode):
                directories += 1
                digest.update(_canonical({"kind": "directory", "path": canonical_relative}))
                visit(path, child_relative)
            elif stat.S_ISREG(inspected.st_mode):
                file_sha256, size = _stable_file_identity(path)
                files += 1
                total_bytes += size
                if files > 1_000_000:
                    raise AuditError("control-state identity exceeds the file-count bound")
                digest.update(
                    _canonical(
                        {
                            "bytes": size,
                            "kind": "file",
                            "path": canonical_relative,
                            "sha256": file_sha256,
                        }
                    )
                )
            else:
                raise AuditError(f"unsupported control-state entry rejected: {path}")
        after = directory.lstat()
        if (
            before.st_dev,
            before.st_ino,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mtime_ns,
        ):
            raise AuditError(f"control-state directory changed during identity scan: {directory}")

    visit(root, Path())
    return {
        "sha256": digest.hexdigest(),
        "files": files,
        "directories": directories,
        "bytes": total_bytes,
    }


def _operational_state_view(coordinator: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_type": "SaturationAuditOperationalState",
        "candidate_binding_digest": coordinator["candidate_binding_digest"],
        "output_identity_digest": coordinator["output_identity_digest"],
        "workspace_identity_digest": coordinator["workspace_identity_digest"],
        "phase": coordinator["phase"],
        "active_iteration": coordinator.get("active_iteration"),
        "baseline_control_state": "baseline.promin",
        "baseline_restored": coordinator["baseline_restored"],
        "baseline_identity_before": coordinator["baseline_identity_before"],
        "baseline_identity_after": coordinator.get("baseline_identity_after"),
        "iterations": list(coordinator["iterations"]),
        "recipe": coordinator.get("recipe_descriptor"),
        "recovery": {
            "control_path": str(coordinator["workspace"] / ".promin"),
            "preserved_baseline_path": str(coordinator["root"] / "baseline.promin"),
            "instruction": (
                "preserve any active .promin under this operational-state directory, "
                "then atomically restore baseline.promin to the workspace"
            ),
        },
    }


def _write_operational_state(coordinator: dict[str, Any]) -> None:
    _write(coordinator["root"] / "operational-state.json", _operational_state_view(coordinator))


def _capture_physical_recipe(
    workspace: Path,
    saturation_tool: Any,
    *,
    files: int,
) -> dict[str, Any]:
    path = workspace / ".promin" / "state" / "physical-corpus.json"
    limits = ParseLimits(
        max_bytes=64 * 1024,
        max_depth=8,
        max_items=128,
        max_string_length=512,
        max_number_length=16,
    )
    try:
        stable = read_external_bytes_stable(
            path,
            root=workspace / ".promin" / "state",
            max_bytes=limits.max_bytes,
        )
        value = parse_json_strict(stable.payload, limits=limits)
        if canonical_bytes(value, limits=limits) != stable.payload:
            raise AuditError("physical-corpus recipe is not canonical JSON")
        saturation_tool._verify_physical_product_recipe(workspace, files)
    except (
        OSError,
        CanonicalError,
        EvidenceError,
        saturation_tool.SaturationError,
    ) as exc:
        raise AuditError(f"physical-corpus recipe cannot be captured: {exc}") from exc
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "content_probe_stride",
            "file_count",
            "hostile_probe_stride",
            "recipe",
            "record_type",
            "representative_classes",
        }
        or value.get("record_type") != "PhysicalCorpusRecipe"
        or value.get("recipe") != saturation_tool._PHYSICAL_CORPUS_RECIPE
        or value.get("file_count") != files
        or value.get("representative_classes")
        != list(saturation_tool._REPRESENTATIVE_PHRASES)
        or value.get("content_probe_stride") != 257
        or value.get("hostile_probe_stride") != 509
    ):
        raise AuditError("physical-corpus recipe is stale, incomplete, or has the wrong file count")
    return {
        "payload": stable.payload,
        "descriptor": {
            "sha256": stable.sha256,
            "bytes": stable.size_bytes,
            "file_count": files,
        },
    }


def _reconcile_operational_state(
    root: Path,
    workspace: Path,
    *,
    candidate_binding_digest: str,
    output_identity_digest: str,
) -> dict[str, Any]:
    root = _require_real_directory(root, label="saturation operational-state root")
    workspace = _require_real_directory(workspace, label="physical workspace")
    marker_path = root / "operational-state.json"
    try:
        marker = load_external_json_stable(marker_path, root=root).value
    except (OSError, EvidenceError) as exc:
        raise AuditError(f"operational-state recovery marker is invalid: {exc}") from exc
    baseline_identity = marker.get("baseline_identity_before")
    if (
        set(marker)
        != {
            "active_iteration",
            "baseline_control_state",
            "baseline_identity_after",
            "baseline_identity_before",
            "baseline_restored",
            "candidate_binding_digest",
            "iterations",
            "output_identity_digest",
            "phase",
            "recipe",
            "record_type",
            "recovery",
            "workspace_identity_digest",
        }
        or marker.get("record_type") != "SaturationAuditOperationalState"
        or marker.get("candidate_binding_digest") != candidate_binding_digest
        or marker.get("output_identity_digest") != output_identity_digest
        or marker.get("workspace_identity_digest")
        != _workspace_identity_digest(workspace)
        or marker.get("baseline_control_state") != "baseline.promin"
        or not isinstance(baseline_identity, dict)
        or set(baseline_identity) != {"bytes", "directories", "files", "sha256"}
        or not _is_hex_digest(baseline_identity.get("sha256"))
        or any(
            not isinstance(baseline_identity.get(field), int)
            or isinstance(baseline_identity.get(field), bool)
            or baseline_identity[field] < 0
            for field in ("bytes", "directories", "files")
        )
    ):
        raise AuditError("operational-state recovery marker differs from the requested audit")
    baseline = root / "baseline.promin"
    control = workspace / ".promin"
    baseline_exists = baseline.exists() or baseline.is_symlink()
    control_exists = control.exists() or control.is_symlink()
    baseline_actual = (
        _control_state_identity(baseline) if baseline_exists else None
    )
    control_actual = _control_state_identity(control) if control_exists else None
    if baseline_actual is not None and baseline_actual != baseline_identity:
        raise AuditError("preserved baseline identity differs from its pre-move identity")

    actual_iterations: dict[int, Path] = {}
    for entry in root.iterdir():
        name = entry.name
        if name in {"baseline.promin", "operational-state.json"}:
            continue
        if name.startswith(".operational-state.json.") and name.endswith(".tmp"):
            raise AuditError(f"unfinished operational-state marker write requires inspection: {entry}")
        if not (
            name.startswith("iteration-")
            and name.endswith(".promin")
            and name[10:12].isdigit()
            and len(name) == len("iteration-00.promin")
        ):
            raise AuditError(f"unexpected operational-state entry rejected: {entry}")
        iteration = int(name[10:12])
        _require_real_directory(entry, label="preserved iteration control state")
        if iteration < 1 or iteration > MAX_ITERATIONS or iteration in actual_iterations:
            raise AuditError("preserved iteration control-state identity is invalid")
        actual_iterations[iteration] = entry

    marked_rows = marker.get("iterations")
    if not isinstance(marked_rows, list) or len(marked_rows) > MAX_ITERATIONS:
        raise AuditError("operational-state recovery iteration ledger is invalid")
    reconciled_rows: list[dict[str, Any]] = []
    marked_by_iteration: dict[int, dict[str, Any]] = {}
    for row in marked_rows:
        if (
            not isinstance(row, dict)
            or set(row)
            != {
                "control_state",
                "iteration",
                "semantic_commit_count",
                "semantic_state_reused",
                "status",
            }
            or not isinstance(row.get("iteration"), int)
            or isinstance(row.get("iteration"), bool)
            or not 1 <= row["iteration"] <= MAX_ITERATIONS
            or row.get("control_state") != f"iteration-{row['iteration']:02d}.promin"
            or not isinstance(row.get("status"), str)
            or not row["status"]
            or not isinstance(row.get("semantic_commit_count"), int)
            or isinstance(row.get("semantic_commit_count"), bool)
            or row["semantic_commit_count"] < 0
            or row.get("semantic_state_reused") is not False
        ):
            raise AuditError("operational-state recovery iteration row is invalid")
        iteration = row["iteration"]
        if iteration in marked_by_iteration:
            raise AuditError("operational-state recovery iteration rows are duplicate")
        marked_by_iteration[iteration] = row
    for iteration, path in sorted(actual_iterations.items()):
        row = marked_by_iteration.get(iteration)
        if row is None:
            row = {
                "iteration": iteration,
                "control_state": path.name,
                "status": "recovered-uncredited",
                "semantic_commit_count": 0,
                "semantic_state_reused": False,
            }
        elif row.get("control_state") != path.name:
            raise AuditError("operational-state recovery path differs from its marker")
        reconciled_rows.append(dict(row))
    missing_marked = sorted(set(marked_by_iteration) - set(actual_iterations))
    if missing_marked:
        raise AuditError(
            f"operational-state marker references absent preserved iterations: {missing_marked}"
        )

    baseline_restored = control_actual == baseline_identity and baseline_actual is None
    active_control = control_actual is not None and not baseline_restored
    if baseline_actual is None and control_actual is None:
        raise AuditError("both active and baseline Promin control states are absent")
    if baseline_actual is not None and control_actual == baseline_identity:
        raise AuditError("baseline control state exists in two locations")
    if baseline_actual is None and active_control:
        raise AuditError("baseline is absent while a non-baseline active state occupies .promin")

    coordinator: dict[str, Any] = {
        "workspace": workspace,
        "root": root,
        "candidate_binding_digest": candidate_binding_digest,
        "output_identity_digest": output_identity_digest,
        "workspace_identity_digest": marker["workspace_identity_digest"],
        "phase": (
            "published"
            if baseline_restored and marker.get("phase") == "published"
            else "complete-recovered"
            if baseline_restored
            else "iteration-active-recovered"
            if active_control
            else "iteration-preserved-recovered"
        ),
        "active_iteration": (
            marker.get("active_iteration")
            if active_control and isinstance(marker.get("active_iteration"), int)
            else (max(actual_iterations, default=0) + 1 if active_control else None)
        ),
        "baseline_restored": baseline_restored,
        "baseline_identity_before": baseline_identity,
        "baseline_identity_after": control_actual if baseline_restored else None,
        "iterations": reconciled_rows,
        "recipe": None,
        "recipe_descriptor": marker.get("recipe"),
    }
    _write_operational_state(coordinator)
    return coordinator


def _archive_published_operational_state(coordinator: dict[str, Any]) -> None:
    if coordinator.get("phase") != "published" or coordinator.get("baseline_restored") is not True:
        raise AuditError("only a published baseline-restored operational state can be archived")
    source = coordinator["root"]
    completed = _operational_state_parent(coordinator["workspace"]) / "completed"
    destination = completed / coordinator["output_identity_digest"][:24]
    _move_real_directory(
        source,
        destination,
        label="published saturation operational state",
    )
    coordinator["root"] = destination
    _write_operational_state(coordinator)


def _guard_workspace_operational_state(workspace: Path) -> None:
    parent = _operational_state_parent(workspace)
    if not parent.exists() and not parent.is_symlink():
        return
    parent = _require_real_directory(parent, label="workspace operational-state parent")
    pending: list[Path] = []
    for entry in parent.iterdir():
        if entry.name == "completed":
            completed = _require_real_directory(
                entry,
                label="completed operational-state archive",
            )
            for archived in completed.iterdir():
                _require_real_directory(
                    archived,
                    label="completed saturation operational state",
                )
            continue
        pending.append(entry)
    for root in sorted(pending, key=lambda value: value.name):
        root = _require_real_directory(root, label="unfinished saturation operational state")
        try:
            marker = load_external_json_stable(
                root / "operational-state.json",
                root=root,
            ).value
        except (OSError, EvidenceError) as exc:
            raise AuditError(f"unfinished operational-state marker is invalid: {root}: {exc}") from exc
        candidate = marker.get("candidate_binding_digest")
        output_identity = marker.get("output_identity_digest")
        if not _is_hex_digest(candidate) or not _is_hex_digest(output_identity):
            raise AuditError(f"unfinished operational-state identity is invalid: {root}")
        reconciled = _reconcile_operational_state(
            root,
            workspace,
            candidate_binding_digest=candidate,
            output_identity_digest=output_identity,
        )
        if reconciled["phase"] == "published" and reconciled["baseline_restored"] is True:
            _archive_published_operational_state(reconciled)
            continue
        raise AuditError(
            "unfinished workspace-exclusive saturation state blocks every output path; "
            f"phase={reconciled['phase']} inspect {root}"
        )


def _operational_state_location(
    workspace: Path,
    output: Path,
    artifact_binding: dict[str, Any],
) -> tuple[Path, str]:
    output_identity_digest = hashlib.sha256(
        _canonical(
            {
                "artifact_binding": artifact_binding["binding_digest"],
                "output": str(output),
            }
        )
    ).hexdigest()
    return (
        _operational_state_parent(workspace) / "active",
        output_identity_digest,
    )


def _begin_operational_state(
    workspace: Path,
    output: Path,
    artifact_binding: dict[str, Any],
    *,
    recipe: dict[str, Any] | None,
) -> dict[str, Any]:
    root, output_identity_digest = _operational_state_location(
        workspace,
        output,
        artifact_binding,
    )
    if root.exists() or root.is_symlink():
        _guard_workspace_operational_state(workspace)
        if root.exists() or root.is_symlink():
            raise AuditError(
                "workspace-exclusive saturation operational state appeared during startup; "
                f"inspect it before retry: {root}"
            )
    _durable_mkdir(root, exist_ok=False)
    baseline_identity = _control_state_identity(workspace / ".promin")
    coordinator: dict[str, Any] = {
        "workspace": workspace,
        "root": root,
        "candidate_binding_digest": artifact_binding["candidate_binding_digest"],
        "output_identity_digest": output_identity_digest,
        "workspace_identity_digest": _workspace_identity_digest(workspace),
        "phase": "baseline-preservation-pending",
        "active_iteration": None,
        "baseline_restored": False,
        "baseline_identity_before": baseline_identity,
        "baseline_identity_after": None,
        "iterations": [],
        "recipe": recipe,
        "recipe_descriptor": recipe["descriptor"] if recipe is not None else None,
    }
    _write_operational_state(coordinator)
    _move_control_state(workspace / ".promin", root / "baseline.promin")
    if _control_state_identity(root / "baseline.promin") != baseline_identity:
        coordinator["phase"] = "baseline-identity-mismatch"
        _write_operational_state(coordinator)
        raise AuditError("baseline control-state identity changed during preservation")
    coordinator["phase"] = "baseline-preserved"
    _write_operational_state(coordinator)
    return coordinator


def _fresh_iteration_control_state(
    coordinator: dict[str, Any],
    saturation_tool: Any,
    artifact_binding: dict[str, Any],
    *,
    iteration: int,
) -> dict[str, Any]:
    workspace = coordinator["workspace"]
    control = workspace / ".promin"
    if control.exists() or control.is_symlink():
        raise AuditError("fresh physical iteration refused a pre-existing semantic control state")
    coordinator["phase"] = "iteration-initialization-pending"
    coordinator["active_iteration"] = iteration
    _write_operational_state(coordinator)
    try:
        from promin_init import apply_plan

        result = apply_plan(workspace, saturation_tool._make_saturation_init_plan(workspace))
        _require_real_directory(control, label="fresh Promin control state")
        candidate = artifact_binding["standard_candidate_binding"]
        if (
            result.get("status") != "created"
            or result.get("product_tree_scans") != 0
            or result.get("core_bundle_digest") != candidate["core_bundle_digest"]
            or result.get("preset_digest") != candidate["preset_digest"]
        ):
            raise AuditError(
                "fresh physical iteration was not a zero-scan initialization bound to the exact candidate"
            )
        verified = saturation_tool._validate_saturation_workspace(
            workspace,
            status="created",
        )
        if verified.get("product_tree_scans") != 0 or verified.get("init_record_count") != 5:
            raise AuditError("fresh physical iteration initialization is incomplete")
        recipe = coordinator.get("recipe")
        if recipe is not None:
            recipe_path = control / "state" / "physical-corpus.json"
            _write_bytes(recipe_path, recipe["payload"])
            restored = _capture_physical_recipe(workspace, saturation_tool, files=recipe["descriptor"]["file_count"])
            if restored["descriptor"] != recipe["descriptor"]:
                raise AuditError("fresh physical iteration restored a different product recipe")
        coordinator["phase"] = "iteration-active"
        _write_operational_state(coordinator)
        return {
            "status": "created",
            "product_tree_scans": 0,
            "init_record_count": verified["init_record_count"],
            "activation_digest": verified["activation_digest"],
            "implementation_closure_digest": verified["implementation_closure_digest"],
            "core_bundle_digest": result["core_bundle_digest"],
            "preset_digest": result["preset_digest"],
            "semantic_state_reused": False,
            "product_tree_reused": recipe is not None,
            "physical_corpus_recipe": (
                dict(recipe["descriptor"]) if recipe is not None else None
            ),
        }
    except BaseException:
        coordinator["phase"] = "iteration-initialization-failed"
        _write_operational_state(coordinator)
        raise


def _preserve_iteration_control_state(
    coordinator: dict[str, Any],
    *,
    iteration: int,
    status: str,
    semantic_commit_count: int,
) -> None:
    if coordinator.get("active_iteration") != iteration:
        raise AuditError("operational-state iteration identity changed before preservation")
    if (
        not isinstance(semantic_commit_count, int)
        or isinstance(semantic_commit_count, bool)
        or semantic_commit_count < 0
        or (status == "zero-new" and semantic_commit_count < 1)
    ):
        raise AuditError("a zero-new physical iteration requires independent nonempty semantic commits")
    destination = coordinator["root"] / f"iteration-{iteration:02d}.promin"
    _move_control_state(coordinator["workspace"] / ".promin", destination)
    coordinator["iterations"].append(
        {
            "iteration": iteration,
            "control_state": destination.name,
            "status": status,
            "semantic_commit_count": semantic_commit_count,
            "semantic_state_reused": False,
        }
    )
    coordinator["active_iteration"] = None
    coordinator["phase"] = "iteration-preserved"
    _write_operational_state(coordinator)


def _restore_baseline_control_state(coordinator: dict[str, Any]) -> None:
    workspace = coordinator["workspace"]
    control = workspace / ".promin"
    if control.exists() or control.is_symlink():
        raise AuditError(
            "active iteration state must be preserved before baseline restoration; "
            f"recovery metadata: {coordinator['root'] / 'operational-state.json'}"
        )
    _move_control_state(coordinator["root"] / "baseline.promin", control)
    restored_identity = _control_state_identity(control)
    coordinator["baseline_identity_after"] = restored_identity
    if restored_identity != coordinator["baseline_identity_before"]:
        coordinator["phase"] = "baseline-restore-identity-mismatch"
        _write_operational_state(coordinator)
        raise AuditError("restored baseline differs from its pre-audit identity")
    coordinator["baseline_restored"] = True
    coordinator["phase"] = "complete"
    _write_operational_state(coordinator)


def _run(command: list[str], *, cwd: Path, env: dict[str, str]) -> tuple[int, str, int]:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    elapsed_ms = round((time.perf_counter() - started) * 1000)
    return completed.returncode, completed.stdout, elapsed_ms


def _fingerprints(output: str) -> list[str]:
    findings: set[str] = set()
    error_details: set[str] = set()
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(("FAILED ", "ERROR ")):
            node = stripped.split(" - ", 1)[0]
            findings.add(
                "sha256:"
                + hashlib.sha256(f"pytest-node:{node}".encode("utf-8")).hexdigest()
            )
        elif stripped.startswith("E   "):
            error_details.add(stripped)
    if not findings:
        for detail in sorted(error_details):
            findings.add(
                "sha256:"
                + hashlib.sha256(f"pytest-error:{detail}".encode("utf-8")).hexdigest()
            )
    return sorted(findings)


def _advance_zero_new_streak(
    current: int,
    *,
    passed: bool,
    new_findings: list[str],
) -> tuple[int, str | None]:
    if new_findings:
        return 0, "new-finding-class"
    if passed:
        return current + 1, None
    return 0, "full-iteration-failed"


def _pytest_command() -> list[str]:
    return [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "-m",
        FOCUSED_MARKER,
        "tests",
    ]


def _physical_pytest_command() -> list[str]:
    return [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "-m",
        PHYSICAL_MARKER,
        "tests",
    ]


def _require_scale_workspace(
    environment: dict[str, str],
    *,
    expected: Path | None = None,
) -> Path:
    configured = environment.get("PROMIN_SCALE_WORKSPACE", "").strip()
    if not configured:
        raise AuditError(
            "PROMIN_SCALE_WORKSPACE is required for `pytest -m scale`; "
            "physical scale selection fails instead of skipping"
        )
    workspace = _require_real_directory(Path(configured), label="PROMIN_SCALE_WORKSPACE")
    if expected is not None and not _same_path(workspace, expected):
        raise AuditError("PROMIN_SCALE_WORKSPACE differs from the requested physical workspace")
    try:
        _require_real_directory(
            workspace / ".promin",
            label="PROMIN_SCALE_WORKSPACE control root",
        )
    except AuditError:
        raise AuditError(
            "PROMIN_SCALE_WORKSPACE must name a production-initialized workspace"
        )
    return workspace


def _mutation_families(package_root: Path) -> list[str]:
    path = package_root / "core" / "conformance.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    families = data.get("mutation_families")
    if not isinstance(families, list) or not families or not all(isinstance(item, str) for item in families):
        raise AuditError("Core conformance mutation_families is missing or invalid")
    if len(families) != len(set(families)):
        raise AuditError("Core conformance mutation_families contains duplicates")
    return families


def _collect_mutations(package_root: Path, families: list[str]) -> dict[str, Any]:
    source = package_root / "tests" / "test_contract_mutations.py"
    if str(package_root) in sys.path:
        sys.path.remove(str(package_root))
    sys.path.insert(0, str(package_root))
    from promin.contracts import MUTATION_PROBES

    if set(MUTATION_PROBES) != set(families):
        raise AuditError("production mutation probe registry differs from Core")
    spec = importlib.util.spec_from_file_location("promin_contract_mutation_catalogue", source)
    if spec is None or spec.loader is None:
        raise AuditError("mutation catalogue cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(spec.name)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(spec.name, None)
        else:
            sys.modules[spec.name] = previous
    discovered = getattr(module, "MUTATION_RUNNERS", None)
    if not isinstance(discovered, dict):
        raise AuditError("mutation test module does not expose MUTATION_RUNNERS")
    missing = sorted(set(families) - set(discovered))
    extra = sorted(set(discovered) - set(families))
    if missing or extra:
        raise AuditError(
            "mutation corpus differs from Core: "
            f"missing={missing} extra={extra}"
        )
    payload = source.read_bytes()
    return {
        "families_discovered": len(families),
        "production_probes_discovered": len(MUTATION_PROBES),
        "catalogue_digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
    }


def _validate_iteration_semantic_freshness(corpus: Any) -> dict[str, Any]:
    try:
        return _validate_saturation_fresh_semantic_corpus(corpus)
    except EvidenceError as exc:
        raise ValueError(
            "physical result reused semantic state in a fresh audit iteration"
        ) from exc


def _read_bound_raw_json(
    verification: dict[str, Any],
    *,
    record_path: Path,
    role: str,
    expected_path: str,
    max_bytes: int,
) -> dict[str, Any]:
    manifest = verification.get("raw_artifact_manifest")
    artifacts = manifest.get("artifacts") if isinstance(manifest, dict) else None
    bindings = (
        [
            binding
            for binding in artifacts
            if isinstance(binding, dict) and binding.get("role") == role
        ]
        if isinstance(artifacts, list)
        else []
    )
    if len(bindings) != 1:
        raise ValueError(f"physical result omitted one bound {role} raw artifact")
    binding = bindings[0]
    if binding.get("path") != expected_path:
        raise ValueError(f"physical result {role} raw artifact path is not canonical")
    try:
        stable = read_external_bytes_stable(
            record_path.parent.joinpath(*expected_path.split("/")),
            root=record_path.parent,
            max_bytes=max_bytes,
        )
        if (
            stable.sha256 != binding.get("sha256")
            or stable.size_bytes != binding.get("bytes")
        ):
            raise ValueError(f"physical result {role} raw artifact binding mismatch")
        limits = ParseLimits(
            max_bytes=max_bytes,
            max_depth=64,
            max_items=1_000_000,
            max_string_length=1_048_576,
            max_number_length=256,
        )
        value = parse_json_strict(stable.payload, limits=limits)
        if canonical_bytes(value, limits=limits) != stable.payload:
            raise ValueError(f"physical result {role} raw artifact is not canonical JSON")
    except (OSError, CanonicalError, EvidenceError) as exc:
        raise ValueError(f"physical result {role} raw artifact cannot be read: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"physical result {role} raw artifact is not an object")
    return value


def _validate_physical_result(
    loaded: Any,
    *,
    record_path: Path,
    artifact_binding: dict[str, Any],
    files: int,
    queries: int,
    performance_profile: str,
) -> dict[str, Any]:
    if not isinstance(loaded, dict):
        raise ValueError("physical result is not an object")
    validated = validate_saturation_evidence(
        loaded,
        candidate_binding=artifact_binding["standard_candidate_binding"],
        source_path=record_path,
        evidence_root=record_path.parent,
    )
    if canonical_bytes(validated) != canonical_bytes(loaded):
        raise ValueError("physical result changed during raw-bound validation")
    if loaded.get("status") != "pass" or loaded.get("pass_credit") is not False:
        raise ValueError("physical result did not fail-closed to a non-credit pass")
    if loaded.get("candidate_binding_digest") != artifact_binding.get(
        "candidate_binding_digest"
    ):
        raise ValueError("physical result binds another StandardReleaseCandidateBinding")
    if (
        loaded.get("physical_files") != EXACT_PHYSICAL_FILES
        or loaded.get("physical_files") != files
        or loaded.get("core_valid_relations") != EXACT_CORE_VALID_RELATIONS
        or loaded.get("core_valid_relations_exact_198999") is not True
        or loaded.get("runtime_queries") != EXACT_RUNTIME_QUERIES
        or loaded.get("runtime_queries") != queries
        or loaded.get("silent_truncations") != 0
        or loaded.get("selected_closure_union_completeness") != 1.0
        or loaded.get("memory_amplification_at_most_32") is not True
        or loaded.get("broad_query_refinement_required") is not True
        or loaded.get("high_cardinality_terms_verified") is not True
        or loaded.get("content_search_verified") is not True
        or loaded.get("miss_behavior_verified") is not True
        or loaded.get("hostile_proxy_content_verified") is not True
        or loaded.get("exact_artifact_search_verified") is not True
        or loaded.get("mixed_query_classes_complete") is not True
        or loaded.get("continuation_token_bytes_at_most_256") is not True
        or loaded.get("continuation_state_bytes_at_most_16384") is not True
        or loaded.get("continuation_token_overhead_at_most_10_percent") is not True
    ):
        raise ValueError("physical result lacks required bounded scale/search predicates")
    binding = loaded.get("artifact_binding")
    if (
        not isinstance(binding, dict)
        or binding.get("binding_digest") != artifact_binding["binding_digest"]
        or binding.get("platform", {}).get("binding_digest")
        != artifact_binding.get("platform", {}).get("binding_digest")
    ):
        raise ValueError("physical result artifact/platform binding differs from audit binding")
    runtime_binding = loaded.get("runtime_binding")
    workspace_initialization = loaded.get("workspace_initialization")
    if (
        not isinstance(runtime_binding, dict)
        or not _is_hex_digest(runtime_binding.get("activation_digest"))
        or not _is_hex_digest(runtime_binding.get("implementation_closure_digest"))
        or runtime_binding.get("platform_binding_digest")
        != artifact_binding.get("platform", {}).get("binding_digest")
    ):
        raise ValueError("physical result omitted Activation/implementation/platform closure")
    if (
        not isinstance(workspace_initialization, dict)
        or workspace_initialization.get("status") != "reused"
        or workspace_initialization.get("product_tree_scans") != 0
        or workspace_initialization.get("init_record_count") != 5
        or workspace_initialization.get("activation_digest")
        != runtime_binding["activation_digest"]
        or workspace_initialization.get("implementation_closure_digest")
        != runtime_binding["implementation_closure_digest"]
    ):
        raise ValueError("physical result did not execute from the freshly initialized workspace")
    physical = loaded.get("physical")
    inventory = loaded.get("inventory")
    projection = loaded.get("projection")
    search = loaded.get("search")
    performance = loaded.get("performance")
    predicates = loaded.get("contract_predicates")
    resources = loaded.get("resources")
    if not all(
        isinstance(value, dict)
        for value in (physical, inventory, projection, search, performance, predicates, resources)
    ):
        raise ValueError("physical result omitted executable metric sections")
    if (
        physical.get("raw_files") != files
        or physical.get("raw_file_proxies") != files
        or physical.get("raw_file_proxy_ratio") != 1.0
        or physical.get("synthetic_task_count") != 0
        or physical.get("synthetic_task_ratio") != 0.0
        or physical.get("inventory_relations") != 0
        or physical.get("relations") != EXACT_CORE_VALID_RELATIONS
    ):
        raise ValueError("physical result violates one-Artifact-per-raw-file semantics")
    corpus = physical.get("explicit_semantic_corpus")
    _validate_iteration_semantic_freshness(corpus)
    if (
        not isinstance(corpus, dict)
        or corpus.get("task_count") != 1_599
        or corpus.get("relation_count") != EXACT_CORE_VALID_RELATIONS
        or corpus.get("depths") != list(range(1, 13))
        or corpus.get("harness_generated") is not True
        or corpus.get("product_acceptance_credit") is not False
    ):
        raise ValueError("explicit semantic depth corpus is incomplete or misclassified")
    relation_fixture = corpus.get("physical_relation_fixture")
    if (
        not isinstance(relation_fixture, dict)
        or relation_fixture.get("task_count") != 1_567
        or relation_fixture.get("relation_count") != 198_971
        or relation_fixture.get("relation_kind") != "READS"
        or relation_fixture.get("artifact_target_count") != files
        or relation_fixture.get("artifact_target_coverage") != 1.0
    ):
        raise ValueError("physical Core-valid Relation corpus is incomplete")
    if (
        inventory.get("passes") != 1
        or inventory.get("entries") != files
        or not isinstance(inventory.get("stream_bytes"), int)
        or inventory["stream_bytes"] <= 0
        or inventory.get("snapshot", {}).get("creditable") is not True
    ):
        raise ValueError("physical result lacks one creditable inventory pass")
    if (
        projection.get("initial_inventory_passes") != 1
        or projection.get("initial_product_passes") != 0
        or projection.get("rebuild_inventory_passes") != 1
        or projection.get("rebuild_product_passes") != 0
        or projection.get("entity_count") != EXACT_PROJECTION_ENTITY_COUNT
        or projection.get("entity_type_counts")
        != EXACT_PROJECTION_ENTITY_TYPE_COUNTS
        or projection.get("relation_count") != EXACT_CORE_VALID_RELATIONS
        or projection.get("equal_semantic_digest") is not True
        or not isinstance(projection.get("database_bytes"), int)
        or projection["database_bytes"] <= 0
        or not isinstance(projection.get("projection_amplification"), (int, float))
        or not isinstance(projection.get("semantic_inflation"), (int, float))
        or projection.get("inventory_integrity", {}).get("untrusted_source_artifacts") != files
        or projection.get("inventory_integrity", {}).get("untrusted_source_tasks") != 0
    ):
        raise ValueError("physical projection/rebuild metrics are incomplete")
    memory_amplification = resources.get("inventory_incremental_memory_amplification")
    pipeline_peak = resources.get("inventory_pipeline_incremental_peak_bytes")
    if (
        not isinstance(memory_amplification, (int, float))
        or isinstance(memory_amplification, bool)
        or not isinstance(pipeline_peak, int)
        or isinstance(pipeline_peak, bool)
        or pipeline_peak <= 0
        or not math.isclose(
            float(memory_amplification),
            pipeline_peak / inventory["stream_bytes"],
            rel_tol=1e-8,
            abs_tol=1e-8,
        )
        or (memory_amplification <= 32.0)
        is not loaded.get("memory_amplification_at_most_32")
    ):
        raise ValueError("physical result lacks truthful RSS-derived memory amplification")
    if (
        search.get("actual_runtime_queries") != queries
        or search.get("continuation_union_complete") is not True
        or search.get("continuation_union_completeness") != 1.0
        or search.get("forced_union_matches") != search.get("forced_continuation_chains")
        or search.get("silent_truncations") != 0
        or set(search.get("forced_depths", ())) != set(range(1, 13))
        or search.get("broad_query_refinement_required") is not True
        or search.get("high_cardinality_terms_verified") is not True
        or search.get("content_search_verified") is not True
        or search.get("miss_behavior_verified") is not True
        or search.get("hostile_proxy_content_verified") is not True
        or search.get("exact_artifact_search_verified") is not True
        or search.get("mixed_query_classes_complete") is not True
        or not isinstance(search.get("query_mix"), dict)
        or len(search["query_mix"]) < 9
        or search.get("maximum_continuation_token_bytes", 257) > 256
        or search.get("continuation_state", {}).get("maximum_bytes", 16_385) > 16_384
        or search.get("continuation_token_overhead_at_most_10_percent") is not True
    ):
        raise ValueError("physical result lacks complete bounded runtime query evidence")
    if (
        performance.get("profile_id") != performance_profile
        or performance.get("all_within_profile") is not True
        or not isinstance(performance.get("predicates"), dict)
        or not performance["predicates"]
        or not all(value is True for value in performance["predicates"].values())
    ):
        raise ValueError("physical result exceeds or omits its canonical performance profile")
    if (
        not predicates
        or predicates.get("core_valid_relations_exact") is not True
        or predicates.get("runtime_queries_exact") is not True
        or not all(value is True for value in predicates.values())
    ):
        raise ValueError("physical result contract predicates are not all satisfied")
    query_grant = loaded.get("query_authorization")
    if (
        not isinstance(query_grant, dict)
        or query_grant.get("capability_id") != "projection.read"
        or not _is_hex_digest(query_grant.get("claim_digest"))
    ):
        raise ValueError("physical result omitted exact projection.read Grant binding")
    release = loaded.get("current_release_regression")
    if (
        not isinstance(release, dict)
        or release.get("eligibility_remained_false") is not True
        or release.get("historical_decision_preserved") is not True
        or loaded.get("acceptance_pass") is not False
        or loaded.get("product_acceptance_pass") is not False
        or loaded.get("public_release_approved") is not False
    ):
        raise ValueError("physical result lacks current-release/product-acceptance separation")
    operation = _read_bound_raw_json(
        loaded,
        record_path=record_path,
        role="operation-metrics",
        expected_path="raw/operation-metrics.json",
        max_bytes=128 * 1024 * 1024,
    )
    semantic_ingestion = operation.get("semantic_ingestion")
    if (
        not isinstance(semantic_ingestion, dict)
        or not isinstance(semantic_ingestion.get("commit_count"), int)
        or isinstance(semantic_ingestion.get("commit_count"), bool)
        or semantic_ingestion["commit_count"] != EXACT_SEMANTIC_COMMIT_COUNT
        or not isinstance(semantic_ingestion.get("changed_records"), int)
        or isinstance(semantic_ingestion.get("changed_records"), bool)
        or semantic_ingestion["changed_records"] < 1
        or not isinstance(semantic_ingestion.get("observations"), list)
        or len(semantic_ingestion["observations"]) != semantic_ingestion["commit_count"]
    ):
        raise ValueError("physical result did not record independent nonempty semantic commits")
    return {
        "raw_file_proxy_ratio": physical["raw_file_proxy_ratio"],
        "synthetic_task_ratio": physical["synthetic_task_ratio"],
        "core_valid_relations": physical["relations"],
        "inventory_passes": inventory["passes"],
        "rebuild_product_passes": projection["rebuild_product_passes"],
        "equal_semantic_digest": projection["equal_semantic_digest"],
        "database_bytes": projection["database_bytes"],
        "projection_amplification": projection["projection_amplification"],
        "inventory_incremental_memory_amplification": memory_amplification,
        "semantic_inflation": projection["semantic_inflation"],
        "p50_ms": search["p50_ms"],
        "p95_ms": search["p95_ms"],
        "p99_ms": search["p99_ms"],
        "peak_rss_bytes": loaded.get("resources", {}).get("peak_rss_bytes"),
        "silent_truncations": search["silent_truncations"],
        "continuation_union_completeness": search["continuation_union_completeness"],
        "query_mix": search["query_mix"],
        "performance_profile": performance_profile,
        "semantic_commit_count": semantic_ingestion["commit_count"],
        "semantic_changed_records": semantic_ingestion["changed_records"],
    }


def _assert_unique_physical_evidence_identities(
    output: Path,
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result_digests: set[str] = set()
    invocation_ids: set[str] = set()
    key_nonces: set[tuple[str, str]] = set()
    signed_claims: set[str] = set()
    records: list[dict[str, Any]] = []
    for row in rows:
        physical = row.get("physical_runtime_saturation")
        if not isinstance(physical, dict):
            raise AuditError("physical iteration identity is missing before final publication")
        relative = physical.get("record_path")
        if (
            not isinstance(relative, str)
            or not relative
            or "\\" in relative
            or Path(relative).is_absolute()
            or any(part in {"", ".", ".."} for part in relative.split("/"))
        ):
            raise AuditError("physical iteration evidence path is non-canonical")
        try:
            stable = load_external_json_stable(
                output.joinpath(*relative.split("/")),
                root=output,
            )
        except (OSError, EvidenceError) as exc:
            raise AuditError(f"physical iteration evidence cannot be re-read safely: {exc}") from exc
        record = stable.value
        attestation = record.get("producer_attestation")
        invocation = record.get("invocation")
        result_digest = record.get("result_digest")
        invocation_id = invocation.get("invocation_id") if isinstance(invocation, dict) else None
        key_id = attestation.get("key_id") if isinstance(attestation, dict) else None
        nonce = attestation.get("nonce") if isinstance(attestation, dict) else None
        signed_claim = (
            attestation.get("signed_claim_digest") if isinstance(attestation, dict) else None
        )
        if (
            stable.sha256 != physical.get("record_sha256")
            or stable.size_bytes != physical.get("record_bytes")
            or not _is_hex_digest(result_digest)
            or not isinstance(invocation_id, str)
            or not invocation_id
            or not isinstance(key_id, str)
            or not key_id
            or not isinstance(nonce, str)
            or not nonce
            or not _is_hex_digest(signed_claim)
        ):
            raise AuditError("physical iteration replay identity is incomplete or drifted")
        key_nonce = (key_id, nonce)
        if (
            result_digest in result_digests
            or invocation_id in invocation_ids
            or key_nonce in key_nonces
            or signed_claim in signed_claims
        ):
            raise AuditError(
                "cross-iteration replay detected in result, invocation, nonce, or signed claim"
            )
        result_digests.add(result_digest)
        invocation_ids.add(invocation_id)
        key_nonces.add(key_nonce)
        signed_claims.add(signed_claim)
        records.append(record)
    if len(records) < 3:
        raise AuditError("final saturation audit requires at least three independent physical records")
    return records


def _publish_validated_saturation_audit(
    output: Path,
    result: dict[str, Any],
    *,
    candidate_binding: dict[str, Any],
    trust_configuration: dict[str, Any],
) -> None:
    final_path = output / "saturation-audit.json"
    staged_path = output / ".saturation-audit.json.staged"
    if final_path.exists() or final_path.is_symlink() or staged_path.exists() or staged_path.is_symlink():
        raise AuditError("saturation audit publication path is not empty")
    _write(staged_path, result)
    try:
        attestation_graph: list[dict[str, Any]] = []
        validated = validate_saturation_audit(
            result,
            candidate_binding=candidate_binding,
            source_path=staged_path,
            evidence_root=output,
            trust_configuration=trust_configuration,
            attestation_graph=attestation_graph,
        )
        if _canonical(validated) != _canonical(result) or len(attestation_graph) < 3:
            raise AuditError("full staged saturation validation changed or omitted the record")
    except (EvidenceError, OSError, ValueError) as exc:
        raise AuditError(f"staged saturation audit failed full validation: {exc}") from exc
    os.replace(staged_path, final_path)
    _fsync_directory(output)


def run(
    package_root: Path,
    output: Path,
    physical_workspace: Path,
    *,
    archive: Path | None = None,
    iterations: int = MAX_ITERATIONS,
    files: int = EXACT_PHYSICAL_FILES,
    queries: int = EXACT_RUNTIME_QUERIES,
    reuse_existing_product: bool = False,
    performance_profile: str = "portable-local-v1",
    physical_evidence_private_key: Path | None = None,
    physical_evidence_trust_configuration: Path | None = None,
    physical_evidence_key_id: str | None = None,
    physical_evidence_producer_id: str | None = None,
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
    if iterations < 3:
        raise AuditError("at least three consecutive full iterations are required")
    if iterations > MAX_ITERATIONS:
        raise AuditError(f"saturation audit cannot exceed {MAX_ITERATIONS} iterations")
    if files != EXACT_PHYSICAL_FILES or queries != EXACT_RUNTIME_QUERIES:
        raise AuditError("full saturation requires exactly 100000 files and exactly 600 queries")
    if importlib.util.find_spec("pytest") is None:
        raise AuditError("pytest is required for the full saturation test corpus")
    roots = _validate_run_roots(package_root, output, physical_workspace)
    package_root = roots["package"]
    output = roots["output"]
    physical_workspace = roots["workspace"]
    if not _same_path(package_root, PACKAGE_ROOT):
        raise AuditError("execute the saturation audit tool from the exact package_root under test")

    _guard_workspace_operational_state(physical_workspace)
    _require_real_directory(
        physical_workspace / ".promin",
        label="physical control root",
    )

    saturation_tool = _load_saturation_tool()
    try:
        artifact_binding = saturation_tool.build_artifact_binding(package_root, archive)
    except saturation_tool.SaturationError as exc:
        raise AuditError(str(exc)) from exc
    if output.exists() or output.is_symlink():
        raise AuditError("audit output directory already exists")

    base_env = os.environ.copy()
    platform_name = str(artifact_binding.get("platform", {}).get("system", "")).casefold()
    if not platform_name:
        raise AuditError("exact artifact binding lacks its producer platform")
    producer_boundary = _producer_boundary(
        base_env,
        platform_name=platform_name,
        physical_private_key=physical_evidence_private_key,
        physical_trust_configuration=physical_evidence_trust_configuration,
        physical_key_id=physical_evidence_key_id,
        physical_producer_id=physical_evidence_producer_id,
    )

    families = _mutation_families(package_root)
    base_env["PYTHONPATH"] = str(package_root) + os.pathsep + base_env.get("PYTHONPATH", "")
    base_env["PYTHONDONTWRITEBYTECODE"] = "1"
    base_env["PROMIN_SCALE_WORKSPACE"] = str(physical_workspace)
    _require_scale_workspace(base_env, expected=physical_workspace)
    collection = _collect_mutations(package_root, families)
    _durable_mkdir(output, exist_ok=False)
    recipe = (
        _capture_physical_recipe(physical_workspace, saturation_tool, files=files)
        if reuse_existing_product
        else None
    )
    operational_state = _begin_operational_state(
        physical_workspace,
        output,
        artifact_binding,
        recipe=recipe,
    )

    rows: list[dict[str, Any]] = []
    known_fingerprints: set[str] = set()
    zero_new_streak = 0
    for iteration in range(1, iterations + 1):
        seed = hashlib.sha256(
            _canonical({"families": families, "iteration": iteration})
        ).hexdigest()
        iteration_env = dict(base_env)
        iteration_env["PROMIN_MUTATION_SEED"] = seed
        iteration_env["PROMIN_MUTATION_ITERATION"] = str(iteration)
        sentinel_path = output / f"iteration-{iteration:02d}-pytest.sentinel"
        sentinel_token = hashlib.sha256(
            _canonical({"iteration": iteration, "mutation_seed": seed, "purpose": "pytest-only-sentinel"})
        ).hexdigest()
        iteration_env["PROMIN_PYTEST_SENTINEL"] = str(sentinel_path)
        iteration_env["PROMIN_PYTEST_SENTINEL_TOKEN"] = sentinel_token

        test_command = _pytest_command()
        test_code, test_output, test_elapsed_ms = _run(
            test_command,
            cwd=package_root,
            env=_without_evidence_configuration(iteration_env),
        )
        test_output = test_output.replace("\r\n", "\n")
        pytest_log_path = output / f"iteration-{iteration:02d}-pytest.log"
        _write_text(pytest_log_path, test_output)
        sentinel_executed = (
            sentinel_path.is_file()
            and sentinel_path.read_text(encoding="utf-8") == sentinel_token
        )

        fresh_control_state = _fresh_iteration_control_state(
            operational_state,
            saturation_tool,
            artifact_binding,
            iteration=iteration,
        )

        saturation_output = output / f"iteration-{iteration:02d}-physical"
        saturation_command = [
            sys.executable,
            str(SATURATION_TOOL),
            str(physical_workspace),
            str(saturation_output),
            "--archive",
            str(Path(archive).resolve()),
            "--files",
            str(files),
            "--queries",
            str(queries),
            "--performance-profile",
            performance_profile,
        ]
        if reuse_existing_product or iteration > 1:
            saturation_command.append("--reuse-product")
        saturation_code, saturation_log, saturation_elapsed_ms = _run(
            saturation_command,
            cwd=package_root,
            env=_physical_evidence_environment(iteration_env, producer_boundary),
        )
        recipe_capture_error: AuditError | None = None
        if operational_state.get("recipe") is None:
            try:
                captured = _capture_physical_recipe(
                    physical_workspace,
                    saturation_tool,
                    files=files,
                )
                operational_state["recipe"] = captured
                operational_state["recipe_descriptor"] = captured["descriptor"]
                fresh_control_state["physical_corpus_recipe"] = dict(
                    captured["descriptor"]
                )
                _write_operational_state(operational_state)
            except AuditError as exc:
                recipe_capture_error = exc
                saturation_code = 2
                saturation_log += f"\nphysical-corpus recipe capture failed: {exc}\n"
        saturation_log = saturation_log.replace("\r\n", "\n")
        physical_log_path = output / f"iteration-{iteration:02d}-physical.log"
        _write_text(physical_log_path, saturation_log)

        test_fingerprints = set(_fingerprints(test_output))
        if test_code != 0 and not test_fingerprints:
            test_fingerprints.add(
                "sha256:" + hashlib.sha256(test_output.encode("utf-8")).hexdigest()
            )
        fingerprints = set(test_fingerprints)
        if not sentinel_executed:
            fingerprints.add(
                "sha256:"
                + hashlib.sha256(b"pytest-only-sentinel-missing-or-invalid").hexdigest()
            )
        if saturation_code != 0:
            saturation_fingerprints = set(_fingerprints(saturation_log))
            if not saturation_fingerprints:
                saturation_fingerprints.add(
                    "sha256:" + hashlib.sha256(saturation_log.encode("utf-8")).hexdigest()
                )
            fingerprints.update(saturation_fingerprints)
        physical_result: dict[str, Any] | None = None
        physical_metrics: dict[str, Any] | None = None
        physical_result_path = saturation_output / "saturation-result.json"
        if saturation_code == 0:
            try:
                loaded = load_external_json_stable(
                    physical_result_path,
                    root=saturation_output,
                ).value
                physical_result = loaded
                physical_metrics = _validate_physical_result(
                    loaded,
                    record_path=physical_result_path,
                    artifact_binding=artifact_binding,
                    files=files,
                    queries=queries,
                    performance_profile=performance_profile,
                )
                runtime_binding = loaded.get("runtime_binding", {})
                if (
                    runtime_binding.get("activation_digest")
                    != fresh_control_state["activation_digest"]
                    or runtime_binding.get("implementation_closure_digest")
                    != fresh_control_state["implementation_closure_digest"]
                    or fresh_control_state.get("semantic_state_reused") is not False
                    or fresh_control_state.get("product_tree_scans") != 0
                ):
                    raise ValueError(
                        "physical result did not preserve the exact fresh-iteration control-state binding"
                    )
                if producer_boundary is not None:
                    _require_planned_attestation(
                        loaded,
                        producer_boundary["physical"],
                    )
            except (EvidenceError, OSError, ValueError, TypeError) as exc:
                saturation_code = 2
                physical_result = None
                physical_metrics = None
                fingerprints.add(
                    "sha256:"
                    + hashlib.sha256(f"invalid-physical-result:{exc}".encode("utf-8")).hexdigest()
                )
        try:
            current_binding = saturation_tool.build_artifact_binding(package_root, archive)
        except saturation_tool.SaturationError as exc:
            current_binding = None
            fingerprints.add(
                "sha256:"
                + hashlib.sha256(f"artifact-binding-drift:{exc}".encode("utf-8")).hexdigest()
            )
        if current_binding is not None and current_binding["binding_digest"] != artifact_binding["binding_digest"]:
            fingerprints.add("sha256:" + hashlib.sha256(b"artifact-binding-drift").hexdigest())
        new_findings = sorted(fingerprints - known_fingerprints)
        known_fingerprints.update(fingerprints)
        passed = test_code == 0 and saturation_code == 0 and not fingerprints
        previous_streak = zero_new_streak
        zero_new_streak, streak_reset_reason = _advance_zero_new_streak(
            zero_new_streak,
            passed=passed,
            new_findings=new_findings,
        )
        row = {
            "iteration": iteration,
            "mutation_seed": seed,
            "mutation_families_run": len(families),
            "focused_and_integration_tests": {
                "exit_code": test_code,
                "elapsed_ms": test_elapsed_ms,
                "output_digest": "sha256:" + hashlib.sha256(test_output.encode("utf-8")).hexdigest(),
                "runner": "pytest",
                "marker_expression": FOCUSED_MARKER,
                "cache_provider_disabled": True,
                "pytest_only_sentinel_executed": sentinel_executed,
                "pytest_only_sentinel_token_digest": "sha256:" + hashlib.sha256(
                    sentinel_token.encode("ascii")
                ).hexdigest(),
                "log_path": pytest_log_path.name,
                "log_sha256": hashlib.sha256(pytest_log_path.read_bytes()).hexdigest(),
                "log_bytes": pytest_log_path.stat().st_size,
                "sentinel_path": sentinel_path.name,
                "sentinel_sha256": (
                    hashlib.sha256(sentinel_path.read_bytes()).hexdigest()
                    if sentinel_path.is_file()
                    else None
                ),
                "sentinel_bytes": (
                    sentinel_path.stat().st_size if sentinel_path.is_file() else None
                ),
            },
            "physical_runtime_saturation": {
                "exit_code": saturation_code,
                "elapsed_ms": saturation_elapsed_ms,
                "output_digest": "sha256:" + hashlib.sha256(saturation_log.encode("utf-8")).hexdigest(),
                "log_path": physical_log_path.name,
                "log_sha256": hashlib.sha256(physical_log_path.read_bytes()).hexdigest(),
                "log_bytes": physical_log_path.stat().st_size,
                "files": files,
                "queries": queries,
                "performance_profile": performance_profile,
                "pytest_marker": PHYSICAL_MARKER,
                "pytest_selection_command": _physical_pytest_command(),
                "pytest_selection_command_executed": False,
                "execution_route": "bound-physical-saturation-tool",
                "fresh_control_state": fresh_control_state,
                "metrics": physical_metrics,
                "artifact_binding_digest": (
                    physical_result.get("artifact_binding", {}).get("binding_digest")
                    if physical_result is not None
                    else None
                ),
                "immutable_snapshot_creditable": (
                    physical_result.get("inventory", {}).get("snapshot", {}).get("creditable")
                    if physical_result is not None
                    else None
                ),
                "platform_binding_digest": (
                    physical_result.get("artifact_binding", {})
                    .get("platform", {})
                    .get("binding_digest")
                    if physical_result is not None
                    else None
                ),
                "record_path": f"iteration-{iteration:02d}-physical/saturation-result.json",
                "record_sha256": (
                    hashlib.sha256(physical_result_path.read_bytes()).hexdigest()
                    if physical_result_path.is_file()
                    else None
                ),
                "record_bytes": (
                    physical_result_path.stat().st_size
                    if physical_result_path.is_file()
                    else None
                ),
                "result_digest": (
                    physical_result.get("result_digest")
                    if physical_result is not None
                    else None
                ),
                "invocation_id": (
                    physical_result.get("invocation", {}).get("invocation_id")
                    if physical_result is not None
                    else None
                ),
                "forced_continuation_chains": (
                    physical_result.get("search", {}).get("forced_continuation_chains")
                    if physical_result is not None
                    else None
                ),
                "forced_union_matches": (
                    physical_result.get("search", {}).get("forced_union_matches")
                    if physical_result is not None
                    else None
                ),
                "current_release_regression": (
                    physical_result.get("current_release_regression")
                    if physical_result is not None
                    else None
                ),
            },
            "new_finding_classes": len(new_findings),
            "finding_fingerprints": sorted(fingerprints),
            "unexpected_accepts": 0 if passed else None,
            "unexpected_rejects": 0 if passed else None,
            "unexpected_crashes": 0 if passed else None,
            "silent_truncations": 0 if passed else None,
            "full_system_corpus_rerun": True,
            "zero_new_streak_before": previous_streak,
            "zero_new_streak_after": zero_new_streak,
            "streak_reset_reason": streak_reset_reason,
            "status": (
                "zero-new"
                if passed and not new_findings
                else "new-findings"
                if new_findings
                else "failed-known"
            ),
        }
        rows.append(row)
        _write(output / "saturation-audit.partial.json", {
            "record_type": "SaturationAuditProgress",
            "complete": False,
            "artifact_binding": artifact_binding,
            "iterations": rows,
            "zero_new_streak": zero_new_streak,
            "maximum_iterations": MAX_ITERATIONS,
        })
        _preserve_iteration_control_state(
            operational_state,
            iteration=iteration,
            status=row["status"],
            semantic_commit_count=(
                physical_metrics["semantic_commit_count"]
                if physical_metrics is not None
                else 0
            ),
        )
        if recipe_capture_error is not None:
            raise AuditError(
                "physical iteration did not establish the exact reusable product recipe; "
                f"recoverable state: {operational_state['root']}"
            ) from recipe_capture_error
        if zero_new_streak == 3:
            break

    _restore_baseline_control_state(operational_state)
    complete = len(rows) >= 3 and zero_new_streak == 3
    operational_state["phase"] = "evidence-validation-pending"
    _write_operational_state(operational_state)
    if not complete:
        operational_state["phase"] = "incomplete-no-final-publication"
        _write_operational_state(operational_state)
        raise AuditError(
            "saturation audit did not close three zero-new iterations; "
            "only partial evidence was retained"
        )
    _assert_unique_physical_evidence_identities(output, rows)
    if producer_boundary is None:
        operational_state["phase"] = "unsigned-no-final-publication"
        _write_operational_state(operational_state)
        raise AuditError("final saturation audit publication requires trusted distinct producers")
    trust_path = Path(base_env["PROMIN_EVIDENCE_TRUST_CONFIGURATION"])
    try:
        trust_read = load_external_json_stable(trust_path)
    except (OSError, EvidenceError) as exc:
        raise AuditError(f"saturation audit trust configuration drifted: {exc}") from exc
    if (
        trust_read.sha256 != producer_boundary["outer"]["trust_configuration_sha256"]
        or trust_read.sha256
        != producer_boundary["physical"]["trust_configuration_sha256"]
    ):
        raise AuditError("saturation audit trust configuration changed after producer preflight")
    result = {
        "record_type": "SaturationAudit",
        "status": "pass" if complete else "fail",
        "candidate_binding_digest": artifact_binding["candidate_binding_digest"],
        "zero_new_iterations": zero_new_streak,
        "new_findings": sum(row["new_finding_classes"] for row in rows),
        "pass_credit": False,
        "artifact_binding": artifact_binding,
        "families": families,
        "collection": collection,
        "iterations": rows,
        "consecutive_full_zero_new": zero_new_streak,
        "requirements": {
            "minimum_consecutive_full_zero_new": 3,
            "maximum_iterations": MAX_ITERATIONS,
            "configured_iteration_limit": iterations,
            "physical_files": files,
            "core_valid_relations": EXACT_CORE_VALID_RELATIONS,
            "actual_runtime_queries": queries,
            "depths": "1-12",
            "raw_file_proxy_ratio": 1.0,
            "synthetic_task_ratio": 0.0,
            "semantic_corpus_tasks": 1_599,
            "semantic_corpus_relations": 198_999,
            "mixed_query_classes": [
                "exact-artifact",
                "content-high-cardinality",
                "content-probe",
                "miss",
                "hostile-content",
                "hostile-exact",
                "broad",
                "exact-semantic",
                "forced-continuation",
            ],
            "performance_profile": performance_profile,
            "profile_bound_fail_closed": True,
            "focused_pytest_marker": FOCUSED_MARKER,
            "physical_pytest_marker": PHYSICAL_MARKER,
            "physical_pytest_command": _physical_pytest_command(),
            "missing_scale_workspace_fails": True,
            "fresh_control_state_per_iteration": True,
            "semantic_state_reused": False,
            "init_product_tree_scans": 0,
        },
        "predeclared_zero_new": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "producer": release_evidence_producer(
            PACKAGE_ROOT,
            "tools/promin_saturation_audit.py",
            version=artifact_binding["standard_candidate_binding"]["version"],
        ),
        "invocation": release_evidence_invocation(
            invocation_id=f"saturation-audit:{uuid.uuid4().hex}",
            operation="saturation-audit",
            arguments={
                "archive_sha256": artifact_binding["archive"]["sha256"],
                "files": files,
                "iterations": iterations,
                "performance_profile": performance_profile,
                "physical_evidence_producer": (
                    {
                        "key_id": producer_boundary["physical"]["key_id"],
                        "producer_id": producer_boundary["physical"]["producer_id"],
                        "trust_configuration_sha256": producer_boundary["physical"][
                            "trust_configuration_sha256"
                        ],
                    }
                    if producer_boundary is not None
                    else {"mode": "untrusted-local"}
                ),
                "queries": queries,
                "reuse_existing_product": reuse_existing_product,
                "fresh_control_state_per_iteration": True,
                "semantic_state_reused": False,
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            exit_code=0,
            platform_binding=artifact_binding["platform"]["binding_digest"][7:],
        ),
    }
    result = seal_release_evidence(result)
    if producer_boundary is not None:
        _require_planned_attestation(result, producer_boundary["outer"])
    _publish_validated_saturation_audit(
        output,
        result,
        candidate_binding=artifact_binding["standard_candidate_binding"],
        trust_configuration=trust_read.value,
    )
    operational_state["phase"] = "published"
    _write_operational_state(operational_state)
    _archive_published_operational_state(operational_state)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run up to 18 full Promin iterations until three zero-new runs")
    parser.add_argument("package_root", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("physical_workspace", type=Path)
    parser.add_argument("--archive", required=True, type=Path, help="exact promin ZIP under test")
    parser.add_argument("--iterations", type=int, default=MAX_ITERATIONS)
    parser.add_argument("--files", type=int, default=EXACT_PHYSICAL_FILES)
    parser.add_argument("--queries", type=int, default=EXACT_RUNTIME_QUERIES)
    parser.add_argument("--performance-profile", default="portable-local-v1")
    parser.add_argument("--reuse-existing-product", action="store_true")
    parser.add_argument("--physical-evidence-private-key", type=Path)
    parser.add_argument("--physical-evidence-trust-configuration", type=Path)
    parser.add_argument("--physical-evidence-key-id")
    parser.add_argument("--physical-evidence-producer-id")
    args = parser.parse_args(argv)
    try:
        result = run(
            args.package_root,
            args.output,
            args.physical_workspace,
            archive=args.archive,
            iterations=args.iterations,
            files=args.files,
            queries=args.queries,
            reuse_existing_product=args.reuse_existing_product,
            performance_profile=args.performance_profile,
            physical_evidence_private_key=args.physical_evidence_private_key,
            physical_evidence_trust_configuration=(
                args.physical_evidence_trust_configuration
            ),
            physical_evidence_key_id=args.physical_evidence_key_id,
            physical_evidence_producer_id=args.physical_evidence_producer_id,
        )
    except (AuditError, OSError, ValueError) as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
