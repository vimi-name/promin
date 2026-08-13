"""Small deterministic bridge from ``promin init`` to the first work proposal.

The route is intentionally mechanical: it reads the resolved init plan, makes
one bounded repository inventory, derives a compact semantic summary, and
optionally records the result below ``.promin-host``.  It does not run a model,
choose an authoritative task, or mutate project files.
"""

from __future__ import annotations

from collections import Counter, deque
from collections.abc import Mapping
import hashlib
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
from typing import Any

from .canonical import CanonicalError, canonical_bytes, digest_bytes, digest_value, load_json_strict


INITIAL_PROJECT_WORK_SCHEMA = "promin.initial-project-work.v1"
DEFAULT_INITIAL_WORK_MAX_FILES = 4_096
DEFAULT_INITIAL_WORK_MAX_BYTES = 8 * 1024 * 1024
MAX_INITIAL_WORK_FILES = 100_000
MAX_INITIAL_WORK_BYTES = 64 * 1024 * 1024

_MAX_DEPTH = 64
_MAX_SAMPLES = 64
_IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".promin",
        ".promin-host",
        ".idea",
        ".vscode",
        ".venv",
        "venv",
        "node_modules",
        "dist",
        "build",
        "target",
        "coverage",
        "vendor",
        "__pycache__",
    }
)


class InitialProjectWorkError(ValueError):
    """Raised when initial work cannot be planned or recorded consistently."""


def _claims() -> dict[str, bool]:
    return {
        "authority": False,
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }


def _validate_limits(max_files: int, max_bytes: int) -> None:
    if type(max_files) is not int or not 1 <= max_files <= MAX_INITIAL_WORK_FILES:
        raise InitialProjectWorkError(
            f"max_files must be between 1 and {MAX_INITIAL_WORK_FILES}"
        )
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_INITIAL_WORK_BYTES:
        raise InitialProjectWorkError(
            f"max_bytes must be between 1 and {MAX_INITIAL_WORK_BYTES}"
        )


def _validated_plan(root: Path, value: Mapping[str, Any]) -> dict[str, Any]:
    if not root.is_dir():
        raise InitialProjectWorkError("project root must be an existing directory")
    if not isinstance(value, Mapping):
        raise InitialProjectWorkError("resolved plan must be a mapping")
    try:
        plan = load_json_strict(root / ".promin" / "generated" / "resolved-plan.json")
        supplied = canonical_bytes(dict(value))
    except (CanonicalError, OSError, TypeError, ValueError) as exc:
        raise InitialProjectWorkError("persisted resolved plan is unavailable") from exc
    if not isinstance(plan, dict) or canonical_bytes(plan) != supplied:
        raise InitialProjectWorkError("persisted resolved plan differs from supplied plan")
    if plan.get("record_type") != "ResolvedInitPlan" or plan.get("plan_version") != 1:
        raise InitialProjectWorkError("resolved plan identity is invalid")
    identity = {key: item for key, item in plan.items() if key != "plan_digest"}
    if plan.get("plan_digest") != digest_value(identity):
        raise InitialProjectWorkError("resolved plan digest mismatch")
    if plan.get("project_root") != ".":
        raise InitialProjectWorkError("resolved plan must describe the selected root")
    try:
        activation = load_json_strict(root / ".promin" / "init" / "activation.json")
    except (CanonicalError, OSError) as exc:
        raise InitialProjectWorkError("initialized activation is unavailable") from exc
    if not isinstance(activation, dict) or not isinstance(
        activation.get("activation_digest"), str
    ):
        raise InitialProjectWorkError("initialized activation is invalid")
    plan["_activation_digest"] = activation["activation_digest"]
    return plan


def _operation_ids(plan: Mapping[str, Any]) -> list[str]:
    declared = plan.get("planned_operations")
    if not isinstance(declared, list):
        raise InitialProjectWorkError("resolved plan has no declared operations")
    selected: list[str] = []
    for item in declared:
        if not isinstance(item, Mapping) or not isinstance(item.get("operation_id"), str):
            raise InitialProjectWorkError("resolved plan operation is invalid")
        operation_id = str(item["operation_id"])
        if operation_id == "initialize-control-layer":
            continue
        selected.append(operation_id)
    if not selected:
        raise InitialProjectWorkError("resolved plan has no initial work")
    return selected


def _workflow_plan(
    plan: Mapping[str, Any], operations: list[str], max_files: int, max_bytes: int
) -> dict[str, Any]:
    identity = {
        "schema": INITIAL_PROJECT_WORK_SCHEMA,
        "record_type": "InitialProjectWorkPlanIdentity",
        "project_id": plan["project_id"],
        "plan_digest": plan["plan_digest"],
        "activation_digest": plan["_activation_digest"],
        "operations": operations,
        "resource_limits": {
            "max_files": max_files,
            "max_content_bytes_read": max_bytes,
            "max_depth": _MAX_DEPTH,
            "max_entry_samples": _MAX_SAMPLES,
        },
        "execution_policy": "static-read-only",
        "model_required": False,
        "network_allowed": False,
        "install_allowed": False,
        "project_mutation_allowed": False,
        **_claims(),
    }
    workflow_digest = digest_value(identity)
    evidence_directory = f".promin-host/initial-work/{workflow_digest}"
    record = {
        **identity,
        "record_type": "InitialProjectWorkPlan",
        "status": "PLANNED_NO_EXECUTION",
        "workflow_digest": workflow_digest,
        "evidence_directory": evidence_directory,
        "writes_planned": [evidence_directory],
        "execution_performed": False,
    }
    return {**record, "work_plan_digest": digest_value(record)}


def _sorted_entries(directory: Path, limit: int) -> tuple[list[os.DirEntry[str]], bool]:
    entries: list[os.DirEntry[str]] = []
    try:
        with os.scandir(directory) as iterator:
            for entry in iterator:
                if len(entries) >= limit:
                    return [], True
                entries.append(entry)
    except OSError as exc:
        raise InitialProjectWorkError(f"repository directory cannot be read: {directory}") from exc
    entries.sort(key=lambda item: (item.name.casefold(), item.name.encode("utf-8")))
    return entries, False


def _digest_file(path: Path, expected_size: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    observed_size = 0
    try:
        with path.open("rb") as handle:
            while observed_size <= expected_size:
                chunk = handle.read(min(64 * 1024, expected_size + 1 - observed_size))
                if not chunk:
                    break
                observed_size += len(chunk)
                if observed_size > expected_size:
                    break
                digest.update(chunk)
    except OSError as exc:
        raise InitialProjectWorkError(f"repository file cannot be read: {path}") from exc
    if observed_size != expected_size:
        raise InitialProjectWorkError(f"repository file changed while read: {path}")
    return digest.hexdigest(), observed_size


def _inventory(root: Path, plan: Mapping[str, Any], max_files: int, max_bytes: int) -> dict[str, Any]:
    pending: deque[tuple[Path, int]] = deque([(root, 0)])
    samples: list[dict[str, Any]] = []
    suffixes: Counter[str] = Counter()
    row_digest = hashlib.sha256()
    row_digest.update(b"[")
    entry_count = 0
    content_bytes = 0
    directories = 1
    max_directories = max_files + 256
    truncated = False
    reason: str | None = None

    while pending and not truncated:
        directory, depth = pending.popleft()
        remaining_entries = (
            max_files - entry_count + max_directories - directories
        )
        entries, too_many = _sorted_entries(directory, remaining_entries)
        if too_many:
            truncated, reason = True, "max_entries"
            break
        for entry in entries:
            relative = Path(entry.path).relative_to(root).as_posix()
            if entry.is_dir(follow_symlinks=False):
                if entry.name.casefold() in _IGNORED_DIRECTORIES:
                    continue
                if depth >= _MAX_DEPTH:
                    truncated, reason = True, "max_depth"
                    break
                directories += 1
                if directories > max_directories:
                    truncated, reason = True, "max_directories"
                    break
                pending.append((Path(entry.path), depth + 1))
                continue
            if not entry.is_file(follow_symlinks=False):
                continue
            if entry_count >= max_files:
                truncated, reason = True, "max_files"
                break
            try:
                size = entry.stat(follow_symlinks=False).st_size
            except OSError as exc:
                raise InitialProjectWorkError(f"repository file cannot be inspected: {relative}") from exc
            if size > max_bytes - content_bytes:
                truncated, reason = True, "max_bytes"
                break
            sha256, bytes_read = _digest_file(Path(entry.path), size)
            content_bytes += bytes_read
            suffix = PurePosixPath(relative).suffix.casefold() or "<none>"
            suffixes[suffix] += 1
            row = {
                "path": relative,
                "size_bytes": size,
                "sha256": sha256,
                "suffix": suffix,
            }
            if entry_count:
                row_digest.update(b",")
            row_digest.update(canonical_bytes(row)[:-1])
            entry_count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(row)

    row_digest.update(b"]\n")

    identity = {
        "schema": INITIAL_PROJECT_WORK_SCHEMA,
        "record_type": "InitialProjectInventory",
        "project_id": plan["project_id"],
        "plan_digest": plan["plan_digest"],
        "single_pass": True,
        "scan_complete": not truncated,
        "truncated": truncated,
        "truncation_reason": reason,
        "entry_count": entry_count,
        "directory_count": directories,
        "content_bytes_read": content_bytes,
        "inventory_digest": row_digest.hexdigest(),
        "entry_samples": samples,
        "entry_samples_truncated": entry_count > _MAX_SAMPLES,
        "suffix_counts": dict(sorted(suffixes.items())),
        **_claims(),
    }
    return {**identity, "observation_digest": digest_value(identity)}


def _semantic_summary(plan: Mapping[str, Any], inventory: Mapping[str, Any]) -> dict[str, Any]:
    declared = sorted(
        str(item["technology"])
        for item in plan.get("detected_technologies", [])
        if isinstance(item, Mapping) and isinstance(item.get("technology"), str)
    )
    identity = {
        "schema": INITIAL_PROJECT_WORK_SCHEMA,
        "record_type": "InitialSemanticMap",
        "project_id": plan["project_id"],
        "plan_digest": plan["plan_digest"],
        "inventory_observation_digest": inventory["observation_digest"],
        "declared_technologies": declared,
        "suffix_counts": dict(inventory["suffix_counts"]),
        "derivation": "deterministic-static-summary",
        "model_used": False,
        "network_used": False,
        **_claims(),
    }
    return {**identity, "semantic_map_digest": digest_value(identity)}


def _proposal(
    workflow: Mapping[str, Any], plan: Mapping[str, Any], baseline_digest: str
) -> dict[str, Any]:
    paths = [
        value
        for key in ("work_sources", "references")
        for value in plan.get(key, [])
        if isinstance(value, str)
    ]
    paths = list(dict.fromkeys(paths))[:64] or ["."]
    identity = {
        "schema": INITIAL_PROJECT_WORK_SCHEMA,
        "record_type": "SuggestedWorkCard",
        "status": "PROPOSAL_ONLY",
        "proposal_id": f"initial-work:{str(workflow['workflow_digest'])[:24]}",
        "workflow_digest": workflow["workflow_digest"],
        "plan_digest": plan["plan_digest"],
        "baseline_kind": "inventory-semantic-map",
        "baseline_digest": baseline_digest,
        "goal": plan.get("goal"),
        "objective": "Review the initial evidence and select the next project-owned work.",
        "task_shape": "direct-or-decomposed-dag",
        "allowed_path_mode": "read-only-observation",
        "allowed_paths": paths,
        "mutation_allowed_paths": [],
        "allowed_tools": [
            {"tool_id": "filesystem-metadata-read", "mode": "read-only", "network": False},
            {"tool_id": "bounded-text-read", "mode": "read-only", "network": False},
            {"tool_id": "static-exact-search", "mode": "read-only", "network": False},
        ],
        "evidence_requirements": [
            {"requirement_id": "baseline-binding", "predicate": f"baseline digest remains {baseline_digest}"},
            {"requirement_id": "fresh-result-evidence", "predicate": "record fresh result evidence for selected work"},
        ],
        "failure_conditions": [
            "the baseline changes before work is selected",
            "required evidence is missing or failed",
        ],
        "task": None,
        "grant": None,
        "lease": None,
        "model_required": False,
        "network_allowed": False,
        "install_allowed": False,
        "mutation_authorized": False,
        "package_defined_task": False,
        "external_proposal_only": True,
        **_claims(),
    }
    return {**identity, "proposal_digest": digest_value(identity)}


def _artifact(name: str, payload: bytes) -> dict[str, Any]:
    return {"path": name, "sha256": digest_bytes(payload), "bytes": len(payload)}


def _file_matches(path: Path, expected: bytes) -> bool:
    offset = 0
    try:
        with path.open("rb") as handle:
            while offset < len(expected):
                chunk = handle.read(min(64 * 1024, len(expected) - offset))
                if not chunk or chunk != expected[offset : offset + len(chunk)]:
                    return False
                offset += len(chunk)
            return handle.read(1) == b""
    except OSError:
        return False


def _payloads_match(directory: Path, payloads: Mapping[str, bytes]) -> bool:
    names: set[str] = set()
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if len(names) >= len(payloads) or not entry.is_file(follow_symlinks=False):
                    return False
                names.add(entry.name)
    except OSError:
        return False
    if names != set(payloads):
        return False
    return all(_file_matches(directory / name, payloads[name]) for name in names)


def _publish(root: Path, workflow_digest: str, payloads: Mapping[str, bytes]) -> Path:
    parent = root / ".promin-host" / "initial-work"
    parent.mkdir(parents=True, exist_ok=True)
    destination = parent / workflow_digest
    if destination.exists():
        if not destination.is_dir() or not _payloads_match(destination, payloads):
            raise InitialProjectWorkError("existing evidence differs from this workflow")
        return destination
    staging = Path(tempfile.mkdtemp(prefix=f".{workflow_digest[:12]}-", dir=parent))
    try:
        for name, payload in payloads.items():
            (staging / name).write_bytes(payload)
        staging.rename(destination)
    except OSError as exc:
        if destination.is_dir() and _payloads_match(destination, payloads):
            return destination
        raise InitialProjectWorkError("initial-work evidence cannot be published") from exc
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return destination


def prepare_initial_project_work(
    project_root: Path | str,
    resolved_plan: Mapping[str, Any],
    *,
    execute: bool = False,
    max_files: int = DEFAULT_INITIAL_WORK_MAX_FILES,
    max_bytes: int = DEFAULT_INITIAL_WORK_MAX_BYTES,
) -> dict[str, Any]:
    """Plan or explicitly execute the bounded, read-only initial work route."""

    if type(execute) is not bool:
        raise InitialProjectWorkError("execute must be boolean")
    _validate_limits(max_files, max_bytes)
    root = Path(project_root).absolute()
    plan = _validated_plan(root, resolved_plan)
    operations = _operation_ids(plan)
    workflow = _workflow_plan(plan, operations, max_files, max_bytes)
    if not execute:
        return workflow

    inventory = _inventory(root, plan, max_files, max_bytes)
    semantic = _semantic_summary(plan, inventory)
    proposal = _proposal(workflow, plan, str(semantic["semantic_map_digest"]))
    payloads = {
        "workflow-plan.json": canonical_bytes(workflow),
        "inventory.json": canonical_bytes(inventory),
        "semantic-map.json": canonical_bytes(semantic),
        "suggested-work-card.json": canonical_bytes(proposal),
    }
    manifest = [_artifact(name, payload) for name, payload in payloads.items()]
    if inventory["truncated"]:
        identity = {
            "schema": INITIAL_PROJECT_WORK_SCHEMA,
            "record_type": "InitialProjectWorkFailure",
            "status": "INCOMPLETE_RESOURCE_LIMIT",
            "workflow_digest": workflow["workflow_digest"],
            "evidence_directory": workflow["evidence_directory"],
            "operations_completed": [operations[0]],
            "failed_operation": operations[0],
            "failure_reason": inventory["truncation_reason"],
            "resource_limits": workflow["resource_limits"],
            "recoverable_with_new_limits": True,
            "artifact_manifest": manifest,
            "suggested_work_card": None,
            "mutation_authorized": False,
            "package_defined_task": False,
            **_claims(),
        }
        result = {**identity, "failure_digest": digest_value(identity)}
        payloads["failure.json"] = canonical_bytes(result)
    else:
        identity = {
            "schema": INITIAL_PROJECT_WORK_SCHEMA,
            "record_type": "InitialProjectWorkResult",
            "status": "READY_PROPOSAL_ONLY",
            "workflow_digest": workflow["workflow_digest"],
            "evidence_directory": workflow["evidence_directory"],
            "operations_completed": operations,
            "artifact_manifest": manifest,
            "suggested_work_card": proposal,
            "execution_performed": True,
            "project_mutation_performed": False,
            "mutation_authorized": False,
            "package_defined_task": False,
            **_claims(),
        }
        result = {**identity, "result_digest": digest_value(identity)}
        payloads["result.json"] = canonical_bytes(result)
    _publish(root, str(workflow["workflow_digest"]), payloads)
    return result


__all__ = [
    "DEFAULT_INITIAL_WORK_MAX_BYTES",
    "DEFAULT_INITIAL_WORK_MAX_FILES",
    "INITIAL_PROJECT_WORK_SCHEMA",
    "InitialProjectWorkError",
    "MAX_INITIAL_WORK_BYTES",
    "MAX_INITIAL_WORK_FILES",
    "prepare_initial_project_work",
]
