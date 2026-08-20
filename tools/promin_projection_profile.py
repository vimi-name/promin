"""Bounded diagnostic profiling for the disposable Promin projection.

This tool deliberately does not produce performance pass credit.  It builds
canonical synthetic inventory and event streams at the fixed 1k, 4k, and 10k
sizes, then invokes the real public ``Projection.rebuild`` seam twice.  SQLite
tracing is observational instrumentation around that seam; projection code is
not replaced and the resulting database is queried independently afterwards.

The profile is a microbenchmark and is not a substitute for the 100k physical
saturation route or for product/release acceptance evidence.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import os
import platform
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar

# Direct execution places ``tools`` ahead of the package root and would make
# tools/promin.py shadow the actual ``promin`` package.  Match the other
# standalone package tools by binding the repository/package root explicitly.
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from promin.canonical import canonical_bytes, digest_value, load_json_strict
from promin.contracts import validate_definition
from promin.events import (
    CommitReadView,
    CommitStateSnapshot,
    EventStore,
    EventStorePolicy,
    PreparedCommit,
    command_intent_identity,
    parse_timestamp,
    state_binding_leaf_id,
    state_binding_value_digest,
)
from promin.projection import (
    Projection,
    ProjectionLimits,
    VerifiedInventoryInput,
    compile_relation_domains,
)
from promin.version import standard_version


FIXED_PROFILE_SIZES = (1_000, 4_000, 10_000)
PROFILE_PROTOCOL_VERSION = 1
SEMANTIC_SHARD_COUNT = 256
RSS_SAMPLE_INTERVAL_SECONDS = 0.01
CREATED_AT = "2026-08-12T00:00:00Z"
SUBJECT_ID = "subject:projection-profile"
ACTIVATION_DIGEST = digest_value(
    {"tool": "promin_projection_profile", "binding": "synthetic-activation-v1"}
)
ACTIVATION_RECORD_DIGEST = digest_value(
    {"tool": "promin_projection_profile", "binding": "synthetic-activation-record-v1"}
)
IMPLEMENTATION_CLOSURE_DIGEST = digest_value(
    {"tool": "promin_projection_profile", "binding": "implementation-closure-v1"}
)
CANDIDATE_DIGEST = digest_value(
    {"tool": "promin_projection_profile", "binding": "synthetic-candidate-v1"}
)
AUTHORITY_INIT_DIGEST = digest_value(
    {"tool": "promin_projection_profile", "binding": "synthetic-authority-v1"}
)
TOKEN_KEY = hashlib.sha256(b"promin-projection-profile-token-key-v1").digest()
TOOL_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
RUNTIME_SOURCE_SHA256 = {
    relative: hashlib.sha256((PACKAGE_ROOT / relative).read_bytes()).hexdigest()
    for relative in (
        "promin/canonical.py",
        "promin/contracts.py",
        "promin/events.py",
        "promin/projection.py",
    )
}

_T = TypeVar("_T")
_SQL_TRACE_LOCK = threading.RLock()
_SQL_OPERATION = re.compile(r"^([A-Z]+)\b")
_SEMANTIC_SHARD_VALUE = re.compile(
    r"^INSERT INTO SEMANTIC_SHARDS\([^)]*\) VALUES \((\d+),",
    re.IGNORECASE,
)
_SEMANTIC_ROW_WRITE = re.compile(
    r"^INSERT(?: OR REPLACE)? INTO SEMANTIC_ROWS\b",
    re.IGNORECASE,
)


class ProfileError(RuntimeError):
    """Raised when the diagnostic fixture or measurement is invalid."""


@dataclass(frozen=True)
class _RuntimeContracts:
    schema: Mapping[str, Any]
    schema_digest: str
    event_policy: EventStorePolicy
    projection_limits: ProjectionLimits
    relation_domains: Mapping[str, tuple[frozenset[str], frozenset[str]]]


@dataclass
class _SqlTrace:
    statement_count: int = 0
    operations: Counter[str] = field(default_factory=Counter)
    semantic_row_write_statements: int = 0
    semantic_shard_recomputations: int = 0
    semantic_shard_indices: set[int] = field(default_factory=set)
    connection_total_changes: int = 0

    def observe(self, statement: str) -> None:
        normalized = " ".join(statement.strip().split())
        if not normalized:
            return
        self.statement_count += 1
        upper = normalized.upper()
        match = _SQL_OPERATION.match(upper)
        self.operations[match.group(1) if match else "OTHER"] += 1
        if _SEMANTIC_ROW_WRITE.match(normalized):
            self.semantic_row_write_statements += 1
        if upper.startswith("INSERT INTO SEMANTIC_SHARDS"):
            self.semantic_shard_recomputations += 1
            shard = _SEMANTIC_SHARD_VALUE.match(normalized)
            if shard is not None:
                self.semantic_shard_indices.add(int(shard.group(1)))

    def as_dict(self) -> dict[str, Any]:
        indices = sorted(self.semantic_shard_indices)
        return {
            "trace_api": "sqlite3.Connection.set_trace_callback",
            "statement_count": self.statement_count,
            "statements_by_operation": dict(sorted(self.operations.items())),
            "connection_total_changes": self.connection_total_changes,
            "semantic_row_write_statements": self.semantic_row_write_statements,
            "semantic_shard_recomputations": self.semantic_shard_recomputations,
            "semantic_shard_unique_count": len(indices),
            "semantic_shard_min": indices[0] if indices else None,
            "semantic_shard_max": indices[-1] if indices else None,
            "semantic_shard_full_coverage_observed": indices
            == list(range(SEMANTIC_SHARD_COUNT)),
        }


class _SqliteModuleProxy:
    """Delegate sqlite3 except for one traced connection factory."""

    def __init__(self, trace: _SqlTrace):
        self._trace = trace

    def connect(self, *args: Any, **kwargs: Any) -> sqlite3.Connection:
        trace = self._trace

        class TracedConnection(sqlite3.Connection):
            def __init__(self, *connection_args: Any, **connection_kwargs: Any):
                super().__init__(*connection_args, **connection_kwargs)
                self.set_trace_callback(trace.observe)

            def close(self) -> None:
                trace.connection_total_changes += self.total_changes
                super().close()

        if "factory" in kwargs:
            raise ProfileError("projection supplied an unexpected SQLite connection factory")
        return sqlite3.connect(*args, factory=TracedConnection, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(sqlite3, name)


@contextlib.contextmanager
def _trace_projection_sql(trace: _SqlTrace) -> Iterable[None]:
    """Observe SQL while preserving the public rebuild implementation."""

    import promin.projection as projection_runtime

    with _SQL_TRACE_LOCK:
        original = projection_runtime.sqlite3
        projection_runtime.sqlite3 = _SqliteModuleProxy(trace)  # type: ignore[assignment]
        try:
            yield
        finally:
            projection_runtime.sqlite3 = original


def _windows_rss_bytes() -> int | None:
    if os.name != "nt":
        return None

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
            ("PrivateUsage", ctypes.c_size_t),
        ]

    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        psapi.GetProcessMemoryInfo.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ProcessMemoryCounters),
            ctypes.c_ulong,
        ]
        psapi.GetProcessMemoryInfo.restype = ctypes.c_int
        process = kernel32.GetCurrentProcess()
        accepted = psapi.GetProcessMemoryInfo(
            process,
            ctypes.byref(counters),
            counters.cb,
        )
    except (AttributeError, OSError):
        return None
    return int(counters.WorkingSetSize) if accepted else None


def _current_rss_bytes() -> int | None:
    windows = _windows_rss_bytes()
    if windows is not None:
        return windows
    statm = Path("/proc/self/statm")
    try:
        fields = statm.read_text(encoding="ascii").split()
        if len(fields) >= 2:
            return int(fields[1]) * int(os.sysconf("SC_PAGE_SIZE"))
    except (OSError, ValueError):
        pass
    try:
        import resource

        maximum = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        return maximum if sys.platform == "darwin" else maximum * 1024
    except (ImportError, OSError, ValueError):
        return None


def _measure_phase(
    phase: str,
    operation: Callable[[], _T],
) -> tuple[_T, dict[str, Any]]:
    baseline = _current_rss_bytes()
    samples: list[int] = [] if baseline is None else [baseline]
    stopped = threading.Event()

    def sample() -> None:
        while not stopped.wait(RSS_SAMPLE_INTERVAL_SECONDS):
            value = _current_rss_bytes()
            if value is not None:
                samples.append(value)

    sampler = threading.Thread(
        target=sample,
        name=f"promin-profile-rss-{phase}",
        daemon=True,
    )
    sampler.start()
    wall_started = time.perf_counter_ns()
    cpu_started = time.process_time_ns()
    try:
        result = operation()
    finally:
        cpu_finished = time.process_time_ns()
        wall_finished = time.perf_counter_ns()
        stopped.set()
        sampler.join(timeout=1.0)
        terminal = _current_rss_bytes()
        if terminal is not None:
            samples.append(terminal)
    peak = max(samples) if samples else None
    return result, {
        "phase": phase,
        "wall_ns": wall_finished - wall_started,
        "cpu_ns": cpu_finished - cpu_started,
        "rss_supported": peak is not None,
        "rss_baseline_bytes": baseline,
        "rss_peak_bytes": peak,
        "rss_terminal_bytes": terminal,
        "rss_incremental_peak_bytes": (
            max(0, peak - baseline)
            if peak is not None and baseline is not None
            else None
        ),
        "rss_sample_count": len(samples),
        "rss_sample_interval_ms": round(RSS_SAMPLE_INTERVAL_SECONDS * 1000, 3),
    }


def _compiled_event_store_policy(
    authority: Mapping[str, Any],
    semantic: Mapping[str, Any],
) -> EventStorePolicy:
    event = authority["event_contract"]
    mutation = authority["command_mutation_claim_rule"]
    identity: dict[str, Any] = {
        "record_type": "EventStorePolicy",
        "authority_model_digest": digest_value(authority),
        "max_command_bytes": event["command_bytes_max"],
        "max_envelope_bytes": event["envelope_bytes_max"],
        "max_state_binding_bytes": event["state_binding_bytes_max"],
        "max_state_binding_updates_per_batch": event[
            "state_binding_updates_per_batch_max"
        ],
        "max_events_per_batch": event["events_per_batch_max"],
        "max_requested_scope_items": authority["scope_contract"][
            "requested_scope_items_max"
        ],
        "derived_tail_batch_threshold": event["derived_tail_batch_threshold"],
        "derived_tail_byte_threshold": event["derived_tail_byte_threshold"],
        "runtime_overlay_compaction_depth": event[
            "runtime_overlay_compaction_depth"
        ],
        "command_required_fields": event["command_required_fields"],
        "command_conditional_fields": event["command_conditional_fields"],
        "command_mutation_fields": mutation["required_command_fields"],
        "lease_bound_command_kinds": mutation["lease_bound_command_kinds"],
        "lease_bound_task_transition_states": mutation[
            "lease_bound_task_transition_states"
        ],
        "command_to_primary_event": [
            [command_kind, event_kind]
            for command_kind, event_kind in event["command_to_primary_event"].items()
        ],
        "allowed_state_binding_leaf_types": [
            "Activation",
            *[item["kind"] for item in semantic["persistent_entities"]],
            "Relation",
        ],
        "state_binding_identity_rules": event["state_binding_identity_rules"],
        "state_binding_algorithm_contract": event[
            "state_binding_algorithm_contract"
        ],
        "state_binding_value_rules": event["state_binding_value_rules"],
        "canonical_timestamp_contract": authority[
            "canonical_timestamp_contract"
        ],
        "genesis_previous_authority_commitment": event[
            "genesis_previous_authority_commitment"
        ],
        "genesis_event_semantic_digest": event["genesis_event_semantic_digest"],
    }
    return EventStorePolicy.from_compiled(
        {**identity, "policy_digest": digest_value(identity)}
    )


def _projection_limits(
    event_policy: EventStorePolicy,
    *,
    authority: Mapping[str, Any],
    semantic: Mapping[str, Any],
    conformance: Mapping[str, Any],
    policy_set: Mapping[str, Any],
    preset: Mapping[str, Any],
) -> ProjectionLimits:
    continuation = authority["continuation_access_rule"]
    selected_profile_id = "extended"
    selected_profile = preset["profiles"][selected_profile_id]
    owner: dict[str, Any] = {
        "record_type": "ProjectionLimits",
        "token_version": continuation["token_version"],
        "ranking_algorithm_id": continuation["ranking_algorithm_id"],
        "traversal_algorithm_id": continuation["traversal_algorithm_id"],
        "dependency_depth_hard_max": conformance["dependency_depth_hard_max"],
        "continuation_ttl_seconds_max": continuation["ttl_seconds_max"],
        "selected_profile_id": selected_profile_id,
        "selected_profile_digest": digest_value(selected_profile),
        "persistent_entity_types": [
            item["kind"] for item in semantic["persistent_entities"]
        ],
        "default_budget": {
            "max_bytes": selected_profile["max_context_bytes"],
            "max_entities": selected_profile["max_entities"],
            "max_relations": selected_profile["max_relations"],
            "max_fanout_per_entity": selected_profile[
                "max_fanout_per_entity"
            ],
            "top_k": selected_profile["top_k"],
        },
        "hard_budget": conformance["workcard_hard_ceiling"],
        "default_depth": selected_profile["default_dependency_depth"],
        "depth_min": continuation["depth_min"],
        "depth_max": conformance["dependency_depth_hard_max"],
        "default_ttl_seconds": continuation["default_ttl_seconds"],
        "ttl_min_seconds": continuation["ttl_min_seconds"],
        "ttl_max_seconds": continuation["ttl_seconds_max"],
        "max_token_bytes": conformance["scale_contracts"]["workcard"][
            "continuation_token_bytes_max"
        ],
        "max_continuation_state_bytes": conformance["scale_contracts"][
            "workcard"
        ]["continuation_state_bytes_max"],
        "max_query_bytes": policy_set["derived_result_contracts"][
            "RetrievalPage"
        ]["query_bytes_max"],
        "min_result_bytes": continuation["min_result_bytes"],
        "max_resume_binding_fields": continuation["max_resume_binding_fields"],
        "max_resume_binding_key_chars": continuation[
            "max_resume_binding_key_chars"
        ],
        "max_resume_binding_value_bytes": continuation[
            "max_resume_binding_value_bytes"
        ],
        "max_resume_binding_bytes": continuation["max_resume_binding_bytes"],
        "required_resume_binding_fields": continuation[
            "required_resume_binding_fields"
        ],
    }
    runtime = {
        **owner,
        "persistent_entity_types": tuple(owner["persistent_entity_types"]),
        "required_resume_binding_fields": tuple(
            owner["required_resume_binding_fields"]
        ),
    }
    return ProjectionLimits(
        **runtime,
        policy_digest=digest_value(owner),
        event_store_policy=event_policy,
    )


def _compile_runtime_contracts() -> _RuntimeContracts:
    core = PACKAGE_ROOT / "core"
    schema = load_json_strict(core / "contracts.schema.json")
    authority = load_json_strict(core / "authority-model.json")
    semantic = load_json_strict(core / "semantic-model.json")
    conformance = load_json_strict(core / "conformance.json")
    policy_set = load_json_strict(core / "policy-set.json")
    preset = load_json_strict(PACKAGE_ROOT / "presets" / "semantic-standard.json")
    event_policy = _compiled_event_store_policy(authority, semantic)
    return _RuntimeContracts(
        schema=schema,
        schema_digest=digest_value(schema),
        event_policy=event_policy,
        projection_limits=_projection_limits(
            event_policy,
            authority=authority,
            semantic=semantic,
            conformance=conformance,
            policy_set=policy_set,
            preset=preset,
        ),
        relation_domains=compile_relation_domains(semantic),
    )


def _artifact_id(index: int) -> str:
    path = f"product/record-{index:08d}.txt"
    return "artifact:file:" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:48]


def _build_inventory_stream(
    root: Path,
    size: int,
) -> tuple[VerifiedInventoryInput, dict[str, Any]]:
    path = root / "inventory.jsonl"
    stream_digest = hashlib.sha256()
    identity_digest = hashlib.sha256()
    total_bytes = 0
    with path.open("xb") as output:
        for index in range(size):
            relative = f"product/record-{index:08d}.txt"
            file_digest = hashlib.sha256(
                f"projection-profile-payload-{index:08d}".encode("utf-8")
            ).hexdigest()
            row = {
                "path": relative,
                "digest": file_digest,
                "size": index % 4096 + 1,
                "search_text": f"projection profile synthetic source {index:08d}",
            }
            encoded = canonical_bytes(row)
            output.write(encoded)
            stream_digest.update(encoded)
            identity_digest.update(
                canonical_bytes(
                    {
                        "path": row["path"],
                        "digest": row["digest"],
                        "size": row["size"],
                    }
                )
            )
            total_bytes += len(encoded)
        output.flush()
        os.fsync(output.fileno())
    manifest_identity = {
        "record_type": "ProjectionProfileInventoryManifest",
        "entry_count": size,
        "stream_digest": stream_digest.hexdigest(),
        "stream_bytes": total_bytes,
        "inventory_digest": identity_digest.hexdigest(),
        "diagnostic_only": True,
        "pass_credit": False,
    }
    inventory = VerifiedInventoryInput(
        activation_digest=ACTIVATION_DIGEST,
        stream_digest=stream_digest.hexdigest(),
        inventory_digest=identity_digest.hexdigest(),
        entry_count=size,
        stream_path=path,
        stream_bytes=total_bytes,
        manifest_digest=digest_value(manifest_identity),
        observed_at=CREATED_AT,
        product_tree_passes=1,
    )
    return inventory, {
        "entry_count": size,
        "stream_bytes": total_bytes,
        "stream_digest": stream_digest.hexdigest(),
        "inventory_digest": identity_digest.hexdigest(),
        "manifest_digest": digest_value(manifest_identity),
        "canonical_jsonl": True,
    }


def _task(batch_index: int, defined_at_head: str | None) -> dict[str, Any]:
    task_id = f"task:projection-profile:{batch_index:08d}"
    base: dict[str, Any] = {
        "record_type": "Task",
        "task_id": task_id,
        "state": "PLANNED",
        "required_capability": "task.execute",
        "acceptance_predicate": (
            f"diagnostic projection profile batch {batch_index:08d}"
        ),
        "allowed_paths": ["product/**"],
        "activation_digest": ACTIVATION_DIGEST,
        "candidate_digest": CANDIDATE_DIGEST,
        "created_at": CREATED_AT,
    }
    owner_digest = digest_value(
        {key: value for key, value in base.items() if key != "state"}
    )
    definition = {
        "definition_kind": "GateRunDefinition",
        "definition_id": f"definition:projection-profile:{batch_index:08d}",
        "owner_kind": "Task",
        "owner_digest": owner_digest,
        "defined_at_head_digest": defined_at_head,
        "gate_id": f"gate:projection-profile:{batch_index:08d}",
        "run_kind": "validation",
        "expected_evidence_class": "validator",
        "expected_evidence_purpose": "diagnostic",
        "product_credit_required": False,
        "target_kind": "candidate",
        "target_digest": CANDIDATE_DIGEST,
        "target_scope": [
            {"kind": "candidate", "value": CANDIDATE_DIGEST}
        ],
        "candidate_digest": CANDIDATE_DIGEST,
        "policy_digest": digest_value(
            {"tool": "promin_projection_profile", "policy": "diagnostic-only-v1"}
        ),
        "tool_digest": _tool_digest(),
        "implementation_closure_digest": IMPLEMENTATION_CLOSURE_DIGEST,
        "provider_binding_digest": digest_value(
            {"provider": "local-python", "diagnostic_only": True}
        ),
        "input_digests": [digest_value({"batch_index": batch_index})],
        "activation_digest": ACTIVATION_DIGEST,
    }
    base["gate_run_definitions"] = [
        {"definition_digest": digest_value(definition), "definition": definition}
    ]
    return base


def _relation(index: int, *, source_id: str, target_index: int) -> dict[str, Any]:
    return {
        "record_type": "Relation",
        "relation_id": f"relation:projection-profile:{index:08d}",
        "kind": "READS",
        "source_type": "Task",
        "source_id": source_id,
        "target_type": "Artifact",
        "target_id": _artifact_id(target_index),
        "activation_digest": ACTIVATION_DIGEST,
        "created_at": CREATED_AT,
    }


def _command(
    batch_index: int,
    task: Mapping[str, Any],
    expected_head: str | None,
) -> dict[str, Any]:
    command: dict[str, Any] = {
        "record_type": "CommandRequest",
        "command_id": f"command:projection-profile:{batch_index:08d}",
        "command_kind": "task.record",
        "subject_id": SUBJECT_ID,
        "activation_digest": ACTIVATION_DIGEST,
        "idempotency_key": f"idempotency:projection-profile:{batch_index:08d}",
        "requested_scope": [{"kind": "task", "value": task["task_id"]}],
        "expected_head_digest": expected_head,
        "issued_at": CREATED_AT,
        "payload": dict(task),
        "authorization": {
            "kind": "root",
            "subject_id": SUBJECT_ID,
            "proofs": [
                {
                    "kind": "local-root-command",
                    "subject_id": SUBJECT_ID,
                    "authority_init_digest": AUTHORITY_INIT_DIGEST,
                    "signed_intent_digest": "0" * 64,
                }
            ],
        },
    }
    command["intent_digest"] = digest_value(command_intent_identity(command))
    command["authorization"]["proofs"][0]["signed_intent_digest"] = command[
        "intent_digest"
    ]
    return command


def _candidate() -> dict[str, Any]:
    inventory_digest = digest_value(
        {"tool": "promin_projection_profile", "source": "synthetic-inventory-v1"}
    )
    product_root_digest = digest_value(
        {"tool": "promin_projection_profile", "source": "synthetic-product-v1"}
    )
    return {
        "record_type": "Candidate",
        "candidate_id": "candidate:projection-profile",
        "candidate_digest": CANDIDATE_DIGEST,
        "inventory_digest": inventory_digest,
        "product_root_digest": product_root_digest,
        "control_excluded": True,
        "candidate_recipe_digest": digest_value(
            {"tool": "promin_projection_profile", "recipe": "synthetic-v1"}
        ),
        "consistency_mode": "observational-best-effort",
        "creditable": False,
        "baseline_kind": "product",
    }


def _candidate_command(candidate: Mapping[str, Any]) -> dict[str, Any]:
    command: dict[str, Any] = {
        "record_type": "CommandRequest",
        "command_id": "command:projection-profile:candidate",
        "command_kind": "candidate.record",
        "subject_id": SUBJECT_ID,
        "activation_digest": ACTIVATION_DIGEST,
        "idempotency_key": "idempotency:projection-profile:candidate",
        "requested_scope": [
            {"kind": "candidate", "value": candidate["candidate_id"]}
        ],
        "expected_head_digest": None,
        "issued_at": CREATED_AT,
        "payload": dict(candidate),
        "authorization": {
            "kind": "root",
            "subject_id": SUBJECT_ID,
            "proofs": [
                {
                    "kind": "local-root-command",
                    "subject_id": SUBJECT_ID,
                    "authority_init_digest": AUTHORITY_INIT_DIGEST,
                    "signed_intent_digest": "0" * 64,
                }
            ],
        },
    }
    command["intent_digest"] = digest_value(command_intent_identity(command))
    command["authorization"]["proofs"][0]["signed_intent_digest"] = command[
        "intent_digest"
    ]
    return command


def _state_update(
    policy: EventStorePolicy,
    value: Mapping[str, Any],
    *,
    event_kind: str,
) -> dict[str, Any]:
    record_type = str(value["record_type"])
    leaf_type = "Grant" if record_type == "GrantRevocation" else record_type
    return {
        "leaf_type": leaf_type,
        "leaf_id": state_binding_leaf_id(policy, leaf_type, value),
        "operation": "set",
        "value_digest": state_binding_value_digest(
            policy,
            leaf_type,
            value,
            event_kind=event_kind,
        ),
    }


def _event_store_callbacks(
    contracts: _RuntimeContracts,
) -> dict[str, Callable[..., Any]]:
    schema = contracts.schema
    policy = contracts.event_policy

    def compiled_record(
        definition: str,
        value: Mapping[str, Any],
        *,
        evaluation_time: str,
        operation: str,
    ) -> bool:
        del operation
        parse_timestamp(evaluation_time)
        validate_definition(schema, definition, value)
        return True

    def command_validator(
        value: Mapping[str, Any], *, evaluation_time: str
    ) -> bool:
        if value.get("issued_at") != evaluation_time:
            raise ProfileError("synthetic command evaluation time is detached")
        validate_definition(schema, "CommandRequest", value)
        return True

    def authorization_validator(
        value: Mapping[str, Any], *, evaluation_time: str
    ) -> bool:
        if value.get("issued_at") != evaluation_time:
            raise ProfileError("synthetic authorization evaluation time is detached")
        authorization = value.get("authorization")
        if not isinstance(authorization, Mapping):
            raise ProfileError("synthetic command authorization is missing")
        validate_definition(schema, "RootAuthorization", authorization)
        proofs = authorization.get("proofs")
        if (
            not isinstance(proofs, list)
            or len(proofs) != 1
            or proofs[0].get("signed_intent_digest") != value.get("intent_digest")
        ):
            raise ProfileError("synthetic root proof is not intent-bound")
        return True

    def event_validator(
        value: Mapping[str, Any],
        *,
        evaluation_time: str,
        command: Mapping[str, Any],
    ) -> bool:
        parse_timestamp(evaluation_time)
        validate_definition(schema, "Event", value)
        if value.get("activation_digest") != command.get("activation_digest"):
            raise ProfileError("synthetic Event Activation is detached")
        return True

    def load_state(
        view: CommitReadView,
        envelopes: Callable[[], Iterable[Mapping[str, Any]]],
    ) -> CommitStateSnapshot:
        batch_ids = tuple(
            envelope["batch"]["batch_id"] for envelope in envelopes()
        )
        return CommitStateSnapshot(
            batch_ids,
            view.head_sequence,
            view.head_digest,
            view.current_state_binding_digest,
        )

    def prepare_commit(
        _view: CommitReadView,
        command: Mapping[str, Any],
        relations: Iterable[Mapping[str, Any]],
    ) -> PreparedCommit:
        relation_values = tuple(dict(value) for value in relations)
        updates = [
            _state_update(
                policy,
                command["payload"],
                event_kind=policy.primary_events[str(command["command_kind"])],
            )
        ]
        updates.extend(
            _state_update(policy, value, event_kind="relation.recorded")
            for value in relation_values
        )
        updates.sort(key=lambda value: (value["leaf_type"], value["leaf_id"]))
        return PreparedCommit(relation_values, tuple(updates))

    def validate_state(
        _name: str,
        _state: Any,
        *,
        expected_binding_digest: str,
    ) -> bool:
        return bool(re.fullmatch(r"[0-9a-f]{64}", expected_binding_digest))

    return {
        "compiled_record_validator": compiled_record,
        "command_validator": command_validator,
        "authorization_validator": authorization_validator,
        "event_validator": event_validator,
        "commit_state_loader": load_state,
        "commit_prepare_callback": prepare_commit,
        "derived_state_validator": validate_state,
    }


def _build_event_stream(
    root: Path,
    size: int,
    contracts: _RuntimeContracts,
) -> tuple[EventStore, dict[str, Any]]:
    store = EventStore(
        root / "events",
        active_activation_digest=ACTIVATION_DIGEST,
        activation_record_digest=ACTIVATION_RECORD_DIGEST,
        implementation_closure_digest=IMPLEMENTATION_CLOSURE_DIGEST,
        policy=contracts.event_policy,
        **_event_store_callbacks(contracts),
    )
    candidate = _candidate()
    store.commit(
        _candidate_command(candidate),
        created_at=CREATED_AT,
    )
    remaining = size - 1
    batch_index = 1
    task_count = 0
    relation_index = 0
    maximum_relations = contracts.event_policy.max_events_per_batch - 1
    while remaining:
        relation_count = min(maximum_relations, remaining - 1)
        head = store.head()["batch_digest"]
        task = _task(batch_index, head)
        relations = tuple(
            _relation(
                relation_index + offset,
                source_id=task["task_id"],
                target_index=(relation_index + offset) % size,
            )
            for offset in range(relation_count)
        )
        store.commit(
            _command(batch_index, task, head),
            auxiliary_relations=relations,
            created_at=CREATED_AT,
        )
        batch_index += 1
        task_count += 1
        relation_index += relation_count
        remaining -= relation_count + 1
    head = store.head()
    return store, {
        "event_count": size,
        "batch_count": batch_index,
        "candidate_event_count": 1,
        "task_event_count": task_count,
        "relation_event_count": relation_index,
        "head_sequence": head["sequence"],
        "head_digest": head["batch_digest"],
        "events_per_batch_max": contracts.event_policy.max_events_per_batch,
        "schema_validated": True,
        "event_store_commit_ingress": True,
        "authorization_validation": "schema-and-intent-binding-only",
        "product_authority_claim": False,
    }


def _database_metrics(db_path: Path) -> dict[str, Any]:
    if not db_path.is_file():
        raise ProfileError("public rebuild did not publish its SQLite projection")
    connection = sqlite3.connect(str(db_path))
    try:
        row_counts: dict[str, int] = {}
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
            )
        }
        for table in (
            "metadata",
            "entities",
            "relations",
            "operational_order",
            "semantic_rows",
            "semantic_shards",
            "continuations",
            "ready_frontiers",
            "ready_frontier_items",
            "entity_fts",
        ):
            if table in tables:
                row_counts[table] = int(
                    connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
                )
        metadata = {
            str(key): str(value)
            for key, value in connection.execute(
                "SELECT key,value FROM metadata ORDER BY key"
            )
        }
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        free_pages = int(connection.execute("PRAGMA freelist_count").fetchone()[0])
        table_bytes: dict[str, int] | None
        try:
            table_bytes = {
                str(name): int(value)
                for name, value in connection.execute(
                    "SELECT name,sum(pgsize) FROM dbstat GROUP BY name ORDER BY name"
                )
            }
        except sqlite3.Error:
            table_bytes = None
    finally:
        connection.close()
    return {
        "independent_readback_connection": True,
        "file_bytes": db_path.stat().st_size,
        "page_size_bytes": page_size,
        "page_count": page_count,
        "freelist_page_count": free_pages,
        "allocated_page_bytes": page_size * page_count,
        "used_page_bytes": page_size * (page_count - free_pages),
        "row_counts": row_counts,
        "metadata": metadata,
        "dbstat_available": table_bytes is not None,
        "bytes_by_object": table_bytes,
    }


def _profile_one_rebuild(
    phase: str,
    operation: Callable[[], Mapping[str, Any]],
    db_path: Path,
) -> dict[str, Any]:
    trace = _SqlTrace()

    def invoke() -> Mapping[str, Any]:
        with _trace_projection_sql(trace):
            return operation()

    result, timing = _measure_phase(phase, invoke)
    return {
        "phase_metrics": timing,
        "public_result": dict(result),
        "sqlite_trace": trace.as_dict(),
        "sqlite_database": _database_metrics(db_path),
        "claim": False,
        "pass_credit": False,
    }


def profile_projection_rebuild(
    projection: Projection,
    event_store: EventStore,
    inventory: VerifiedInventoryInput,
) -> dict[str, Any]:
    """Measure two calls through the real public ``Projection.rebuild`` seam."""

    first = _profile_one_rebuild(
        "first-rebuild",
        lambda: projection.rebuild(event_store, inventory=inventory),
        projection.db_path,
    )
    second = _profile_one_rebuild(
        "second-rebuild",
        lambda: projection.rebuild(event_store, inventory=inventory),
        projection.db_path,
    )
    return _rebuild_comparison(
        first,
        second,
        seam="Projection.rebuild",
    )


def profile_service_rebuild(
    service: Any,
    inventory: Any,
    *,
    db_path: Path | None = None,
) -> dict[str, Any]:
    """Measure two calls through ``ProminService.rebuild`` on a prepared service.

    The caller owns preparation of the initialized service and its verified
    ``InventoryResult``.  This adapter exists so the same independent SQL and
    resource instrumentation can be applied without accessing a private service
    method.  The synthetic CLI below uses the narrower Projection public seam.
    """

    from promin.service import InventoryResult, ProminService

    if not isinstance(service, ProminService):
        raise ProfileError("service profiling requires a ProminService instance")
    if inventory is not None and not isinstance(inventory, InventoryResult):
        raise ProfileError(
            "service profiling accepts only a verified InventoryResult"
        )
    selected_db = db_path or (
        Path(service.root)
        / ".promin"
        / "state"
        / "projection"
        / "promin.sqlite3"
    )
    first = _profile_one_rebuild(
        "first-rebuild",
        lambda: service.rebuild(inventory),
        selected_db,
    )
    second = _profile_one_rebuild(
        "second-rebuild",
        lambda: service.rebuild(inventory),
        selected_db,
    )
    return _rebuild_comparison(
        first,
        second,
        seam="ProminService.rebuild",
    )


def _rebuild_comparison(
    first: Mapping[str, Any],
    second: Mapping[str, Any],
    *,
    seam: str,
) -> dict[str, Any]:
    first_phase = first["phase_metrics"]
    second_phase = second["phase_metrics"]
    first_db = first["sqlite_database"]
    second_db = second["sqlite_database"]
    first_result = first["public_result"]
    second_result = second["public_result"]

    def ratio(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 9) if denominator else None

    comparison = {
        "wall_second_over_first": ratio(
            int(second_phase["wall_ns"]), int(first_phase["wall_ns"])
        ),
        "cpu_second_over_first": ratio(
            int(second_phase["cpu_ns"]), int(first_phase["cpu_ns"])
        ),
        "database_bytes_delta": int(second_db["file_bytes"])
        - int(first_db["file_bytes"]),
        "row_counts_equal": first_db["row_counts"] == second_db["row_counts"],
        "semantic_digest_equal": first_result.get("semantic_digest")
        == second_result.get("semantic_digest"),
        "readback_semantic_digest_equal": first_db["metadata"].get(
            "semantic_digest"
        )
        == second_db["metadata"].get("semantic_digest"),
        "first_public_digest_matches_readback": first_result.get(
            "semantic_digest"
        )
        == first_db["metadata"].get("semantic_digest"),
        "second_public_digest_matches_readback": second_result.get(
            "semantic_digest"
        )
        == second_db["metadata"].get("semantic_digest"),
        "entity_count_equal": first_result.get("entity_count")
        == second_result.get("entity_count"),
        "relation_count_equal": first_result.get("relation_count")
        == second_result.get("relation_count"),
        "observational_only": True,
        "performance_claim": False,
        "pass_credit": False,
    }
    return {
        "rebuild_seam": {
            "name": seam,
            "public_method": True,
            "implementation_replaced": False,
            "sqlite_trace_observational": True,
        },
        "first": dict(first),
        "second": dict(second),
        "comparison": comparison,
        "claim": False,
        "pass_credit": False,
    }


def run_profile_case(work_root: Path, size: int) -> dict[str, Any]:
    """Execute one exact fixed-size synthetic profile case."""

    if size not in FIXED_PROFILE_SIZES:
        raise ProfileError(
            f"profile size must be one of {list(FIXED_PROFILE_SIZES)}"
        )
    work_root = Path(work_root).resolve()
    work_root.mkdir(parents=True, exist_ok=True)
    if any(work_root.iterdir()):
        raise ProfileError("profile work root must be empty")

    contracts, contract_phase = _measure_phase(
        "contract-compilation", _compile_runtime_contracts
    )
    inventory_result, inventory_phase = _measure_phase(
        "inventory-stream-build",
        lambda: _build_inventory_stream(work_root, size),
    )
    inventory, inventory_manifest = inventory_result
    event_result, event_phase = _measure_phase(
        "event-stream-build",
        lambda: _build_event_stream(work_root, size, contracts),
    )
    event_store, event_manifest = event_result
    projection = Projection(
        work_root / "projection" / "promin.sqlite3",
        TOKEN_KEY,
        implementation_closure_digest=IMPLEMENTATION_CLOSURE_DIGEST,
        limits=contracts.projection_limits,
        relation_domains=contracts.relation_domains,
    )
    try:
        rebuilds = profile_projection_rebuild(projection, event_store, inventory)
    finally:
        event_store.close()

    actual_first = rebuilds["first"]["public_result"]
    actual_second = rebuilds["second"]["public_result"]
    profile: dict[str, Any] = {
        "record_type": "ProminProjectionRebuildProfile",
        "protocol_version": PROFILE_PROTOCOL_VERSION,
        "status": "diagnostic-only",
        "generated_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "standard_version": standard_version(),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "os_name": os.name,
        },
        "claim": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "performance_acceptance": False,
        "public_release_approved": False,
        "workload": {
            "fixed_profile_sizes": list(FIXED_PROFILE_SIZES),
            "selected_size": size,
            "requested_inventory_rows": size,
            "actual_inventory_rows": actual_first.get("inventory_entries"),
            "requested_event_records": size,
            "actual_event_records_first": actual_first.get("event_count"),
            "actual_event_records_second": actual_second.get("event_count"),
            "workload_reduced": False,
            "physical_100k_executed": False,
            "full_saturation_substitute": False,
            "authoritative_product_workload": False,
        },
        "bindings": {
            "activation_digest": ACTIVATION_DIGEST,
            "implementation_closure_digest": IMPLEMENTATION_CLOSURE_DIGEST,
            "event_store_policy_digest": contracts.event_policy.policy_digest,
            "projection_limits_policy_digest": contracts.projection_limits.policy_digest,
            "schema_digest": contracts.schema_digest,
            "tool_sha256": _tool_digest(),
            "runtime_source_sha256": dict(RUNTIME_SOURCE_SHA256),
        },
        "setup": {
            "contract_compilation": contract_phase,
            "inventory_stream": {
                "phase_metrics": inventory_phase,
                **inventory_manifest,
            },
            "event_stream": {
                "phase_metrics": event_phase,
                **event_manifest,
            },
        },
        "rebuilds": rebuilds,
        "evidence_limits": [
            "diagnostic microbenchmark only",
            "fixed 1k/4k/10k synthetic cases only",
            "not a 100k physical saturation execution",
            "not a product workload",
            "synthetic root proof is schema/intent-bound, not product authority",
            "SQLite trace callback adds observational overhead",
            "no performance or release pass credit",
        ],
    }
    profile["report_digest"] = digest_value(profile)
    return profile


def run_profile_suite(work_root: Path, sizes: Sequence[int]) -> dict[str, Any]:
    selected = tuple(sizes)
    if not selected or any(size not in FIXED_PROFILE_SIZES for size in selected):
        raise ProfileError(
            f"suite sizes must be selected from {list(FIXED_PROFILE_SIZES)}"
        )
    if len(selected) != len(set(selected)):
        raise ProfileError("suite sizes must not contain duplicates")
    profiles = []
    for size in selected:
        profiles.append(run_profile_case(work_root / f"size-{size}", size))
    suite: dict[str, Any] = {
        "record_type": "ProminProjectionRebuildProfileSuite",
        "protocol_version": PROFILE_PROTOCOL_VERSION,
        "status": "diagnostic-only",
        "generated_at": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "standard_version": standard_version(),
        "fixed_profile_sizes": list(FIXED_PROFILE_SIZES),
        "executed_sizes": list(selected),
        "physical_100k_executed": False,
        "full_saturation_substitute": False,
        "claim": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "performance_acceptance": False,
        "public_release_approved": False,
        "profiles": profiles,
    }
    suite["report_digest"] = digest_value(suite)
    return suite


def _tool_digest() -> str:
    return TOOL_SHA256


def _write_report(path: Path | None, value: Mapping[str, Any]) -> None:
    payload = canonical_bytes(dict(value))
    if path is None:
        sys.stdout.buffer.write(payload)
        return
    destination = Path(path).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, destination)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _windows_extended_cleanup_path(path: Path) -> str:
    """Return a deletion path that preserves the full Windows path length.

    A fixed profile can legitimately create package receipts whose nested path
    exceeds the legacy Windows path ceiling when its caller supplies a deep
    ``--work-root``.  Python's default ``TemporaryDirectory`` cleanup walks
    the normal spelling, which can leave those children behind and finish with
    WinError 145.  This is only a cleanup spelling: profile inputs, output,
    and EventStore behavior remain unchanged.
    """

    resolved = str(path.resolve())
    if os.name != "nt" or resolved.startswith("\\\\?\\"):
        return resolved
    if resolved.startswith("\\\\"):
        return "\\\\?\\UNC\\" + resolved[2:]
    return "\\\\?\\" + resolved


def _cleanup_profile_workdir(temporary: tempfile.TemporaryDirectory[str]) -> None:
    """Close a disposable profile root without truncating a Windows pathname."""

    if os.name != "nt":
        temporary.cleanup()
        return
    workdir = Path(temporary.name)
    if workdir.exists():
        shutil.rmtree(_windows_extended_cleanup_path(workdir))
    # Detach TemporaryDirectory's finalizer after the extended-path deletion.
    # Its normal cleanup sees an absent root and is therefore a no-op.
    temporary.cleanup()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run bounded diagnostic Projection.rebuild profiles at exact fixed sizes; "
            "this never grants performance pass credit."
        )
    )
    parser.add_argument(
        "--size",
        action="append",
        type=int,
        choices=FIXED_PROFILE_SIZES,
        help="exact case size; repeat to select multiple (default: all fixed sizes)",
    )
    parser.add_argument("--output", type=Path, help="canonical JSON report path")
    parser.add_argument(
        "--work-root",
        type=Path,
        help="empty parent for temporary case directories (default: system temp)",
    )
    parser.add_argument(
        "--retain-workdirs",
        action="store_true",
        help="retain generated EventStore, inventory, and SQLite files for inspection",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    sizes = tuple(args.size or FIXED_PROFILE_SIZES)
    if len(sizes) != len(set(sizes)):
        raise ProfileError("--size values must not contain duplicates")
    base = None if args.work_root is None else args.work_root.resolve()
    if base is not None:
        base.mkdir(parents=True, exist_ok=True)
    if args.retain_workdirs:
        work = Path(tempfile.mkdtemp(prefix="promin-projection-profile-", dir=base))
        report = run_profile_suite(work, sizes)
        report["retained_work_root"] = str(work)
        report["report_digest"] = digest_value(
            {key: value for key, value in report.items() if key != "report_digest"}
        )
        _write_report(args.output, report)
        return 0
    temporary = tempfile.TemporaryDirectory(
        prefix="promin-projection-profile-", dir=base
    )
    try:
        work = Path(temporary.name)
        report = run_profile_suite(work, sizes)
        _write_report(args.output, report)
    finally:
        _cleanup_profile_workdir(temporary)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ProfileError, ValueError) as exc:
        print(f"promin projection profile rejected: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
