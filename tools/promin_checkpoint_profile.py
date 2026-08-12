"""Bounded, claim-free profiling for normalized runtime checkpoint storage.

This diagnostic intentionally stays below the ProminService authorization
surface.  It exercises the real EventStore commit, state-binding, tail, and
normalized SQLite checkpoint seams with schema-valid records.  Results are
measurements only: they never grant product, performance, or acceptance credit.
"""

from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import json
import os
import platform
import sqlite3
import sys
import tempfile
import threading
import time
from collections.abc import Iterable, Mapping, Sequence
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) in sys.path:
    sys.path.remove(str(PACKAGE_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT))

from promin.canonical import canonical_bytes, digest_file, digest_value
from promin.contracts import ContractError, load_contract_bundle, validate_definition
from promin.events import (
    CommitReadView,
    CommitStateSnapshot,
    EventStore,
    EventStoreError,
    EventStorePolicy,
    PreparedCommit,
    command_intent_identity,
    state_binding_leaf_id,
    state_binding_value_digest,
)


PROFILE_SCHEMA = "promin.checkpoint-profile.v1"
DEFAULT_ROW_COUNTS = (1_000, 10_000, 20_000)
DEFAULT_BATCH_SIZES = (1, 2, 127, 128)
MAX_PROFILE_ROWS = 20_000
MAX_CADENCE_BATCHES = 128
ACTIVATION_DIGEST = hashlib.sha256(b"promin-checkpoint-profile-activation").hexdigest()
ACTIVATION_RECORD_DIGEST = hashlib.sha256(
    b"promin-checkpoint-profile-activation-record"
).hexdigest()
IMPLEMENTATION_CLOSURE_DIGEST = hashlib.sha256(
    b"promin-checkpoint-profile-implementation-closure"
).hexdigest()
CANDIDATE_DIGEST = hashlib.sha256(
    b"promin-checkpoint-profile-candidate"
).hexdigest()
AUTHORITY_INIT_DIGEST = hashlib.sha256(
    b"promin-checkpoint-profile-schema-only-root"
).hexdigest()
SUBJECT_ID = "subject:checkpoint-profiler"
PROJECT_ID = "project:checkpoint-profiler"
CREATED_AT = "2026-08-12T00:00:00Z"
RELATION_SECTION = "40.relations.records"
ROW_KEY_WIDTH = 12
_RSS_READER_LOCK = threading.Lock()
_WINDOWS_RSS_READER: Any = None
TOOL_DIGEST = digest_file(Path(__file__))


class CheckpointProfileError(RuntimeError):
    """The bounded diagnostic configuration or execution is invalid."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _claims() -> dict[str, bool]:
    return {
        "claim": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "performance_acceptance": False,
        "release_eligible": False,
    }


def parse_positive_integers(
    value: str,
    *,
    label: str,
    maximum: int,
    strictly_increasing: bool,
) -> tuple[int, ...]:
    try:
        selected = tuple(int(item.strip()) for item in value.split(","))
    except ValueError as exc:
        raise CheckpointProfileError(f"{label} must be comma-separated integers") from exc
    if not selected or any(item < 1 or item > maximum for item in selected):
        raise CheckpointProfileError(
            f"{label} must contain integers from 1 through {maximum}"
        )
    if len(selected) != len(set(selected)):
        raise CheckpointProfileError(f"{label} must not contain duplicates")
    if strictly_increasing and any(
        right <= left for left, right in zip(selected, selected[1:])
    ):
        raise CheckpointProfileError(f"{label} must be strictly increasing")
    return selected


def _event_store_policy(bundle: Any) -> EventStorePolicy:
    authority = bundle.core["authority-model.json"]
    semantic = bundle.core["semantic-model.json"]
    event = authority["event_contract"]
    mutation = authority["command_mutation_claim_rule"]
    identity = {
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
        "command_required_fields": copy.deepcopy(event["command_required_fields"]),
        "command_conditional_fields": copy.deepcopy(
            event["command_conditional_fields"]
        ),
        "command_mutation_fields": copy.deepcopy(
            mutation["required_command_fields"]
        ),
        "lease_bound_command_kinds": copy.deepcopy(
            mutation["lease_bound_command_kinds"]
        ),
        "lease_bound_task_transition_states": copy.deepcopy(
            mutation["lease_bound_task_transition_states"]
        ),
        "command_to_primary_event": [
            [command_kind, event_kind]
            for command_kind, event_kind in event["command_to_primary_event"].items()
        ],
        "allowed_state_binding_leaf_types": [
            "Activation",
            *[item["kind"] for item in semantic["persistent_entities"]],
            "Relation",
        ],
        "state_binding_identity_rules": copy.deepcopy(
            event["state_binding_identity_rules"]
        ),
        "state_binding_algorithm_contract": copy.deepcopy(
            event["state_binding_algorithm_contract"]
        ),
        "state_binding_value_rules": copy.deepcopy(
            event["state_binding_value_rules"]
        ),
        "canonical_timestamp_contract": copy.deepcopy(
            authority["canonical_timestamp_contract"]
        ),
        "genesis_previous_authority_commitment": event[
            "genesis_previous_authority_commitment"
        ],
        "genesis_event_semantic_digest": event["genesis_event_semantic_digest"],
    }
    compiled = {**identity, "policy_digest": digest_value(identity)}
    validate_definition(bundle.schema, "EventStorePolicy", compiled)
    return EventStorePolicy.from_compiled(compiled)


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_thaw(item) for item in value]
    return value


def _load_commit_state(
    view: CommitReadView,
    envelopes: Any,
) -> CommitStateSnapshot:
    return CommitStateSnapshot(
        tuple(
            event["event_id"]
            for envelope in envelopes()
            for event in envelope["batch"]["events"]
        ),
        view.head_sequence,
        view.head_digest,
        view.current_state_binding_digest,
    )


def _prepare_commit(
    policy: EventStorePolicy,
    _view: CommitReadView,
    frozen_command: Mapping[str, Any],
    frozen_relations: Iterable[Mapping[str, Any]],
) -> PreparedCommit:
    command = _thaw(frozen_command)
    relations = tuple(_thaw(value) for value in frozen_relations)
    task = command["payload"]
    task_event_kind = policy.primary_events[command["command_kind"]]
    updates = [
        {
            "leaf_type": "Task",
            "leaf_id": state_binding_leaf_id(policy, "Task", task),
            "operation": "set",
            "value_digest": state_binding_value_digest(
                policy,
                "Task",
                task,
                event_kind=task_event_kind,
            ),
        },
        *(
            {
                "leaf_type": "Relation",
                "leaf_id": relation["relation_id"],
                "operation": "set",
                "value_digest": state_binding_value_digest(
                    policy,
                    "Relation",
                    relation,
                    event_kind="relation.recorded",
                ),
            }
            for relation in relations
        ),
    ]
    return PreparedCommit(
        relations,
        tuple(sorted(updates, key=lambda item: (item["leaf_type"], item["leaf_id"]))),
    )


def _event_store(root: Path, bundle: Any, policy: EventStorePolicy) -> EventStore:
    def compiled_record(
        definition: str,
        value: Mapping[str, Any],
        *,
        evaluation_time: str,
        operation: str,
    ) -> bool:
        del evaluation_time, operation
        validate_definition(bundle.schema, definition, value)
        return True

    def command(value: Mapping[str, Any], *, evaluation_time: str) -> bool:
        if value.get("issued_at") != evaluation_time:
            raise CheckpointProfileError("command evaluation time is detached")
        validate_definition(bundle.schema, "CommandRequest", value)
        return True

    def authorization(value: Mapping[str, Any], *, evaluation_time: str) -> bool:
        if value.get("issued_at") != evaluation_time:
            raise CheckpointProfileError("authorization evaluation time is detached")
        authorization_value = value.get("authorization")
        if not isinstance(authorization_value, Mapping):
            raise CheckpointProfileError("command authorization is missing")
        validate_definition(bundle.schema, "RootAuthorization", authorization_value)
        return True

    def event(
        value: Mapping[str, Any],
        *,
        evaluation_time: str,
        command: Mapping[str, Any],
    ) -> bool:
        del evaluation_time
        validate_definition(bundle.schema, "Event", value)
        if value.get("activation_digest") != command.get("activation_digest"):
            raise CheckpointProfileError("event Activation differs from command")
        return True

    return EventStore(
        root,
        ACTIVATION_DIGEST,
        activation_record_digest=ACTIVATION_RECORD_DIGEST,
        implementation_closure_digest=IMPLEMENTATION_CLOSURE_DIGEST,
        policy=policy,
        compiled_record_validator=compiled_record,
        command_validator=command,
        authorization_validator=authorization,
        event_validator=event,
        commit_state_loader=_load_commit_state,
        commit_prepare_callback=lambda view, command_value, relations: _prepare_commit(
            policy, view, command_value, relations
        ),
    )


def _task(batch_size: int, batch_index: int, head_digest: str | None) -> dict[str, Any]:
    task_id = f"task:checkpoint-profile:b{batch_size:03d}:{batch_index:06d}"
    base = {
        "record_type": "Task",
        "task_id": task_id,
        "state": "PLANNED",
        "required_capability": "task.execute",
        "acceptance_predicate": "measure claim-free EventStore checkpoint cost",
        "allowed_paths": ["product/**"],
        "activation_digest": ACTIVATION_DIGEST,
        "candidate_digest": CANDIDATE_DIGEST,
        "created_at": CREATED_AT,
    }
    owner_digest = digest_value({key: value for key, value in base.items() if key != "state"})
    gate_id = f"gate:checkpoint-profile:b{batch_size:03d}:{batch_index:06d}"
    definition = {
        "definition_kind": "GateRunDefinition",
        "definition_id": f"definition:{gate_id}",
        "owner_kind": "Task",
        "owner_digest": owner_digest,
        # EventStore permits a null command HEAD at genesis but deliberately
        # rejects nulls nested inside critical payloads.  This schema-only
        # diagnostic gate therefore binds an explicit genesis identity until
        # a real journal batch digest exists; no service/gate credit is claimed.
        "defined_at_head_digest": head_digest
        or hashlib.sha256(b"promin-checkpoint-profile-genesis-head").hexdigest(),
        "gate_id": gate_id,
        "run_kind": "validation",
        "expected_evidence_class": "validator",
        "expected_evidence_purpose": "diagnostic",
        "product_credit_required": False,
        "target_kind": "candidate",
        "target_digest": CANDIDATE_DIGEST,
        "target_scope": [{"kind": "candidate", "value": CANDIDATE_DIGEST}],
        "candidate_digest": CANDIDATE_DIGEST,
        "policy_digest": hashlib.sha256(b"claim-free-checkpoint-profile").hexdigest(),
        "tool_digest": TOOL_DIGEST,
        "implementation_closure_digest": IMPLEMENTATION_CLOSURE_DIGEST,
        "provider_binding_digest": hashlib.sha256(
            b"eventstore-supported-diagnostic-seam"
        ).hexdigest(),
        "input_digests": [hashlib.sha256(task_id.encode("utf-8")).hexdigest()],
        "activation_digest": ACTIVATION_DIGEST,
    }
    return {
        **base,
        "gate_run_definitions": [
            {"definition_digest": digest_value(definition), "definition": definition}
        ],
    }


def _relation(
    *,
    batch_size: int,
    batch_index: int,
    relation_index: int,
    source_id: str,
) -> dict[str, Any]:
    global_index = batch_index * max(batch_size, 1) + relation_index
    return {
        "record_type": "Relation",
        "relation_id": (
            f"relation:checkpoint-profile:b{batch_size:03d}:"
            f"{batch_index:06d}:{relation_index:03d}"
        ),
        "kind": "READS",
        "source_type": "Task",
        "source_id": source_id,
        "target_type": "Artifact",
        "target_id": f"artifact:checkpoint-profile:{global_index:012d}",
        "activation_digest": ACTIVATION_DIGEST,
        "created_at": CREATED_AT,
    }


def _command(
    task: Mapping[str, Any],
    *,
    batch_size: int,
    batch_index: int,
    head_digest: str | None,
) -> dict[str, Any]:
    command_id = f"command:checkpoint-profile:b{batch_size:03d}:{batch_index:06d}"
    value: dict[str, Any] = {
        "record_type": "CommandRequest",
        "command_id": command_id,
        "command_kind": "task.record",
        "subject_id": SUBJECT_ID,
        "activation_digest": ACTIVATION_DIGEST,
        "idempotency_key": f"idempotency:{command_id}",
        "requested_scope": [
            {"kind": "project", "value": PROJECT_ID},
            {"kind": "task", "value": task["task_id"]},
        ],
        "expected_head_digest": head_digest,
        "issued_at": CREATED_AT,
        "payload": dict(task),
    }
    value["intent_digest"] = digest_value(command_intent_identity(value))
    value["authorization"] = {
        "kind": "root",
        "subject_id": SUBJECT_ID,
        "proofs": [
            {
                "kind": "local-root-command",
                "subject_id": SUBJECT_ID,
                "authority_init_digest": AUTHORITY_INIT_DIGEST,
                "signed_intent_digest": value["intent_digest"],
            }
        ],
    }
    return value


def _profile_relation_value(index: int) -> dict[str, Any]:
    return {
        "record_type": "Relation",
        "relation_id": f"relation:checkpoint-profile:cardinality:{index:012d}",
        "kind": "READS",
        "source_type": "Task",
        "source_id": f"task:checkpoint-profile:cardinality:{index // 127:012d}",
        "target_type": "Artifact",
        "target_id": f"artifact:checkpoint-profile:cardinality:{index:012d}",
        "activation_digest": ACTIVATION_DIGEST,
        "created_at": CREATED_AT,
    }


def _normalized_relation_row(index: int, value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "section": RELATION_SECTION,
        "key": f"{index:0{ROW_KEY_WIDTH}d}",
        "value": dict(value),
    }


def _windows_rss_reader() -> Any:
    global _WINDOWS_RSS_READER
    with _RSS_READER_LOCK:
        if _WINDOWS_RSS_READER is not None:
            return _WINDOWS_RSS_READER
        from ctypes import wintypes

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ProcessMemoryCounters),
            wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        process = kernel32.GetCurrentProcess()

        def read() -> dict[str, Any]:
            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            if not psapi.GetProcessMemoryInfo(
                process, ctypes.byref(counters), counters.cb
            ):
                return {
                    "rss_bytes": None,
                    "process_peak_rss_bytes": None,
                    "source": "unavailable",
                }
            return {
                "rss_bytes": int(counters.WorkingSetSize),
                "process_peak_rss_bytes": int(counters.PeakWorkingSetSize),
                "source": "windows-process-memory-counters",
            }

        _WINDOWS_RSS_READER = read
        return read


def _rss_snapshot() -> dict[str, Any]:
    if os.name == "nt":
        return _windows_rss_reader()()
    if sys.platform.startswith("linux"):
        try:
            values: dict[str, int] = {}
            for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
                if line.startswith(("VmRSS:", "VmHWM:")):
                    key, raw = line.split(":", 1)
                    values[key] = int(raw.strip().split()[0]) * 1024
            if "VmRSS" in values:
                return {
                    "rss_bytes": values["VmRSS"],
                    "process_peak_rss_bytes": values.get("VmHWM"),
                    "source": "linux-proc-status",
                }
        except (OSError, ValueError, IndexError):
            pass
    try:
        import resource

        raw = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        peak = raw if sys.platform == "darwin" else raw * 1024
        return {
            "rss_bytes": peak,
            "process_peak_rss_bytes": peak,
            "source": "resource-rusage-peak",
        }
    except (ImportError, OSError, ValueError):
        return {
            "rss_bytes": None,
            "process_peak_rss_bytes": None,
            "source": "unavailable",
        }


class _Measurement:
    def __init__(self, sample_interval_seconds: float = 0.01) -> None:
        self.sample_interval_seconds = sample_interval_seconds
        self.before: dict[str, Any] = {}
        self.after: dict[str, Any] = {}
        self._wall_started = 0.0
        self._cpu_started = 0.0
        self._observed_peak: int | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _sample(self) -> None:
        while not self._stop.wait(self.sample_interval_seconds):
            rss = _rss_snapshot().get("rss_bytes")
            if isinstance(rss, int):
                self._observed_peak = (
                    rss if self._observed_peak is None else max(self._observed_peak, rss)
                )

    def __enter__(self) -> "_Measurement":
        self.before = _rss_snapshot()
        before_rss = self.before.get("rss_bytes")
        self._observed_peak = before_rss if isinstance(before_rss, int) else None
        self._wall_started = time.perf_counter()
        self._cpu_started = time.process_time()
        self._thread = threading.Thread(target=self._sample, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.cpu_seconds = time.process_time() - self._cpu_started
        self.wall_seconds = time.perf_counter() - self._wall_started
        self._stop.set()
        assert self._thread is not None
        self._thread.join(timeout=1.0)
        self.after = _rss_snapshot()
        after_rss = self.after.get("rss_bytes")
        if isinstance(after_rss, int):
            self._observed_peak = (
                after_rss
                if self._observed_peak is None
                else max(self._observed_peak, after_rss)
            )

    def record(self) -> dict[str, Any]:
        before_rss = self.before.get("rss_bytes")
        after_rss = self.after.get("rss_bytes")
        return {
            "wall_seconds": round(self.wall_seconds, 9),
            "cpu_seconds": round(self.cpu_seconds, 9),
            "rss_before_bytes": before_rss,
            "rss_after_bytes": after_rss,
            "rss_delta_bytes": (
                after_rss - before_rss
                if isinstance(before_rss, int) and isinstance(after_rss, int)
                else None
            ),
            "rss_peak_observed_bytes": self._observed_peak,
            "process_peak_rss_bytes": self.after.get("process_peak_rss_bytes"),
            "rss_source": self.after.get("source", "unavailable"),
            "sample_interval_seconds": self.sample_interval_seconds,
        }


def _sqlite_metrics(path: Path) -> dict[str, int]:
    with closing(sqlite3.connect(path)) as connection:
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        freelist_count = int(connection.execute("PRAGMA freelist_count").fetchone()[0])
        row_count = int(connection.execute("SELECT COUNT(*) FROM derived_row").fetchone()[0])
    return {
        "page_size_bytes": page_size,
        "page_count": page_count,
        "freelist_pages": freelist_count,
        "allocated_page_bytes": page_size * page_count,
        "rows": row_count,
    }


def _write_checkpoint_measurement(
    store: EventStore,
    *,
    name: str,
    rows: Iterable[Mapping[str, Any]],
    checkpoint_count: int,
) -> dict[str, Any]:
    logical_bytes = 0

    def measured_rows() -> Iterable[Mapping[str, Any]]:
        nonlocal logical_bytes
        for row in rows:
            logical_bytes += len(canonical_bytes(dict(row)))
            yield row

    with _Measurement() as measurement:
        manifest = store.write_derived_rows(
            name,
            measured_rows(),
            expected_head=store.head(),
            checkpoint_count=checkpoint_count,
        )
    path = store.derived_rows_root / (hashlib.sha256(name.encode("utf-8")).hexdigest() + ".sqlite3")
    sqlite_metrics = _sqlite_metrics(path)
    physical_bytes = store.derived_rows_storage_bytes(name)
    if manifest["row_count"] != sqlite_metrics["rows"]:
        raise CheckpointProfileError("checkpoint manifest and SQLite row counts differ")
    return {
        "rows_written": manifest["row_count"],
        "logical_row_bytes": logical_bytes,
        "physical_database_bytes": physical_bytes,
        "physical_to_logical_ratio": (
            round(physical_bytes / logical_bytes, 9) if logical_bytes else None
        ),
        "sqlite": sqlite_metrics,
        "checkpoint_digest": manifest["checkpoint_digest"],
        "row_transcript_digest": manifest["row_transcript_digest"],
        "measurement": measurement.record(),
        **_claims(),
    }


def profile_cardinality(
    root: Path,
    *,
    bundle: Any,
    policy: EventStorePolicy,
    row_counts: Sequence[int],
) -> list[dict[str, Any]]:
    store = _event_store(root / "cardinality-events", bundle, policy)
    observations: list[dict[str, Any]] = []
    try:
        for checkpoint_count, relation_count in enumerate(row_counts, start=1):
            rows = (
                _normalized_relation_row(index, _profile_relation_value(index))
                for index in range(relation_count)
            )
            observation = _write_checkpoint_measurement(
                store,
                name="runtime-cardinality-profile",
                rows=rows,
                checkpoint_count=checkpoint_count,
            )
            observations.append(
                {
                    "relation_rows": relation_count,
                    "normalized_section": RELATION_SECTION,
                    "authoritative": False,
                    "status": "diagnostic-observed",
                    **observation,
                }
            )
    finally:
        store.close()
    return observations


def _commit_batch(
    store: EventStore,
    *,
    batch_size: int,
    batch_index: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    head_digest = store.head()["batch_digest"]
    task = _task(batch_size, batch_index, head_digest)
    relations = [
        _relation(
            batch_size=batch_size,
            batch_index=batch_index,
            relation_index=index,
            source_id=task["task_id"],
        )
        for index in range(batch_size)
    ]
    command = _command(
        task,
        batch_size=batch_size,
        batch_index=batch_index,
        head_digest=head_digest,
    )
    return (
        store.commit(command, auxiliary_relations=relations, created_at=CREATED_AT),
        relations,
    )


def profile_batch_cadence(
    root: Path,
    *,
    bundle: Any,
    policy: EventStorePolicy,
    batch_size: int,
    cadence_max_batches: int,
) -> dict[str, Any]:
    store = _event_store(root / f"batch-{batch_size:03d}-events", bundle, policy)
    relations: list[dict[str, Any]] = []
    checkpoint_name = "runtime-cadence-profile"
    try:
        baseline = _write_checkpoint_measurement(
            store,
            name=checkpoint_name,
            rows=(),
            checkpoint_count=1,
        )
        initial_head = store.head()
        if batch_size >= policy.max_events_per_batch:
            try:
                _commit_batch(store, batch_size=batch_size, batch_index=0)
            except EventStoreError as exc:
                return {
                    "relation_batch_size": batch_size,
                    "primary_events_per_batch": 1,
                    "total_events_attempted": batch_size + 1,
                    "status": "policy-rejected",
                    "admitted": False,
                    "rejection_type": type(exc).__name__,
                    "rejection_reason": str(exc),
                    "head_unchanged": store.head() == initial_head,
                    "compaction_cadence": None,
                    "baseline_checkpoint": baseline,
                    **_claims(),
                }
            raise CheckpointProfileError(
                "EventStore admitted a relation batch beyond the event ceiling"
            )

        commits = 0
        tail = store.derived_rows_tail_status(checkpoint_name)
        with _Measurement() as commit_measurement:
            while commits < cadence_max_batches and not tail["compaction_due"]:
                _result, committed_relations = _commit_batch(
                    store,
                    batch_size=batch_size,
                    batch_index=commits,
                )
                relations.extend(committed_relations)
                commits += 1
                tail = store.derived_rows_tail_status(checkpoint_name)

        compaction: dict[str, Any] | None = None
        after_tail: dict[str, Any] | None = None
        if tail["compaction_due"]:
            compaction = _write_checkpoint_measurement(
                store,
                name=checkpoint_name,
                rows=(
                    _normalized_relation_row(index, relation)
                    for index, relation in enumerate(relations)
                ),
                checkpoint_count=2,
            )
            after_tail = store.derived_rows_tail_status(checkpoint_name)
        trigger = {
            "batch_threshold_reached": tail["tail_batches"]
            >= policy.derived_tail_batch_threshold,
            "byte_threshold_reached": tail["tail_bytes"]
            >= policy.derived_tail_byte_threshold,
        }
        return {
            "relation_batch_size": batch_size,
            "primary_events_per_batch": 1,
            "total_events_per_admitted_batch": batch_size + 1,
            "status": (
                "compaction-observed"
                if tail["compaction_due"]
                else "bounded-cap-before-compaction"
            ),
            "admitted": True,
            "commits_observed": commits,
            "relations_committed": len(relations),
            "commit_measurement": commit_measurement.record(),
            "compaction_cadence": {
                "observed": tail["compaction_due"],
                "tail_batches": tail["tail_batches"],
                "tail_bytes": tail["tail_bytes"],
                "batch_threshold": policy.derived_tail_batch_threshold,
                "byte_threshold": policy.derived_tail_byte_threshold,
                "trigger": trigger,
                "checkpoint_rewrite": compaction,
                "tail_after_checkpoint": (
                    None
                    if after_tail is None
                    else {
                        "tail_batches": after_tail["tail_batches"],
                        "tail_bytes": after_tail["tail_bytes"],
                        "compaction_due": after_tail["compaction_due"],
                        "checkpoint_count": after_tail["checkpoint_count"],
                    }
                ),
            },
            "baseline_checkpoint": baseline,
            **_claims(),
        }
    finally:
        store.close()


def build_profile(
    work_root: Path,
    *,
    row_counts: Sequence[int] = DEFAULT_ROW_COUNTS,
    batch_sizes: Sequence[int] = DEFAULT_BATCH_SIZES,
    cadence_max_batches: int = MAX_CADENCE_BATCHES,
) -> dict[str, Any]:
    checked_rows = tuple(row_counts)
    checked_batches = tuple(batch_sizes)
    if (
        not checked_rows
        or any(
            not isinstance(item, int)
            or isinstance(item, bool)
            or item < 1
            or item > MAX_PROFILE_ROWS
            for item in checked_rows
        )
        or any(right <= left for left, right in zip(checked_rows, checked_rows[1:]))
    ):
        raise CheckpointProfileError(
            f"row_counts must be strictly increasing integers up to {MAX_PROFILE_ROWS}"
        )
    if (
        not checked_batches
        or len(checked_batches) != len(set(checked_batches))
        or any(
            not isinstance(item, int)
            or isinstance(item, bool)
            or item < 1
            or item > 128
            for item in checked_batches
        )
    ):
        raise CheckpointProfileError("batch_sizes must be unique integers from 1 through 128")
    if (
        not isinstance(cadence_max_batches, int)
        or isinstance(cadence_max_batches, bool)
        or not 1 <= cadence_max_batches <= MAX_CADENCE_BATCHES
    ):
        raise CheckpointProfileError(
            f"cadence_max_batches must be from 1 through {MAX_CADENCE_BATCHES}"
        )
    if work_root.exists() or work_root.is_symlink():
        raise CheckpointProfileError("work root must not already exist")
    work_root.mkdir(parents=True)

    bundle = load_contract_bundle(
        PACKAGE_ROOT,
        PACKAGE_ROOT / "presets" / "semantic-standard.json",
    )
    policy = _event_store_policy(bundle)
    cardinality = profile_cardinality(
        work_root,
        bundle=bundle,
        policy=policy,
        row_counts=checked_rows,
    )
    batch_observations = [
        profile_batch_cadence(
            work_root,
            bundle=bundle,
            policy=policy,
            batch_size=batch_size,
            cadence_max_batches=cadence_max_batches,
        )
        for batch_size in checked_batches
    ]
    return {
        "schema": PROFILE_SCHEMA,
        "record_type": "CheckpointProfileDiagnostic",
        "status": "diagnostic-complete",
        "generated_at": _utc_now(),
        "tool": {
            "path": "tools/promin_checkpoint_profile.py",
            "sha256": TOOL_DIGEST,
        },
        "environment": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "sqlite_version": sqlite3.sqlite_version,
        },
        "scope": {
            "route": "eventstore-supported-normalized-derived-row-diagnostic",
            "normalized_relation_section": RELATION_SECTION,
            "eventstore_commit_exercised": True,
            "eventstore_state_binding_exercised": True,
            "eventstore_tail_compaction_exercised": True,
            "eventstore_sqlite_checkpoint_exercised": True,
            "promin_service_authorization_exercised": False,
            "full_runtime_checkpoint_reconstruction_exercised": False,
            "diagnostic_only": True,
        },
        "configuration": {
            "relation_row_counts": list(checked_rows),
            "relation_batch_sizes": list(checked_batches),
            "cadence_max_batches": cadence_max_batches,
            "full_requested_batch_boundary_selected": checked_batches
            == DEFAULT_BATCH_SIZES,
            "workload_bounded": max(checked_rows) <= MAX_PROFILE_ROWS,
        },
        "policy": {
            "policy_digest": policy.policy_digest,
            "max_events_per_batch": policy.max_events_per_batch,
            "max_relations_per_task_batch": policy.max_events_per_batch - 1,
            "derived_tail_batch_threshold": policy.derived_tail_batch_threshold,
            "derived_tail_byte_threshold": policy.derived_tail_byte_threshold,
        },
        "checkpoint_cardinality": cardinality,
        "batch_boundary_and_compaction": batch_observations,
        **_claims(),
    }


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    payload = canonical_bytes(dict(report))
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise CheckpointProfileError("output path already exists") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Profile bounded normalized EventStore checkpoints without pass credit."
    )
    parser.add_argument(
        "--row-counts",
        default=",".join(str(value) for value in DEFAULT_ROW_COUNTS),
        help=f"strictly increasing relation rows, each <= {MAX_PROFILE_ROWS}",
    )
    parser.add_argument(
        "--batch-sizes",
        default=",".join(str(value) for value in DEFAULT_BATCH_SIZES),
        help="unique auxiliary Relation batch sizes (default: 1,2,127,128)",
    )
    parser.add_argument(
        "--cadence-max-batches",
        type=int,
        default=MAX_CADENCE_BATCHES,
        help=f"bounded EventStore commits per batch-size lane (max {MAX_CADENCE_BATCHES})",
    )
    parser.add_argument(
        "--work-root",
        type=Path,
        help="new directory to preserve diagnostic databases; omitted uses a disposable root",
    )
    parser.add_argument("--output", type=Path, help="new canonical JSON output path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        row_counts = parse_positive_integers(
            arguments.row_counts,
            label="row counts",
            maximum=MAX_PROFILE_ROWS,
            strictly_increasing=True,
        )
        batch_sizes = parse_positive_integers(
            arguments.batch_sizes,
            label="batch sizes",
            maximum=128,
            strictly_increasing=False,
        )
        if arguments.work_root is None:
            with tempfile.TemporaryDirectory(prefix="promin-checkpoint-profile-") as raw:
                report = build_profile(
                    Path(raw) / "work",
                    row_counts=row_counts,
                    batch_sizes=batch_sizes,
                    cadence_max_batches=arguments.cadence_max_batches,
                )
        else:
            report = build_profile(
                arguments.work_root.absolute(),
                row_counts=row_counts,
                batch_sizes=batch_sizes,
                cadence_max_batches=arguments.cadence_max_batches,
            )
        if arguments.output is not None:
            _write_report(arguments.output.absolute(), report)
        sys.stdout.buffer.write(canonical_bytes(report))
        return 0
    except (
        CheckpointProfileError,
        ContractError,
        EventStoreError,
        OSError,
        sqlite3.Error,
    ) as exc:
        failure = {
            "schema": PROFILE_SCHEMA,
            "record_type": "CheckpointProfileFailure",
            "status": "diagnostic-failed",
            "error_type": type(exc).__name__,
            "reason": str(exc),
            **_claims(),
        }
        sys.stderr.buffer.write(canonical_bytes(failure))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
