#!/usr/bin/env python3
"""Build a claim-free ingestion/rebuild complexity model from bound evidence.

The model is deliberately diagnostic.  It verifies and binds supplied evidence,
separates observations from derivations and estimates, and never evaluates a
performance threshold or grants product, release, or acceptance credit.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import argparse
import ast
import hashlib
import math
import os
from pathlib import Path
import stat
import sys
from typing import Any, Final


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) in sys.path:
    sys.path.remove(str(PACKAGE_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT))

from promin.canonical import (  # noqa: E402
    CanonicalError,
    ParseLimits,
    canonical_bytes,
    digest_value,
    parse_json_strict,
)


MODEL_SCHEMA: Final = "promin.performance-complexity-model.v1"
DEFAULT_TARGETS: Final = (1_000, 10_000, 100_000)
_MAX_ARTIFACT_BYTES: Final = 64 * 1024 * 1024
_INPUT_LIMITS: Final = ParseLimits(
    max_bytes=_MAX_ARTIFACT_BYTES,
    max_depth=96,
    max_items=4_000_000,
    max_string_length=4 * 1024 * 1024,
    max_number_length=256,
)
_DIGEST = frozenset("0123456789abcdef")

# These are algorithm-shape constants for the r5 physical saturation route,
# not configurable product thresholds.
_TREE_DEPTH_BYTES: Final = 32
_STATE_BINDING_LEVELS: Final = _TREE_DEPTH_BYTES + 1
_RELATIONS_PER_PHYSICAL_COMMIT: Final = 127
_FIXED_SEARCH_RELATIONS: Final = 28
_FIXED_SEARCH_TASKS: Final = 32
_FIXED_GRANT_AND_CANDIDATE_COMMITS: Final = 5
_FIXED_SEMANTIC_COMMITS: Final = (
    _FIXED_SEARCH_TASKS + _FIXED_GRANT_AND_CANDIDATE_COMMITS
)

_CLAIMS: Final = {
    "acceptance_pass": False,
    "pass_credit": False,
    "performance_acceptance": False,
    "product_acceptance_pass": False,
    "release_eligible": False,
}


class PerformanceModelError(ValueError):
    """Raised when supplied evidence cannot support a truthful model."""


def _metric(value: object, classification: str, basis: str) -> dict[str, object]:
    return {
        "value": value,
        "classification": classification,
        "basis": basis,
    }


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value).issubset(_DIGEST)
    )


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise PerformanceModelError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PerformanceModelError(f"{label} must be a non-negative integer")
    return value


def _finite_nonnegative(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0.0
    ):
        raise PerformanceModelError(f"{label} must be a finite non-negative number")
    return float(value)


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise PerformanceModelError(f"{label} must be a string-keyed object")
    return value


def _sequence(value: object, label: str) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise PerformanceModelError(f"{label} must be an array")
    return value


def _verified_digest(
    value: Mapping[str, object],
    *,
    digest_field: str,
    label: str,
) -> None:
    supplied = value.get(digest_field)
    if not _is_digest(supplied):
        raise PerformanceModelError(f"{label} {digest_field} is missing or invalid")
    body = dict(value)
    body.pop(digest_field)
    if digest_value(body, limits=_INPUT_LIMITS) != supplied:
        raise PerformanceModelError(f"{label} {digest_field} does not verify")


def _regular_artifact(path: Path) -> tuple[Path, bytes]:
    resolved = Path(os.path.abspath(path))
    try:
        metadata = resolved.lstat()
    except OSError as exc:
        raise PerformanceModelError(f"evidence artifact is unavailable: {resolved}: {exc}") from exc
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400))
    if (
        stat.S_ISLNK(metadata.st_mode)
        or resolved.is_symlink()
        or attributes & reparse
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise PerformanceModelError(
            f"evidence artifact must be a physical regular file: {resolved}"
        )
    if metadata.st_size < 1 or metadata.st_size > _MAX_ARTIFACT_BYTES:
        raise PerformanceModelError(
            f"evidence artifact bytes must be within 1..{_MAX_ARTIFACT_BYTES}: {resolved}"
        )
    try:
        payload = resolved.read_bytes()
    except OSError as exc:
        raise PerformanceModelError(f"evidence artifact cannot be read: {resolved}: {exc}") from exc
    if len(payload) != metadata.st_size:
        raise PerformanceModelError(f"evidence artifact changed while being read: {resolved}")
    return resolved, payload


def _class_method(
    tree: ast.Module,
    class_name: str,
    method_name: str,
) -> ast.FunctionDef | ast.AsyncFunctionDef:
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            matches = [
                item
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name == method_name
            ]
            if len(matches) != 1:
                break
            return matches[0]
    raise PerformanceModelError(
        f"source must define exactly one {class_name}.{method_name}"
    )


def _attribute_call_count(node: ast.AST, attribute: str) -> int:
    return sum(
        1
        for item in ast.walk(node)
        if isinstance(item, ast.Call)
        and isinstance(item.func, ast.Attribute)
        and item.func.attr == attribute
    )


def _static_execute_statements(node: ast.AST, label: str) -> list[str]:
    statements: list[str] = []
    for item in ast.walk(node):
        if (
            not isinstance(item, ast.Call)
            or not isinstance(item.func, ast.Attribute)
            or item.func.attr != "execute"
            or not item.args
        ):
            continue
        try:
            statement = ast.literal_eval(item.args[0])
        except (ValueError, TypeError) as exc:
            raise PerformanceModelError(
                f"{label} contains a dynamically formed SQLite execute statement"
            ) from exc
        if not isinstance(statement, str):
            raise PerformanceModelError(
                f"{label} SQLite execute statement must be a static string"
            )
        statements.append(" ".join(statement.upper().split()))
    return statements


def derive_state_binding_sql_geometry(
    source_path: Path = PACKAGE_ROOT / "promin" / "events.py",
) -> dict[str, object]:
    """Derive normal-path state-binding SELECT geometry from exact source bytes."""

    resolved, payload = _regular_artifact(source_path)
    try:
        source_text = payload.decode("utf-8", errors="strict")
        tree = ast.parse(source_text, filename=str(resolved))
    except (UnicodeError, SyntaxError) as exc:
        raise PerformanceModelError(
            f"EventStore source cannot be parsed for SQL geometry: {resolved}: {exc}"
        ) from exc
    binding = _class_method(tree, "EventStore", "_state_binding_binding")
    union = _class_method(tree, "EventStore", "_state_storage_union_rows")
    stage = _class_method(tree, "EventStore", "_stage_state_binding_delta")
    publish = _class_method(tree, "EventStore", "_publish_state_binding_delta")

    binding_calls = _attribute_call_count(stage, "_state_binding_binding") + (
        _attribute_call_count(publish, "_state_binding_binding")
    )
    union_calls = _attribute_call_count(stage, "_state_storage_union_rows") + (
        _attribute_call_count(publish, "_state_storage_union_rows")
    )
    legacy_range_calls = _attribute_call_count(stage, "_state_storage_rows") + (
        _attribute_call_count(publish, "_state_storage_rows")
    )
    binding_sql = _static_execute_statements(binding, "_state_binding_binding")
    union_sql = _static_execute_statements(union, "_state_storage_union_rows")
    binding_selects = [
        statement
        for statement in binding_sql
        if statement.startswith("SELECT ") and " FROM BINDING " in f" {statement} "
    ]
    union_selects = [
        statement
        for statement in union_sql
        if statement.startswith(("SELECT ", "WITH "))
        and " NODE " in f" {statement} "
    ]
    storage_mode_pragmas = [
        statement
        for statement in binding_sql
        if statement == "PRAGMA AUTO_VACUUM"
    ]
    unexpected_binding_reads = [
        statement
        for statement in binding_sql
        if statement.startswith(("SELECT ", "WITH "))
        and statement not in binding_selects
    ]
    unexpected_union_reads = [
        statement
        for statement in union_sql
        if statement.startswith(("SELECT ", "WITH "))
        and statement not in union_selects
    ]
    if (
        binding_calls < 1
        or union_calls < 1
        or len(binding_selects) != 1
        or len(union_selects) != 1
        or unexpected_binding_reads
        or unexpected_union_reads
    ):
        raise PerformanceModelError(
            "current EventStore state-binding SELECT geometry is unsupported; "
            "refresh the evidence model instead of using a stale operation count"
        )
    binding_per_commit = binding_calls * len(binding_selects)
    union_per_commit = union_calls * len(union_selects)
    return {
        "source": {
            "source_id": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "path": str(resolved),
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "classification": "source-derived",
        },
        "normal_path": {
            "binding_helper_calls_per_commit": binding_calls,
            "node_union_helper_calls_per_commit": union_calls,
            "legacy_depth_range_helper_calls_per_commit": legacy_range_calls,
            "binding_select_statements_per_commit": binding_per_commit,
            "node_union_select_statements_per_commit": union_per_commit,
            "select_statements_per_commit": binding_per_commit + union_per_commit,
            "storage_mode_pragma_statements_per_commit": (
                binding_calls * len(storage_mode_pragmas)
            ),
        },
        "derivation": {
            "classification": "derived",
            "method": (
                "Python AST call-graph count over EventStore stage/publish and "
                "static SQLite statements in their binding/node helpers"
            ),
            "sqlite_statement_isolation": (
                "one Connection.execute call is one statement; SELECT clauses "
                "inside the recursive CTE are not counted as separate round trips"
            ),
            "pragma_excluded_from_select_count": True,
        },
    }


def _parse_artifact(payload: bytes, path: Path) -> list[Mapping[str, object]]:
    try:
        parsed = parse_json_strict(payload, limits=_INPUT_LIMITS)
    except CanonicalError as whole_error:
        rows: list[Mapping[str, object]] = []
        for line_number, line in enumerate(payload.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                row = parse_json_strict(line, limits=_INPUT_LIMITS)
            except CanonicalError as exc:
                raise PerformanceModelError(
                    f"evidence artifact is neither JSON nor JSONL at line {line_number}: "
                    f"{path}: {exc}"
                ) from whole_error
            rows.append(_mapping(row, f"evidence row {line_number}"))
        if not rows:
            raise PerformanceModelError(f"evidence artifact has no JSON records: {path}")
        return rows
    if isinstance(parsed, list):
        if not parsed:
            raise PerformanceModelError(f"evidence artifact array is empty: {path}")
        return [
            _mapping(row, f"evidence row {index}")
            for index, row in enumerate(parsed)
        ]
    return [_mapping(parsed, "evidence record")]


def _false_claims(record: Mapping[str, object], label: str) -> None:
    for field in (
        "acceptance_pass",
        "pass_credit",
        "performance_acceptance",
        "product_acceptance_pass",
        "public_release_approved",
        "release_eligible",
    ):
        if field in record and record[field] is not False:
            raise PerformanceModelError(f"{label} must not supply positive {field}")
    nested = record.get("claims")
    if isinstance(nested, Mapping):
        for field, value in nested.items():
            if (
                isinstance(field, str)
                and any(token in field for token in ("acceptance", "pass", "approved", "eligible"))
                and value is not False
            ):
                raise PerformanceModelError(
                    f"{label} must not supply positive claims.{field}"
                )


def _validate_failure_receipt(record: Mapping[str, object]) -> list[str]:
    if (
        record.get("schema") != "promin.saturation-failure.v1"
        or record.get("record_type") != "SaturationFailure"
        or record.get("status") not in {"fail", "rejected"}
    ):
        raise PerformanceModelError("receipt is not a rejected Promin saturation failure v1")
    _verified_digest(record, digest_field="receipt_digest", label="failure receipt")
    _false_claims(record, "failure receipt")
    workload = _mapping(record.get("workload"), "failure receipt workload")
    if workload.get("workload_reduced") is not False:
        raise PerformanceModelError("failure receipt workload must remain unreduced")
    checks = ["receipt_digest"]
    for field in ("archive_binding", "tool_binding", "storage"):
        bound = _mapping(record.get(field), f"failure receipt {field}")
        _verified_digest(bound, digest_field="binding_digest", label=field)
        checks.append(f"{field}.binding_digest")
    return checks


def _validate_journal_checkpoint(record: Mapping[str, object]) -> list[str]:
    if record.get("record_type") != "DerivedJournalCheckpoint":
        raise PerformanceModelError("journal checkpoint record_type is invalid")
    _verified_digest(record, digest_field="checkpoint_digest", label="journal checkpoint")
    if record.get("authoritative") is not False:
        raise PerformanceModelError("derived journal checkpoint must remain non-authoritative")
    return ["checkpoint_digest"]


def _validate_operation_metrics(record: Mapping[str, object]) -> list[str]:
    if record.get("record_type") != "SaturationOperationMetrics":
        raise PerformanceModelError("operation metrics record_type is invalid")
    _false_claims(record, "operation metrics")
    if record.get("product_acceptance_credit") is not False:
        raise PerformanceModelError("operation metrics must deny product acceptance credit")
    semantic = _mapping(record.get("semantic_ingestion"), "semantic_ingestion")
    observations = list(_sequence(semantic.get("observations"), "semantic observations"))
    supplied = semantic.get("result_digest")
    if not _is_digest(supplied) or digest_value(
        observations, limits=_INPUT_LIMITS
    ) != supplied:
        raise PerformanceModelError("operation metrics semantic result_digest does not verify")
    if _positive_int(semantic.get("commit_count"), "semantic commit_count") != len(
        observations
    ):
        raise PerformanceModelError("semantic commit_count differs from observations")
    return ["semantic_ingestion.result_digest"]


def _source_binding(path: Path, payload: bytes, records: list[Mapping[str, object]]) -> dict[str, object]:
    if len(records) > 1 and not all(
        record.get("record_type") is None
        and isinstance(record.get("phase"), str)
        for record in records
    ):
        raise PerformanceModelError(
            f"multi-record artifacts must contain only homogeneous phase-log rows: {path}"
        )
    checks: list[str] = []
    classification = "sha256-bound-only"
    types: list[str] = []
    for record in records:
        record_type = record.get("record_type")
        if isinstance(record_type, str):
            types.append(record_type)
        elif isinstance(record.get("phase"), str):
            types.append("SaturationPhaseLogRow")
        else:
            raise PerformanceModelError(f"unsupported evidence record in {path}")
        if record_type == "SaturationFailure":
            checks.extend(_validate_failure_receipt(record))
            classification = "self-sealed"
        elif record_type == "DerivedJournalCheckpoint":
            checks.extend(_validate_journal_checkpoint(record))
            classification = "self-sealed"
        elif record_type == "SaturationOperationMetrics":
            checks.extend(_validate_operation_metrics(record))
            classification = "nested-digest-verified"
        elif record_type == "ProminAlpha4R5Windows100kInterruptionObservation":
            _false_claims(record, "interruption observation")
        elif record_type == "SaturationPhaseStorageMeasurement":
            pass
        elif isinstance(record.get("phase"), str):
            _false_claims(record, "phase log row")
        else:
            raise PerformanceModelError(f"unsupported evidence record_type {record_type!r}")
    return {
        "source_id": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "path": str(path),
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "record_types": sorted(set(types)),
        "integrity": {
            "classification": classification,
            "verified_checks": sorted(set(checks)),
            "exact_bytes_bound": True,
        },
        "acceptance_credit_consumed": False,
    }


def _load_source(path: Path) -> tuple[dict[str, object], list[Mapping[str, object]]]:
    resolved, payload = _regular_artifact(path)
    records = _parse_artifact(payload, resolved)
    return _source_binding(resolved, payload, records), records


def _record_metric(
    state: dict[str, dict[str, object]],
    name: str,
    value: object,
    classification: str,
    basis: str,
    *,
    priority: int,
    allow_progression: bool = False,
) -> None:
    current = state.get(name)
    if current is not None and current["value"] != value:
        if not allow_progression or priority <= int(current["priority"]):
            raise PerformanceModelError(
                f"bound evidence disagrees for {name}: {current['value']} != {value}"
            )
    if current is None or priority > int(current["priority"]):
        state[name] = {
            "value": value,
            "classification": classification,
            "basis": basis,
            "priority": priority,
        }


def _store_checkpoints(
    state: dict[str, object],
    raw: object,
    *,
    basis: str,
    priority: int,
) -> None:
    records = [
        _mapping(item, f"{basis} checkpoint")
        for item in _sequence(raw, f"{basis} checkpoints")
    ]
    if not records:
        return
    sequences: list[int] = []
    normalized: list[dict[str, object]] = []
    for item in records:
        sequence = _positive_int(item.get("sequence"), f"{basis} checkpoint sequence")
        operation_sequence = item.get("operation_sequence", sequence)
        if operation_sequence != sequence:
            raise PerformanceModelError(f"{basis} checkpoint operation sequence differs")
        written = item.get("checkpoint_written")
        if not isinstance(written, bool):
            raise PerformanceModelError(f"{basis} checkpoint_written must be boolean")
        normalized.append(dict(item))
        sequences.append(sequence)
    if sequences != list(range(sequences[0], sequences[-1] + 1)):
        raise PerformanceModelError(f"{basis} checkpoint sequences are not contiguous")
    current = state.get("checkpoints")
    if isinstance(current, Mapping):
        existing = list(current["records"])
        by_sequence = {int(item["sequence"]): item for item in existing}
        for item in normalized:
            sequence = int(item["sequence"])
            if sequence in by_sequence and by_sequence[sequence] != item:
                raise PerformanceModelError(
                    f"bound checkpoint evidence disagrees at sequence {sequence}"
                )
        if len(existing) > len(normalized) and priority <= int(current["priority"]):
            return
    state["checkpoints"] = {
        "records": normalized,
        "basis": basis,
        "priority": priority,
    }


def _database_components(
    metrics: dict[str, dict[str, object]],
    measurement: Mapping[str, object],
    *,
    basis: str,
) -> None:
    phase = measurement.get("phase")
    if not isinstance(phase, str):
        raise PerformanceModelError(f"{basis} storage phase is missing")
    files = _sequence(measurement.get("database_files", []), f"{basis} database_files")
    phase_priority = {
        "preflight": 20,
        "physical-generation": 30,
        "inventory": 40,
        "semantic-ingestion": 80,
        "projection": 85,
        "runtime-queries": 90,
        "result": 95,
    }.get(phase, 60)
    measured_total = 0
    for raw in files:
        item = _mapping(raw, f"{basis} database file")
        path = item.get("path")
        if not isinstance(path, str):
            raise PerformanceModelError(f"{basis} database path is invalid")
        logical_bytes = _nonnegative_int(
            item.get("logical_bytes"), f"{basis} database logical_bytes"
        )
        measured_total += logical_bytes
        normalized = path.replace("\\", "/").lower()
        metric_name: str | None = None
        if normalized.endswith("/event-identities.sqlite3"):
            metric_name = "event_identity_database_bytes"
        elif normalized.endswith("/state-binding.sqlite3"):
            metric_name = "state_binding_database_bytes"
        elif "/derived-rows/" in normalized and normalized.endswith(".sqlite3"):
            metric_name = "derived_rows_database_bytes"
        elif normalized.endswith("/projection/promin.sqlite3"):
            metric_name = "projection_database_bytes"
        if metric_name is not None:
            _record_metric(
                metrics,
                metric_name,
                logical_bytes,
                "observed",
                f"bound {phase} storage measurement",
                priority=phase_priority,
                allow_progression=True,
            )
    supplied_total = measurement.get("database_logical_bytes")
    if supplied_total is not None and _nonnegative_int(
        supplied_total, f"{basis} database_logical_bytes"
    ) != measured_total:
        raise PerformanceModelError(f"{basis} database byte total is not recomputable")
    if phase == "semantic-ingestion":
        _record_metric(
            metrics,
            "ingestion_database_bytes",
            measured_total,
            "observed",
            "bound semantic-ingestion storage measurement",
            priority=80,
        )


def _extract_storage(
    metrics: dict[str, dict[str, object]],
    run_state: dict[str, object],
    storage: Mapping[str, object],
    *,
    basis: str,
    priority: int,
) -> None:
    measurement = storage.get("measurement")
    if isinstance(measurement, Mapping):
        _database_components(metrics, measurement, basis=basis)
    checkpoints = storage.get("commit_checkpoints")
    if checkpoints is not None:
        checkpoint_rows = list(_sequence(checkpoints, f"{basis} commit_checkpoints"))
        count = _positive_int(
            storage.get("commit_checkpoint_count"), f"{basis} commit_checkpoint_count"
        )
        if len(checkpoint_rows) != count:
            raise PerformanceModelError(f"{basis} full checkpoint count differs")
        supplied_digest = storage.get("commit_checkpoint_digest")
        if not _is_digest(supplied_digest) or digest_value(
            checkpoint_rows, limits=_INPUT_LIMITS
        ) != supplied_digest:
            raise PerformanceModelError(f"{basis} commit_checkpoint_digest does not verify")
        _store_checkpoints(
            run_state,
            checkpoint_rows,
            basis=basis,
            priority=priority,
        )


def _extract_receipt(
    record: Mapping[str, object],
    metrics: dict[str, dict[str, object]],
    run_state: dict[str, object],
) -> None:
    workload = _mapping(record.get("workload"), "failure receipt workload")
    _record_metric(
        metrics,
        "physical_files",
        _positive_int(workload.get("physical_files"), "physical_files"),
        "observed",
        "self-sealed failure receipt workload",
        priority=90,
    )
    _record_metric(
        metrics,
        "core_valid_relations",
        _positive_int(workload.get("core_valid_relations"), "core_valid_relations"),
        "observed",
        "self-sealed failure receipt workload",
        priority=90,
    )
    storage = _mapping(record.get("storage"), "failure receipt storage")
    commit_count = _positive_int(
        storage.get("commit_checkpoint_count"), "commit_checkpoint_count"
    )
    _record_metric(
        metrics,
        "semantic_commits",
        commit_count,
        "observed",
        "self-sealed failure receipt commit_checkpoint_count",
        priority=70,
    )
    phases = _sequence(storage.get("phase_measurements"), "phase_measurements")
    seen: set[str] = set()
    for raw in phases:
        measurement = _mapping(raw, "failure receipt phase measurement")
        phase = measurement.get("phase")
        if not isinstance(phase, str) or phase in seen:
            raise PerformanceModelError("failure receipt storage phases are invalid")
        seen.add(phase)
        _database_components(metrics, measurement, basis="failure receipt")
    run_state["projection_phase_observed"] = "projection" in seen
    tail = storage.get("commit_checkpoint_tail")
    if tail is not None:
        _store_checkpoints(
            run_state,
            tail,
            basis="self-sealed failure receipt tail",
            priority=60,
        )


def _extract_journal_checkpoint(
    record: Mapping[str, object],
    metrics: dict[str, dict[str, object]],
) -> None:
    _record_metric(
        metrics,
        "semantic_commits",
        _positive_int(record.get("batch_count"), "journal checkpoint batch_count"),
        "observed",
        "bound DerivedJournalCheckpoint batch_count",
        priority=100,
    )
    _record_metric(
        metrics,
        "state_binding_updates",
        _positive_int(
            record.get("state_binding_update_count"),
            "journal checkpoint state_binding_update_count",
        ),
        "observed",
        "bound DerivedJournalCheckpoint state_binding_update_count",
        priority=100,
    )
    event_count = _positive_int(record.get("event_count"), "journal checkpoint event_count")
    _record_metric(
        metrics,
        "event_count",
        event_count,
        "observed",
        "bound DerivedJournalCheckpoint event_count",
        priority=100,
    )


def _extract_operation_metrics(
    record: Mapping[str, object],
    metrics: dict[str, dict[str, object]],
    run_state: dict[str, object],
) -> None:
    semantic = _mapping(record.get("semantic_ingestion"), "semantic_ingestion")
    _record_metric(
        metrics,
        "semantic_commits",
        _positive_int(semantic.get("commit_count"), "semantic commit_count"),
        "observed",
        "bound operation metrics commit_count",
        priority=95,
    )
    _record_metric(
        metrics,
        "state_binding_updates",
        _positive_int(semantic.get("changed_records"), "semantic changed_records"),
        "observed",
        "bound operation metrics changed_records",
        priority=95,
    )
    _record_metric(
        metrics,
        "semantic_ingestion_seconds",
        _finite_nonnegative(semantic.get("elapsed_seconds"), "semantic elapsed_seconds"),
        "observed",
        "bound operation metrics elapsed_seconds",
        priority=95,
    )
    observations = list(_sequence(semantic.get("observations"), "semantic observations"))
    storage_rows: list[dict[str, object]] = []
    for raw in observations:
        observation = dict(_mapping(raw, "semantic observation"))
        storage_rows.append(
            {
                "sequence": observation.get("sequence"),
                "operation_sequence": observation.get("sequence"),
                "phase": observation.get("phase"),
                "checkpoint_written": observation.get("checkpoint_written"),
                "runtime_checkpoint_bytes": observation.get("checkpoint_bytes"),
                "physical_payload_bytes": observation.get("physical_payload_bytes"),
                "duration_ms": observation.get("duration_ms"),
            }
        )
    _store_checkpoints(
        run_state,
        storage_rows,
        basis="bound operation metrics",
        priority=95,
    )
    projection = _mapping(record.get("projection"), "operation projection")
    initial = _nonnegative_int(
        projection.get("initial_inventory_passes"), "initial_inventory_passes"
    )
    rebuild = _nonnegative_int(
        projection.get("rebuild_inventory_passes"), "rebuild_inventory_passes"
    )
    _record_metric(
        metrics,
        "projection_rebuilds",
        initial + rebuild,
        "observed",
        "bound operation metrics inventory passes",
        priority=95,
    )
    relation_count = _positive_int(
        projection.get("relation_count"), "projection relation_count"
    )
    _record_metric(
        metrics,
        "core_valid_relations",
        relation_count,
        "observed",
        "bound operation metrics projection relation_count",
        priority=95,
    )
    for field, metric_name in (
        ("entity_count", "projection_entities"),
        ("relation_count", "projection_relations"),
        ("database_bytes", "projection_database_bytes"),
    ):
        _record_metric(
            metrics,
            metric_name,
            _positive_int(projection.get(field), f"projection {field}"),
            "observed",
            f"bound operation metrics {field}",
            priority=95,
        )
    elapsed_ms = projection.get("elapsed_ms")
    if elapsed_ms is not None:
        _record_metric(
            metrics,
            "projection_seconds",
            _finite_nonnegative(elapsed_ms, "projection elapsed_ms") / 1000.0,
            "observed",
            "bound operation metrics projection elapsed_ms",
            priority=95,
        )
    physical = record.get("physical")
    if isinstance(physical, Mapping) and physical.get("files") is not None:
        _record_metric(
            metrics,
            "physical_files",
            _positive_int(physical.get("files"), "operation physical files"),
            "observed",
            "bound operation metrics physical files",
            priority=95,
        )


def _extract_phase_rows(
    records: Sequence[Mapping[str, object]],
    metrics: dict[str, dict[str, object]],
    run_state: dict[str, object],
) -> None:
    seen: set[str] = set()
    for row in records:
        phase = row.get("phase")
        if not isinstance(phase, str) or phase in seen:
            raise PerformanceModelError("phase artifact has missing or duplicate phase")
        seen.add(phase)
        elapsed_ms = row.get("elapsed_ms")
        if elapsed_ms is not None and phase in {"semantic-ingestion", "projection"}:
            metric_name = (
                "semantic_ingestion_seconds"
                if phase == "semantic-ingestion"
                else "projection_seconds"
            )
            _record_metric(
                metrics,
                metric_name,
                _finite_nonnegative(elapsed_ms, f"{phase} elapsed_ms") / 1000.0,
                "observed",
                f"bound phase-log {phase} elapsed_ms",
                priority=85,
            )
        storage = row.get("storage")
        if isinstance(storage, Mapping):
            _extract_storage(
                metrics,
                run_state,
                storage,
                basis=f"phase-log {phase}",
                priority=85,
            )
        run_state["projection_phase_observed"] = bool(
            run_state.get("projection_phase_observed") or phase == "projection"
        )


def _extract_interruption(
    record: Mapping[str, object],
    metrics: dict[str, dict[str, object]],
) -> None:
    run = _mapping(record.get("run"), "interruption run")
    workload = _mapping(run.get("requested_workload"), "interruption workload")
    _record_metric(
        metrics,
        "physical_files",
        _positive_int(workload.get("physical_files"), "interruption physical_files"),
        "observed",
        "SHA256-bound diagnostic interruption observation",
        priority=40,
    )
    if workload.get("core_valid_relations") is not None:
        _record_metric(
            metrics,
            "core_valid_relations",
            _positive_int(
                workload.get("core_valid_relations"), "interruption core_valid_relations"
            ),
            "observed",
            "SHA256-bound diagnostic interruption observation",
            priority=40,
        )
    ingestion = _mapping(record.get("physical_ingestion"), "physical_ingestion")
    _record_metric(
        metrics,
        "semantic_commits",
        _positive_int(ingestion.get("head_sequence"), "interruption head_sequence"),
        "observed",
        "SHA256-bound diagnostic interruption journal recount",
        priority=45,
    )
    _record_metric(
        metrics,
        "event_count",
        _positive_int(ingestion.get("event_count"), "interruption event_count"),
        "observed",
        "SHA256-bound diagnostic interruption journal recount",
        priority=45,
    )
    checkpoint = ingestion.get("checkpoint")
    if isinstance(checkpoint, Mapping):
        updates = checkpoint.get("state_binding_update_count")
        if updates is not None:
            _record_metric(
                metrics,
                "state_binding_updates",
                _positive_int(updates, "interruption state_binding_update_count"),
                "observed",
                "SHA256-bound diagnostic interruption checkpoint",
                priority=45,
            )


def _extract_records(
    records: Sequence[Mapping[str, object]],
    metrics: dict[str, dict[str, object]],
    run_state: dict[str, object],
) -> None:
    if all(record.get("record_type") is None for record in records):
        _extract_phase_rows(records, metrics, run_state)
        return
    for record in records:
        record_type = record.get("record_type")
        if record_type == "SaturationFailure":
            _extract_receipt(record, metrics, run_state)
        elif record_type == "DerivedJournalCheckpoint":
            _extract_journal_checkpoint(record, metrics)
        elif record_type == "SaturationOperationMetrics":
            _extract_operation_metrics(record, metrics, run_state)
        elif record_type == "ProminAlpha4R5Windows100kInterruptionObservation":
            _extract_interruption(record, metrics)
        elif record_type == "SaturationPhaseStorageMeasurement":
            _database_components(metrics, record, basis="standalone phase artifact")
            run_state["projection_phase_observed"] = bool(
                run_state.get("projection_phase_observed")
                or record.get("phase") == "projection"
            )
        elif isinstance(record.get("phase"), str):
            _extract_phase_rows([record], metrics, run_state)


def _ceil_div(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


def _semantic_shape(relations: int) -> tuple[int, int, int]:
    physical_relations = max(0, relations - _FIXED_SEARCH_RELATIONS)
    physical_commits = _ceil_div(
        physical_relations, _RELATIONS_PER_PHYSICAL_COMMIT
    )
    commits = _FIXED_SEMANTIC_COMMITS + physical_commits
    updates = relations + commits
    return commits, updates, physical_commits


def _update_batches(relations: int, commits: int) -> list[int]:
    physical_relations = max(0, relations - _FIXED_SEARCH_RELATIONS)
    fixed = [1] * _FIXED_GRANT_AND_CANDIDATE_COMMITS
    fixed.extend([2] * _FIXED_SEARCH_RELATIONS)
    fixed.extend([1] * (_FIXED_SEARCH_TASKS - _FIXED_SEARCH_RELATIONS))
    physical: list[int] = []
    remaining = physical_relations
    while remaining:
        selected = min(_RELATIONS_PER_PHYSICAL_COMMIT, remaining)
        physical.append(selected + 1)
        remaining -= selected
    result = fixed + physical
    updates = relations + commits
    if len(result) == commits and sum(result) == updates:
        return result
    # Supplemental evidence from a compatible but differently batched route is
    # retained without inventing its ordering: distribute exact observed totals
    # deterministically and label downstream prefix counts as estimates.
    if updates < commits:
        raise PerformanceModelError("state-binding updates cannot be fewer than commits")
    base, extra = divmod(updates, commits)
    return [base + (1 if index < extra else 0) for index in range(commits)]


def _prefix_rows_bounds(update_batches: Sequence[int]) -> tuple[int, int, float]:
    lower = 0
    upper = 0
    expected = 0.0
    for updates in update_batches:
        if updates < 1:
            raise PerformanceModelError("state-binding update batch must be positive")
        lower += updates + _TREE_DEPTH_BYTES
        upper += 1 + _TREE_DEPTH_BYTES * updates
        for depth in range(_STATE_BINDING_LEVELS):
            if depth == 0:
                expected += 1.0
                continue
            if depth == _TREE_DEPTH_BYTES:
                expected += float(updates)
                continue
            buckets = float(256**depth)
            if buckets > 1e15:
                distinct = updates - (updates * (updates - 1) / (2.0 * buckets))
            else:
                distinct = -buckets * math.expm1(
                    updates * math.log1p(-1.0 / buckets)
                )
            expected += distinct
    return lower, upper, round(expected, 3)


def _checkpoint_observation(
    run_state: Mapping[str, object],
    *,
    relations: int,
    commits: int,
    updates: int,
) -> tuple[dict[str, object], dict[str, object]]:
    raw = run_state.get("checkpoints")
    if not isinstance(raw, Mapping):
        return (
            {
                "available": False,
                "classification": "unavailable",
                "basis": "no bound per-commit checkpoint artifact was supplied",
            },
            {
                "cadence": None,
                "first_sequence": None,
                "bytes_per_update": None,
                "baseline_cumulative_bytes": None,
            },
        )
    records = [dict(item) for item in raw["records"]]
    writes = [item for item in records if item.get("checkpoint_written") is True]
    write_sequences = [int(item["sequence"]) for item in writes]
    deltas = [
        right - left for left, right in zip(write_sequences, write_sequences[1:])
    ]
    exact_cadence = bool(deltas) and len(set(deltas)) == 1
    cadence = deltas[0] if exact_cadence else (
        int(round(float(sorted(deltas)[len(deltas) // 2]))) if deltas else None
    )
    first_sequence = None
    if cadence is not None and write_sequences:
        first_sequence = write_sequences[0] % cadence or cadence
    payload_values = [
        _nonnegative_int(item.get("physical_payload_bytes", 0), "physical_payload_bytes")
        for item in records
    ]
    checkpoint_values = [
        _nonnegative_int(item.get("runtime_checkpoint_bytes", 0), "runtime_checkpoint_bytes")
        for item in writes
    ]
    payload_total = sum(payload_values)
    checkpoint_total = sum(checkpoint_values)
    batches = _update_batches(relations, commits)
    cumulative: list[int] = []
    running = 0
    for count in batches:
        running += count
        cumulative.append(running)
    ratios: list[float] = []
    for item in writes:
        sequence = int(item["sequence"])
        checkpoint_bytes = _nonnegative_int(
            item.get("runtime_checkpoint_bytes", 0), "runtime_checkpoint_bytes"
        )
        if checkpoint_bytes and sequence <= len(cumulative):
            ratios.append(checkpoint_bytes / cumulative[sequence - 1])
    if ratios:
        ordered = sorted(ratios)
        bytes_per_update = ordered[len(ordered) // 2]
    else:
        bytes_per_update = None
    observation: dict[str, object] = {
        "available": True,
        "source": raw["basis"],
        "commit_sequence_range": _metric(
            [int(records[0]["sequence"]), int(records[-1]["sequence"])],
            "observed",
            "bound checkpoint records",
        ),
        "checkpoint_write_sequences": _metric(
            write_sequences,
            "observed",
            "checkpoint_written=true records",
        ),
        "checkpoint_cadence_commits": _metric(
            cadence,
            "observed" if exact_cadence else "estimated",
            (
                "constant differences between bound checkpoint write sequences"
                if exact_cadence
                else "median difference between bound checkpoint write sequences"
            ),
        ),
        "inferred_first_checkpoint_sequence": _metric(
            first_sequence,
            "inferred",
            "periodic backward extension of the observed checkpoint cadence",
        ),
        "checkpoint_bytes": _metric(
            checkpoint_total,
            "observed",
            "sum of runtime_checkpoint_bytes in the bound checkpoint slice",
        ),
        "physical_payload_bytes": _metric(
            payload_total,
            "observed",
            "sum of physical_payload_bytes in the bound checkpoint slice",
        ),
        "checkpoint_payload_share": _metric(
            round(checkpoint_total / payload_total, 9) if payload_total else None,
            "derived",
            "checkpoint bytes divided by reported physical payload bytes in the same slice",
        ),
        "checkpoint_bytes_per_state_update": _metric(
            round(bytes_per_update, 9) if bytes_per_update is not None else None,
            "derived",
            "median checkpoint bytes divided by modeled cumulative state-binding updates",
        ),
    }
    if records and all("database_logical_bytes" in item for item in records):
        first_database = _nonnegative_int(
            records[0]["database_logical_bytes"], "first database_logical_bytes"
        )
        last_database = _nonnegative_int(
            records[-1]["database_logical_bytes"], "last database_logical_bytes"
        )
        observation["database_growth_bytes"] = _metric(
            last_database - first_database,
            "derived",
            "last minus first database bytes in the same bound checkpoint slice",
        )
    if writes and all("duration_ms" in item for item in writes):
        durations = [
            _finite_nonnegative(item["duration_ms"], "checkpoint duration_ms")
            for item in writes
        ]
        observation["checkpoint_commit_duration_ms"] = _metric(
            {
                "first": round(durations[0], 6),
                "last": round(durations[-1], 6),
                "growth_ratio": (
                    round(durations[-1] / durations[0], 9)
                    if durations[0] > 0
                    else None
                ),
            },
            "observed",
            "checkpoint commit durations in bound operation metrics",
        )
    schedule = _checkpoint_schedule(commits, first_sequence, cadence)
    baseline_bytes = None
    if bytes_per_update is not None:
        baseline_bytes = sum(
            int(round(bytes_per_update * cumulative[sequence - 1]))
            for sequence in schedule
        )
    parameters = {
        "cadence": cadence,
        "first_sequence": first_sequence,
        "bytes_per_update": bytes_per_update,
        "baseline_cumulative_bytes": baseline_bytes,
    }
    if running != updates:
        raise PerformanceModelError("state-binding update batches do not preserve total updates")
    return observation, parameters


def _checkpoint_schedule(
    commits: int,
    first_sequence: int | None,
    cadence: int | None,
) -> list[int]:
    if first_sequence is None or cadence is None or first_sequence > commits:
        return []
    return list(range(first_sequence, commits + 1, cadence))


def _scale_int(value: int, numerator: int, denominator: int) -> int:
    return (value * numerator + denominator // 2) // denominator


def _metric_value(metrics: Mapping[str, dict[str, object]], name: str) -> object | None:
    value = metrics.get(name)
    return None if value is None else value["value"]


def _prediction(
    *,
    target: int,
    baseline_metrics: Mapping[str, dict[str, object]],
    checkpoint_parameters: Mapping[str, object],
    baseline_work_units: float,
    state_binding_selects_per_commit: int,
) -> dict[str, object]:
    baseline_files = int(baseline_metrics["physical_files"]["value"])
    baseline_relations = int(baseline_metrics["core_valid_relations"]["value"])
    relations = max(1, _scale_int(baseline_relations, target, baseline_files))
    commits, updates, _physical_commits = _semantic_shape(relations)
    batches = _update_batches(relations, commits)
    row_min, row_max, row_expected = _prefix_rows_bounds(batches)
    selects = commits * state_binding_selects_per_commit
    entities = target + commits
    rebuilds = int(baseline_metrics["projection_rebuilds"]["value"])
    projection_rows = rebuilds * (entities + relations)

    cadence = checkpoint_parameters.get("cadence")
    first_sequence = checkpoint_parameters.get("first_sequence")
    schedule = _checkpoint_schedule(
        commits,
        int(first_sequence) if isinstance(first_sequence, int) else None,
        int(cadence) if isinstance(cadence, int) else None,
    )
    bytes_per_update = checkpoint_parameters.get("bytes_per_update")
    checkpoint_bytes: int | None = None
    checkpoint_last_bytes: int | None = None
    checkpoint_equivalent_updates = 0.0
    if isinstance(bytes_per_update, (int, float)) and float(bytes_per_update) > 0:
        running = 0
        cumulative: list[int] = []
        for count in batches:
            running += count
            cumulative.append(running)
        sizes = [
            int(round(float(bytes_per_update) * cumulative[sequence - 1]))
            for sequence in schedule
        ]
        checkpoint_bytes = sum(sizes)
        checkpoint_last_bytes = sizes[-1] if sizes else 0
        checkpoint_equivalent_updates = checkpoint_bytes / float(bytes_per_update)
    work_units = row_expected + checkpoint_equivalent_updates

    metrics: dict[str, dict[str, object]] = {
        "core_valid_relations": _metric(
            relations,
            "estimated",
            "r5 observed relation density scaled to target physical files",
        ),
        "semantic_commits": _metric(
            commits,
            "derived",
            "37 fixed semantic commits plus ceil(physical relations / 127)",
        ),
        "state_binding_updates": _metric(
            updates,
            "derived",
            "one state-binding update per semantic entity or Relation event",
        ),
        "state_binding_select_statements": _metric(
            selects,
            "derived",
            (
                f"{state_binding_selects_per_commit} source-derived state-binding "
                "SELECT statements per normal-path commit"
            ),
        ),
        "state_binding_rows_selected_lower_bound": _metric(
            row_min,
            "derived",
            "unique leaf rows plus the minimum shared byte-prefix path rows",
        ),
        "state_binding_rows_selected_upper_bound": _metric(
            row_max,
            "derived",
            "one root plus up to 32 non-root rows per update in each commit",
        ),
        "state_binding_rows_selected_uniform_hash_estimate": _metric(
            row_expected,
            "estimated",
            "expected distinct byte prefixes for uniformly distributed SHA-256 leaf keys",
        ),
        "state_binding_rows_written_lower_bound": _metric(
            row_min,
            "derived",
            "publication overlay has the same touched byte-prefix rows",
        ),
        "state_binding_rows_written_upper_bound": _metric(
            row_max,
            "derived",
            "publication overlay has the same touched byte-prefix rows",
        ),
        "runtime_checkpoint_writes": _metric(
            len(schedule),
            "estimated",
            "periodic extension of observed checkpoint cadence",
        ),
        "runtime_checkpoint_bytes": _metric(
            checkpoint_bytes,
            "estimated" if checkpoint_bytes is not None else "unavailable",
            "sum of estimated full checkpoint bytes at each modeled checkpoint sequence",
        ),
        "runtime_checkpoint_last_bytes": _metric(
            checkpoint_last_bytes,
            "estimated" if checkpoint_last_bytes is not None else "unavailable",
            "state-update-normalized estimate for the last checkpoint",
        ),
        "projection_entities": _metric(
            entities,
            "derived",
            "one Artifact per physical file plus Candidate, Grant, and Task entities",
        ),
        "projection_relations": _metric(
            relations,
            "estimated",
            "same scaled Core-valid relation contour used by ingestion",
        ),
        "projection_rebuilds": _metric(
            rebuilds,
            str(baseline_metrics["projection_rebuilds"]["classification"]),
            "constant rebuild count from the bound baseline route",
        ),
        "projection_rows_processed": _metric(
            projection_rows,
            "derived",
            "projection rebuild count multiplied by entity and Relation rows",
        ),
        "modeled_ingestion_work_units": _metric(
            round(work_units, 3),
            "estimated",
            "uniform-hash state rows plus full-checkpoint update-equivalent writes",
        ),
    }
    baseline_updates = int(baseline_metrics["state_binding_updates"]["value"])
    for name in (
        "event_identity_database_bytes",
        "state_binding_database_bytes",
        "derived_rows_database_bytes",
        "ingestion_database_bytes",
    ):
        value = _metric_value(baseline_metrics, name)
        if isinstance(value, int):
            metrics[name] = _metric(
                _scale_int(value, updates, baseline_updates),
                "estimated",
                "bound baseline bytes scaled by modeled state-binding updates",
            )
    baseline_projection_bytes = _metric_value(
        baseline_metrics, "projection_database_bytes"
    )
    baseline_projection_entities = int(
        baseline_metrics["projection_entities"]["value"]
    )
    baseline_projection_relations = int(
        baseline_metrics["projection_relations"]["value"]
    )
    if isinstance(baseline_projection_bytes, int):
        metrics["projection_database_bytes"] = _metric(
            _scale_int(
                baseline_projection_bytes,
                entities + relations,
                baseline_projection_entities + baseline_projection_relations,
            ),
            "estimated",
            "bound projection bytes scaled by modeled entity and Relation rows",
        )
    baseline_ingestion_seconds = _metric_value(
        baseline_metrics, "semantic_ingestion_seconds"
    )
    if isinstance(baseline_ingestion_seconds, (int, float)) and baseline_work_units > 0:
        metrics["semantic_ingestion_seconds"] = _metric(
            round(float(baseline_ingestion_seconds) * work_units / baseline_work_units, 6),
            "estimated",
            "bound baseline time scaled by modeled ingestion work units",
        )
    baseline_projection_seconds = _metric_value(
        baseline_metrics, "projection_seconds"
    )
    baseline_projection_rows = int(
        baseline_metrics["projection_rows_processed"]["value"]
    )
    if isinstance(baseline_projection_seconds, (int, float)) and baseline_projection_rows > 0:
        metrics["projection_seconds"] = _metric(
            round(
                float(baseline_projection_seconds)
                * projection_rows
                / baseline_projection_rows,
                6,
            ),
            "estimated",
            "bound baseline projection time scaled by modeled projection rows",
        )
    return {
        "physical_files": target,
        "metrics": metrics,
        "claims": dict(_CLAIMS),
    }


def _targets(value: Sequence[int]) -> tuple[int, ...]:
    targets = tuple(value)
    if (
        len(targets) < 1
        or any(isinstance(item, bool) or not isinstance(item, int) or item < 1 for item in targets)
        or tuple(sorted(targets)) != targets
        or len(set(targets)) != len(targets)
    ):
        raise PerformanceModelError("targets must be unique, positive, and strictly increasing")
    return targets


def build_performance_model(
    *,
    receipt_path: Path | None = None,
    phase_artifact_paths: Sequence[Path] = (),
    targets: Sequence[int] = DEFAULT_TARGETS,
    run_label: str = "baseline",
) -> dict[str, object]:
    """Verify supplied evidence and return one deterministic claim-free model."""

    selected_targets = _targets(targets)
    sql_geometry = derive_state_binding_sql_geometry()
    normal_sql = _mapping(
        sql_geometry.get("normal_path"), "state-binding SQL geometry"
    )
    state_binding_selects_per_commit = _positive_int(
        normal_sql.get("select_statements_per_commit"),
        "state-binding SELECT statements per commit",
    )
    if not isinstance(run_label, str) or not run_label.strip() or run_label != run_label.strip():
        raise PerformanceModelError("run_label must be a non-empty trimmed string")
    paths: list[Path] = []
    if receipt_path is not None:
        paths.append(Path(receipt_path))
    paths.extend(Path(path) for path in phase_artifact_paths)
    if not paths:
        raise PerformanceModelError("at least one bound receipt or phase artifact is required")
    absolute = [Path(os.path.abspath(path)) for path in paths]
    if len(set(os.path.normcase(str(path)) for path in absolute)) != len(absolute):
        raise PerformanceModelError("evidence artifact paths must not be duplicated")

    sources: list[dict[str, object]] = []
    metrics: dict[str, dict[str, object]] = {}
    run_state: dict[str, object] = {}
    for path in paths:
        binding, records = _load_source(path)
        sources.append(binding)
        _extract_records(records, metrics, run_state)

    if "physical_files" not in metrics or "core_valid_relations" not in metrics:
        raise PerformanceModelError(
            "bound evidence must provide physical_files and core_valid_relations"
        )
    files = int(metrics["physical_files"]["value"])
    relations = int(metrics["core_valid_relations"]["value"])
    derived_commits, derived_updates, _physical_commits = _semantic_shape(relations)
    if "semantic_commits" not in metrics:
        _record_metric(
            metrics,
            "semantic_commits",
            derived_commits,
            "inferred",
            "r5 semantic corpus batching shape",
            priority=10,
        )
    commits = int(metrics["semantic_commits"]["value"])
    if "state_binding_updates" not in metrics:
        _record_metric(
            metrics,
            "state_binding_updates",
            relations + commits,
            "inferred",
            "one state-binding update per semantic entity or Relation event",
            priority=10,
        )
    updates = int(metrics["state_binding_updates"]["value"])
    if commits == derived_commits and updates != derived_updates:
        raise PerformanceModelError(
            "bound state_binding_updates disagree with the r5 semantic event contour"
        )
    if "event_count" in metrics and int(metrics["event_count"]["value"]) != updates:
        raise PerformanceModelError(
            "bound event_count differs from state_binding_update_count"
        )

    projection_entities = files + commits
    if "projection_entities" not in metrics:
        _record_metric(
            metrics,
            "projection_entities",
            projection_entities,
            "inferred",
            "one Artifact per file plus Candidate, Grant, and Task entities",
            priority=10,
        )
    if "projection_relations" not in metrics:
        _record_metric(
            metrics,
            "projection_relations",
            relations,
            "inferred",
            "projection consumes the bound Core-valid relation corpus",
            priority=10,
        )
    if "projection_rebuilds" not in metrics:
        if not run_state.get("projection_phase_observed"):
            raise PerformanceModelError(
                "bound evidence does not establish that the projection phase was reached"
            )
        _record_metric(
            metrics,
            "projection_rebuilds",
            2,
            "inferred",
            "r5 saturation route performs initial projection and deterministic rebuild",
            priority=10,
        )
    rebuilds = int(metrics["projection_rebuilds"]["value"])
    _record_metric(
        metrics,
        "projection_rows_processed",
        rebuilds
        * (
            int(metrics["projection_entities"]["value"])
            + int(metrics["projection_relations"]["value"])
        ),
        "derived",
        "projection rebuild count multiplied by bound entities and Relations",
        priority=20,
    )

    update_batches = _update_batches(relations, commits)
    row_min, row_max, row_expected = _prefix_rows_bounds(update_batches)
    _record_metric(
        metrics,
        "state_binding_select_statements",
        commits * state_binding_selects_per_commit,
        "derived",
        (
            "exact current EventStore source: binding and node-union "
            "Connection.execute SELECT statements on the normal commit path"
        ),
        priority=20,
    )
    _record_metric(
        metrics,
        "state_binding_rows_selected_lower_bound",
        row_min,
        "derived",
        "minimum touched byte-prefix rows for the bound update batches",
        priority=20,
    )
    _record_metric(
        metrics,
        "state_binding_rows_selected_upper_bound",
        row_max,
        "derived",
        "maximum touched byte-prefix rows for the bound update batches",
        priority=20,
    )
    _record_metric(
        metrics,
        "state_binding_rows_selected_uniform_hash_estimate",
        row_expected,
        "estimated",
        "uniform SHA-256 byte-prefix occupancy for the bound update batches",
        priority=20,
    )

    observed_tail, checkpoint_parameters = _checkpoint_observation(
        run_state,
        relations=relations,
        commits=commits,
        updates=updates,
    )
    baseline_checkpoint_bytes = checkpoint_parameters.get("baseline_cumulative_bytes")
    checkpoint_equivalent_updates = 0.0
    bytes_per_update = checkpoint_parameters.get("bytes_per_update")
    if (
        isinstance(baseline_checkpoint_bytes, int)
        and isinstance(bytes_per_update, (int, float))
        and float(bytes_per_update) > 0
    ):
        checkpoint_equivalent_updates = baseline_checkpoint_bytes / float(bytes_per_update)
    baseline_work_units = row_expected + checkpoint_equivalent_updates

    baseline_public = {
        name: {
            key: value
            for key, value in item.items()
            if key != "priority"
        }
        for name, item in sorted(metrics.items())
    }
    predictions = [
        _prediction(
            target=target,
            baseline_metrics=baseline_public,
            checkpoint_parameters=checkpoint_parameters,
            baseline_work_units=baseline_work_units,
            state_binding_selects_per_commit=(
                state_binding_selects_per_commit
            ),
        )
        for target in selected_targets
    ]
    report: dict[str, object] = {
        "schema": MODEL_SCHEMA,
        "record_type": "ProminPerformanceComplexityModel",
        "status": "diagnostic-model",
        "run_label": run_label,
        "evidence_class": "bound-observation-and-explicit-estimation",
        "sources": sources,
        "baseline": {
            "physical_files": files,
            "metrics": baseline_public,
        },
        "observed_checkpoint_tail": observed_tail,
        "algorithm_source": sql_geometry["source"],
        "algorithm_shape": {
            "state_binding_tree_depth_bytes": _TREE_DEPTH_BYTES,
            "state_binding_selected_levels_per_commit": _STATE_BINDING_LEVELS,
            "state_binding_binding_select_statements_per_commit": normal_sql[
                "binding_select_statements_per_commit"
            ],
            "state_binding_node_union_select_statements_per_commit": normal_sql[
                "node_union_select_statements_per_commit"
            ],
            "state_binding_legacy_depth_range_helper_calls_per_commit": normal_sql[
                "legacy_depth_range_helper_calls_per_commit"
            ],
            "state_binding_select_statements_per_commit": (
                state_binding_selects_per_commit
            ),
            "state_binding_storage_mode_pragma_statements_per_commit": normal_sql[
                "storage_mode_pragma_statements_per_commit"
            ],
            "state_binding_sql_geometry_derivation": sql_geometry["derivation"],
            "physical_relations_per_commit": _RELATIONS_PER_PHYSICAL_COMMIT,
            "fixed_semantic_commits": _FIXED_SEMANTIC_COMMITS,
        },
        "complexity": {
            "semantic_commits": {
                "order": "O(N / 127)",
                "classification": "derived",
                "scope": "r5 physical relation batching",
            },
            "state_binding_rows": {
                "order": "O(U * 32)",
                "classification": "derived",
                "scope": "normal commit path without recovery replay",
            },
            "runtime_checkpoint_bytes": {
                "order": "O(N^2 / B)",
                "classification": "inferred",
                "scope": (
                    "full-state checkpoint bytes under approximately constant B-commit cadence; "
                    "this is a growth model, not a measured timing exponent"
                ),
            },
            "projection_rebuild_rows": {
                "order": "O(R * (E + L))",
                "classification": "derived",
                "scope": "R rebuilds over E entities and L Relations",
            },
        },
        "predictions": predictions,
        "comparison_dimensions": [
            "semantic_commits",
            "state_binding_select_statements",
            "state_binding_rows_selected_uniform_hash_estimate",
            "runtime_checkpoint_bytes",
            "ingestion_database_bytes",
            "projection_rows_processed",
            "projection_database_bytes",
            "semantic_ingestion_seconds",
            "projection_seconds",
        ],
        "limitations": [
            "The model is diagnostic evidence and does not establish a performance exponent by itself.",
            "Prefix-row expectations assume uniformly distributed SHA-256 leaf keys; exact lower and upper bounds are emitted separately.",
            "State-binding SELECT counts cover the normal commit path and exclude recovery/replay fallback work.",
            "Checkpoint projections extend the observed cadence and full-checkpoint byte density; they are estimates, not measurements.",
            "A projection phase in a failure receipt proves stored phase state, while its two-rebuild count remains an inference unless operation metrics are supplied.",
        ],
        "thresholds_evaluated": False,
        "claims": dict(_CLAIMS),
    }
    report["model_digest"] = digest_value(report)
    return report


def _parse_targets(value: str) -> tuple[int, ...]:
    try:
        parsed = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError("targets must be comma-separated integers") from exc
    try:
        return _targets(parsed)
    except PerformanceModelError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument(
        "--phase-artifact",
        action="append",
        type=Path,
        default=[],
        help="bound phase-log, operation-metrics, journal-checkpoint, or diagnostic observation; repeatable",
    )
    parser.add_argument(
        "--targets",
        type=_parse_targets,
        default=DEFAULT_TARGETS,
        help="strictly increasing comma-separated physical-file counts",
    )
    parser.add_argument("--run-label", default="baseline")
    parser.add_argument("--output", type=Path)
    return parser


def _emit(payload: Mapping[str, object], output: Path | None, sources: Sequence[Path]) -> None:
    encoded = canonical_bytes(dict(payload))
    if output is not None:
        destination = Path(os.path.abspath(output))
        normalized_sources = {os.path.normcase(str(Path(os.path.abspath(path)))) for path in sources}
        if os.path.normcase(str(destination)) in normalized_sources:
            raise PerformanceModelError("output must not overwrite a source evidence artifact")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(encoded)
    sys.stdout.buffer.write(encoded)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    sources = ([args.receipt] if args.receipt is not None else []) + list(
        args.phase_artifact
    )
    try:
        report = build_performance_model(
            receipt_path=args.receipt,
            phase_artifact_paths=args.phase_artifact,
            targets=args.targets,
            run_label=args.run_label,
        )
        _emit(report, args.output, sources)
        return 0
    except (CanonicalError, OSError, PerformanceModelError) as exc:
        failure = {
            "schema": MODEL_SCHEMA,
            "record_type": "ProminPerformanceComplexityModelFailure",
            "status": "rejected",
            "reason": str(exc).replace("\r", " ").replace("\n", " ")[:2048],
            "thresholds_evaluated": False,
            "claims": dict(_CLAIMS),
        }
        try:
            _emit(failure, args.output, sources)
        except (OSError, PerformanceModelError):
            sys.stdout.buffer.write(canonical_bytes(failure))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
