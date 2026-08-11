from __future__ import annotations

import hashlib
import random
import sqlite3
from contextlib import closing
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from promin.authority import AuthorityEngine
from promin.canonical import (
    CanonicalError,
    ParseLimits,
    canonical_bytes,
    digest_value,
    digest_value_streaming,
)
from promin.events import DerivedCheckpointError, SimulatedCrash
from promin.service import ProminService, ServiceError
from test_heavy_event_batching import NOW, _command, _store
from test_heavy_relation_ledger_hotpath import (  # type: ignore[import-not-found]
    _grant_authorization,
    _issued_at,
    _service_command,
    _service_with_relation_grants,
    _task_with_gate_definition,
)


def test_streaming_canonical_digest_matches_existing_identity_and_scales() -> None:
    representative = {
        "unicode": "e\u0301",
        "nested": [None, True, False, -17, -0.0, 1.25, {"z": "last", "a": "first"}],
    }
    assert digest_value_streaming(representative) == digest_value(representative)

    payload = "x" * 4_096
    row_count = 4_200
    aggregate = {"rows": [payload] * row_count}
    with pytest.raises(CanonicalError, match="canonical JSON exceeds"):
        digest_value(aggregate)

    expected = hashlib.sha256()
    expected.update(b'{"rows":[')
    encoded_payload = b'"' + payload.encode("ascii") + b'"'
    for index in range(row_count):
        if index:
            expected.update(b",")
        expected.update(encoded_payload)
    expected.update(b"]}\n")
    assert digest_value_streaming(
        aggregate,
        limits=ParseLimits(max_bytes=32 * 1024 * 1024, max_items=10_000),
    ) == expected.hexdigest()


def test_streaming_canonical_digest_matches_randomized_canonical_values() -> None:
    randomizer = random.Random(0xA4_CAFE)
    scalar_values = [
        None,
        True,
        False,
        0,
        -1,
        2**63,
        -0.0,
        1.25,
        "",
        "quote:\" slash:\\ newline:\n",
        "e\u0301",
        "Україна",
    ]

    def value(depth: int):
        if depth >= 4 or randomizer.random() < 0.45:
            return deepcopy(randomizer.choice(scalar_values))
        if randomizer.random() < 0.5:
            return [value(depth + 1) for _unused in range(randomizer.randrange(6))]
        keys = randomizer.sample(
            ["a", "b", "z", "é", "ключ", "line\nkey"],
            randomizer.randrange(6),
        )
        return {key: value(depth + 1) for key in keys}

    for _unused in range(500):
        candidate = value(0)
        assert digest_value_streaming(candidate) == digest_value(candidate)

    invalid_values = [
        {"é": 1, "e\u0301": 2},
        {1: "non-string-key"},
        ("tuple",),
        float("nan"),
        float("inf"),
    ]
    for candidate in invalid_values:
        with pytest.raises(CanonicalError):
            digest_value(candidate)
        with pytest.raises(CanonicalError):
            digest_value_streaming(candidate)


def test_large_authority_checkpoint_roundtrips_beyond_aggregate_limit(
    tmp_path: Path,
) -> None:
    service, _candidate, _planner, _head, _activation = _service_with_relation_grants(
        tmp_path
    )
    context = service._context()
    store = service._event_store(context)
    snapshot = service._runtime_state(context, store)
    authority = snapshot.authority
    overlay_type = type(authority._candidate_actions)
    ((unused_identity, template_provenance),) = tuple(
        authority._candidate_actions.items()
    )
    _unused_target, capability = unused_identity
    template = template_provenance[0]
    action_count = 30_000
    actions = {}
    for index in range(action_count):
        target = f"{index:064x}"
        value = deepcopy(template)
        value["target_id"] = target
        actions[(target, capability)] = (value,)
    authority._candidate_actions = overlay_type(values=actions, sealed=True)

    try:
        checkpoint = authority.checkpoint()
        assert len(checkpoint["candidate_actions"]) == action_count
        with pytest.raises(CanonicalError, match="canonical JSON exceeds"):
            canonical_bytes(checkpoint)

        restored = AuthorityEngine(
            authority._authority_init,
            authority.activation_digest,
            authority._runtime_policy,
            signature_verifier=authority.signature_verifier,
            decision_resolver=authority.decision_resolver,
        )
        restored.restore_checkpoint(checkpoint)
        restored_checkpoint = restored.checkpoint()
        assert restored_checkpoint["checkpoint_digest"] == checkpoint["checkpoint_digest"]
        assert len(restored_checkpoint["candidate_actions"]) == action_count
    finally:
        store.close()
        service.close()


def test_derived_rows_exceed_aggregate_json_limit_and_reopen_exactly(
    tmp_path: Path,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    try:
        committed = store.commit(_command(9001), created_at=NOW)
        assert committed["outcome"] == "committed"
        row_count = 4_200
        payload = "x" * 4_096

        def rows():
            for index in range(row_count):
                yield {
                    "section": "large.records",
                    "key": f"{index:012d}",
                    "value": {"index": index, "payload": payload},
                }

        logical_bytes = sum(len(canonical_bytes(row)) for row in rows())
        assert logical_bytes > 16 * 1024 * 1024
        manifest = store.write_derived_rows(
            "large-runtime",
            rows(),
            expected_head=store.head(),
            checkpoint_count=1,
        )
        assert manifest["row_count"] == row_count
        assert store.derived_rows_storage_bytes("large-runtime") > 16 * 1024 * 1024
    finally:
        store.close()

    reopened = _store(root)
    observed_count = 0
    observed_digest = hashlib.sha256()

    def consume(row):
        nonlocal observed_count
        observed_count += 1
        observed_digest.update(canonical_bytes(row))

    try:
        manifest = reopened.consume_derived_rows("large-runtime", consume)
        assert manifest is not None
        assert manifest["row_count"] == row_count
        assert observed_count == row_count
        assert observed_digest.hexdigest() == hashlib.sha256(
            b"".join(canonical_bytes(row) for row in rows())
        ).hexdigest()
    finally:
        reopened.close()


def test_derived_rows_crash_is_old_or_new_and_tamper_is_a_cache_miss(
    tmp_path: Path,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    try:
        store.commit(_command(9002), created_at=NOW)

        def rows(label: str):
            return [
                {
                    "section": "runtime.records",
                    "key": f"{index:012d}",
                    "value": {"index": index, "label": label},
                }
                for index in range(4)
            ]

        original = store.write_derived_rows(
            "crash-runtime",
            rows("old"),
            expected_head=store.head(),
            checkpoint_count=1,
        )
        with pytest.raises(SimulatedCrash):
            store.write_derived_rows(
                "crash-runtime",
                rows("discarded"),
                expected_head=store.head(),
                checkpoint_count=2,
                crash_hook=lambda point: point == "before_derived_rows_checkpoint",
            )
        observed: list[dict] = []
        assert store.consume_derived_rows("crash-runtime", observed.append) == original
        assert [row["value"]["label"] for row in observed] == ["old"] * 4

        with pytest.raises(SimulatedCrash):
            store.write_derived_rows(
                "crash-runtime",
                rows("new"),
                expected_head=store.head(),
                checkpoint_count=2,
                crash_hook=lambda point: point == "after_derived_rows_checkpoint",
            )
        observed = []
        current = store.consume_derived_rows("crash-runtime", observed.append)
        assert current is not None and current["checkpoint_count"] == 2
        assert [row["value"]["label"] for row in observed] == ["new"] * 4

        with pytest.raises(DerivedCheckpointError, match="unique canonical order"):
            store.write_derived_rows(
                "crash-runtime",
                [rows("bad")[1], rows("bad")[0]],
                expected_head=store.head(),
                checkpoint_count=3,
            )
        assert store.consume_derived_rows("crash-runtime", lambda _row: None) == current
        path = store._derived_rows_path("crash-runtime")
    finally:
        store.close()

    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            "UPDATE derived_row SET payload=? WHERE section=? AND key=?",
            (b'{}', "runtime.records", "000000000000"),
        )
        connection.commit()

    reopened = _store(root)
    try:
        assert reopened.consume_derived_rows("crash-runtime", lambda _row: None) is None
        issue = reopened.derived_rows_issue("crash-runtime")
        assert isinstance(issue, str) and "DerivedCheckpointError" in issue
        assert reopened.head()["sequence"] == 1
    finally:
        reopened.close()


@pytest.mark.performance
def test_199k_semantic_rows_remain_one_bounded_checkpoint_file(
    tmp_path: Path,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    row_count = 199_000

    def rows():
        for index in range(row_count):
            yield {
                "section": "runtime.relations",
                "key": f"{index:012d}",
                "value": {
                    "relation_id": f"relation:checkpoint:{index:06d}",
                    "kind": "READS",
                },
            }

    try:
        store.commit(_command(9003), created_at=NOW)
        manifest = store.write_derived_rows(
            "cardinality-runtime",
            rows(),
            expected_head=store.head(),
            checkpoint_count=1,
        )
        path = store._derived_rows_path("cardinality-runtime")
        assert manifest["row_count"] == row_count
        assert len(canonical_bytes(manifest)) < 16 * 1024
        assert 0 < path.stat().st_size < 256 * 1024 * 1024
        assert list(path.parent.glob("*.sqlite3")) == [path]
    finally:
        store.close()

    reopened = _store(root)
    observed = 0

    def consume(_row):
        nonlocal observed
        observed += 1

    try:
        manifest = reopened.consume_derived_rows("cardinality-runtime", consume)
        assert manifest is not None
        assert manifest["row_count"] == row_count
        assert observed == row_count
        assert len(list(reopened.derived_rows_root.glob("*"))) == 1
    finally:
        reopened.close()


def test_service_runtime_uses_one_normalized_checkpoint_and_reopens(
    tmp_path: Path,
    monkeypatch,
) -> None:
    service, _candidate, _planner, _head, _activation = _service_with_relation_grants(
        tmp_path
    )
    context = service._context()
    store = service._event_store(context)
    snapshot = service._runtime_state(context, store)
    validation_calls = 0
    original_validate = store.validate_state_binding_commitments

    def counted_validate(*args, **kwargs):
        nonlocal validation_calls
        validation_calls += 1
        return original_validate(*args, **kwargs)

    monkeypatch.setattr(store, "validate_state_binding_commitments", counted_validate)
    metrics = service._write_runtime_checkpoint(
        context,
        store,
        snapshot,
        force=True,
    )
    rows_root = service.root / ".promin" / "state" / "events" / "derived-rows"
    runtime_path = rows_root / (hashlib.sha256(b"runtime").hexdigest() + ".sqlite3")
    assert metrics["written"] is True
    assert validation_calls == 0
    assert metrics["authoritative"] is False
    assert metrics["checkpoint_bytes"] == runtime_path.stat().st_size
    assert list(rows_root.glob("*.sqlite3")) == [runtime_path]
    assert not (
        service.root
        / ".promin"
        / "state"
        / "events"
        / "derived-state"
        / (hashlib.sha256(b"runtime").hexdigest() + ".json")
    ).exists()
    expected_tasks = set(snapshot.domain.tasks)
    expected_relations = snapshot.relations.count()
    project_root = service.root
    with pytest.raises(ServiceError, match="journal authority"):
        service._write_runtime_checkpoint(
            context,
            store,
            replace(snapshot, state_binding_digest="f" * 64),
            force=True,
        )
    service.close()

    reopened = ProminService(project_root)
    try:
        context = reopened._context()
        store = reopened._event_store(context)
        restored = reopened._runtime_state(context, store)
        assert set(restored.domain.tasks) == expected_tasks
        assert restored.relations.count() == expected_relations
        assert restored.state_binding_digest == snapshot.state_binding_digest
        assert reopened._runtime_checkpoint_cursor is not None
        assert reopened._runtime_checkpoint_cursor.checkpoint_count >= 1
    finally:
        reopened.close()


def test_postcommit_checkpoint_failure_preserves_commit_and_replay(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """A disposable checkpoint failure cannot negate an authoritative batch."""

    service, candidate, planner, head, activation = _service_with_relation_grants(
        tmp_path
    )
    issued_at = _issued_at()
    task = _task_with_gate_definition(
        service,
        {
            "record_type": "Task",
            "task_id": "task:checkpoint-storage-unavailable",
            "state": "PLANNED",
            "required_capability": "task.execute",
            "acceptance_predicate": "durable commit survives derived storage failure",
            "allowed_paths": ["product/**"],
            "activation_digest": activation,
            "candidate_digest": candidate["candidate_digest"],
            "created_at": issued_at,
        },
        defined_at_head_digest=head,
        gate_id="gate:checkpoint-storage-unavailable",
    )
    command = _service_command(
        activation_digest=activation,
        command_id="command:checkpoint-storage-unavailable",
        command_kind="task.record",
        payload=task,
        expected_head=head,
        issued_at=issued_at,
        authorization=_grant_authorization(planner),
    )

    def unavailable_checkpoint(*_args, **_kwargs):
        raise OSError(28, "simulated derived checkpoint disk full")

    monkeypatch.setattr(service, "_write_runtime_checkpoint", unavailable_checkpoint)
    committed = service.commit(command)

    assert committed["outcome"] == "committed"
    checkpoint = committed["operation_metrics"]["runtime_checkpoint"]
    assert checkpoint["written"] is False
    assert checkpoint["status"] == "unavailable"
    assert checkpoint["authoritative"] is False
    assert checkpoint["checkpoint_bytes"] == 0
    assert checkpoint["checkpoint_count"] >= 1
    assert checkpoint["tail_batches"] >= 1
    assert checkpoint["tail_bytes"] > 0
    assert checkpoint["issue"] == "derived-checkpoint-unavailable"
    assert checkpoint["error_type"] == "OSError"

    reopened = ProminService(service.root)
    context = reopened._context()
    store = reopened._event_store(context)
    assert store.head()["batch_digest"] == committed["batch_digest"]
    replayed = reopened._runtime_state(context, store)
    assert task["task_id"] in replayed.domain.tasks
    reopened.close()
    service.close()


def test_validated_replay_reports_disposable_checkpoint_unavailable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    service, _candidate, _planner, _head, _activation = _service_with_relation_grants(
        tmp_path
    )

    def unavailable_checkpoint(*_args, **_kwargs):
        raise OSError(28, "simulated replay checkpoint disk full")

    monkeypatch.setattr(service, "_write_runtime_checkpoint", unavailable_checkpoint)
    try:
        context = service._context()
        store = service._event_store(context)
        result = service._replay_validated(context, store)
        assert result["status"] == "pass"
        assert result["runtime_checkpoint_written"] is False
        assert result["runtime_checkpoint_authoritative"] is False
        assert result["runtime_checkpoint"]["status"] == "unavailable"
        assert result["runtime_checkpoint"]["issue"] == "derived-checkpoint-unavailable"
        assert result["runtime_checkpoint"]["error_type"] == "OSError"
    finally:
        service.close()
