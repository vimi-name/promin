from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import promin.events as events_module
from promin.events import DerivedCheckpointError, SimulatedCrash
from promin.service import ProminService
from test_heavy_event_batching import NOW, _command, _store
from test_heavy_relation_ledger_hotpath import (  # type: ignore[import-not-found]
    _grant_authorization,
    _issued_at,
    _relation,
    _service_command,
    _service_with_relation_grants,
    _task_with_gate_definition,
)


def _runtime_rows(label: str, relation_ids: tuple[str, ...]) -> list[dict[str, object]]:
    return [
        {
            "section": "00.runtime",
            "key": "header",
            "value": {"label": label, "record_type": "RuntimeRowsState"},
        },
        *[
            {
                "section": "40.relations.records",
                "key": relation_id,
                "value": {
                    "record_type": "Relation",
                    "relation_id": relation_id,
                    "kind": "READS",
                },
            }
            for relation_id in relation_ids
        ],
    ]


def test_runtime_v2_checkpoint_is_in_place_incremental_and_tamper_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    try:
        store.commit(_command(9811), created_at=NOW)
        first_rows = _runtime_rows(
            "first",
            ("relation:incremental:001", "relation:incremental:002"),
        )
        first = store.write_runtime_rows_v2(
            first_rows,
            expected_head=store.head(),
            checkpoint_count=1,
        )
        assert first["version"] == 2
        assert first["row_count"] == 3
        assert first["row_merkle_digest"]

        # A v2 compaction updates its current SQLite generation.  Replacing the
        # complete file would turn every due checkpoint into an O(runtime-size)
        # write again, so this path must never call the v1 replacement helper.
        monkeypatch.setattr(
            events_module,
            "_replace_durable",
            lambda *_args, **_kwargs: pytest.fail("v2 must not replace its database"),
        )
        second = store.write_runtime_rows_v2(
            _runtime_rows("second", ("relation:incremental:003",)),
            expected_head=store.head(),
            checkpoint_count=2,
        )
        assert second["version"] == 2
        assert second["row_count"] == 4
        assert second["checkpoint_count"] == 2
        assert second["row_merkle_digest"] != first["row_merkle_digest"]

        observed: list[dict[str, object]] = []
        assert store.consume_derived_rows("runtime", observed.append) == second
        assert {row["key"] for row in observed} == {
            "header",
            "relation:incremental:001",
            "relation:incremental:002",
            "relation:incremental:003",
        }

        with pytest.raises(SimulatedCrash):
            store.write_runtime_rows_v2(
                _runtime_rows("discarded", ("relation:incremental:004",)),
                expected_head=store.head(),
                checkpoint_count=3,
                crash_hook=lambda point: point == "before_runtime_rows_v2_commit",
            )
        preserved: list[dict[str, object]] = []
        assert store.consume_derived_rows("runtime", preserved.append) == second
        assert all(row["value"].get("label") != "discarded" for row in preserved)

        with pytest.raises(SimulatedCrash):
            store.write_runtime_rows_v2(
                _runtime_rows("third", ("relation:incremental:004",)),
                expected_head=store.head(),
                checkpoint_count=3,
                crash_hook=lambda point: point == "after_runtime_rows_v2_commit",
            )
        current: list[dict[str, object]] = []
        manifest = store.consume_derived_rows("runtime", current.append)
        assert manifest is not None and manifest["checkpoint_count"] == 3
        assert {row["key"] for row in current} >= {"relation:incremental:004"}
        path = store._derived_rows_path("runtime")
    finally:
        store.close()

    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE derived_row SET payload = ? WHERE section = ? AND key = ?",
            (b"{}", "40.relations.records", "relation:incremental:004"),
        )
        connection.commit()

    reopened = _store(root)
    try:
        assert reopened.consume_derived_rows("runtime", lambda _row: None) is None
        issue = reopened.derived_rows_issue("runtime")
        assert isinstance(issue, str) and "DerivedCheckpointError" in issue
        assert reopened.head()["sequence"] == 1
    finally:
        reopened.close()


def test_runtime_v1_checkpoint_migrates_in_place_only_when_v2_bootstraps(
    tmp_path: Path,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    try:
        store.commit(_command(9812), created_at=NOW)
        legacy_rows = _runtime_rows("legacy", ("relation:legacy:001",))
        legacy = store.write_derived_rows(
            "runtime",
            legacy_rows,
            expected_head=store.head(),
            checkpoint_count=1,
        )
        migrated = store.write_runtime_rows_v2(
            _runtime_rows(
                "migrated",
                ("relation:legacy:001", "relation:legacy:002"),
            ),
            expected_head=store.head(),
            checkpoint_count=2,
        )
        assert legacy["version"] == 1
        assert migrated["version"] == 2
        rows: list[dict[str, object]] = []
        assert store.consume_derived_rows("runtime", rows.append) == migrated
        assert {row["key"] for row in rows} == {
            "header",
            "relation:legacy:001",
            "relation:legacy:002",
        }
    finally:
        store.close()


def test_runtime_v2_restores_stable_relation_rows_with_full_journal_parity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, candidate, planner, head, activation = _service_with_relation_grants(
        tmp_path
    )
    issued_at = _issued_at()
    task = _task_with_gate_definition(
        service,
        {
            "record_type": "Task",
            "task_id": "task:runtime-v2-relation",
            "state": "PLANNED",
            "required_capability": "task.execute",
            "acceptance_predicate": "runtime v2 restores immutable relation identities",
            "allowed_paths": ["product/**"],
            "activation_digest": activation,
            "candidate_digest": candidate["candidate_digest"],
            "created_at": issued_at,
        },
        defined_at_head_digest=head,
        gate_id="gate:runtime-v2-relation",
    )
    command = _service_command(
        activation_digest=activation,
        command_id="command:runtime-v2-relation",
        command_kind="task.record",
        payload=task,
        expected_head=head,
        issued_at=issued_at,
        authorization=_grant_authorization(planner),
    )
    relation_id = "relation:runtime-v2-stable"
    service.commit(
        command,
        auxiliary_relations=[
            _relation(
                relation_id,
                kind="READS",
                source_id=task["task_id"],
                target_id=candidate["candidate_id"],
                target_type="Candidate",
                activation_digest=activation,
            )
        ],
    )
    context = service._context()
    store = service._event_store(context)
    snapshot = service._runtime_state(context, store)
    checkpoint = service._write_runtime_checkpoint(
        context,
        store,
        snapshot,
        force=True,
    )
    assert checkpoint["written"] is True
    second_head = store.head()["batch_digest"]
    second_task = _task_with_gate_definition(
        service,
        {
            "record_type": "Task",
            "task_id": "task:runtime-v2-incremental",
            "state": "PLANNED",
            "required_capability": "task.execute",
            "acceptance_predicate": "runtime v2 updates only task and relation rows",
            "allowed_paths": ["product/**"],
            "activation_digest": activation,
            "candidate_digest": candidate["candidate_digest"],
            "created_at": issued_at,
        },
        defined_at_head_digest=second_head,
        gate_id="gate:runtime-v2-incremental",
    )
    second_relation_id = "relation:runtime-v2-incremental"
    service.commit(
        _service_command(
            activation_digest=activation,
            command_id="command:runtime-v2-incremental",
            command_kind="task.record",
            payload=second_task,
            expected_head=second_head,
            issued_at=issued_at,
            authorization=_grant_authorization(planner),
        ),
        auxiliary_relations=[
            _relation(
                second_relation_id,
                kind="READS",
                source_id=second_task["task_id"],
                target_id=candidate["candidate_id"],
                target_type="Candidate",
                activation_digest=activation,
            )
        ],
    )
    monkeypatch.setattr(
        events_module,
        "_replace_durable",
        lambda *_args, **_kwargs: pytest.fail("runtime v2 incremental write replaced its database"),
    )
    context = service._context()
    store = service._event_store(context)
    incremental = service._write_runtime_checkpoint(
        context,
        store,
        service._runtime_state(context, store),
        force=True,
    )
    assert incremental["written"] is True
    project_root = service.root
    service.close()

    reopened = ProminService(project_root)
    try:
        context = reopened._context()
        store = reopened._event_store(context)
        restored = reopened._runtime_state(context, store)
        assert restored.relations.count() == 2
        assert {value["relation_id"] for value in restored.relations.values()} == {
            relation_id,
            second_relation_id,
        }
        assert task["task_id"] in restored.domain.tasks
        assert second_task["task_id"] in restored.domain.tasks
    finally:
        reopened.close()
