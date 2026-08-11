from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

import pytest

from promin.canonical import canonical_bytes
from promin.events import (
    CommitReadView,
    CommitStateSnapshot,
    EventStore,
    EventStoreError,
    EventStorePolicy,
    PreparedCommit,
    SimulatedCrash,
    command_intent_identity,
    digest_value,
    state_binding_leaf_id,
    state_binding_value_digest,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_MODEL = json.loads(
    (PACKAGE_ROOT / "core" / "authority-model.json").read_text(encoding="utf-8")
)
SEMANTIC_MODEL = json.loads(
    (PACKAGE_ROOT / "core" / "semantic-model.json").read_text(encoding="utf-8")
)
ACTIVATION = "a" * 64
ACTIVATION_RECORD_DIGEST = "b" * 64
IMPLEMENTATION_CLOSURE = "c" * 64
NOW = "2026-08-09T13:00:00Z"


def _policy() -> EventStorePolicy:
    event = AUTHORITY_MODEL["event_contract"]
    mutation = AUTHORITY_MODEL["command_mutation_claim_rule"]
    value: dict[str, Any] = {
        "record_type": "EventStorePolicy",
        "authority_model_digest": digest_value(AUTHORITY_MODEL),
        "max_command_bytes": event["command_bytes_max"],
        "max_envelope_bytes": event["envelope_bytes_max"],
        "max_state_binding_bytes": event["state_binding_bytes_max"],
        "max_state_binding_updates_per_batch": event[
            "state_binding_updates_per_batch_max"
        ],
        "max_events_per_batch": event["events_per_batch_max"],
        "max_requested_scope_items": AUTHORITY_MODEL["scope_contract"][
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
            *[item["kind"] for item in SEMANTIC_MODEL["persistent_entities"]],
            "Relation",
        ],
        "state_binding_identity_rules": event["state_binding_identity_rules"],
        "state_binding_algorithm_contract": event[
            "state_binding_algorithm_contract"
        ],
        "state_binding_value_rules": event["state_binding_value_rules"],
        "canonical_timestamp_contract": AUTHORITY_MODEL[
            "canonical_timestamp_contract"
        ],
        "genesis_previous_authority_commitment": event[
            "genesis_previous_authority_commitment"
        ],
        "genesis_event_semantic_digest": event["genesis_event_semantic_digest"],
    }
    value["policy_digest"] = digest_value(value)
    return EventStorePolicy.from_compiled(value)


POLICY = _policy()


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
    _view: CommitReadView,
    frozen_command: Mapping[str, Any],
    frozen_relations: Iterable[Mapping[str, Any]],
) -> PreparedCommit:
    command = _thaw(frozen_command)
    relations = tuple(_thaw(value) for value in frozen_relations)
    task = command["payload"]
    task_event_kind = POLICY.primary_events[command["command_kind"]]
    updates = [
        {
            "leaf_type": "Task",
            "leaf_id": state_binding_leaf_id(POLICY, "Task", task),
            "operation": "set",
            "value_digest": state_binding_value_digest(
                POLICY, "Task", task, event_kind=task_event_kind
            ),
        },
        *(
            {
                "leaf_type": "Relation",
                "leaf_id": relation["relation_id"],
                "operation": "set",
                "value_digest": state_binding_value_digest(
                    POLICY,
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
        tuple(sorted(updates, key=lambda update: (update["leaf_type"], update["leaf_id"]))),
    )


def _store(root: Path) -> EventStore:
    return EventStore(
        root,
        ACTIVATION,
        activation_record_digest=ACTIVATION_RECORD_DIGEST,
        implementation_closure_digest=IMPLEMENTATION_CLOSURE,
        policy=POLICY,
        compiled_record_validator=lambda _definition, _value, **_kwargs: True,
        command_validator=lambda _value, **_kwargs: True,
        authorization_validator=lambda _value, **_kwargs: True,
        event_validator=lambda _value, **_kwargs: True,
        commit_state_loader=_load_commit_state,
        commit_prepare_callback=_prepare_commit,
        derived_state_validator=lambda _name, _state, **_kwargs: True,
    )


def _command(index: int, expected_head: str | None = None) -> dict[str, Any]:
    command: dict[str, Any] = {
        "record_type": "CommandRequest",
        "command_id": f"command:batch:{index:04d}",
        "command_kind": "task.record",
        "subject_id": "subject:batch-writer",
        "activation_digest": ACTIVATION,
        "idempotency_key": f"idempotency:batch:{index:04d}",
        "requested_scope": [{"kind": "project", "value": "project:batch"}],
        "expected_head_digest": expected_head,
        "issued_at": NOW,
        "payload": {
            "record_type": "Task",
            "task_id": f"task:batch:{index:04d}",
            "state": "PLANNED",
        },
        "intent_digest": "0" * 64,
        "authorization": {
            "kind": "root",
            "subject_id": "subject:batch-writer",
            "proof_digest": "d" * 64,
        },
    }
    command["intent_digest"] = digest_value(command_intent_identity(command))
    return command


def _reads_relations(task_id: str, count: int) -> list[dict[str, Any]]:
    return [
        {
            "record_type": "Relation",
            "relation_id": f"relation:reads:{index:03d}",
            "kind": "READS",
            "source_type": "Task",
            "source_id": task_id,
            "target_type": "Artifact",
            "target_id": f"artifact:physical:{index:03d}",
            "activation_digest": ACTIVATION,
            "created_at": NOW,
        }
        for index in range(count)
    ]


def _restored_leaves(
    command: Mapping[str, Any], relations: Iterable[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    leaves = [
        {"leaf_type": "Task", "value": dict(command["payload"])},
        *({"leaf_type": "Relation", "value": dict(relation)} for relation in relations),
    ]
    return sorted(
        leaves,
        key=lambda leaf: (
            leaf["leaf_type"],
            state_binding_leaf_id(POLICY, leaf["leaf_type"], leaf["value"]),
        ),
    )


@pytest.mark.performance
def test_task_with_127_reads_commits_exact_128_event_batch_with_exact_replay_and_root(
    tmp_path: Path,
) -> None:
    assert POLICY.max_events_per_batch == 128
    assert POLICY.max_state_binding_updates_per_batch == 128
    assert POLICY.max_command_bytes == 1_048_576
    assert POLICY.max_state_binding_bytes == 1_048_576
    assert POLICY.max_envelope_bytes == 2_097_152

    store = _store(tmp_path / "events")
    command = _command(1)
    relations = _reads_relations(command["payload"]["task_id"], 127)
    result = store.commit(command, auxiliary_relations=relations, created_at=NOW)
    envelope = store.read_envelope(result["batch_digest"])
    batch = envelope["batch"]

    assert len(batch["events"]) == 128
    assert batch["events"][0]["event_kind"] == "task.recorded"
    assert [event["event_kind"] for event in batch["events"][1:]] == [
        "relation.recorded"
    ] * 127
    assert len(batch["state_binding_delta"]) == 128
    assert len(canonical_bytes(command)) < POLICY.max_command_bytes
    assert len(canonical_bytes(batch["state_binding_delta"])) < POLICY.max_state_binding_bytes
    assert len(canonical_bytes(envelope)) < POLICY.max_envelope_bytes
    assert (
        store.validate_state_binding_leaves(
            _restored_leaves(command, relations), expected_head=store.head()
        )
        == batch["state_binding_digest"]
    )

    replay = store.replay(lambda state, event: state + [event["event_id"]], [])
    assert replay.batch_count == 1
    assert replay.event_count == 128
    assert replay.semantic_digest == batch["event_semantic_digest"]
    assert replay.state == [event["event_id"] for event in batch["events"]]
    assert store.commit(command, auxiliary_relations=relations, created_at=NOW)["outcome"] == "idempotent-replay"

    with pytest.raises(EventStoreError, match="event ceiling"):
        _store(tmp_path / "rejected").commit(
            _command(2),
            auxiliary_relations=_reads_relations("task:batch:0002", 128),
            created_at=NOW,
        )


def test_crashed_128_event_batch_recovers_exact_root_and_idempotency(tmp_path: Path) -> None:
    root = tmp_path / "events"
    command = _command(3)
    relations = _reads_relations(command["payload"]["task_id"], 127)
    store = _store(root)
    with pytest.raises(SimulatedCrash):
        store.commit(
            command,
            auxiliary_relations=relations,
            created_at=NOW,
            crash_hook=lambda point: point == "after_batch",
        )

    reopened = _store(root)
    envelope = reopened.read_envelope(reopened.head()["batch_digest"])
    assert len(envelope["batch"]["events"]) == 128
    assert (
        reopened.validate_state_binding_leaves(
            _restored_leaves(command, relations), expected_head=reopened.head()
        )
        == envelope["batch"]["state_binding_digest"]
    )
    assert reopened.commit(command, auxiliary_relations=relations, created_at=NOW)["outcome"] == "idempotent-replay"
