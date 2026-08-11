from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

import pytest

import promin.events as events_module
from promin.events import (
    CommitReadView,
    CommitStateSnapshot,
    DerivedCheckpointError,
    EventStore,
    EventStorePolicy,
    PreparedCommit,
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
NOW = "2026-08-11T12:00:00Z"


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
    _envelopes: Any,
) -> CommitStateSnapshot:
    return CommitStateSnapshot(
        (),
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
    event_kind = POLICY.primary_events[command["command_kind"]]
    return PreparedCommit(
        relations,
        (
            {
                "leaf_type": "Task",
                "leaf_id": state_binding_leaf_id(POLICY, "Task", task),
                "operation": "set",
                "value_digest": state_binding_value_digest(
                    POLICY,
                    "Task",
                    task,
                    event_kind=event_kind,
                ),
            },
        ),
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
    value: dict[str, Any] = {
        "record_type": "CommandRequest",
        "command_id": f"command:posthead:{index:04d}",
        "command_kind": "task.record",
        "subject_id": "subject:posthead",
        "activation_digest": ACTIVATION,
        "idempotency_key": f"idempotency:posthead:{index:04d}",
        "requested_scope": [{"kind": "project", "value": "project:posthead"}],
        "expected_head_digest": expected_head,
        "issued_at": NOW,
        "payload": {
            "record_type": "Task",
            "task_id": f"task:posthead:{index:04d}",
            "state": "PLANNED",
        },
        "intent_digest": "0" * 64,
        "authorization": {
            "kind": "root",
            "subject_id": "subject:posthead",
            "proof_digest": "d" * 64,
        },
    }
    value["intent_digest"] = digest_value(command_intent_identity(value))
    return value


@pytest.mark.parametrize(
    "publication_edge",
    ("_write_envelope_index_entries", "_publish_state_binding_delta"),
)
def test_post_head_derived_index_failure_returns_exact_commit_and_recovers_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    publication_edge: str,
) -> None:
    root = tmp_path / publication_edge.removeprefix("_")
    store = _store(root)
    command = _command(1)
    calls = 0

    def fail_publication(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        raise DerivedCheckpointError(f"injected {publication_edge} failure")

    with monkeypatch.context() as fault:
        fault.setattr(store, publication_edge, fail_publication)
        committed = store.commit(command, created_at=NOW)

        assert committed["outcome"] == "committed"
        assert calls == 1
        assert store.head()["batch_digest"] == committed["batch_digest"]
        status = store.checkpoint_status()
        assert status["open_mode"] == "authority-only-derived-unavailable"
        assert publication_edge in status["fallback_reason"]
        assert status["authoritative"] is False

        envelope = store.envelope_at_head()
        assert envelope is not None
        assert envelope["command"] == command
        assert digest_value(envelope["batch"]) == committed["batch_digest"]
        assert store.commit(command, created_at=NOW)["outcome"] == "idempotent-replay"
        unavailable_next = _command(2, committed["batch_digest"])
        with pytest.raises(DerivedCheckpointError, match=publication_edge):
            store.commit(unavailable_next, created_at=NOW)
        assert calls == 2
        assert store.head()["batch_digest"] == committed["batch_digest"]
        assert len(list(store.iter_envelopes())) == 1

    store.close()
    reopened = _store(root)
    try:
        assert reopened.head()["batch_digest"] == committed["batch_digest"]
        assert reopened.checkpoint_status()["open_mode"] == "full-replay-fallback"
        envelope = reopened.envelope_at_head()
        assert envelope is not None
        assert envelope["command"] == command
        assert digest_value(envelope["batch"]) == committed["batch_digest"]
        assert reopened.commit(command, created_at=NOW)["outcome"] == "idempotent-replay"
        assert len(list(reopened.iter_envelopes())) == 1

        second = _command(2, committed["batch_digest"])
        assert reopened.commit(second, created_at=NOW)["outcome"] == "committed"
        assert len(list(reopened.iter_envelopes())) == 2
    finally:
        reopened.close()


def test_pre_head_authority_failure_is_not_reported_as_committed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path / "pre-head")

    def fail_authority_root(*_args: Any, **_kwargs: Any) -> Any:
        raise DerivedCheckpointError("injected pre-HEAD authority failure")

    monkeypatch.setattr(store, "_write_authority_root", fail_authority_root)
    with pytest.raises(DerivedCheckpointError, match="pre-HEAD authority failure"):
        store.commit(_command(1), created_at=NOW)
    assert store.head()["sequence"] == 0
    assert not store.head_path.exists()
    store.close()


@pytest.mark.parametrize(
    "finalization_edge",
    (
        "journal-checkpoint",
        "windows-control",
        "pending-unlink",
        "pending-fsync",
    ),
)
def test_post_head_finalization_failure_returns_exact_commit_and_reopens_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    finalization_edge: str,
) -> None:
    root = tmp_path / finalization_edge
    store = _store(root)
    command = _command(1)
    failure_calls = 0
    original_unlink = events_module._unlink
    original_fsync_directory = events_module._fsync_directory
    original_checkpoint = store._write_journal_checkpoint
    checkpoint_completed = False

    def fail_checkpoint(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal failure_calls
        failure_calls += 1
        raise DerivedCheckpointError("injected journal-checkpoint failure")

    def fail_windows_control(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal failure_calls
        failure_calls += 1
        raise events_module.JournalCorruption("injected windows-control failure")

    def fail_pending_unlink(path: Path, *, missing_ok: bool = False) -> None:
        nonlocal failure_calls
        if path.parent == store.pending and path.suffix == ".json":
            failure_calls += 1
            raise OSError("injected pending-unlink failure")
        original_unlink(path, missing_ok=missing_ok)

    def arm_after_checkpoint(*args: Any, **kwargs: Any) -> Any:
        nonlocal checkpoint_completed
        value = original_checkpoint(*args, **kwargs)
        checkpoint_completed = True
        return value

    def fail_pending_fsync(path: Path) -> None:
        nonlocal failure_calls
        if checkpoint_completed and path == store.pending:
            failure_calls += 1
            raise OSError("injected pending-fsync failure")
        original_fsync_directory(path)

    with monkeypatch.context() as fault:
        if finalization_edge == "journal-checkpoint":
            fault.setattr(store, "_write_journal_checkpoint", fail_checkpoint)
        elif finalization_edge == "windows-control":
            fault.setattr(
                store,
                "_advance_windows_history_control_locked",
                fail_windows_control,
            )
        elif finalization_edge == "pending-unlink":
            fault.setattr(events_module, "_unlink", fail_pending_unlink)
        else:
            fault.setattr(store, "_write_journal_checkpoint", arm_after_checkpoint)
            fault.setattr(events_module, "_fsync_directory", fail_pending_fsync)

        committed = store.commit(command, created_at=NOW)

        assert committed["outcome"] == "committed"
        assert failure_calls == 1
        assert store.head()["batch_digest"] == committed["batch_digest"]
        status = store.checkpoint_status()
        assert status["open_mode"] == "authority-only-derived-unavailable"
        assert finalization_edge in status["fallback_reason"]
        assert status["authoritative"] is False

        envelope = store.envelope_at_head()
        assert envelope is not None
        assert envelope["command"] == command
        assert digest_value(envelope["batch"]) == committed["batch_digest"]
        assert store.commit(command, created_at=NOW)["outcome"] == "idempotent-replay"
        assert len(list(store.iter_envelopes())) == 1

    store.close()
    reopened = _store(root)
    try:
        expected_mode = (
            "verified-checkpoint"
            if finalization_edge == "pending-fsync"
            else "full-replay-fallback"
        )
        assert reopened.checkpoint_status()["open_mode"] == expected_mode
        assert reopened.head()["batch_digest"] == committed["batch_digest"]
        envelope = reopened.envelope_at_head()
        assert envelope is not None
        assert envelope["command"] == command
        assert digest_value(envelope["batch"]) == committed["batch_digest"]
        assert reopened.commit(command, created_at=NOW)["outcome"] == "idempotent-replay"
        assert len(list(reopened.iter_envelopes())) == 1

        second = _command(2, committed["batch_digest"])
        assert reopened.commit(second, created_at=NOW)["outcome"] == "committed"
        assert len(list(reopened.iter_envelopes())) == 2
    finally:
        reopened.close()
