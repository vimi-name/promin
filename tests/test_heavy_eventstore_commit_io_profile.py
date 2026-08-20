from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from promin.events import CommitReadView, CommitStateSnapshot, EventStore

# The profile keeps the exact compiled 128-event batch.  It deliberately
# measures portable EventStore work, not optional host/OS protection behavior.
from test_heavy_event_batching import (  # type: ignore[import-not-found]
    ACTIVATION,
    ACTIVATION_RECORD_DIGEST,
    IMPLEMENTATION_CLOSURE,
    NOW,
    POLICY,
    _command,
    _prepare_commit,
)


def _constant_commit_state(
    view: CommitReadView,
    _envelopes: Any,
) -> CommitStateSnapshot:
    return CommitStateSnapshot(
        (),
        view.head_sequence,
        view.head_digest,
        view.current_state_binding_digest,
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
        commit_state_loader=_constant_commit_state,
        commit_prepare_callback=_prepare_commit,
        derived_state_validator=lambda _name, _state, **_kwargs: True,
    )


def _profile_relations(batch_index: int) -> list[dict[str, Any]]:
    task_id = f"task:batch:{batch_index:04d}"
    return [
        {
            "record_type": "Relation",
            "relation_id": f"relation:io:{batch_index:04d}:{offset:03d}",
            "kind": "READS",
            "source_type": "Task",
            "source_id": task_id,
            "target_type": "Artifact",
            "target_id": f"artifact:io:{batch_index:04d}:{offset:03d}",
            "activation_digest": ACTIVATION,
            "created_at": NOW,
        }
        for offset in range(127)
    ]


@pytest.mark.performance
def test_max_batch_commit_is_portable_and_recovers_exact_128_event_order(
    tmp_path: Path,
) -> None:
    """The maximum configured batch remains durable without host sealing.

    Regression break caught: removing journal/HEAD/state-binding persistence,
    weakening the 128-event batch, or reintroducing a platform-specific append
    dependency breaks this real commit/reopen/recovery route.
    """

    assert POLICY.max_events_per_batch == 128
    root = tmp_path / "events"
    store = _store(root)
    try:
        command = _command(1)
        result = store.commit(
            command,
            auxiliary_relations=_profile_relations(1),
            created_at=NOW,
        )
        metrics = store.last_commit_write_metrics()
        expected_head = store.head()
        assert result["outcome"] == "committed"
        assert expected_head["sequence"] == 1
        assert metrics["changed_records"] == 128
        assert metrics["state_binding_updates"] == 128
        assert 128 <= metrics["state_binding_node_writes"] <= 256
        assert metrics["journal_checkpoint_writes"] == 1
    finally:
        store.close()

    reopened = _store(root)
    try:
        assert reopened.recover() == expected_head
        envelope = reopened.envelope_at_head()
        assert envelope is not None
        assert envelope["batch"]["command_id"] == "command:batch:0001"
        assert len(envelope["batch"]["events"]) == 128
        assert [event["event_kind"] for event in envelope["batch"]["events"]] == [
            "task.recorded",
            *("relation.recorded" for _ in range(127)),
        ]
    finally:
        reopened.close()
