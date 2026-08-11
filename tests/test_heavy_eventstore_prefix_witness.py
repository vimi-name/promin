from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from typing import Any, Iterable, Mapping
from unittest import mock

from promin.events import (
    CommitReadView,
    CommitStateSnapshot,
    EventStore,
    EventStorePolicy,
    JournalCorruption,
    PreparedCommit,
    SimulatedCrash,
    command_intent_identity,
    digest_value,
    state_binding_leaf_id,
    state_binding_value_digest,
)
from promin.service import _committed_envelope


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
NOW = "2026-08-09T12:00:00Z"


def _policy() -> EventStorePolicy:
    event = AUTHORITY_MODEL["event_contract"]
    mutation = AUTHORITY_MODEL["command_mutation_claim_rule"]
    value = {
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
    state = tuple(
        event["event_id"]
        for envelope in envelopes()
        for event in envelope["batch"]["events"]
    )
    return CommitStateSnapshot(
        state,
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
    payload = command["payload"]
    event_kind = POLICY.primary_events[command["command_kind"]]
    updates = [
        {
            "leaf_type": "Task",
            "leaf_id": state_binding_leaf_id(POLICY, "Task", payload),
            "operation": "set",
            "value_digest": state_binding_value_digest(
                POLICY,
                "Task",
                payload,
                event_kind=event_kind,
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
        tuple(sorted(updates, key=lambda value: (value["leaf_type"], value["leaf_id"]))),
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


def _open_store(stores: ExitStack, root: Path) -> EventStore:
    """Register explicit EventStore release before the owning temp tree exits."""

    store = _store(root)
    stores.callback(store.close)
    return store


def _command(index: int, expected_head: str | None) -> dict[str, Any]:
    value: dict[str, Any] = {
        "record_type": "CommandRequest",
        "command_id": f"command:{index:04d}",
        "command_kind": "task.record",
        "subject_id": "subject:writer",
        "activation_digest": ACTIVATION,
        "idempotency_key": f"idempotency:{index:04d}",
        "requested_scope": [{"kind": "project", "value": "project:heavy"}],
        "expected_head_digest": expected_head,
        "issued_at": NOW,
        "payload": {
            "record_type": "Task",
            "task_id": f"task:{index:04d}",
            "state": "PLANNED",
        },
        "intent_digest": "0" * 64,
        "authorization": {
            "kind": "root",
            "subject_id": "subject:writer",
            "proof_digest": "d" * 64,
        },
    }
    value["intent_digest"] = digest_value(command_intent_identity(value))
    return value


def _relations(task_id: str, count: int = 19) -> list[dict[str, Any]]:
    return [
        {
            "record_type": "Relation",
            "relation_id": f"relation:heavy:{index:03d}",
            "kind": "DEPENDS_ON",
            "source_type": "Task",
            "source_id": task_id,
            "target_type": "Task",
            "target_id": f"task:target:{index:03d}",
            "activation_digest": ACTIVATION,
            "created_at": NOW,
        }
        for index in range(count)
    ]


def _substitute_same_size(path: Path, marker: bytes) -> None:
    before = path.stat()
    raw = path.read_bytes()
    position = raw.index(marker) + len(marker) - 1
    replacement = b"9" if raw[position : position + 1] != b"9" else b"8"
    changed = raw[:position] + replacement + raw[position + 1 :]
    if len(changed) != len(raw):
        raise AssertionError("test mutation changed journal size")
    path.write_bytes(changed)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))


class EventStorePrefixWitnessTests(unittest.TestCase):
    def test_service_helper_uses_public_read_for_authority_surface(self) -> None:
        command = _command(0, None)
        batch = {"record_type": "EventBatch", "sequence": 1}
        batch_digest = digest_value(batch)
        envelope = {"command": command, "batch": batch}
        case = self

        class ReceiptStore:
            def __init__(self) -> None:
                self.receipt_calls = 0
                self.public_read_calls = 0

            def _consume_non_authoritative_same_commit_receipt(
                self,
                received_command: Mapping[str, Any],
                received_digest: str,
            ) -> dict[str, Any]:
                self.receipt_calls += 1
                case.assertEqual(received_command, command)
                case.assertEqual(received_digest, batch_digest)
                return envelope

            def read_envelope(self, received_digest: str) -> dict[str, Any]:
                self.public_read_calls += 1
                case.assertEqual(received_digest, batch_digest)
                return envelope

        store = ReceiptStore()
        self.assertEqual(
            _committed_envelope(store, command, batch_digest),
            envelope,
        )
        self.assertEqual((store.receipt_calls, store.public_read_calls), (1, 0))

        authority_store = ReceiptStore()
        self.assertEqual(
            _committed_envelope(
                authority_store,
                command,
                batch_digest,
                require_authority=True,
            ),
            envelope,
        )
        self.assertEqual(
            (authority_store.receipt_calls, authority_store.public_read_calls),
            (0, 1),
        )

    def test_same_commit_receipt_returns_exact_twenty_event_envelope_without_second_prefix_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stores:
            store = _open_store(stores, Path(temporary) / "events")
            calls = 0
            original = EventStore._verify_authority_prefix_locked

            def counted(instance: EventStore, *args: Any, **kwargs: Any) -> dict[str, Any]:
                nonlocal calls
                calls += 1
                return original(instance, *args, **kwargs)

            command = _command(0, None)
            with mock.patch.object(
                EventStore, "_verify_authority_prefix_locked", counted
            ):
                result = store.commit(
                    command,
                    auxiliary_relations=_relations(command["payload"]["task_id"]),
                    created_at=NOW,
                )
                history = store._windows_event_history
                seal_backed = history is not None and history.is_bound
                # A fresh store first validates its empty durable controls.
                # On a supported Windows volume, first-commit physical seal
                # admission then validates the newly immutable one-batch
                # prefix once more.  The opaque receipt must add neither.
                self.assertEqual(calls, 2 if seal_backed else 1)
                calls_after_commit = calls
                envelope = _committed_envelope(
                    store,
                    command,
                    result["batch_digest"],
                )
                self.assertEqual(calls, calls_after_commit)
                self.assertIsNotNone(envelope)
                assert envelope is not None
                self.assertEqual(envelope["command"], command)
                self.assertEqual(
                    digest_value(envelope["batch"]), result["batch_digest"]
                )
                self.assertEqual(len(envelope["batch"]["events"]), 20)
                self.assertIsNone(store._committed_envelope_witness)
                store.read_envelope(result["batch_digest"])
                # A public read remains authority-bearing: it either uses the
                # exact physical seal admitted above or runs the ordinary full
                # verifier.  It never consumes the non-authoritative receipt.
                self.assertEqual(calls, calls_after_commit + (0 if seal_backed else 1))

    def test_public_read_detects_old_same_size_byte_tamper_before_first_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stores:
            root = Path(temporary) / "events"
            store = _open_store(stores, root)
            first = store.commit(_command(0, None), created_at=NOW)
            journal = next(store.journal.glob("*.json"))
            head_bytes = store.head_path.read_bytes()
            if os.name == "nt":
                with self.assertRaises(PermissionError):
                    _substitute_same_size(journal, b"task:0000")
            store.close()
            _substitute_same_size(journal, b"task:0000")

            with self.assertRaises(JournalCorruption):
                _open_store(stores, root).read_envelope(first["batch_digest"])
            self.assertEqual(store.head_path.read_bytes(), head_bytes)
            self.assertIsNone(store._committed_envelope_witness)

    def test_same_commit_receipt_is_not_authority_after_old_prefix_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stores:
            root = Path(temporary) / "events"
            store = _open_store(stores, root)
            first_command = _command(0, None)
            first = store.commit(first_command, created_at=NOW)
            store.read_envelope(first["batch_digest"])
            command = _command(1, first["batch_digest"])
            second = store.commit(command, created_at=NOW)
            journal = sorted(store.journal.glob("*.json"))[0]

            receipt = store._consume_non_authoritative_same_commit_receipt(
                command,
                second["batch_digest"],
            )
            self.assertIsNotNone(receipt)
            assert receipt is not None
            self.assertEqual(receipt["command"], command)
            self.assertEqual(
                digest_value(receipt["batch"]),
                second["batch_digest"],
            )
            if os.name == "nt":
                with self.assertRaises(PermissionError):
                    _substitute_same_size(journal, b"task:0000")
            store.close()
            _substitute_same_size(journal, b"task:0000")
            with self.assertRaises(JournalCorruption):
                _open_store(stores, root).read_envelope(second["batch_digest"])

    def test_same_commit_receipt_requires_exact_command_and_batch_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stores:
            store = _open_store(stores, Path(temporary) / "events")
            command = _command(0, None)
            first = store.commit(command, created_at=NOW)
            wrong_command = _command(1, None)
            self.assertIsNone(
                store._consume_non_authoritative_same_commit_receipt(
                    wrong_command,
                    first["batch_digest"],
                )
            )
            self.assertIsNone(store._committed_envelope_witness)
            self.assertEqual(
                store.read_envelope(first["batch_digest"])["command"],
                command,
            )

    def test_external_head_drift_invalidates_witness_and_uses_normal_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stores:
            root = Path(temporary) / "events"
            store = _open_store(stores, root)
            first = store.commit(_command(0, None), created_at=NOW)
            external = _open_store(stores, root)
            second = external.commit(
                _command(1, external.head()["batch_digest"]), created_at=NOW
            )
            calls = 0
            original = EventStore._verify_authority_prefix_locked

            def counted(instance: EventStore, *args: Any, **kwargs: Any) -> dict[str, Any]:
                nonlocal calls
                calls += 1
                return original(instance, *args, **kwargs)

            with mock.patch.object(
                EventStore, "_verify_authority_prefix_locked", counted
            ):
                self.assertIsNone(
                    store._consume_non_authoritative_same_commit_receipt(
                        _command(0, None),
                        first["batch_digest"],
                    )
                )
                envelope = store.read_envelope(first["batch_digest"])
            self.assertEqual(envelope["command"]["command_id"], "command:0000")
            self.assertEqual(store.head()["batch_digest"], second["batch_digest"])
            self.assertGreaterEqual(calls, 1)
            self.assertIsNone(store._committed_envelope_witness)

    def test_crash_reopen_has_no_witness_and_recovers_exact_committed_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stores:
            root = Path(temporary) / "events"
            command = _command(0, None)
            store = _open_store(stores, root)
            with self.assertRaises(SimulatedCrash):
                store.commit(
                    command,
                    created_at=NOW,
                    crash_hook=lambda point: point == "after_checkpoint",
                )
            calls = 0
            original = EventStore._verify_authority_prefix_locked

            def counted(instance: EventStore, *args: Any, **kwargs: Any) -> dict[str, Any]:
                nonlocal calls
                calls += 1
                return original(instance, *args, **kwargs)

            with mock.patch.object(
                EventStore, "_verify_authority_prefix_locked", counted
            ):
                reopened = _open_store(stores, root)
                self.assertIsNone(reopened._committed_envelope_witness)
                history = reopened._windows_event_history
                seal_backed = history is not None and history.is_bound
                # Pending recovery replays the journal before it can bind a
                # Windows seal.  The early pending branch prevents a known
                # redundant checkpoint verification; seal-backed recovery
                # therefore has exactly one held-handle admission verifier.
                self.assertEqual(calls, 1 if seal_backed else 0)
                calls_after_reopen = calls
                envelope = reopened.read_envelope(reopened.head()["batch_digest"])
            self.assertEqual(
                calls,
                calls_after_reopen + (0 if seal_backed else 1),
            )
            self.assertEqual(envelope["command"], command)
            self.assertEqual(
                reopened.commit(command, created_at=NOW)["outcome"], "idempotent-replay"
            )

    def test_recovery_rejects_committed_history_rollback_without_rebinding_head(self) -> None:
        for mode in ("deleted", "replaced", "rewound_head", "missing_head"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary, ExitStack() as stores:
                root = Path(temporary) / "events"
                store = _open_store(stores, root)
                first = store.commit(_command(0, None), created_at=NOW)
                store.read_envelope(first["batch_digest"])
                first_head_bytes = store.head_path.read_bytes()
                second = store.commit(
                    _command(1, first["batch_digest"]), created_at=NOW
                )
                self.assertIsNotNone(second["batch_digest"])
                head_bytes = store.head_path.read_bytes()
                if mode == "deleted":
                    tail = sorted(store.journal.glob("*.json"))[-1]
                    if os.name == "nt":
                        with self.assertRaises(PermissionError):
                            tail.unlink()
                        store.close()
                    tail.unlink()
                    expected_head_bytes = head_bytes
                elif mode == "replaced":
                    tail = sorted(store.journal.glob("*.json"))[-1]
                    if os.name == "nt":
                        with self.assertRaises(PermissionError):
                            _substitute_same_size(tail, b"task:0001")
                        store.close()
                    _substitute_same_size(tail, b"task:0001")
                    expected_head_bytes = head_bytes
                elif mode == "rewound_head":
                    store.head_path.write_bytes(first_head_bytes)
                    expected_head_bytes = first_head_bytes
                else:
                    store.head_path.unlink()
                    expected_head_bytes = None

                with self.assertRaises(JournalCorruption):
                    _store(root)
                if expected_head_bytes is None:
                    self.assertFalse(store.head_path.exists())
                else:
                    self.assertEqual(store.head_path.read_bytes(), expected_head_bytes)

    def test_only_exact_pending_suffix_can_advance_recovery(self) -> None:
        for point in (
            "after_batch",
            "after_authority_root",
            "after_head",
            "after_state_binding_index",
        ):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as temporary, ExitStack() as stores:
                root = Path(temporary) / "events"
                command = _command(0, None)
                store = _open_store(stores, root)
                with self.assertRaises(SimulatedCrash):
                    store.commit(
                        command,
                        created_at=NOW,
                        crash_hook=lambda current, expected=point: current == expected,
                    )
                reopened = _open_store(stores, root)
                self.assertEqual(reopened.head()["sequence"], 1)
                self.assertEqual(
                    reopened.commit(command, created_at=NOW)["outcome"],
                    "idempotent-replay",
                )
                self.assertEqual(list(reopened.pending.glob("*.json")), [])

        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stores:
            root = Path(temporary) / "events"
            command = _command(0, None)
            store = _open_store(stores, root)
            with self.assertRaises(SimulatedCrash):
                store.commit(
                    command,
                    created_at=NOW,
                    crash_hook=lambda point: point == "after_batch",
                )
            for pending in store.pending.glob("*.json"):
                pending.unlink()
            self.assertFalse(store.head_path.exists())
            with self.assertRaises(JournalCorruption):
                _store(root)
            self.assertFalse(store.head_path.exists())

    def test_corrupt_disposable_authority_files_rebuild_without_head_rollback(self) -> None:
        for target in ("root", "segment"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary, ExitStack() as stores:
                root = Path(temporary) / "events"
                store = _open_store(stores, root)
                first = store.commit(_command(0, None), created_at=NOW)
                store.read_envelope(first["batch_digest"])
                second = store.commit(
                    _command(1, first["batch_digest"]), created_at=NOW
                )
                head_bytes = store.head_path.read_bytes()
                if target == "root":
                    store.authority_head_path.write_bytes(b"{}")
                else:
                    checkpoint = json.loads(store.checkpoint_path.read_text(encoding="utf-8"))
                    segment = (
                        store.authority_root
                        / checkpoint["authority_generation"]
                        / "00000000000000000001.json"
                    )
                    if os.name == "nt":
                        with self.assertRaises(PermissionError):
                            segment.write_bytes(b"{}")
                        store.close()
                    segment.write_bytes(b"{}")

                reopened = _open_store(stores, root)
                self.assertEqual(reopened.head()["batch_digest"], second["batch_digest"])
                self.assertEqual(reopened.head_path.read_bytes(), head_bytes)
                self.assertIsNone(reopened._committed_envelope_witness)


if __name__ == "__main__":
    unittest.main()
