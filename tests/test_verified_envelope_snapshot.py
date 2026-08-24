from __future__ import annotations

import json
from pathlib import Path

import pytest

from promin.canonical import canonical_bytes
from promin.events import EventStoreError
from tests.test_events_projection import (
    ACTIVATION,
    ACTIVATION_RECORD_DIGEST,
    IMPLEMENTATION,
    NOW,
    EventStore,
    event_store_runtime_options,
    command,
    task,
)


def _store(tmp_path: Path) -> EventStore:
    return EventStore(
        tmp_path / "events",
        active_activation_digest=ACTIVATION,
        activation_record_digest=ACTIVATION_RECORD_DIGEST,
        implementation_closure_digest=IMPLEMENTATION,
        **event_store_runtime_options(),
    )


def _commit(store: EventStore, index: int) -> None:
    store.commit(
        command(
            f"command:snapshot:{index:03d}",
            "task.record",
            task(f"task:snapshot:{index:03d}", f"snapshot {index}"),
            store.head()["batch_digest"],
        ),
        created_at=NOW,
    )


def test_snapshot_matches_public_order_and_payload_without_revalidating_iteration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    try:
        _commit(store, 0)
        _commit(store, 1)
        public = list(store.iter_envelopes())
        validate_calls = 0
        original = type(store)._validate_envelope

        def counted(instance, *args, **kwargs):
            nonlocal validate_calls
            validate_calls += 1
            return original(instance, *args, **kwargs)

        monkeypatch.setattr(type(store), "_validate_envelope", counted)
        with store.begin_verified_envelope_snapshot() as snapshot:
            observed = list(snapshot)
            assert observed == public
            # Checkpoint admission validates the durable tail once, then the
            # snapshot performs the one full replay validation.
            assert validate_calls == len(public) + 1
            with pytest.raises(EventStoreError, match="consumed"):
                list(snapshot)
        assert validate_calls == len(public) + 1
    finally:
        store.close()


def test_public_iterator_still_rejects_validation_bypass(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        with pytest.raises(EventStoreError, match="cannot disable validation"):
            list(store.iter_envelopes(validate=False))
    finally:
        store.close()


@pytest.mark.parametrize("target", ["tail", "old", "head", "authority"])
def test_snapshot_fails_closed_on_bound_byte_drift(tmp_path: Path, target: str) -> None:
    store = _store(tmp_path)
    try:
        _commit(store, 0)
        _commit(store, 1)
        snapshot = store.begin_verified_envelope_snapshot()
        try:
            if target == "tail":
                path = sorted(store.journal.glob("*.json"))[-1]
                payload = path.read_bytes()
                path.write_bytes(payload[:-1] + (b" " if payload[-1:] == b"\n" else b"\n"))
            elif target == "old":
                path = sorted(store.journal.glob("*.json"))[0]
                payload = path.read_bytes()
                path.write_bytes(payload[:-1] + (b" " if payload[-1:] == b"\n" else b"\n"))
            elif target == "head":
                value = json.loads(store.head_path.read_text(encoding="utf-8"))
                value["sequence"] = value["sequence"] + 1
                store.head_path.write_bytes(canonical_bytes(value))
            else:
                value = json.loads(store.authority_head_path.read_text(encoding="utf-8"))
                value["event_count"] = value["event_count"] + 1
                store.authority_head_path.write_bytes(canonical_bytes(value))
            with pytest.raises(EventStoreError, match="binding"):
                list(snapshot)
        finally:
            with pytest.raises(EventStoreError, match="binding"):
                snapshot.close()
    finally:
        store.close()


def test_snapshot_context_releases_writer_lock_after_failure(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        _commit(store, 0)
        snapshot = store.begin_verified_envelope_snapshot()
        snapshot.close()
        with pytest.raises(EventStoreError, match="closed"):
            list(snapshot)
        store.refresh()
        with pytest.raises(EventStoreError, match="closed"):
            snapshot.close()
    finally:
        store.close()


def test_snapshot_iterator_fails_closed_after_close_between_records(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        _commit(store, 0)
        _commit(store, 1)
        snapshot = store.begin_verified_envelope_snapshot()
        iterator = iter(snapshot)
        first = next(iterator)
        assert first["batch"]["sequence"] == 1
        snapshot.close()
        with pytest.raises(EventStoreError, match="closed"):
            next(iterator)
    finally:
        store.close()


def test_snapshot_rejects_nested_and_foreign_store_drift(tmp_path: Path) -> None:
    store = _store(tmp_path)
    try:
        _commit(store, 0)
        snapshot = store.begin_verified_envelope_snapshot()
        with pytest.raises(EventStoreError, match="already active"):
            store.begin_verified_envelope_snapshot()
        foreign = _store(tmp_path)
        try:
            _commit(foreign, 1)
        finally:
            foreign.close()
        with pytest.raises(EventStoreError, match="binding"):
            list(snapshot)
        with pytest.raises(EventStoreError, match="binding"):
            snapshot.close()
    finally:
        store.close()
