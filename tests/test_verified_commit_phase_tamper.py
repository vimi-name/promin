from __future__ import annotations

from pathlib import Path

import pytest

from promin.events import EventStoreError, JournalCorruption, SimulatedCrash
from tests.test_heavy_eventstore_prefix_witness import (
    NOW,
    _command,
    _store,
    _substitute_same_size,
)


_CLOSE_FAILURES = (EventStoreError, JournalCorruption)


def test_verified_commit_phase_rejects_foreign_head_drift_on_close(
    tmp_path: Path,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    foreign = _store(tmp_path / "foreign-events")
    phase = store.begin_verified_commit_phase(max_operations=1)
    try:
        committed = phase.commit(_command(0, None), created_at=NOW)
        expected_head_bytes = store.head_path.read_bytes()
        foreign.commit(_command(1, None), created_at=NOW)
        store.head_path.write_bytes(foreign.head_path.read_bytes())

        with pytest.raises(_CLOSE_FAILURES):
            phase.close()

        # Restore only the test tamper so the ordinary public refresh route can
        # still release the store cleanly after the failed close.
        store.head_path.write_bytes(expected_head_bytes)
        assert store.head()["batch_digest"] == committed["batch_digest"]
    finally:
        foreign.close()
        store.close()


@pytest.mark.parametrize("surface", ["authority", "tail"])
def test_verified_commit_phase_close_fails_closed_on_authority_or_tail_mismatch(
    tmp_path: Path,
    surface: str,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    phase = store.begin_verified_commit_phase(max_operations=1)
    phase.commit(_command(0, None), created_at=NOW)
    authority_bytes = store.authority_head_path.read_bytes()
    tail = sorted(store.journal.glob("*.json"))[-1]
    tail_bytes = tail.read_bytes()
    try:
        if surface == "authority":
            store.authority_head_path.write_bytes(b"{}")
        else:
            _substitute_same_size(tail, b"task:0000")

        with pytest.raises(_CLOSE_FAILURES):
            phase.close()
    finally:
        store.authority_head_path.write_bytes(authority_bytes)
        tail.write_bytes(tail_bytes)
        store.close()


@pytest.mark.parametrize("surface", ["head", "authority", "tail"])
def test_verified_commit_phase_rejects_drift_before_next_commit_without_appending(
    tmp_path: Path,
    surface: str,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    foreign = _store(tmp_path / "foreign-events") if surface == "head" else None
    phase = store.begin_verified_commit_phase(max_operations=2)
    first = phase.commit(_command(0, None), created_at=NOW)
    journal_before = sorted(store.journal.glob("*.json"))
    head_before = store.head_path.read_bytes()
    authority_before = store.authority_head_path.read_bytes()
    tail = journal_before[-1]
    tail_before = tail.read_bytes()
    expected_disk_head = head_before
    try:
        if surface == "head":
            assert foreign is not None
            foreign.commit(_command(1, None), created_at=NOW)
            expected_disk_head = foreign.head_path.read_bytes()
            store.head_path.write_bytes(expected_disk_head)
        elif surface == "authority":
            store.authority_head_path.write_bytes(b"{}")
        else:
            _substitute_same_size(tail, b"task:0000")

        with pytest.raises(EventStoreError):
            phase.commit(_command(1, first["batch_digest"]), created_at=NOW)
        assert sorted(store.journal.glob("*.json")) == journal_before
        assert store.head_path.read_bytes() == expected_disk_head
        assert store.head()["batch_digest"] == first["batch_digest"]
        with pytest.raises(EventStoreError):
            phase.close()
    finally:
        store.head_path.write_bytes(head_before)
        store.authority_head_path.write_bytes(authority_before)
        tail.write_bytes(tail_before)
        if foreign is not None:
            foreign.close()
        store.close()


def test_verified_commit_phase_close_detects_historic_same_size_journal_mutation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    phase = store.begin_verified_commit_phase(max_operations=2)
    phase.commit(_command(0, None), created_at=NOW)
    second = phase.commit(_command(1, store.head()["batch_digest"]), created_at=NOW)
    historic = sorted(store.journal.glob("*.json"))[0]
    historic_bytes = historic.read_bytes()
    try:
        _substitute_same_size(historic, b"task:0000")
        with pytest.raises(_CLOSE_FAILURES):
            phase.close()
    finally:
        historic.write_bytes(historic_bytes)
        store.close()

    assert second["batch_digest"]


def test_verified_commit_phase_is_poisoned_after_commit_exception_and_public_route_recovers(
    tmp_path: Path,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    phase = store.begin_verified_commit_phase(max_operations=2)
    invalid = _command(0, None)
    invalid["expected_head_digest"] = "f" * 64
    try:
        with pytest.raises(EventStoreError):
            phase.commit(invalid, created_at=NOW)
        with pytest.raises(EventStoreError, match="poison"):
            phase.commit(_command(0, None), created_at=NOW)
        with pytest.raises(EventStoreError):
            phase.close()
    finally:
        store.close()

    reopened = _store(root)
    try:
        assert reopened.recover() == {"sequence": 0, "batch_id": None, "batch_digest": None}
        assert reopened.head()["sequence"] == 0
    finally:
        reopened.close()


def test_verified_commit_phase_is_poisoned_after_crash_and_reopen_uses_fresh_recovery(
    tmp_path: Path,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    phase = store.begin_verified_commit_phase(max_operations=2)
    command = _command(0, None)
    try:
        with pytest.raises(SimulatedCrash):
            phase.commit(
                command,
                created_at=NOW,
                crash_hook=lambda point: point == "after_checkpoint",
            )
        with pytest.raises(EventStoreError, match="poison"):
            phase.commit(_command(1, None), created_at=NOW)
        with pytest.raises(EventStoreError):
            phase.close()
    finally:
        store.close()

    reopened = _store(root)
    try:
        envelope = reopened.read_envelope(reopened.head()["batch_digest"])
        assert envelope["command"] == command
        assert reopened.commit(command, created_at=NOW)["outcome"] == "idempotent-replay"
        assert reopened.recover() == reopened.head()
    finally:
        reopened.close()


def test_verified_commit_phase_close_leaves_public_recovery_and_reopen_fresh(
    tmp_path: Path,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    phase = store.begin_verified_commit_phase(max_operations=1)
    command = _command(0, None)
    committed = phase.commit(command, created_at=NOW)
    phase.close()
    expected_head = store.head()
    store.close()

    reopened = _store(root)
    try:
        assert reopened.recover() == expected_head
        assert reopened.read_envelope(committed["batch_digest"])["command"] == command
    finally:
        reopened.close()
