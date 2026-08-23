from __future__ import annotations

from pathlib import Path

import pytest

from promin.events import EventStore, EventStoreError
from tests.test_heavy_event_batching import NOW, _command, _store


def _commit_chain_command(index: int, expected_head: str | None) -> dict:
    return _command(index, expected_head=expected_head)


def test_verified_commit_phase_verifies_admission_and_close_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path / "events")
    verifier = EventStore._verify_authority_prefix_locked
    calls = 0

    def counted(instance, *args, **kwargs):
        nonlocal calls
        calls += 1
        return verifier(instance, *args, **kwargs)

    monkeypatch.setattr(EventStore, "_verify_authority_prefix_locked", counted)
    phase = store.begin_verified_commit_phase(max_operations=3)
    assert calls == 1
    first = phase.commit(_commit_chain_command(1, None), created_at=NOW)
    second = phase.commit(
        _commit_chain_command(2, first["batch_digest"]), created_at=NOW
    )
    third = phase.commit(
        _commit_chain_command(3, second["batch_digest"]), created_at=NOW
    )
    assert [first["outcome"], second["outcome"], third["outcome"]] == [
        "committed",
        "committed",
        "committed",
    ]
    assert calls == 1
    phase.close()
    assert calls == 2


def test_verified_commit_phase_chains_exact_order_and_envelopes(tmp_path: Path) -> None:
    store = _store(tmp_path / "events")
    phase = store.begin_verified_commit_phase(max_operations=3)
    results = []
    expected_head = None
    for index in range(1, 4):
        result = phase.commit(
            _commit_chain_command(index, expected_head), created_at=NOW
        )
        results.append(result)
        expected_head = result["batch_digest"]
    phase.close()

    envelopes = [store.read_envelope(result["batch_digest"]) for result in results]
    assert [envelope["batch"]["sequence"] for envelope in envelopes] == [1, 2, 3]
    assert [envelope["command"]["command_id"] for envelope in envelopes] == [
        "command:batch:0001",
        "command:batch:0002",
        "command:batch:0003",
    ]
    assert [
        envelope["batch"]["previous_digest"] for envelope in envelopes
    ] == [None, results[0]["batch_digest"], results[1]["batch_digest"]]


@pytest.mark.parametrize("max_operations", [0, -1, True, False, 1.0, "2"])
def test_verified_commit_phase_rejects_invalid_operation_budget(
    tmp_path: Path, max_operations
) -> None:
    store = _store(tmp_path / "events")
    with pytest.raises(EventStoreError, match="max_operations"):
        store.begin_verified_commit_phase(max_operations=max_operations)


def test_verified_commit_phase_exhaustion_nesting_and_closed_use(tmp_path: Path) -> None:
    store = _store(tmp_path / "events")
    phase = store.begin_verified_commit_phase(max_operations=1)
    with pytest.raises(EventStoreError):
        store.begin_verified_commit_phase(max_operations=1)
    first = phase.commit(_commit_chain_command(1, None), created_at=NOW)
    with pytest.raises(EventStoreError, match="exhausted"):
        phase.commit(
            _commit_chain_command(2, first["batch_digest"]), created_at=NOW
        )
    phase.close()
    with pytest.raises(EventStoreError, match="closed"):
        phase.commit(_commit_chain_command(2, None), created_at=NOW)


def test_verified_commit_phase_poisoned_by_operation_exception_and_releases_lock(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "events")
    phase = store.begin_verified_commit_phase(max_operations=2)
    invalid = _commit_chain_command(1, None)
    invalid["expected_head_digest"] = "f" * 64
    with pytest.raises(EventStoreError):
        phase.commit(invalid, created_at=NOW)
    with pytest.raises(EventStoreError, match="poison"):
        phase.commit(_commit_chain_command(1, None), created_at=NOW)
    with pytest.raises(EventStoreError):
        phase.close()
    # A failed operation and fail-closed close must not strand the single-writer lock.
    store.refresh()
    recovered_phase = store.begin_verified_commit_phase(max_operations=1)
    recovered_phase.close()


def test_verified_commit_phase_close_releases_writer_lock(tmp_path: Path) -> None:
    store = _store(tmp_path / "events")
    phase = store.begin_verified_commit_phase(max_operations=1)
    phase.commit(_commit_chain_command(1, None), created_at=NOW)
    phase.close()
    assert store.refresh()["sequence"] == 1
