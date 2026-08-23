from __future__ import annotations

from pathlib import Path

import pytest

from promin.events import EventStore
from tests.test_heavy_event_batching import NOW, _command, _store


def test_verified_commit_phase_refreshes_authority_only_at_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep the full authority proof at phase boundaries, not per commit."""

    store = _store(tmp_path / "events")
    original_verify = EventStore._verify_authority_prefix_locked
    refresh_calls = 0

    def counted_verify(instance, *args, **kwargs):
        nonlocal refresh_calls
        refresh_calls += 1
        return original_verify(instance, *args, **kwargs)

    monkeypatch.setattr(EventStore, "_verify_authority_prefix_locked", counted_verify)

    phase = store.begin_verified_commit_phase(max_operations=3)
    assert refresh_calls == 1

    results = []
    expected_head = None
    for index in range(1, 4):
        result = phase.commit(
            _command(index, expected_head=expected_head), created_at=NOW
        )
        assert result["outcome"] == "committed"
        results.append(result)
        expected_head = result["batch_digest"]

    # Successful phase-owned commits reuse the entry proof.  No per-commit
    # authority-prefix refresh is allowed.
    assert refresh_calls == 1
    phase.close()
    assert refresh_calls == 2

    envelopes = [store.read_envelope(result["batch_digest"]) for result in results]
    assert [envelope["batch"]["sequence"] for envelope in envelopes] == [1, 2, 3]
    assert [
        envelope["batch"]["previous_digest"] for envelope in envelopes
    ] == [None, results[0]["batch_digest"], results[1]["batch_digest"]]
    assert [
        envelope["batch"]["events"][0]["payload"]["task_id"]
        for envelope in envelopes
    ] == ["task:batch:0001", "task:batch:0002", "task:batch:0003"]
    assert [
        envelope["command"]["command_id"] for envelope in envelopes
    ] == [
        "command:batch:0001",
        "command:batch:0002",
        "command:batch:0003",
    ]

    # The ordinary public route performs its own fresh authority read after
    # the phase has released the writer lock and returns the final envelope.
    refresh_calls_before_final_read = refresh_calls
    final = store.read_envelope(results[-1]["batch_digest"])
    assert final["batch"]["sequence"] == 3
    assert final["command"]["command_id"] == "command:batch:0003"
    assert refresh_calls == refresh_calls_before_final_read + 1
    store.close()
