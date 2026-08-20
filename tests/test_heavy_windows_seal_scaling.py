from __future__ import annotations

from pathlib import Path
from unittest import mock

import promin.windows_event_history as history_module

# This file deliberately retains its historical name so prior test selectors
# keep working.  The EventStore no longer owns Windows history sealing: these
# are platform-neutral operation and recovery checks instead.
from test_heavy_event_batching import (  # type: ignore[import-not-found]
    NOW,
    _command,
    _store,
)


def test_normal_eventstore_commit_and_reopen_never_activate_platform_history_seal(
    tmp_path: Path,
) -> None:
    """A normal durable commit is portable and reopens without a host seal.

    Regression break caught: reintroducing a call from EventStore to the
    optional Windows history-seal module makes this real commit/reopen route
    raise the sentinel assertion below.  The journal/HEAD check is independent
    of that optional host machinery.
    """

    root = tmp_path / "events"
    with mock.patch.object(
        history_module.WindowsEventHistorySeal,
        "try_hold_existing",
        side_effect=AssertionError("EventStore must not activate platform history sealing"),
    ):
        store = _store(root)
        try:
            committed = store.commit(_command(1), created_at=NOW)
            assert committed["outcome"] == "committed"
            assert store.head()["sequence"] == 1
        finally:
            store.close()

        reopened = _store(root)
        try:
            assert reopened.head()["sequence"] == 1
            envelope = reopened.envelope_at_head()
            assert envelope is not None
            assert envelope["batch"]["command_id"] == "command:batch:0001"
        finally:
            reopened.close()


def test_platform_neutral_explicit_recovery_preserves_committed_journal_order(
    tmp_path: Path,
) -> None:
    """Recovery recomputes deterministic authority from portable journal bytes."""

    root = tmp_path / "events"
    store = _store(root)
    try:
        first = store.commit(_command(1), created_at=NOW)
        second = store.commit(
            _command(2, first["batch_digest"]),
            created_at=NOW,
        )
        expected_head = store.head()
    finally:
        store.close()

    reopened = _store(root)
    try:
        recovered_head = reopened.recover()
        assert recovered_head == expected_head
        envelopes = list(reopened.iter_envelopes())
        assert [envelope["batch"]["command_id"] for envelope in envelopes] == [
            "command:batch:0001",
            "command:batch:0002",
        ]
    finally:
        reopened.close()
