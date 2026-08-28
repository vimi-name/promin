from __future__ import annotations

from pathlib import Path

from test_heavy_event_batching import (  # type: ignore[import-not-found]
    NOW,
    _command,
    _store,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def test_runtime_has_no_windows_event_history_seal_dependency() -> None:
    """Portable runtime modules must not reactivate the removed host seal."""

    forbidden = ("windows_event_history", "WindowsEventHistorySeal")
    offenders: dict[str, list[str]] = {}
    for path in sorted((PACKAGE_ROOT / "promin").glob("*.py")):
        source = path.read_text(encoding="utf-8")
        markers = [marker for marker in forbidden if marker in source]
        if markers:
            offenders[path.relative_to(PACKAGE_ROOT).as_posix()] = markers
    assert offenders == {}


def test_normal_eventstore_commit_and_reopen_preserves_portable_history(
    tmp_path: Path,
) -> None:
    """A normal durable commit is portable and reopens from the journal."""

    root = tmp_path / "events"
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


def test_portable_explicit_recovery_preserves_committed_journal_order(
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
