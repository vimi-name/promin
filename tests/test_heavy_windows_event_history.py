from __future__ import annotations

import ctypes
import json
import os
import shutil
import tempfile
import unittest
from ctypes import wintypes
from pathlib import Path
from unittest import mock

import promin.events as events_module
from promin.events import EventStore, JournalCorruption, SimulatedCrash
from promin.windows_event_history import (
    WindowsEventHistorySeal,
    WindowsEventHistoryUnavailable,
    WindowsEventHistoryViolation,
)

# Reuse the bounded real EventStore policy/command fixture rather than invent
# a second authority surface just for physical Windows history tests.
from test_heavy_eventstore_prefix_witness import (  # type: ignore[import-not-found]
    NOW,
    _command,
    _store,
)


def _same_size_substitution(path: Path, marker: bytes) -> None:
    before = path.stat()
    raw = path.read_bytes()
    position = raw.index(marker) + len(marker) - 1
    replacement = b"9" if raw[position : position + 1] != b"9" else b"8"
    changed = raw[:position] + replacement + raw[position + 1 :]
    if len(changed) != len(raw):
        raise AssertionError("test substitution changed immutable file size")
    path.write_bytes(changed)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))


def _process_handle_count() -> int:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetProcessHandleCount.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.GetProcessHandleCount.restype = wintypes.BOOL
    count = wintypes.DWORD()
    if not kernel32.GetProcessHandleCount(
        kernel32.GetCurrentProcess(), ctypes.byref(count)
    ):
        raise OSError(ctypes.get_last_error(), "GetProcessHandleCount failed")
    return int(count.value)


@unittest.skipUnless(os.name == "nt", "Windows physical history seal")
class WindowsEventHistoryTests(unittest.TestCase):
    def _close(self, *stores: EventStore) -> None:
        for store in stores:
            store.close()

    def test_reopen_has_one_full_admission_scan_and_second_atomic_commit_stays_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "events"
            seed = _store(root)
            try:
                first = seed.commit(_command(0, None), created_at=NOW)
            finally:
                seed.close()

            calls = 0
            original = EventStore._verify_authority_prefix_locked

            def counted(instance: EventStore, *args: object, **kwargs: object) -> dict:
                nonlocal calls
                calls += 1
                return original(instance, *args, **kwargs)

            with mock.patch.object(EventStore, "_verify_authority_prefix_locked", counted):
                store = _store(root)
                try:
                    history = store._windows_event_history
                    self.assertIsNotNone(history)
                    assert history is not None
                    self.assertTrue(history.is_bound)
                    self.assertEqual(history.held_file_count, 2)
                    second = store.commit(
                        _command(1, first["batch_digest"]), created_at=NOW
                    )
                    self.assertEqual(calls, 1)
                    self.assertEqual(store.head()["batch_digest"], second["batch_digest"])
                    self.assertEqual(store._windows_event_history.held_file_count, 4)
                finally:
                    store.close()

    def test_byte_substitution_is_denied_and_metadata_drift_forces_full_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "events"
            store = _store(root)
            try:
                first = store.commit(_command(0, None), created_at=NOW)
                journal = next(store.journal.glob("*.json"))
                before = journal.stat()
                with self.assertRaises(OSError):
                    with journal.open("r+b") as stream:
                        stream.seek(0)
                        stream.write(b"{")

                # CPython may issue SetFileTime without opening a write-data
                # handle.  If the host permits it, the native ChangeTime
                # witness must still discard the fast path before authority
                # reads; if it denies it, that is even stronger.
                changed_metadata = False
                try:
                    os.utime(journal, ns=(before.st_atime_ns, before.st_mtime_ns))
                    changed_metadata = True
                except OSError:
                    pass

                calls = 0
                original = EventStore._verify_authority_prefix_locked

                def counted(instance: EventStore, *args: object, **kwargs: object) -> dict:
                    nonlocal calls
                    calls += 1
                    return original(instance, *args, **kwargs)

                with mock.patch.object(EventStore, "_verify_authority_prefix_locked", counted):
                    envelope = store.read_envelope(first["batch_digest"])
                self.assertEqual(envelope["command"]["command_id"], "command:0000")
                if changed_metadata:
                    self.assertEqual(calls, 1)
                    self.assertIsNone(store._windows_event_history)
            finally:
                store.close()

            # With no held handles, an actual same-size byte substitution plus
            # mtime restoration must fail the normal first authority read.
            journal = next((root / "journal").glob("*.json"))
            _same_size_substitution(journal, b"task:0000")
            with self.assertRaises(JournalCorruption):
                reopened = _store(root)
                reopened.close()

    def test_root_rebind_same_names_drops_fast_path_before_any_new_path_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "events"
            moved = parent / "events-moved"
            store = _store(root)
            try:
                first = store.commit(_command(0, None), created_at=NOW)
                self.assertIsNotNone(store._windows_event_history)
                try:
                    root.rename(moved)
                except OSError:
                    # Some NTFS configurations reject the ancestor rename due
                    # to the live immutable file handles.  That is a physical
                    # block; there is no path alias to accept.
                    self.assertTrue(root.exists())
                    return
                shutil.copytree(moved, root)

                calls = 0
                original = EventStore._verify_authority_prefix_locked

                def counted(instance: EventStore, *args: object, **kwargs: object) -> dict:
                    nonlocal calls
                    calls += 1
                    return original(instance, *args, **kwargs)

                with mock.patch.object(EventStore, "_verify_authority_prefix_locked", counted):
                    envelope = store.read_envelope(first["batch_digest"])
                self.assertEqual(envelope["command"]["command_id"], "command:0000")
                self.assertEqual(calls, 1)
                self.assertIsNone(store._windows_event_history)
            finally:
                store.close()
                if moved.exists():
                    shutil.rmtree(moved, ignore_errors=True)

    def test_provisional_admission_detects_rebind_between_hold_and_bind(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "events"
            moved = parent / "events-moved"
            store = _store(root)
            try:
                store.commit(_command(0, None), created_at=NOW)
                head_payload = store.head_path.read_bytes()
                authority_root_payload = store.authority_head_path.read_bytes()
                checkpoint_payload = store.checkpoint_path.read_bytes()
            finally:
                store.close()
            authority_root = json.loads(authority_root_payload)
            generation = authority_root["generation"]
            seal = WindowsEventHistorySeal.try_hold_existing(
                root=root,
                journal_directory=root / "journal",
                authority_directory=root / "journal-authority" / generation,
                journal_files=sorted((root / "journal").glob("*.json")),
                authority_files=sorted(
                    (root / "journal-authority" / generation).glob("*.json")
                ),
                max_file_bytes=2 * 1024 * 1024,
            )
            self.assertIsNotNone(seal)
            assert seal is not None
            try:
                try:
                    root.rename(moved)
                except OSError:
                    # A live admission guard / immutable handle prevented the
                    # race.  This is the stronger physical outcome.
                    self.assertTrue(root.exists())
                    return
                shutil.copytree(moved, root)
                with self.assertRaises(WindowsEventHistoryViolation):
                    seal.bind_verified_control(
                        head=json.loads(head_payload),
                        authority_generation=generation,
                        head_payload=head_payload,
                        authority_root_payload=authority_root_payload,
                        checkpoint_payload=checkpoint_payload,
                    )
            finally:
                seal.close()
                if moved.exists():
                    shutil.rmtree(moved, ignore_errors=True)

    def test_crash_reopen_discards_old_handles_and_reseals_recovered_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "events"
            store = _store(root)
            try:
                first = store.commit(_command(0, None), created_at=NOW)
                self.assertIsNotNone(store._windows_event_history)
                with self.assertRaises(SimulatedCrash):
                    store.commit(
                        _command(1, first["batch_digest"]),
                        created_at=NOW,
                        crash_hook=lambda point: point == "after_batch",
                    )
            finally:
                # Explicit lifecycle release simulates process exit before the
                # recovery instance starts; no held generation may be reused.
                store.close()
            reopened = _store(root)
            try:
                self.assertEqual(reopened.head()["sequence"], 2)
                self.assertIsNotNone(reopened._windows_event_history)
                envelope = reopened.read_envelope(reopened.head()["batch_digest"])
                self.assertEqual(envelope["command"]["command_id"], "command:0001")
            finally:
                reopened.close()

    def test_failed_provisional_acquisition_closes_partial_native_handles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "events"
            store = _store(root)
            try:
                store.commit(_command(0, None), created_at=NOW)
            finally:
                store.close()
            authority_root = (root / "journal-authority-root.json").read_text(
                encoding="utf-8"
            )
            import json

            generation = json.loads(authority_root)["generation"]
            journal_files = sorted((root / "journal").glob("*.json"))
            segment_files = sorted(
                (root / "journal-authority" / generation).glob("*.json")
            )
            before = _process_handle_count()
            original = WindowsEventHistorySeal._hold_file
            calls = 0

            def fail_second(*args: object, **kwargs: object) -> object:
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise WindowsEventHistoryUnavailable("injected acquisition failure")
                return original(*args, **kwargs)

            with mock.patch.object(
                WindowsEventHistorySeal, "_hold_file", side_effect=fail_second
            ):
                seal = WindowsEventHistorySeal.try_hold_existing(
                    root=root,
                    journal_directory=root / "journal",
                    authority_directory=root / "journal-authority" / generation,
                    journal_files=journal_files,
                    authority_files=segment_files,
                    max_file_bytes=2 * 1024 * 1024,
                )
            self.assertIsNone(seal)
            self.assertLessEqual(_process_handle_count(), before + 2)

    def test_near_cap_retires_seal_before_append_and_keeps_exact_history_valid(
        self,
    ) -> None:
        """A valid append falls back before either immutable file is written."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "events"
            store = _store(root)
            try:
                first = store.commit(_command(0, None), created_at=NOW)
                history = store._windows_event_history
                self.assertIsNotNone(history)
                assert history is not None
                # Deliberately force an append that has room for only one of
                # the two immutable artifacts.  The production default stays
                # 65,536; this is an injected near-cap boundary.
                history._max_held_files = history.held_file_count + 1

                calls = 0
                sealed_during_verifier: list[bool] = []
                append_write_seals: list[object] = []
                original = EventStore._verify_authority_prefix_locked
                original_write_atomic = events_module._write_atomic

                def counted(
                    instance: EventStore,
                    *args: object,
                    **kwargs: object,
                ) -> dict:
                    nonlocal calls
                    calls += 1
                    sealed_during_verifier.append(
                        instance._windows_event_history is history
                    )
                    return original(instance, *args, **kwargs)

                def observed_write(path: Path, payload: bytes) -> None:
                    if path.parent in {store.pending, store.journal}:
                        append_write_seals.append(store._windows_event_history)
                    original_write_atomic(path, payload)

                with mock.patch.object(
                    EventStore, "_verify_authority_prefix_locked", counted
                ), mock.patch("promin.events._write_atomic", observed_write):
                    second = store.commit(
                        _command(1, first["batch_digest"]),
                        created_at=NOW,
                    )
                self.assertEqual(calls, 1)
                self.assertEqual(sealed_during_verifier, [True])
                self.assertEqual(len(append_write_seals), 2)
                self.assertTrue(all(item is None for item in append_write_seals))
                self.assertIsNone(store._windows_event_history)
                self.assertTrue(store._windows_history_capacity_exhausted)
                self.assertEqual(store.head()["batch_digest"], second["batch_digest"])
                self.assertEqual(
                    store.read_envelope(second["batch_digest"])["command"]["command_id"],
                    "command:0001",
                )
            finally:
                store.close()

            # The stored bytes/head remain ordinary authoritative EventStore
            # history.  A fresh instance performs its usual admission scan
            # and proves the fallback did not leave a half-published pair.
            reopened = _store(root)
            try:
                self.assertEqual(reopened.head()["sequence"], 2)
                self.assertEqual(
                    reopened.read_envelope(reopened.head()["batch_digest"])["command"]
                    ["command_id"],
                    "command:0001",
                )
            finally:
                reopened.close()

    @unittest.skipUnless(
        os.environ.get("PROMIN_RUN_WINDOWS_EVENT_HISTORY_SCALE") == "1",
        "set PROMIN_RUN_WINDOWS_EVENT_HISTORY_SCALE=1 for 64/256/1024 scale proof",
    )
    def test_64_256_1024_commits_keep_one_initial_prefix_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "events"
            seed = _store(root)
            try:
                first = seed.commit(_command(0, None), created_at=NOW)
            finally:
                seed.close()

            calls = 0
            original = EventStore._verify_authority_prefix_locked

            def counted(instance: EventStore, *args: object, **kwargs: object) -> dict:
                nonlocal calls
                calls += 1
                return original(instance, *args, **kwargs)

            with mock.patch.object(EventStore, "_verify_authority_prefix_locked", counted):
                store = _store(root)
                try:
                    previous = first["batch_digest"]
                    for index in range(1, 1024):
                        previous = store.commit(
                            _command(index, previous), created_at=NOW
                        )["batch_digest"]
                        if index + 1 in {64, 256, 1024}:
                            self.assertEqual(calls, 1)
                    self.assertEqual(store.head()["batch_digest"], previous)
                    self.assertLessEqual(
                        store._windows_event_history.held_file_count,
                        2 * 1024,
                    )
                finally:
                    store.close()


if __name__ == "__main__":
    unittest.main()
