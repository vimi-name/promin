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

from promin.windows_event_history import (
    WindowsEventHistorySeal,
    WindowsEventHistoryUnavailable,
    WindowsEventHistoryViolation,
)

# Build canonical sample history with the bounded real EventStore fixture, then
# exercise the optional host seal separately from EventStore activation.
from test_heavy_eventstore_prefix_witness import (  # type: ignore[import-not-found]
    NOW,
    _command,
    _store,
)

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


@unittest.skipUnless(os.name == "nt", "Windows host seal unit API")
class WindowsEventHistorySealUnitTests(unittest.TestCase):
    """Host-owned seal checks with no EventStore seal activation assumption."""

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


if __name__ == "__main__":
    unittest.main()
