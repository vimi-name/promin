"""Heavy real-Windows probes for the create-only publication boundary.

These tests intentionally use the public publication/platform APIs rather than
mocking the native rename.  They exercise the difficult Windows cases that can
otherwise hide behind a small happy-path test: an ordinary long Unicode path on
a non-C volume, simultaneous parent-handle users, an externally held source,
and authority drift after reservation.
"""

from __future__ import annotations

import ctypes
import hashlib
import multiprocessing
import os
import queue
import shutil
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

import pytest

from promin.platform_paths import filesystem_path, physical_rename_directory_create_only
from promin.publication import (
    PublicationError,
    SourcePublicationReceipt,
    publish_directory_create_only,
)


pytestmark = [
    pytest.mark.windows_integration,
    pytest.mark.skipif(os.name != "nt", reason="native create-only publication is Windows-only"),
]


_WINDOWS_FILE_LIST_DIRECTORY = 0x00000001
_WINDOWS_FILE_READ_ATTRIBUTES = 0x00000080
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000


def _write_bytes(path: Path, value: bytes) -> None:
    with open(filesystem_path(path), "wb") as stream:
        stream.write(value)


def _read_bytes(path: Path) -> bytes:
    with open(filesystem_path(path), "rb") as stream:
        return stream.read()


def _receipt_for_payload(
    source: Path,
    membership_root: Path,
    payload: Path,
) -> SourcePublicationReceipt:
    authority = hashlib.sha256(_read_bytes(payload)).hexdigest()
    membership = hashlib.sha256(
        os.path.normcase(str(membership_root.absolute())).encode("utf-8")
    ).hexdigest()
    return SourcePublicationReceipt(
        source=source,
        membership_root=membership_root,
        authority_digest=authority,
        membership_digest=membership,
    )


def _mkdir(path: Path) -> None:
    os.mkdir(filesystem_path(path))


def _make_long_unicode_root(base: Path) -> Path:
    root = base / "вхід-київ-東京"
    _mkdir(root)
    counter = 0
    while len(str(root)) < 285:
        counter += 1
        root = root / f"сегмент-{counter:02d}-дані"
        _mkdir(root)
    return root


def _writable_non_c_root() -> Path:
    for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
        root = Path(f"{letter}:\\")
        if root.exists() and os.access(root, os.W_OK):
            return root
    pytest.skip("no writable non-C Windows volume is available for this probe")


@contextmanager
def _owned_non_c_directory() -> Iterator[Path]:
    root = _writable_non_c_root()
    directory = Path(tempfile.mkdtemp(prefix="promin-heavy-publication-", dir=root))
    try:
        yield directory
    finally:
        if directory.exists():
            # The tree is created exclusively by this test and may contain a
            # >260-character child.  An explicit extended root keeps cleanup
            # reliable on Windows hosts where legacy process settings persist.
            shutil.rmtree("\\\\?\\" + str(directory), ignore_errors=False)


@contextmanager
def _hold_directory_without_delete_share(path: Path) -> Iterator[int]:
    """Act as an external Windows owner that denies a DELETE open on *path*."""

    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        os.fspath(filesystem_path(path)),
        _WINDOWS_FILE_LIST_DIRECTORY | _WINDOWS_FILE_READ_ATTRIBUTES,
        _WINDOWS_FILE_SHARE_READ,
        None,
        _WINDOWS_OPEN_EXISTING,
        _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    value = handle if isinstance(handle, int) else getattr(handle, "value", None)
    if value in {None, invalid_handle}:
        raise ctypes.WinError(ctypes.get_last_error())
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    try:
        yield int(value)
    finally:
        if not close_handle(wintypes.HANDLE(value)):
            raise ctypes.WinError(ctypes.get_last_error())


def _rename_contender(
    source_text: str,
    destination_text: str,
    start_gate: object,
    outcomes: object,
) -> None:
    """Spawn-safe worker used for genuine competing native rename attempts."""

    if not start_gate.wait(30):
        outcomes.put(("error", "start-timeout", source_text))
        return
    try:
        physical_rename_directory_create_only(Path(source_text), Path(destination_text))
    except FileExistsError:
        outcomes.put(("exists", source_text, destination_text))
    except BaseException as exc:
        outcomes.put(("error", type(exc).__name__, str(exc)))
    else:
        outcomes.put(("moved", source_text, destination_text))


def _run_contenders(
    contenders: list[tuple[Path, Path]],
) -> list[tuple[str, str, str]]:
    context = multiprocessing.get_context("spawn")
    start_gate = context.Event()
    outcomes = context.Queue()
    processes = [
        context.Process(
            target=_rename_contender,
            args=(str(source), str(destination), start_gate, outcomes),
        )
        for source, destination in contenders
    ]
    for process in processes:
        process.start()
    start_gate.set()
    deadline = time.monotonic() + 45
    for process in processes:
        process.join(timeout=max(0, deadline - time.monotonic()))
    stuck = [process for process in processes if process.is_alive()]
    for process in stuck:
        process.terminate()
        process.join(timeout=10)
    assert not stuck, "native create-only contender did not finish within 45 seconds"
    assert all(process.exitcode == 0 for process in processes)

    observed: list[tuple[str, str, str]] = []
    for _ in processes:
        try:
            observed.append(outcomes.get(timeout=10))
        except queue.Empty as exc:
            raise AssertionError("native create-only contender returned no outcome") from exc
    outcomes.close()
    outcomes.join_thread()
    return observed


def test_windows_heavy_long_unicode_non_c_publication_is_create_only_and_no_credit() -> None:
    with _owned_non_c_directory() as base:
        root = _make_long_unicode_root(base)
        source = root / "джерело-даних"
        destination = root / "опубліковано-дані"
        _mkdir(source)
        payload = source / "доказ-東京.bin"
        _write_bytes(payload, b"long-unicode-non-c-payload")

        result = publish_directory_create_only(
            source,
            destination,
            membership_root=root,
            source_preflight=lambda observed_source, observed_root: _receipt_for_payload(
                observed_source, observed_root, payload
            ),
            authoritative_recheck=lambda expected, reservation: _receipt_for_payload(
                reservation.source,
                expected.membership_root,
                payload,
            ),
        )

        assert len(str(source)) > 260
        assert not os.path.exists(filesystem_path(source))
        assert os.path.isdir(filesystem_path(destination))
        assert _read_bytes(destination / "доказ-東京.bin") == b"long-unicode-non-c-payload"
        assert result.destination == destination
        assert not result.authority
        assert not result.pass_credit
        assert not result.acceptance_pass
        assert not result.product_acceptance_pass
        assert not result.runtime_acceptance_pass
        assert not result.release_ready


def test_windows_heavy_parallel_unique_destinations_share_one_parent_without_deadlock(
    tmp_path: Path,
) -> None:
    sources_root = tmp_path / "джерела"
    destination_parent = tmp_path / "публікації"
    sources_root.mkdir()
    destination_parent.mkdir()
    contenders: list[tuple[Path, Path]] = []
    for index in range(12):
        source = sources_root / f"source-{index:02d}"
        _mkdir(source)
        _write_bytes(source / "payload.bin", f"payload-{index}".encode("ascii"))
        contenders.append((source, destination_parent / f"published-{index:02d}"))

    observed = _run_contenders(contenders)

    assert [status for status, _source, _destination in observed].count("moved") == len(
        contenders
    )
    assert not [outcome for outcome in observed if outcome[0] == "error"]
    for index, (source, destination) in enumerate(contenders):
        assert not source.exists()
        assert _read_bytes(destination / "payload.bin") == f"payload-{index}".encode("ascii")


def test_windows_heavy_parallel_same_destination_preserves_exactly_one_source(
    tmp_path: Path,
) -> None:
    sources_root = tmp_path / "джерела"
    destination_parent = tmp_path / "публікації"
    destination = destination_parent / "one-create-only-destination"
    sources_root.mkdir()
    destination_parent.mkdir()
    contenders: list[tuple[Path, Path]] = []
    for index in range(12):
        source = sources_root / f"contender-{index:02d}"
        _mkdir(source)
        _write_bytes(source / "winner.bin", f"candidate-{index}".encode("ascii"))
        contenders.append((source, destination))

    observed = _run_contenders(contenders)

    statuses = [status for status, _source, _destination in observed]
    assert statuses.count("moved") == 1
    assert statuses.count("exists") == len(contenders) - 1
    assert not [outcome for outcome in observed if outcome[0] == "error"]
    assert destination.is_dir()
    published_payload = _read_bytes(destination / "winner.bin")
    surviving_sources = [source for source, _destination in contenders if source.exists()]
    assert len(surviving_sources) == len(contenders) - 1
    assert published_payload not in {
        _read_bytes(source / "winner.bin") for source in surviving_sources
    }


def test_windows_heavy_external_handle_contention_fails_closed_then_releases(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "published"
    source.mkdir()
    _write_bytes(source / "payload.bin", b"contention")

    with _hold_directory_without_delete_share(source):
        with pytest.raises(OSError) as captured:
            physical_rename_directory_create_only(source, destination)
        assert getattr(captured.value, "winerror", None) in {5, 32}
        assert source.is_dir()
        assert not destination.exists()

    physical_rename_directory_create_only(source, destination)
    assert not source.exists()
    assert _read_bytes(destination / "payload.bin") == b"contention"


def test_windows_heavy_authority_drift_and_callback_fault_release_every_reservation(
    tmp_path: Path,
) -> None:
    drift_root = tmp_path / "drift"
    drift_root.mkdir()

    for index in range(8):
        source = drift_root / f"source-{index:02d}"
        destination = drift_root / f"published-{index:02d}"
        _mkdir(source)
        payload = source / "payload.bin"
        _write_bytes(payload, f"baseline-{index}".encode("ascii"))
        expected = _receipt_for_payload(source, drift_root, payload)

        def drift_recheck(
            _expected: SourcePublicationReceipt,
            _reservation: object,
            *,
            current_payload: Path = payload,
            current_source: Path = source,
        ) -> SourcePublicationReceipt:
            _write_bytes(current_payload, b"changed-after-reservation")
            return _receipt_for_payload(current_source, drift_root, current_payload)

        with pytest.raises(PublicationError, match="authority changed"):
            publish_directory_create_only(
                source,
                destination,
                membership_root=drift_root,
                source_preflight=lambda observed_source, observed_root, receipt=expected: receipt,
                authoritative_recheck=drift_recheck,
            )

        assert source.is_dir()
        assert not destination.exists()
        released = drift_root / f"released-drift-{index:02d}"
        os.rename(filesystem_path(source), filesystem_path(released))
        assert released.is_dir()

    for index in range(8):
        source = drift_root / f"fault-source-{index:02d}"
        destination = drift_root / f"fault-published-{index:02d}"
        _mkdir(source)

        def callback_failure(_reservation: object) -> None:
            raise RuntimeError("injected authoritative callback fault")

        with pytest.raises(RuntimeError, match="injected authoritative callback fault"):
            physical_rename_directory_create_only(
                source,
                destination,
                after_reservation=callback_failure,
            )

        assert source.is_dir()
        assert not destination.exists()
        released = drift_root / f"released-fault-{index:02d}"
        os.rename(filesystem_path(source), filesystem_path(released))
        assert released.is_dir()
