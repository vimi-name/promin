"""Windows physical seals for immutable EventStore history files.

This module intentionally has a narrow job.  It is not a second journal
authority and it never derives an authority decision from metadata alone.
After EventStore has performed its normal byte-for-byte verification, the
seal keeps no-write/no-delete handles for the immutable journal envelopes and
the selected journal-authority generation.  A later healthy operation can
avoid hashing those already physically protected payloads only while the
exact handle, directory, control-file, and filename closure remain intact.

The implementation is deliberately Windows-only.  Unsupported filesystems,
API failures, handle pressure, and every uncertain observation are reported
as unavailable/invalid so EventStore can take its existing full-scan path.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


# The performance target explicitly requires that a healthy seal can cover at
# least 32k immutable files.  The default leaves room for a journal and its
# corresponding authority segments without silently degrading below that
# lower bound.
MINIMUM_WINDOWS_HISTORY_FILE_CAP = 32_768
DEFAULT_WINDOWS_HISTORY_FILE_CAP = 65_536


class WindowsEventHistoryError(RuntimeError):
    """Base failure for the optional Windows physical history seal."""


class WindowsEventHistoryUnavailable(WindowsEventHistoryError):
    """The optional fast path cannot be established on this host/volume."""


class WindowsEventHistoryViolation(WindowsEventHistoryError):
    """A live physical seal no longer proves its exact admitted layout."""


@dataclass(frozen=True)
class NativeFileWitness:
    """Stable NT handle facts used only beside the held physical handle."""

    volume_serial: int
    file_index: int
    size: int
    change_time: int
    attributes: int


@dataclass
class _HeldImmutable:
    kind: str
    path: Path
    digest: str
    witness: NativeFileWitness
    handle: int


@dataclass
class _HeldDirectory:
    path: Path
    names: frozenset[str]
    witness: NativeFileWitness
    handle: int


@dataclass(frozen=True)
class WindowsHistoryControl:
    """Exact mutable control bytes bound to one admitted immutable prefix."""

    head: tuple[int, str | None, str | None]
    authority_generation: str
    head_digest: str
    authority_root_digest: str
    checkpoint_digest: str


@dataclass(frozen=True)
class WindowsHistorySealCounters:
    """Bounded diagnostic counts for one live physical history seal.

    These values describe work performed by this process only.  They are not
    authority, health, or acceptance evidence and are never consulted by the
    EventStore verifier.  In particular, ``native_handles_live`` makes the
    exact one-handle-per-immutable-file cost visible instead of attributing a
    whole-process handle sample to this seal.
    """

    immutable_handles_live: int
    long_lived_directory_handles_live: int
    admission_guard_handles_live: int
    native_handles_live: int
    immutable_handle_opens: int
    immutable_witness_queries: int
    immutable_payload_bytes_hashed: int
    directory_closure_checks: int
    journal_index_build_visits: int
    journal_path_lookups: int
    journal_path_candidates_examined: int
    fast_validations: int
    control_advances: int


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", _FILETIME),
        ("ftLastAccessTime", _FILETIME),
        ("ftLastWriteTime", _FILETIME),
        ("dwVolumeSerialNumber", wintypes.DWORD),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("nNumberOfLinks", wintypes.DWORD),
        ("nFileIndexHigh", wintypes.DWORD),
        ("nFileIndexLow", wintypes.DWORD),
    ]


class _FILE_BASIC_INFO(ctypes.Structure):
    _fields_ = [
        ("CreationTime", ctypes.c_longlong),
        ("LastAccessTime", ctypes.c_longlong),
        ("LastWriteTime", ctypes.c_longlong),
        ("ChangeTime", ctypes.c_longlong),
        ("FileAttributes", wintypes.DWORD),
    ]


_GENERIC_READ = 0x80000000
_FILE_READ_ATTRIBUTES = 0x00000080
_FILE_LIST_DIRECTORY = 0x00000001
_SYNCHRONIZE = 0x00100000
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_BASIC_INFO_CLASS = 0
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_READ_CHUNK_BYTES = 1024 * 1024


def _native_path(path: Path) -> str:
    absolute = str(path.absolute())
    if absolute.startswith("\\\\?\\"):
        return absolute
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


def _kernel32() -> ctypes.WinDLL:
    if os.name != "nt":
        raise WindowsEventHistoryUnavailable("Windows physical history seals require Windows")
    try:
        return ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError) as exc:
        raise WindowsEventHistoryUnavailable("kernel32 is unavailable") from exc


def _raise_last_error(action: str, path: Path | None = None) -> None:
    error = ctypes.get_last_error()
    suffix = f": {path}" if path is not None else ""
    raise WindowsEventHistoryUnavailable(f"{action} failed with Win32 error {error}{suffix}")


def _configure_kernel32(kernel32: ctypes.WinDLL) -> None:
    # Assigning arg/restypes is idempotent and keeps all raw-handle operations
    # explicit.  Nothing in this module relies on CRT file descriptors.
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        wintypes.INT,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.SetFilePointerEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    ]
    kernel32.SetFilePointerEx.restype = wintypes.BOOL
    kernel32.GetVolumePathNameW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    kernel32.GetVolumePathNameW.restype = wintypes.BOOL
    kernel32.GetVolumeInformationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    kernel32.GetVolumeInformationW.restype = wintypes.BOOL


def _close_handle(handle: int | None) -> None:
    if handle is None or handle == _INVALID_HANDLE_VALUE:
        return
    try:
        kernel32 = _kernel32()
        _configure_kernel32(kernel32)
        kernel32.CloseHandle(handle)
    except WindowsEventHistoryError:
        return


def _open_handle(
    path: Path,
    *,
    desired_access: int,
    share_mode: int = _FILE_SHARE_READ,
    creation_disposition: int,
    flags: int,
) -> int:
    kernel32 = _kernel32()
    _configure_kernel32(kernel32)
    handle = kernel32.CreateFileW(
        _native_path(path),
        desired_access,
        share_mode,
        None,
        creation_disposition,
        flags,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        _raise_last_error("CreateFileW", path)
    return int(handle)


def _query_witness(handle: int, path: Path) -> NativeFileWitness:
    kernel32 = _kernel32()
    _configure_kernel32(kernel32)
    basic = _FILE_BASIC_INFO()
    if not kernel32.GetFileInformationByHandleEx(
        handle,
        _FILE_BASIC_INFO_CLASS,
        ctypes.byref(basic),
        ctypes.sizeof(basic),
    ):
        _raise_last_error("GetFileInformationByHandleEx", path)
    info = _BY_HANDLE_FILE_INFORMATION()
    if not kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
        _raise_last_error("GetFileInformationByHandle", path)
    return NativeFileWitness(
        volume_serial=int(info.dwVolumeSerialNumber),
        file_index=(int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow),
        size=(int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow),
        change_time=int(basic.ChangeTime),
        attributes=int(basic.FileAttributes),
    )


def _require_regular_witness(witness: NativeFileWitness, path: Path) -> None:
    if witness.attributes & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT):
        raise WindowsEventHistoryUnavailable(
            f"immutable history path is not a direct regular file: {path}"
        )


def _require_directory_witness(witness: NativeFileWitness, path: Path) -> None:
    if not witness.attributes & _FILE_ATTRIBUTE_DIRECTORY or witness.attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
        raise WindowsEventHistoryUnavailable(
            f"history directory is not a direct directory: {path}"
        )


def _read_exact_bytes_from_handle(handle: int, path: Path, expected_size: int) -> bytes:
    """Read exact bounded bytes through an already held native file handle."""

    kernel32 = _kernel32()
    _configure_kernel32(kernel32)
    current = ctypes.c_longlong()
    if not kernel32.SetFilePointerEx(handle, 0, ctypes.byref(current), 0):
        _raise_last_error("SetFilePointerEx", path)
    chunks: list[bytes] = []
    remaining = expected_size
    while remaining:
        requested = min(_READ_CHUNK_BYTES, remaining)
        buffer = ctypes.create_string_buffer(requested)
        read = wintypes.DWORD()
        if not kernel32.ReadFile(handle, buffer, requested, ctypes.byref(read), None):
            _raise_last_error("ReadFile", path)
        count = int(read.value)
        if count <= 0:
            raise WindowsEventHistoryUnavailable(
                f"immutable history file ended before its native size: {path}"
            )
        chunks.append(buffer.raw[:count])
        remaining -= count
    # A handle with a stable exact byte count must be at EOF now.  Confirming
    # this catches a short/direct-read anomaly without trusting a path stat.
    one = ctypes.create_string_buffer(1)
    read = wintypes.DWORD()
    if not kernel32.ReadFile(handle, one, 1, ctypes.byref(read), None):
        _raise_last_error("ReadFile EOF", path)
    if read.value:
        raise WindowsEventHistoryUnavailable(
            f"immutable history file grew during held-handle read: {path}"
        )
    return b"".join(chunks)


def _read_digest_from_handle(handle: int, path: Path, expected_size: int) -> str:
    """Hash exact bytes through an already no-write/no-delete held handle."""

    return hashlib.sha256(
        _read_exact_bytes_from_handle(handle, path, expected_size)
    ).hexdigest()


def _child_names(directory: Path) -> frozenset[str]:
    try:
        with os.scandir(_native_path(directory)) as entries:
            return frozenset(entry.name for entry in entries)
    except OSError as exc:
        raise WindowsEventHistoryUnavailable(
            f"history directory enumeration failed: {directory}"
        ) from exc


def _filesystem_name(path: Path) -> str:
    kernel32 = _kernel32()
    _configure_kernel32(kernel32)
    volume_path = ctypes.create_unicode_buffer(32768)
    if not kernel32.GetVolumePathNameW(
        _native_path(path), volume_path, len(volume_path)
    ):
        _raise_last_error("GetVolumePathNameW", path)
    fs_name = ctypes.create_unicode_buffer(256)
    volume_serial = wintypes.DWORD()
    maximum_component = wintypes.DWORD()
    flags = wintypes.DWORD()
    if not kernel32.GetVolumeInformationW(
        volume_path.value,
        None,
        0,
        ctypes.byref(volume_serial),
        ctypes.byref(maximum_component),
        ctypes.byref(flags),
        fs_name,
        len(fs_name),
    ):
        _raise_last_error("GetVolumeInformationW", path)
    return fs_name.value.upper()


def _head_tuple(head: Mapping[str, object]) -> tuple[int, str | None, str | None]:
    sequence = head.get("sequence")
    batch_id = head.get("batch_id")
    batch_digest = head.get("batch_digest")
    if (
        not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 0
        or batch_id is not None and not isinstance(batch_id, str)
        or batch_digest is not None and not isinstance(batch_digest, str)
    ):
        raise WindowsEventHistoryUnavailable("history seal received an invalid HEAD")
    return sequence, batch_id, batch_digest


class WindowsEventHistorySeal:
    """Held Windows handles for one verified immutable EventStore prefix.

    `try_hold_existing` deliberately only establishes a provisional physical
    hold.  EventStore must complete its normal full verifier while these
    handles are held and then call `bind_verified_control`.  This sequencing
    avoids the verify-then-open TOCTOU gap.
    """

    def __init__(
        self,
        *,
        root: Path,
        root_directory: _HeldDirectory,
        journal_directory: _HeldDirectory,
        authority_directory: _HeldDirectory,
        held: dict[Path, _HeldImmutable],
        max_held_files: int,
    ) -> None:
        self.root = root.absolute()
        self._root_directory = root_directory
        self._journal_directory = journal_directory
        self._authority_directory = authority_directory
        self._held = held
        self._max_held_files = max_held_files
        # A journal replay asks for every sequence in order.  Scanning
        # ``_held`` for each request used to inspect both journal and authority
        # members B * (2B) times for B batches.  The index is derived only from
        # already held paths, retains every collision, and therefore preserves
        # the previous missing/ambiguous fail-closed behavior in O(1) lookup.
        self._journal_paths_by_sequence: dict[int, Path | None] = {}
        self._journal_index_build_visits = 0
        self._journal_path_lookups = 0
        self._journal_path_candidates_examined = 0
        for item in held.values():
            if item.kind == "journal":
                self._index_journal_path(item.path)

        # Operation counters are deliberately a fixed-cardinality set of
        # scalars and retain no per-operation/path records.  Initial
        # acquisition sampled every immutable handle before and after hashing
        # its exact bytes.
        self._immutable_handle_opens = len(held)
        self._immutable_witness_queries = 2 * len(held)
        self._immutable_payload_bytes_hashed = sum(
            item.witness.size for item in held.values()
        )
        self._directory_closure_checks = 0
        self._fast_validations = 0
        self._control_advances = 0
        # Kept from provisional acquisition until EventStore finishes its
        # pathname-based full verifier and binds controls.  They deny DELETE
        # sharing so a directory cannot be renamed/rebound between those two
        # operations, while still allowing verifier reads.
        self._admission_guards: dict[Path, _HeldDirectory] = {}
        self._control: WindowsHistoryControl | None = None
        self._closed = False

    @property
    def held_file_count(self) -> int:
        return len(self._held)

    @property
    def maximum_held_files(self) -> int:
        return self._max_held_files

    @property
    def performance_counters(self) -> WindowsHistorySealCounters:
        """Return non-authoritative bounded operation and handle counts."""

        immutable_handles = 0 if self._closed else len(self._held)
        directory_handles = 0 if self._closed else 3
        admission_handles = 0 if self._closed else len(self._admission_guards)
        return WindowsHistorySealCounters(
            immutable_handles_live=immutable_handles,
            long_lived_directory_handles_live=directory_handles,
            admission_guard_handles_live=admission_handles,
            native_handles_live=immutable_handles + directory_handles + admission_handles,
            immutable_handle_opens=self._immutable_handle_opens,
            immutable_witness_queries=self._immutable_witness_queries,
            immutable_payload_bytes_hashed=self._immutable_payload_bytes_hashed,
            directory_closure_checks=self._directory_closure_checks,
            journal_index_build_visits=self._journal_index_build_visits,
            journal_path_lookups=self._journal_path_lookups,
            journal_path_candidates_examined=self._journal_path_candidates_examined,
            fast_validations=self._fast_validations,
            control_advances=self._control_advances,
        )

    def has_capacity_for(self, immutable_file_count: int) -> bool:
        """Return whether one atomic append can reserve its whole file pair.

        EventStore publishes one journal envelope and one matching authority
        segment for every committed batch.  It must ask for both slots before
        the pending/journal durability sequence begins; accepting only the
        first file would turn ordinary handle pressure into a partially
        published transaction and an avoidable recovery failure.
        """

        self._ensure_live()
        if (
            not isinstance(immutable_file_count, int)
            or isinstance(immutable_file_count, bool)
            or immutable_file_count < 0
        ):
            raise WindowsEventHistoryViolation(
                "immutable history capacity request is invalid"
            )
        return len(self._held) + immutable_file_count <= self._max_held_files

    @property
    def is_bound(self) -> bool:
        return not self._closed and self._control is not None

    @property
    def authority_generation(self) -> str | None:
        return None if self._control is None else self._control.authority_generation

    def journal_path_for_sequence(self, sequence: int) -> Path:
        """Resolve a journal member without reopening its mutable pathname."""

        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise WindowsEventHistoryViolation("journal sequence is invalid")
        self._journal_path_lookups += 1
        if sequence not in self._journal_paths_by_sequence:
            raise WindowsEventHistoryViolation(
                f"sealed journal sequence is missing or ambiguous: {sequence}"
            )
        path = self._journal_paths_by_sequence[sequence]
        if path is None:
            # Two candidates are sufficient to establish ambiguity; all held
            # colliders remain in ``_held`` and under their physical handles.
            self._journal_path_candidates_examined += 2
            raise WindowsEventHistoryViolation(
                f"sealed journal sequence is missing or ambiguous: {sequence}"
            )
        self._journal_path_candidates_examined += 1
        return path

    def read_held_bytes(self, path: Path) -> bytes:
        """Read one exact sealed immutable payload by handle, not pathname."""

        self._ensure_live()
        item = self._held.get(path.absolute())
        if item is None:
            raise WindowsEventHistoryViolation(
                f"path is not a held immutable history file: {path}"
            )
        current = _query_witness(item.handle, item.path)
        self._immutable_witness_queries += 1
        _require_regular_witness(current, item.path)
        if current != item.witness:
            raise WindowsEventHistoryViolation(
                f"held immutable history file identity changed: {item.path}"
            )
        raw = _read_exact_bytes_from_handle(item.handle, item.path, item.witness.size)
        self._immutable_payload_bytes_hashed += len(raw)
        if hashlib.sha256(raw).hexdigest() != item.digest:
            raise WindowsEventHistoryViolation(
                f"held immutable history file digest changed: {item.path}"
            )
        return raw

    @classmethod
    def try_hold_existing(
        cls,
        *,
        root: Path,
        journal_directory: Path,
        authority_directory: Path,
        journal_files: Sequence[Path],
        authority_files: Sequence[Path],
        max_file_bytes: int,
        max_held_files: int = DEFAULT_WINDOWS_HISTORY_FILE_CAP,
    ) -> "WindowsEventHistorySeal | None":
        """Acquire physical holds before EventStore's full byte verification.

        The method returns ``None`` only for platform/volume/capability
        absence.  A caller must use the regular full verifier in that case.
        It raises neither a security acceptance nor a metadata-only result.
        """

        if os.name != "nt":
            return None
        if max_held_files < MINIMUM_WINDOWS_HISTORY_FILE_CAP:
            raise ValueError("Windows history file cap must be at least 32768")
        if not isinstance(max_file_bytes, int) or max_file_bytes < 1:
            raise ValueError("max_file_bytes must be a positive integer")
        root_directory: _HeldDirectory | None = None
        journal: _HeldDirectory | None = None
        authority: _HeldDirectory | None = None
        held: dict[Path, _HeldImmutable] = {}
        seal: WindowsEventHistorySeal | None = None
        try:
            fs_name = _filesystem_name(root)
            if fs_name not in {"NTFS", "REFS"}:
                raise WindowsEventHistoryUnavailable(
                    f"filesystem {fs_name or '<unknown>'} lacks supported seal semantics"
                )
            journal_directory = journal_directory.absolute()
            authority_directory = authority_directory.absolute()
            root_directory = cls._hold_directory(root.absolute())
            journal = cls._hold_directory(journal_directory)
            authority = cls._hold_directory(authority_directory)
            files = [
                *( ("journal", path) for path in journal_files ),
                *( ("authority", path) for path in authority_files ),
            ]
            if len(files) > max_held_files:
                raise WindowsEventHistoryUnavailable(
                    f"immutable history file count {len(files)} exceeds held handle cap {max_held_files}"
                )
            for kind, path in files:
                directory = journal_directory if kind == "journal" else authority_directory
                absolute = path.absolute()
                if absolute.parent != directory or absolute.name in {"", ".", ".."}:
                    raise WindowsEventHistoryUnavailable(
                        f"immutable history file is outside its sealed directory: {path}"
                    )
                if absolute in held:
                    raise WindowsEventHistoryUnavailable(
                        f"duplicate immutable history file: {path}"
                    )
                held[absolute] = cls._hold_file(
                    kind=kind,
                    path=absolute,
                    max_file_bytes=max_file_bytes,
                )
            seal = cls(
                root=root,
                root_directory=root_directory,
                journal_directory=journal,
                authority_directory=authority,
                held=held,
                max_held_files=max_held_files,
            )
            # Keep path-identity/no-delete guards through the caller's full
            # verifier and bind.  The verifier currently consumes paths, so a
            # guard opened only afterwards would leave a rebind gap.
            seal._acquire_admission_guards()
            # Names are captured only after both directory handles are open.
            # The subsequent full EventStore verifier checks canonical content
            # under the same no-write/no-delete file holds and path guards.
            seal._require_exact_directory_names()
            return seal
        except WindowsEventHistoryUnavailable:
            if seal is not None:
                seal.close()
            else:
                for item in held.values():
                    _close_handle(item.handle)
                if root_directory is not None:
                    _close_handle(root_directory.handle)
                if journal is not None:
                    _close_handle(journal.handle)
                if authority is not None:
                    _close_handle(authority.handle)
            return None
        except BaseException:
            if seal is not None:
                seal.close()
            else:
                for item in held.values():
                    _close_handle(item.handle)
                if root_directory is not None:
                    _close_handle(root_directory.handle)
                if journal is not None:
                    _close_handle(journal.handle)
                if authority is not None:
                    _close_handle(authority.handle)
            raise

    @staticmethod
    def _hold_directory(path: Path) -> _HeldDirectory:
        handle = _open_handle(
            path,
            desired_access=_FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            share_mode=_FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            creation_disposition=_OPEN_EXISTING,
            flags=_FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        )
        try:
            witness = _query_witness(handle, path)
            _require_directory_witness(witness, path)
            return _HeldDirectory(
                path=path,
                names=_child_names(path),
                witness=witness,
                handle=handle,
            )
        except BaseException:
            _close_handle(handle)
            raise

    @staticmethod
    def _guard_directory_path(path: Path) -> _HeldDirectory:
        """Freeze rename/delete of the current path while closing its names.

        The long-lived directory handle deliberately shares WRITE and DELETE so
        EventStore can retain its durable temp+replace protocol.  This short
        guard is different: it shares READ|WRITE but not DELETE, then compares
        the *current pathname* to the long-lived directory identity before
        `scandir`.  That closes a rename/rebind-to-same-names gap without
        claiming that directory ChangeTime alone is an authority witness.
        """

        handle = _open_handle(
            path,
            desired_access=_FILE_LIST_DIRECTORY | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            share_mode=_FILE_SHARE_READ | _FILE_SHARE_WRITE,
            creation_disposition=_OPEN_EXISTING,
            flags=_FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        )
        try:
            witness = _query_witness(handle, path)
            _require_directory_witness(witness, path)
            return _HeldDirectory(
                path=path,
                names=_child_names(path),
                witness=witness,
                handle=handle,
            )
        except BaseException:
            _close_handle(handle)
            raise

    @staticmethod
    def _hold_file(
        *, kind: str, path: Path, max_file_bytes: int
    ) -> _HeldImmutable:
        handle = _open_handle(
            path,
            desired_access=_GENERIC_READ | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
            creation_disposition=_OPEN_EXISTING,
            flags=_FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_SEQUENTIAL_SCAN,
        )
        try:
            before = _query_witness(handle, path)
            _require_regular_witness(before, path)
            if before.size > max_file_bytes:
                raise WindowsEventHistoryUnavailable(
                    f"immutable history file exceeds bounded payload ceiling: {path}"
                )
            digest = _read_digest_from_handle(handle, path, before.size)
            after = _query_witness(handle, path)
            if after != before:
                raise WindowsEventHistoryUnavailable(
                    f"immutable history file changed while its held handle was read: {path}"
                )
            return _HeldImmutable(kind, path, digest, before, handle)
        except BaseException:
            _close_handle(handle)
            raise

    def bind_verified_control(
        self,
        *,
        head: Mapping[str, object],
        authority_generation: str,
        head_payload: bytes,
        authority_root_payload: bytes,
        checkpoint_payload: bytes,
    ) -> None:
        """Admit the hold only after EventStore's full verifier succeeded."""

        self._ensure_live()
        if not isinstance(authority_generation, str) or not authority_generation:
            raise WindowsEventHistoryViolation("verified authority generation is invalid")
        if self._authority_directory.path.name != authority_generation:
            raise WindowsEventHistoryViolation(
                "verified authority generation differs from held directory"
            )
        self._require_exact_directory_names()
        self._require_held_witnesses()
        self._control = WindowsHistoryControl(
            head=_head_tuple(head),
            authority_generation=authority_generation,
            head_digest=hashlib.sha256(head_payload).hexdigest(),
            authority_root_digest=hashlib.sha256(authority_root_payload).hexdigest(),
            checkpoint_digest=hashlib.sha256(checkpoint_payload).hexdigest(),
        )
        self._release_admission_guards()

    def validate_fast(
        self,
        *,
        head: Mapping[str, object],
        authority_generation: str,
        head_payload: bytes,
        authority_root_payload: bytes,
        checkpoint_payload: bytes,
    ) -> None:
        """Validate only physical/incremental facts; never rehash old files."""

        self._ensure_live()
        self._fast_validations += 1
        control = self._control
        if control is None:
            raise WindowsEventHistoryViolation("Windows history hold was never fully verified")
        if (
            _head_tuple(head) != control.head
            or authority_generation != control.authority_generation
            or hashlib.sha256(head_payload).hexdigest() != control.head_digest
            or hashlib.sha256(authority_root_payload).hexdigest()
            != control.authority_root_digest
            or hashlib.sha256(checkpoint_payload).hexdigest()
            != control.checkpoint_digest
        ):
            raise WindowsEventHistoryViolation("mutable history controls changed")
        # ChangeTime is deliberately not the authority.  Exact child-name
        # closure and retained handles are mandatory because an attacker with
        # FILE_WRITE_ATTRIBUTES can restore timestamps on NTFS.
        self._require_exact_directory_names()
        self._require_held_witnesses()

    def hold_new_existing(
        self,
        *,
        kind: str,
        path: Path,
        payload: bytes,
        max_file_bytes: int,
    ) -> str:
        """Hold an atomically published immutable file before HEAD can advance.

        EventStore deliberately retains its existing temp-write + durable
        replace publication protocol.  This method runs immediately after that
        atomic publication, under the EventStore writer lock, opens the final
        path with a no-write/no-delete sharing mode, and hashes the expected
        canonical payload through the retained handle.  A conflict or mismatch
        aborts before HEAD is advanced; normal recovery owns any resulting
        orphan/pending suffix.
        """

        self._ensure_live()
        if kind not in {"journal", "authority"}:
            raise WindowsEventHistoryViolation("unknown immutable history kind")
        directory = (
            self._journal_directory if kind == "journal" else self._authority_directory
        )
        absolute = path.absolute()
        if absolute.parent != directory.path or absolute.name in directory.names:
            raise WindowsEventHistoryViolation(
                f"new immutable history filename is not fresh: {path}"
            )
        if len(payload) > max_file_bytes:
            raise WindowsEventHistoryViolation("new immutable history payload exceeds ceiling")
        if len(self._held) >= self._max_held_files:
            raise WindowsEventHistoryViolation("Windows immutable history handle cap reached")
        expected = hashlib.sha256(payload).hexdigest()
        item: _HeldImmutable | None = None
        guard: _HeldDirectory | None = None
        try:
            # Hold the directory pathname against rename/delete before opening
            # or hashing the just-published final file.  The atomic writer ran
            # before this guard; from here until the sealed file handle exists,
            # the pathname cannot be rebound underneath this operation.
            guard = self._guard_directory_path(directory.path)
            current_directory = _query_witness(directory.handle, directory.path)
            _require_directory_witness(current_directory, directory.path)
            if not self._same_directory_identity(
                current_directory, guard.witness
            ) or not self._same_directory_identity(
                current_directory, directory.witness
            ):
                raise WindowsEventHistoryViolation(
                    f"history directory path was rebound beside new immutable file: {directory.path}"
                )
            if kind == "journal":
                expected_names = frozenset(
                    (*self._journal_directory.names, absolute.name)
                )
            else:
                expected_names = frozenset(
                    (*self._authority_directory.names, absolute.name)
                )
            if guard.names != expected_names:
                raise WindowsEventHistoryViolation(
                    f"history directory changed beside new immutable file: {directory.path}"
                )
            item = self._hold_file(
                kind=kind,
                path=absolute,
                max_file_bytes=max_file_bytes,
            )
            if item.witness.size != len(payload) or item.digest != expected:
                raise WindowsEventHistoryViolation(
                    "new immutable history file differs from its canonical payload"
                )
            self._held[absolute] = item
            self._immutable_handle_opens += 1
            self._immutable_witness_queries += 2
            self._immutable_payload_bytes_hashed += item.witness.size
            if kind == "journal":
                self._index_journal_path(absolute)
            directory.names = expected_names
            return item.digest
        except BaseException:
            if item is not None and absolute not in self._held:
                # `_hold_file` closes on its own failure.  This branch only
                # closes a successfully held file that failed a later check.
                _close_handle(item.handle)
            raise
        finally:
            if guard is not None:
                _close_handle(guard.handle)

    def advance_verified_control(
        self,
        *,
        head: Mapping[str, object],
        authority_generation: str,
        head_payload: bytes,
        authority_root_payload: bytes,
        checkpoint_payload: bytes,
    ) -> None:
        """Record expected own control writes after newly appended files seal."""

        self._ensure_live()
        self._control_advances += 1
        self._require_exact_directory_names(rebaseline=True)
        self._require_held_witnesses()
        self._control = WindowsHistoryControl(
            head=_head_tuple(head),
            authority_generation=authority_generation,
            head_digest=hashlib.sha256(head_payload).hexdigest(),
            authority_root_digest=hashlib.sha256(authority_root_payload).hexdigest(),
            checkpoint_digest=hashlib.sha256(checkpoint_payload).hexdigest(),
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for item in tuple(self._held.values()):
            _close_handle(item.handle)
        self._held.clear()
        self._journal_paths_by_sequence.clear()
        self._release_admission_guards()
        _close_handle(self._root_directory.handle)
        _close_handle(self._journal_directory.handle)
        _close_handle(self._authority_directory.handle)

    def _ensure_live(self) -> None:
        if self._closed:
            raise WindowsEventHistoryViolation("Windows history seal is closed")

    def _require_exact_directory_names(self, *, rebaseline: bool = False) -> None:
        self._directory_closure_checks += 1
        self._require_root_identity()
        for directory in (self._journal_directory, self._authority_directory):
            admission_guard = self._admission_guards.get(directory.path)
            # Always reopen the *current pathname*.  A retained admission
            # guard references the old object, so it alone cannot prove that
            # an ancestor rebind did not make the same string resolve anew.
            fresh_guard = self._guard_directory_path(directory.path)
            try:
                current = _query_witness(directory.handle, directory.path)
                _require_directory_witness(current, directory.path)
                if (
                    not self._same_directory_identity(current, fresh_guard.witness)
                    or not self._same_directory_identity(current, directory.witness)
                    or admission_guard is not None
                    and not self._same_directory_identity(
                        current, admission_guard.witness
                    )
                ):
                    raise WindowsEventHistoryViolation(
                        f"history directory path was rebound: {directory.path}"
                    )
                # `guard.names` was enumerated while the current directory
                # pathname could not be renamed or deleted.  Child creation is
                # intentionally still allowed for EventStore's atomic writer;
                # any persistent unexpected child is caught by exact closure.
                names = fresh_guard.names
                if admission_guard is not None and admission_guard.names != directory.names:
                    raise WindowsEventHistoryViolation(
                        f"history directory topology changed during provisional admission: {directory.path}"
                    )
                if rebaseline:
                    # This is allowed only for EventStore's known own append,
                    # after the new file is already sealed.
                    if names != directory.names:
                        raise WindowsEventHistoryViolation(
                            f"history directory topology changed during own append: {directory.path}"
                        )
                    directory.witness = current
                    continue
                if current != directory.witness or names != directory.names:
                    raise WindowsEventHistoryViolation(
                        f"history directory identity or exact filename closure changed: {directory.path}"
                    )
            finally:
                _close_handle(fresh_guard.handle)

    def _require_root_identity(self) -> None:
        """Bind the current EventStore root pathname to the held root object."""

        directory = self._root_directory
        admission_guard = self._admission_guards.get(directory.path)
        fresh_guard = self._guard_directory_path(directory.path)
        try:
            current = _query_witness(directory.handle, directory.path)
            _require_directory_witness(current, directory.path)
            if (
                not self._same_directory_identity(current, directory.witness)
                or not self._same_directory_identity(current, fresh_guard.witness)
                or admission_guard is not None
                and not self._same_directory_identity(
                    current, admission_guard.witness
                )
            ):
                raise WindowsEventHistoryViolation(
                    f"EventStore root path was rebound: {directory.path}"
                )
        finally:
            _close_handle(fresh_guard.handle)

    def _acquire_admission_guards(self) -> None:
        if self._admission_guards:
            raise WindowsEventHistoryViolation(
                "Windows history admission guards were already acquired"
            )
        try:
            for directory in (
                self._root_directory,
                self._journal_directory,
                self._authority_directory,
            ):
                guard = self._guard_directory_path(directory.path)
                current = _query_witness(directory.handle, directory.path)
                _require_directory_witness(current, directory.path)
                if not self._same_directory_identity(
                    current, directory.witness
                ) or not self._same_directory_identity(current, guard.witness):
                    _close_handle(guard.handle)
                    raise WindowsEventHistoryViolation(
                        f"history directory path changed during provisional admission: {directory.path}"
                    )
                if directory is not self._root_directory and guard.names != directory.names:
                    _close_handle(guard.handle)
                    raise WindowsEventHistoryViolation(
                        f"history directory topology changed during provisional admission: {directory.path}"
                    )
                self._admission_guards[directory.path] = guard
        except BaseException:
            self._release_admission_guards()
            raise

    def _release_admission_guards(self) -> None:
        for guard in self._admission_guards.values():
            _close_handle(guard.handle)
        self._admission_guards.clear()

    @staticmethod
    def _same_directory_identity(
        left: NativeFileWitness, right: NativeFileWitness
    ) -> bool:
        return (
            left.volume_serial == right.volume_serial
            and left.file_index == right.file_index
            and left.attributes == right.attributes
        )

    def _require_held_witnesses(self) -> None:
        for item in self._held.values():
            self._immutable_witness_queries += 1
            current = _query_witness(item.handle, item.path)
            _require_regular_witness(current, item.path)
            if current != item.witness:
                raise WindowsEventHistoryViolation(
                    f"held immutable history file identity changed: {item.path}"
                )

    @staticmethod
    def _journal_sequence(path: Path) -> int | None:
        """Return the exact legacy lookup prefix encoded by one held path."""

        name = path.name
        delimiter = name.find("-")
        if delimiter < 20:
            return None
        prefix = name[:delimiter]
        if any(character < "0" or character > "9" for character in prefix):
            return None
        sequence = int(prefix)
        if sequence < 1 or prefix != f"{sequence:020d}":
            return None
        return sequence

    def _index_journal_path(self, path: Path) -> None:
        self._journal_index_build_visits += 1
        sequence = self._journal_sequence(path)
        if sequence is not None:
            if sequence in self._journal_paths_by_sequence:
                self._journal_paths_by_sequence[sequence] = None
            else:
                self._journal_paths_by_sequence[sequence] = path

    def __enter__(self) -> "WindowsEventHistorySeal":
        return self

    def __exit__(self, *_unused: object) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - best effort interpreter cleanup
        try:
            self.close()
        except BaseException:
            pass
