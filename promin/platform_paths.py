"""Cross-platform filesystem path guards.

Core logic calls this module instead of embedding Windows/macOS/POSIX path
quirks.  The API is deliberately small: resolve one existing path under a
boundary and format an absolute path for Windows extended-length APIs.
"""

from __future__ import annotations

import ntpath
import os
import re
import stat
import tempfile
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Callable, Iterator


class PlatformPathError(ValueError):
    pass


_ROOT_IDENTITY_CACHE_LIMIT = 256
_root_identity_cache: OrderedDict[tuple[str, tuple[int, int, int, int, int]], Path] = (
    OrderedDict()
)
_root_identity_cache_lock = RLock()


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    """Return the change-sensitive identity used for one cache lookup.

    A cached identity is never trusted by name alone: ``resolve_contained_path``
    stats the lexical root on every use and only reuses its resolved spelling
    when the observed object is still the same directory.
    """

    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _resolved_root_identity(raw_root: Path, root_stat: os.stat_result) -> Path:
    """Resolve one unchanged containment root without repeated OS identity I/O."""

    absolute_root = raw_root.absolute()
    key = (normalize_identity_text(absolute_root), _stat_identity(root_stat))
    with _root_identity_cache_lock:
        cached = _root_identity_cache.pop(key, None)
        if cached is not None:
            _root_identity_cache[key] = cached
            return cached
    try:
        resolved = resolve_identity_path(absolute_root, strict=True)
    except OSError as exc:
        raise PlatformPathError(f"path root cannot be inspected: {exc}") from exc
    with _root_identity_cache_lock:
        _root_identity_cache[key] = resolved
        if len(_root_identity_cache) > _ROOT_IDENTITY_CACHE_LIMIT:
            _root_identity_cache.popitem(last=False)
    return resolved


def _is_link_or_reparse(path: Path, inspected: os.stat_result | None = None) -> bool:
    value = inspected if inspected is not None else os.lstat(filesystem_path(path))
    # ``lstat`` already observes the link bit.  Calling ``os.path.islink``
    # afterwards repeats that same filesystem lookup for every path component.
    if stat.S_ISLNK(value.st_mode):
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    attributes = getattr(value, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    return bool(attributes & reparse_flag)


def resolve_contained_path(
    path: str | os.PathLike[str],
    *,
    root: str | os.PathLike[str],
    require_regular: bool = False,
    reject_internal_links: bool = True,
) -> Path:
    """Resolve *path* under *root* with one consistent normalization.

    The root itself may be addressed through an OS alias (Windows 8.3 path or
    macOS ``/var`` symlink).  Symlink/reparse components *inside* the boundary
    remain rejected.  Containment is always checked resolved-vs-resolved.
    """

    raw_root = Path(root)
    raw_path = Path(path)
    if not raw_path.is_absolute():
        root_absolute = raw_root.absolute()
        candidate_absolute = raw_path.absolute()
        try:
            candidate_absolute.relative_to(root_absolute)
        except ValueError:
            raw_path = raw_root / raw_path
        else:
            raw_path = candidate_absolute
    try:
        root_stat = os.stat(filesystem_path(raw_root))
        resolved_root = _resolved_root_identity(raw_root, root_stat)
    except OSError as exc:
        raise PlatformPathError(f"path root cannot be inspected: {exc}") from exc
    if not stat.S_ISDIR(root_stat.st_mode):
        raise PlatformPathError("path root must resolve to a directory")
    try:
        resolved = resolve_identity_path(raw_path, strict=True)
        relative = resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise PlatformPathError("path escapes configured root or is unavailable") from exc

    if reject_internal_links:
        # Containment is resolved-vs-resolved, while link inspection follows the
        # caller's lexical spelling below the root.  This allows a root alias
        # (Windows 8.3, macOS /var, or an explicit junction) but still detects a
        # symlink/reparse component introduced inside that root.
        try:
            lexical_relative = raw_path.absolute().relative_to(raw_root.absolute())
        except ValueError as exc:
            raise PlatformPathError("path spelling is not contained by the configured root") from exc
        cursor = raw_root
        for part in lexical_relative.parts:
            cursor = cursor / part
            try:
                inspected = os.lstat(filesystem_path(cursor))
            except OSError as exc:
                raise PlatformPathError("path component cannot be inspected") from exc
            if _is_link_or_reparse(cursor, inspected):
                raise PlatformPathError("symbolic link or reparse point rejected")

    if require_regular:
        try:
            mode = os.stat(filesystem_path(resolved), follow_symlinks=False).st_mode
        except OSError as exc:
            raise PlatformPathError("file cannot be inspected") from exc
        if not stat.S_ISREG(mode):
            raise PlatformPathError("expected regular file")
    return resolved


def strip_windows_extended_prefix(value: str | os.PathLike[str]) -> str:
    r"""Remove Windows transport-only extended-length prefixes.

    Canonical identity never contains extended-length prefixes. Those spellings
    are introduced only at the final subprocess boundary.
    """

    text = os.fspath(value)
    if text[:8].casefold() == "\\\\?\\unc\\":
        return "\\\\" + text[8:]
    if text.startswith("\\\\?\\"):
        return text[4:]
    return text


def normalize_identity_text(value: str | os.PathLike[str]) -> str:
    """Return a comparison-only normalized spelling for one filesystem identity."""

    text = strip_windows_extended_prefix(value)
    if re.match(r"^[A-Za-z]:[\\/]", text) or text.startswith("\\\\"):
        return ntpath.normcase(ntpath.normpath(text.replace("/", "\\")))
    return os.path.normcase(os.path.normpath(text))


def resolve_identity_path(
    value: str | os.PathLike[str],
    *,
    base: str | os.PathLike[str] | None = None,
    strict: bool = True,
) -> Path:
    """Resolve a canonical filesystem identity through one cross-platform owner."""

    path = Path(strip_windows_extended_prefix(value)).expanduser()
    if not path.is_absolute():
        path = Path(base) / path if base is not None else Path.cwd() / path
    try:
        resolved = os.path.realpath(filesystem_path(path), strict=strict)
        return Path(strip_windows_extended_prefix(resolved))
    except OSError as exc:
        raise PlatformPathError("path identity is unavailable") from exc


def _temporary_filesystem_path(value: str | os.PathLike[str]) -> str | Path:
    """Address an owner-created temporary tree at the final filesystem boundary."""

    path = Path(value).absolute()
    if os.name == "nt":
        return windows_extended_path(path)
    return path


def _remove_temporary_tree(root: Path) -> None:
    """Remove an owner-created temporary tree after read-only installation work.

    Promin deliberately makes copied standards and provider receipts read-only.
    When they live inside a ``TemporaryDirectory`` (for example, doctor’s real
    sandbox init), Windows cleanup must restore the directory attributes before
    ``tempfile`` removes the lexical alias it originally created.  This helper
    only operates on the temporary tree owned by this module and never follows
    links while traversing it.
    """

    native_root = _temporary_filesystem_path(root)
    if not os.path.lexists(native_root):
        return
    for directory, directories, filenames in os.walk(
        native_root, topdown=False, followlinks=False
    ):
        for name in filenames:
            path = os.path.join(directory, name)
            if not os.path.islink(path):
                os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
            os.unlink(path)
        for name in directories:
            path = os.path.join(directory, name)
            if os.path.islink(path):
                os.unlink(path)
                continue
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
            os.rmdir(path)
    os.chmod(native_root, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
    os.rmdir(native_root)


@contextmanager
def resolved_temporary_directory(
    *,
    prefix: str = "tmp",
    suffix: str | None = None,
    dir: str | os.PathLike[str] | None = None,
) -> Iterator[Path]:
    """Create a temporary directory and expose one canonical filesystem identity.

    ``tempfile`` may return a lexical alias (Windows 8.3, a junction-backed
    cache root, or macOS ``/var``). Any path later used as a containment
    boundary must be resolved before children are created or compared. This
    helper is the sole runtime owner for temporary directory identities.
    """

    directory = None if dir is None else filesystem_path(dir)
    temporary_directory = tempfile.TemporaryDirectory(
        prefix=prefix, suffix=suffix, dir=directory
    )
    temporary = resolve_identity_path(temporary_directory.name, strict=True)
    try:
        yield temporary
    finally:
        _remove_temporary_tree(temporary)
        temporary_directory.cleanup()


def windows_extended_path(value: str | os.PathLike[str]) -> str:
    """Return a normalized Windows extended-length spelling.

    The function is pure and therefore testable on non-Windows hosts. Duplicate
    separators are collapsed before adding the extended prefix.
    """

    text = str(value).replace("/", "\\")
    if text.startswith("\\\\?\\"):
        return text
    if text.startswith("\\\\"):
        tail = re.sub(r"\\+", r"\\", text[2:]).strip("\\")
        return "\\\\?\\UNC\\" + tail
    normalized = re.sub(r"\\+", r"\\", ntpath.normpath(text))
    if re.match(r"^[A-Za-z]:\\", normalized):
        return "\\\\?\\" + normalized
    return normalized


def filesystem_path(value: str | os.PathLike[str]) -> str | Path:
    """Format a path only for the final host filesystem operation.

    Canonical records retain ordinary path spellings. This adapter is for
    ``open``, ``stat`` and copy calls that need Windows extended-length syntax;
    it never supplies a persisted identity or receipt path.
    """

    path = Path(strip_windows_extended_prefix(value)).expanduser()
    if os.name != "nt":
        return path
    absolute = str(path.absolute())
    if len(absolute) < 248 and not absolute.startswith("\\\\"):
        return absolute
    return windows_extended_path(absolute)


def sqlite_path(value: str | os.PathLike[str]) -> str:
    """Format an existing-parent SQLite file path for the Windows SQLite host.

    The bundled SQLite build cannot open ``\\\\?\\`` database names on this
    host.  Its parent has already been created through :func:`filesystem_path`;
    use the Win32 short spelling only for the final SQLite connection argument.
    Canonical identities and persisted records retain their ordinary spelling.
    """

    path = Path(strip_windows_extended_prefix(value)).absolute()
    if os.name != "nt":
        return str(path)
    if len(str(path)) < 248:
        return str(path)
    try:
        import ctypes

        parent = str(path.parent)
        required = ctypes.windll.kernel32.GetShortPathNameW(parent, None, 0)
        if required:
            buffer = ctypes.create_unicode_buffer(required)
            if ctypes.windll.kernel32.GetShortPathNameW(parent, buffer, required):
                return str(Path(buffer.value) / path.name)
    except (AttributeError, OSError):
        pass
    return windows_extended_path(path)


def subprocess_path(path: str | os.PathLike[str]) -> str:
    """Format an already-resolved executable/file path for process creation only."""

    absolute = str(resolve_identity_path(path, strict=True))
    if os.name != "nt":
        return absolute
    # Keep ordinary paths ordinary.  Extended syntax is reserved for paths near
    # the historical Win32 directory limit or UNC paths.
    return windows_extended_path(absolute) if len(absolute) >= 248 or absolute.startswith("\\\\") else absolute


@dataclass(frozen=True, slots=True)
class WindowsCreateOnlyRenameReservation:
    """The pinned objects used by one Windows directory publication.

    The native handles intentionally remain private.  This receipt lets a
    caller perform an authoritative source recheck only after the source and
    destination parent are pinned, without creating a second overlapping
    reservation that could self-block on a shared ancestor.
    """

    source: Path
    destination: Path
    source_volume_serial: int
    source_file_index: int
    destination_parent: Path
    destination_parent_volume_serial: int
    destination_parent_file_index: int


@dataclass(frozen=True, slots=True)
class _WindowsHeldObjectIdentity:
    """Stable identity returned by ``GetFileInformationByHandle``."""

    volume_serial: int
    file_index: int
    file_attributes: int


@dataclass(frozen=True, slots=True)
class _WindowsLexicalDirectoryIdentity:
    """The no-follow lexical observation paired with a held object handle."""

    device: int
    inode: int
    mode: int
    file_attributes: int


_WINDOWS_DELETE = 0x00010000
_WINDOWS_FILE_READ_ATTRIBUTES = 0x00000080
_WINDOWS_FILE_LIST_DIRECTORY = 0x00000001
_WINDOWS_FILE_ADD_FILE = 0x00000002
_WINDOWS_FILE_ADD_SUBDIRECTORY = 0x00000004
_WINDOWS_FILE_SHARE_READ = 0x00000001
_WINDOWS_FILE_SHARE_WRITE = 0x00000002
_WINDOWS_FILE_SHARE_DELETE = 0x00000004
_WINDOWS_OPEN_EXISTING = 3
_WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WINDOWS_REPARSE_POINT_ATTRIBUTE = 0x00000400
_WINDOWS_NT_FILE_RENAME_INFORMATION_CLASS = 10


def _windows_create_only_lexical_path(value: str | os.PathLike[str]) -> Path:
    """Validate one caller path before a native create-only operation."""

    try:
        text = os.fspath(value)
    except TypeError as exc:
        raise PlatformPathError("create-only publication path is not path-like") from exc
    if not isinstance(text, str) or not text or "\x00" in text:
        raise PlatformPathError("create-only publication path is empty or invalid")
    normalized_text = text.replace("/", "\\")
    folded = normalized_text.casefold()
    if folded.startswith(("\\\\?\\", "\\\\.\\", "\\??\\", "\\\\??\\")):
        raise PlatformPathError(
            "caller-supplied Windows device or extended namespace is forbidden"
        )
    if not ntpath.isabs(normalized_text):
        raise PlatformPathError("create-only publication path must be absolute")
    drive, tail = ntpath.splitdrive(normalized_text)
    if not drive or not tail.startswith("\\"):
        raise PlatformPathError(
            "create-only publication path must be drive-rooted or a complete UNC path"
        )
    if any(part == ".." for part in tail.split("\\")):
        raise PlatformPathError("create-only publication path contains parent traversal")
    return Path(ntpath.normpath(normalized_text))


def _windows_same_path(left: Path, right: Path) -> bool:
    return ntpath.normcase(ntpath.normpath(os.fspath(left))) == ntpath.normcase(
        ntpath.normpath(os.fspath(right))
    )


def _windows_path_contains(parent: Path, child: Path) -> bool:
    """Return whether *child* is lexically equal to or below *parent*."""

    parent_text = ntpath.normcase(ntpath.normpath(os.fspath(parent)))
    child_text = ntpath.normcase(ntpath.normpath(os.fspath(child)))
    try:
        common = ntpath.normcase(ntpath.commonpath((parent_text, child_text)))
    except ValueError:
        return False
    return common == parent_text


def _windows_reject_create_only_overlap(source: Path, destination: Path) -> None:
    """Reject self moves and a destination in either side of the source tree."""

    if _windows_same_path(source, destination):
        raise PlatformPathError("create-only publication source and destination must differ")
    if _windows_path_contains(source, destination) or _windows_path_contains(
        destination, source
    ):
        raise PlatformPathError(
            "create-only publication source and destination directories overlap"
        )


def _windows_validate_destination_leaf(destination: Path) -> None:
    leaf = destination.name
    if not leaf or leaf in {".", ".."} or "\\" in leaf or "/" in leaf:
        raise PlatformPathError("create-only publication destination must have one leaf")
    if leaf[-1] in {" ", "."} or any(ord(character) < 32 for character in leaf):
        raise PlatformPathError("create-only publication destination leaf is invalid")
    if any(character in '<>:"|?*' for character in leaf):
        raise PlatformPathError("create-only publication destination leaf is invalid")
    stem = leaf.split(".", 1)[0].upper()
    if stem in {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"} or (
        len(stem) == 4 and stem[:3] in {"COM", "LPT"} and stem[3] in "123456789"
    ):
        raise PlatformPathError("create-only publication destination leaf is reserved")


def _windows_lstat_real_directory(
    path: Path, *, label: str
) -> _WindowsLexicalDirectoryIdentity:
    """Inspect a literal directory without admitting a reparse entry."""

    try:
        inspected = os.lstat(filesystem_path(path))
    except OSError as exc:
        raise PlatformPathError(
            f"create-only publication {label} cannot be inspected: {path}"
        ) from exc
    if _is_link_or_reparse(path, inspected) or not stat.S_ISDIR(inspected.st_mode):
        raise PlatformPathError(
            f"create-only publication {label} must be a non-reparse directory"
        )
    return _WindowsLexicalDirectoryIdentity(
        device=int(inspected.st_dev),
        inode=int(inspected.st_ino),
        mode=int(inspected.st_mode),
        file_attributes=int(getattr(inspected, "st_file_attributes", 0)),
    )


def _windows_same_lexical_directory(
    left: _WindowsLexicalDirectoryIdentity,
    right: _WindowsLexicalDirectoryIdentity,
) -> bool:
    return (
        left.device == right.device
        and left.inode == right.inode
        and stat.S_IFMT(left.mode) == stat.S_IFMT(right.mode)
        and bool(left.file_attributes & _WINDOWS_REPARSE_POINT_ATTRIBUTE)
        == bool(right.file_attributes & _WINDOWS_REPARSE_POINT_ATTRIBUTE)
    )


def _windows_open_held_directory(
    path: Path, *, desired_access: int, share_mode: int
) -> int:
    """Open one directory literally while denying delete sharing as requested."""

    import ctypes
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
        desired_access,
        share_mode,
        None,
        _WINDOWS_OPEN_EXISTING,
        _WINDOWS_FILE_FLAG_BACKUP_SEMANTICS | _WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    handle_value = handle if isinstance(handle, int) else getattr(handle, "value", None)
    if handle_value in {None, invalid_handle}:
        raise ctypes.WinError(ctypes.get_last_error())
    return int(handle_value)


def _windows_close_held_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    if not close_handle(wintypes.HANDLE(handle)):
        raise ctypes.WinError(ctypes.get_last_error())


def _windows_held_object_identity(handle: int) -> _WindowsHeldObjectIdentity:
    import ctypes
    from ctypes import wintypes

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = (
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    )
    get_information.restype = wintypes.BOOL
    information = _ByHandleFileInformation()
    if not get_information(wintypes.HANDLE(handle), ctypes.byref(information)):
        raise ctypes.WinError(ctypes.get_last_error())
    return _WindowsHeldObjectIdentity(
        volume_serial=int(information.dwVolumeSerialNumber),
        file_index=(int(information.nFileIndexHigh) << 32)
        | int(information.nFileIndexLow),
        file_attributes=int(information.dwFileAttributes),
    )


def _windows_probe_directory_identity(path: Path) -> _WindowsHeldObjectIdentity:
    """Compare a lexical name with a held handle without taking a new lock."""

    probe = _windows_open_held_directory(
        path,
        desired_access=_WINDOWS_FILE_READ_ATTRIBUTES,
        share_mode=(
            _WINDOWS_FILE_SHARE_READ
            | _WINDOWS_FILE_SHARE_WRITE
            | _WINDOWS_FILE_SHARE_DELETE
        ),
    )
    try:
        return _windows_held_object_identity(probe)
    finally:
        _windows_close_held_handle(probe)


def _windows_revalidate_held_directory(
    path: Path,
    expected: _WindowsHeldObjectIdentity,
    *,
    label: str,
) -> None:
    """Fail closed if the lexical directory no longer names the held object."""

    _windows_lstat_real_directory(path, label=label)
    observed = _windows_probe_directory_identity(path)
    if observed != expected or bool(observed.file_attributes & _WINDOWS_REPARSE_POINT_ATTRIBUTE):
        raise PlatformPathError(
            f"create-only publication {label} identity changed during reservation"
        )


def _windows_assert_destination_absent(destination: Path) -> None:
    try:
        os.lstat(filesystem_path(destination))
    except FileNotFoundError:
        return
    except NotADirectoryError as exc:
        raise PlatformPathError(
            "create-only publication destination parent is not a directory"
        ) from exc
    except OSError as exc:
        raise PlatformPathError(
            f"create-only publication destination cannot be inspected: {destination}"
        ) from exc
    raise FileExistsError(f"create-only publication destination exists: {destination}")


def _windows_rename_held_directory_create_only(
    source_handle: int,
    destination: Path,
    destination_parent_handle: int,
) -> None:
    """Bind a held source handle to a held parent with ReplaceIfExists=false."""

    import ctypes
    from ctypes import wintypes

    _windows_validate_destination_leaf(destination)

    class _FileRenameInformation(ctypes.Structure):
        _fields_ = (
            ("ReplaceIfExists", ctypes.c_ubyte),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", wintypes.WCHAR * 1),
        )

    class _IoStatusBlock(ctypes.Structure):
        _fields_ = (
            ("StatusOrPointer", ctypes.c_void_p),
            ("Information", ctypes.c_size_t),
        )

    destination_name = destination.name
    encoded_name = destination_name.encode("utf-16-le")
    filename_offset = _FileRenameInformation.FileName.offset
    buffer = ctypes.create_string_buffer(
        max(
            ctypes.sizeof(_FileRenameInformation),
            filename_offset + len(encoded_name),
        )
    )
    information = _FileRenameInformation.from_buffer(buffer)
    information.ReplaceIfExists = 0
    information.RootDirectory = wintypes.HANDLE(destination_parent_handle)
    information.FileNameLength = len(encoded_name)
    ctypes.memmove(
        ctypes.addressof(buffer) + filename_offset,
        encoded_name,
        len(encoded_name),
    )

    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    set_information = ntdll.NtSetInformationFile
    set_information.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_IoStatusBlock),
        wintypes.LPVOID,
        wintypes.ULONG,
        ctypes.c_int,
    )
    set_information.restype = wintypes.LONG
    io_status = _IoStatusBlock()
    status = int(
        set_information(
            wintypes.HANDLE(source_handle),
            ctypes.byref(io_status),
            ctypes.byref(buffer),
            len(buffer),
            _WINDOWS_NT_FILE_RENAME_INFORMATION_CLASS,
        )
    )
    if status >= 0:
        return

    to_dos_error = ntdll.RtlNtStatusToDosError
    to_dos_error.argtypes = (wintypes.LONG,)
    to_dos_error.restype = wintypes.ULONG
    error = ctypes.WinError(int(to_dos_error(status)))
    if getattr(error, "winerror", None) in {80, 183}:
        raise FileExistsError(
            f"create-only publication destination exists: {destination}"
        ) from error
    raise error


def physical_rename_directory_create_only(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    *,
    after_reservation: Callable[[WindowsCreateOnlyRenameReservation], None] | None = None,
) -> Path:
    """Publish one real Windows directory through a held create-only rename.

    The source and destination-parent handles deny delete sharing.  They are
    both held before ``after_reservation`` runs, allowing an authority layer to
    re-read its source identity in the otherwise unavoidable time-of-check to
    time-of-use interval.  Any callback error releases both handles and the
    native rename is not attempted.  The helper deliberately has no POSIX
    emulation: Python cannot offer the same directory no-replace guarantee.
    """

    if os.name != "nt":
        raise PlatformPathError(
            "create-only directory publication currently requires Windows"
        )
    if after_reservation is not None and not callable(after_reservation):
        raise PlatformPathError("after_reservation must be callable")

    lexical_source = _windows_create_only_lexical_path(source)
    lexical_destination = _windows_create_only_lexical_path(destination)
    _windows_reject_create_only_overlap(lexical_source, lexical_destination)
    _windows_validate_destination_leaf(lexical_destination)
    if _windows_same_path(lexical_source, Path(lexical_source.anchor)):
        raise PlatformPathError("create-only publication cannot move a volume anchor")

    source_before = _windows_lstat_real_directory(lexical_source, label="source")
    destination_parent_before = _windows_lstat_real_directory(
        lexical_destination.parent, label="destination parent"
    )
    _windows_assert_destination_absent(lexical_destination)

    source_handle: int | None = None
    destination_parent_handle: int | None = None
    body_failed = False
    try:
        source_handle = _windows_open_held_directory(
            lexical_source,
            desired_access=(
                _WINDOWS_DELETE
                | _WINDOWS_FILE_READ_ATTRIBUTES
                | _WINDOWS_FILE_LIST_DIRECTORY
            ),
            share_mode=_WINDOWS_FILE_SHARE_READ,
        )
        source_identity = _windows_held_object_identity(source_handle)
        if bool(source_identity.file_attributes & _WINDOWS_REPARSE_POINT_ATTRIBUTE):
            raise PlatformPathError("create-only publication source became a reparse entry")
        if not _windows_same_lexical_directory(
            source_before,
            _windows_lstat_real_directory(lexical_source, label="source"),
        ):
            raise PlatformPathError("create-only publication source changed while opening")

        destination_parent_handle = _windows_open_held_directory(
            lexical_destination.parent,
            desired_access=(
                _WINDOWS_FILE_READ_ATTRIBUTES
                | _WINDOWS_FILE_ADD_FILE
                | _WINDOWS_FILE_ADD_SUBDIRECTORY
            ),
            # The rename itself modifies this parent.  Sharing write remains
            # necessary for that native operation, while denying delete still
            # pins the parent name and prevents a replacement during the
            # post-reservation authority recheck.
            share_mode=_WINDOWS_FILE_SHARE_READ | _WINDOWS_FILE_SHARE_WRITE,
        )
        destination_parent_identity = _windows_held_object_identity(
            destination_parent_handle
        )
        if bool(
            destination_parent_identity.file_attributes
            & _WINDOWS_REPARSE_POINT_ATTRIBUTE
        ):
            raise PlatformPathError(
                "create-only publication destination parent became a reparse entry"
            )
        if not _windows_same_lexical_directory(
            destination_parent_before,
            _windows_lstat_real_directory(
                lexical_destination.parent, label="destination parent"
            ),
        ):
            raise PlatformPathError(
                "create-only publication destination parent changed while opening"
            )
        if source_identity.volume_serial != destination_parent_identity.volume_serial:
            raise PlatformPathError(
                "create-only directory publication requires one Windows volume"
            )

        _windows_revalidate_held_directory(
            lexical_source, source_identity, label="source"
        )
        _windows_revalidate_held_directory(
            lexical_destination.parent,
            destination_parent_identity,
            label="destination parent",
        )
        _windows_assert_destination_absent(lexical_destination)
        reservation = WindowsCreateOnlyRenameReservation(
            source=lexical_source,
            destination=lexical_destination,
            source_volume_serial=source_identity.volume_serial,
            source_file_index=source_identity.file_index,
            destination_parent=lexical_destination.parent,
            destination_parent_volume_serial=destination_parent_identity.volume_serial,
            destination_parent_file_index=destination_parent_identity.file_index,
        )
        if after_reservation is not None:
            after_reservation(reservation)

        # A recheck callback may take enough time for a hostile process to
        # change a lexical name or create the requested destination.  Rebind
        # both names to their held objects before the irreversible operation.
        _windows_revalidate_held_directory(
            lexical_source, source_identity, label="source"
        )
        _windows_revalidate_held_directory(
            lexical_destination.parent,
            destination_parent_identity,
            label="destination parent",
        )
        _windows_assert_destination_absent(lexical_destination)
        _windows_rename_held_directory_create_only(
            source_handle,
            lexical_destination,
            destination_parent_handle,
        )

        source_after = _windows_held_object_identity(source_handle)
        if source_after != source_identity:
            raise PlatformPathError(
                "create-only publication source handle identity changed after rename"
            )
        _windows_lstat_real_directory(lexical_destination, label="destination")
        if _windows_probe_directory_identity(lexical_destination) != source_identity:
            raise PlatformPathError(
                "create-only publication destination differs from held source"
            )
        try:
            os.lstat(filesystem_path(lexical_source))
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise PlatformPathError(
                "create-only publication source cannot be verified after rename"
            ) from exc
        else:
            raise PlatformPathError(
                "create-only publication source lexical path remains after rename"
            )
        _windows_revalidate_held_directory(
            lexical_destination.parent,
            destination_parent_identity,
            label="destination parent",
        )
        return lexical_destination
    except BaseException:
        body_failed = True
        raise
    finally:
        close_error: BaseException | None = None
        for handle in (destination_parent_handle, source_handle):
            if handle is None:
                continue
            try:
                _windows_close_held_handle(handle)
            except BaseException as exc:
                if close_error is None:
                    close_error = exc
        if close_error is not None and not body_failed:
            raise close_error
