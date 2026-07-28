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
from pathlib import Path


class PlatformPathError(ValueError):
    pass


def _is_link_or_reparse(path: Path, inspected: os.stat_result | None = None) -> bool:
    value = inspected if inspected is not None else os.lstat(filesystem_path(path))
    if stat.S_ISLNK(value.st_mode) or os.path.islink(filesystem_path(path)):
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
        resolved_root = resolve_identity_path(raw_root, strict=True)
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


def subprocess_path(path: str | os.PathLike[str]) -> str:
    """Format an already-resolved executable/file path for process creation only."""

    absolute = str(resolve_identity_path(path, strict=True))
    if os.name != "nt":
        return absolute
    # Keep ordinary paths ordinary.  Extended syntax is reserved for paths near
    # the historical Win32 directory limit or UNC paths.
    return windows_extended_path(absolute) if len(absolute) >= 248 or absolute.startswith("\\\\") else absolute
