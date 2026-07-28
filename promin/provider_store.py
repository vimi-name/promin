"""Shared content-addressed provider blob store.

The store verifies immutable provider bytes once per host. Project-local receipts
are materialized with copy-on-write cloning when the filesystem supports it, and
with a normal copy otherwise. Hard links are deliberately forbidden: a project
receipt is an adversarially testable surface and must never be able to corrupt the
shared blob or another project's receipt.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import time
from pathlib import Path

from .platform_paths import filesystem_path


class ProviderStoreError(RuntimeError):
    pass


def _native_os_path(path: Path) -> str | Path:
    """Format only the final Windows filesystem operation for long paths.

    Provider identities remain ordinary resolved ``Path`` values.  Windows'
    extended spelling is transport syntax for the API call, never a persisted
    identity or receipt path.
    """

    if os.name != "nt":
        return path
    return filesystem_path(path)


def provider_store_root() -> Path:
    override = os.environ.get("PROMIN_PROVIDER_STORE")
    if override:
        base = Path(override).expanduser()
        selected = base
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
        selected = base / "promin" / "provider-store-v1"
    elif _platform() == "darwin":
        selected = Path.home() / "Library" / "Caches" / "promin" / "provider-store-v1"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or (Path.home() / ".cache"))
        selected = base / "promin" / "provider-store-v1"
    # Every branch returns one physical identity.  This collapses Windows 8.3,
    # MSIX/container redirects, junctions and the macOS /var -> /private/var alias.
    return selected.expanduser().resolve(strict=False)


def _platform() -> str:
    import platform

    return platform.system().casefold()


def _blob_path(digest: str) -> Path:
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ProviderStoreError("invalid sha256 digest")
    return provider_store_root() / digest[:2] / digest


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with open(_native_os_path(path), "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_source(source: Path, expected_digest: str) -> int:
    mode = os.stat(_native_os_path(source), follow_symlinks=False).st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise ProviderStoreError("provider source is not a regular file")
    if _digest(source) != expected_digest:
        raise ProviderStoreError("provider source digest changed")
    return mode


def _write_blob(source: Path, target: Path, expected_digest: str, source_mode: int) -> None:
    temporary = target.with_name(f".{target.name}.{os.getpid()}.{time.time_ns()}.tmp")
    try:
        with source.open("rb") as reader, temporary.open("xb") as writer:
            digest = hashlib.sha256()
            for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                digest.update(chunk)
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
        if digest.hexdigest() != expected_digest:
            raise ProviderStoreError("provider changed while creating shared blob")
        # Shared blobs are immutable data. Execution bits are preserved; write
        # bits are removed so accidental project tooling cannot edit the store.
        immutable_mode = stat.S_IMODE(source_mode) & ~0o222
        os.chmod(temporary, immutable_mode)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def ensure_blob(source: Path, expected_digest: str) -> Path:
    source = source.resolve(strict=True)
    source_mode = _verify_source(source, expected_digest)
    target = _blob_path(expected_digest)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_file() and not target.is_symlink():
        if _digest(target) == expected_digest:
            return target
        quarantine = target.with_name(f".{target.name}.corrupt.{time.time_ns()}")
        os.replace(target, quarantine)
        try:
            _write_blob(source, target, expected_digest, source_mode)
        finally:
            quarantine.unlink(missing_ok=True)
    elif target.exists():
        raise ProviderStoreError("shared provider blob path has the wrong type")
    else:
        _write_blob(source, target, expected_digest, source_mode)
    if _digest(target) != expected_digest:
        raise ProviderStoreError("shared provider blob verification failed")
    return target


def _try_linux_reflink(source: Path, destination: Path) -> bool:
    if _platform() != "linux":
        return False
    try:
        import fcntl

        ficlone = 0x40049409
        with source.open("rb") as reader, destination.open("xb") as writer:
            fcntl.ioctl(writer.fileno(), ficlone, reader.fileno())
            writer.flush()
            os.fsync(writer.fileno())
        return True
    except (ImportError, OSError):
        destination.unlink(missing_ok=True)
        return False


def materialize_from_store(source: Path, destination: Path, expected_digest: str) -> str:
    """Materialize independent project-local bytes.

    Returns ``reflink`` when a copy-on-write clone was available, otherwise
    ``copy``. The shared blob is never hard-linked into a project.
    """

    blob = ensure_blob(source, expected_digest)
    os.makedirs(_native_os_path(destination.parent), exist_ok=True)
    try:
        os.unlink(_native_os_path(destination))
    except FileNotFoundError:
        pass
    mode = "reflink" if _try_linux_reflink(blob, destination) else "copy"
    if mode == "copy":
        shutil.copy2(_native_os_path(blob), _native_os_path(destination))
    os.chmod(
        _native_os_path(destination),
        stat.S_IMODE(os.stat(_native_os_path(source), follow_symlinks=False).st_mode),
    )
    if _digest(destination) != expected_digest:
        try:
            os.unlink(_native_os_path(destination))
        except FileNotFoundError:
            pass
        raise ProviderStoreError("materialized provider receipt digest mismatch")
    return mode


def provider_store_stats() -> dict[str, int]:
    root = provider_store_root()
    files = [path for path in root.rglob("*") if path.is_file() and not path.is_symlink()] if root.is_dir() else []
    return {
        "blob_count": len(files),
        "logical_bytes": sum(path.stat(follow_symlinks=False).st_size for path in files),
    }
