"""Byte-authoritative target receipts bound to canonical provider evidence.

``input_identity`` owns source selection and provider input identity.
``provider_envelope`` owns physical seals, driver/module envelopes, exact
``FullScan``/``Reuse`` coverage and lifecycle timestamp intervals.  This module
does not recreate any of those schemas.  It reads selected source bytes,
creates a target-scoped Merkle closure, then binds canonical records from the
two owner modules to that closure and to a reuse lineage.

Metadata is used only to establish a safe path boundary and to detect a read
race.  Every included source file is SHA-256 hashed on every closure capture;
there is no metadata-only cache authority in this layer.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import time
import unicodedata
from bisect import bisect_left
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from threading import RLock
from typing import Any, Iterable, Sequence

from .canonical import canonical_bytes, digest_value
from .gate_admission import ReceiptInvalidationClass
from .input_identity import (
    ProviderInputIdentity,
    SourceEntry,
    SourceSelection,
)
from .platform_paths import filesystem_path, resolve_contained_path
from .provider_envelope import (
    ConservativeTimestampInterval,
    CoverageUnion,
    ProviderEnvelope,
    ProviderEnvelopeError,
    ScanMode,
    canonical_provider_envelope_bytes,
    verify_envelope_physical_artifact,
)


class ProviderReceiptError(ValueError):
    """Raised when a target receipt cannot be proven from exact bytes."""


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$")
_LEAF_DOMAIN = b"promin.target-merkle-receipt.leaf.v1\0"
_NODE_DOMAIN = b"promin.target-merkle-receipt.node.v1\0"
_EMPTY_DOMAIN = b"promin.target-merkle-receipt.empty.v1\0"
_MERKLE_ALGORITHM = "sha256-domain-separated-merkle-v1"
_CLOSURE_SCHEMA = "promin.target-merkle-closure.v1"
_RECEIPT_SCHEMA = "promin.target-merkle-receipt.v2"
_CAPTURE_SCHEMA = "promin.target-merkle-capture.v1"
_BENCHMARK_SCHEMA = "promin.target-merkle-benchmark.v1"
_CACHE_ENTRY_OVERHEAD_BYTES = 256


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise ProviderReceiptError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ProviderReceiptError(f"{field} has an invalid identifier")
    if unicodedata.normalize("NFC", value) != value:
        raise ProviderReceiptError(f"{field} must be NFC-normalized")
    return value


def _safe_relative_path(value: str | Path, field: str) -> PurePosixPath:
    raw = value.as_posix() if isinstance(value, Path) else value
    if not isinstance(raw, str) or not raw:
        raise ProviderReceiptError(f"{field} must be non-empty portable relative text")
    if (
        raw.startswith(("/", "\\"))
        or "\\" in raw
        or ":" in raw
        or "\x00" in raw
        or unicodedata.normalize("NFC", raw) != raw
    ):
        raise ProviderReceiptError(f"{field} must be an NFC-normalized POSIX relative path")
    parts = raw.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise ProviderReceiptError(f"{field} has an unsafe path segment")
    return PurePosixPath(raw)


def _is_link_or_reparse(path: Path, state: os.stat_result | None = None) -> bool:
    observed = state if state is not None else os.lstat(filesystem_path(path))
    if stat.S_ISLNK(observed.st_mode):
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    attributes = getattr(observed, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400))


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _canonical_paths(values: Iterable[str | Path], field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if isinstance(values, (str, Path)):
        raise ProviderReceiptError(f"{field} must be an iterable of paths")
    normalized = tuple(_safe_relative_path(value, field).as_posix() for value in values)
    if not normalized and not allow_empty:
        raise ProviderReceiptError(f"{field} must not be empty")
    if len(set(normalized)) != len(normalized):
        raise ProviderReceiptError(f"{field} contains duplicate paths")
    folded = [value.casefold() for value in normalized]
    if len(set(folded)) != len(folded):
        raise ProviderReceiptError(f"{field} contains portable case-colliding paths")
    return tuple(sorted(normalized, key=lambda value: value.encode("utf-8")))


def _assert_nonoverlapping_prefixes(paths: Sequence[str], field: str) -> None:
    seen: set[str] = set()
    for current in paths:
        prefix = ""
        for component in current.split("/")[:-1]:
            prefix = component if not prefix else prefix + "/" + component
            if prefix in seen:
                raise ProviderReceiptError(f"{field} contains overlapping paths")
        seen.add(current)


def _transient_applies_to_selection(selected: Sequence[str], transient: Sequence[str]) -> None:
    """Prove every declared transient has a selected descendant in O(t log n)."""

    # ``_canonical_paths`` orders normalized UTF-8 paths.  UTF-8 preserves
    # Unicode scalar ordering, so the canonical selected tuple is directly
    # searchable with ``bisect`` without materializing a second file list.
    for prefix in transient:
        position = bisect_left(selected, prefix)
        if position < len(selected) and selected[position] == prefix:
            continue
        descendant_prefix = prefix + "/"
        position = bisect_left(selected, descendant_prefix)
        if position == len(selected) or not selected[position].startswith(descendant_prefix):
            raise ProviderReceiptError("explicit transient path is outside the selected target closure")


def _path_is_under_transient(path: str, transient_paths: frozenset[str]) -> bool:
    prefix = ""
    for component in path.split("/"):
        prefix = component if not prefix else prefix + "/" + component
        if prefix in transient_paths:
            return True
    return False


def _excluded_selected_paths(selected: Sequence[str], transient: Sequence[str]) -> tuple[str, ...]:
    if not transient:
        return ()
    roots = frozenset(transient)
    return tuple(path for path in selected if _path_is_under_transient(path, roots))


def _selected_paths(selection: SourceSelection) -> tuple[str, ...]:
    if not isinstance(selection, SourceSelection):
        raise ProviderReceiptError("target closure requires a typed source selection")
    if not isinstance(selection.entries, tuple):
        raise ProviderReceiptError("source selection entries must be an exact tuple")
    selected = _canonical_paths((entry.path for entry in selection.entries), "source selection entry")
    if tuple(entry.path for entry in selection.entries) != selected:
        raise ProviderReceiptError("source selection entries are not in canonical order")
    allowed = _canonical_paths(selection.allowed_roots, "allowed source root")
    forbidden = _canonical_paths(selection.forbidden_roots, "forbidden source root", allow_empty=True)
    if set(allowed) & set(forbidden):
        raise ProviderReceiptError("source selection has an overlapping allowed and forbidden root")
    for path in selected:
        if not any(_under(path, root) for root in allowed):
            raise ProviderReceiptError(f"selected source path is outside allowed roots: {path}")
        if any(_under(path, root) for root in forbidden):
            raise ProviderReceiptError(f"selected source path is below a forbidden root: {path}")
    return selected


def _assert_selection_root(selection: SourceSelection) -> Path:
    root = Path(selection.root).absolute()
    try:
        state = os.lstat(filesystem_path(root))
    except OSError as exc:
        raise ProviderReceiptError(f"source selection root is unavailable: {root}: {exc}") from exc
    if _is_link_or_reparse(root, state) or not stat.S_ISDIR(state.st_mode):
        raise ProviderReceiptError("source selection root must remain a real directory")
    if (
        int(state.st_dev) != selection.root_device
        or int(state.st_ino) != selection.root_inode
        or stat.S_IMODE(state.st_mode) != selection.root_mode
    ):
        raise ProviderReceiptError("source selection root changed after containment preflight")
    return root


def _stat_witness(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Return a read-race witness only; it never authorizes content reuse."""

    return (
        int(value.st_mode),
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def _assert_selection_entry_matches(entry: SourceEntry, state: os.stat_result, *, relative: str) -> None:
    """Bind a one-pass byte read to the already-authorized source selection.

    The metadata comparison rejects selection drift, but it is deliberately
    not a cache key.  The caller still hashes the exact opened bytes even when
    all of these values match (the Windows restored-mtime attack case).
    """

    if not isinstance(entry, SourceEntry):
        raise ProviderReceiptError("source selection contains an untyped entry")
    observed = (
        stat.S_IMODE(state.st_mode),
        int(state.st_size),
        int(state.st_dev),
        int(state.st_ino),
        int(state.st_mtime_ns),
        int(state.st_ctime_ns),
    )
    expected = (
        entry.mode,
        entry.size_bytes,
        entry.device,
        entry.inode,
        entry.modified_ns,
        entry.changed_ns,
    )
    if observed != expected:
        raise ProviderReceiptError(
            f"source selection changed after containment preflight: {relative}"
        )


def _stable_file_digest(
    path: Path,
    *,
    root: Path,
    relative: str,
    expected_entry: SourceEntry,
) -> tuple[str, int]:
    """Hash one selected file while rejecting path or object replacement races."""

    try:
        before = os.lstat(filesystem_path(path))
        resolve_contained_path(
            path,
            root=root,
            require_regular=True,
            reject_internal_links=True,
        )
    except Exception as exc:
        raise ProviderReceiptError(f"receipt input cannot be resolved before hashing: {relative}") from exc
    if _is_link_or_reparse(path, before) or not stat.S_ISREG(before.st_mode):
        raise ProviderReceiptError(f"receipt input is not a real regular file: {relative}")
    _assert_selection_entry_matches(expected_entry, before, relative=relative)

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    descriptor: int | None = None
    try:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(filesystem_path(path), flags | nofollow)
        except OSError:
            # Windows CRTs may expose O_NOFOLLOW without accepting it.  The
            # lstat/fstat/lstat + resolved-boundary checks remain fail-closed.
            descriptor = os.open(filesystem_path(path), flags)
        opened = os.fstat(descriptor)
        # Windows' CRT can report a synthetic ``st_ctime_ns`` from ``fstat``
        # that differs from ``lstat`` even for the same unopened file.  The
        # path witnesses before/after retain all six fields; this descriptor
        # comparison is deliberately limited to stable object identity/size.
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_mode, opened.st_dev, opened.st_ino, opened.st_size)
            != (before.st_mode, before.st_dev, before.st_ino, before.st_size)
        ):
            raise ProviderReceiptError(f"receipt input changed before hashing: {relative}")
        digest = hashlib.sha256()
        byte_count = 0
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            descriptor = None
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
                byte_count += len(block)
    except ProviderReceiptError:
        raise
    except OSError as exc:
        raise ProviderReceiptError(f"receipt input cannot be read: {relative}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)

    try:
        resolve_contained_path(
            path,
            root=root,
            require_regular=True,
            reject_internal_links=True,
        )
        after = os.lstat(filesystem_path(path))
    except Exception as exc:
        raise ProviderReceiptError(f"receipt input escaped or disappeared after hashing: {relative}") from exc
    if (
        _is_link_or_reparse(path, after)
        or not stat.S_ISREG(after.st_mode)
        or _stat_witness(before) != _stat_witness(after)
        or byte_count != int(after.st_size)
    ):
        raise ProviderReceiptError(f"receipt input changed during hashing: {relative}")
    return digest.hexdigest(), byte_count


def _domain_hash(domain: bytes, value: Any) -> str:
    payload = canonical_bytes(value)
    return hashlib.sha256(domain + len(payload).to_bytes(8, "big") + payload).hexdigest()


@dataclass(frozen=True)
class ReceiptLeaf:
    """One content-addressed selected-file leaf."""

    path: str
    sha256: str
    byte_count: int
    leaf_digest: str

    @classmethod
    def from_content(cls, path: str, sha256: str, byte_count: int) -> "ReceiptLeaf":
        normalized = _safe_relative_path(path, "receipt leaf path").as_posix()
        digest = _require_digest(sha256, "receipt leaf SHA-256")
        if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0:
            raise ProviderReceiptError("receipt leaf byte_count must be a non-negative integer")
        identity = {"path": normalized, "sha256": digest, "byte_count": byte_count}
        return cls(normalized, digest, byte_count, _domain_hash(_LEAF_DOMAIN, identity))

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "byte_count": self.byte_count,
            "leaf_digest": self.leaf_digest,
        }


def _validated_leaf(value: ReceiptLeaf) -> ReceiptLeaf:
    if not isinstance(value, ReceiptLeaf):
        raise ProviderReceiptError("Merkle closure contains an untyped receipt leaf")
    expected = ReceiptLeaf.from_content(value.path, value.sha256, value.byte_count)
    if value != expected:
        raise ProviderReceiptError("receipt leaf digest mismatch")
    return expected


@dataclass(frozen=True)
class MerkleLeafCacheLimits:
    """Explicit process-local bounds for byte-validated leaf reuse."""

    max_entries: int = 250_000
    max_bytes: int = 128 * 1024 * 1024

    def __post_init__(self) -> None:
        for field, value in (("max_entries", self.max_entries), ("max_bytes", self.max_bytes)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ProviderReceiptError(f"leaf cache {field} must be a non-negative integer")


@dataclass(frozen=True)
class MerkleLeafCacheStatistics:
    """A non-crediting view of bounded in-memory cache behavior."""

    entry_count: int
    accounted_bytes: int
    hits: int
    misses: int
    evictions: int
    uncacheable_leaves: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_type": "MerkleLeafCacheStatistics",
            "schema": "promin.merkle-leaf-cache.v1",
            "entry_count": self.entry_count,
            "accounted_bytes": self.accounted_bytes,
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "uncacheable_leaves": self.uncacheable_leaves,
            "acceptance_pass": False,
            "pass_credit": False,
        }


def _leaf_cache_cost(leaf: ReceiptLeaf) -> int:
    """Conservative bounded-accounting cost, not a host heap measurement."""

    return _CACHE_ENTRY_OVERHEAD_BYTES + len(leaf.path.encode("utf-8"))


class MerkleLeafCache:
    """LRU leaf reuse that accepts a hit only after a fresh byte SHA-256.

    This is intentionally process-local and stores no host paths.  A caller
    cannot obtain a leaf from it using metadata; :meth:`_after_byte_validation`
    receives the SHA-256 generated by the current physical read.
    """

    def __init__(self, limits: MerkleLeafCacheLimits | None = None) -> None:
        self._limits = MerkleLeafCacheLimits() if limits is None else limits
        if not isinstance(self._limits, MerkleLeafCacheLimits):
            raise ProviderReceiptError("leaf cache limits must be typed")
        self._entries: OrderedDict[tuple[str, str, int], tuple[ReceiptLeaf, int]] = OrderedDict()
        self._accounted_bytes = 0
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._uncacheable_leaves = 0
        self._lock = RLock()

    @property
    def limits(self) -> MerkleLeafCacheLimits:
        return self._limits

    def statistics(self) -> MerkleLeafCacheStatistics:
        with self._lock:
            return MerkleLeafCacheStatistics(
                entry_count=len(self._entries),
                accounted_bytes=self._accounted_bytes,
                hits=self._hits,
                misses=self._misses,
                evictions=self._evictions,
                uncacheable_leaves=self._uncacheable_leaves,
            )

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._accounted_bytes = 0

    def _after_byte_validation(
        self,
        *,
        path: str,
        sha256: str,
        byte_count: int,
    ) -> tuple[ReceiptLeaf, bool, int, bool]:
        """Reuse only a leaf that equals the digest from this capture's read."""

        fresh = ReceiptLeaf.from_content(path, sha256, byte_count)
        key = (fresh.path, fresh.sha256, fresh.byte_count)
        cost = _leaf_cache_cost(fresh)
        with self._lock:
            cached = self._entries.pop(key, None)
            if cached is not None:
                leaf, recorded_cost = cached
                if leaf != fresh or recorded_cost != cost:
                    raise ProviderReceiptError("leaf cache entry does not match fresh byte validation")
                self._entries[key] = cached
                self._hits += 1
                return leaf, True, 0, False

            self._misses += 1
            if (
                self._limits.max_entries == 0
                or cost > self._limits.max_bytes
                or self._limits.max_bytes == 0
            ):
                self._uncacheable_leaves += 1
                return fresh, False, 0, True
            local_evictions = 0
            while self._entries and (
                len(self._entries) >= self._limits.max_entries
                or self._accounted_bytes + cost > self._limits.max_bytes
            ):
                _, (_, evicted_cost) = self._entries.popitem(last=False)
                self._accounted_bytes -= evicted_cost
                self._evictions += 1
                local_evictions += 1
            if (
                len(self._entries) >= self._limits.max_entries
                or self._accounted_bytes + cost > self._limits.max_bytes
            ):
                self._uncacheable_leaves += 1
                return fresh, False, local_evictions, True
            self._entries[key] = (fresh, cost)
            self._accounted_bytes += cost
            return fresh, False, local_evictions, False


def _merkle_root_ordered(leaves: Iterable[ReceiptLeaf], *, validate: bool = True) -> str:
    """Fold canonically ordered leaves with O(log n) intermediate hashes."""

    stack: list[str | None] = []
    previous_path: str | None = None
    count = 0
    for raw_leaf in leaves:
        leaf = _validated_leaf(raw_leaf) if validate else raw_leaf
        if not isinstance(leaf, ReceiptLeaf):
            raise ProviderReceiptError("Merkle closure contains an untyped receipt leaf")
        if previous_path is not None and leaf.path <= previous_path:
            if leaf.path == previous_path:
                raise ProviderReceiptError("Merkle closure contains duplicate logical paths")
            raise ProviderReceiptError("Merkle closure leaves are not in canonical order")
        previous_path = leaf.path
        node = leaf.leaf_digest
        level = 0
        while True:
            if level == len(stack):
                stack.append(node)
                break
            left = stack[level]
            if left is None:
                stack[level] = node
                break
            node = _domain_hash(_NODE_DOMAIN, {"left": left, "right": node})
            stack[level] = None
            level += 1
        count += 1
    if count == 0:
        return hashlib.sha256(_EMPTY_DOMAIN).hexdigest()

    folded: str | None = None
    folded_level = 0
    for level, left in enumerate(stack):
        if left is None:
            continue
        if folded is None:
            folded = left
            folded_level = level
            continue
        while folded_level < level:
            folded = _domain_hash(_NODE_DOMAIN, {"left": folded, "right": folded})
            folded_level += 1
        folded = _domain_hash(_NODE_DOMAIN, {"left": left, "right": folded})
        folded_level = level + 1
    if folded is None:  # Defensive; count above proves a tree exists.
        raise ProviderReceiptError("Merkle closure fold is unavailable")
    return folded


def merkle_root(leaves: Iterable[ReceiptLeaf]) -> str:
    """Calculate one order-stable, domain-separated Merkle root."""

    ordered = sorted((_validated_leaf(item) for item in leaves), key=lambda item: item.path.encode("utf-8"))
    return _merkle_root_ordered(ordered, validate=False)


@dataclass(frozen=True)
class TargetClosure:
    """A target-scoped byte/Merkle closure bound to a source selection digest."""

    selection_digest: str
    selected_paths: tuple[str, ...]
    transient_paths: tuple[str, ...]
    excluded_paths: tuple[str, ...]
    leaves: tuple[ReceiptLeaf, ...]
    total_bytes: int
    merkle_root: str
    closure_digest: str

    @property
    def authority_identity(self) -> dict[str, Any]:
        return {
            "record_type": "TargetMerkleClosure",
            "schema": _CLOSURE_SCHEMA,
            "algorithm": _MERKLE_ALGORITHM,
            "source_selection_digest": self.selection_digest,
            "selected_paths": list(self.selected_paths),
            "explicit_transient_paths": list(self.transient_paths),
            "excluded_paths": list(self.excluded_paths),
            "leaves": [item.as_dict() for item in self.leaves],
            "file_count": len(self.leaves),
            "total_bytes": self.total_bytes,
            "merkle_root": self.merkle_root,
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            **self.authority_identity,
            "closure_digest": self.closure_digest,
            "acceptance_pass": False,
            "pass_credit": False,
        }


@dataclass(frozen=True)
class TargetClosureLimits:
    """Bound materialized receipt state while allowing a 100k-file closure."""

    max_files: int = 250_000
    max_total_bytes: int = 16 * 1024 * 1024 * 1024
    max_leaf_accounted_bytes: int = 128 * 1024 * 1024

    def __post_init__(self) -> None:
        for field, value in (
            ("max_files", self.max_files),
            ("max_total_bytes", self.max_total_bytes),
            ("max_leaf_accounted_bytes", self.max_leaf_accounted_bytes),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ProviderReceiptError(f"target closure {field} must be a positive integer")


@dataclass(frozen=True)
class TargetClosureCapture:
    """One physical traversal's bounded, non-crediting capture observations."""

    closure: TargetClosure
    physical_traversal_passes: int
    files_byte_validated: int
    bytes_byte_validated: int
    leaf_cache_hits: int
    leaf_cache_misses: int
    leaf_cache_evictions: int
    leaf_cache_uncacheable_leaves: int
    leaf_accounted_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.closure, TargetClosure):
            raise ProviderReceiptError("target closure capture requires a typed closure")
        for field, value in (
            ("physical_traversal_passes", self.physical_traversal_passes),
            ("files_byte_validated", self.files_byte_validated),
            ("bytes_byte_validated", self.bytes_byte_validated),
            ("leaf_cache_hits", self.leaf_cache_hits),
            ("leaf_cache_misses", self.leaf_cache_misses),
            ("leaf_cache_evictions", self.leaf_cache_evictions),
            ("leaf_cache_uncacheable_leaves", self.leaf_cache_uncacheable_leaves),
            ("leaf_accounted_bytes", self.leaf_accounted_bytes),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ProviderReceiptError(f"target closure capture {field} must be non-negative")
        if self.physical_traversal_passes != 1:
            raise ProviderReceiptError("target closure capture must report exactly one physical traversal")
        if self.files_byte_validated != len(self.closure.leaves):
            raise ProviderReceiptError("target closure capture file count does not match closure leaves")
        if self.bytes_byte_validated != self.closure.total_bytes:
            raise ProviderReceiptError("target closure capture byte count does not match closure")
        if self.leaf_cache_hits + self.leaf_cache_misses != self.files_byte_validated:
            raise ProviderReceiptError("target closure capture cache accounting does not match leaf count")

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_type": "TargetClosureCapture",
            "schema": _CAPTURE_SCHEMA,
            "closure_digest": self.closure.closure_digest,
            "physical_traversal_passes": self.physical_traversal_passes,
            "files_byte_validated": self.files_byte_validated,
            "bytes_byte_validated": self.bytes_byte_validated,
            "leaf_cache": {
                "hits": self.leaf_cache_hits,
                "misses": self.leaf_cache_misses,
                "evictions": self.leaf_cache_evictions,
                "uncacheable_leaves": self.leaf_cache_uncacheable_leaves,
                "accounted_leaf_bytes": self.leaf_accounted_bytes,
            },
            "acceptance_pass": False,
            "pass_credit": False,
        }


@dataclass(frozen=True)
class TargetClosureBenchmark:
    """A controlled diagnostic benchmark; it never grants performance credit."""

    samples: int
    warmup_samples: int
    file_count: int
    elapsed_seconds: tuple[float, ...]
    p95_seconds: float
    requested_budget_seconds: float | None
    within_budget: bool | None
    cache_hits: int
    cache_misses: int

    def __post_init__(self) -> None:
        if not isinstance(self.samples, int) or isinstance(self.samples, bool) or not 1 <= self.samples <= 5:
            raise ProviderReceiptError("benchmark samples must be between one and five")
        if not isinstance(self.warmup_samples, int) or isinstance(self.warmup_samples, bool) or not 0 <= self.warmup_samples <= 2:
            raise ProviderReceiptError("benchmark warmup_samples must be between zero and two")
        if not isinstance(self.file_count, int) or isinstance(self.file_count, bool) or self.file_count < 1:
            raise ProviderReceiptError("benchmark file_count must be positive")
        if len(self.elapsed_seconds) != self.samples or any(
            not isinstance(value, float) or not math.isfinite(value) or value < 0.0
            for value in self.elapsed_seconds
        ):
            raise ProviderReceiptError("benchmark elapsed_seconds are invalid")
        if (
            not isinstance(self.p95_seconds, float)
            or not math.isfinite(self.p95_seconds)
            or self.p95_seconds < 0.0
        ):
            raise ProviderReceiptError("benchmark p95_seconds is invalid")
        if self.requested_budget_seconds is None:
            if self.within_budget is not None:
                raise ProviderReceiptError("benchmark without a budget must not claim within_budget")
        elif (
            not isinstance(self.requested_budget_seconds, float)
            or not math.isfinite(self.requested_budget_seconds)
            or self.requested_budget_seconds <= 0.0
            or not isinstance(self.within_budget, bool)
        ):
            raise ProviderReceiptError("benchmark budget fields are invalid")
        for field, value in (("cache_hits", self.cache_hits), ("cache_misses", self.cache_misses)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ProviderReceiptError(f"benchmark {field} must be non-negative")

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_type": "TargetClosureBenchmark",
            "schema": _BENCHMARK_SCHEMA,
            "classification": "DIAGNOSTIC_ONLY",
            "samples": self.samples,
            "warmup_samples": self.warmup_samples,
            "file_count": self.file_count,
            "elapsed_seconds": list(self.elapsed_seconds),
            "p95_seconds": self.p95_seconds,
            "requested_budget_seconds": self.requested_budget_seconds,
            "within_budget": self.within_budget,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "performance_acceptance": False,
            "acceptance_pass": False,
            "pass_credit": False,
        }


def validate_target_closure(closure: TargetClosure) -> TargetClosure:
    """Recompute a closure's exact leaf set and content-addressed identity."""

    if not isinstance(closure, TargetClosure):
        raise ProviderReceiptError("target closure must be typed")
    selection_digest = _require_digest(closure.selection_digest, "source selection digest")
    if not isinstance(closure.selected_paths, tuple):
        raise ProviderReceiptError("target closure selected_paths must be an exact tuple")
    selected = _canonical_paths(closure.selected_paths, "target closure selected path")
    if closure.selected_paths != selected:
        raise ProviderReceiptError("target closure selected paths are not in canonical order")
    if not isinstance(closure.transient_paths, tuple):
        raise ProviderReceiptError("target closure transient_paths must be an exact tuple")
    transient = _canonical_paths(
        closure.transient_paths,
        "target closure transient path",
        allow_empty=True,
    )
    if closure.transient_paths != transient:
        raise ProviderReceiptError("target closure transient paths are not in canonical order")
    _assert_nonoverlapping_prefixes(transient, "target closure transient paths")
    _transient_applies_to_selection(selected, transient)
    excluded = _excluded_selected_paths(selected, transient)
    if closure.excluded_paths != excluded:
        raise ProviderReceiptError("target closure excluded paths do not match explicit transient paths")
    if not isinstance(closure.leaves, tuple):
        raise ProviderReceiptError("target closure leaves must be an exact tuple")
    leaves = tuple(_validated_leaf(item) for item in closure.leaves)
    if tuple(item.path for item in leaves) != tuple(sorted((item.path for item in leaves), key=lambda item: item.encode("utf-8"))):
        raise ProviderReceiptError("target closure leaves are not in canonical order")
    included = tuple(path for path in selected if path not in excluded)
    if tuple(item.path for item in leaves) != included:
        raise ProviderReceiptError("target closure leaves do not exactly cover selected non-transient paths")
    if not leaves:
        raise ProviderReceiptError("target closure must retain at least one non-transient source file")
    total_bytes = sum(item.byte_count for item in leaves)
    if closure.total_bytes != total_bytes:
        raise ProviderReceiptError("target closure byte count mismatch")
    root = _merkle_root_ordered(leaves, validate=False)
    if closure.merkle_root != root:
        raise ProviderReceiptError("target closure Merkle root mismatch")
    normalized = TargetClosure(
        selection_digest=selection_digest,
        selected_paths=selected,
        transient_paths=transient,
        excluded_paths=excluded,
        leaves=leaves,
        total_bytes=total_bytes,
        merkle_root=root,
        closure_digest="",
    )
    expected_digest = digest_value(normalized.authority_identity)
    if closure.closure_digest != expected_digest:
        raise ProviderReceiptError("target closure digest mismatch")
    return TargetClosure(
        selection_digest=selection_digest,
        selected_paths=selected,
        transient_paths=transient,
        excluded_paths=excluded,
        leaves=leaves,
        total_bytes=total_bytes,
        merkle_root=root,
        closure_digest=expected_digest,
    )


def capture_target_closure(
    selection: SourceSelection,
    *,
    transient_paths: Iterable[str | Path] = (),
    leaf_cache: MerkleLeafCache | None = None,
    limits: TargetClosureLimits | None = None,
) -> TargetClosureCapture:
    """Capture a closure in one physical source traversal.

    ``selection`` is intentionally the typed output of
    :func:`input_identity.validate_source_selection`; raw roots and path lists
    are not admitted here.  The preflight metadata is compared while each file
    is opened and byte-hashed, rather than by a separate filesystem traversal.
    A cache hit is possible only after that fresh byte hash matches a leaf.
    """

    if not isinstance(selection, SourceSelection):
        raise ProviderReceiptError("target closure requires a typed source selection")
    active_limits = TargetClosureLimits() if limits is None else limits
    if not isinstance(active_limits, TargetClosureLimits):
        raise ProviderReceiptError("target closure limits must be typed")
    if leaf_cache is not None and not isinstance(leaf_cache, MerkleLeafCache):
        raise ProviderReceiptError("target closure leaf_cache must be typed")
    selected = _selected_paths(selection)
    if len(selected) > active_limits.max_files:
        raise ProviderReceiptError("target closure exceeds its selected-file bound")
    root = _assert_selection_root(selection)
    transient = _canonical_paths(transient_paths, "explicit transient path", allow_empty=True)
    _assert_nonoverlapping_prefixes(transient, "explicit transient paths")
    _transient_applies_to_selection(selected, transient)
    excluded = _excluded_selected_paths(selected, transient)
    if len(excluded) == len(selected):
        raise ProviderReceiptError("target closure must retain at least one non-transient source file")
    transient_roots = frozenset(transient)
    leaves: list[ReceiptLeaf] = []
    total_bytes = 0
    leaf_accounted_bytes = 0
    cache_hits = 0
    cache_misses = 0
    cache_evictions = 0
    cache_uncacheable = 0
    for entry in selection.entries:
        relative = entry.path
        if _path_is_under_transient(relative, transient_roots):
            continue
        candidate = root.joinpath(*PurePosixPath(relative).parts)
        sha256, byte_count = _stable_file_digest(
            candidate,
            root=root,
            relative=relative,
            expected_entry=entry,
        )
        total_bytes += byte_count
        if total_bytes > active_limits.max_total_bytes:
            raise ProviderReceiptError("target closure exceeds its byte bound")
        if leaf_cache is None:
            leaf = ReceiptLeaf.from_content(relative, sha256, byte_count)
            cache_misses += 1
        else:
            leaf, hit, evictions, uncacheable = leaf_cache._after_byte_validation(
                path=relative,
                sha256=sha256,
                byte_count=byte_count,
            )
            cache_hits += int(hit)
            cache_misses += int(not hit)
            cache_evictions += evictions
            cache_uncacheable += int(uncacheable)
        leaf_accounted_bytes += _leaf_cache_cost(leaf)
        if leaf_accounted_bytes > active_limits.max_leaf_accounted_bytes:
            raise ProviderReceiptError("target closure exceeds its materialized leaf bound")
        leaves.append(leaf)
    _assert_selection_root(selection)
    provisional = TargetClosure(
        selection_digest=selection.selection_digest,
        selected_paths=selected,
        transient_paths=transient,
        excluded_paths=excluded,
        leaves=tuple(leaves),
        total_bytes=total_bytes,
        merkle_root=_merkle_root_ordered(leaves, validate=False),
        closure_digest="",
    )
    closure = TargetClosure(
        selection_digest=provisional.selection_digest,
        selected_paths=provisional.selected_paths,
        transient_paths=provisional.transient_paths,
        excluded_paths=provisional.excluded_paths,
        leaves=provisional.leaves,
        total_bytes=provisional.total_bytes,
        merkle_root=provisional.merkle_root,
        closure_digest=digest_value(provisional.authority_identity),
    )
    normalized = validate_target_closure(closure)
    return TargetClosureCapture(
        closure=normalized,
        physical_traversal_passes=1,
        files_byte_validated=len(normalized.leaves),
        bytes_byte_validated=normalized.total_bytes,
        leaf_cache_hits=cache_hits,
        leaf_cache_misses=cache_misses,
        leaf_cache_evictions=cache_evictions,
        leaf_cache_uncacheable_leaves=cache_uncacheable,
        leaf_accounted_bytes=leaf_accounted_bytes,
    )


def scan_target_closure(
    selection: SourceSelection,
    *,
    transient_paths: Iterable[str | Path] = (),
    leaf_cache: MerkleLeafCache | None = None,
    limits: TargetClosureLimits | None = None,
) -> TargetClosure:
    """Return the closure from one byte-validated physical capture."""

    return capture_target_closure(
        selection,
        transient_paths=transient_paths,
        leaf_cache=leaf_cache,
        limits=limits,
    ).closure


def benchmark_target_closure_capture(
    selection: SourceSelection,
    *,
    transient_paths: Iterable[str | Path] = (),
    leaf_cache: MerkleLeafCache | None = None,
    limits: TargetClosureLimits | None = None,
    samples: int = 3,
    warmup_samples: int = 1,
    budget_seconds: float | None = None,
) -> TargetClosureBenchmark:
    """Run a bounded diagnostic-only benchmark over real byte captures.

    It intentionally reports observations rather than a performance pass.  A
    caller supplies a preselected target and may choose a process-local cache;
    no source file is synthesized, mutated, or persisted by this helper.
    """

    if not isinstance(samples, int) or isinstance(samples, bool) or not 1 <= samples <= 5:
        raise ProviderReceiptError("benchmark samples must be between one and five")
    if not isinstance(warmup_samples, int) or isinstance(warmup_samples, bool) or not 0 <= warmup_samples <= 2:
        raise ProviderReceiptError("benchmark warmup_samples must be between zero and two")
    if budget_seconds is not None and (
        isinstance(budget_seconds, bool)
        or not isinstance(budget_seconds, (int, float))
        or not math.isfinite(float(budget_seconds))
        or float(budget_seconds) <= 0.0
    ):
        raise ProviderReceiptError("benchmark budget_seconds must be a positive finite number")
    shared_cache = MerkleLeafCache() if leaf_cache is None else leaf_cache
    for _ in range(warmup_samples):
        capture_target_closure(
            selection,
            transient_paths=transient_paths,
            leaf_cache=shared_cache,
            limits=limits,
        )
    elapsed: list[float] = []
    hits = 0
    misses = 0
    file_count: int | None = None
    for _ in range(samples):
        started = time.perf_counter()
        capture = capture_target_closure(
            selection,
            transient_paths=transient_paths,
            leaf_cache=shared_cache,
            limits=limits,
        )
        elapsed.append(float(time.perf_counter() - started))
        hits += capture.leaf_cache_hits
        misses += capture.leaf_cache_misses
        if file_count is None:
            file_count = capture.files_byte_validated
        elif file_count != capture.files_byte_validated:
            raise ProviderReceiptError("benchmark target closure changed between controlled samples")
    ordered = sorted(elapsed)
    p95 = ordered[(95 * len(ordered) + 99) // 100 - 1]
    budget = None if budget_seconds is None else float(budget_seconds)
    return TargetClosureBenchmark(
        samples=samples,
        warmup_samples=warmup_samples,
        file_count=0 if file_count is None else file_count,
        elapsed_seconds=tuple(elapsed),
        p95_seconds=float(p95),
        requested_budget_seconds=budget,
        within_budget=None if budget is None else p95 <= budget,
        cache_hits=hits,
        cache_misses=misses,
    )


def _canonical_record_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


@dataclass(frozen=True)
class TargetMerkleReceipt:
    """A binding of canonical provider records to one byte/Merkle closure.

    The nested values are deliberately digest/byte references, not local copies
    of provider-envelope, coverage, physical-seal or lifecycle schemas.  Their
    canonical owners remain ``input_identity`` and ``provider_envelope``.
    """

    target_id: str
    source_selection_digest: str
    source_selection_bytes_sha256: str
    input_identity_digest: str
    provider_envelope_digest: str
    provider_envelope_bytes_sha256: str
    provider_scan_mode: ScanMode
    coverage_union_digest: str
    coverage_union_bytes_sha256: str
    target_closure_digest: str
    target_closure_bytes_sha256: str
    lifecycle_interval_digest: str | None
    lifecycle_interval_bytes_sha256: str | None
    lineage: dict[str, str]
    receipt_digest: str
    contributing_envelope_digests: tuple[str, ...] = ()

    @property
    def authority_identity(self) -> dict[str, Any]:
        identity: dict[str, Any] = {
            "record_type": "TargetMerkleReceipt",
            "schema": _RECEIPT_SCHEMA,
            "target_id": self.target_id,
            "source_selection": {
                "selection_digest": self.source_selection_digest,
                "authority_bytes_sha256": self.source_selection_bytes_sha256,
            },
            "input_identity_digest": self.input_identity_digest,
            "provider_envelope": {
                "envelope_digest": self.provider_envelope_digest,
                "canonical_bytes_sha256": self.provider_envelope_bytes_sha256,
                "scan_mode": self.provider_scan_mode.value,
            },
            "coverage_union": {
                "coverage_union_digest": self.coverage_union_digest,
                "canonical_bytes_sha256": self.coverage_union_bytes_sha256,
            },
            "target_closure": {
                "closure_digest": self.target_closure_digest,
                "canonical_bytes_sha256": self.target_closure_bytes_sha256,
            },
            "contributor_lineage": {
                "contributing_envelope_digests": list(self.contributing_envelope_digests),
            },
            "lineage": dict(self.lineage),
        }
        if self.lifecycle_interval_digest is not None:
            identity["lifecycle_interval"] = {
                "interval_digest": self.lifecycle_interval_digest,
                "canonical_bytes_sha256": self.lifecycle_interval_bytes_sha256,
            }
        return identity

    def to_record(self) -> dict[str, Any]:
        return {
            **self.authority_identity,
            "receipt_digest": self.receipt_digest,
            "acceptance_pass": False,
            "pass_credit": False,
        }


def _validate_receipt_shape(receipt: TargetMerkleReceipt) -> TargetMerkleReceipt:
    if not isinstance(receipt, TargetMerkleReceipt):
        raise ProviderReceiptError("target Merkle receipt must be typed")
    _require_identifier(receipt.target_id, "target_id")
    for field, value in (
        ("source selection digest", receipt.source_selection_digest),
        ("source selection bytes SHA-256", receipt.source_selection_bytes_sha256),
        ("input identity digest", receipt.input_identity_digest),
        ("provider envelope digest", receipt.provider_envelope_digest),
        ("provider envelope bytes SHA-256", receipt.provider_envelope_bytes_sha256),
        ("coverage union digest", receipt.coverage_union_digest),
        ("coverage union bytes SHA-256", receipt.coverage_union_bytes_sha256),
        ("target closure digest", receipt.target_closure_digest),
        ("target closure bytes SHA-256", receipt.target_closure_bytes_sha256),
        ("receipt digest", receipt.receipt_digest),
    ):
        _require_digest(value, field)
    if not isinstance(receipt.provider_scan_mode, ScanMode):
        raise ProviderReceiptError("target receipt provider scan mode must be typed")
    if not isinstance(receipt.contributing_envelope_digests, tuple):
        raise ProviderReceiptError("target receipt contributor lineage must be an exact tuple")
    contributors = tuple(
        sorted(
            (_require_digest(value, "contributing envelope digest") for value in receipt.contributing_envelope_digests),
            key=lambda value: value.encode("utf-8"),
        )
    )
    if not contributors or len(contributors) != len(set(contributors)):
        raise ProviderReceiptError("target receipt contributor lineage must be non-empty and unique")
    if receipt.contributing_envelope_digests != contributors:
        raise ProviderReceiptError("target receipt contributor lineage is not canonical")
    if receipt.provider_envelope_digest not in contributors:
        raise ProviderReceiptError("target receipt primary envelope is absent from contributor lineage")
    if (receipt.lifecycle_interval_digest is None) != (receipt.lifecycle_interval_bytes_sha256 is None):
        raise ProviderReceiptError("target receipt lifecycle binding is incomplete")
    if receipt.lifecycle_interval_digest is not None:
        _require_digest(receipt.lifecycle_interval_digest, "lifecycle interval digest")
        _require_digest(receipt.lifecycle_interval_bytes_sha256, "lifecycle interval bytes SHA-256")
    if not isinstance(receipt.lineage, dict):
        raise ProviderReceiptError("target receipt lineage must be an exact object")
    if receipt.provider_scan_mode is ScanMode.FULL_SCAN:
        if receipt.lineage != {"kind": "root"}:
            raise ProviderReceiptError("FullScan target receipt must have root lineage")
    elif set(receipt.lineage) != {"kind", "parent_target_receipt_digest"} or receipt.lineage.get("kind") != "reuse":
        raise ProviderReceiptError("Reuse target receipt must have explicit parent receipt lineage")
    else:
        _require_digest(receipt.lineage["parent_target_receipt_digest"], "parent target receipt digest")
    if receipt.receipt_digest != digest_value(receipt.authority_identity):
        raise ProviderReceiptError("target Merkle receipt digest mismatch")
    return receipt


def classify_target_receipt_invalidation(
    previous: TargetClosure,
    current: TargetClosure,
    *,
    previous_receipt: TargetMerkleReceipt | None = None,
    current_receipt: TargetMerkleReceipt | None = None,
) -> ReceiptInvalidationClass:
    """Classify a verified closure change without trusting cache metadata.

    Provider/contributor changes are deliberately ranked before target-leaf
    differences: they require the stronger existing configure/provider route.
    When both receipts are absent, classification is restricted to the exact
    byte/Merkle closure.  Supplying only one receipt is ambiguous and fails.
    """

    before = validate_target_closure(previous)
    after = validate_target_closure(current)
    if (previous_receipt is None) != (current_receipt is None):
        raise ProviderReceiptError("receipt invalidation requires both contributor lineages or neither")
    if previous_receipt is not None and current_receipt is not None:
        prior_receipt = _validate_receipt_shape(previous_receipt)
        next_receipt = _validate_receipt_shape(current_receipt)
        if (
            prior_receipt.input_identity_digest != next_receipt.input_identity_digest
            or prior_receipt.provider_envelope_digest != next_receipt.provider_envelope_digest
            or prior_receipt.provider_envelope_bytes_sha256
            != next_receipt.provider_envelope_bytes_sha256
        ):
            return ReceiptInvalidationClass.PROVIDER_IDENTITY_CHANGED
        if (
            prior_receipt.coverage_union_digest != next_receipt.coverage_union_digest
            or prior_receipt.coverage_union_bytes_sha256
            != next_receipt.coverage_union_bytes_sha256
            or prior_receipt.contributing_envelope_digests
            != next_receipt.contributing_envelope_digests
        ):
            return ReceiptInvalidationClass.DEPENDENCY_CLOSURE_CHANGED
    if before.transient_paths != after.transient_paths:
        return ReceiptInvalidationClass.TRANSIENT_POLICY_CHANGED
    if before.selected_paths != after.selected_paths or before.excluded_paths != after.excluded_paths:
        return ReceiptInvalidationClass.SOURCE_TOPOLOGY_CHANGED
    before_leaves = tuple((leaf.path, leaf.sha256, leaf.byte_count) for leaf in before.leaves)
    after_leaves = tuple((leaf.path, leaf.sha256, leaf.byte_count) for leaf in after.leaves)
    if before_leaves != after_leaves or before.merkle_root != after.merkle_root:
        return ReceiptInvalidationClass.BYTE_CONTENT_CHANGED
    if before.selection_digest != after.selection_digest:
        return ReceiptInvalidationClass.SELECTION_DRIFT
    return ReceiptInvalidationClass.REUSE_VALIDATED


def _bindable_records(
    *,
    selection: SourceSelection,
    closure: TargetClosure,
    input_identity: ProviderInputIdentity,
    envelope: ProviderEnvelope,
    coverage_union: CoverageUnion,
    provider_artifact_path: str | os.PathLike[str],
    lifecycle_interval: ConservativeTimestampInterval | None,
) -> tuple[
    TargetClosure,
    dict[str, Any],
    bytes,
    dict[str, Any],
    dict[str, Any] | None,
    tuple[str, ...],
]:
    if not isinstance(selection, SourceSelection):
        raise ProviderReceiptError("target receipt requires a typed source selection")
    selected = _selected_paths(selection)
    normalized_closure = validate_target_closure(closure)
    if normalized_closure.selection_digest != selection.selection_digest:
        raise ProviderReceiptError("target closure is not bound to the supplied source selection")
    if normalized_closure.selected_paths != selected:
        raise ProviderReceiptError("target closure does not exactly match the supplied source selection")
    if not isinstance(input_identity, ProviderInputIdentity):
        raise ProviderReceiptError("target receipt requires a typed provider input identity")
    if not isinstance(envelope, ProviderEnvelope):
        raise ProviderReceiptError("target receipt requires a typed provider envelope")
    if not isinstance(coverage_union, CoverageUnion):
        raise ProviderReceiptError("target receipt requires a typed provider coverage union")
    expected_input_digest = input_identity.input_digest
    if envelope.input_identity_digest != expected_input_digest:
        raise ProviderReceiptError("provider envelope input identity does not match target receipt input")
    if coverage_union.input_identity_digest != expected_input_digest:
        raise ProviderReceiptError("provider coverage union input identity does not match target receipt input")
    if coverage_union.status != "PASS" or coverage_union.missing_modules:
        raise ProviderReceiptError("provider coverage union is not exact and passing")
    if envelope.scan_mode not in coverage_union.scan_modes:
        raise ProviderReceiptError("provider coverage union does not include the envelope scan mode")
    if envelope.envelope_digest not in coverage_union.contributing_envelope_digests:
        raise ProviderReceiptError("provider coverage union does not bind the current envelope")
    if not set(coverage_union.required_driver_roles).issubset(
        {driver.role for driver in envelope.global_drivers}
    ):
        raise ProviderReceiptError("provider envelope does not satisfy union driver-role requirements")
    if not set(envelope.module_subset).issubset(coverage_union.requested_modules):
        raise ProviderReceiptError("provider envelope subset is outside requested coverage")
    if not set(envelope.covered_modules).issubset(coverage_union.covered_modules):
        raise ProviderReceiptError("provider envelope coverage is outside the coverage union")
    try:
        sealed = verify_envelope_physical_artifact(envelope, provider_artifact_path)
    except ProviderEnvelopeError as exc:
        raise ProviderReceiptError("provider physical artifact cannot be verified") from exc
    if not sealed:
        raise ProviderReceiptError("provider physical artifact no longer matches its canonical seal")
    envelope_bytes = canonical_provider_envelope_bytes(envelope)
    coverage_record = coverage_union.to_record()
    interval_record: dict[str, Any] | None = None
    if lifecycle_interval is not None:
        if not isinstance(lifecycle_interval, ConservativeTimestampInterval):
            raise ProviderReceiptError("target receipt lifecycle interval must be typed")
        interval_record = lifecycle_interval.to_record()
    return (
        normalized_closure,
        selection.to_record(),
        envelope_bytes,
        coverage_record,
        interval_record,
        coverage_union.contributing_envelope_digests,
    )


def bind_target_merkle_receipt(
    *,
    target_id: str,
    selection: SourceSelection,
    closure: TargetClosure,
    input_identity: ProviderInputIdentity,
    envelope: ProviderEnvelope,
    coverage_union: CoverageUnion,
    provider_artifact_path: str | os.PathLike[str],
    lifecycle_interval: ConservativeTimestampInterval | None = None,
    parent_target_receipt_digest: str | None = None,
) -> TargetMerkleReceipt:
    """Bind canonical provider records to a byte-authoritative target closure.

    A receipt is only created after the envelope's physical artifact matches the
    physical seal owned by :mod:`promin.provider_envelope`.  The host path is
    checked but intentionally never persisted in the receipt.
    """

    identifier = _require_identifier(target_id, "target_id")
    (
        normalized,
        selection_record,
        envelope_bytes,
        coverage_record,
        interval_record,
        contributors,
    ) = _bindable_records(
        selection=selection,
        closure=closure,
        input_identity=input_identity,
        envelope=envelope,
        coverage_union=coverage_union,
        provider_artifact_path=provider_artifact_path,
        lifecycle_interval=lifecycle_interval,
    )
    if envelope.scan_mode is ScanMode.REUSE:
        if parent_target_receipt_digest is None:
            raise ProviderReceiptError("Reuse provider envelope requires an explicit parent target receipt digest")
        lineage = {
            "kind": "reuse",
            "parent_target_receipt_digest": _require_digest(
                parent_target_receipt_digest,
                "parent target receipt digest",
            ),
        }
    else:
        if parent_target_receipt_digest is not None:
            raise ProviderReceiptError("FullScan provider envelope must not claim reuse lineage")
        lineage = {"kind": "root"}
    provisional = TargetMerkleReceipt(
        target_id=identifier,
        source_selection_digest=selection.selection_digest,
        source_selection_bytes_sha256=_canonical_record_sha256(selection_record),
        input_identity_digest=input_identity.input_digest,
        provider_envelope_digest=envelope.envelope_digest,
        provider_envelope_bytes_sha256=hashlib.sha256(envelope_bytes).hexdigest(),
        provider_scan_mode=envelope.scan_mode,
        coverage_union_digest=coverage_record["coverage_union_digest"],
        coverage_union_bytes_sha256=_canonical_record_sha256(coverage_record),
        target_closure_digest=normalized.closure_digest,
        target_closure_bytes_sha256=_canonical_record_sha256(normalized.as_dict()),
        lifecycle_interval_digest=(None if interval_record is None else interval_record["interval_digest"]),
        lifecycle_interval_bytes_sha256=(
            None if interval_record is None else _canonical_record_sha256(interval_record)
        ),
        lineage=lineage,
        receipt_digest="",
        contributing_envelope_digests=contributors,
    )
    receipt = TargetMerkleReceipt(
        target_id=provisional.target_id,
        source_selection_digest=provisional.source_selection_digest,
        source_selection_bytes_sha256=provisional.source_selection_bytes_sha256,
        input_identity_digest=provisional.input_identity_digest,
        provider_envelope_digest=provisional.provider_envelope_digest,
        provider_envelope_bytes_sha256=provisional.provider_envelope_bytes_sha256,
        provider_scan_mode=provisional.provider_scan_mode,
        coverage_union_digest=provisional.coverage_union_digest,
        coverage_union_bytes_sha256=provisional.coverage_union_bytes_sha256,
        target_closure_digest=provisional.target_closure_digest,
        target_closure_bytes_sha256=provisional.target_closure_bytes_sha256,
        lifecycle_interval_digest=provisional.lifecycle_interval_digest,
        lifecycle_interval_bytes_sha256=provisional.lifecycle_interval_bytes_sha256,
        lineage=provisional.lineage,
        receipt_digest=digest_value(provisional.authority_identity),
        contributing_envelope_digests=provisional.contributing_envelope_digests,
    )
    return _validate_receipt_shape(receipt)


def validate_target_merkle_receipt(
    receipt: TargetMerkleReceipt,
    *,
    selection: SourceSelection,
    closure: TargetClosure,
    input_identity: ProviderInputIdentity,
    envelope: ProviderEnvelope,
    coverage_union: CoverageUnion,
    provider_artifact_path: str | os.PathLike[str],
    lifecycle_interval: ConservativeTimestampInterval | None = None,
) -> TargetMerkleReceipt:
    """Rebind a receipt against canonical owner records and current artifact bytes."""

    _validate_receipt_shape(receipt)
    parent = receipt.lineage.get("parent_target_receipt_digest")
    expected = bind_target_merkle_receipt(
        target_id=receipt.target_id,
        selection=selection,
        closure=closure,
        input_identity=input_identity,
        envelope=envelope,
        coverage_union=coverage_union,
        provider_artifact_path=provider_artifact_path,
        lifecycle_interval=lifecycle_interval,
        parent_target_receipt_digest=parent,
    )
    if receipt.to_record() != expected.to_record():
        raise ProviderReceiptError("target Merkle receipt does not match its canonical bindings")
    return expected


def canonical_target_merkle_receipt_bytes(
    receipt: TargetMerkleReceipt,
    *,
    selection: SourceSelection,
    closure: TargetClosure,
    input_identity: ProviderInputIdentity,
    envelope: ProviderEnvelope,
    coverage_union: CoverageUnion,
    provider_artifact_path: str | os.PathLike[str],
    lifecycle_interval: ConservativeTimestampInterval | None = None,
) -> bytes:
    """Serialize only a receipt that has just been rebound to canonical inputs."""

    validated = validate_target_merkle_receipt(
        receipt,
        selection=selection,
        closure=closure,
        input_identity=input_identity,
        envelope=envelope,
        coverage_union=coverage_union,
        provider_artifact_path=provider_artifact_path,
        lifecycle_interval=lifecycle_interval,
    )
    return canonical_bytes(validated.to_record())
