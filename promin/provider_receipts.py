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
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

from .canonical import canonical_bytes, digest_value
from .input_identity import (
    InputIdentityError,
    ProviderInputIdentity,
    SourceSelection,
    revalidate_source_selection,
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
_RECEIPT_SCHEMA = "promin.target-merkle-receipt.v1"


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
    for index, left in enumerate(paths):
        for right in paths[index + 1 :]:
            if _under(left, right) or _under(right, left):
                raise ProviderReceiptError(f"{field} contains overlapping paths")


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


def _contained_selected_file(root: Path, relative: str) -> Path:
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    try:
        resolve_contained_path(
            candidate,
            root=root,
            require_regular=True,
            reject_internal_links=True,
        )
    except Exception as exc:
        raise ProviderReceiptError(
            f"selected receipt input is outside the source boundary or unavailable: {relative}"
        ) from exc
    try:
        state = os.lstat(filesystem_path(candidate))
    except OSError as exc:
        raise ProviderReceiptError(f"selected receipt input cannot be inspected: {relative}") from exc
    if _is_link_or_reparse(candidate, state) or not stat.S_ISREG(state.st_mode):
        raise ProviderReceiptError(f"selected receipt input is not a real regular file: {relative}")
    return candidate


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


def _stable_file_digest(path: Path, *, root: Path, relative: str) -> tuple[str, int]:
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


def merkle_root(leaves: Iterable[ReceiptLeaf]) -> str:
    """Calculate one order-stable, domain-separated Merkle root."""

    typed = tuple(_validated_leaf(item) for item in leaves)
    ordered = tuple(sorted(typed, key=lambda item: item.path.encode("utf-8")))
    paths = tuple(item.path for item in ordered)
    if len(paths) != len(set(paths)):
        raise ProviderReceiptError("Merkle closure contains duplicate logical paths")
    if not ordered:
        return hashlib.sha256(_EMPTY_DOMAIN).hexdigest()
    level = [item.leaf_digest for item in ordered]
    while len(level) > 1:
        next_level: list[str] = []
        for index in range(0, len(level), 2):
            left = level[index]
            right = level[index + 1] if index + 1 < len(level) else left
            next_level.append(_domain_hash(_NODE_DOMAIN, {"left": left, "right": right}))
        level = next_level
    return level[0]


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
    if any(not any(_under(path, prefix) for path in selected) for prefix in transient):
        raise ProviderReceiptError("target closure declares a transient path outside its selected inputs")
    excluded = tuple(path for path in selected if any(_under(path, prefix) for prefix in transient))
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
    root = merkle_root(leaves)
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


def scan_target_closure(
    selection: SourceSelection,
    *,
    transient_paths: Iterable[str | Path] = (),
) -> TargetClosure:
    """Hash all and only a canonical selected target closure.

    ``selection`` is intentionally the typed output of
    :func:`input_identity.validate_source_selection`; raw roots and path lists
    are not admitted here.  That keeps containment and source selection owned
    by one canonical layer before this module reads a single source byte.
    """

    if not isinstance(selection, SourceSelection):
        raise ProviderReceiptError("target closure requires a typed source selection")
    try:
        # SourceSelection is the canonical owner of pre-hash membership and
        # metadata drift detection.  A successful revalidation is still never
        # byte authority: the loop below hashes every included file again.
        selection = revalidate_source_selection(selection)
    except InputIdentityError as exc:
        raise ProviderReceiptError("source selection changed after containment preflight") from exc
    selected = _selected_paths(selection)
    root = _assert_selection_root(selection)
    transient = _canonical_paths(transient_paths, "explicit transient path", allow_empty=True)
    _assert_nonoverlapping_prefixes(transient, "explicit transient paths")
    if any(not any(_under(path, prefix) for path in selected) for prefix in transient):
        raise ProviderReceiptError("explicit transient path is outside the selected target closure")
    excluded = tuple(path for path in selected if any(_under(path, prefix) for prefix in transient))
    leaves: list[ReceiptLeaf] = []
    for relative in selected:
        if relative in excluded:
            continue
        candidate = _contained_selected_file(root, relative)
        sha256, byte_count = _stable_file_digest(candidate, root=root, relative=relative)
        leaves.append(ReceiptLeaf.from_content(relative, sha256, byte_count))
    _assert_selection_root(selection)
    provisional = TargetClosure(
        selection_digest=selection.selection_digest,
        selected_paths=selected,
        transient_paths=transient,
        excluded_paths=excluded,
        leaves=tuple(leaves),
        total_bytes=sum(item.byte_count for item in leaves),
        merkle_root=merkle_root(leaves),
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
    return validate_target_closure(closure)


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


def _bindable_records(
    *,
    selection: SourceSelection,
    closure: TargetClosure,
    input_identity: ProviderInputIdentity,
    envelope: ProviderEnvelope,
    coverage_union: CoverageUnion,
    provider_artifact_path: str | os.PathLike[str],
    lifecycle_interval: ConservativeTimestampInterval | None,
) -> tuple[TargetClosure, dict[str, Any], bytes, dict[str, Any], dict[str, Any] | None]:
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
    return normalized_closure, selection.to_record(), envelope_bytes, coverage_record, interval_record


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
    normalized, selection_record, envelope_bytes, coverage_record, interval_record = _bindable_records(
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
