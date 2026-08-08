"""Generic, source-first identities for provider and configure admission.

The objects in this module deliberately separate repository, tooling,
dependency, and target identity.  A VCS observation may be retained for
diagnostics, but it is never part of the authority digest that admits a
provider, configure, or receipt operation.

``SourceSelection`` is intentionally metadata-only.  It closes lexical,
membership, link/reparse, duplicate, and portable case-collision invariants
before a caller reads bytes, hashes content, or reserves an output path.
Content hashing belongs to the later, explicitly selected content-addressed
operation.
"""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .canonical import canonical_bytes, digest_value
from .platform_paths import filesystem_path


class InputIdentityError(ValueError):
    """Raised when an identity or source-selection invariant is not exact."""


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTITY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_FORBIDDEN_CLAIM_KEYS = frozenset(
    {
        "acceptance_pass",
        "pass_credit",
        "authoritative",
        "release_ready",
        "product_acceptance",
    }
)
_DEFAULT_FORBIDDEN_ROOTS = (".git", ".promin")
_PARTITION_KINDS = ("repository", "tooling", "dependencies", "target")


def _require_text(value: object, *, label: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise InputIdentityError(f"{label} must be a non-empty string")
    if unicodedata.normalize("NFC", value) != value:
        raise InputIdentityError(f"{label} must be NFC-normalized")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise InputIdentityError(f"{label} has an invalid form")
    return value


def _require_digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise InputIdentityError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _reject_claims(value: object, *, label: str) -> None:
    """Reject embedded authority claims instead of silently dropping them."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise InputIdentityError(f"{label} contains a non-string key")
            if key in _FORBIDDEN_CLAIM_KEYS and item is not False:
                raise InputIdentityError(f"{label} must not carry an authority claim: {key}")
            _reject_claims(item, label=label)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_claims(item, label=label)


def _canonical_attributes(value: Mapping[str, Any] | None, *, label: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise InputIdentityError(f"{label} must be a mapping")
    _reject_claims(value, label=label)
    # ``canonical_bytes`` performs the complete JSON type, NFC-key, depth and
    # duplicate-normalization validation.  Round-tripping it gives callers a
    # plain immutable-by-convention JSON value without preserving custom maps.
    try:
        import json

        return json.loads(canonical_bytes(dict(value)).decode("utf-8"))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise InputIdentityError(f"{label} is not canonical JSON") from exc


@dataclass(frozen=True)
class IdentityRecord:
    """One exact input record in a non-overlapping identity partition."""

    identity_id: str
    identity_kind: str
    digest: str
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "identity_id",
            _require_text(self.identity_id, label="identity_id", pattern=_IDENTITY_ID),
        )
        object.__setattr__(
            self,
            "identity_kind",
            _require_text(self.identity_kind, label="identity_kind", pattern=_IDENTITY_ID),
        )
        object.__setattr__(self, "digest", _require_digest(self.digest, label="identity digest"))
        object.__setattr__(
            self,
            "attributes",
            _canonical_attributes(self.attributes, label="identity attributes"),
        )

    def to_record(self) -> dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "identity_kind": self.identity_kind,
            "digest": self.digest,
            "attributes": dict(self.attributes),
        }


def identity_record(
    identity_id: str,
    identity_kind: str,
    digest: str,
    *,
    attributes: Mapping[str, Any] | None = None,
) -> IdentityRecord:
    """Create one typed input identity without assigning any pass credit."""

    return IdentityRecord(identity_id, identity_kind, digest, attributes or {})


@dataclass(frozen=True)
class IdentityPartition:
    """A deterministic collection for one authority input category."""

    kind: str
    records: tuple[IdentityRecord, ...]

    def __post_init__(self) -> None:
        if self.kind not in _PARTITION_KINDS:
            raise InputIdentityError(f"unsupported identity partition: {self.kind}")
        if not self.records:
            raise InputIdentityError(f"{self.kind} identity partition must not be empty")
        if any(not isinstance(item, IdentityRecord) for item in self.records):
            raise InputIdentityError(f"{self.kind} partition contains an invalid record")
        ordered = tuple(sorted(self.records, key=lambda item: item.identity_id.encode("utf-8")))
        identifiers = tuple(item.identity_id for item in ordered)
        if len(set(identifiers)) != len(identifiers):
            raise InputIdentityError(f"{self.kind} partition has duplicate identity_id values")
        object.__setattr__(self, "records", ordered)

    @property
    def digest(self) -> str:
        return digest_value(
            {
                "record_type": "IdentityPartition",
                "kind": self.kind,
                "records": [item.to_record() for item in self.records],
            }
        )

    def to_record(self) -> dict[str, Any]:
        identity = {
            "record_type": "IdentityPartition",
            "kind": self.kind,
            "records": [item.to_record() for item in self.records],
        }
        return {**identity, "partition_digest": digest_value(identity)}


def identity_partition(kind: str, records: Iterable[IdentityRecord]) -> IdentityPartition:
    """Build a partition whose digest cannot accidentally blend another role."""

    return IdentityPartition(kind, tuple(records))


@dataclass(frozen=True)
class ProviderInputIdentity:
    """The authority input for a provider/configure/receipt operation.

    ``repository_observation`` is deliberately outside :attr:`authority_digest`.
    For example, a Git HEAD change can be retained as diagnostic provenance but
    cannot, on its own, permit configure, provider scanning, or receipt capture.
    """

    repository: IdentityPartition
    tooling: IdentityPartition
    dependencies: IdentityPartition
    target: IdentityPartition
    repository_observation: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        expected = {
            "repository": self.repository,
            "tooling": self.tooling,
            "dependencies": self.dependencies,
            "target": self.target,
        }
        for kind, partition in expected.items():
            if not isinstance(partition, IdentityPartition) or partition.kind != kind:
                raise InputIdentityError(f"provider input requires the {kind} identity partition")
        if self.repository_observation is not None:
            object.__setattr__(
                self,
                "repository_observation",
                _canonical_attributes(
                    self.repository_observation, label="repository observation"
                ),
            )

    @property
    def authority_identity(self) -> dict[str, Any]:
        return {
            "record_type": "ProviderInputIdentity",
            "schema": "promin.provider-input-identity.v1",
            "repository": self.repository.to_record(),
            "tooling": self.tooling.to_record(),
            "dependencies": self.dependencies.to_record(),
            "target": self.target.to_record(),
        }

    @property
    def authority_digest(self) -> str:
        return digest_value(self.authority_identity)

    @property
    def input_digest(self) -> str:
        """Alias used by gate receipts; it excludes non-authoritative VCS data."""

        return self.authority_digest

    def to_record(self) -> dict[str, Any]:
        identity = self.authority_identity
        observation = (
            None
            if self.repository_observation is None
            else {
                "record_type": "RepositoryObservation",
                "authoritative": False,
                "value": dict(self.repository_observation),
                "observation_digest": digest_value(dict(self.repository_observation)),
            }
        )
        return {
            **identity,
            "repository_observation": observation,
            "authority_digest": self.authority_digest,
            "acceptance_pass": False,
            "pass_credit": False,
        }


def provider_input_identity(
    *,
    repository: IdentityPartition,
    tooling: IdentityPartition,
    dependencies: IdentityPartition,
    target: IdentityPartition,
    repository_observation: Mapping[str, Any] | None = None,
) -> ProviderInputIdentity:
    return ProviderInputIdentity(
        repository=repository,
        tooling=tooling,
        dependencies=dependencies,
        target=target,
        repository_observation=repository_observation,
    )


def _canonical_relative_path(value: object, *, label: str) -> str:
    raw = _require_text(value, label=label)
    if (
        len(raw) > 4096
        or raw.startswith("/")
        or raw.startswith("\\")
        or "\\" in raw
        or "\x00" in raw
        or (len(raw) >= 2 and raw[0].isalpha() and raw[1] == ":")
    ):
        raise InputIdentityError(f"{label} must be an anchored POSIX relative path")
    parts = raw.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise InputIdentityError(f"{label} contains an invalid path component")
    return raw


def _canonical_roots(values: Iterable[str], *, label: str) -> tuple[str, ...]:
    roots = tuple(_canonical_relative_path(value, label=label) for value in values)
    if len(set(roots)) != len(roots):
        raise InputIdentityError(f"{label} contains duplicate paths")
    folded = [value.casefold() for value in roots]
    if len(set(folded)) != len(folded):
        raise InputIdentityError(f"{label} contains portable case-colliding paths")
    return tuple(sorted(roots, key=lambda value: value.encode("utf-8")))


def _is_reparse_or_link(path: Path, inspected: os.stat_result) -> bool:
    if stat.S_ISLNK(inspected.st_mode):
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    attributes = getattr(inspected, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400))


def _lstat_real(path: Path, *, label: str) -> os.stat_result:
    try:
        inspected = os.lstat(filesystem_path(path))
    except OSError as exc:
        raise InputIdentityError(f"{label} cannot be inspected: {path}: {exc}") from exc
    if _is_reparse_or_link(path, inspected):
        raise InputIdentityError(f"{label} must not be a symbolic link or reparse point: {path}")
    return inspected


def _assert_case_unambiguous(parent: Path, component: str) -> None:
    try:
        matches = {
            entry.name
            for entry in os.scandir(filesystem_path(parent))
            if unicodedata.normalize("NFC", entry.name).casefold() == component.casefold()
        }
    except OSError as exc:
        raise InputIdentityError(f"source parent cannot be enumerated: {parent}: {exc}") from exc
    if len(matches) > 1:
        raise InputIdentityError(
            f"source path has a portable case collision below {parent}: {sorted(matches)}"
        )


@dataclass(frozen=True)
class SourceEntry:
    """Metadata-only identity for one selected source path."""

    path: str
    mode: int
    size_bytes: int
    device: int
    inode: int
    modified_ns: int
    changed_ns: int

    def to_record(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "mode": self.mode,
            "size_bytes": self.size_bytes,
            "device": self.device,
            "inode": self.inode,
            "modified_ns": self.modified_ns,
            "changed_ns": self.changed_ns,
        }


@dataclass(frozen=True)
class SourceSelection:
    """A verified lexical selection that intentionally contains no byte digest."""

    root: Path
    allowed_roots: tuple[str, ...]
    forbidden_roots: tuple[str, ...]
    entries: tuple[SourceEntry, ...]
    root_device: int
    root_inode: int
    root_mode: int

    @property
    def authority_identity(self) -> dict[str, Any]:
        return {
            "record_type": "SourceSelection",
            "schema": "promin.source-selection.v1",
            "allowed_roots": list(self.allowed_roots),
            "forbidden_roots": list(self.forbidden_roots),
            "root_identity": {
                "device": self.root_device,
                "inode": self.root_inode,
                "mode": self.root_mode,
            },
            "entries": [entry.to_record() for entry in self.entries],
        }

    @property
    def selection_digest(self) -> str:
        return digest_value(self.authority_identity)

    @property
    def authority_bytes(self) -> bytes:
        return canonical_bytes(self.authority_identity)

    def to_record(self) -> dict[str, Any]:
        return {
            **self.authority_identity,
            "selection_digest": self.selection_digest,
            "content_hashed": False,
            "acceptance_pass": False,
            "pass_credit": False,
        }


def _allowed(relative: str, roots: Sequence[str]) -> bool:
    return any(relative == root or relative.startswith(root + "/") for root in roots)


def validate_source_selection(
    root: str | os.PathLike[str],
    paths: Iterable[str],
    *,
    allowed_roots: Iterable[str],
    forbidden_roots: Iterable[str] = _DEFAULT_FORBIDDEN_ROOTS,
) -> SourceSelection:
    """Validate source membership before any content read or output mutation.

    The function performs only directory/metadata operations.  It deliberately
    does not hash, open, or parse selected source files.
    """

    root_path = Path(root).absolute()
    root_stat = _lstat_real(root_path, label="source root")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise InputIdentityError(f"source root must be a real directory: {root_path}")
    allowed = _canonical_roots(allowed_roots, label="allowed source root")
    if not allowed:
        raise InputIdentityError("at least one allowed source root is required")
    forbidden = _canonical_roots(forbidden_roots, label="forbidden source root")
    if set(allowed) & set(forbidden):
        raise InputIdentityError("an allowed source root is also forbidden")

    logical_paths = tuple(_canonical_relative_path(value, label="source path") for value in paths)
    if not logical_paths:
        raise InputIdentityError("source selection must not be empty")
    if len(set(logical_paths)) != len(logical_paths):
        raise InputIdentityError("source selection contains duplicate paths")
    folded = [value.casefold() for value in logical_paths]
    if len(set(folded)) != len(folded):
        raise InputIdentityError("source selection contains portable case-colliding paths")

    entries: list[SourceEntry] = []
    for relative in sorted(logical_paths, key=lambda value: value.encode("utf-8")):
        if not _allowed(relative, allowed):
            raise InputIdentityError(f"source path is outside allowed roots: {relative}")
        if _allowed(relative, forbidden):
            raise InputIdentityError(f"source path is below a forbidden root: {relative}")
        current = root_path
        components = relative.split("/")
        for index, component in enumerate(components):
            _assert_case_unambiguous(current, component)
            current = current / component
            inspected = _lstat_real(current, label="source path")
            if index + 1 < len(components):
                if not stat.S_ISDIR(inspected.st_mode):
                    raise InputIdentityError(f"source path ancestor is not a directory: {current}")
            elif not stat.S_ISREG(inspected.st_mode):
                raise InputIdentityError(f"source path is not a regular file: {current}")
        entries.append(
            SourceEntry(
                path=relative,
                mode=stat.S_IMODE(inspected.st_mode),
                size_bytes=inspected.st_size,
                device=inspected.st_dev,
                inode=inspected.st_ino,
                modified_ns=inspected.st_mtime_ns,
                changed_ns=inspected.st_ctime_ns,
            )
        )
    return SourceSelection(
        root=root_path,
        allowed_roots=allowed,
        forbidden_roots=forbidden,
        entries=tuple(entries),
        root_device=root_stat.st_dev,
        root_inode=root_stat.st_ino,
        root_mode=stat.S_IMODE(root_stat.st_mode),
    )


def revalidate_source_selection(selection: SourceSelection) -> SourceSelection:
    """Re-read the authoritative selection and reject any metadata drift.

    This is the post-reservation half of the source-first contract.  It compares
    canonical selection bytes, not a lossy timestamp or an incidental Git HEAD.
    A content-addressed later stage remains responsible for byte hashing.
    """

    if not isinstance(selection, SourceSelection):
        raise InputIdentityError("source selection must be typed")
    current = validate_source_selection(
        selection.root,
        [entry.path for entry in selection.entries],
        allowed_roots=selection.allowed_roots,
        forbidden_roots=selection.forbidden_roots,
    )
    if current.authority_bytes != selection.authority_bytes:
        raise InputIdentityError("source selection changed after preflight")
    return current


def source_selection_identity(
    selection: SourceSelection, *, identity_id: str = "target-source-selection"
) -> IdentityRecord:
    """Expose a selected target as a typed target partition input."""

    if not isinstance(selection, SourceSelection):
        raise InputIdentityError("source selection must be typed")
    return identity_record(
        identity_id,
        "source-selection",
        selection.selection_digest,
        attributes={
            "entry_count": len(selection.entries),
            "content_hashed": False,
        },
    )
