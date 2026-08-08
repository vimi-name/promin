"""Fail-closed primitives for owner-confirmed clean reinitialization.

The functions here admit a clean operation, preserve a whole previous control
root outside the next active root, and restore that whole root only before a
new activation is published.  They intentionally do not call legacy repair or
guided-init code, do not copy operational state, and do not touch SQLite,
projections, provider caches, receipts, locks, leases, or evidence.
"""

from __future__ import annotations

import ctypes
import errno
import os
import re
import stat
import sys
import unicodedata
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable

from .canonical import digest_bytes, digest_value, fsync_directory
from .platform_paths import filesystem_path
from .writer_identity import (
    WriterIdentityError,
    WriterLivenessReport,
    require_recovery_permitted,
)


class RecoveryError(RuntimeError):
    """Raised when clean reinitialization cannot preserve its invariants."""


class RecoveryUnavailable(RecoveryError):
    """Raised when the host lacks an atomic no-replace directory move."""


class RecoveryIntentMismatch(RecoveryError):
    """Raised when a completed result belongs to another clean-init intent."""


_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_OPERATIONAL_CONTROL_CHILDREN = frozenset(
    {
        "init",
        "state",
        "providers",
        "evidence",
        "cache",
        "locks",
        "leases",
        "host",
        "standard",
        "generated",
        "recovery",
    }
)
_TRACKED_CONTROL_CHILDREN = frozenset({"docs"})
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise RecoveryError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise RecoveryError(f"{label} is not a bounded identifier")
    return value


def _require_nonnegative(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RecoveryError(f"{label} must be a non-negative integer")
    return value


def _require_positive(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RecoveryError(f"{label} must be a positive integer")
    return value


def _normalized_extension_root(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise RecoveryError("tracked extension root is required")
    if value != unicodedata.normalize("NFC", value):
        raise RecoveryError("tracked extension root must already use NFC")
    if "\\" in value or value.startswith("/") or value.endswith("/") or "//" in value:
        raise RecoveryError("tracked extension root must use one relative POSIX spelling")
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise RecoveryError("tracked extension root has a non-canonical component")
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or candidate.parts != tuple(raw_parts):
        raise RecoveryError("tracked extension root is not a relative lexical path")
    normalized = "/".join(candidate.parts)
    parts = candidate.parts
    if parts[0] == ".promin-host":
        raise RecoveryError("tracked extensions cannot enter host-local control state")
    if parts[0] == ".promin":
        if len(parts) < 2:
            raise RecoveryError("tracked extension cannot name the whole control root")
        child = parts[1]
        if child in _OPERATIONAL_CONTROL_CHILDREN:
            raise RecoveryError(
                f"tracked extension enters forbidden operational root: .promin/{child}"
            )
        if child not in _TRACKED_CONTROL_CHILDREN:
            raise RecoveryError(
                "tracked control extensions are limited to .promin/docs"
            )
    return normalized


def _is_link_or_reparse(path: Path, inspected: os.stat_result) -> bool:
    return (
        stat.S_ISLNK(inspected.st_mode)
        or os.path.islink(filesystem_path(path))
        or bool(getattr(inspected, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE)
    )


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        return os.lstat(filesystem_path(path))
    except OSError as exc:
        raise RecoveryError(f"{label} cannot be inspected: {path}: {exc}") from exc


def _require_real_directory(path: Path, label: str) -> os.stat_result:
    inspected = _lstat(path, label)
    if _is_link_or_reparse(path, inspected) or not stat.S_ISDIR(inspected.st_mode):
        raise RecoveryError(f"{label} must be a real directory: {path}")
    return inspected


def _require_absent(path: Path, label: str) -> None:
    if os.path.lexists(filesystem_path(path)):
        raise RecoveryError(f"{label} already exists: {path}")


def _absolute_lexical(path: str | os.PathLike[str]) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _same_lexical_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.normpath(str(left))) == os.path.normcase(
        os.path.normpath(str(right))
    )


def _is_lexically_within(candidate: Path, root: Path) -> bool:
    candidate_text = os.path.normcase(os.path.normpath(str(candidate)))
    root_text = os.path.normcase(os.path.normpath(str(root)))
    try:
        return os.path.commonpath((candidate_text, root_text)) == root_text
    except ValueError:
        return False


def _file_identity(inspected: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        int(inspected.st_dev),
        int(inspected.st_ino),
        int(inspected.st_mode),
        int(inspected.st_size),
        int(inspected.st_mtime_ns),
        int(inspected.st_ctime_ns),
        int(inspected.st_nlink),
        int(getattr(inspected, "st_file_attributes", 0)),
    )


@dataclass(frozen=True, slots=True)
class TrackedExtensionRoot:
    """One explicitly bounded directory eligible for clean-init overlay."""

    root: str
    max_files: int
    max_total_bytes: int
    max_file_bytes: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", _normalized_extension_root(self.root))
        _require_nonnegative(self.max_files, "max_files")
        _require_nonnegative(self.max_total_bytes, "max_total_bytes")
        _require_nonnegative(self.max_file_bytes, "max_file_bytes")

    def to_record(self) -> dict[str, object]:
        return {
            "root": self.root,
            "max_files": self.max_files,
            "max_total_bytes": self.max_total_bytes,
            "max_file_bytes": self.max_file_bytes,
            "link_policy": "reject-links-and-reparse-points",
        }


@dataclass(frozen=True, slots=True)
class ExtensionMember:
    """One byte-exact regular file selected from a tracked extension root."""

    path: str
    byte_count: int
    sha256: str

    def __post_init__(self) -> None:
        _normalized_extension_root(self.path)
        _require_nonnegative(self.byte_count, "extension member byte_count")
        _require_digest(self.sha256, "extension member sha256")

    def to_record(self) -> dict[str, object]:
        return {"path": self.path, "bytes": self.byte_count, "sha256": self.sha256}


def validate_tracked_extension_roots(
    roots: Iterable[TrackedExtensionRoot],
) -> tuple[TrackedExtensionRoot, ...]:
    """Reject duplicate, case-colliding and nested extension authorities."""

    normalized = tuple(roots)
    if not normalized:
        raise RecoveryError("at least one typed tracked extension root is required")
    if not all(isinstance(item, TrackedExtensionRoot) for item in normalized):
        raise RecoveryError("tracked extension roots must use TrackedExtensionRoot")
    ordered = tuple(sorted(normalized, key=lambda item: item.root.casefold()))
    seen: set[str] = set()
    for item in ordered:
        folded = item.root.casefold()
        if folded in seen:
            raise RecoveryError("tracked extension roots collide after case folding")
        seen.add(folded)
    for position, left in enumerate(ordered):
        left_parts = PurePosixPath(left.root).parts
        for right in ordered[position + 1 :]:
            right_parts = PurePosixPath(right.root).parts
            if tuple(part.casefold() for part in right_parts[: len(left_parts)]) == tuple(
                part.casefold() for part in left_parts
            ):
                raise RecoveryError("tracked extension roots cannot overlap")
    return ordered


@dataclass(frozen=True, slots=True)
class TrackedExtensionAdmission:
    """The manifest of one byte-exact, link-free extension overlay source."""

    source_root: Path
    roots: tuple[TrackedExtensionRoot, ...]
    members: tuple[ExtensionMember, ...]
    total_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.source_root, Path):
            raise RecoveryError("tracked extension source root must be a Path")
        object.__setattr__(self, "source_root", _absolute_lexical(self.source_root))
        canonical_roots = validate_tracked_extension_roots(self.roots)
        object.__setattr__(self, "roots", canonical_roots)
        if not all(isinstance(member, ExtensionMember) for member in self.members):
            raise RecoveryError("tracked extension manifest members are invalid")
        ordered_members = tuple(sorted(self.members, key=lambda item: item.path.casefold()))
        paths: set[str] = set()
        for member in ordered_members:
            folded = member.path.casefold()
            if folded in paths:
                raise RecoveryError("tracked extension files collide after case folding")
            paths.add(folded)
            member_parts = PurePosixPath(member.path).parts
            matching_roots = [
                policy
                for policy in canonical_roots
                if tuple(
                    part.casefold()
                    for part in member_parts[: len(PurePosixPath(policy.root).parts)]
                )
                == tuple(part.casefold() for part in PurePosixPath(policy.root).parts)
                and len(member_parts) > len(PurePosixPath(policy.root).parts)
            ]
            if len(matching_roots) != 1:
                raise RecoveryError(
                    "tracked extension member is not owned by exactly one typed root"
                )
            policy = matching_roots[0]
            if member.byte_count > policy.max_file_bytes:
                raise RecoveryError("tracked extension member exceeds its root byte limit")
        for policy in canonical_roots:
            selected = [
                member
                for member in ordered_members
                if member.path.casefold().startswith((policy.root + "/").casefold())
            ]
            if len(selected) > policy.max_files:
                raise RecoveryError("tracked extension root exceeds its file limit")
            if sum(member.byte_count for member in selected) > policy.max_total_bytes:
                raise RecoveryError("tracked extension root exceeds its byte limit")
        if sum(member.byte_count for member in ordered_members) != self.total_bytes:
            raise RecoveryError("tracked extension byte total does not equal member closure")
        _require_nonnegative(self.total_bytes, "tracked extension total_bytes")
        object.__setattr__(self, "members", ordered_members)

    def admission_payload(self) -> dict[str, object]:
        return {
            "schema": "promin.tracked-extension-admission.v1",
            "record_type": "TrackedExtensionAdmission",
            "roots": [item.to_record() for item in self.roots],
            "members": [item.to_record() for item in self.members],
            "total_bytes": self.total_bytes,
            "byte_equivalence": "sha256-per-member",
            "link_policy": "reject-links-and-reparse-points",
        }

    @property
    def admission_digest(self) -> str:
        return digest_value(self.admission_payload())

    def to_record(self) -> dict[str, object]:
        return {**self.admission_payload(), "admission_digest": self.admission_digest}


def _entry_name(name: str) -> str:
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise RecoveryError("tracked extension contains an invalid filesystem entry")
    if name != unicodedata.normalize("NFC", name):
        raise RecoveryError("tracked extension contains a non-NFC filesystem entry")
    return name


def _read_stable_extension_file(path: Path, maximum: int) -> bytes:
    before = _lstat(path, "tracked extension file")
    if _is_link_or_reparse(path, before) or not stat.S_ISREG(before.st_mode):
        raise RecoveryError(f"tracked extension member must be a real regular file: {path}")
    if before.st_nlink != 1:
        raise RecoveryError(f"tracked extension member cannot be hard-linked: {path}")
    if before.st_size > maximum:
        raise RecoveryError(f"tracked extension member exceeds byte limit: {path}")
    try:
        with open(filesystem_path(path), "rb") as stream:
            payload = stream.read(maximum + 1)
    except OSError as exc:
        raise RecoveryError(f"tracked extension member cannot be read: {path}: {exc}") from exc
    if len(payload) > maximum:
        raise RecoveryError(f"tracked extension member exceeds byte limit: {path}")
    after = _lstat(path, "tracked extension file")
    if _is_link_or_reparse(path, after) or _file_identity(before) != _file_identity(after):
        raise RecoveryError(f"tracked extension member changed while being admitted: {path}")
    return payload


def admit_tracked_extensions(
    source_root: str | os.PathLike[str],
    roots: Iterable[TrackedExtensionRoot],
) -> TrackedExtensionAdmission:
    """Inspect allowed extension roots before any target control-root mutation."""

    selected_roots = validate_tracked_extension_roots(roots)
    source = _absolute_lexical(source_root)
    _require_real_directory(source, "tracked extension source root")
    members: list[ExtensionMember] = []
    total_bytes = 0
    seen_paths: dict[str, str] = {}

    for policy in selected_roots:
        root_path = source.joinpath(*PurePosixPath(policy.root).parts)
        _require_real_directory(root_path, f"tracked extension root {policy.root}")
        file_count = 0
        root_bytes = 0
        stack: list[tuple[Path, str]] = [(root_path, policy.root)]
        while stack:
            directory, relative_directory = stack.pop()
            _require_real_directory(directory, "tracked extension directory")
            try:
                entries = sorted(
                    list(os.scandir(filesystem_path(directory))),
                    key=lambda entry: unicodedata.normalize("NFC", entry.name).casefold(),
                )
            except OSError as exc:
                raise RecoveryError(
                    f"tracked extension directory cannot be enumerated: {directory}: {exc}"
                ) from exc
            for entry in entries:
                name = _entry_name(entry.name)
                candidate = Path(entry.path)
                try:
                    inspected = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise RecoveryError(
                        f"tracked extension entry cannot be inspected: {candidate}: {exc}"
                    ) from exc
                if _is_link_or_reparse(candidate, inspected):
                    raise RecoveryError(f"tracked extension links are forbidden: {candidate}")
                relative = f"{relative_directory}/{name}"
                if stat.S_ISDIR(inspected.st_mode):
                    stack.append((candidate, relative))
                    continue
                if not stat.S_ISREG(inspected.st_mode):
                    raise RecoveryError(
                        f"tracked extension entry must be a regular file or directory: {candidate}"
                    )
                payload = _read_stable_extension_file(candidate, policy.max_file_bytes)
                file_count += 1
                root_bytes += len(payload)
                if file_count > policy.max_files:
                    raise RecoveryError(
                        f"tracked extension root exceeds file limit: {policy.root}"
                    )
                if root_bytes > policy.max_total_bytes:
                    raise RecoveryError(
                        f"tracked extension root exceeds byte limit: {policy.root}"
                    )
                folded = relative.casefold()
                previous = seen_paths.get(folded)
                if previous is not None:
                    raise RecoveryError(
                        "tracked extension files collide after case folding: "
                        f"{previous} / {relative}"
                    )
                seen_paths[folded] = relative
                members.append(
                    ExtensionMember(
                        path=relative,
                        byte_count=len(payload),
                        sha256=digest_bytes(payload),
                    )
                )
                total_bytes += len(payload)
    return TrackedExtensionAdmission(
        source_root=source,
        roots=selected_roots,
        members=tuple(members),
        total_bytes=total_bytes,
    )


def verify_tracked_extension_admission(
    admission: TrackedExtensionAdmission,
) -> TrackedExtensionAdmission:
    """Re-read the selected source and reject a changed extension closure."""

    if not isinstance(admission, TrackedExtensionAdmission):
        raise RecoveryError("tracked extension admission is required")
    observed = admit_tracked_extensions(admission.source_root, admission.roots)
    if observed.admission_digest != admission.admission_digest:
        raise RecoveryError("tracked extension closure changed after admission")
    return observed


@dataclass(frozen=True, slots=True)
class CleanReinitializationIntent:
    """The exact non-replay operation the owner is being asked to approve."""

    project_identity: str
    package_digest: str
    profile_id: str
    extension_admission_digest: str

    def __post_init__(self) -> None:
        _require_digest(self.project_identity, "project_identity")
        _require_digest(self.package_digest, "package_digest")
        _require_identifier(self.profile_id, "profile_id")
        _require_digest(self.extension_admission_digest, "extension_admission_digest")

    def intent_payload(self) -> dict[str, object]:
        return {
            "schema": "promin.clean-reinitialization-intent.v1",
            "record_type": "CleanReinitializationIntent",
            "project_identity": self.project_identity,
            "package_digest": self.package_digest,
            "profile_id": self.profile_id,
            "extension_admission_digest": self.extension_admission_digest,
            "state_migration_supported": False,
            "previous_progress_replay_supported": False,
            "product_credit": False,
        }

    @property
    def intent_digest(self) -> str:
        return digest_value(self.intent_payload())

    def to_record(self) -> dict[str, object]:
        return {**self.intent_payload(), "intent_digest": self.intent_digest}


@dataclass(frozen=True, slots=True)
class OwnerConfirmation:
    """An explicit owner decision bound to one exact clean-init intent."""

    owner_id: str
    confirmation_id: str
    intent_digest: str
    confirmed_at_ns: int
    approved: bool = True

    def __post_init__(self) -> None:
        _require_identifier(self.owner_id, "owner_id")
        _require_identifier(self.confirmation_id, "confirmation_id")
        _require_digest(self.intent_digest, "owner confirmation intent_digest")
        _require_positive(self.confirmed_at_ns, "confirmed_at_ns")
        if self.approved is not True:
            raise RecoveryError("clean reinitialization requires explicit owner approval")

    def to_record(self) -> dict[str, object]:
        return {
            "schema": "promin.owner-confirmation.v1",
            "record_type": "OwnerConfirmation",
            "owner_id": self.owner_id,
            "confirmation_id": self.confirmation_id,
            "intent_digest": self.intent_digest,
            "confirmed_at_ns": self.confirmed_at_ns,
            "approved": True,
            "confirmation_digest": digest_value(
                {
                    "owner_id": self.owner_id,
                    "confirmation_id": self.confirmation_id,
                    "intent_digest": self.intent_digest,
                    "confirmed_at_ns": self.confirmed_at_ns,
                    "approved": True,
                }
            ),
        }


@dataclass(frozen=True, slots=True)
class CleanStateAdmission:
    """A non-authoritative admission result for a destructive clean operation."""

    intent: CleanReinitializationIntent
    owner_confirmation: OwnerConfirmation
    extension_admission: TrackedExtensionAdmission

    def __post_init__(self) -> None:
        if not isinstance(self.intent, CleanReinitializationIntent):
            raise RecoveryError("clean reinitialization intent is required")
        if not isinstance(self.owner_confirmation, OwnerConfirmation):
            raise RecoveryError("owner confirmation is required")
        if not isinstance(self.extension_admission, TrackedExtensionAdmission):
            raise RecoveryError("tracked extension admission is required")
        if self.owner_confirmation.intent_digest != self.intent.intent_digest:
            raise RecoveryIntentMismatch("owner confirmation belongs to another intent")
        if self.extension_admission.admission_digest != self.intent.extension_admission_digest:
            raise RecoveryIntentMismatch("tracked extension admission belongs to another intent")

    def to_record(self) -> dict[str, object]:
        return {
            "schema": "promin.clean-state-admission.v1",
            "record_type": "CleanStateAdmission",
            "intent": self.intent.to_record(),
            "owner_confirmation": self.owner_confirmation.to_record(),
            "extension_admission": self.extension_admission.to_record(),
            "state_migration_supported": False,
            "previous_progress_replay_supported": False,
            "previous_progress_imported": False,
            "acceptance_pass": False,
            "pass_credit": False,
            "product_credit": False,
            "authoritative": False,
        }


def admit_clean_state(
    intent: CleanReinitializationIntent,
    owner_confirmation: OwnerConfirmation,
    extension_admission: TrackedExtensionAdmission,
) -> CleanStateAdmission:
    """Bind explicit consent and the selected package extension closure."""

    return CleanStateAdmission(
        intent=intent,
        owner_confirmation=owner_confirmation,
        extension_admission=extension_admission,
    )


@dataclass(frozen=True, slots=True)
class PublishedCleanReinitialization:
    """A candidate published result that still needs an external verifier."""

    intent_digest: str
    package_digest: str
    extension_admission_digest: str
    activation_digest: str
    published: bool = True
    state_migration_supported: bool = False
    previous_progress_imported: bool = False
    product_credit: bool = False

    def __post_init__(self) -> None:
        _require_digest(self.intent_digest, "published intent_digest")
        _require_digest(self.package_digest, "published package_digest")
        _require_digest(
            self.extension_admission_digest, "published extension_admission_digest"
        )
        _require_digest(self.activation_digest, "published activation_digest")
        if self.published is not True:
            raise RecoveryError("only an explicitly published result can be reused")
        if self.state_migration_supported is not False:
            raise RecoveryError("clean reinitialization cannot enable state migration")
        if self.previous_progress_imported is not False:
            raise RecoveryError("clean reinitialization cannot import previous progress")
        if self.product_credit is not False:
            raise RecoveryError("clean reinitialization cannot grant product credit")


PublishedResultVerifier = Callable[[PublishedCleanReinitialization], bool]


def reuse_verified_clean_reinitialization(
    intent: CleanReinitializationIntent,
    existing: PublishedCleanReinitialization | None,
    *,
    verifier: PublishedResultVerifier,
) -> PublishedCleanReinitialization | None:
    """Reuse only an exactly matching result proven by an external verifier."""

    if existing is None:
        return None
    if not isinstance(intent, CleanReinitializationIntent):
        raise RecoveryError("clean reinitialization intent is required")
    if not isinstance(existing, PublishedCleanReinitialization):
        raise RecoveryError("existing clean reinitialization result is invalid")
    if existing.intent_digest != intent.intent_digest:
        raise RecoveryIntentMismatch("existing clean reinitialization intent does not match")
    if existing.package_digest != intent.package_digest:
        raise RecoveryIntentMismatch("existing result package does not match its intent")
    if existing.extension_admission_digest != intent.extension_admission_digest:
        raise RecoveryIntentMismatch("existing result extension closure does not match")
    if not callable(verifier):
        raise RecoveryError("a published-result verifier is required for reuse")
    try:
        verified = verifier(existing)
    except Exception as exc:
        raise RecoveryError(
            f"existing clean reinitialization verification failed: {type(exc).__name__}"
        ) from exc
    if verified is not True:
        raise RecoveryError("existing clean reinitialization result did not verify")
    return existing


@dataclass(frozen=True, slots=True)
class QuarantinedControlRoot:
    """Receipt for one whole prior `.promin` root moved outside active control."""

    intent_digest: str
    project_root: Path
    active_root: Path
    quarantine_root: Path
    source_device: int

    def __post_init__(self) -> None:
        _require_digest(self.intent_digest, "quarantine intent_digest")
        if not all(isinstance(item, Path) for item in (self.project_root, self.active_root, self.quarantine_root)):
            raise RecoveryError("quarantine paths must be Path instances")
        if not isinstance(self.source_device, int) or isinstance(self.source_device, bool):
            raise RecoveryError("quarantine source_device is invalid")


def _mkdir_real_child(parent: Path, name: str, label: str) -> Path:
    child = parent / name
    if os.path.lexists(filesystem_path(child)):
        _require_real_directory(child, label)
        return child
    try:
        os.mkdir(filesystem_path(child))
    except FileExistsError:
        pass
    except OSError as exc:
        raise RecoveryError(f"cannot create {label}: {child}: {exc}") from exc
    _require_real_directory(child, label)
    return child


def _quarantine_parent(project_root: Path) -> Path:
    host_root = _mkdir_real_child(project_root, ".promin-host", "host-local control root")
    return _mkdir_real_child(host_root, "recovery", "host-local recovery root")


def _windows_move_no_replace(source: Path, destination: Path) -> None:
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    move_file = kernel32.MoveFileExW
    move_file.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
    move_file.restype = wintypes.BOOL
    movefile_write_through = 0x00000008
    if move_file(
        filesystem_path(source),
        filesystem_path(destination),
        movefile_write_through,
    ):
        return
    error = ctypes.get_last_error()
    if error in {80, 183}:  # ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS
        raise RecoveryError(f"atomic move destination already exists: {destination}")
    raise OSError(error, "MoveFileExW without replacement failed", str(destination))


def _linux_move_no_replace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise RecoveryUnavailable("Linux host does not expose renameat2(RENAME_NOREPLACE)")
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    at_fdcwd = -100
    rename_noreplace = 1
    result = renameat2(
        at_fdcwd,
        os.fsencode(filesystem_path(source)),
        at_fdcwd,
        os.fsencode(filesystem_path(destination)),
        rename_noreplace,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise RecoveryError(f"atomic move destination already exists: {destination}")
    if error in {errno.ENOSYS, errno.EINVAL}:
        raise RecoveryUnavailable("Linux host cannot perform a no-replace directory move")
    raise OSError(error, "renameat2(RENAME_NOREPLACE) failed", str(destination))


def _atomic_move_no_replace(source: Path, destination: Path) -> None:
    """Move a whole root without replacement API semantics."""

    _require_absent(destination, "atomic move destination")
    if os.name == "nt":
        _windows_move_no_replace(source, destination)
        return
    if sys.platform.startswith("linux"):
        _linux_move_no_replace(source, destination)
        return
    raise RecoveryUnavailable(
        "this host has no verified atomic no-replace directory move implementation"
    )


def _control_paths(project_root: str | os.PathLike[str]) -> tuple[Path, Path, Path]:
    project = _absolute_lexical(project_root)
    _require_real_directory(project, "project root")
    active = project / ".promin"
    quarantine = project / ".promin-host" / "recovery"
    if _same_lexical_path(active, quarantine):
        raise RecoveryError("active and quarantine roots cannot be the same path")
    return project, active, quarantine


def _reject_previous_control_extension_source(
    extension_admission: TrackedExtensionAdmission,
    active_root: Path,
) -> None:
    """Keep clean mode from rebuilding its seed closure out of old control data."""

    for policy in extension_admission.roots:
        selected_source = extension_admission.source_root.joinpath(
            *PurePosixPath(policy.root).parts
        )
        if _is_lexically_within(selected_source, active_root):
            raise RecoveryError(
                "clean reinitialization cannot use tracked extensions from the prior active control root"
            )


def quarantine_previous_control_root(
    project_root: str | os.PathLike[str],
    admission: CleanStateAdmission,
    writer_liveness: WriterLivenessReport,
) -> QuarantinedControlRoot | None:
    """Atomically move the entire old root before any new root is published.

    The caller must already hold the authoritative writer lock.  The supplied
    liveness result is an additional fail-closed admission gate; it does not
    claim to be a substitute for that lock.
    """

    if not isinstance(admission, CleanStateAdmission):
        raise RecoveryError("clean state admission is required")
    try:
        require_recovery_permitted(writer_liveness)
    except WriterIdentityError as exc:
        raise RecoveryError(str(exc)) from exc
    project, active, configured_quarantine_parent = _control_paths(project_root)
    target = configured_quarantine_parent / admission.intent.intent_digest
    verify_tracked_extension_admission(admission.extension_admission)
    active_exists = os.path.lexists(filesystem_path(active))
    if not active_exists:
        if os.path.lexists(filesystem_path(target)):
            raise RecoveryError(
                "a prior root is already quarantined for this intent; exact recovery review is required"
            )
        return None
    _reject_previous_control_extension_source(admission.extension_admission, active)
    active_stat = _require_real_directory(active, "previous active control root")
    _require_absent(target, "quarantine target")

    # All cheap path, type and destination checks above precede this first
    # output mutation. Re-read after making the recovery parent to close its
    # local TOCTOU window before the no-replace move.
    quarantine_parent = _quarantine_parent(project)
    if not _same_lexical_path(quarantine_parent, configured_quarantine_parent):
        raise RecoveryError("configured quarantine parent changed during admission")
    _require_absent(target, "quarantine target")
    refreshed_active = _require_real_directory(active, "previous active control root")
    if _file_identity(active_stat) != _file_identity(refreshed_active):
        raise RecoveryError("previous active control root changed before quarantine")
    parent_stat = _require_real_directory(quarantine_parent, "host-local recovery root")
    if int(active_stat.st_dev) != int(parent_stat.st_dev):
        raise RecoveryError("quarantine root must share the active control root filesystem")
    try:
        _atomic_move_no_replace(active, target)
    except OSError as exc:
        raise RecoveryError(f"cannot quarantine prior active control root: {exc}") from exc
    fsync_directory(active.parent)
    fsync_directory(target.parent)
    _require_real_directory(target, "quarantined control root")
    _require_absent(active, "active root after quarantine")
    return QuarantinedControlRoot(
        intent_digest=admission.intent.intent_digest,
        project_root=project,
        active_root=active,
        quarantine_root=target,
        source_device=int(active_stat.st_dev),
    )


def rollback_quarantined_control_root(receipt: QuarantinedControlRoot) -> None:
    """Restore a whole previous root only while no new active root exists."""

    if not isinstance(receipt, QuarantinedControlRoot):
        raise RecoveryError("quarantine receipt is required for rollback")
    project, active, configured_quarantine_parent = _control_paths(receipt.project_root)
    if not _same_lexical_path(project, receipt.project_root):
        raise RecoveryError("quarantine project root spelling changed")
    if not _same_lexical_path(active, receipt.active_root):
        raise RecoveryError("quarantine active root does not match this project")
    if not _same_lexical_path(receipt.quarantine_root.parent, configured_quarantine_parent):
        raise RecoveryError("quarantine root is outside the approved host-local recovery parent")
    _require_absent(active, "active root before rollback")
    quarantined_stat = _require_real_directory(receipt.quarantine_root, "quarantined control root")
    parent_stat = _require_real_directory(configured_quarantine_parent, "host-local recovery root")
    if int(quarantined_stat.st_dev) != int(parent_stat.st_dev):
        raise RecoveryError("quarantined root filesystem changed before rollback")
    if int(quarantined_stat.st_dev) != receipt.source_device:
        raise RecoveryError("quarantined root device does not match its receipt")
    try:
        _atomic_move_no_replace(receipt.quarantine_root, active)
    except OSError as exc:
        raise RecoveryError(f"cannot roll back quarantined control root: {exc}") from exc
    fsync_directory(receipt.quarantine_root.parent)
    fsync_directory(active.parent)
    _require_real_directory(active, "restored active control root")
    _require_absent(receipt.quarantine_root, "quarantine root after rollback")


class CleanReinitializationPhase(str, Enum):
    ADMITTED = "ADMITTED"
    QUARANTINED = "QUARANTINED"
    PUBLISHED = "PUBLISHED"
    ROLLED_BACK = "ROLLED_BACK"


class CleanReinitializationTransaction:
    """Stateful guard for the narrow destructive window of clean re-init.

    It neither performs standard initialization nor declares acceptance.  The
    integrator supplies the real standard-init and activation verifier between
    ``quarantine_previous_root`` and ``mark_published``.
    """

    def __init__(
        self,
        project_root: str | os.PathLike[str],
        admission: CleanStateAdmission,
        writer_liveness: WriterLivenessReport,
    ) -> None:
        if not isinstance(admission, CleanStateAdmission):
            raise RecoveryError("clean state admission is required")
        if not isinstance(writer_liveness, WriterLivenessReport):
            raise RecoveryError("writer liveness report is required")
        try:
            require_recovery_permitted(writer_liveness)
        except WriterIdentityError as exc:
            raise RecoveryError(str(exc)) from exc
        self._project_root = _absolute_lexical(project_root)
        self._admission = admission
        self._writer_liveness = writer_liveness
        self._phase = CleanReinitializationPhase.ADMITTED
        self._receipt: QuarantinedControlRoot | None = None

    @property
    def phase(self) -> CleanReinitializationPhase:
        return self._phase

    @property
    def receipt(self) -> QuarantinedControlRoot | None:
        return self._receipt

    def quarantine_previous_root(self) -> QuarantinedControlRoot | None:
        if self._phase is not CleanReinitializationPhase.ADMITTED:
            raise RecoveryError("previous control root can be quarantined only once")
        self._receipt = quarantine_previous_control_root(
            self._project_root,
            self._admission,
            self._writer_liveness,
        )
        self._phase = CleanReinitializationPhase.QUARANTINED
        return self._receipt

    def rollback_before_publication(self) -> None:
        if self._phase is not CleanReinitializationPhase.QUARANTINED:
            raise RecoveryError("rollback is allowed only before publication")
        if self._receipt is not None:
            rollback_quarantined_control_root(self._receipt)
        self._phase = CleanReinitializationPhase.ROLLED_BACK

    def mark_published(
        self,
        result: PublishedCleanReinitialization,
        *,
        verifier: PublishedResultVerifier,
    ) -> PublishedCleanReinitialization:
        if self._phase is not CleanReinitializationPhase.QUARANTINED:
            raise RecoveryError("publication can follow only the quarantine phase")
        _project, active, _quarantine = _control_paths(self._project_root)
        _require_real_directory(active, "new active control root")
        verified = reuse_verified_clean_reinitialization(
            self._admission.intent,
            result,
            verifier=verifier,
        )
        if verified is None:
            raise RecoveryError("published clean reinitialization verification was absent")
        self._phase = CleanReinitializationPhase.PUBLISHED
        return verified


__all__ = [
    "CleanReinitializationIntent",
    "CleanReinitializationPhase",
    "CleanReinitializationTransaction",
    "CleanStateAdmission",
    "ExtensionMember",
    "OwnerConfirmation",
    "PublishedCleanReinitialization",
    "QuarantinedControlRoot",
    "RecoveryError",
    "RecoveryIntentMismatch",
    "RecoveryUnavailable",
    "TrackedExtensionAdmission",
    "TrackedExtensionRoot",
    "admit_clean_state",
    "admit_tracked_extensions",
    "quarantine_previous_control_root",
    "reuse_verified_clean_reinitialization",
    "rollback_quarantined_control_root",
    "validate_tracked_extension_roots",
    "verify_tracked_extension_admission",
]
