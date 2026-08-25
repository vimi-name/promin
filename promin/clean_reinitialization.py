"""Bounded, owner-confirmed clean reinitialization orchestration.

This module bridges the alpha4 package verifier, recovery transaction, and
writer-liveness guard without creating operational state itself.  It stages
only verified ``.promin/docs`` package members in a private temporary shell;
the injected standard initializer owns any real activation work.
"""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator

from .canonical import CanonicalError, canonical_bytes, digest_bytes, parse_json_strict
from .platform_paths import (
    PlatformPathError,
    filesystem_path,
    resolve_contained_path,
    resolved_temporary_directory,
)
from .project_package import (
    PROJECT_PACKAGE_CONTENT_NAME,
    VerifiedProjectPackage,
    verify_project_package,
)
from .recovery import (
    CleanReinitializationIntent,
    CleanReinitializationPhase,
    CleanReinitializationTransaction,
    CleanStateAdmission,
    OwnerConfirmation,
    PublishedCleanReinitialization,
    PublishedResultVerifier,
    TrackedExtensionAdmission,
    TrackedExtensionRoot,
    admit_clean_state,
    admit_tracked_extensions,
)
from .writer_identity import (
    ProcessObserver,
    WriterIdentity,
    WriterLivenessReport,
    classify_writer_liveness,
    observe_process,
)


class CleanReinitializationOperationError(RuntimeError):
    """Raised when the orchestration boundary cannot proceed safely."""


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_MEMBER_MODES = frozenset({0o644, 0o755})


@dataclass(frozen=True, slots=True)
class CleanReinitializationSeedMember:
    """One package member copied into the temporary docs shell."""

    source_path: str
    target_path: str
    byte_count: int
    sha256: str
    mode: int


@dataclass(frozen=True, slots=True)
class CleanReinitializationPreparation:
    """Non-mutating data needed to obtain an explicit owner confirmation."""

    package: VerifiedProjectPackage
    intent: CleanReinitializationIntent
    seeded_members: tuple[CleanReinitializationSeedMember, ...]

    def to_record(self) -> dict[str, object]:
        """Return a portable preparation record without local temporary paths."""

        return {
            "record_type": "CleanReinitializationPreparation",
            "package": self.package.receipt(),
            "intent": self.intent.to_record(),
            "seeded_members": [
                {
                    "source_path": member.source_path,
                    "target_path": member.target_path,
                    "bytes": member.byte_count,
                    "sha256": member.sha256,
                    "mode": member.mode,
                }
                for member in self.seeded_members
            ],
            "state_migration_supported": False,
            "previous_progress_replay_supported": False,
            "previous_progress_imported": False,
            "acceptance_pass": False,
            "pass_credit": False,
            "product_credit": False,
            "authoritative": False,
        }


@dataclass(frozen=True, slots=True)
class StandardInitializationRequest:
    """The sole input handed to an injected standard initializer.

    ``docs_shell`` is a private temporary ``.promin`` directory containing
    exactly the verified package documentation and typed extensions.  The
    callback must consume it synchronously and must not copy prior operational
    state from the quarantined control root.  If it raises, it must leave the
    active ``project_root / '.promin'`` path absent so the transaction can
    restore the whole prior root; the operation will otherwise fail closed
    rather than overwrite newly-created state.
    """

    project_root: Path
    docs_shell: Path
    package: VerifiedProjectPackage
    admission: CleanStateAdmission

    @property
    def intent(self) -> CleanReinitializationIntent:
        """Return the owner-confirmed intent for this initializer invocation."""

        return self.admission.intent


@dataclass(frozen=True, slots=True)
class StandardInitializationPublication:
    """A callback result that can be independently verified before publication."""

    result: PublishedCleanReinitialization
    verifier: PublishedResultVerifier

    def __post_init__(self) -> None:
        if not isinstance(self.result, PublishedCleanReinitialization):
            raise CleanReinitializationOperationError(
                "standard initializer must return a PublishedCleanReinitialization"
            )
        if not callable(self.verifier):
            raise CleanReinitializationOperationError(
                "standard initializer publication requires a verifier"
            )


StandardInitializer = Callable[[StandardInitializationRequest], StandardInitializationPublication]


class CleanReinitializationState(str, Enum):
    """Observable orchestration state, distinct from product acceptance."""

    PENDING = "PENDING"
    PUBLISHED = "PUBLISHED"


@dataclass(frozen=True, slots=True)
class CleanReinitializationResult:
    """Truthful result of a pending or independently published clean operation."""

    state: CleanReinitializationState
    preparation: CleanReinitializationPreparation
    writer_liveness: WriterLivenessReport
    initializer_called: bool
    transaction_phase: CleanReinitializationPhase | None
    quarantine_root: Path | None
    publication: PublishedCleanReinitialization | None
    state_migration_supported: bool = False
    previous_progress_replay_supported: bool = False
    previous_progress_imported: bool = False
    acceptance_pass: bool = False
    pass_credit: bool = False
    product_credit: bool = False
    authoritative: bool = False

    def __post_init__(self) -> None:
        if any(
            value is not False
            for value in (
                self.state_migration_supported,
                self.previous_progress_replay_supported,
                self.previous_progress_imported,
                self.acceptance_pass,
                self.pass_credit,
                self.product_credit,
                self.authoritative,
            )
        ):
            raise CleanReinitializationOperationError(
                "clean reinitialization operation claims must remain false"
            )
        if self.state is CleanReinitializationState.PENDING:
            if (
                self.initializer_called
                or self.transaction_phase is not None
                or self.quarantine_root is not None
                or self.publication is not None
            ):
                raise CleanReinitializationOperationError(
                    "pending clean reinitialization cannot mutate or publish"
                )
        elif self.state is CleanReinitializationState.PUBLISHED:
            if (
                not self.initializer_called
                or self.transaction_phase is not CleanReinitializationPhase.PUBLISHED
                or self.publication is None
            ):
                raise CleanReinitializationOperationError(
                    "published clean reinitialization requires a verified initializer result"
                )
        else:  # pragma: no cover - Enum enforcement protects normal callers.
            raise CleanReinitializationOperationError("clean reinitialization state is invalid")

    def to_record(self) -> dict[str, object]:
        """Return a report record that never grants migration or acceptance credit."""

        return {
            "record_type": "CleanReinitializationResult",
            "state": self.state.value,
            "preparation": self.preparation.to_record(),
            "writer_liveness": self.writer_liveness.to_record(),
            "initializer_called": self.initializer_called,
            "transaction_phase": (
                self.transaction_phase.value if self.transaction_phase is not None else None
            ),
            "quarantine_performed": self.quarantine_root is not None,
            "published_result_present": self.publication is not None,
            "recovery_status": (
                "PENDING_OWNER_APPLY"
                if self.state is CleanReinitializationState.PENDING
                else "PUBLISHED_CANDIDATE"
            ),
            "diagnostic_only": True,
            "no_pass_credit": True,
            "owner_confirmation_required": self.state is CleanReinitializationState.PENDING,
            "state_migration_supported": False,
            "previous_progress_replay_supported": False,
            "previous_progress_imported": False,
            "acceptance_pass": False,
            "pass_credit": False,
            "product_credit": False,
            "authoritative": False,
        }


def _is_link_or_reparse(path: Path, inspected: os.stat_result) -> bool:
    if stat.S_ISLNK(inspected.st_mode) or os.path.islink(filesystem_path(path)):
        return True
    attributes = getattr(inspected, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    return bool(attributes & reparse_flag)


def _stable_regular_bytes(path: Path, *, root: Path, label: str) -> bytes:
    """Read one contained regular file without accepting a changed identity."""

    try:
        resolved = resolve_contained_path(path, root=root, require_regular=True)
        before = os.stat(filesystem_path(resolved), follow_symlinks=False)
    except (OSError, PlatformPathError) as exc:
        raise CleanReinitializationOperationError(
            f"{label} is not a contained regular file"
        ) from exc
    if _is_link_or_reparse(resolved, before) or not stat.S_ISREG(before.st_mode):
        raise CleanReinitializationOperationError(f"{label} must be a real regular file")
    try:
        with open(filesystem_path(resolved), "rb") as stream:
            payload = stream.read(before.st_size + 1)
    except OSError as exc:
        raise CleanReinitializationOperationError(f"{label} cannot be read") from exc
    try:
        after = os.stat(filesystem_path(resolved), follow_symlinks=False)
    except OSError as exc:
        raise CleanReinitializationOperationError(f"{label} disappeared while being read") from exc
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if (
        _is_link_or_reparse(resolved, after)
        or identity_before != identity_after
        or len(payload) != before.st_size
    ):
        raise CleanReinitializationOperationError(f"{label} changed while being read")
    return payload


def _relative_parts(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise CleanReinitializationOperationError(f"{label} is not a normalized portable path")
    if value.startswith("/") or value.endswith("/"):
        raise CleanReinitializationOperationError(f"{label} is not a normalized relative path")
    if unicodedata.normalize("NFC", value) != value:
        raise CleanReinitializationOperationError(f"{label} must be NFC-normalized")
    parts = tuple(value.split("/"))
    if any(not part or part in {".", ".."} for part in parts):
        raise CleanReinitializationOperationError(f"{label} has unsafe path components")
    return parts


def _manifest_members(package: VerifiedProjectPackage) -> tuple[CleanReinitializationSeedMember, ...]:
    """Read the already-verified manifest defensively for temporary staging."""

    raw = _stable_regular_bytes(
        package.package_root / PROJECT_PACKAGE_CONTENT_NAME,
        root=package.package_root,
        label="project package content record",
    )
    try:
        content = parse_json_strict(raw)
    except CanonicalError as exc:
        raise CleanReinitializationOperationError(
            "project package content record is no longer strict JSON"
        ) from exc
    if not isinstance(content, dict) or canonical_bytes(content) != raw:
        raise CleanReinitializationOperationError(
            "project package content record is no longer canonical"
        )
    members = content.get("members")
    if not isinstance(members, list) or len(members) != package.member_count:
        raise CleanReinitializationOperationError(
            "project package member list changed after verification"
        )

    result: list[CleanReinitializationSeedMember] = []
    sources: set[str] = set()
    targets: set[str] = set()
    for index, raw_member in enumerate(members):
        if not isinstance(raw_member, dict) or set(raw_member) != {
            "source_path",
            "target_path",
            "member_class",
            "bytes",
            "sha256",
            "mode",
        }:
            raise CleanReinitializationOperationError(
                "project package member record changed after verification"
            )
        source_path = raw_member["source_path"]
        target_path = raw_member["target_path"]
        source_parts = _relative_parts(source_path, label=f"members[{index}].source_path")
        target_parts = _relative_parts(target_path, label=f"members[{index}].target_path")
        if source_parts[:1] != ("seeds",) or len(source_parts) < 2:
            raise CleanReinitializationOperationError("package member source is outside seeds")
        if target_parts[:2] != (".promin", "docs") or len(target_parts) < 3:
            raise CleanReinitializationOperationError(
                "package member target is outside the docs shell"
            )
        member_class = raw_member["member_class"]
        if member_class not in {"portable-doc", "typed-extension"}:
            raise CleanReinitializationOperationError("package member class is unsupported")
        if member_class == "portable-doc" and target_parts[:3] == (
            ".promin",
            "docs",
            "extensions",
        ):
            raise CleanReinitializationOperationError(
                "portable document occupies a typed extension namespace"
            )
        if member_class == "typed-extension" and (
            target_parts[:3] != (".promin", "docs", "extensions")
            or len(target_parts) < 5
        ):
            raise CleanReinitializationOperationError(
                "typed extension target is outside a typed docs namespace"
            )
        size = raw_member["bytes"]
        digest = raw_member["sha256"]
        mode = raw_member["mode"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise CleanReinitializationOperationError("package member byte count is invalid")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise CleanReinitializationOperationError("package member digest is invalid")
        if not isinstance(mode, int) or isinstance(mode, bool) or mode not in _CANONICAL_MEMBER_MODES:
            raise CleanReinitializationOperationError("package member mode is invalid")
        if not isinstance(source_path, str) or not isinstance(target_path, str):
            raise CleanReinitializationOperationError("package member path is invalid")
        if source_path.casefold() in sources or target_path.casefold() in targets:
            raise CleanReinitializationOperationError("package member paths collide")
        sources.add(source_path.casefold())
        targets.add(target_path.casefold())
        result.append(
            CleanReinitializationSeedMember(
                source_path=source_path,
                target_path=target_path,
                byte_count=size,
                sha256=digest,
                mode=mode,
            )
        )
    if sum(member.byte_count for member in result) != package.total_bytes:
        raise CleanReinitializationOperationError(
            "project package byte total changed after verification"
        )
    return tuple(result)


def _make_directory(path: Path) -> None:
    try:
        os.mkdir(filesystem_path(path))
    except FileExistsError as exc:
        raise CleanReinitializationOperationError(
            f"temporary docs shell path already exists: {path}"
        ) from exc
    except OSError as exc:
        raise CleanReinitializationOperationError(
            f"cannot create temporary docs shell directory: {path}"
        ) from exc
    try:
        inspected = os.lstat(filesystem_path(path))
    except OSError as exc:
        raise CleanReinitializationOperationError(
            f"temporary docs shell directory cannot be inspected: {path}"
        ) from exc
    if _is_link_or_reparse(path, inspected) or not stat.S_ISDIR(inspected.st_mode):
        raise CleanReinitializationOperationError(
            f"temporary docs shell directory is not real: {path}"
        )


def _make_member_parent(shell: Path, target_parts: tuple[str, ...]) -> Path:
    """Create real, private directories below the temporary `.promin` shell."""

    current = shell
    # Target validation has already guaranteed this begins `.promin/docs`.
    for part in target_parts[1:-1]:
        candidate = current / part
        try:
            inspected = os.lstat(filesystem_path(candidate))
        except FileNotFoundError:
            _make_directory(candidate)
            current = candidate
            continue
        except OSError as exc:
            raise CleanReinitializationOperationError(
                f"temporary docs shell parent cannot be inspected: {candidate}"
            ) from exc
        if _is_link_or_reparse(candidate, inspected) or not stat.S_ISDIR(inspected.st_mode):
            raise CleanReinitializationOperationError(
                f"temporary docs shell parent is not a real directory: {candidate}"
            )
        current = candidate
    return current


def _write_member(destination: Path, payload: bytes, *, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(filesystem_path(destination), flags, 0o600)
    except OSError as exc:
        raise CleanReinitializationOperationError(
            f"cannot create temporary docs member: {destination}"
        ) from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        raise
    try:
        os.chmod(filesystem_path(destination), mode)
    except OSError as exc:
        raise CleanReinitializationOperationError(
            f"cannot set temporary docs member mode: {destination}"
        ) from exc
    observed = _stable_regular_bytes(
        destination,
        root=destination.parent,
        label="temporary docs member",
    )
    if observed != payload:
        raise CleanReinitializationOperationError(
            f"temporary docs member bytes changed after write: {destination}"
        )


def _admission_matches_members(
    admission: TrackedExtensionAdmission,
    members: tuple[CleanReinitializationSeedMember, ...],
) -> bool:
    expected = sorted(
        (member.target_path, member.byte_count, member.sha256) for member in members
    )
    observed = sorted(
        (member.path, member.byte_count, member.sha256) for member in admission.members
    )
    return expected == observed and admission.total_bytes == sum(
        member.byte_count for member in members
    )


@contextmanager
def _temporary_docs_shell(
    package: VerifiedProjectPackage,
) -> Iterator[tuple[Path, tuple[CleanReinitializationSeedMember, ...], TrackedExtensionAdmission]]:
    """Stage exact package docs in a private tree and admit that exact closure."""

    members = _manifest_members(package)
    with resolved_temporary_directory(prefix="promin-clean-reinitialization-") as temporary_root:
        shell = temporary_root / ".promin"
        _make_directory(shell)
        _make_directory(shell / "docs")
        for member in members:
            source = package.package_root.joinpath(*_relative_parts(member.source_path, label="source"))
            payload = _stable_regular_bytes(
                source,
                root=package.package_root,
                label="verified package member",
            )
            if len(payload) != member.byte_count or digest_bytes(payload) != member.sha256:
                raise CleanReinitializationOperationError(
                    "package member no longer matches its verified bytes"
                )
            target_parts = _relative_parts(member.target_path, label="target")
            parent = _make_member_parent(shell, target_parts)
            destination = parent / target_parts[-1]
            _write_member(destination, payload, mode=member.mode)

        # A second verifier pass closes the package-to-shell handoff.  The
        # temporary closure is independently admitted by recovery below.
        if verify_project_package(package.package_root) != package:
            raise CleanReinitializationOperationError(
                "project package changed while the temporary docs shell was materialized"
            )
        max_file_bytes = max((member.byte_count for member in members), default=0)
        admission = admit_tracked_extensions(
            temporary_root,
            (
                TrackedExtensionRoot(
                    root=".promin/docs",
                    max_files=len(members),
                    max_total_bytes=sum(member.byte_count for member in members),
                    max_file_bytes=max_file_bytes,
                ),
            ),
        )
        if not _admission_matches_members(admission, members):
            raise CleanReinitializationOperationError(
                "temporary docs shell differs from verified package members"
            )
        yield shell, members, admission


def _prepare_from_verified_package(
    package: VerifiedProjectPackage,
    *,
    project_identity: str,
) -> CleanReinitializationPreparation:
    with _temporary_docs_shell(package) as (_shell, members, admission):
        intent = CleanReinitializationIntent(
            project_identity=project_identity,
            package_digest=package.tree_sha256,
            profile_id=package.default_profile,
            extension_admission_digest=admission.admission_digest,
        )
        return CleanReinitializationPreparation(
            package=package,
            intent=intent,
            seeded_members=members,
        )


def prepare_clean_reinitialization(
    package_root: str | os.PathLike[str],
    *,
    project_identity: str,
) -> CleanReinitializationPreparation:
    """Produce the exact non-mutating intent an owner must confirm.

    This performs no project-root mutation and leaves no persisted control
    shell.  Execute :func:`clean_reinitialize_project` with an
    :class:`OwnerConfirmation` bound to the returned intent digest.
    """

    package = verify_project_package(package_root)
    return _prepare_from_verified_package(package, project_identity=project_identity)


def _rollback_initializer_failure(
    transaction: CleanReinitializationTransaction,
    failure: BaseException,
) -> None:
    """Restore the whole old root whenever the callback left no active root."""

    try:
        transaction.rollback_before_publication()
    except BaseException as rollback_error:
        error = CleanReinitializationOperationError(
            "standard initializer failed and whole-root rollback was blocked"
        )
        error.add_note(
            f"rollback error: {type(rollback_error).__name__}: {rollback_error}"
        )
        raise error from failure
    raise CleanReinitializationOperationError(
        "standard initializer failed; the prior control root was restored"
    ) from failure


def clean_reinitialize_project(
    project_root: str | os.PathLike[str],
    package_root: str | os.PathLike[str],
    *,
    project_identity: str,
    owner_confirmation: OwnerConfirmation,
    writer_identity: WriterIdentity | None = None,
    writer_observer: ProcessObserver = observe_process,
    writer_now_ns: int | None = None,
    standard_initializer: StandardInitializer | None = None,
) -> CleanReinitializationResult:
    """Run one owner-confirmed clean reinitialization through a real callback.

    Without ``standard_initializer`` this returns ``PENDING`` after package
    verification and temporary-shell admission, preserving the active root.
    With an initializer, the old ``.promin`` root is quarantined first; any
    initializer or publication failure attempts full-root rollback before the
    error is reported.  The callback is synchronous and must return an
    independently verifiable publication result.
    """

    if not isinstance(owner_confirmation, OwnerConfirmation):
        raise CleanReinitializationOperationError(
            "clean reinitialization requires an explicit OwnerConfirmation"
        )
    if standard_initializer is not None and not callable(standard_initializer):
        raise CleanReinitializationOperationError("standard initializer must be callable")

    package = verify_project_package(package_root)
    writer_liveness = classify_writer_liveness(
        writer_identity,
        now_ns=writer_now_ns,
        observer=writer_observer,
    )
    with _temporary_docs_shell(package) as (shell, members, extension_admission):
        intent = CleanReinitializationIntent(
            project_identity=project_identity,
            package_digest=package.tree_sha256,
            profile_id=package.default_profile,
            extension_admission_digest=extension_admission.admission_digest,
        )
        preparation = CleanReinitializationPreparation(
            package=package,
            intent=intent,
            seeded_members=members,
        )
        admission = admit_clean_state(intent, owner_confirmation, extension_admission)
        if standard_initializer is None:
            return CleanReinitializationResult(
                state=CleanReinitializationState.PENDING,
                preparation=preparation,
                writer_liveness=writer_liveness,
                initializer_called=False,
                transaction_phase=None,
                quarantine_root=None,
                publication=None,
            )

        transaction = CleanReinitializationTransaction(
            project_root,
            admission,
            writer_liveness,
        )
        receipt = transaction.quarantine_previous_root()
        initializer_request = StandardInitializationRequest(
            project_root=Path(project_root).absolute(),
            docs_shell=shell,
            package=package,
            admission=admission,
        )
        try:
            publication = standard_initializer(initializer_request)
            if not isinstance(publication, StandardInitializationPublication):
                raise CleanReinitializationOperationError(
                    "standard initializer must return StandardInitializationPublication"
                )
            verified_publication = transaction.mark_published(
                publication.result,
                verifier=publication.verifier,
            )
        except BaseException as exc:
            _rollback_initializer_failure(transaction, exc)
            raise AssertionError("unreachable")  # pragma: no cover
        return CleanReinitializationResult(
            state=CleanReinitializationState.PUBLISHED,
            preparation=preparation,
            writer_liveness=writer_liveness,
            initializer_called=True,
            transaction_phase=transaction.phase,
            quarantine_root=receipt.quarantine_root if receipt is not None else None,
            publication=verified_publication,
        )


__all__ = [
    "CleanReinitializationOperationError",
    "CleanReinitializationPreparation",
    "CleanReinitializationResult",
    "CleanReinitializationSeedMember",
    "CleanReinitializationState",
    "StandardInitializationPublication",
    "StandardInitializationRequest",
    "StandardInitializer",
    "clean_reinitialize_project",
    "prepare_clean_reinitialization",
]
