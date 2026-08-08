"""Fail-closed authority boundary for Windows create-only directory publication.

This module deliberately does not decide whether a source is acceptable.  Its
caller supplies a source-and-membership receipt from the owning authority
layer, then supplies the same authority observation again after native handles
have pinned the source and destination parent.  A mismatch aborts before the
rename and receives no acceptance or release credit.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .platform_paths import (
    WindowsCreateOnlyRenameReservation,
    normalize_identity_text,
    physical_rename_directory_create_only,
)


class PublicationError(ValueError):
    """Raised when a create-only publication cannot retain its authority."""


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _absolute_lexical_path(value: str | os.PathLike[str], *, label: str) -> Path:
    try:
        path = Path(os.fspath(value)).expanduser()
    except (TypeError, ValueError) as exc:
        raise PublicationError(f"{label} must be a non-empty path") from exc
    if not path.is_absolute():
        raise PublicationError(f"{label} must be absolute")
    return path.absolute()


def _identity_key(path: Path) -> str:
    return normalize_identity_text(path)


def _contains_or_same(parent: Path, child: Path) -> bool:
    """Compare lexical paths without resolving an attacker-controlled alias."""

    parent_key = _identity_key(parent)
    child_key = _identity_key(child)
    path_module = os.path
    try:
        common = path_module.normcase(path_module.commonpath((parent_key, child_key)))
    except ValueError:
        return False
    return common == path_module.normcase(parent_key)


def _reject_directory_overlap(source: Path, destination: Path) -> None:
    if _identity_key(source) == _identity_key(destination):
        raise PublicationError("create-only publication source and destination must differ")
    if _contains_or_same(source, destination) or _contains_or_same(destination, source):
        raise PublicationError(
            "create-only publication source and destination directories overlap"
        )


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class SourcePublicationReceipt:
    """One exact source/membership observation supplied by its authority owner.

    ``authority_digest`` must bind the source bytes and all authority facts the
    owner needs to preserve.  ``membership_digest`` must bind the selection that
    admitted this source under ``membership_root``.  The publication boundary
    compares a fresh receipt for exact equality after native reservation; it
    never interprets a mere successful rename as authority evidence.
    """

    source: Path
    membership_root: Path
    authority_digest: str
    membership_digest: str


@dataclass(frozen=True, slots=True)
class CreateOnlyDirectoryPublication:
    """A completed filesystem move that intentionally earns no acceptance credit."""

    source: Path
    destination: Path
    authority_digest: str
    membership_digest: str
    authority: bool = field(init=False, default=False)
    pass_credit: bool = field(init=False, default=False)
    acceptance_pass: bool = field(init=False, default=False)
    product_acceptance_pass: bool = field(init=False, default=False)
    runtime_acceptance_pass: bool = field(init=False, default=False)
    release_ready: bool = field(init=False, default=False)

    def record(self) -> dict[str, object]:
        """Expose the operation fact without promoting it to a release claim."""

        return {
            "record_type": "CreateOnlyDirectoryPublication",
            "source": str(self.source),
            "destination": str(self.destination),
            "authority_digest": self.authority_digest,
            "membership_digest": self.membership_digest,
            "authority": False,
            "pass_credit": False,
            "acceptance_pass": False,
            "product_acceptance_pass": False,
            "runtime_acceptance_pass": False,
            "release_ready": False,
        }


SourcePreflight = Callable[[Path, Path], SourcePublicationReceipt]
AuthoritativeRecheck = Callable[
    [SourcePublicationReceipt, WindowsCreateOnlyRenameReservation],
    SourcePublicationReceipt,
]


def _validate_source_receipt(
    receipt: object,
    *,
    source: Path,
    membership_root: Path,
    phase: str,
) -> SourcePublicationReceipt:
    if not isinstance(receipt, SourcePublicationReceipt):
        raise PublicationError(f"{phase} must return SourcePublicationReceipt")
    observed_source = _absolute_lexical_path(receipt.source, label=f"{phase} source")
    observed_membership = _absolute_lexical_path(
        receipt.membership_root, label=f"{phase} membership root"
    )
    if _identity_key(observed_source) != _identity_key(source):
        raise PublicationError(f"{phase} source differs from publication source")
    if _identity_key(observed_membership) != _identity_key(membership_root):
        raise PublicationError(f"{phase} membership root differs from publication root")
    if not _contains_or_same(observed_membership, observed_source):
        raise PublicationError(f"{phase} source escapes its membership root")
    if not _valid_digest(receipt.authority_digest):
        raise PublicationError(f"{phase} authority digest must be lowercase SHA-256")
    if not _valid_digest(receipt.membership_digest):
        raise PublicationError(f"{phase} membership digest must be lowercase SHA-256")
    return SourcePublicationReceipt(
        source=observed_source,
        membership_root=observed_membership,
        authority_digest=receipt.authority_digest,
        membership_digest=receipt.membership_digest,
    )


def publish_directory_create_only(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    *,
    membership_root: str | os.PathLike[str],
    source_preflight: SourcePreflight,
    authoritative_recheck: AuthoritativeRecheck,
) -> CreateOnlyDirectoryPublication:
    """Move a directory only after source preflight and post-reservation closure.

    The order is intentional and part of the API:

    1. lexical source/membership/overlap checks and ``source_preflight`` run
       before the platform primitive is even called;
    2. the Windows primitive opens its create-only source and destination-parent
       handles;
    3. ``authoritative_recheck`` returns an equal receipt while those handles
       remain live; a mismatch raises and releases the reservation;
    4. only then may the native no-replace rename occur.

    This operation is a filesystem safety boundary, not a product, runtime,
    acceptance, or release result.  Every such claim remains ``False`` in the
    returned object.
    """

    if not callable(source_preflight):
        raise PublicationError("source_preflight must be callable")
    if not callable(authoritative_recheck):
        raise PublicationError("authoritative_recheck must be callable")

    lexical_source = _absolute_lexical_path(source, label="publication source")
    lexical_destination = _absolute_lexical_path(
        destination, label="publication destination"
    )
    lexical_membership_root = _absolute_lexical_path(
        membership_root, label="publication membership root"
    )
    if not _contains_or_same(lexical_membership_root, lexical_source):
        raise PublicationError("publication source escapes its membership root")
    _reject_directory_overlap(lexical_source, lexical_destination)

    # This must remain before any platform reservation.  In particular, a
    # non-Windows host must still report a portable source/membership failure
    # rather than masking it with the Windows-only primitive's availability.
    expected = _validate_source_receipt(
        source_preflight(lexical_source, lexical_membership_root),
        source=lexical_source,
        membership_root=lexical_membership_root,
        phase="source preflight",
    )

    def recheck_after_reservation(
        reservation: WindowsCreateOnlyRenameReservation,
    ) -> None:
        actual = _validate_source_receipt(
            authoritative_recheck(expected, reservation),
            source=lexical_source,
            membership_root=lexical_membership_root,
            phase="authoritative recheck",
        )
        if actual != expected:
            raise PublicationError(
                "publication source authority changed after create-only reservation"
            )

    published = physical_rename_directory_create_only(
        lexical_source,
        lexical_destination,
        after_reservation=recheck_after_reservation,
    )
    if _identity_key(published) != _identity_key(lexical_destination):
        raise PublicationError("platform publication returned an unexpected destination")
    return CreateOnlyDirectoryPublication(
        source=lexical_source,
        destination=lexical_destination,
        authority_digest=expected.authority_digest,
        membership_digest=expected.membership_digest,
    )
