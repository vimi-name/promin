"""Typed, SHA-bound provider evidence with conservative lifecycle intervals.

Provider envelopes describe what a provider actually covered.  They do not
grant product, release, or pass credit: callers still need the surrounding
source, semantic, build, and runtime gates.  In particular, a ``Reuse``
envelope never inherits unobserved ``FullScan`` counters; coverage is proved by
the explicit union of module identifiers carried by the submitted envelopes.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .canonical import canonical_bytes, digest_value, format_utc_second
from .input_identity import ProviderInputIdentity
from .platform_paths import filesystem_path


class ProviderEnvelopeError(ValueError):
    """Raised when provider evidence is incomplete, ambiguous, or unbound."""


class ScanMode(str, Enum):
    """The only two coverage provenance modes accepted by this contract."""

    FULL_SCAN = "FullScan"
    REUSE = "Reuse"


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$")
_UTC_FRACTION = re.compile(
    r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?P<fraction>\.[0-9]{1,6})?Z$"
)


def _require_identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ProviderEnvelopeError(f"{label} has an invalid identifier")
    if unicodedata.normalize("NFC", value) != value:
        raise ProviderEnvelopeError(f"{label} must be NFC-normalized")
    return value


def _require_digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ProviderEnvelopeError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _canonical_modules(values: Iterable[str], *, label: str, allow_empty: bool = False) -> tuple[str, ...]:
    modules = tuple(_require_identifier(value, label=label) for value in values)
    if not modules and not allow_empty:
        raise ProviderEnvelopeError(f"{label} must not be empty")
    if len(set(modules)) != len(modules):
        raise ProviderEnvelopeError(f"{label} contains duplicates")
    folded = [value.casefold() for value in modules]
    if len(set(folded)) != len(folded):
        raise ProviderEnvelopeError(f"{label} contains portable case-colliding identifiers")
    return tuple(sorted(modules, key=lambda value: value.encode("utf-8")))


def _is_reparse_or_link(path: Path, inspected: os.stat_result) -> bool:
    if stat.S_ISLNK(inspected.st_mode):
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    attributes = getattr(inspected, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400))


def _physical_regular_file(path: str | os.PathLike[str]) -> tuple[Path, os.stat_result]:
    candidate = Path(path).absolute()
    try:
        inspected = os.lstat(filesystem_path(candidate))
    except OSError as exc:
        raise ProviderEnvelopeError(f"physical provider artifact is unavailable: {candidate}: {exc}") from exc
    if _is_reparse_or_link(candidate, inspected) or not stat.S_ISREG(inspected.st_mode):
        raise ProviderEnvelopeError("physical provider artifact must be a real regular file")
    return candidate, inspected


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with open(filesystem_path(path), "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ProviderEnvelopeError(f"physical provider artifact cannot be read: {path}: {exc}") from exc
    return digest.hexdigest()


@dataclass(frozen=True)
class PhysicalSeal:
    """A SHA-256 seal for one physical provider artifact.

    ``artifact_id`` is a logical identifier, never a persisted host-specific
    path.  The host path is supplied only when the seal is created or checked.
    """

    artifact_id: str
    sha256: str
    size_bytes: int
    mode: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_id", _require_identifier(self.artifact_id, label="artifact_id"))
        object.__setattr__(self, "sha256", _require_digest(self.sha256, label="physical seal"))
        if not isinstance(self.size_bytes, int) or isinstance(self.size_bytes, bool) or self.size_bytes < 0:
            raise ProviderEnvelopeError("physical seal size_bytes must be a non-negative integer")
        if not isinstance(self.mode, int) or isinstance(self.mode, bool) or not 0 <= self.mode <= 0o7777:
            raise ProviderEnvelopeError("physical seal mode must be a file mode")

    def to_record(self) -> dict[str, Any]:
        return {
            "record_type": "PhysicalSeal",
            "algorithm": "sha256",
            "artifact_id": self.artifact_id,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "mode": self.mode,
        }


def seal_physical_artifact(
    path: str | os.PathLike[str], *, artifact_id: str
) -> PhysicalSeal:
    """Read a real regular file once to construct its explicit physical seal."""

    physical, inspected = _physical_regular_file(path)
    return PhysicalSeal(
        artifact_id=artifact_id,
        sha256=_sha256_file(physical),
        size_bytes=inspected.st_size,
        mode=stat.S_IMODE(inspected.st_mode),
    )


def verify_physical_seal(
    path: str | os.PathLike[str], seal: PhysicalSeal
) -> bool:
    """Return true only when current bytes and physical size still match a seal."""

    if not isinstance(seal, PhysicalSeal):
        raise ProviderEnvelopeError("physical seal must be typed")
    physical, inspected = _physical_regular_file(path)
    return (
        inspected.st_size == seal.size_bytes
        and stat.S_IMODE(inspected.st_mode) == seal.mode
        and _sha256_file(physical) == seal.sha256
    )


@dataclass(frozen=True)
class ProviderDriver:
    """One global compiler/provider driver identity, independent of a subset."""

    role: str
    driver_id: str
    sha256: str
    version: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", _require_identifier(self.role, label="driver role"))
        object.__setattr__(self, "driver_id", _require_identifier(self.driver_id, label="driver_id"))
        object.__setattr__(self, "sha256", _require_digest(self.sha256, label="driver SHA-256"))
        if self.version is not None:
            object.__setattr__(self, "version", _require_identifier(self.version, label="driver version"))

    def to_record(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "driver_id": self.driver_id,
            "sha256": self.sha256,
            "version": self.version,
        }


def provider_driver(
    role: str, driver_id: str, sha256: str, *, version: str | None = None
) -> ProviderDriver:
    return ProviderDriver(role=role, driver_id=driver_id, sha256=sha256, version=version)


def _canonical_drivers(values: Iterable[ProviderDriver]) -> tuple[ProviderDriver, ...]:
    drivers = tuple(values)
    if not drivers or any(not isinstance(item, ProviderDriver) for item in drivers):
        raise ProviderEnvelopeError("global driver set must contain typed drivers")
    ordered = tuple(sorted(drivers, key=lambda item: (item.role.encode("utf-8"), item.driver_id.encode("utf-8"))))
    roles = [item.role for item in ordered]
    if len(set(roles)) != len(roles):
        raise ProviderEnvelopeError("global driver set has duplicate roles")
    return ordered


@dataclass(frozen=True)
class ProviderEnvelope:
    """Typed evidence of exact provider coverage, bound to bytes and inputs."""

    provider_id: str
    scan_mode: ScanMode
    input_identity_digest: str
    physical_seal: PhysicalSeal
    global_drivers: tuple[ProviderDriver, ...]
    module_subset: tuple[str, ...]
    covered_modules: tuple[str, ...]
    required_driver_roles: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_id", _require_identifier(self.provider_id, label="provider_id"))
        if not isinstance(self.scan_mode, ScanMode):
            try:
                object.__setattr__(self, "scan_mode", ScanMode(self.scan_mode))
            except (TypeError, ValueError) as exc:
                raise ProviderEnvelopeError("scan_mode must be FullScan or Reuse") from exc
        object.__setattr__(
            self,
            "input_identity_digest",
            _require_digest(self.input_identity_digest, label="provider input identity"),
        )
        if not isinstance(self.physical_seal, PhysicalSeal):
            raise ProviderEnvelopeError("provider envelope requires a typed physical seal")
        object.__setattr__(self, "global_drivers", _canonical_drivers(self.global_drivers))
        object.__setattr__(
            self,
            "module_subset",
            _canonical_modules(self.module_subset, label="module_subset"),
        )
        object.__setattr__(
            self,
            "covered_modules",
            _canonical_modules(self.covered_modules, label="covered_modules"),
        )
        object.__setattr__(
            self,
            "required_driver_roles",
            _canonical_modules(
                self.required_driver_roles,
                label="required_driver_roles",
                allow_empty=True,
            ),
        )
        if not set(self.module_subset).issubset(self.covered_modules):
            raise ProviderEnvelopeError("module_subset must be included in explicit coverage")
        known_roles = {item.role for item in self.global_drivers}
        missing_roles = set(self.required_driver_roles) - known_roles
        if missing_roles:
            raise ProviderEnvelopeError(
                f"global driver set misses required roles: {sorted(missing_roles)}"
            )

    @property
    def coverage_digest(self) -> str:
        return digest_value(
            {
                "record_type": "ProviderCoverage",
                "module_subset": list(self.module_subset),
                "covered_modules": list(self.covered_modules),
            }
        )

    @property
    def authority_identity(self) -> dict[str, Any]:
        return {
            "record_type": "ProviderEnvelope",
            "schema": "promin.provider-envelope.v1",
            "provider_id": self.provider_id,
            "scan_mode": self.scan_mode.value,
            "input_identity_digest": self.input_identity_digest,
            "physical_seal": self.physical_seal.to_record(),
            "global_drivers": [item.to_record() for item in self.global_drivers],
            "required_driver_roles": list(self.required_driver_roles),
            "module_subset": list(self.module_subset),
            "coverage": {
                "covered_modules": list(self.covered_modules),
                "coverage_digest": self.coverage_digest,
            },
        }

    @property
    def envelope_digest(self) -> str:
        return digest_value(self.authority_identity)

    def to_record(self) -> dict[str, Any]:
        return {
            **self.authority_identity,
            "envelope_digest": self.envelope_digest,
            "acceptance_pass": False,
            "pass_credit": False,
        }


def provider_envelope(
    *,
    provider_id: str,
    scan_mode: ScanMode | str,
    input_identity: ProviderInputIdentity,
    physical_seal: PhysicalSeal,
    global_drivers: Iterable[ProviderDriver],
    module_subset: Iterable[str],
    covered_modules: Iterable[str],
    required_driver_roles: Iterable[str] = (),
) -> ProviderEnvelope:
    """Create an envelope from exact typed source identities and coverage."""

    if not isinstance(input_identity, ProviderInputIdentity):
        raise ProviderEnvelopeError("provider envelope requires a typed provider input identity")
    return ProviderEnvelope(
        provider_id=provider_id,
        scan_mode=ScanMode(scan_mode),
        input_identity_digest=input_identity.input_digest,
        physical_seal=physical_seal,
        global_drivers=tuple(global_drivers),
        module_subset=tuple(module_subset),
        covered_modules=tuple(covered_modules),
        required_driver_roles=tuple(required_driver_roles),
    )


def verify_provider_envelope_record(value: Mapping[str, Any]) -> ProviderEnvelope:
    """Parse and verify a serialized envelope rather than trusting its digest."""

    if not isinstance(value, Mapping):
        raise ProviderEnvelopeError("provider envelope record must be a mapping")
    required = {
        "record_type",
        "schema",
        "provider_id",
        "scan_mode",
        "input_identity_digest",
        "physical_seal",
        "global_drivers",
        "required_driver_roles",
        "module_subset",
        "coverage",
        "envelope_digest",
        "acceptance_pass",
        "pass_credit",
    }
    if set(value) != required:
        raise ProviderEnvelopeError("provider envelope record fields are not exact")
    if value.get("record_type") != "ProviderEnvelope" or value.get("schema") != "promin.provider-envelope.v1":
        raise ProviderEnvelopeError("provider envelope record type is invalid")
    if value.get("acceptance_pass") is not False or value.get("pass_credit") is not False:
        raise ProviderEnvelopeError("provider envelope must not claim pass credit")
    raw_seal = value.get("physical_seal")
    if not isinstance(raw_seal, Mapping) or set(raw_seal) != {
        "record_type",
        "algorithm",
        "artifact_id",
        "sha256",
        "size_bytes",
        "mode",
    } or raw_seal.get("record_type") != "PhysicalSeal" or raw_seal.get("algorithm") != "sha256":
        raise ProviderEnvelopeError("provider envelope physical seal is invalid")
    raw_drivers = value.get("global_drivers")
    if not isinstance(raw_drivers, list):
        raise ProviderEnvelopeError("provider envelope global_drivers is invalid")
    drivers: list[ProviderDriver] = []
    for item in raw_drivers:
        if not isinstance(item, Mapping) or set(item) != {"role", "driver_id", "sha256", "version"}:
            raise ProviderEnvelopeError("provider driver record is invalid")
        drivers.append(
            ProviderDriver(
                role=item["role"],
                driver_id=item["driver_id"],
                sha256=item["sha256"],
                version=item["version"],
            )
        )
    coverage = value.get("coverage")
    if not isinstance(coverage, Mapping) or set(coverage) != {"covered_modules", "coverage_digest"}:
        raise ProviderEnvelopeError("provider envelope coverage is invalid")
    envelope = ProviderEnvelope(
        provider_id=value.get("provider_id"),
        scan_mode=value.get("scan_mode"),
        input_identity_digest=value.get("input_identity_digest"),
        physical_seal=PhysicalSeal(
            artifact_id=raw_seal.get("artifact_id"),
            sha256=raw_seal.get("sha256"),
            size_bytes=raw_seal.get("size_bytes"),
            mode=raw_seal.get("mode"),
        ),
        global_drivers=tuple(drivers),
        module_subset=tuple(value.get("module_subset", ())),
        covered_modules=tuple(coverage.get("covered_modules", ())),
        required_driver_roles=tuple(value.get("required_driver_roles", ())),
    )
    if coverage.get("coverage_digest") != envelope.coverage_digest:
        raise ProviderEnvelopeError("provider envelope coverage digest mismatch")
    if value.get("envelope_digest") != envelope.envelope_digest:
        raise ProviderEnvelopeError("provider envelope digest mismatch")
    return envelope


def verify_envelope_physical_artifact(
    envelope: ProviderEnvelope, path: str | os.PathLike[str]
) -> bool:
    if not isinstance(envelope, ProviderEnvelope):
        raise ProviderEnvelopeError("provider envelope must be typed")
    return verify_physical_seal(path, envelope.physical_seal)


@dataclass(frozen=True)
class CoverageUnion:
    """A non-crediting result for exact requested-module coverage."""

    requested_modules: tuple[str, ...]
    covered_modules: tuple[str, ...]
    missing_modules: tuple[str, ...]
    input_identity_digest: str | None
    status: str
    scan_modes: tuple[ScanMode, ...]
    contributing_envelope_digests: tuple[str, ...]
    required_driver_roles: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in {"PASS", "FAIL", "UNAVAILABLE"}:
            raise ProviderEnvelopeError("coverage status is invalid")
        object.__setattr__(
            self,
            "contributing_envelope_digests",
            tuple(sorted({_require_digest(value, label="contributing envelope digest") for value in self.contributing_envelope_digests})),
        )
        object.__setattr__(
            self,
            "required_driver_roles",
            _canonical_modules(
                self.required_driver_roles,
                label="coverage required_driver_roles",
                allow_empty=True,
            ),
        )
        if self.status == "PASS" and not self.contributing_envelope_digests:
            raise ProviderEnvelopeError("passing coverage union requires contributing envelopes")

    def to_record(self) -> dict[str, Any]:
        identity = {
            "record_type": "ProviderCoverageUnion",
            "schema": "promin.provider-coverage-union.v1",
            "requested_modules": list(self.requested_modules),
            "covered_modules": list(self.covered_modules),
            "missing_modules": list(self.missing_modules),
            "input_identity_digest": self.input_identity_digest,
            "status": self.status,
            "scan_modes": [item.value for item in self.scan_modes],
            "contributing_envelope_digests": list(self.contributing_envelope_digests),
            "required_driver_roles": list(self.required_driver_roles),
        }
        return {
            **identity,
            "coverage_union_digest": digest_value(identity),
            "acceptance_pass": False,
            "pass_credit": False,
        }


def provider_coverage_union(
    requested_modules: Iterable[str],
    envelopes: Iterable[ProviderEnvelope],
    *,
    expected_input_identity_digest: str | None = None,
    required_driver_roles: Iterable[str] = (),
) -> CoverageUnion:
    """Prove only the union explicitly described by submitted envelopes.

    No implicit full-scan counters exist in this operation.  A union can be
    structurally complete while its ``pass_credit`` remains false, because this
    operation has not run the downstream semantic, compile, or runtime gates.
    """

    requested = _canonical_modules(requested_modules, label="requested_modules")
    typed = tuple(envelopes)
    if not typed:
        return CoverageUnion(
            requested,
            (),
            requested,
            expected_input_identity_digest,
            "UNAVAILABLE",
            (),
            (),
            (),
        )
    if any(not isinstance(item, ProviderEnvelope) for item in typed):
        raise ProviderEnvelopeError("coverage union requires typed provider envelopes")
    expected = (
        _require_digest(expected_input_identity_digest, label="expected provider input identity")
        if expected_input_identity_digest is not None
        else typed[0].input_identity_digest
    )
    requested_roles = _canonical_modules(
        required_driver_roles, label="required_driver_roles", allow_empty=True
    )
    covered: set[str] = set()
    status = "PASS"
    for envelope in typed:
        if envelope.input_identity_digest != expected:
            status = "FAIL"
        roles = {driver.role for driver in envelope.global_drivers}
        if not set(requested_roles).issubset(roles):
            status = "FAIL"
        covered.update(envelope.covered_modules)
    covered_ordered = tuple(sorted(covered, key=lambda value: value.encode("utf-8")))
    missing = tuple(item for item in requested if item not in covered)
    if missing:
        status = "FAIL"
    return CoverageUnion(
        requested_modules=requested,
        covered_modules=covered_ordered,
        missing_modules=missing,
        input_identity_digest=expected,
        status=status,
        scan_modes=tuple(sorted({item.scan_mode for item in typed}, key=lambda item: item.value)),
        contributing_envelope_digests=tuple(
            sorted({item.envelope_digest for item in typed})
        ),
        required_driver_roles=requested_roles,
    )


@dataclass(frozen=True)
class _ObservedTimestamp:
    instant: datetime
    text: str
    fractional_digits: int


def _parse_observed_timestamp(value: str | datetime, *, label: str) -> _ObservedTimestamp:
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ProviderEnvelopeError(f"{label} must be timezone-aware UTC")
        instant = value.astimezone(timezone.utc)
        fractional_digits = 6 if instant.microsecond else 0
        if fractional_digits:
            text = instant.strftime("%Y-%m-%dT%H:%M:%S") + f".{instant.microsecond:06d}Z"
        else:
            text = format_utc_second(instant)
        return _ObservedTimestamp(instant, text, fractional_digits)
    if not isinstance(value, str):
        raise ProviderEnvelopeError(f"{label} must be an exact UTC timestamp")
    match = _UTC_FRACTION.fullmatch(value)
    if match is None:
        raise ProviderEnvelopeError(f"{label} must use exact UTC Z notation with at most microseconds")
    try:
        instant = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ProviderEnvelopeError(f"{label} is not a real UTC timestamp") from exc
    fraction = match.group("fraction")
    return _ObservedTimestamp(instant, value, 0 if fraction is None else len(fraction) - 1)


def _floor_second(value: datetime) -> datetime:
    return value.replace(microsecond=0)


def _ceil_second(value: datetime) -> datetime:
    floor = _floor_second(value)
    if value.microsecond == 0:
        return floor
    try:
        return floor + timedelta(seconds=1)
    except OverflowError as exc:
        raise ProviderEnvelopeError("timestamp cannot be conservatively rounded upward") from exc


@dataclass(frozen=True)
class ConservativeTimestampInterval:
    """A whole-second interval that can only widen observed microsecond bounds."""

    observed_started_at: str
    observed_completed_at: str
    valid_from: str
    valid_until: str
    started_fractional_digits: int
    completed_fractional_digits: int

    def to_record(self) -> dict[str, Any]:
        identity = {
            "record_type": "ConservativeTimestampInterval",
            "schema": "promin.provider-lifecycle-interval.v1",
            "observed_started_at": self.observed_started_at,
            "observed_completed_at": self.observed_completed_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "source_precision": {
                "started_fractional_digits": self.started_fractional_digits,
                "completed_fractional_digits": self.completed_fractional_digits,
            },
            "conversion": "floor-start-ceil-completed",
        }
        return {
            **identity,
            "interval_digest": digest_value(identity),
            "acceptance_pass": False,
            "pass_credit": False,
        }


def conservative_timestamp_interval(
    started_at: str | datetime, completed_at: str | datetime
) -> ConservativeTimestampInterval:
    """Convert precise provider timestamps without narrowing their interval.

    Starts are floored and completions are ceiled.  Naive, non-UTC, malformed,
    or reverse-ordered values fail closed instead of being rounded implicitly.
    """

    started = _parse_observed_timestamp(started_at, label="started_at")
    completed = _parse_observed_timestamp(completed_at, label="completed_at")
    if completed.instant < started.instant:
        raise ProviderEnvelopeError("completed_at precedes started_at")
    return ConservativeTimestampInterval(
        observed_started_at=started.text,
        observed_completed_at=completed.text,
        valid_from=format_utc_second(_floor_second(started.instant)),
        valid_until=format_utc_second(_ceil_second(completed.instant)),
        started_fractional_digits=started.fractional_digits,
        completed_fractional_digits=completed.fractional_digits,
    )


def canonical_provider_envelope_bytes(envelope: ProviderEnvelope) -> bytes:
    """Expose one canonical byte owner for typed serialized envelope evidence."""

    if not isinstance(envelope, ProviderEnvelope):
        raise ProviderEnvelopeError("provider envelope must be typed")
    return canonical_bytes(envelope.to_record())
