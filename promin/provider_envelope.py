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
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .canonical import canonical_bytes, digest_value, format_utc_second
from .input_identity import BoundedModuleClosure, ProviderInputIdentity
from .platform_paths import filesystem_path


class ProviderEnvelopeError(ValueError):
    """Raised when provider evidence is incomplete, ambiguous, or unbound."""


class ScanMode(str, Enum):
    """The only two coverage provenance modes accepted by this contract."""

    FULL_SCAN = "FullScan"
    REUSE = "Reuse"


class ProviderLanguage(str, Enum):
    """Portable language labels for an explicitly multi-driver provider set."""

    C = "c"
    CPP = "cpp"
    CSHARP = "csharp"
    JAVA = "java"
    JAVASCRIPT = "javascript"
    PYTHON = "python"


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}$")
_MODULE_IDENTIFIER = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9@._:/+~-]{0,511}$")
_UTC_FRACTION = re.compile(
    r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?P<fraction>\.[0-9]{1,6})?Z$"
)


def _require_identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ProviderEnvelopeError(f"{label} has an invalid identifier")
    if unicodedata.normalize("NFC", value) != value:
        raise ProviderEnvelopeError(f"{label} must be NFC-normalized")
    return value


def _require_module_identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _MODULE_IDENTIFIER.fullmatch(value) is None:
        raise ProviderEnvelopeError(f"{label} has an invalid module identifier")
    if unicodedata.normalize("NFC", value) != value:
        raise ProviderEnvelopeError(f"{label} must be NFC-normalized")
    return value


def _require_digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ProviderEnvelopeError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _canonical_modules(values: Iterable[str], *, label: str, allow_empty: bool = False) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ProviderEnvelopeError(f"{label} must be an iterable of module identifiers")
    try:
        materialized = tuple(values)
    except TypeError as exc:
        raise ProviderEnvelopeError(f"{label} must be an iterable of module identifiers") from exc
    modules = tuple(_require_module_identifier(value, label=label) for value in materialized)
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


def _canonical_languages(
    values: Iterable[ProviderLanguage | str], *, label: str, allow_empty: bool = False
) -> tuple[ProviderLanguage, ...]:
    if isinstance(values, (str, bytes)):
        raise ProviderEnvelopeError(f"{label} must be an iterable of language labels")
    try:
        materialized = tuple(values)
    except TypeError as exc:
        raise ProviderEnvelopeError(f"{label} must be an iterable of language labels") from exc
    languages: list[ProviderLanguage] = []
    for value in materialized:
        try:
            languages.append(value if isinstance(value, ProviderLanguage) else ProviderLanguage(value))
        except (TypeError, ValueError) as exc:
            raise ProviderEnvelopeError(f"{label} has an unsupported language") from exc
    if not languages and not allow_empty:
        raise ProviderEnvelopeError(f"{label} must not be empty")
    if len(set(languages)) != len(languages):
        raise ProviderEnvelopeError(f"{label} contains duplicate languages")
    return tuple(sorted(languages, key=lambda item: item.value.encode("utf-8")))


@dataclass(frozen=True)
class LanguageDriver:
    """One language-to-driver binding in a global provider driver set."""

    language: ProviderLanguage
    driver: ProviderDriver

    def __post_init__(self) -> None:
        try:
            object.__setattr__(
                self,
                "language",
                self.language
                if isinstance(self.language, ProviderLanguage)
                else ProviderLanguage(self.language),
            )
        except (TypeError, ValueError) as exc:
            raise ProviderEnvelopeError("language driver language is invalid") from exc
        if not isinstance(self.driver, ProviderDriver):
            raise ProviderEnvelopeError("language driver must carry a typed provider driver")

    def to_record(self) -> dict[str, Any]:
        return {"language": self.language.value, "driver": self.driver.to_record()}


def language_driver(
    language: ProviderLanguage | str, driver: ProviderDriver
) -> LanguageDriver:
    return LanguageDriver(language=ProviderLanguage(language), driver=driver)


@dataclass(frozen=True)
class MultiLanguageDriverSet:
    """An exact, deterministic multi-language global driver set.

    A selected module subset cannot hide a driver for another configured
    language.  The set is therefore separate from individual provider
    envelopes and is checked against every envelope in a large-project pass.
    """

    drivers: tuple[LanguageDriver, ...]
    required_languages: tuple[ProviderLanguage, ...]

    def __post_init__(self) -> None:
        values = tuple(self.drivers)
        if not values or any(not isinstance(item, LanguageDriver) for item in values):
            raise ProviderEnvelopeError("multi-language driver set must contain typed language drivers")
        ordered = tuple(sorted(values, key=lambda item: item.language.value.encode("utf-8")))
        languages = tuple(item.language for item in ordered)
        if len(set(languages)) != len(languages):
            raise ProviderEnvelopeError("multi-language driver set duplicates a language")
        driver_roles = tuple(item.driver.role for item in ordered)
        if len(set(driver_roles)) != len(driver_roles):
            raise ProviderEnvelopeError("multi-language driver set duplicates a driver role")
        object.__setattr__(self, "drivers", ordered)
        object.__setattr__(
            self,
            "required_languages",
            _canonical_languages(
                self.required_languages,
                label="required_languages",
                allow_empty=True,
            ),
        )
        present = set(languages)
        missing = set(self.required_languages) - present
        if missing:
            raise ProviderEnvelopeError(
                "multi-language driver set misses required languages: "
                + ", ".join(item.value for item in sorted(missing, key=lambda item: item.value))
            )

    @property
    def global_drivers(self) -> tuple[ProviderDriver, ...]:
        return tuple(item.driver for item in self.drivers)

    @property
    def authority_identity(self) -> dict[str, Any]:
        return {
            "record_type": "MultiLanguageDriverSet",
            "schema": "promin.multi-language-driver-set.v1",
            "drivers": [item.to_record() for item in self.drivers],
            "required_languages": [item.value for item in self.required_languages],
        }

    @property
    def driver_set_digest(self) -> str:
        return digest_value(self.authority_identity)

    def to_record(self) -> dict[str, Any]:
        return {
            **self.authority_identity,
            "driver_set_digest": self.driver_set_digest,
            "acceptance_pass": False,
            "pass_credit": False,
        }


def multi_language_driver_set(
    drivers: Iterable[LanguageDriver],
    *,
    required_languages: Iterable[ProviderLanguage | str] = (),
) -> MultiLanguageDriverSet:
    return MultiLanguageDriverSet(
        drivers=tuple(drivers),
        required_languages=_canonical_languages(
            required_languages,
            label="required_languages",
            allow_empty=True,
        ),
    )


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
class ContributorDigest:
    """Byte-authoritative provenance for one contributor over exact modules."""

    contributor_id: str
    contribution_kind: str
    module_ids: tuple[str, ...]
    physical_seal: PhysicalSeal

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "contributor_id",
            _require_identifier(self.contributor_id, label="contributor_id"),
        )
        object.__setattr__(
            self,
            "contribution_kind",
            _require_identifier(self.contribution_kind, label="contribution_kind"),
        )
        object.__setattr__(
            self,
            "module_ids",
            _canonical_modules(self.module_ids, label="contributor module_ids"),
        )
        if not isinstance(self.physical_seal, PhysicalSeal):
            raise ProviderEnvelopeError("contributor digest requires a typed physical seal")

    @property
    def authority_identity(self) -> dict[str, Any]:
        return {
            "record_type": "ContributorDigest",
            "schema": "promin.contributor-digest.v1",
            "contributor_id": self.contributor_id,
            "contribution_kind": self.contribution_kind,
            "module_ids": list(self.module_ids),
            "physical_seal": self.physical_seal.to_record(),
        }

    @property
    def contributor_digest(self) -> str:
        return digest_value(self.authority_identity)

    def to_record(self) -> dict[str, Any]:
        return {
            **self.authority_identity,
            "contributor_digest": self.contributor_digest,
            "acceptance_pass": False,
            "pass_credit": False,
        }


def contributor_digest_from_artifact(
    path: str | os.PathLike[str],
    *,
    contributor_id: str,
    contribution_kind: str,
    module_ids: Iterable[str],
    artifact_id: str | None = None,
) -> ContributorDigest:
    """Seal contributor bytes once and bind their declared module membership."""

    identifier = _require_identifier(contributor_id, label="contributor_id")
    return ContributorDigest(
        contributor_id=identifier,
        contribution_kind=contribution_kind,
        module_ids=tuple(module_ids),
        physical_seal=seal_physical_artifact(
            path,
            artifact_id=artifact_id or identifier,
        ),
    )


@dataclass(frozen=True)
class ContributorProvenance:
    """Deterministic full-closure provenance with no implicit contributor gaps."""

    module_closure_digest: str
    module_ids: tuple[str, ...]
    contributors: tuple[ContributorDigest, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "module_closure_digest",
            _require_digest(self.module_closure_digest, label="module closure digest"),
        )
        object.__setattr__(
            self,
            "module_ids",
            _canonical_modules(self.module_ids, label="provenance module_ids"),
        )
        values = tuple(self.contributors)
        if not values or any(not isinstance(item, ContributorDigest) for item in values):
            raise ProviderEnvelopeError("contributor provenance requires typed contributors")
        ordered = tuple(sorted(values, key=lambda item: item.contributor_id.encode("utf-8")))
        identifiers = tuple(item.contributor_id for item in ordered)
        if len(set(identifiers)) != len(identifiers):
            raise ProviderEnvelopeError("contributor provenance has duplicate contributor IDs")
        declared = {module for item in ordered for module in item.module_ids}
        if declared != set(self.module_ids):
            missing = sorted(set(self.module_ids) - declared, key=lambda item: item.encode("utf-8"))
            extra = sorted(declared - set(self.module_ids), key=lambda item: item.encode("utf-8"))
            details: list[str] = []
            if missing:
                details.append("missing=" + ",".join(missing))
            if extra:
                details.append("extra=" + ",".join(extra))
            raise ProviderEnvelopeError("contributor provenance does not exactly cover modules: " + "; ".join(details))
        object.__setattr__(self, "contributors", ordered)

    @property
    def authority_identity(self) -> dict[str, Any]:
        return {
            "record_type": "ContributorProvenance",
            "schema": "promin.contributor-provenance.v1",
            "module_closure_digest": self.module_closure_digest,
            "module_ids": list(self.module_ids),
            "contributors": [item.authority_identity for item in self.contributors],
        }

    @property
    def provenance_digest(self) -> str:
        return digest_value(self.authority_identity)

    def to_record(self) -> dict[str, Any]:
        return {
            **self.authority_identity,
            "provenance_digest": self.provenance_digest,
            "acceptance_pass": False,
            "pass_credit": False,
        }


def contributor_provenance(
    closure: BoundedModuleClosure,
    contributors: Iterable[ContributorDigest],
) -> ContributorProvenance:
    """Bind sealed contributors to an exact complete module closure only."""

    if not isinstance(closure, BoundedModuleClosure):
        raise ProviderEnvelopeError("contributor provenance requires a typed module closure")
    if not closure.complete:
        raise ProviderEnvelopeError("truncated module closure cannot receive contributor provenance")
    return ContributorProvenance(
        module_closure_digest=closure.closure_digest,
        module_ids=closure.modules,
        contributors=tuple(contributors),
    )


@dataclass(frozen=True)
class ContributorSealVerification:
    """Measured byte re-verification of every contributor artifact."""

    provenance_digest: str
    status: str
    checked_contributor_count: int
    bytes_rehashed: int
    failed_contributor_ids: tuple[str, ...]
    elapsed_seconds: float

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "provenance_digest",
            _require_digest(self.provenance_digest, label="provenance digest"),
        )
        if self.status not in {"PASS", "FAIL"}:
            raise ProviderEnvelopeError("contributor seal verification status is invalid")
        for label, value in (
            ("checked_contributor_count", self.checked_contributor_count),
            ("bytes_rehashed", self.bytes_rehashed),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ProviderEnvelopeError(f"contributor seal verification {label} is invalid")
        if not isinstance(self.elapsed_seconds, (int, float)) or isinstance(self.elapsed_seconds, bool) or self.elapsed_seconds < 0:
            raise ProviderEnvelopeError("contributor seal verification elapsed_seconds is invalid")
        failed = _canonical_modules(
            self.failed_contributor_ids,
            label="failed contributor IDs",
            allow_empty=True,
        )
        if self.status == "PASS" and failed:
            raise ProviderEnvelopeError("passing contributor seal verification cannot have failures")
        if self.status == "FAIL" and not failed:
            raise ProviderEnvelopeError("failed contributor seal verification requires a failure")
        object.__setattr__(self, "failed_contributor_ids", failed)

    @property
    def authority_identity(self) -> dict[str, Any]:
        return {
            "record_type": "ContributorSealVerification",
            "schema": "promin.contributor-seal-verification.v1",
            "provenance_digest": self.provenance_digest,
            "status": self.status,
            "checked_contributor_count": self.checked_contributor_count,
            "bytes_rehashed": self.bytes_rehashed,
            "failed_contributor_ids": list(self.failed_contributor_ids),
        }

    def to_record(self) -> dict[str, Any]:
        return {
            **self.authority_identity,
            "elapsed_seconds": float(self.elapsed_seconds),
            "verification_digest": digest_value(self.authority_identity),
            "acceptance_pass": False,
            "pass_credit": False,
        }


def verify_contributor_artifacts(
    provenance: ContributorProvenance,
    artifact_paths: Mapping[str, str | os.PathLike[str]],
) -> ContributorSealVerification:
    """Rehash every contributor path and fail if one byte seal no longer binds."""

    if not isinstance(provenance, ContributorProvenance):
        raise ProviderEnvelopeError("contributor artifact verification requires typed provenance")
    if not isinstance(artifact_paths, Mapping):
        raise ProviderEnvelopeError("contributor artifact paths must be a mapping")
    expected = {item.contributor_id for item in provenance.contributors}
    actual = set(artifact_paths)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("extra=" + ",".join(extra))
        raise ProviderEnvelopeError("contributor artifact paths are not exact: " + "; ".join(details))
    started = time.perf_counter()
    failed: list[str] = []
    bytes_rehashed = 0
    for contributor in provenance.contributors:
        bytes_rehashed += contributor.physical_seal.size_bytes
        try:
            matches = verify_physical_seal(
                artifact_paths[contributor.contributor_id], contributor.physical_seal
            )
        except ProviderEnvelopeError:
            matches = False
        if not matches:
            failed.append(contributor.contributor_id)
    elapsed = time.perf_counter() - started
    return ContributorSealVerification(
        provenance_digest=provenance.provenance_digest,
        status="FAIL" if failed else "PASS",
        checked_contributor_count=len(provenance.contributors),
        bytes_rehashed=bytes_rehashed,
        failed_contributor_ids=tuple(failed),
        elapsed_seconds=elapsed,
    )


@dataclass(frozen=True)
class LargeProjectProviderEnvelope:
    """One provider envelope enriched with complete closure/driver provenance."""

    envelope: ProviderEnvelope
    module_closure: BoundedModuleClosure
    contributor_provenance: ContributorProvenance
    language_drivers: MultiLanguageDriverSet
    reuse_parent_aggregate_digest: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, ProviderEnvelope):
            raise ProviderEnvelopeError("large-project provider envelope requires a typed base envelope")
        if not isinstance(self.module_closure, BoundedModuleClosure):
            raise ProviderEnvelopeError("large-project provider envelope requires a typed module closure")
        if not self.module_closure.complete:
            raise ProviderEnvelopeError("large-project provider envelope cannot use a truncated module closure")
        if not isinstance(self.contributor_provenance, ContributorProvenance):
            raise ProviderEnvelopeError("large-project provider envelope requires contributor provenance")
        if self.contributor_provenance.module_closure_digest != self.module_closure.closure_digest:
            raise ProviderEnvelopeError("contributor provenance is bound to another module closure")
        if self.contributor_provenance.module_ids != self.module_closure.modules:
            raise ProviderEnvelopeError("contributor provenance modules differ from the module closure")
        if not isinstance(self.language_drivers, MultiLanguageDriverSet):
            raise ProviderEnvelopeError("large-project provider envelope requires a multi-language driver set")
        global_drivers = set(self.envelope.global_drivers)
        detached = [
            item.language.value
            for item in self.language_drivers.drivers
            if item.driver not in global_drivers
        ]
        if detached:
            raise ProviderEnvelopeError(
                "language driver is absent from the global provider driver set: "
                + ", ".join(detached)
            )
        closure_modules = set(self.module_closure.modules)
        if not set(self.envelope.module_subset).issubset(closure_modules):
            raise ProviderEnvelopeError("provider module_subset is outside the bounded module closure")
        if not set(self.envelope.covered_modules).issubset(closure_modules):
            raise ProviderEnvelopeError("provider coverage is outside the bounded module closure")
        if self.envelope.scan_mode is ScanMode.REUSE:
            object.__setattr__(
                self,
                "reuse_parent_aggregate_digest",
                _require_digest(
                    self.reuse_parent_aggregate_digest,
                    label="reuse parent aggregate digest",
                ),
            )
        elif self.reuse_parent_aggregate_digest is not None:
            raise ProviderEnvelopeError("FullScan large-project envelope must not carry reuse parent lineage")

    @property
    def authority_identity(self) -> dict[str, Any]:
        return {
            "record_type": "LargeProjectProviderEnvelope",
            "schema": "promin.large-project-provider-envelope.v1",
            "provider_envelope": self.envelope.authority_identity,
            "provider_envelope_digest": self.envelope.envelope_digest,
            "module_closure": self.module_closure.authority_identity,
            "module_closure_digest": self.module_closure.closure_digest,
            "contributor_provenance": self.contributor_provenance.authority_identity,
            "contributor_provenance_digest": self.contributor_provenance.provenance_digest,
            "language_drivers": self.language_drivers.authority_identity,
            "language_driver_set_digest": self.language_drivers.driver_set_digest,
            "reuse_parent_aggregate_digest": self.reuse_parent_aggregate_digest,
        }

    @property
    def large_envelope_digest(self) -> str:
        return digest_value(self.authority_identity)

    def to_record(self) -> dict[str, Any]:
        return {
            **self.authority_identity,
            "large_envelope_digest": self.large_envelope_digest,
            "acceptance_pass": False,
            "pass_credit": False,
        }


def large_project_provider_envelope(
    *,
    envelope: ProviderEnvelope,
    module_closure: BoundedModuleClosure,
    contributor_provenance: ContributorProvenance,
    language_drivers: MultiLanguageDriverSet,
    reuse_parent_aggregate_digest: str | None = None,
) -> LargeProjectProviderEnvelope:
    return LargeProjectProviderEnvelope(
        envelope=envelope,
        module_closure=module_closure,
        contributor_provenance=contributor_provenance,
        language_drivers=language_drivers,
        reuse_parent_aggregate_digest=reuse_parent_aggregate_digest,
    )


@dataclass(frozen=True)
class ProviderReuseMetrics:
    """Measured structural reuse counts, kept outside deterministic identity."""

    elapsed_seconds: float
    envelope_count: int
    full_scan_envelope_count: int
    reuse_envelope_count: int
    requested_module_count: int
    covered_module_count: int
    reused_module_count: int
    contributor_count: int
    reused_contributor_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.elapsed_seconds, (int, float)) or isinstance(self.elapsed_seconds, bool) or self.elapsed_seconds < 0:
            raise ProviderEnvelopeError("provider reuse metrics elapsed_seconds is invalid")
        for label, value in (
            ("envelope_count", self.envelope_count),
            ("full_scan_envelope_count", self.full_scan_envelope_count),
            ("reuse_envelope_count", self.reuse_envelope_count),
            ("requested_module_count", self.requested_module_count),
            ("covered_module_count", self.covered_module_count),
            ("reused_module_count", self.reused_module_count),
            ("contributor_count", self.contributor_count),
            ("reused_contributor_count", self.reused_contributor_count),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ProviderEnvelopeError(f"provider reuse metrics {label} is invalid")
        if self.full_scan_envelope_count + self.reuse_envelope_count > self.envelope_count:
            raise ProviderEnvelopeError("provider reuse metrics scan counts exceed envelope count")
        if self.reused_module_count > self.covered_module_count:
            raise ProviderEnvelopeError("provider reuse metrics reused modules exceed covered modules")
        if self.reused_contributor_count > self.contributor_count:
            raise ProviderEnvelopeError("provider reuse metrics reused contributors exceed contributors")

    def to_record(self) -> dict[str, Any]:
        return {
            "record_type": "ProviderReuseMetrics",
            "schema": "promin.provider-reuse-metrics.v1",
            "elapsed_seconds": float(self.elapsed_seconds),
            "envelope_count": self.envelope_count,
            "full_scan_envelope_count": self.full_scan_envelope_count,
            "reuse_envelope_count": self.reuse_envelope_count,
            "requested_module_count": self.requested_module_count,
            "covered_module_count": self.covered_module_count,
            "reused_module_count": self.reused_module_count,
            "contributor_count": self.contributor_count,
            "reused_contributor_count": self.reused_contributor_count,
            "acceptance_pass": False,
            "pass_credit": False,
        }


@dataclass(frozen=True)
class ProviderIdentityAggregate:
    """Deterministic aggregate of full/reuse large-project provider envelopes."""

    module_closure_digest: str
    input_identity_digest: str | None
    status: str
    envelope_digests: tuple[str, ...]
    coverage_union_digest: str | None
    contributor_provenance_digest: str | None
    language_driver_set_digest: str | None
    reuse_parent_aggregate_digests: tuple[str, ...]
    metrics: ProviderReuseMetrics
    errors: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "module_closure_digest",
            _require_digest(self.module_closure_digest, label="aggregate module closure digest"),
        )
        if self.input_identity_digest is not None:
            object.__setattr__(
                self,
                "input_identity_digest",
                _require_digest(self.input_identity_digest, label="aggregate input identity digest"),
            )
        for field_name in ("coverage_union_digest", "contributor_provenance_digest", "language_driver_set_digest"):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(self, field_name, _require_digest(value, label=field_name))
        if self.status not in {"PASS", "FAIL", "UNAVAILABLE"}:
            raise ProviderEnvelopeError("provider identity aggregate status is invalid")
        envelope_digests = tuple(
            sorted({_require_digest(value, label="large envelope digest") for value in self.envelope_digests})
        )
        parent_digests = tuple(
            sorted(
                {
                    _require_digest(value, label="reuse parent aggregate digest")
                    for value in self.reuse_parent_aggregate_digests
                }
            )
        )
        if not isinstance(self.metrics, ProviderReuseMetrics):
            raise ProviderEnvelopeError("provider identity aggregate requires typed reuse metrics")
        if self.status == "PASS" and (
            not envelope_digests
            or self.coverage_union_digest is None
            or self.contributor_provenance_digest is None
            or self.language_driver_set_digest is None
            or self.errors
        ):
            raise ProviderEnvelopeError("passing provider identity aggregate is incomplete")
        object.__setattr__(self, "envelope_digests", envelope_digests)
        object.__setattr__(self, "reuse_parent_aggregate_digests", parent_digests)
        object.__setattr__(self, "errors", tuple(sorted(set(self.errors))))

    @property
    def authority_identity(self) -> dict[str, Any]:
        return {
            "record_type": "ProviderIdentityAggregate",
            "schema": "promin.provider-identity-aggregate.v1",
            "module_closure_digest": self.module_closure_digest,
            "input_identity_digest": self.input_identity_digest,
            "status": self.status,
            "envelope_digests": list(self.envelope_digests),
            "coverage_union_digest": self.coverage_union_digest,
            "contributor_provenance_digest": self.contributor_provenance_digest,
            "language_driver_set_digest": self.language_driver_set_digest,
            "reuse_parent_aggregate_digests": list(self.reuse_parent_aggregate_digests),
            "errors": list(self.errors),
            "structural_metrics": {
                "envelope_count": self.metrics.envelope_count,
                "full_scan_envelope_count": self.metrics.full_scan_envelope_count,
                "reuse_envelope_count": self.metrics.reuse_envelope_count,
                "requested_module_count": self.metrics.requested_module_count,
                "covered_module_count": self.metrics.covered_module_count,
                "reused_module_count": self.metrics.reused_module_count,
                "contributor_count": self.metrics.contributor_count,
                "reused_contributor_count": self.metrics.reused_contributor_count,
            },
        }

    @property
    def aggregate_digest(self) -> str:
        return digest_value(self.authority_identity)

    def to_record(self) -> dict[str, Any]:
        return {
            **self.authority_identity,
            "aggregate_digest": self.aggregate_digest,
            "metrics": self.metrics.to_record(),
            "acceptance_pass": False,
            "pass_credit": False,
        }


def aggregate_large_project_envelopes(
    module_closure: BoundedModuleClosure,
    envelopes: Iterable[LargeProjectProviderEnvelope],
    *,
    expected_input_identity_digest: str | None = None,
    required_languages: Iterable[ProviderLanguage | str] = (),
    known_reuse_parent_aggregate_digests: Iterable[str] = (),
    max_envelopes: int = 4096,
) -> ProviderIdentityAggregate:
    """Aggregate exact FullScan/Reuse coverage without re-reading artifacts.

    The operation is intentionally pure after its input envelopes were sealed.
    Its timing and reuse counts make reuse observable, while its aggregate
    digest excludes elapsed wall time so equivalent input remains deterministic.
    """

    if not isinstance(module_closure, BoundedModuleClosure):
        raise ProviderEnvelopeError("large-project aggregation requires a typed module closure")
    if not isinstance(max_envelopes, int) or isinstance(max_envelopes, bool) or max_envelopes < 1:
        raise ProviderEnvelopeError("max_envelopes must be a positive integer")
    requested_languages = _canonical_languages(
        required_languages,
        label="aggregate required_languages",
        allow_empty=True,
    )
    known_parents = tuple(
        sorted(
            {
                _require_digest(value, label="known reuse parent aggregate digest")
                for value in known_reuse_parent_aggregate_digests
            }
        )
    )
    started = time.perf_counter()
    values = tuple(envelopes)
    if any(not isinstance(item, LargeProjectProviderEnvelope) for item in values):
        raise ProviderEnvelopeError("large-project aggregation requires typed large-project envelopes")

    def metrics_for(
        coverage: CoverageUnion | None,
        contributor_count: int,
    ) -> ProviderReuseMetrics:
        full = sum(item.envelope.scan_mode is ScanMode.FULL_SCAN for item in values)
        reuse = sum(item.envelope.scan_mode is ScanMode.REUSE for item in values)
        reused_modules = {
            module
            for item in values
            if item.envelope.scan_mode is ScanMode.REUSE
            for module in item.envelope.covered_modules
        }
        return ProviderReuseMetrics(
            elapsed_seconds=time.perf_counter() - started,
            envelope_count=len(values),
            full_scan_envelope_count=full,
            reuse_envelope_count=reuse,
            requested_module_count=len(module_closure.modules),
            covered_module_count=0 if coverage is None else len(coverage.covered_modules),
            reused_module_count=len(reused_modules),
            contributor_count=contributor_count,
            reused_contributor_count=contributor_count if reuse else 0,
        )

    if not module_closure.complete:
        return ProviderIdentityAggregate(
            module_closure_digest=module_closure.closure_digest,
            input_identity_digest=expected_input_identity_digest,
            status="UNAVAILABLE",
            envelope_digests=(),
            coverage_union_digest=None,
            contributor_provenance_digest=None,
            language_driver_set_digest=None,
            reuse_parent_aggregate_digests=(),
            metrics=metrics_for(None, 0),
            errors=("module closure is truncated",),
        )
    if len(values) > max_envelopes:
        return ProviderIdentityAggregate(
            module_closure_digest=module_closure.closure_digest,
            input_identity_digest=expected_input_identity_digest,
            status="UNAVAILABLE",
            envelope_digests=(),
            coverage_union_digest=None,
            contributor_provenance_digest=None,
            language_driver_set_digest=None,
            reuse_parent_aggregate_digests=(),
            metrics=metrics_for(None, 0),
            errors=("envelope bound reached",),
        )
    if not values:
        return ProviderIdentityAggregate(
            module_closure_digest=module_closure.closure_digest,
            input_identity_digest=expected_input_identity_digest,
            status="UNAVAILABLE",
            envelope_digests=(),
            coverage_union_digest=None,
            contributor_provenance_digest=None,
            language_driver_set_digest=None,
            reuse_parent_aggregate_digests=(),
            metrics=metrics_for(None, 0),
            errors=("no provider envelopes were supplied",),
        )

    expected = (
        _require_digest(expected_input_identity_digest, label="expected provider input identity")
        if expected_input_identity_digest is not None
        else values[0].envelope.input_identity_digest
    )
    provenance = values[0].contributor_provenance
    drivers = values[0].language_drivers
    required_roles = tuple(item.driver.role for item in drivers.drivers)
    errors: list[str] = []
    parent_digests: set[str] = set()
    envelope_digests: list[str] = []
    for value in values:
        envelope_digests.append(value.large_envelope_digest)
        if value.module_closure.closure_digest != module_closure.closure_digest:
            errors.append("envelope module closure differs from aggregate closure")
        if value.envelope.input_identity_digest != expected:
            errors.append("envelope input identity differs from aggregate input")
        if value.contributor_provenance.provenance_digest != provenance.provenance_digest:
            errors.append("envelope contributor provenance differs")
        if value.language_drivers.driver_set_digest != drivers.driver_set_digest:
            errors.append("envelope language driver set differs")
        present_languages = {item.language for item in value.language_drivers.drivers}
        if not set(requested_languages).issubset(present_languages):
            errors.append("envelope is missing a required language driver")
        if value.envelope.scan_mode is ScanMode.REUSE:
            parent = value.reuse_parent_aggregate_digest
            assert parent is not None  # established by LargeProjectProviderEnvelope
            parent_digests.add(parent)
            if parent not in known_parents:
                errors.append("Reuse envelope parent aggregate is not explicitly known")
    if len(set(envelope_digests)) != len(envelope_digests):
        errors.append("large-project aggregation contains duplicate envelopes")
    if not any(item.envelope.scan_mode is ScanMode.FULL_SCAN for item in values):
        errors.append("large-project aggregation has no FullScan contribution")

    coverage = provider_coverage_union(
        module_closure.modules,
        (item.envelope for item in values),
        expected_input_identity_digest=expected,
        required_driver_roles=required_roles,
    )
    if coverage.status != "PASS" or coverage.missing_modules:
        errors.append("FullScan/Reuse coverage union is incomplete")
    extra_coverage = set(coverage.covered_modules) - set(module_closure.modules)
    if extra_coverage:
        errors.append("provider coverage escapes the bounded module closure")
    status = "PASS" if not errors else "FAIL"
    return ProviderIdentityAggregate(
        module_closure_digest=module_closure.closure_digest,
        input_identity_digest=expected,
        status=status,
        envelope_digests=tuple(envelope_digests),
        coverage_union_digest=coverage.to_record()["coverage_union_digest"],
        contributor_provenance_digest=provenance.provenance_digest,
        language_driver_set_digest=drivers.driver_set_digest,
        reuse_parent_aggregate_digests=tuple(parent_digests),
        metrics=metrics_for(coverage, len(provenance.contributors)),
        errors=tuple(errors),
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
