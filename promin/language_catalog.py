"""Bounded, data-only composition of generic language capabilities.

The catalog reads portable JSON descriptions.  It deliberately does not probe a
compiler, start a language server, configure a build, or grant any authority.
Host observations are supplied as typed input and remain non-crediting facts.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
from itertools import islice
import json
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Final
import unicodedata


class LanguageCatalogError(ValueError):
    """Raised when a language capability catalog is invalid or outside bounds."""


PROFILE_SCHEMA: Final = "promin.language-capability-profile.v1"
CATALOG_SCHEMA: Final = "promin.language-catalog.v1"
COMPOSITION_SCHEMA: Final = "promin.composed-language-capabilities.v1"

_MAX_PROFILE_FILES: Final = 32
_MAX_PROFILE_BYTES: Final = 256 * 1024
_MAX_CATALOG_BYTES: Final = 1 * 1024 * 1024
_MAX_LIST_ITEMS: Final = 64
_MAX_JSON_DEPTH: Final = 16
_MAX_IDENTIFIER_LENGTH: Final = 128
_MAX_AVAILABILITY_DETAIL: Final = 512
_IDENTIFIER = re.compile(r"[a-z][a-z0-9.-]{0,127}\Z")
_PROFILE_ID = re.compile(r"[a-z][a-z0-9-]{0,127}\Z")
_EXTENSION = re.compile(r"\.[a-z0-9+_-]{1,31}\Z")
_SAFE_RELATIVE_PATH = re.compile(r"[A-Za-z0-9._/-]{1,192}\Z")
_AVAILABILITY_STATES: Final = frozenset({"AVAILABLE", "UNAVAILABLE", "FAIL", "SKIPPED"})
_DOCUMENTATION_CHOICES: Final = frozenset(
    {"ask", "accept", "decline", "profile-default"}
)
_OVERRIDE_MODES: Final = frozenset({"accept", "decline", "custom"})
_FAMILY_BY_LANGUAGE: Final = {
    "c": "c-family",
    "cpp": "c-family",
    "csharp": "csharp",
    "java": "java",
    "kotlin": "java",
    "scala": "java",
    "groovy": "java",
    "javascript": "javascript",
    "typescript": "javascript",
    "python": "python",
    # These two bounded extension families are admitted so an installed
    # language_profiles directory remains closed and deterministic.  They are
    # never selected by the C-family/C#/Java/JS/Python aliases below.
    "build": "tooling",
    "documentation": "tooling",
    "static-analysis": "tooling",
    "generic": "generic",
}
_LANGUAGE_ALIASES: Final = {
    "c": "c",
    "c++": "cpp",
    "cpp": "cpp",
    "c#": "csharp",
    "csharp": "csharp",
    "java": "java",
    "kotlin": "kotlin",
    "scala": "scala",
    "groovy": "groovy",
    "js": "javascript",
    "javascript": "javascript",
    "ts": "typescript",
    "typescript": "typescript",
    "py": "python",
    "python": "python",
    "build": "build",
    "documentation": "documentation",
    "static-analysis": "static-analysis",
    "generic": "generic",
}
_DEFAULT_EXTENSIONS: Final = {
    "c-family": (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx", ".ixx"),
    "csharp": (".cs",),
    "java": (".java",),
    "jvm": (".groovy", ".java", ".kt", ".kts", ".scala"),
    "javascript": (".cjs", ".js", ".mjs", ".ts", ".tsx"),
    "python": (".py", ".pyi"),
    "tooling": (".cmake", ".json", ".md", ".rst", ".toml", ".yaml", ".yml"),
    "generic": (".txt",),
}
_BASE_PROFILE_KEYS: Final = frozenset(
    {"schema", "profileId", "languages", "documentation", "verification", "artifactPolicy"}
)
_COMPACT_REQUIRED_KEYS: Final = _BASE_PROFILE_KEYS | frozenset({"sourceExtensions"})
_COMPACT_OPTIONAL_KEYS: Final = frozenset({"staticCapabilities", "claims"})
_SEMANTIC_PROFILE_KEYS: Final = frozenset(
    {
        "schema",
        "profileId",
        "languages",
        "sourceExtensions",
        "documentation",
        "verification",
        "artifactPolicy",
        "valueCategories",
        "binaryBoundary",
        "directVisibility",
        "compilerFailureProfiles",
        "semanticRoles",
        "documentationQuality",
        "interfaceWeight",
        "gateAdmission",
        "claims",
    }
)
_CLAIM_KEYS: Final = frozenset(
    {"acceptancePass", "passCredit", "productAcceptancePass", "releaseApproved"}
)


@dataclass(frozen=True)
class LanguageCapabilityProfile:
    """One immutable normalized profile with both canonical and source identity."""

    profile_id: str
    language_family: str
    languages: tuple[str, ...]
    source_extensions: tuple[str, ...]
    documentation_choice: str
    documentation_primary: tuple[str, ...]
    documentation_optional: tuple[str, ...]
    static_capabilities: tuple[str, ...]
    recommended_tools: tuple[str, ...]
    optional_tools: tuple[str, ...]
    artifact_policy: Mapping[str, object]
    profile_digest: str
    source_digest: str
    canonical_bytes: bytes


@dataclass(frozen=True)
class BundledLanguageProfile:
    """Exact distribution identity plus detector aliases owned by that profile."""

    filename: str
    profile_id: str
    language_family: str
    languages: tuple[str, ...]
    technology_language_aliases: tuple[tuple[str, str], ...] = ()


BUNDLED_LANGUAGE_PROFILES: Final[tuple[BundledLanguageProfile, ...]] = (
    BundledLanguageProfile(
        "c-family-semantic.json",
        "c-family-semantic",
        "c-family",
        ("c", "cpp"),
        (
            ("cmake", "cpp"),
            ("visual-studio", "cpp"),
            ("windows-native", "cpp"),
        ),
    ),
    BundledLanguageProfile(
        "csharp-semantic.json",
        "csharp-semantic",
        "csharp",
        ("csharp",),
        (("dotnet", "csharp"),),
    ),
    BundledLanguageProfile(
        "javascript-typescript-semantic.json",
        "javascript-typescript-semantic",
        "javascript",
        ("javascript", "typescript"),
        (
            ("expo", "javascript"),
            ("express", "javascript"),
            ("nextjs", "javascript"),
            ("node", "javascript"),
            ("react", "javascript"),
            ("react-native", "javascript"),
            ("svelte", "javascript"),
            ("supabase", "javascript"),
            ("vite", "javascript"),
            ("vue", "javascript"),
        ),
    ),
    BundledLanguageProfile(
        "jvm-semantic.json",
        "jvm-semantic",
        "java",
        ("java", "kotlin", "scala", "groovy"),
        (("android", "kotlin"), ("gradle", "groovy")),
    ),
    BundledLanguageProfile(
        "open-source-tooling.json",
        "open-source-tooling",
        "tooling",
        ("build", "documentation", "static-analysis"),
        (("containers", "build"),),
    ),
    BundledLanguageProfile(
        "python-semantic.json",
        "python-semantic",
        "python",
        ("python",),
    ),
    BundledLanguageProfile(
        "weak-host-fallback.json",
        "weak-host-fallback",
        "generic",
        ("generic",),
        (
            ("dart", "generic"),
            ("go", "generic"),
            ("rust", "generic"),
            ("swift", "generic"),
        ),
    ),
)


def languages_for_detected_technologies(
    technologies: Iterable[str],
) -> tuple[str, ...]:
    """Resolve detector facts to canonical languages in bundled-profile order.

    Direct language facts retain their exact identity (for example TypeScript
    stays ``typescript`` and Kotlin stays ``kotlin``).  Ecosystem aliases live
    beside the one bundled profile that owns their target language, so callers
    cannot maintain a second mapping.  Unknown future facts are ignored until a
    bundled profile explicitly owns them.
    """

    if isinstance(technologies, (str, bytes)):
        raise LanguageCatalogError(
            "technologies must be an iterable of technology identifiers"
        )
    try:
        requested = list(islice(iter(technologies), _MAX_LIST_ITEMS + 1))
    except TypeError as error:
        raise LanguageCatalogError(
            "technologies must be an iterable of technology identifiers"
        ) from error
    if len(requested) > _MAX_LIST_ITEMS:
        raise LanguageCatalogError("technologies exceeds the bounded item limit")

    ordered_languages: list[str] = []
    technology_languages: dict[str, str] = {}
    for descriptor in BUNDLED_LANGUAGE_PROFILES:
        for language in descriptor.languages:
            if language in technology_languages:
                raise LanguageCatalogError(
                    f"bundled technology identity is ambiguous: {language}"
                )
            technology_languages[language] = language
            ordered_languages.append(language)
        for technology, language in descriptor.technology_language_aliases:
            if language not in descriptor.languages:
                raise LanguageCatalogError(
                    f"bundled technology alias {technology} targets another profile"
                )
            if technology in technology_languages:
                raise LanguageCatalogError(
                    f"bundled technology identity is ambiguous: {technology}"
                )
            technology_languages[technology] = language

    selected: set[str] = set()
    for index, raw_value in enumerate(requested):
        if not isinstance(raw_value, str):
            raise LanguageCatalogError(f"technologies[{index}] must be a string")
        technology = unicodedata.normalize("NFC", raw_value).casefold().strip()
        language = technology_languages.get(technology)
        if language is not None:
            selected.add(language)
    return tuple(language for language in ordered_languages if language in selected)


@dataclass(frozen=True)
class LanguageCatalog:
    """A closed set of profile documents, ordered by profile identity."""

    profiles: tuple[LanguageCapabilityProfile, ...]
    catalog_digest: str
    source_digest: str

    def profile(self, profile_id: str) -> LanguageCapabilityProfile:
        """Return one catalog member or fail instead of falling back implicitly."""

        for profile in self.profiles:
            if profile.profile_id == profile_id:
                return profile
        raise LanguageCatalogError(f"unknown language profile: {profile_id}")


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _bounded_sequence(
    value: object,
    label: str,
    maximum_items: int,
) -> tuple[object, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise LanguageCatalogError(f"{label} must be an array")
    if len(value) > maximum_items:
        raise LanguageCatalogError(f"{label} exceeds its bounded item count")
    return tuple(value)


def _normalise_json(
    value: object,
    *,
    depth: int = 0,
) -> object:
    if depth > _MAX_JSON_DEPTH:
        raise LanguageCatalogError("profile JSON exceeds its bounded nesting depth")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        source = _bounded_mapping(value, "profile JSON object", _MAX_LIST_ITEMS)
        for raw_key, raw_value in source.items():
            if not isinstance(raw_key, str):
                raise LanguageCatalogError("profile JSON object keys must be strings")
            key = unicodedata.normalize("NFC", raw_key)
            if key in normalized:
                raise LanguageCatalogError("profile JSON contains duplicate normalized keys")
            normalized[key] = _normalise_json(raw_value, depth=depth + 1)
        return normalized
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        items = _bounded_sequence(value, "profile JSON array", _MAX_LIST_ITEMS)
        return [_normalise_json(item, depth=depth + 1) for item in items]
    return value


def _duplicate_key_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise LanguageCatalogError(f"profile JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json(value: str) -> None:
    raise LanguageCatalogError(f"profile JSON contains non-finite value: {value}")


def _bounded_mapping(
    value: object,
    label: str,
    maximum_keys: int,
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise LanguageCatalogError(f"{label} must be an object")
    if len(value) > maximum_keys:
        raise LanguageCatalogError(f"{label} exceeds its bounded key count")
    result = dict(value)
    if any(not isinstance(key, str) for key in result):
        raise LanguageCatalogError(f"{label} keys must be strings")
    return result


def _mapping(value: object, label: str) -> Mapping[str, object]:
    return _bounded_mapping(value, label, _MAX_LIST_ITEMS)


def _exact_keys(value: object, keys: frozenset[str], label: str) -> Mapping[str, object]:
    mapping = _bounded_mapping(value, label, len(keys))
    observed_keys = frozenset(mapping)
    if observed_keys != keys:
        missing = sorted(keys - observed_keys)
        unexpected = sorted(observed_keys - keys)
        raise LanguageCatalogError(
            f"{label} keys must be exact; missing={missing}; unexpected={unexpected}"
        )
    return mapping


def _identifier(value: object, label: str, *, profile_id: bool = False) -> str:
    expression = _PROFILE_ID if profile_id else _IDENTIFIER
    if (
        not isinstance(value, str)
        or not expression.fullmatch(value)
        or value != value.strip()
        or len(value) > _MAX_IDENTIFIER_LENGTH
    ):
        raise LanguageCatalogError(f"{label} must be a bounded lowercase identifier")
    return value


def _identifier_list(value: object, label: str, *, allow_empty: bool) -> tuple[str, ...]:
    items = _bounded_sequence(value, label, _MAX_LIST_ITEMS)
    result = tuple(
        _identifier(item, f"{label}[{index}]")
        for index, item in enumerate(items)
    )
    if not allow_empty and not result:
        raise LanguageCatalogError(f"{label} must not be empty")
    if len(result) != len(set(result)):
        raise LanguageCatalogError(f"{label} contains duplicates")
    return result


def _language_list(value: object) -> tuple[str, ...]:
    items = _bounded_sequence(value, "languages", 4)
    if not items:
        raise LanguageCatalogError("languages must contain one through four identifiers")
    normalized: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, str) or item not in _FAMILY_BY_LANGUAGE:
            raise LanguageCatalogError(f"languages[{index}] is not a supported canonical language")
        normalized.append(item)
    if len(normalized) != len(set(normalized)):
        raise LanguageCatalogError("languages contains duplicates")
    families = {_FAMILY_BY_LANGUAGE[item] for item in normalized}
    if len(families) != 1:
        raise LanguageCatalogError("one profile must describe exactly one language family")
    return tuple(normalized)


def _source_extensions(value: object, family: str) -> tuple[str, ...]:
    if value is None:
        return _DEFAULT_EXTENSIONS[family]
    items = _bounded_sequence(value, "sourceExtensions", _MAX_LIST_ITEMS)
    if not items:
        raise LanguageCatalogError("sourceExtensions must contain one through the bounded item limit")
    extensions: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, str) or not _EXTENSION.fullmatch(item):
            raise LanguageCatalogError(f"sourceExtensions[{index}] must be a safe suffix")
        extensions.append(item)
    if len(extensions) != len(set(extensions)):
        raise LanguageCatalogError("sourceExtensions contains duplicates")
    return tuple(extensions)


def _documentation(value: object) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    document = _exact_keys(
        value,
        frozenset({"recommended", "userChoice", "primary", "optional"}),
        "documentation",
    )
    if not isinstance(document["recommended"], bool):
        raise LanguageCatalogError("documentation.recommended must be boolean")
    choice = document["userChoice"]
    if choice not in _DOCUMENTATION_CHOICES:
        raise LanguageCatalogError("documentation.userChoice is invalid")
    primary = _identifier_list(document["primary"], "documentation.primary", allow_empty=False)
    optional = _identifier_list(document["optional"], "documentation.optional", allow_empty=True)
    if set(primary) & set(optional):
        raise LanguageCatalogError("documentation primary and optional capabilities overlap")
    return str(choice), primary, optional


def _verification(value: object) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    verification = _exact_keys(
        value,
        frozenset({"cheapRequired", "recommended", "optional"}),
        "verification",
    )
    cheap = _identifier_list(verification["cheapRequired"], "verification.cheapRequired", allow_empty=True)
    recommended = _identifier_list(
        verification["recommended"], "verification.recommended", allow_empty=True
    )
    optional = _identifier_list(verification["optional"], "verification.optional", allow_empty=True)
    if set(cheap) & set(recommended) or set(cheap) & set(optional) or set(recommended) & set(optional):
        raise LanguageCatalogError("verification capability tiers overlap")
    return cheap, recommended, optional


def _safe_relative_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not _SAFE_RELATIVE_PATH.fullmatch(value):
        raise LanguageCatalogError(f"{label} must be a safe portable relative path")
    pieces = value.split("/")
    if value.startswith("/") or any(piece in {"", ".", ".."} for piece in pieces):
        raise LanguageCatalogError(f"{label} must be a safe portable relative path")
    return value


def _artifact_policy(value: object) -> Mapping[str, object]:
    policy = _exact_keys(
        value,
        frozenset({"defaultMode", "trackedSummary", "diagnosticRoot", "forensicRoot"}),
        "artifactPolicy",
    )
    if policy["defaultMode"] not in {"minimal", "diagnostic", "forensic"}:
        raise LanguageCatalogError("artifactPolicy.defaultMode is invalid")
    if not isinstance(policy["trackedSummary"], bool):
        raise LanguageCatalogError("artifactPolicy.trackedSummary must be boolean")
    return MappingProxyType(
        {
            "defaultMode": str(policy["defaultMode"]),
            "trackedSummary": policy["trackedSummary"],
            "diagnosticRoot": _safe_relative_path(
                policy["diagnosticRoot"], "artifactPolicy.diagnosticRoot"
            ),
            "forensicRoot": _safe_relative_path(
                policy["forensicRoot"], "artifactPolicy.forensicRoot"
            ),
        }
    )


def _claims(value: object | None) -> None:
    if value is None:
        return
    claims = _exact_keys(value, _CLAIM_KEYS, "claims")
    if any(item is not False for item in claims.values()):
        raise LanguageCatalogError("language profile claims must remain false")


def _validate_semantic_profile(document: Mapping[str, object]) -> None:
    """Reuse the existing full C-family semantic validator for its exact layout."""

    try:
        from .language_analysis import AnalysisError, parse_language_profile

        parse_language_profile(document)
    except (ImportError, AnalysisError) as error:
        raise LanguageCatalogError(f"full semantic profile is invalid: {error}") from error


def _profile_layout(document: Mapping[str, object]) -> tuple[bool, bool]:
    keys = frozenset(document)
    if keys == _SEMANTIC_PROFILE_KEYS:
        return True, True
    if keys == _BASE_PROFILE_KEYS:
        return False, False
    if _COMPACT_REQUIRED_KEYS.issubset(keys) and keys <= (
        _COMPACT_REQUIRED_KEYS | _COMPACT_OPTIONAL_KEYS
    ):
        return False, True
    raise LanguageCatalogError("language profile uses an unsupported strict field layout")


def _ordered_union(*groups: Sequence[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for item in group:
            if item not in seen:
                seen.add(item)
                result.append(item)
    return tuple(result)


def parse_language_catalog_profile(
    document: Mapping[str, object], *, source_bytes: bytes | None = None
) -> LanguageCapabilityProfile:
    """Validate one supported profile layout and bind exact source/canonical digests."""

    normalized_object = _normalise_json(_mapping(document, "language profile"))
    if not isinstance(normalized_object, Mapping):
        raise LanguageCatalogError("language profile must be an object")
    normalized = _mapping(normalized_object, "language profile")
    semantic_layout, has_extensions = _profile_layout(normalized)
    if normalized.get("schema") != PROFILE_SCHEMA:
        raise LanguageCatalogError(f"language profile schema must be {PROFILE_SCHEMA}")
    if semantic_layout:
        _validate_semantic_profile(normalized)

    profile_id = _identifier(normalized["profileId"], "profileId", profile_id=True)
    languages = _language_list(normalized["languages"])
    family = _FAMILY_BY_LANGUAGE[languages[0]]
    source_extensions = _source_extensions(
        normalized.get("sourceExtensions") if has_extensions else None, family
    )
    documentation_choice, primary_docs, optional_docs = _documentation(normalized["documentation"])
    cheap_required, recommended_tools, optional_tools = _verification(normalized["verification"])
    explicit_static = _identifier_list(
        normalized.get("staticCapabilities", []),
        "staticCapabilities",
        allow_empty=True,
    )
    if set(cheap_required) & set(explicit_static):
        raise LanguageCatalogError("staticCapabilities duplicates verification.cheapRequired")
    static_capabilities = _ordered_union(cheap_required, explicit_static)
    if not static_capabilities:
        raise LanguageCatalogError("a language profile must declare at least one static capability")
    artifact_policy = _artifact_policy(normalized["artifactPolicy"])
    _claims(normalized.get("claims"))

    canonical = _canonical_bytes(normalized)
    return LanguageCapabilityProfile(
        profile_id=profile_id,
        language_family=family,
        languages=languages,
        source_extensions=source_extensions,
        documentation_choice=documentation_choice,
        documentation_primary=primary_docs,
        documentation_optional=optional_docs,
        static_capabilities=static_capabilities,
        recommended_tools=recommended_tools,
        optional_tools=optional_tools,
        artifact_policy=artifact_policy,
        profile_digest=hashlib.sha256(canonical).hexdigest(),
        source_digest=hashlib.sha256(source_bytes if source_bytes is not None else canonical).hexdigest(),
        canonical_bytes=canonical,
    )


def _parse_profile_source(source_bytes: bytes) -> Mapping[str, object]:
    try:
        parsed = json.loads(
            source_bytes.decode("utf-8"),
            object_pairs_hook=_duplicate_key_object,
            parse_constant=_reject_nonfinite_json,
        )
    except LanguageCatalogError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise LanguageCatalogError(
            f"language profile JSON is invalid: {type(error).__name__}"
        ) from error
    if not isinstance(parsed, Mapping):
        raise LanguageCatalogError("language profile JSON root must be an object")
    return _mapping(parsed, "language profile")


def _read_profile(path: Path) -> tuple[Mapping[str, object], bytes]:
    try:
        if not path.is_file():
            raise LanguageCatalogError("language profile must be a file")
        with path.open("rb") as handle:
            source_bytes = handle.read(_MAX_PROFILE_BYTES + 1)
    except LanguageCatalogError:
        raise
    except OSError as error:
        raise LanguageCatalogError(
            f"language profile is unavailable: {type(error).__name__}"
        ) from error
    if len(source_bytes) > _MAX_PROFILE_BYTES:
        raise LanguageCatalogError("language profile exceeds the bounded byte limit")
    return _parse_profile_source(source_bytes), source_bytes


def _directory_entries(path: Path, maximum: int) -> tuple[Path, ...]:
    try:
        if not path.is_dir():
            raise LanguageCatalogError("language catalog path must be a file or directory")
        entries = list(islice(path.iterdir(), maximum + 1))
    except LanguageCatalogError:
        raise
    except OSError as error:
        raise LanguageCatalogError(
            f"language catalog cannot be enumerated: {type(error).__name__}"
        ) from error
    if len(entries) > maximum:
        raise LanguageCatalogError("language catalog exceeds the bounded profile count")
    return tuple(sorted(entries, key=lambda item: (item.name.casefold(), item.name)))


def _load_profile_entries(
    entries: Sequence[Path],
) -> tuple[LanguageCapabilityProfile, ...]:
    records: list[LanguageCapabilityProfile] = []
    total_bytes = 0
    for entry in entries:
        document, source_bytes = _read_profile(entry)
        total_bytes += len(source_bytes)
        if total_bytes > _MAX_CATALOG_BYTES:
            raise LanguageCatalogError("language catalog exceeds the bounded byte limit")
        records.append(
            parse_language_catalog_profile(document, source_bytes=source_bytes)
        )
    return tuple(records)


def _generic_profile_entries(directory: Path) -> tuple[Path, ...]:
    entries = _directory_entries(directory, _MAX_PROFILE_FILES)
    profiles: list[Path] = []
    for entry in entries:
        if entry.name.endswith(".json"):
            if not entry.is_file():
                raise LanguageCatalogError("language catalog member must be a file")
            profiles.append(entry)
        elif entry.is_dir():
            raise LanguageCatalogError(
                "language catalog does not permit nested directories"
            )
    if not profiles:
        raise LanguageCatalogError(
            "language catalog does not contain a JSON profile"
        )
    return tuple(profiles)


def _bundled_profile_entries(directory: Path) -> tuple[Path, ...]:
    expected_names = {
        descriptor.filename for descriptor in BUNDLED_LANGUAGE_PROFILES
    }
    entries = _directory_entries(directory, _MAX_PROFILE_FILES)
    actual_names = {entry.name for entry in entries}
    missing = sorted(expected_names - actual_names)
    unexpected = sorted(actual_names - expected_names)
    if missing or unexpected:
        raise LanguageCatalogError(
            "bundled language catalog filenames must be exact; "
            f"missing={missing}; unexpected={unexpected}"
        )
    if any(not entry.is_file() for entry in entries):
        raise LanguageCatalogError("bundled language catalog members must be files")
    return entries


def _language_catalog(records: Sequence[LanguageCapabilityProfile]) -> LanguageCatalog:
    ordered = tuple(sorted(records, key=lambda profile: profile.profile_id))
    profile_ids = [profile.profile_id for profile in ordered]
    if len(profile_ids) != len(set(profile_ids)):
        raise LanguageCatalogError("language catalog contains duplicate profileId values")
    language_owners: dict[str, str] = {}
    for profile in ordered:
        for language in profile.languages:
            previous = language_owners.setdefault(language, profile.profile_id)
            if previous != profile.profile_id:
                raise LanguageCatalogError(
                    f"language catalog assigns {language} to multiple profiles: {previous}, {profile.profile_id}"
                )
    catalog_identity = {
        "schema": CATALOG_SCHEMA,
        "profiles": [
            {"profile_id": profile.profile_id, "profile_digest": profile.profile_digest}
            for profile in ordered
        ],
    }
    source_identity = {
        "schema": CATALOG_SCHEMA,
        "profiles": [
            {"profile_id": profile.profile_id, "source_digest": profile.source_digest}
            for profile in ordered
        ],
    }
    return LanguageCatalog(
        profiles=ordered,
        catalog_digest=_digest(catalog_identity),
        source_digest=_digest(source_identity),
    )


def _load_generic_directory(directory: Path) -> LanguageCatalog:
    return _language_catalog(_load_profile_entries(_generic_profile_entries(directory)))


def _load_single_profile(path: Path) -> LanguageCatalog:
    if path.suffix != ".json":
        raise LanguageCatalogError(
            "language catalog file must use the .json suffix"
        )
    document, source_bytes = _read_profile(path)
    return _language_catalog(
        (parse_language_catalog_profile(document, source_bytes=source_bytes),)
    )


def _load_catalog_path(path: Path, *, bundled: bool) -> LanguageCatalog:
    if path.is_file():
        if bundled:
            raise LanguageCatalogError("bundled language catalog must be a directory")
        return _load_single_profile(path)
    if path.is_dir():
        return _load_bundled_directory(path) if bundled else _load_generic_directory(path)
    raise LanguageCatalogError("language catalog path must be a file or directory")


def _translate_catalog_path_error(
    path: Path | str,
    *,
    bundled: bool,
) -> LanguageCatalog:
    try:
        return _load_catalog_path(Path(path), bundled=bundled)
    except LanguageCatalogError:
        raise
    except OSError as error:
        label = "bundled language catalog" if bundled else "language catalog"
        raise LanguageCatalogError(f"{label} is unavailable") from error


def load_language_catalog(path: Path | str) -> LanguageCatalog:
    """Load one bounded profile or directory with portable filesystem calls."""

    return _translate_catalog_path_error(path, bundled=False)


def load_bundled_language_catalog(path: Path | str) -> LanguageCatalog:
    """Load the exact distribution catalog and bind each filename to its profile."""

    return _translate_catalog_path_error(path, bundled=True)


def _load_bundled_directory(directory: Path) -> LanguageCatalog:
    expected = {profile.filename: profile for profile in BUNDLED_LANGUAGE_PROFILES}
    entries = _bundled_profile_entries(directory)
    records: list[LanguageCapabilityProfile] = []
    total_bytes = 0
    for entry in entries:
        document, source_bytes = _read_profile(entry)
        total_bytes += len(source_bytes)
        if total_bytes > _MAX_CATALOG_BYTES:
            raise LanguageCatalogError(
                "language catalog exceeds the bounded byte limit"
            )
        parsed = parse_language_catalog_profile(document, source_bytes=source_bytes)
        descriptor = expected[entry.name]
        if (
            parsed.profile_id != descriptor.profile_id
            or parsed.language_family != descriptor.language_family
            or parsed.languages != descriptor.languages
        ):
            raise LanguageCatalogError(
                f"bundled language profile identity differs from {entry.name}"
            )
        records.append(parsed)
    return _language_catalog(records)


def _requested_languages(languages: Iterable[str]) -> tuple[str, ...]:
    if isinstance(languages, (str, bytes)):
        raise LanguageCatalogError("languages must be an iterable of language identifiers")
    try:
        requested = list(islice(iter(languages), _MAX_LIST_ITEMS + 1))
    except TypeError as error:
        raise LanguageCatalogError(
            "languages must be an iterable of language identifiers"
        ) from error
    if not requested or len(requested) > _MAX_LIST_ITEMS:
        raise LanguageCatalogError(
            "languages must contain one through the bounded item limit"
        )
    result: list[str] = []
    for index, raw_value in enumerate(requested):
        if not isinstance(raw_value, str):
            raise LanguageCatalogError(f"languages[{index}] must be a string")
        value = unicodedata.normalize("NFC", raw_value).casefold().strip()
        canonical = _LANGUAGE_ALIASES.get(value)
        if canonical is None:
            raise LanguageCatalogError(f"languages[{index}] is not a supported language alias")
        if canonical in result:
            raise LanguageCatalogError("languages contains duplicate canonical values")
        result.append(canonical)
    return tuple(sorted(result))


def _selection(value: object, label: str, allowed: tuple[str, ...]) -> tuple[str, tuple[str, ...]]:
    selection = _exact_keys(value, frozenset({"mode", "items"}), label)
    mode = selection["mode"]
    if mode not in _OVERRIDE_MODES:
        raise LanguageCatalogError(f"{label}.mode is invalid")
    items = _identifier_list(selection["items"], f"{label}.items", allow_empty=True)
    if mode in {"accept", "decline"} and items:
        raise LanguageCatalogError(f"{label}.{mode} must not specify items")
    if mode == "custom" and not items:
        raise LanguageCatalogError(f"{label}.custom must specify one or more items")
    undeclared = sorted(set(items) - set(allowed))
    if undeclared:
        raise LanguageCatalogError(f"{label} may select only declared capabilities: {undeclared}")
    return str(mode), items


def _profile_override(
    value: object | None, profile: LanguageCapabilityProfile
) -> tuple[tuple[str, tuple[str, ...]], tuple[str, tuple[str, ...]]]:
    if value is None:
        documentation = profile.documentation_choice
        if documentation in {"accept", "profile-default"}:
            docs = ("accept", profile.documentation_primary)
        elif documentation == "decline":
            docs = ("decline", ())
        else:
            docs = ("ask", ())
        return docs, ("profile-default", profile.recommended_tools)

    allowed_fields = frozenset({"documentation", "tools"})
    override = _bounded_mapping(
        value,
        f"override for {profile.profile_id}",
        len(allowed_fields),
    )
    if not frozenset(override) <= allowed_fields or not override:
        raise LanguageCatalogError(f"override for {profile.profile_id} is not bounded")
    documentation = _profile_override(None, profile)[0]
    tools = _profile_override(None, profile)[1]
    if "documentation" in override:
        mode, items = _selection(
            override["documentation"],
            f"override {profile.profile_id}.documentation",
            _ordered_union(profile.documentation_primary, profile.documentation_optional),
        )
        documentation = (
            ("accept", profile.documentation_primary)
            if mode == "accept"
            else ("decline", ())
            if mode == "decline"
            else ("custom", items)
        )
    if "tools" in override:
        mode, items = _selection(
            override["tools"],
            f"override {profile.profile_id}.tools",
            _ordered_union(profile.recommended_tools, profile.optional_tools),
        )
        tools = (
            ("accept", profile.recommended_tools)
            if mode == "accept"
            else ("decline", ())
            if mode == "decline"
            else ("custom", items)
        )
    return documentation, tools


def _availability(
    value: Mapping[str, object] | None, allowed_capabilities: set[str]
) -> dict[str, dict[str, str]]:
    if value is None:
        return {}
    observations = _bounded_mapping(
        value,
        "availability",
        len(allowed_capabilities),
    )
    result: dict[str, dict[str, str]] = {}
    for capability, raw_record in observations.items():
        capability_id = _identifier(capability, "availability capability")
        if capability_id not in allowed_capabilities:
            raise LanguageCatalogError(
                f"availability names a capability outside selected profiles: {capability_id}"
            )
        record = _exact_keys(raw_record, frozenset({"status", "detail"}), f"availability {capability_id}")
        status = record["status"]
        if status == "PASS":
            raise LanguageCatalogError("availability must not report PASS; static composition did not run a tool")
        if status not in _AVAILABILITY_STATES:
            raise LanguageCatalogError(f"availability {capability_id}.status is invalid")
        detail = record["detail"]
        if (
            not isinstance(detail, str)
            or not detail
            or len(detail) > _MAX_AVAILABILITY_DETAIL
            or detail != detail.strip()
            or "\n" in detail
            or "\r" in detail
        ):
            raise LanguageCatalogError(f"availability {capability_id}.detail is not bounded portable text")
        result[capability_id] = {"status": str(status), "detail": detail}
    return result


def _status(unresolved: Sequence[str], selected: Sequence[dict[str, object]]) -> str:
    required = [record for record in selected if record["required"] is True]
    required_statuses = {str(record["status"]) for record in required}
    if "FAIL" in required_statuses:
        return "FAIL"
    if unresolved or "UNAVAILABLE" in required_statuses:
        return "UNAVAILABLE"
    if "SKIPPED" in required_statuses:
        return "SKIPPED"
    return "AVAILABLE"


def compose_language_capabilities(
    catalog: LanguageCatalog,
    *,
    languages: Iterable[str],
    availability: Mapping[str, object] | None = None,
    overrides: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Compose selected profiles without probing or promoting any capability.

    Overrides can only select a declared documentation or optional/recommended
    tool capability.  They cannot change languages, static capabilities,
    artifact policy, profile identity, or the always-false claim boundary.
    """

    if not isinstance(catalog, LanguageCatalog):
        raise LanguageCatalogError("catalog must be loaded by load_language_catalog")
    requested = _requested_languages(languages)
    selected_profiles = tuple(
        profile
        for profile in catalog.profiles
        if set(profile.languages).intersection(requested)
    )
    resolved = {language for profile in selected_profiles for language in profile.languages}
    unresolved = sorted(set(requested) - resolved)
    override_mapping = (
        _bounded_mapping(
            overrides,
            "overrides",
            len(selected_profiles),
        )
        if overrides is not None
        else {}
    )
    selected_ids = {profile.profile_id for profile in selected_profiles}
    unknown_override_ids = sorted(set(override_mapping) - selected_ids)
    if unknown_override_ids:
        raise LanguageCatalogError(
            f"overrides must name a selected profile only: {unknown_override_ids}"
        )

    declared_capabilities = {
        capability
        for profile in selected_profiles
        for capability in _ordered_union(
            profile.static_capabilities,
            profile.documentation_primary,
            profile.documentation_optional,
            profile.recommended_tools,
            profile.optional_tools,
        )
    }
    all_catalog_capabilities = {
        capability
        for profile in catalog.profiles
        for capability in _ordered_union(
            profile.static_capabilities,
            profile.documentation_primary,
            profile.documentation_optional,
            profile.recommended_tools,
            profile.optional_tools,
        )
    }
    observations = _availability(availability, all_catalog_capabilities)

    static_capabilities: set[str] = set()
    selected_documentation: set[str] = set()
    selected_tools: set[str] = set()
    roles: dict[str, set[str]] = {}
    selections: list[dict[str, object]] = []
    artifact_policies: list[dict[str, object]] = []
    for profile in selected_profiles:
        documentation, tools = _profile_override(override_mapping.get(profile.profile_id), profile)
        static_capabilities.update(profile.static_capabilities)
        selected_documentation.update(documentation[1])
        selected_tools.update(tools[1])
        for capability in profile.static_capabilities:
            roles.setdefault(capability, set()).add("static")
        for capability in documentation[1]:
            roles.setdefault(capability, set()).add("documentation")
        for capability in tools[1]:
            roles.setdefault(capability, set()).add("tool")
        selections.append(
            {
                "profile_id": profile.profile_id,
                "documentation": {"mode": documentation[0], "items": list(documentation[1])},
                "tools": {"mode": tools[0], "items": list(tools[1])},
            }
        )
        artifact_policies.append(
            {"profile_id": profile.profile_id, **dict(profile.artifact_policy)}
        )

    selected_records: list[dict[str, object]] = []
    for capability in sorted(roles):
        observed = observations.get(capability, {"status": "SKIPPED", "detail": "not-observed"})
        capability_roles = sorted(roles[capability])
        selected_records.append(
            {
                "capability": capability,
                "roles": capability_roles,
                "required": "static" in capability_roles,
                "status": observed["status"],
                "detail": observed["detail"],
            }
        )
    observation_records = [
        {"capability": capability, **record}
        for capability, record in sorted(observations.items())
        if capability in declared_capabilities
    ]
    claims = {
        "acceptance_pass": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
        "release_approved": False,
    }
    identity = {
        "schema": COMPOSITION_SCHEMA,
        "catalog_digest": catalog.catalog_digest,
        "catalog_source_digest": catalog.source_digest,
        "requested_languages": list(requested),
        "resolved_languages": sorted(set(requested) - set(unresolved)),
        "unresolved_languages": unresolved,
        "language_families": sorted(
            {profile.language_family for profile in selected_profiles}
        ),
        "selected_profile_ids": [profile.profile_id for profile in selected_profiles],
        "profile_digests": [
            {"profile_id": profile.profile_id, "digest": profile.profile_digest}
            for profile in selected_profiles
        ],
        "source_extensions": sorted(
            {extension for profile in selected_profiles for extension in profile.source_extensions}
        ),
        "selected_static_capabilities": sorted(static_capabilities),
        "selected_documentation": sorted(selected_documentation),
        "selected_tools": sorted(selected_tools),
        "profile_selections": selections,
        "artifact_policies": artifact_policies,
        "availability_observations": observation_records,
        "availability_results": selected_records,
        "status": _status(unresolved, selected_records),
        "claims": claims,
        "acceptance_pass": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
        "release_approved": False,
    }
    return {**identity, "composition_digest": _digest(identity)}


def compose_language_catalog(*args: object, **kwargs: object) -> dict[str, object]:
    """Compatibility spelling for callers that name the operation after its catalog."""

    return compose_language_capabilities(*args, **kwargs)  # type: ignore[arg-type]


__all__ = [
    "BUNDLED_LANGUAGE_PROFILES",
    "BundledLanguageProfile",
    "CATALOG_SCHEMA",
    "COMPOSITION_SCHEMA",
    "LanguageCapabilityProfile",
    "LanguageCatalog",
    "LanguageCatalogError",
    "PROFILE_SCHEMA",
    "compose_language_capabilities",
    "compose_language_catalog",
    "languages_for_detected_technologies",
    "load_bundled_language_catalog",
    "load_language_catalog",
    "parse_language_catalog_profile",
]
