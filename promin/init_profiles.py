"""Generic, non-authoritative capability-profile resolution for ``promin init``.

The module deliberately resolves configuration only.  It neither discovers a
host tool nor grants an action capability: Core authority, Grants, Leases, and
their effect scopes remain the only route to a mutation.  Keeping that boundary
here makes profile selection safe to use before an activation is published.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import islice
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .canonical import (
    DEFAULT_LIMITS,
    CanonicalError,
    canonical_bytes,
    digest_value,
    parse_json_strict,
)
from .language_catalog import (
    LanguageCatalog,
    LanguageCatalogError,
    LanguageCapabilityProfile,
    compose_language_capabilities,
    load_bundled_language_catalog,
)
from .resources import ResourceError, bundle_root


class InitProfileError(ValueError):
    """Raised when a capability profile or its selected overlay is invalid."""


INIT_PROFILE_SCHEMA = "promin.init-profile.v1"
LANGUAGE_CAPABILITY_PROFILE_SCHEMA = "promin.language-capability-profile.v1"
INIT_ANALYSIS_CHOICE_SCHEMA = "promin.init-analysis-choice.v1"
RESOLVED_INIT_PROFILE_SCHEMA = "promin.resolved-init-profile.v1"
EXPERT_INIT_BUNDLE_SCHEMA = "promin.expert-init-bundle.v1"

_SELECTION_SOURCES = (
    "default",
    "host-profile",
    "project-package",
    "cli",
    "interactive-user",
)
_ANALYSIS_PROFILES = frozenset({"off", "minimal", "standard", "diagnostic"})
_ARTIFACT_PROFILES = frozenset({"minimal", "standard", "diagnostic", "forensic"})
_AUTONOMY_PROFILES = frozenset({"ask", "standing-reversible"})
_PROVIDER_STRATEGIES = frozenset({"reuse-preferred", "full-scan"})
_CHOICES = frozenset({"ask", "accept", "decline", "custom", "profile-default"})
_RESOLVED_CHOICES = frozenset({"accept", "decline", "custom"})
_TOOL_STATES = frozenset({"AVAILABLE", "PASS", "UNAVAILABLE", "FAIL", "SKIPPED"})


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise InitProfileError(f"{label} must be an object")
    return dict(value)


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise InitProfileError(f"{label} must be a non-empty bounded string")
    if any(character in value for character in "\\/\r\n\t"):
        raise InitProfileError(f"{label} must be an identifier, not a path")
    return value


def _string_list(value: object, label: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list):
        raise InitProfileError(f"{label} must be an array")
    result = [_id(item, f"{label} item") for item in value]
    if len(result) != len(set(result)):
        raise InitProfileError(f"{label} contains duplicates")
    if not allow_empty and not result:
        raise InitProfileError(f"{label} must not be empty")
    return result


def _choice(value: object, label: str, *, resolved: bool = False) -> str:
    allowed = _RESOLVED_CHOICES if resolved else _CHOICES
    if value not in allowed:
        raise InitProfileError(f"{label} is not a supported choice")
    return str(value)


def _selection_defaults(value: object) -> dict[str, Any]:
    selection = _mapping(value, "selection_defaults")
    expected = {
        "schema",
        "profile",
        "documentationChoice",
        "verificationChoice",
        "selectionSource",
        "customProfile",
    }
    if set(selection) != expected:
        raise InitProfileError("selection_defaults has an unsupported field set")
    if selection["schema"] != INIT_ANALYSIS_CHOICE_SCHEMA:
        raise InitProfileError("selection_defaults schema is invalid")
    profile = selection["profile"]
    if profile not in _ANALYSIS_PROFILES:
        raise InitProfileError("selection_defaults profile is invalid")
    documentation = _choice(
        selection["documentationChoice"], "selection_defaults documentationChoice"
    )
    verification = _choice(
        selection["verificationChoice"], "selection_defaults verificationChoice"
    )
    if selection["selectionSource"] != "default":
        raise InitProfileError("selection_defaults selectionSource must be default")
    custom = selection["customProfile"]
    if custom is not None:
        custom = _id(custom, "selection_defaults customProfile")
    if custom is not None and documentation != "custom" and verification != "custom":
        raise InitProfileError("customProfile requires a custom selection")
    return {
        "schema": INIT_ANALYSIS_CHOICE_SCHEMA,
        "profile": profile,
        "documentationChoice": documentation,
        "verificationChoice": verification,
        "selectionSource": "default",
        "customProfile": custom,
    }


def validate_language_capability_profile(value: object) -> dict[str, Any]:
    """Validate one portable language capability description.

    The root fields intentionally name capabilities rather than repository paths
    or host executables.  Actual tool probing belongs to a host-local operation.
    """

    profile = _mapping(value, "language capability profile")
    expected = {
        "schema",
        "profileId",
        "languages",
        "documentation",
        "verification",
        "artifactPolicy",
    }
    if set(profile) != expected:
        raise InitProfileError("language capability profile has an unsupported field set")
    if profile["schema"] != LANGUAGE_CAPABILITY_PROFILE_SCHEMA:
        raise InitProfileError("language capability profile schema is invalid")
    documentation = _mapping(profile["documentation"], "language documentation")
    if set(documentation) != {"recommended", "userChoice", "primary", "optional"}:
        raise InitProfileError("language documentation has an unsupported field set")
    if not isinstance(documentation["recommended"], bool):
        raise InitProfileError("language documentation recommended must be boolean")
    documentation_choice = _choice(documentation["userChoice"], "language documentation userChoice")

    verification = _mapping(profile["verification"], "language verification")
    if set(verification) != {"cheapRequired", "recommended", "optional"}:
        raise InitProfileError("language verification has an unsupported field set")

    artifacts = _mapping(profile["artifactPolicy"], "language artifactPolicy")
    if set(artifacts) != {
        "defaultMode",
        "trackedSummary",
        "diagnosticRoot",
        "forensicRoot",
    }:
        raise InitProfileError("language artifactPolicy has an unsupported field set")
    if artifacts["defaultMode"] not in {"minimal", "diagnostic", "forensic"}:
        raise InitProfileError("language artifactPolicy defaultMode is invalid")
    if not isinstance(artifacts["trackedSummary"], bool):
        raise InitProfileError("language artifactPolicy trackedSummary must be boolean")
    diagnostic_root = _id(artifacts["diagnosticRoot"], "language diagnosticRoot")
    forensic_root = _id(artifacts["forensicRoot"], "language forensicRoot")
    if not diagnostic_root.startswith("host-local-") or not forensic_root.startswith("host-local-"):
        raise InitProfileError("language artifact roots must be host-local classifications")

    return {
        "schema": LANGUAGE_CAPABILITY_PROFILE_SCHEMA,
        "profileId": _id(profile["profileId"], "language profileId"),
        "languages": _string_list(profile["languages"], "languages", allow_empty=False),
        "documentation": {
            "recommended": documentation["recommended"],
            "userChoice": documentation_choice,
            "primary": _string_list(documentation["primary"], "documentation primary"),
            "optional": _string_list(documentation["optional"], "documentation optional"),
        },
        "verification": {
            "cheapRequired": _string_list(
                verification["cheapRequired"], "verification cheapRequired"
            ),
            "recommended": _string_list(
                verification["recommended"], "verification recommended"
            ),
            "optional": _string_list(verification["optional"], "verification optional"),
        },
        "artifactPolicy": {
            "defaultMode": artifacts["defaultMode"],
            "trackedSummary": artifacts["trackedSummary"],
            "diagnosticRoot": diagnostic_root,
            "forensicRoot": forensic_root,
        },
    }


def validate_init_profile(value: object) -> dict[str, Any]:
    """Validate the complete Standard default profile, without granting authority."""

    profile = _mapping(value, "init profile")
    expected = {
        "schema",
        "id",
        "analysis_profile",
        "documentation_profile",
        "artifact_profile",
        "autonomy",
        "agent_slots",
        "canonical_build_owners",
        "provider_strategy",
        "selection_defaults",
        "language_capability_profiles",
    }
    if set(profile) != expected:
        raise InitProfileError("init profile has an unsupported field set")
    if profile["schema"] != INIT_PROFILE_SCHEMA:
        raise InitProfileError("init profile schema is invalid")
    if profile["analysis_profile"] not in _ANALYSIS_PROFILES:
        raise InitProfileError("analysis_profile is invalid")
    if profile["documentation_profile"] not in _ANALYSIS_PROFILES:
        raise InitProfileError("documentation_profile is invalid")
    if profile["artifact_profile"] not in _ARTIFACT_PROFILES:
        raise InitProfileError("artifact_profile is invalid")
    if profile["autonomy"] not in _AUTONOMY_PROFILES:
        raise InitProfileError("autonomy is invalid")
    slots = profile["agent_slots"]
    if not isinstance(slots, int) or isinstance(slots, bool) or not 1 <= slots <= 256:
        raise InitProfileError("agent_slots must be an integer from 1 through 256")
    if profile["canonical_build_owners"] != 1:
        raise InitProfileError("canonical_build_owners must be exactly one")
    if profile["provider_strategy"] not in _PROVIDER_STRATEGIES:
        raise InitProfileError("provider_strategy is invalid")
    language_profiles = profile["language_capability_profiles"]
    if not isinstance(language_profiles, list):
        raise InitProfileError("language_capability_profiles must be an array")
    normalized_languages = [validate_language_capability_profile(item) for item in language_profiles]
    profile_ids = [item["profileId"] for item in normalized_languages]
    if len(profile_ids) != len(set(profile_ids)):
        raise InitProfileError("language_capability_profiles contains duplicate profileId values")
    return {
        "schema": INIT_PROFILE_SCHEMA,
        "id": _id(profile["id"], "init profile id"),
        "analysis_profile": str(profile["analysis_profile"]),
        "documentation_profile": str(profile["documentation_profile"]),
        "artifact_profile": str(profile["artifact_profile"]),
        "autonomy": str(profile["autonomy"]),
        "agent_slots": slots,
        "canonical_build_owners": 1,
        "provider_strategy": str(profile["provider_strategy"]),
        "selection_defaults": _selection_defaults(profile["selection_defaults"]),
        "language_capability_profiles": normalized_languages,
    }


def load_init_profile(path: Path | str) -> dict[str, Any]:
    """Load one portable JSON profile without any host probing or side effect."""

    candidate = Path(path)
    try:
        with candidate.open("r", encoding="utf-8", newline="") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InitProfileError(f"init profile cannot be loaded: {candidate}") from exc
    return validate_init_profile(value)


def _validate_override(value: object, source: str) -> dict[str, Any]:
    override = _mapping(value, f"{source} override")
    allowed = {
        "analysis_profile",
        "documentation_profile",
        "artifact_profile",
        "autonomy",
        "agent_slots",
        "provider_strategy",
        "selection",
    }
    unexpected = set(override) - allowed
    if unexpected:
        name = sorted(unexpected)[0]
        if name == "canonical_build_owners":
            raise InitProfileError("canonical_build_owners is an invariant and cannot be overridden")
        raise InitProfileError(f"unsupported init profile override: {name}")
    for name, allowed_values in (
        ("analysis_profile", _ANALYSIS_PROFILES),
        ("documentation_profile", _ANALYSIS_PROFILES),
        ("artifact_profile", _ARTIFACT_PROFILES),
        ("autonomy", _AUTONOMY_PROFILES),
        ("provider_strategy", _PROVIDER_STRATEGIES),
    ):
        if name in override and override[name] not in allowed_values:
            raise InitProfileError(f"{source} override {name} is invalid")
    if "agent_slots" in override:
        slots = override["agent_slots"]
        if not isinstance(slots, int) or isinstance(slots, bool) or not 1 <= slots <= 256:
            raise InitProfileError(f"{source} override agent_slots is invalid")
    if "selection" in override:
        selection = _mapping(override["selection"], f"{source} selection")
        selection_allowed = {
            "profile",
            "documentationChoice",
            "verificationChoice",
            "customProfile",
        }
        extras = set(selection) - selection_allowed
        if extras:
            raise InitProfileError(f"{source} selection cannot choose its provenance")
        if "profile" in selection and selection["profile"] not in _ANALYSIS_PROFILES:
            raise InitProfileError(f"{source} selection profile is invalid")
        for key in ("documentationChoice", "verificationChoice"):
            if key in selection:
                _choice(selection[key], f"{source} selection {key}")
        if "customProfile" in selection and selection["customProfile"] is not None:
            _id(selection["customProfile"], f"{source} selection customProfile")
        override["selection"] = selection
    return override


def resolve_init_profile(
    standard_default: Mapping[str, Any],
    *,
    host_override: Mapping[str, Any] | None = None,
    project_override: Mapping[str, Any] | None = None,
    cli_override: Mapping[str, Any] | None = None,
    interactive_override: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve a profile in immutable precedence order with per-field provenance.

    The project package can contribute only the ``project_override`` default.  A
    CLI or interactive choice always wins; neither source can set authority or
    change the single canonical build owner invariant.
    """

    base = validate_init_profile(standard_default)
    effective: dict[str, Any] = {
        name: base[name]
        for name in (
            "analysis_profile",
            "documentation_profile",
            "artifact_profile",
            "autonomy",
            "agent_slots",
            "canonical_build_owners",
            "provider_strategy",
        )
    }
    selection = dict(base["selection_defaults"])
    provenance = {
        **{name: "default" for name in effective},
        "selection.profile": "default",
        "selection.documentationChoice": "default",
        "selection.verificationChoice": "default",
        "selection.customProfile": "default",
    }
    applied_sources: list[str] = ["default"]
    layers = (
        ("host-profile", host_override),
        ("project-package", project_override),
        ("cli", cli_override),
        ("interactive-user", interactive_override),
    )
    for source, override_value in layers:
        if override_value is None:
            continue
        override = _validate_override(override_value, source)
        if source not in applied_sources:
            applied_sources.append(source)
        for key in (
            "analysis_profile",
            "documentation_profile",
            "artifact_profile",
            "autonomy",
            "agent_slots",
            "provider_strategy",
        ):
            if key in override:
                effective[key] = override[key]
                provenance[key] = source
        nested = override.get("selection")
        if isinstance(nested, Mapping):
            for key, value in nested.items():
                selection[key] = value
                provenance[f"selection.{key}"] = source

    # The analysis choice is bound to the effective analysis profile.  A caller
    # cannot make a selection label disagree with the actual selected profile.
    selection["profile"] = effective["analysis_profile"]
    provenance["selection.profile"] = provenance["analysis_profile"]
    selection_source = max(
        provenance.values(), key=lambda item: _SELECTION_SOURCES.index(str(item))
    )
    selection["selectionSource"] = selection_source
    if selection["customProfile"] is not None and (
        selection["documentationChoice"] != "custom"
        and selection["verificationChoice"] != "custom"
    ):
        raise InitProfileError("customProfile requires a custom documentation or verification choice")

    effective["selection"] = selection
    identity = {
        "schema": RESOLVED_INIT_PROFILE_SCHEMA,
        "profile_id": base["id"],
        "effective": effective,
        "provenance": provenance,
        "selection_source": selection_source,
        "applied_sources": applied_sources,
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
    }
    return {**identity, "profile_digest": digest_value(identity)}


def _ordered_union(values: Iterable[Iterable[str]]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for group in values:
        for value in group:
            if value not in seen:
                seen.add(value)
                result.append(value)
    return result


def negotiate_language_capabilities(
    language_profiles: Sequence[Mapping[str, Any]],
    *,
    languages: Iterable[str],
    documentation_choice: str,
    verification_choice: str,
    selection_source: str,
    custom_documentation: Iterable[str] = (),
    custom_verification: Iterable[str] = (),
) -> dict[str, Any]:
    """Resolve accepted language documentation/tooling surfaces without probing them.

    A choice merely selects what init may configure.  It does not say a tool is
    installed, run, valid, or creditable; those are host-local observations.
    """

    if selection_source not in _SELECTION_SOURCES:
        raise InitProfileError("language capability selection source is invalid")
    documentation_choice = _choice(
        documentation_choice, "documentation choice", resolved=True
    )
    verification_choice = _choice(
        verification_choice, "verification choice", resolved=True
    )
    selected_languages = _string_list(list(languages), "languages")
    profiles = [validate_language_capability_profile(item) for item in language_profiles]
    selected = [
        profile
        for profile in sorted(profiles, key=lambda item: item["profileId"])
        if set(profile["languages"]) & set(selected_languages)
    ]
    custom_docs = _string_list(list(custom_documentation), "custom documentation")
    custom_checks = _string_list(list(custom_verification), "custom verification")
    if documentation_choice == "custom" and not custom_docs:
        raise InitProfileError("custom documentation choice requires at least one tool")
    if verification_choice == "custom" and not custom_checks:
        raise InitProfileError("custom verification choice requires at least one tool")

    required = _ordered_union(
        profile["verification"]["cheapRequired"] for profile in selected
    )
    docs = (
        _ordered_union(profile["documentation"]["primary"] for profile in selected)
        if documentation_choice == "accept"
        else custom_docs if documentation_choice == "custom" else []
    )
    verification = (
        _ordered_union(profile["verification"]["recommended"] for profile in selected)
        if verification_choice == "accept"
        else custom_checks if verification_choice == "custom" else []
    )
    identity = {
        "record_type": "LanguageCapabilitySelection",
        "schema": "promin.language-capability-selection.v1",
        "profile_ids": [profile["profileId"] for profile in selected],
        "languages": selected_languages,
        "documentation_choice": documentation_choice,
        "verification_choice": verification_choice,
        "documentation_tools": docs,
        "required_verification_tools": required,
        "recommended_verification_tools": verification,
        "selection_source": selection_source,
        "status": "AVAILABLE" if selected else "UNAVAILABLE",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
    }
    return {**identity, "selection_digest": digest_value(identity)}


@dataclass(frozen=True)
class ToolOutcome:
    """A typed host-local optional-tool observation.

    ``PASS`` is a result of a specific tool gate only.  It never implies product
    acceptance, and every other state, especially ``UNAVAILABLE``, is barred
    from pass credit by construction.
    """

    tool_id: str
    state: str
    required: bool
    detail: str
    pass_credit: bool = False

    def __post_init__(self) -> None:
        _id(self.tool_id, "tool_id")
        if self.state not in _TOOL_STATES:
            raise InitProfileError("tool state is invalid")
        if not isinstance(self.required, bool):
            raise InitProfileError("tool required must be boolean")
        if not isinstance(self.detail, str) or not self.detail or len(self.detail) > 2048:
            raise InitProfileError("tool detail must be a non-empty bounded string")
        if not isinstance(self.pass_credit, bool):
            raise InitProfileError("tool pass_credit must be boolean")
        if self.pass_credit and self.state != "PASS":
            raise InitProfileError(f"{self.state} tool outcome cannot receive pass credit")

    def as_record(self) -> dict[str, Any]:
        return {
            "record_type": "ToolOutcome",
            "tool_id": self.tool_id,
            "state": self.state,
            "required": self.required,
            "detail": self.detail,
            "pass_credit": self.pass_credit,
            "acceptance_pass": False,
            "authority_granted": False,
        }


# Init language choices use the installed catalog as their only profile authority.
# The init layer adds experience/source labels and false claims, but it does not
# maintain a second language or tool catalog.
INIT_EXPERIENCE_SCHEMA = "promin.init-experience.v1"
LANGUAGE_REFERENCE_SELECTION_SCHEMA = "promin.language-reference-selection.v1"

_INIT_EXPERIENCES = frozenset({"minimal", "expert"})
_EXPERT_SELECTION_SOURCES = frozenset({"owner", "cli", "interactive-user"})
_MINIMAL_SELECTION_SOURCE = "minimal-one-click"
_MAX_EXPLICIT_LANGUAGES = 64
_EXPERT_INIT_FILE = "expert-init.json"
_BUNDLE_CLAIMS = {
    "authority_effect": "none",
    "authority_granted": False,
    "pass_credit": False,
    "acceptance_pass": False,
    "product_acceptance_pass": False,
    "release_approved": False,
}


def _iterable_values(
    value: object,
    label: str,
    *,
    maximum: int,
) -> list[object]:
    """Read at most one item beyond an ordinary public iterable bound."""

    if isinstance(value, (str, bytes, Mapping)):
        raise InitProfileError(f"{label} must be an explicit array")
    try:
        result = list(islice(iter(value), maximum + 1))  # type: ignore[arg-type]
    except TypeError as exc:
        raise InitProfileError(f"{label} must be an explicit array") from exc
    if len(result) > maximum:
        raise InitProfileError(f"{label} exceeds registered maximum {maximum}")
    return result


def _installed_language_catalog() -> LanguageCatalog:
    try:
        return load_bundled_language_catalog(bundle_root() / "language_profiles")
    except (LanguageCatalogError, ResourceError) as exc:
        raise InitProfileError(f"installed language catalog is invalid: {exc}") from exc


def _compose_languages(
    catalog: LanguageCatalog,
    *,
    languages: Iterable[str],
    overrides: Mapping[str, object] | None = None,
) -> dict[str, object] | None:
    values = _iterable_values(
        languages,
        "languages",
        maximum=_MAX_EXPLICIT_LANGUAGES,
    )
    if not values:
        return None
    try:
        return compose_language_capabilities(
            catalog,
            languages=values,
            overrides=overrides,
        )
    except LanguageCatalogError as exc:
        raise InitProfileError(str(exc)) from exc


def _catalog_profiles(
    catalog: LanguageCatalog,
) -> tuple[dict[str, LanguageCapabilityProfile], dict[str, LanguageCapabilityProfile]]:
    by_id = {profile.profile_id: profile for profile in catalog.profiles}
    by_language = {
        language: profile
        for profile in catalog.profiles
        for language in profile.languages
    }
    return by_id, by_language


def _selection_items(
    value: object,
    label: str,
    *,
    maximum: int,
) -> tuple[str, ...]:
    raw = _iterable_values(value, label, maximum=maximum)
    values = tuple(_id(item, f"{label} item") for item in raw)
    if len(values) != len(set(values)):
        raise InitProfileError(f"{label} contains duplicates")
    return values


def _legacy_selection_mode(
    values: tuple[str, ...],
    *,
    declared: tuple[str, ...],
    legacy_allowed: set[str],
    label: str,
) -> dict[str, object]:
    if not values:
        return {"mode": "decline", "items": []}
    if set(values) <= set(declared):
        return {"mode": "custom", "items": list(values)}
    unknown = sorted(set(values) - legacy_allowed)
    if unknown:
        raise InitProfileError(f"unknown {label} reference: {unknown[0]}")
    return {"mode": "accept", "items": []}


def _legacy_profile_override(
    language: str,
    value: object,
    profile: LanguageCapabilityProfile,
) -> dict[str, object]:
    """Translate the pre-catalog language-keyed form once, then discard it."""

    selection = _mapping(value, f"expert {language} selection")
    if set(selection) != {"capability_id", "documentation", "tools"}:
        raise InitProfileError(
            f"expert {language} selection has an unsupported field set"
        )
    if selection["capability_id"] != f"{language}-language":
        raise InitProfileError(
            f"expert {language} selection cannot change its catalog language"
        )

    declared_documentation = (
        profile.documentation_primary + profile.documentation_optional
    )
    declared_tools = profile.recommended_tools + profile.optional_tools
    documentation = _selection_items(
        selection["documentation"],
        f"expert {language} documentation",
        maximum=max(1, len(declared_documentation)),
    )
    tools = _selection_items(
        selection["tools"],
        f"expert {language} tools",
        maximum=max(1, len(declared_tools)),
    )

    language_names = {language}
    if language == "javascript":
        language_names.add("ecmascript")
    legacy_documentation = {
        f"{name}-{suffix}"
        for name in language_names
        for suffix in (
            "language-reference",
            "language-specification",
            "api-guidelines",
            "api-documentation",
            "documentation-generator",
        )
    }
    legacy_tools = {
        f"{language}-{suffix}"
        for suffix in (
            "syntax-check",
            "compiler-check",
            "compile-check",
            "language-server",
            "static-analysis",
        )
    }
    if tools and not set(tools) <= set(declared_tools) and not any(
        item.endswith("-syntax-check")
        or item.endswith("-compiler-check")
        or item.endswith("-compile-check")
        for item in tools
    ):
        raise InitProfileError(
            f"expert {language} selection omits required tool"
        )

    return {
        "documentation": _legacy_selection_mode(
            documentation,
            declared=declared_documentation,
            legacy_allowed=legacy_documentation,
            label=f"expert {language} documentation",
        ),
        "tools": _legacy_selection_mode(
            tools,
            declared=declared_tools,
            legacy_allowed=legacy_tools,
            label=f"expert {language} tool",
        ),
    }


def _canonical_profile_selections(
    composition: Mapping[str, object],
) -> dict[str, dict[str, object]]:
    records = composition.get("profile_selections")
    if not isinstance(records, list):
        raise InitProfileError("language composition profile selections are invalid")
    result: dict[str, dict[str, object]] = {}
    for record in records:
        if not isinstance(record, Mapping):
            raise InitProfileError("language composition profile selection is invalid")
        profile_id = record.get("profile_id")
        documentation = record.get("documentation")
        tools = record.get("tools")
        if (
            not isinstance(profile_id, str)
            or not isinstance(documentation, Mapping)
            or not isinstance(tools, Mapping)
        ):
            raise InitProfileError("language composition profile selection is invalid")
        result[profile_id] = {
            "documentation": dict(documentation),
            "tools": dict(tools),
        }
    return result


def _normalize_expert_selections(
    catalog: LanguageCatalog,
    preview: Mapping[str, object],
    value: Mapping[str, Any],
) -> tuple[dict[str, dict[str, object]], dict[str, object]]:
    raw = _canonical_object(value, "expert language selections")
    selected_profile_ids = tuple(preview["selected_profile_ids"])
    requested_languages = tuple(preview["requested_languages"])
    profile_keys = set(selected_profile_ids)
    language_keys = set(requested_languages)

    if set(raw) == profile_keys:
        for profile_id, selection in raw.items():
            candidate = _mapping(selection, f"expert {profile_id} selection")
            if set(candidate) != {"documentation", "tools"}:
                raise InitProfileError(
                    f"expert {profile_id} selection must contain documentation and tools"
                )
        normalized_input: dict[str, object] = raw
    elif set(raw) == language_keys:
        _, by_language = _catalog_profiles(catalog)
        translated: dict[str, object] = {}
        for language in requested_languages:
            profile = by_language[language]
            override = _legacy_profile_override(language, raw[language], profile)
            previous = translated.get(profile.profile_id)
            if previous is not None and previous != override:
                raise InitProfileError(
                    f"legacy selections for {profile.profile_id} disagree"
                )
            translated[profile.profile_id] = override
        normalized_input = translated
    else:
        raise InitProfileError(
            "expert language selections must contain exactly the selected profile IDs"
        )

    composition = _compose_languages(
        catalog,
        languages=requested_languages,
        overrides=normalized_input,
    )
    if composition is None:  # pragma: no cover - expert selection is non-empty
        raise InitProfileError("expert experience requires at least one language")
    composed = _canonical_profile_selections(composition)
    if set(composed) != profile_keys:
        raise InitProfileError(
            "expert language selections do not cover the selected profiles"
        )
    normalized = {
        profile_id: {
            "documentation": dict(
                _mapping(
                    _mapping(normalized_input[profile_id], profile_id)["documentation"],
                    f"{profile_id} documentation",
                )
            ),
            "tools": dict(
                _mapping(
                    _mapping(normalized_input[profile_id], profile_id)["tools"],
                    f"{profile_id} tools",
                )
            ),
        }
        for profile_id in selected_profile_ids
    }
    return normalized, composition


def _capability_selection_records(
    catalog: LanguageCatalog,
    composition: Mapping[str, object] | None,
    *,
    selection_source: str,
) -> list[dict[str, object]]:
    if composition is None:
        return []
    requested = set(composition["requested_languages"])
    by_id, _ = _catalog_profiles(catalog)
    normalized = _canonical_profile_selections(composition)
    records: list[dict[str, object]] = []
    for profile_id, selection in normalized.items():
        profile = by_id[profile_id]
        identity = {
            "schema": LANGUAGE_REFERENCE_SELECTION_SCHEMA,
            "profile_id": profile_id,
            "languages": [
                language for language in profile.languages if language in requested
            ],
            "selection_source": selection_source,
            "documentation": selection["documentation"],
            "tools": selection["tools"],
            "profile_digest": profile.profile_digest,
            "authority_granted": False,
            "pass_credit": False,
            "acceptance_pass": False,
        }
        records.append({**identity, "selection_digest": digest_value(identity)})
    return records


def resolve_init_experience(
    standard_default: Mapping[str, Any],
    *,
    experience: str = "minimal",
    languages: Iterable[str] = (),
    host_override: Mapping[str, Any] | None = None,
    project_override: Mapping[str, Any] | None = None,
    cli_override: Mapping[str, Any] | None = None,
    interactive_override: Mapping[str, Any] | None = None,
    expert_selections: Mapping[str, Any] | None = None,
    expert_source: str | None = None,
) -> dict[str, Any]:
    """Resolve minimal defaults or explicit expert profile choices.

    All language, documentation, and tool identities come from the installed
    language catalog.  This function performs no tool discovery or execution.
    """

    if experience not in _INIT_EXPERIENCES:
        raise InitProfileError("init experience must be minimal or expert")
    profile = resolve_init_profile(
        standard_default,
        host_override=host_override,
        project_override=project_override,
        cli_override=cli_override,
        interactive_override=interactive_override,
    )
    catalog = _installed_language_catalog()
    preview = _compose_languages(catalog, languages=languages)

    if experience == "minimal":
        if expert_selections is not None or expert_source is not None:
            raise InitProfileError(
                "minimal one-click experience does not accept expert selections"
            )
        selection_source = _MINIMAL_SELECTION_SOURCE
        composition = preview
        normalized_selections = (
            {} if composition is None else _canonical_profile_selections(composition)
        )
        capability_precedence = [
            "installed-language-catalog",
            _MINIMAL_SELECTION_SOURCE,
        ]
    else:
        if preview is None:
            raise InitProfileError(
                "expert experience requires at least one explicit language"
            )
        if expert_selections is None:
            raise InitProfileError(
                "expert experience requires explicit profile selections"
            )
        if expert_source not in _EXPERT_SELECTION_SOURCES:
            raise InitProfileError(
                "expert selection source must be owner, cli, or interactive-user"
            )
        selection_source = str(expert_source)
        normalized_selections, composition = _normalize_expert_selections(
            catalog,
            preview,
            expert_selections,
        )
        capability_precedence = ["installed-language-catalog", selection_source]

    selected_languages = (
        [] if composition is None else list(composition["requested_languages"])
    )
    selections = _capability_selection_records(
        catalog,
        composition,
        selection_source=selection_source,
    )
    identity = {
        "schema": INIT_EXPERIENCE_SCHEMA,
        "experience": experience,
        "profile": profile,
        "profile_precedence": list(_SELECTION_SOURCES),
        "applied_profile_sources": list(profile["applied_sources"]),
        "profile_provenance": profile["provenance"],
        "capability_precedence": capability_precedence,
        "capability_selection_source": selection_source,
        "language_catalog_digest": catalog.catalog_digest,
        "language_catalog_source_digest": catalog.source_digest,
        "languages": selected_languages,
        "profile_selections": normalized_selections,
        "capability_selections": selections,
        "language_composition": composition,
        "semantic_decision_policy": "catalog-default-or-explicit-profile-selection",
        "weak_model_semantic_decisions": False,
        "model_inference_used": False,
        "host_probe_performed": False,
        "status": "CONFIGURED_PENDING_HOST_OBSERVATION",
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "release_approved": False,
    }
    return {**identity, "experience_digest": digest_value(identity)}


def _canonical_object(value: object, label: str) -> dict[str, Any]:
    candidate = _mapping(value, label)
    try:
        normalized = parse_json_strict(canonical_bytes(candidate))
    except CanonicalError as exc:
        raise InitProfileError(f"{label} is not bounded canonical JSON") from exc
    if not isinstance(normalized, dict):  # pragma: no cover - _mapping owns this
        raise InitProfileError(f"{label} must be an object")
    return normalized


def _bundle_override(
    value: Mapping[str, Any] | None,
    source: str,
) -> dict[str, Any] | None:
    if value is None:
        return None
    return _validate_override(
        _canonical_object(value, f"{source} override"),
        source,
    )


def _bundle_claims_are_false(value: Mapping[str, Any], label: str) -> None:
    for field, expected in _BUNDLE_CLAIMS.items():
        if value.get(field) != expected or type(value.get(field)) is not type(expected):
            raise InitProfileError(f"{label} {field} is invalid")


def _expert_bundle_values(
    *,
    standard_default: Mapping[str, Any],
    plan_inputs: Mapping[str, Any],
    languages: Iterable[str],
    expert_selections: Mapping[str, Any],
    expert_source: str,
    host_override: Mapping[str, Any] | None,
    project_override: Mapping[str, Any] | None,
    cli_override: Mapping[str, Any] | None,
    interactive_override: Mapping[str, Any] | None,
) -> dict[str, Any]:
    standard = validate_init_profile(
        _canonical_object(standard_default, "expert bundle standard profile")
    )
    overrides = {
        "host_override": _bundle_override(host_override, "host-profile"),
        "project_override": _bundle_override(project_override, "project-package"),
        "cli_override": _bundle_override(cli_override, "cli"),
        "interactive_override": _bundle_override(
            interactive_override,
            "interactive-user",
        ),
    }
    normalized_plan_inputs = _canonical_object(plan_inputs, "expert plan_inputs")
    if not normalized_plan_inputs:
        raise InitProfileError("expert plan_inputs must not be empty")
    resolved = resolve_init_experience(
        standard,
        experience="expert",
        languages=languages,
        expert_selections=expert_selections,
        expert_source=expert_source,
        **overrides,
    )

    identity = {
        "record_type": "ExpertInit",
        "schema": EXPERT_INIT_BUNDLE_SCHEMA,
        "bundle_file": _EXPERT_INIT_FILE,
        "standard_default": standard,
        **overrides,
        "languages": resolved["languages"],
        "expert_selections": resolved["profile_selections"],
        "expert_source": expert_source,
        "plan_inputs": normalized_plan_inputs,
        "resolved_experience": resolved,
        **_BUNDLE_CLAIMS,
    }
    return {**identity, "bundle_digest": digest_value(identity)}


def _read_canonical_bundle_object(data: bytes) -> dict[str, Any]:
    try:
        value = parse_json_strict(data)
        if canonical_bytes(value) != data:
            raise InitProfileError("expert init bytes are not canonical")
    except InitProfileError:
        raise
    except CanonicalError as exc:
        raise InitProfileError("expert init cannot be loaded") from exc
    if not isinstance(value, dict):
        raise InitProfileError("expert init must be an object")
    return value


def _exact_expert_init_path(directory: Path) -> Path:
    try:
        if not directory.is_dir():
            raise InitProfileError("expert init bundle must be a directory")
        entries = list(islice(directory.iterdir(), 2))
    except InitProfileError:
        raise
    except OSError as exc:
        raise InitProfileError("expert init bundle directory cannot be read") from exc
    if (
        len(entries) != 1
        or entries[0].name != _EXPERT_INIT_FILE
        or not entries[0].is_file()
    ):
        raise InitProfileError(
            f"expert init bundle must contain exactly {_EXPERT_INIT_FILE}"
        )
    return entries[0]


def _read_expert_init_bytes(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            data = handle.read(DEFAULT_LIMITS.max_bytes + 1)
    except OSError as exc:
        raise InitProfileError("expert init file cannot be read") from exc
    if not data or len(data) > DEFAULT_LIMITS.max_bytes:
        raise InitProfileError("expert init file exceeds its bounded size")
    return data


def export_expert_init_bundle(
    directory: Path | str,
    *,
    standard_default: Mapping[str, Any],
    plan_inputs: Mapping[str, Any],
    languages: Iterable[str],
    expert_selections: Mapping[str, Any],
    expert_source: str,
    host_override: Mapping[str, Any] | None = None,
    project_override: Mapping[str, Any] | None = None,
    cli_override: Mapping[str, Any] | None = None,
    interactive_override: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create one directory containing one canonical expert-init document."""

    document = _expert_bundle_values(
        standard_default=standard_default,
        plan_inputs=plan_inputs,
        languages=languages,
        expert_selections=expert_selections,
        expert_source=expert_source,
        host_override=host_override,
        project_override=project_override,
        cli_override=cli_override,
        interactive_override=interactive_override,
    )
    try:
        data = canonical_bytes(document)
    except CanonicalError as exc:  # pragma: no cover - values were normalized above
        raise InitProfileError("expert init document exceeds its bounds") from exc

    destination = Path(directory)
    try:
        destination.mkdir()
    except FileExistsError as exc:
        raise InitProfileError("expert bundle destination already exists") from exc
    except FileNotFoundError as exc:
        raise InitProfileError(
            "expert bundle destination parent must already be a directory"
        ) from exc
    except OSError as exc:
        raise InitProfileError("expert bundle destination cannot be created") from exc

    try:
        with (destination / _EXPERT_INIT_FILE).open("xb") as handle:
            handle.write(data)
    except OSError as exc:
        raise InitProfileError("expert init file cannot be written") from exc

    imported = import_expert_init_bundle(destination)
    if imported != document:
        raise InitProfileError("expert init publication did not round-trip exactly")
    return imported


def import_expert_init_bundle(directory: Path | str) -> dict[str, Any]:
    """Load and recompute one canonical expert-init document."""

    path = _exact_expert_init_path(Path(directory))
    value = _read_canonical_bundle_object(_read_expert_init_bytes(path))
    if value.get("record_type") != "ExpertInit":
        raise InitProfileError("expert init record_type is invalid")
    if value.get("schema") != EXPERT_INIT_BUNDLE_SCHEMA:
        raise InitProfileError("expert init schema is invalid")
    if value.get("bundle_file") != _EXPERT_INIT_FILE:
        raise InitProfileError("expert init filename binding is invalid")
    _bundle_claims_are_false(value, "expert init")

    identity = {key: item for key, item in value.items() if key != "bundle_digest"}
    if value.get("bundle_digest") != digest_value(identity):
        raise InitProfileError("expert init bundle digest mismatch")

    required = {
        "standard_default",
        "plan_inputs",
        "languages",
        "expert_selections",
        "expert_source",
        "host_override",
        "project_override",
        "cli_override",
        "interactive_override",
    }
    if not required <= set(value):
        raise InitProfileError("expert init is missing a required configuration field")
    try:
        expected = _expert_bundle_values(
            standard_default=value["standard_default"],
            plan_inputs=value["plan_inputs"],
            languages=value["languages"],
            expert_selections=value["expert_selections"],
            expert_source=value["expert_source"],
            host_override=value["host_override"],
            project_override=value["project_override"],
            cli_override=value["cli_override"],
            interactive_override=value["interactive_override"],
        )
    except (KeyError, TypeError) as exc:
        raise InitProfileError("expert init configuration is invalid") from exc
    if value != expected:
        raise InitProfileError("expert init is not normalized or self-consistent")
    return expected
