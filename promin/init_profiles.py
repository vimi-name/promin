"""Generic, non-authoritative capability-profile resolution for ``promin init``.

The module deliberately resolves configuration only.  It neither discovers a
host tool nor grants an action capability: Core authority, Grants, Leases, and
their effect scopes remain the only route to a mutation.  Keeping that boundary
here makes profile selection safe to use before an activation is published.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .canonical import digest_value


class InitProfileError(ValueError):
    """Raised when a capability profile or its selected overlay is invalid."""


INIT_PROFILE_SCHEMA = "promin.init-profile.v1"
LANGUAGE_CAPABILITY_PROFILE_SCHEMA = "promin.language-capability-profile.v1"
INIT_ANALYSIS_CHOICE_SCHEMA = "promin.init-analysis-choice.v1"
RESOLVED_INIT_PROFILE_SCHEMA = "promin.resolved-init-profile.v1"

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


# H1 deliberately keeps these as generic, portable reference identifiers.  A
# selected identifier is not a host probe, executable path, installed package,
# semantic classification, or authority grant.
INIT_EXPERIENCE_SCHEMA = "promin.init-experience.v1"
LANGUAGE_REFERENCE_SELECTION_SCHEMA = "promin.language-reference-selection.v1"

_INIT_EXPERIENCES = frozenset({"minimal", "expert"})
_EXPERT_SELECTION_SOURCES = frozenset({"owner", "cli", "interactive-user"})
_MINIMAL_SELECTION_SOURCE = "minimal-one-click"
_GENERIC_LANGUAGE_ORDER = (
    "c",
    "cpp",
    "csharp",
    "java",
    "javascript",
    "python",
)


@dataclass(frozen=True, slots=True)
class LanguageReferenceSet:
    """The bounded generic references available for one explicit language ID."""

    language: str
    capability_id: str
    minimal_documentation: tuple[str, ...]
    optional_documentation: tuple[str, ...]
    required_tools: tuple[str, ...]
    optional_tools: tuple[str, ...]

    def __post_init__(self) -> None:
        _id(self.language, "generic language id")
        _id(self.capability_id, "generic capability id")
        for label, values in (
            ("minimal documentation", self.minimal_documentation),
            ("optional documentation", self.optional_documentation),
            ("required tools", self.required_tools),
            ("optional tools", self.optional_tools),
        ):
            if not values:
                raise InitProfileError(f"generic {label} must not be empty")
            for item in values:
                _id(item, f"generic {label} item")
            if len(values) != len(set(values)):
                raise InitProfileError(f"generic {label} contains duplicates")
        if set(self.minimal_documentation) & set(self.optional_documentation):
            raise InitProfileError("generic documentation references overlap")
        if set(self.required_tools) & set(self.optional_tools):
            raise InitProfileError("generic tool references overlap")

    @property
    def documentation_references(self) -> tuple[str, ...]:
        return self.minimal_documentation + self.optional_documentation

    @property
    def tool_references(self) -> tuple[str, ...]:
        return self.required_tools + self.optional_tools


_GENERIC_LANGUAGE_REFERENCES: dict[str, LanguageReferenceSet] = {
    "c": LanguageReferenceSet(
        language="c",
        capability_id="c-language",
        minimal_documentation=("c-language-reference",),
        optional_documentation=("c-api-guidelines", "c-documentation-generator"),
        required_tools=("c-syntax-check",),
        optional_tools=("c-language-server", "c-static-analysis"),
    ),
    "cpp": LanguageReferenceSet(
        language="cpp",
        capability_id="cpp-language",
        minimal_documentation=("cpp-language-reference",),
        optional_documentation=("cpp-core-guidelines", "cpp-documentation-generator"),
        required_tools=("cpp-syntax-check",),
        optional_tools=("cpp-language-server", "cpp-static-analysis"),
    ),
    "csharp": LanguageReferenceSet(
        language="csharp",
        capability_id="csharp-language",
        minimal_documentation=("csharp-language-reference",),
        optional_documentation=("csharp-api-guidelines", "csharp-documentation-generator"),
        required_tools=("csharp-compiler-check",),
        optional_tools=("csharp-language-server", "csharp-static-analysis"),
    ),
    "java": LanguageReferenceSet(
        language="java",
        capability_id="java-language",
        minimal_documentation=("java-language-specification",),
        optional_documentation=("java-api-documentation", "java-documentation-generator"),
        required_tools=("java-compiler-check",),
        optional_tools=("java-language-server", "java-static-analysis"),
    ),
    "javascript": LanguageReferenceSet(
        language="javascript",
        capability_id="javascript-language",
        minimal_documentation=("ecmascript-language-specification",),
        optional_documentation=(
            "javascript-api-documentation",
            "javascript-documentation-generator",
        ),
        required_tools=("javascript-syntax-check",),
        optional_tools=("javascript-language-server", "javascript-static-analysis"),
    ),
    "python": LanguageReferenceSet(
        language="python",
        capability_id="python-language",
        minimal_documentation=("python-language-reference",),
        optional_documentation=("python-api-documentation", "python-documentation-generator"),
        required_tools=("python-compile-check",),
        optional_tools=("python-language-server", "python-static-analysis"),
    ),
}


def _iterable_values(value: object, label: str) -> list[object]:
    """Require a caller-owned sequence instead of coercing strings or mappings."""

    if isinstance(value, (str, bytes, Mapping)):
        raise InitProfileError(f"{label} must be an explicit array")
    try:
        return list(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise InitProfileError(f"{label} must be an explicit array") from exc


def _selected_generic_languages(languages: Iterable[str]) -> tuple[str, ...]:
    requested = _string_list(
        _iterable_values(languages, "generic languages"),
        "generic languages",
    )
    unknown = sorted(set(requested) - set(_GENERIC_LANGUAGE_REFERENCES))
    if unknown:
        raise InitProfileError(f"unknown generic language selection: {unknown[0]}")
    selected = set(requested)
    return tuple(language for language in _GENERIC_LANGUAGE_ORDER if language in selected)


def _registered_values(
    value: object,
    *,
    allowed: tuple[str, ...],
    label: str,
) -> tuple[str, ...]:
    requested = _string_list(_iterable_values(value, label), label)
    unknown = sorted(set(requested) - set(allowed))
    if unknown:
        raise InitProfileError(f"unknown {label} reference: {unknown[0]}")
    selected = set(requested)
    return tuple(item for item in allowed if item in selected)


def _expert_language_selections(
    value: Mapping[str, Any],
    *,
    languages: tuple[str, ...],
) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    selections = _mapping(value, "expert language selections")
    if set(selections) != set(languages):
        raise InitProfileError(
            "expert language selections must contain exactly the explicit language IDs"
        )
    result: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {}
    for language in languages:
        reference_set = _GENERIC_LANGUAGE_REFERENCES[language]
        selection = _mapping(selections[language], f"expert {language} selection")
        if set(selection) != {"capability_id", "documentation", "tools"}:
            raise InitProfileError(
                f"expert {language} selection has an unsupported field set"
            )
        if selection["capability_id"] != reference_set.capability_id:
            raise InitProfileError(
                f"expert {language} selection cannot change its registered capability"
            )
        documentation = _registered_values(
            selection["documentation"],
            allowed=reference_set.documentation_references,
            label=f"expert {language} documentation",
        )
        tools = _registered_values(
            selection["tools"],
            allowed=reference_set.tool_references,
            label=f"expert {language} tools",
        )
        missing_required = [
            tool for tool in reference_set.required_tools if tool not in tools
        ]
        if missing_required:
            raise InitProfileError(
                f"expert {language} selection omits required tool {missing_required[0]}"
            )
        result[language] = (documentation, tools)
    return result


def _language_reference_selection(
    reference_set: LanguageReferenceSet,
    *,
    documentation: tuple[str, ...],
    tools: tuple[str, ...],
    selection_source: str,
) -> dict[str, Any]:
    """Return one typed selection without asserting a tool exists on this host."""

    identity = {
        "schema": LANGUAGE_REFERENCE_SELECTION_SCHEMA,
        "language": reference_set.language,
        "capability_id": reference_set.capability_id,
        "selection_source": selection_source,
        "semantic_decision_policy": "registered-reference-only",
        "weak_model_semantic_decision": False,
        "documentation": [
            {
                "reference_id": reference,
                "reference_kind": "generic-documentation-reference",
                "source": selection_source,
            }
            for reference in documentation
        ],
        "tools": [
            {
                "tool_id": tool,
                "reference_kind": "generic-tool-reference",
                "source": selection_source,
                "required": tool in reference_set.required_tools,
                "availability": "UNOBSERVED",
                "pass_credit": False,
            }
            for tool in tools
        ],
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
    }
    return {**identity, "selection_digest": digest_value(identity)}


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
    """Resolve deterministic minimal or explicitly selected expert init UX.

    Language IDs must be supplied by a caller that already has an explicit,
    independently-derived language choice.  This function never infers a
    language, chooses a semantic capability from model output, probes tools, or
    grants authority.  Expert input can choose only registered generic
    references, and every unknown input is rejected before a result is made.
    """

    if not isinstance(experience, str) or experience not in _INIT_EXPERIENCES:
        raise InitProfileError("init experience must be minimal or expert")
    profile = resolve_init_profile(
        standard_default,
        host_override=host_override,
        project_override=project_override,
        cli_override=cli_override,
        interactive_override=interactive_override,
    )
    selected_languages = _selected_generic_languages(languages)
    if experience == "minimal":
        if expert_selections is not None or expert_source is not None:
            raise InitProfileError(
                "minimal one-click experience does not accept expert semantic selections"
            )
        selection_source = _MINIMAL_SELECTION_SOURCE
        selections = [
            _language_reference_selection(
                _GENERIC_LANGUAGE_REFERENCES[language],
                documentation=_GENERIC_LANGUAGE_REFERENCES[language].minimal_documentation,
                tools=_GENERIC_LANGUAGE_REFERENCES[language].required_tools,
                selection_source=selection_source,
            )
            for language in selected_languages
        ]
        capability_precedence = [
            "registered-generic-reference",
            _MINIMAL_SELECTION_SOURCE,
        ]
    else:
        if not selected_languages:
            raise InitProfileError("expert experience requires at least one explicit language")
        if expert_selections is None:
            raise InitProfileError("expert experience requires explicit language selections")
        if (
            not isinstance(expert_source, str)
            or expert_source not in _EXPERT_SELECTION_SOURCES
        ):
            raise InitProfileError(
                "expert semantic selection source must be owner, cli, or interactive-user"
            )
        selection_source = expert_source
        selected = _expert_language_selections(
            expert_selections,
            languages=selected_languages,
        )
        selections = [
            _language_reference_selection(
                _GENERIC_LANGUAGE_REFERENCES[language],
                documentation=selected[language][0],
                tools=selected[language][1],
                selection_source=selection_source,
            )
            for language in selected_languages
        ]
        capability_precedence = ["registered-generic-reference", selection_source]

    identity = {
        "schema": INIT_EXPERIENCE_SCHEMA,
        "experience": experience,
        "profile": profile,
        "profile_precedence": list(_SELECTION_SOURCES),
        "applied_profile_sources": list(profile["applied_sources"]),
        "profile_provenance": profile["provenance"],
        "capability_precedence": capability_precedence,
        "capability_selection_source": selection_source,
        "languages": list(selected_languages),
        "capability_selections": selections,
        "semantic_decision_policy": "registered-default-or-explicit-owner-cli-interactive",
        "weak_model_semantic_decisions": False,
        "model_inference_used": False,
        "host_probe_performed": False,
        "status": "CONFIGURED_PENDING_HOST_OBSERVATION",
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
    }
    return {**identity, "experience_digest": digest_value(identity)}
