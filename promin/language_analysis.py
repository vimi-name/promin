"""Pure, profile-driven language-analysis contracts.

This module intentionally performs no process, provider, build, database, or
filesystem mutation.  It classifies bounded source facts for a later tool or
admission operation; it is never product or release evidence.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
import re
import unicodedata
from typing import Any, Iterable, Mapping, Sequence


PROFILE_SCHEMA = "promin.language-capability-profile.v1"
_PROFILE_KEYS = frozenset(
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
_PROFILE_REQUIRED_KEYS = _PROFILE_KEYS
_ID = re.compile(r"^[a-z][a-z0-9-]{0,127}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_VALUE_CATEGORIES = frozenset(
    {
        "by-value",
        "rvalue-reference",
        "borrowed-reference",
        "member",
        "result-extraction",
    }
)
_DESTINATION_CATEGORIES = frozenset(
    {"owned-value", "member", "result", "external-owner"}
)
_POSTCONDITIONS = frozenset(
    {
        "not-observable",
        "explicit-empty",
        "explicit-reset",
        "transactional-exchange",
        "unknown",
    }
)


class AnalysisError(ValueError):
    """Raised when an analysis profile or structured fact is not trustworthy."""


class FindingClassification(str, Enum):
    """Evidence strength, deliberately separate from a gate outcome."""

    PROVEN = "PROVEN"
    REVIEW = "REVIEW"
    SAFE = "SAFE"


class GateStatus(str, Enum):
    """Machine-readable, non-crediting gate states."""

    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"
    SAFE = "SAFE"
    UNAVAILABLE = "UNAVAILABLE"
    SKIPPED = "SKIPPED"
    TIMEOUT = "TIMEOUT"


class ProofKind(str, Enum):
    """The only evidence origins understood by the generic source gate."""

    SOURCE_CANDIDATE = "source-candidate"
    COMPILER_INVALID = "compiler-invalid"
    CONTRACT_PROVEN = "contract-proven"
    TOOL_UNAVAILABLE = "tool-unavailable"


@dataclass(frozen=True)
class AnalysisFinding:
    rule_id: str
    classification: FindingClassification
    proof_kind: ProofKind
    message: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class GateOutcome:
    status: GateStatus
    findings: tuple[AnalysisFinding, ...]
    pass_credit: bool = False
    acceptance_pass: bool = False
    product_acceptance_pass: bool = False
    release_approved: bool = False


@dataclass(frozen=True)
class LanguageProfile:
    """An immutable loaded generic capability profile and its exact digest."""

    document: Mapping[str, Any]
    canonical_bytes: bytes
    digest: str

    @property
    def profile_id(self) -> str:
        return str(self.document["profileId"])

    @property
    def languages(self) -> tuple[str, ...]:
        return tuple(str(item) for item in self.document["languages"])

    @property
    def source_extensions(self) -> tuple[str, ...]:
        return tuple(str(item) for item in self.document["sourceExtensions"])

    @property
    def value_categories(self) -> Mapping[str, Mapping[str, Any]]:
        return self.document["valueCategories"]  # type: ignore[return-value]

    @property
    def documentation(self) -> Mapping[str, Any]:
        return self.document["documentation"]  # type: ignore[return-value]

    @property
    def verification(self) -> Mapping[str, Any]:
        return self.document["verification"]  # type: ignore[return-value]

    @property
    def binary_boundary(self) -> Mapping[str, Any]:
        return self.document["binaryBoundary"]  # type: ignore[return-value]


def _normalized(value: Any) -> Any:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, list):
        return [_normalized(item) for item in value]
    if isinstance(value, tuple):
        return [_normalized(item) for item in value]
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise AnalysisError("profile object keys must be strings")
            normalized[unicodedata.normalize("NFC", key)] = _normalized(item)
        return normalized
    return value


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            _normalized(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AnalysisError(f"{label} must be a non-empty string")
    return value


def _require_string_list(value: Any, label: str, *, unique: bool = True) -> list[str]:
    if not isinstance(value, list) or not value:
        raise AnalysisError(f"{label} must be a non-empty array")
    values = [_require_string(item, f"{label} item") for item in value]
    if unique and len(values) != len(set(values)):
        raise AnalysisError(f"{label} must be unique")
    return values


def _require_exact_keys(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise AnalysisError(f"{label} must contain exactly {sorted(keys)}")
    return value


def _validate_profile_document(document: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(document, Mapping):
        raise AnalysisError("language capability profile must be an object")
    if set(document) != _PROFILE_REQUIRED_KEYS:
        missing = sorted(_PROFILE_REQUIRED_KEYS - set(document))
        extra = sorted(set(document) - _PROFILE_REQUIRED_KEYS)
        raise AnalysisError(f"language capability profile keys mismatch: missing={missing} extra={extra}")
    if document.get("schema") != PROFILE_SCHEMA:
        raise AnalysisError(f"profile schema must be {PROFILE_SCHEMA}")
    profile_id = _require_string(document.get("profileId"), "profileId")
    if not _ID.fullmatch(profile_id):
        raise AnalysisError("profileId must be a lowercase generic identifier")
    languages = _require_string_list(document.get("languages"), "languages")
    if any(not _ID.fullmatch(item) for item in languages):
        raise AnalysisError("language identifiers must be lowercase generic identifiers")
    extensions = _require_string_list(document.get("sourceExtensions"), "sourceExtensions")
    if any(not item.startswith(".") or "/" in item or "\\" in item for item in extensions):
        raise AnalysisError("sourceExtensions must contain file suffixes only")

    documentation = _require_exact_keys(
        document.get("documentation"),
        {"recommended", "userChoice", "primary", "optional"},
        "documentation",
    )
    if not isinstance(documentation["recommended"], bool):
        raise AnalysisError("documentation.recommended must be boolean")
    if documentation["userChoice"] not in {"ask", "accept", "decline", "profile-default"}:
        raise AnalysisError("documentation.userChoice is invalid")
    _require_string_list(documentation["primary"], "documentation.primary")
    if not isinstance(documentation["optional"], list) or any(
        not isinstance(item, str) or not item for item in documentation["optional"]
    ):
        raise AnalysisError("documentation.optional must be a string array")

    verification = _require_exact_keys(
        document.get("verification"),
        {"cheapRequired", "recommended", "optional"},
        "verification",
    )
    for key in verification:
        if not isinstance(verification[key], list) or any(
            not isinstance(item, str) or not item for item in verification[key]
        ):
            raise AnalysisError(f"verification.{key} must be a string array")
    artifact_policy = _require_exact_keys(
        document.get("artifactPolicy"),
        {"defaultMode", "trackedSummary", "diagnosticRoot", "forensicRoot"},
        "artifactPolicy",
    )
    if artifact_policy["defaultMode"] not in {"minimal", "diagnostic", "forensic"}:
        raise AnalysisError("artifactPolicy.defaultMode is invalid")
    if artifact_policy["trackedSummary"] is not True:
        raise AnalysisError("artifactPolicy.trackedSummary must remain true")
    for key in ("diagnosticRoot", "forensicRoot"):
        text = _require_string(artifact_policy[key], f"artifactPolicy.{key}")
        if text.startswith("/") or "\\" in text or ".." in text.split("/"):
            raise AnalysisError(f"artifactPolicy.{key} must be a safe portable relative path")

    categories = document.get("valueCategories")
    if not isinstance(categories, Mapping) or set(categories) != _VALUE_CATEGORIES:
        raise AnalysisError("valueCategories must define exactly the five C-family transfer categories")
    for category, rule in categories.items():
        if not isinstance(rule, Mapping) or set(rule) != {
            "unknownClassification",
            "observablePostconditions",
            "allowedDestinations",
        }:
            raise AnalysisError(f"valueCategories.{category} has an invalid rule shape")
        if rule["unknownClassification"] != "REVIEW":
            raise AnalysisError(f"valueCategories.{category} must conservatively classify unknown as REVIEW")
        allowed_postconditions = _require_string_list(
            rule["observablePostconditions"], f"valueCategories.{category}.observablePostconditions"
        )
        if not set(allowed_postconditions) <= _POSTCONDITIONS - {"unknown", "not-observable"}:
            raise AnalysisError(f"valueCategories.{category} permits an invalid observable postcondition")
        destinations = _require_string_list(
            rule["allowedDestinations"], f"valueCategories.{category}.allowedDestinations"
        )
        if not set(destinations) <= _DESTINATION_CATEGORIES:
            raise AnalysisError(f"valueCategories.{category} permits an invalid destination category")

    binary_boundary = _require_exact_keys(
        document.get("binaryBoundary"),
        {
            "explicitConstCorrectConversion",
            "exactSizeRequired",
            "ownershipPreservationRequired",
            "forbidCompatibilityHelper",
            "allowedSourceRepresentations",
            "allowedDestinationRepresentations",
        },
        "binaryBoundary",
    )
    for key in (
        "explicitConstCorrectConversion",
        "exactSizeRequired",
        "ownershipPreservationRequired",
        "forbidCompatibilityHelper",
    ):
        if binary_boundary[key] is not True:
            raise AnalysisError(f"binaryBoundary.{key} must be fail-closed true")
    if binary_boundary["allowedSourceRepresentations"] != ["byte-storage"]:
        raise AnalysisError("binaryBoundary must declare one explicit byte storage source")
    if binary_boundary["allowedDestinationRepresentations"] != ["const-unsigned-byte-view"]:
        raise AnalysisError("binaryBoundary must declare one explicit const unsigned byte view")

    visibility = _require_exact_keys(
        document.get("directVisibility"),
        {"uniqueOwnerRequired", "routes", "maskedRegions", "excludedSymbols"},
        "directVisibility",
    )
    if visibility["uniqueOwnerRequired"] is not True:
        raise AnalysisError("directVisibility.uniqueOwnerRequired must be true")
    if set(_require_string_list(visibility["routes"], "directVisibility.routes")) != {
        "direct-import",
        "explicit-export-import-closure",
        "same-named-module",
    }:
        raise AnalysisError("directVisibility.routes is incomplete")
    if set(_require_string_list(visibility["maskedRegions"], "directVisibility.maskedRegions")) != {
        "comments",
        "preprocessor",
        "ordinary-strings",
        "raw-strings",
        "character-literals",
        "embedded-language-payloads",
    }:
        raise AnalysisError("directVisibility.maskedRegions is incomplete")
    if set(_require_string_list(visibility["excludedSymbols"], "directVisibility.excludedSymbols")) != {
        "template-parameters",
        "local-declarations",
        "member-access",
        "qualified-namespace-components",
    }:
        raise AnalysisError("directVisibility.excludedSymbols is incomplete")

    compiler_rules = document.get("compilerFailureProfiles")
    if not isinstance(compiler_rules, list):
        raise AnalysisError("compilerFailureProfiles must be an array")
    seen_rules: set[str] = set()
    for rule in compiler_rules:
        expected = {"id", "classification", "expression", "message", "toolchainPredicate", "requiresCompilerDiagnostic"}
        if not isinstance(rule, Mapping) or set(rule) != expected:
            raise AnalysisError("compiler failure rule has an invalid shape")
        rule_id = _require_string(rule["id"], "compiler failure rule id")
        if not _ID.fullmatch(rule_id) or rule_id in seen_rules:
            raise AnalysisError("compiler failure rule id is invalid or duplicate")
        seen_rules.add(rule_id)
        if rule["classification"] not in {"PROVEN", "REVIEW"}:
            raise AnalysisError("compiler failure rule classification is invalid")
        _require_string(rule["expression"], "compiler failure rule expression")
        _require_string(rule["message"], "compiler failure rule message")
        predicate = rule["toolchainPredicate"]
        if predicate is not None:
            if not isinstance(predicate, Mapping) or set(predicate) - {"families", "minimumVersion", "maximumVersion"}:
                raise AnalysisError("compiler failure toolchain predicate has an invalid shape")
            families = predicate.get("families", [])
            if not isinstance(families, list) or not families or any(not isinstance(item, str) or not item for item in families):
                raise AnalysisError("compiler failure toolchain families must be a non-empty string array")
            for field in ("minimumVersion", "maximumVersion"):
                if field in predicate and (not isinstance(predicate[field], str) or not predicate[field]):
                    raise AnalysisError(f"compiler failure {field} must be a non-empty string")
        if not isinstance(rule["requiresCompilerDiagnostic"], bool):
            raise AnalysisError("compiler failure requiresCompilerDiagnostic must be boolean")
        if rule["classification"] == "PROVEN" and rule["requiresCompilerDiagnostic"] is not True:
            raise AnalysisError("PROVEN compiler rules require an actual compiler diagnostic")

    semantic_roles = document.get("semanticRoles")
    if not isinstance(semantic_roles, Mapping) or set(semantic_roles) != {"roles", "classificationSources", "forbidden"}:
        raise AnalysisError("semanticRoles has an invalid shape")
    roles = semantic_roles["roles"]
    if not isinstance(roles, Mapping) or set(roles) != {"COMMAND", "QUERY", "VALUE_QUERY"}:
        raise AnalysisError("semanticRoles must define COMMAND, QUERY and VALUE_QUERY")
    expected_roles = {
        "COMMAND": ("mutation", {"command-result", "explicit-status"}),
        "QUERY": ("read", {"query-result", "value"}),
        "VALUE_QUERY": ("read", {"value"}),
    }
    for role, (effect, allowed_results) in expected_roles.items():
        rule = roles[role]
        if not isinstance(rule, Mapping) or set(rule) != {"effect", "allowedResults"}:
            raise AnalysisError(f"semantic role {role} has an invalid rule shape")
        if rule["effect"] != effect or set(_require_string_list(rule["allowedResults"], f"semantic role {role} results")) != allowed_results:
            raise AnalysisError(f"semantic role {role} is incompatible")
    if set(_require_string_list(semantic_roles["classificationSources"], "semantic role classification sources")) != {
        "annotation",
        "project-mapping",
        "configurable-naming-rule",
    }:
        raise AnalysisError("semantic role classification sources are incomplete")
    if set(_require_string_list(semantic_roles["forbidden"], "semantic role forbidden pairs")) != {
        "command-returning-query-result",
        "query-returning-command-result",
    }:
        raise AnalysisError("semantic role forbidden pairs are incomplete")

    documentation_quality = _require_exact_keys(
        document.get("documentationQuality"),
        {"priorities", "meaningfulFields", "forbiddenCredit", "generatedDetail", "initModes", "userOverrideRequired"},
        "documentationQuality",
    )
    if set(_require_string_list(documentation_quality["priorities"], "documentationQuality.priorities")) != {
        "high-fanout",
        "ownership",
        "lifetime",
        "failure-semantics",
        "transaction",
        "configuration-boundary",
    }:
        raise AnalysisError("documentation quality priorities are incomplete")
    if set(_require_string_list(documentation_quality["meaningfulFields"], "documentationQuality.meaningfulFields")) != {
        "purpose",
        "ownership",
        "lifetime",
        "failure",
        "configuration",
    }:
        raise AnalysisError("documentation quality fields are incomplete")
    if set(_require_string_list(documentation_quality["forbiddenCredit"], "documentationQuality.forbiddenCredit")) != {
        "empty-comment",
        "filename-only-comment",
        "generated-boilerplate",
        "host-local-html-presence",
    }:
        raise AnalysisError("documentation quality forbidden credit is incomplete")
    if documentation_quality["generatedDetail"] != "host-local":
        raise AnalysisError("generated documentation detail must remain host-local")
    if set(_require_string_list(documentation_quality["initModes"], "documentationQuality.initModes")) != {
        "off",
        "minimal",
        "standard",
        "diagnostic",
    }:
        raise AnalysisError("documentation quality init modes are incomplete")
    if documentation_quality["userOverrideRequired"] is not True:
        raise AnalysisError("documentation quality must require explicit user override")

    interface_weight = _require_exact_keys(
        document.get("interfaceWeight"),
        {"classification", "metrics", "automaticDefect", "automaticDecomposition", "generatedDetailRoot", "thresholdsAreProfileOverrides", "truncationMustBeExplicit"},
        "interfaceWeight",
    )
    if interface_weight["classification"] != "REVIEW_ONLY":
        raise AnalysisError("interface weight must remain REVIEW_ONLY")
    if interface_weight["automaticDefect"] is not False or interface_weight["automaticDecomposition"] is not False:
        raise AnalysisError("interface weight must not authorize automatic defects or decomposition")
    if interface_weight["generatedDetailRoot"] != "host-local" or interface_weight["thresholdsAreProfileOverrides"] is not True or interface_weight["truncationMustBeExplicit"] is not True:
        raise AnalysisError("interface weight output policy is invalid")
    _require_string_list(interface_weight["metrics"], "interfaceWeight.metrics")

    gate_admission = _require_exact_keys(
        document.get("gateAdmission"),
        {"ordering", "gitHeadAloneInvalidates", "invalidationClasses", "requiredReceiptFields"},
        "gateAdmission",
    )
    if gate_admission["ordering"] != "cheapest-sufficient-first" or gate_admission["gitHeadAloneInvalidates"] is not False:
        raise AnalysisError("gate admission must remain source-first and ignore HEAD-only invalidation")
    if set(_require_string_list(gate_admission["invalidationClasses"], "gateAdmission.invalidationClasses")) != {
        "BODY_ONLY",
        "IMPORT_SURFACE",
        "CMAKE_TOPOLOGY",
        "TOOLING_ONLY",
    }:
        raise AnalysisError("gate admission invalidation classes are incomplete")
    if set(_require_string_list(gate_admission["requiredReceiptFields"], "gateAdmission.requiredReceiptFields")) != {
        "elapsed-seconds",
        "input-digest",
        "scope-count",
        "status",
        "credit",
    }:
        raise AnalysisError("gate admission receipt fields are incomplete")

    claims = _require_exact_keys(
        document.get("claims"),
        {"acceptancePass", "passCredit", "productAcceptancePass", "releaseApproved"},
        "claims",
    )
    if any(value is not False for value in claims.values()):
        raise AnalysisError("language capability profile must not grant acceptance or credit")
    return deepcopy(dict(document))


def parse_language_profile(document: Mapping[str, Any]) -> LanguageProfile:
    """Validate one complete generic profile and bind its canonical bytes."""

    normalized = _validate_profile_document(document)
    payload = _canonical_bytes(normalized)
    return LanguageProfile(
        document=normalized,
        canonical_bytes=payload,
        digest=hashlib.sha256(payload).hexdigest(),
    )


def load_language_profile(path: Path | str) -> LanguageProfile:
    """Load one regular JSON profile without searching a project or host path."""

    profile_path = Path(path)
    try:
        if profile_path.is_symlink() or not profile_path.is_file():
            raise AnalysisError("language capability profile must be a regular file")
        value = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AnalysisError(f"cannot load language capability profile: {exc}") from exc
    return parse_language_profile(value)


def _deep_overlay(base: Any, override: Any) -> Any:
    if isinstance(base, Mapping) and isinstance(override, Mapping):
        result = {key: deepcopy(value) for key, value in base.items()}
        for key, value in override.items():
            result[key] = _deep_overlay(result[key], value) if key in result else deepcopy(value)
        return result
    return deepcopy(override)


def overlay_language_profile(base: LanguageProfile, override: Mapping[str, Any]) -> LanguageProfile:
    """Apply one bounded project/user overlay to a selected Standard profile.

    The overlay cannot replace the schema, profile identity, or false-claim
    invariant.  It is data, not a second profile authority.
    """

    if not isinstance(override, Mapping):
        raise AnalysisError("language profile override must be an object")
    forbidden = {"schema", "profileId", "claims"} & set(override)
    unknown = set(override) - (_PROFILE_KEYS - {"schema", "profileId", "claims"})
    if forbidden or unknown:
        raise AnalysisError(f"language profile override is not bounded: forbidden={sorted(forbidden)} unknown={sorted(unknown)}")
    merged = _deep_overlay(base.document, override)
    return parse_language_profile(merged)


def _coerce_classification(value: FindingClassification | str) -> FindingClassification:
    try:
        return value if isinstance(value, FindingClassification) else FindingClassification(value)
    except ValueError as exc:
        raise AnalysisError("unknown finding classification") from exc


def _coerce_proof_kind(value: ProofKind | str) -> ProofKind:
    try:
        return value if isinstance(value, ProofKind) else ProofKind(value)
    except ValueError as exc:
        raise AnalysisError("unknown proof kind") from exc


def classify_finding(
    *,
    rule_id: str,
    classification: FindingClassification | str,
    proof_kind: ProofKind | str,
    message: str,
    evidence: Sequence[str],
) -> AnalysisFinding:
    """Create a finding while enforcing the no-regex-to-PROVEN boundary."""

    if not _ID.fullmatch(rule_id):
        raise AnalysisError("rule_id must be a lowercase generic identifier")
    selected = _coerce_classification(classification)
    origin = _coerce_proof_kind(proof_kind)
    if selected is FindingClassification.PROVEN and origin not in {
        ProofKind.COMPILER_INVALID,
        ProofKind.CONTRACT_PROVEN,
    }:
        raise AnalysisError("PROVEN findings require compiler-invalid or contract-proven evidence")
    rendered_message = _require_string(message, "finding message")
    rendered_evidence = tuple(_require_string(item, "finding evidence") for item in evidence)
    if not rendered_evidence:
        raise AnalysisError("finding evidence must be non-empty")
    return AnalysisFinding(rule_id, selected, origin, rendered_message, rendered_evidence)


def evaluate_findings(
    findings: Iterable[AnalysisFinding],
    *,
    unavailable: bool = False,
    skipped: bool = False,
) -> GateOutcome:
    """Fold typed findings without deriving any acceptance or pass credit."""

    values = tuple(findings)
    if unavailable and skipped:
        raise AnalysisError("a gate cannot be both unavailable and skipped")
    if any(item.classification is FindingClassification.PROVEN for item in values):
        status = GateStatus.FAIL
    elif unavailable:
        status = GateStatus.UNAVAILABLE
    elif skipped:
        status = GateStatus.SKIPPED
    elif any(item.classification is FindingClassification.REVIEW for item in values):
        status = GateStatus.REVIEW
    elif values:
        status = GateStatus.SAFE
    else:
        status = GateStatus.PASS
    return GateOutcome(status=status, findings=values)


def assess_transfer(
    profile: LanguageProfile,
    *,
    source_category: str,
    destination_category: str,
    source_observable_after_transfer: bool,
    postcondition: str,
    source_scope: str,
    destination_scope: str,
) -> AnalysisFinding:
    """Assess one scoped ownership transfer against the selected profile."""

    if not isinstance(source_observable_after_transfer, bool):
        raise AnalysisError("source_observable_after_transfer must be boolean")
    if not all(isinstance(item, str) and item for item in (source_scope, destination_scope)):
        raise AnalysisError("transfer scopes must be non-empty identifiers")
    if source_category not in profile.value_categories or destination_category not in _DESTINATION_CATEGORIES:
        return classify_finding(
            rule_id="unknown-value-category",
            classification=FindingClassification.REVIEW,
            proof_kind=ProofKind.SOURCE_CANDIDATE,
            message="transfer category is not modeled by the selected language profile",
            evidence=(source_category, destination_category),
        )
    if destination_category not in profile.value_categories[source_category]["allowedDestinations"]:
        return classify_finding(
            rule_id="forbidden-transfer-destination",
            classification=FindingClassification.PROVEN,
            proof_kind=ProofKind.CONTRACT_PROVEN,
            message="selected language profile forbids this ownership transfer destination",
            evidence=(source_category, destination_category),
        )
    if postcondition not in _POSTCONDITIONS:
        return classify_finding(
            rule_id="unknown-transfer-postcondition",
            classification=FindingClassification.REVIEW,
            proof_kind=ProofKind.SOURCE_CANDIDATE,
            message="transfer postcondition is not modeled by the selected language profile",
            evidence=(postcondition,),
        )
    if source_scope != destination_scope:
        return classify_finding(
            rule_id="cross-scope-transfer",
            classification=FindingClassification.REVIEW,
            proof_kind=ProofKind.SOURCE_CANDIDATE,
            message="transfer analysis does not prove ownership across scope boundaries",
            evidence=(source_scope, destination_scope),
        )
    if not source_observable_after_transfer:
        if postcondition == "not-observable":
            return classify_finding(
                rule_id="transfer-postcondition",
                classification=FindingClassification.SAFE,
                proof_kind=ProofKind.CONTRACT_PROVEN,
                message="source is not observable after the transfer",
                evidence=(source_category, destination_category),
            )
        return classify_finding(
            rule_id="transfer-postcondition",
            classification=FindingClassification.PROVEN,
            proof_kind=ProofKind.CONTRACT_PROVEN,
            message="a non-observable source must declare the not-observable postcondition",
            evidence=(postcondition,),
        )
    allowed = set(profile.value_categories[source_category]["observablePostconditions"])
    if postcondition in allowed:
        return classify_finding(
            rule_id="transfer-postcondition",
            classification=FindingClassification.SAFE,
            proof_kind=ProofKind.CONTRACT_PROVEN,
            message="observable moved-from state has a deterministic postcondition",
            evidence=(postcondition,),
        )
    return classify_finding(
        rule_id="transfer-postcondition",
        classification=FindingClassification.PROVEN,
        proof_kind=ProofKind.CONTRACT_PROVEN,
        message="observable moved-from state lacks a deterministic postcondition",
        evidence=(postcondition,),
    )


def assess_binary_boundary(
    profile: LanguageProfile,
    *,
    source_representation: str,
    destination_representation: str,
    conversion: str,
    exact_size: bool,
    ownership_preserved: bool,
    compatibility_helper: bool,
) -> AnalysisFinding:
    """Validate one explicit binary representation conversion boundary."""

    if not all(isinstance(item, bool) for item in (exact_size, ownership_preserved, compatibility_helper)):
        raise AnalysisError("binary boundary boolean facts are invalid")
    boundary = profile.binary_boundary
    if (
        source_representation not in boundary["allowedSourceRepresentations"]
        or destination_representation not in boundary["allowedDestinationRepresentations"]
    ):
        return classify_finding(
            rule_id="unknown-binary-representation",
            classification=FindingClassification.REVIEW,
            proof_kind=ProofKind.SOURCE_CANDIDATE,
            message="binary representation is not modeled by the selected language profile",
            evidence=(source_representation, destination_representation),
        )
    failures: list[str] = []
    if conversion != "explicit-const-unsigned-byte-view":
        failures.append("explicit-conversion")
    if exact_size is not True:
        failures.append("exact-size")
    if ownership_preserved is not True:
        failures.append("ownership-preservation")
    if compatibility_helper is True:
        failures.append("compatibility-helper")
    if failures:
        return classify_finding(
            rule_id="binary-representation-boundary",
            classification=FindingClassification.PROVEN,
            proof_kind=ProofKind.CONTRACT_PROVEN,
            message="binary representation boundary violates an explicit typed requirement",
            evidence=(source_representation, *failures),
        )
    return classify_finding(
        rule_id="binary-representation-boundary",
        classification=FindingClassification.SAFE,
        proof_kind=ProofKind.CONTRACT_PROVEN,
        message="binary representation boundary is explicit, const-correct, and size preserving",
        evidence=(source_representation, destination_representation),
    )


_OWNER_REQUIREMENTS: Mapping[str, frozenset[str]] = {
    "MOVABLE_OWNER": frozenset(
        {"copy_contract_explicit", "move_constructor_complete", "move_assignment_complete"}
    ),
    "EXPLICITLY_IMMOBILE": frozenset(
        {
            "copy_constructor_deleted",
            "copy_assignment_deleted",
            "move_constructor_deleted",
            "move_assignment_deleted",
        }
    ),
    "TRANSACTIONAL_EXCHANGE": frozenset(
        {"copy_contract_explicit", "move_contract_explicit", "noexcept_exchange", "rollback_owner_preserved"}
    ),
}


def validate_owner_mobility(contract: Mapping[str, Any]) -> AnalysisFinding:
    """Require one complete raw-owner policy; partial contracts fail closed."""

    if not isinstance(contract, Mapping):
        raise AnalysisError("owner mobility contract must be an object")
    policy = contract.get("policy")
    if policy not in _OWNER_REQUIREMENTS:
        return classify_finding(
            rule_id="unknown-owner-mobility-policy",
            classification=FindingClassification.REVIEW,
            proof_kind=ProofKind.SOURCE_CANDIDATE,
            message="raw owner mobility policy is not modeled",
            evidence=(str(policy),),
        )
    required = _OWNER_REQUIREMENTS[policy]
    missing = sorted(name for name in required if contract.get(name) is not True)
    unexpected_true = sorted(
        name for name, value in contract.items() if name != "policy" and value is True and name not in required
    )
    if missing or unexpected_true:
        return classify_finding(
            rule_id="raw-owner-mobility",
            classification=FindingClassification.PROVEN,
            proof_kind=ProofKind.CONTRACT_PROVEN,
            message="raw owner mobility policy is partial or mixes incompatible policy facts",
            evidence=(policy, *missing, *unexpected_true),
        )
    return classify_finding(
        rule_id="raw-owner-mobility",
        classification=FindingClassification.SAFE,
        proof_kind=ProofKind.CONTRACT_PROVEN,
        message="raw owner declares one complete mobility policy",
        evidence=(policy,),
    )


def compiler_failure_candidate(
    profile: LanguageProfile,
    *,
    rule_id: str,
    observed_text: str,
    compiler_diagnostic: bool,
    toolchain: Mapping[str, str] | None = None,
) -> AnalysisFinding:
    """Classify a data-driven compiler-pattern candidate conservatively."""

    selected = next(
        (item for item in profile.document["compilerFailureProfiles"] if item["id"] == rule_id),
        None,
    )
    if selected is None:
        raise AnalysisError("unknown compiler failure rule")
    predicate = selected["toolchainPredicate"]
    if predicate is not None:
        if toolchain is None or not isinstance(toolchain.get("family"), str) or not isinstance(toolchain.get("version"), str):
            return classify_finding(
                rule_id=rule_id,
                classification=FindingClassification.REVIEW,
                proof_kind=ProofKind.SOURCE_CANDIDATE,
                message="compiler failure pattern has no matching verified toolchain identity",
                evidence=(rule_id,),
            )
        if not _toolchain_matches(predicate, toolchain):
            return classify_finding(
                rule_id=rule_id,
                classification=FindingClassification.SAFE,
                proof_kind=ProofKind.SOURCE_CANDIDATE,
                message="compiler failure pattern does not apply to this toolchain identity",
                evidence=(rule_id, str(toolchain["family"]), str(toolchain["version"])),
            )
    try:
        matched = re.search(str(selected["expression"]), observed_text) is not None
    except re.error as exc:
        raise AnalysisError("compiler failure expression is invalid") from exc
    if not matched:
        return classify_finding(
            rule_id=rule_id,
            classification=FindingClassification.SAFE,
            proof_kind=ProofKind.SOURCE_CANDIDATE,
            message="compiler failure pattern did not match",
            evidence=(rule_id,),
        )
    classification = FindingClassification(str(selected["classification"]))
    if classification is FindingClassification.PROVEN and compiler_diagnostic and selected["requiresCompilerDiagnostic"] is True:
        proof_kind = ProofKind.COMPILER_INVALID
    else:
        classification = FindingClassification.REVIEW
        proof_kind = ProofKind.SOURCE_CANDIDATE
    return classify_finding(
        rule_id=rule_id,
        classification=classification,
        proof_kind=proof_kind,
        message=str(selected["message"]),
        evidence=(rule_id,),
    )


def _version_key(value: str) -> tuple[int, ...] | None:
    pieces = value.split(".")
    if not pieces or any(not piece.isascii() or not piece.isdigit() for piece in pieces):
        return None
    return tuple(int(piece) for piece in pieces)


def _toolchain_matches(predicate: Mapping[str, Any], toolchain: Mapping[str, str]) -> bool:
    """Compare generic family/version predicates without a product toolchain list."""

    if toolchain["family"] not in predicate["families"]:
        return False
    actual = _version_key(toolchain["version"])
    if actual is None:
        return False
    minimum = predicate.get("minimumVersion")
    maximum = predicate.get("maximumVersion")
    minimum_key = None if minimum is None else _version_key(minimum)
    maximum_key = None if maximum is None else _version_key(maximum)
    if minimum is not None and minimum_key is None:
        return False
    if maximum is not None and maximum_key is None:
        return False
    return (minimum_key is None or actual >= minimum_key) and (maximum_key is None or actual <= maximum_key)


def assess_direct_visibility(
    profile: LanguageProfile,
    *,
    unique_owner: bool,
    owner_module: str,
    using_module: str,
    direct_imports: Iterable[str],
    export_import_closure: Iterable[str],
) -> AnalysisFinding:
    """Require one explicit visibility route for a uniquely owned exported type."""

    if not isinstance(unique_owner, bool) or not all(
        isinstance(item, str) and item for item in (owner_module, using_module)
    ):
        raise AnalysisError("direct visibility facts are invalid")
    direct = set(direct_imports)
    closure = set(export_import_closure)
    if any(not isinstance(item, str) or not item for item in (*direct, *closure)):
        raise AnalysisError("direct visibility module identities are invalid")
    if not unique_owner:
        return classify_finding(
            rule_id="ambiguous-export-owner",
            classification=FindingClassification.REVIEW,
            proof_kind=ProofKind.SOURCE_CANDIDATE,
            message="type ownership is not unique, so direct visibility cannot be proven",
            evidence=(owner_module, using_module),
        )
    if owner_module == using_module:
        route = "same-named-module"
    elif owner_module in direct:
        route = "direct-import"
    elif owner_module in closure:
        route = "explicit-export-import-closure"
    else:
        return classify_finding(
            rule_id="direct-module-visibility",
            classification=FindingClassification.PROVEN,
            proof_kind=ProofKind.CONTRACT_PROVEN,
            message="uniquely owned exported type has no direct or explicit re-export visibility route",
            evidence=(owner_module, using_module),
        )
    if route not in profile.document["directVisibility"]["routes"]:
        raise AnalysisError("selected profile does not permit the observed visibility route")
    return classify_finding(
        rule_id="direct-module-visibility",
        classification=FindingClassification.SAFE,
        proof_kind=ProofKind.CONTRACT_PROVEN,
        message="uniquely owned exported type has an explicit visibility route",
        evidence=(owner_module, using_module, route),
    )


def validate_semantic_operation(
    profile: LanguageProfile,
    *,
    role: str | None,
    effect: str,
    result_kind: str,
    classification_source: str,
) -> AnalysisFinding:
    """Check a profile-resolved command/query role without naming assumptions."""

    roles = profile.document["semanticRoles"]["roles"]
    if classification_source not in profile.document["semanticRoles"]["classificationSources"] or role not in roles:
        return classify_finding(
            rule_id="unknown-semantic-operation-role",
            classification=FindingClassification.REVIEW,
            proof_kind=ProofKind.SOURCE_CANDIDATE,
            message="operation role is not resolved by an allowed profile source",
            evidence=(str(role), classification_source),
        )
    rule = roles[role]
    if effect != rule["effect"] or result_kind not in rule["allowedResults"]:
        return classify_finding(
            rule_id="semantic-operation-role",
            classification=FindingClassification.PROVEN,
            proof_kind=ProofKind.CONTRACT_PROVEN,
            message="operation effect and result are incompatible with its declared semantic role",
            evidence=(role, effect, result_kind),
        )
    return classify_finding(
        rule_id="semantic-operation-role",
        classification=FindingClassification.SAFE,
        proof_kind=ProofKind.CONTRACT_PROVEN,
        message="operation effect and result are compatible with its declared semantic role",
        evidence=(role, effect, result_kind),
    )


def interface_weight_review(profile: LanguageProfile, metrics: Mapping[str, int], *, threshold: int) -> AnalysisFinding:
    """Produce a bounded REVIEW-only interface prioritization signal."""

    if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 0:
        raise AnalysisError("interface weight threshold must be a non-negative integer")
    allowed = set(profile.document["interfaceWeight"]["metrics"])
    if set(metrics) - allowed or any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in metrics.values()):
        raise AnalysisError("interface weight metrics are invalid")
    score = sum(metrics.values())
    if score > threshold:
        return classify_finding(
            rule_id="interface-weight-review",
            classification=FindingClassification.REVIEW,
            proof_kind=ProofKind.SOURCE_CANDIDATE,
            message="bounded structural metrics request review only",
            evidence=(str(score), str(threshold)),
        )
    return classify_finding(
        rule_id="interface-weight-review",
        classification=FindingClassification.SAFE,
        proof_kind=ProofKind.SOURCE_CANDIDATE,
        message="bounded structural metrics are below the selected review threshold",
        evidence=(str(score), str(threshold)),
    )
