from __future__ import annotations

from pathlib import Path

import pytest

from promin.cpp_lexical import c_family_identifiers, mask_c_family_source
from promin.language_analysis import (
    AnalysisError,
    FindingClassification,
    GateStatus,
    assess_binary_boundary,
    assess_direct_visibility,
    assess_transfer,
    classify_finding,
    compiler_failure_candidate,
    evaluate_findings,
    interface_weight_review,
    load_language_profile,
    overlay_language_profile,
    validate_semantic_operation,
    validate_owner_mobility,
)


ROOT = Path(__file__).parents[1]


def _profile():
    return load_language_profile(ROOT / "language_profiles" / "c-family-semantic.json")


def test_c_family_profile_is_generic_and_has_all_required_value_categories() -> None:
    profile = _profile()

    assert profile.profile_id == "c-family-semantic"
    assert profile.languages == ("c", "cpp")
    assert set(profile.value_categories) == {
        "by-value",
        "rvalue-reference",
        "borrowed-reference",
        "member",
        "result-extraction",
    }
    assert profile.documentation["userChoice"] == "ask"
    assert "mor" + "ok" not in profile.canonical_bytes.decode("utf-8").casefold()
    assert "to" + "wer" not in profile.canonical_bytes.decode("utf-8").casefold()


def test_source_candidate_cannot_be_promoted_to_proven_without_independent_proof() -> None:
    with pytest.raises(AnalysisError, match="compiler-invalid or contract-proven"):
        classify_finding(
            rule_id="textual-candidate",
            classification=FindingClassification.PROVEN,
            proof_kind="source-candidate",
            message="a raw token was found",
            evidence=("token",),
        )

    candidate = classify_finding(
        rule_id="textual-candidate",
        classification=FindingClassification.REVIEW,
        proof_kind="source-candidate",
        message="a raw token was found",
        evidence=("token",),
    )
    result = evaluate_findings((candidate,))

    assert result.status is GateStatus.REVIEW
    assert result.pass_credit is False
    assert result.acceptance_pass is False


def test_profile_overlay_is_digest_bound_and_cannot_replace_standard_identity() -> None:
    profile = _profile()
    overlay = overlay_language_profile(
        profile,
        {
            "valueCategories": {
                "borrowed-reference": {
                    "allowedDestinations": ["member"]
                }
            }
        },
    )
    assert overlay.profile_id == profile.profile_id
    assert overlay.digest != profile.digest
    assert overlay.value_categories["borrowed-reference"]["allowedDestinations"] == ["member"]
    with pytest.raises(AnalysisError, match="forbidden"):
        overlay_language_profile(profile, {"profileId": "other"})


def test_contract_proven_transfer_requires_deterministic_observable_postcondition() -> None:
    profile = _profile()
    finding = assess_transfer(
        profile,
        source_category="by-value",
        destination_category="member",
        source_observable_after_transfer=True,
        postcondition="unknown",
        source_scope="operation:one",
        destination_scope="operation:one",
    )

    assert finding.classification is FindingClassification.PROVEN
    assert evaluate_findings((finding,)).status is GateStatus.FAIL

    cross_scope = assess_transfer(
        profile,
        source_category="by-value",
        destination_category="member",
        source_observable_after_transfer=False,
        postcondition="not-observable",
        source_scope="operation:one",
        destination_scope="operation:two",
    )
    assert cross_scope.classification is FindingClassification.REVIEW

    external = assess_transfer(
        profile,
        source_category="result-extraction",
        destination_category="external-owner",
        source_observable_after_transfer=False,
        postcondition="not-observable",
        source_scope="operation:one",
        destination_scope="operation:one",
    )
    assert external.classification is FindingClassification.SAFE


def test_binary_boundary_and_owner_policy_are_complete_or_fail_closed() -> None:
    profile = _profile()
    unsafe = assess_binary_boundary(
        profile,
        source_representation="byte-storage",
        destination_representation="const-unsigned-byte-view",
        conversion="implicit",
        exact_size=False,
        ownership_preserved=False,
        compatibility_helper=True,
    )
    assert unsafe.classification is FindingClassification.PROVEN

    safe = assess_binary_boundary(
        profile,
        source_representation="byte-storage",
        destination_representation="const-unsigned-byte-view",
        conversion="explicit-const-unsigned-byte-view",
        exact_size=True,
        ownership_preserved=True,
        compatibility_helper=False,
    )
    assert safe.classification is FindingClassification.SAFE

    partial_owner = validate_owner_mobility(
        {"policy": "MOVABLE_OWNER", "copy_contract_explicit": True}
    )
    assert partial_owner.classification is FindingClassification.PROVEN
    immobile = validate_owner_mobility(
        {
            "policy": "EXPLICITLY_IMMOBILE",
            "copy_constructor_deleted": True,
            "copy_assignment_deleted": True,
            "move_constructor_deleted": True,
            "move_assignment_deleted": True,
        }
    )
    assert immobile.classification is FindingClassification.SAFE


def test_direct_visibility_and_compiler_profiles_are_fail_closed() -> None:
    profile = _profile()
    missing = assess_direct_visibility(
        profile,
        unique_owner=True,
        owner_module="owner-module",
        using_module="using-module",
        direct_imports=(),
        export_import_closure=(),
    )
    assert missing.classification is FindingClassification.PROVEN
    direct = assess_direct_visibility(
        profile,
        unique_owner=True,
        owner_module="owner-module",
        using_module="using-module",
        direct_imports=("owner-module",),
        export_import_closure=(),
    )
    assert direct.classification is FindingClassification.SAFE

    raw = compiler_failure_candidate(
        profile,
        rule_id="compiler-invalid-visibility",
        observed_text="unknown type",
        compiler_diagnostic=False,
    )
    assert raw.classification is FindingClassification.REVIEW
    diagnosed = compiler_failure_candidate(
        profile,
        rule_id="compiler-invalid-visibility",
        observed_text="unknown type",
        compiler_diagnostic=True,
    )
    assert diagnosed.classification is FindingClassification.PROVEN


def test_operation_roles_and_interface_weight_never_turn_review_into_credit() -> None:
    profile = _profile()
    mismatch = validate_semantic_operation(
        profile,
        role="QUERY",
        effect="read",
        result_kind="command-result",
        classification_source="annotation",
    )
    assert mismatch.classification is FindingClassification.PROVEN
    valid = validate_semantic_operation(
        profile,
        role="VALUE_QUERY",
        effect="read",
        result_kind="value",
        classification_source="project-mapping",
    )
    assert valid.classification is FindingClassification.SAFE
    heavy = interface_weight_review(profile, {"line-count": 11, "export-count": 3}, threshold=10)
    outcome = evaluate_findings((heavy,))
    assert heavy.classification is FindingClassification.REVIEW
    assert outcome.status is GateStatus.REVIEW
    assert outcome.pass_credit is False


def test_lexical_mask_preserves_offsets_and_excludes_non_dependency_tokens() -> None:
    source = '''
// GhostComment
#define GHOST GhostPreprocessor
template <typename TemplateOnly>
void run(VisibleType value) {
  LocalType local;
  local.MemberOnly();
  auto shader = R"shader(GhostShader\nStillHidden)shader";
  const char* text = "GhostString";
  (void)value;
}
'''
    masked = mask_c_family_source(source)

    assert len(masked.masked) == len(source)
    assert masked.masked.count("\n") == source.count("\n")
    assert "GhostComment" not in masked.masked
    assert "GhostPreprocessor" not in masked.masked
    assert "GhostShader" not in masked.masked
    assert "GhostString" not in masked.masked

    occurrences = {item.name: item.exclusion for item in c_family_identifiers(source)}
    assert occurrences["TemplateOnly"] == "template-parameter"
    assert occurrences["local"] == "local-declaration"
    assert occurrences["MemberOnly"] == "member-access"
    assert occurrences["VisibleType"] is None


def test_explicit_embedded_payload_mask_is_offset_preserving_and_fail_closed_on_bad_range() -> None:
    source = "VisibleType payload = EmbeddedLanguageToken;\n"
    start = source.index("EmbeddedLanguageToken")
    end = start + len("EmbeddedLanguageToken")
    masked = mask_c_family_source(
        source,
        embedded_ranges=({"start": start, "end": end, "kind": "embedded-language-payloads"},),
    )
    assert len(masked.masked) == len(source)
    assert "EmbeddedLanguageToken" not in masked.masked
    assert masked.complete is True

    invalid = mask_c_family_source(source, embedded_ranges=({"start": -1, "end": 2},))
    assert invalid.complete is False
    assert invalid.errors == ("invalid embedded language range",)
