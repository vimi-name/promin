from __future__ import annotations

import json
from pathlib import Path

import pytest

from promin.init_profiles import (
    InitProfileError,
    ToolOutcome,
    load_init_profile,
    negotiate_language_capabilities,
    resolve_init_profile,
)


_ASSET_ROOT = Path(__file__).resolve().parents[1] / "capability_profiles"


def _standard_profile() -> dict[str, object]:
    return load_init_profile(_ASSET_ROOT / "standard-init.json")


def test_init_profile_resolution_is_layered_deterministic_and_non_authoritative() -> None:
    resolved = resolve_init_profile(
        _standard_profile(),
        host_override={"analysis_profile": "standard", "agent_slots": 4},
        project_override={"documentation_profile": "standard", "artifact_profile": "diagnostic"},
        cli_override={
            "provider_strategy": "full-scan",
            "autonomy": "standing-reversible",
            "selection": {
                "documentationChoice": "accept",
                "verificationChoice": "decline",
            },
        },
        interactive_override={
            "selection": {
                "documentationChoice": "custom",
                "verificationChoice": "accept",
                "customProfile": "compact-local-contour",
            }
        },
    )

    effective = resolved["effective"]
    assert effective["analysis_profile"] == "standard"
    assert effective["documentation_profile"] == "standard"
    assert effective["artifact_profile"] == "diagnostic"
    assert effective["provider_strategy"] == "full-scan"
    assert effective["autonomy"] == "standing-reversible"
    assert effective["selection"] == {
        "schema": "promin.init-analysis-choice.v1",
        "profile": "standard",
        "documentationChoice": "custom",
        "verificationChoice": "accept",
        "selectionSource": "interactive-user",
        "customProfile": "compact-local-contour",
    }
    assert resolved["provenance"] == {
        "analysis_profile": "host-profile",
        "documentation_profile": "project-package",
        "artifact_profile": "project-package",
        "autonomy": "cli",
        "agent_slots": "host-profile",
        "canonical_build_owners": "default",
        "provider_strategy": "cli",
        "selection.profile": "host-profile",
        "selection.documentationChoice": "interactive-user",
        "selection.verificationChoice": "interactive-user",
        "selection.customProfile": "interactive-user",
    }
    assert resolved["selection_source"] == "interactive-user"
    assert resolved["authority_effect"] == "none"
    assert resolved["authority_granted"] is False
    assert resolved["pass_credit"] is False
    assert resolved["acceptance_pass"] is False
    assert len(resolved["profile_digest"]) == 64


def test_init_profile_rejects_unsafe_override_of_invariant_or_unknown_key() -> None:
    with pytest.raises(InitProfileError, match="canonical_build_owners"):
        resolve_init_profile(_standard_profile(), cli_override={"canonical_build_owners": 2})
    with pytest.raises(InitProfileError, match="unsupported init profile override"):
        resolve_init_profile(_standard_profile(), cli_override={"trust_root": "replace"})


def test_language_negotiation_respects_accept_decline_and_custom_without_credit() -> None:
    profile = _standard_profile()
    language_profiles = profile["language_capability_profiles"]
    assert isinstance(language_profiles, list)

    declined = negotiate_language_capabilities(
        language_profiles,
        languages=("cpp",),
        documentation_choice="decline",
        verification_choice="decline",
        selection_source="cli",
    )
    assert declined["documentation_tools"] == []
    assert declined["recommended_verification_tools"] == []
    assert declined["required_verification_tools"] == ["canonical-compilation-database"]
    assert declined["authority_granted"] is False
    assert declined["pass_credit"] is False
    assert declined["acceptance_pass"] is False

    custom = negotiate_language_capabilities(
        language_profiles,
        languages=("cpp",),
        documentation_choice="custom",
        verification_choice="custom",
        custom_documentation=("contract-catalogue",),
        custom_verification=("compiler-syntax",),
        selection_source="interactive-user",
    )
    assert custom["documentation_tools"] == ["contract-catalogue"]
    assert custom["recommended_verification_tools"] == ["compiler-syntax"]
    assert custom["selection_source"] == "interactive-user"

    with pytest.raises(InitProfileError, match="custom documentation choice"):
        negotiate_language_capabilities(
            language_profiles,
            languages=("cpp",),
            documentation_choice="custom",
            verification_choice="accept",
            selection_source="cli",
        )


def test_unavailable_tool_is_typed_and_can_never_receive_pass_credit() -> None:
    unavailable = ToolOutcome(
        tool_id="optional-semantic-tool",
        state="UNAVAILABLE",
        required=False,
        detail="not installed on this host",
    )
    assert unavailable.as_record()["state"] == "UNAVAILABLE"
    assert unavailable.as_record()["pass_credit"] is False
    assert unavailable.as_record()["acceptance_pass"] is False

    with pytest.raises(InitProfileError, match="UNAVAILABLE"):
        ToolOutcome(
            tool_id="optional-semantic-tool",
            state="UNAVAILABLE",
            required=False,
            detail="not installed on this host",
            pass_credit=True,
        )


def test_profile_asset_is_plain_portable_json_without_host_path() -> None:
    payload = json.loads((_ASSET_ROOT / "standard-init.json").read_text(encoding="utf-8"))
    assert payload["schema"] == "promin.init-profile.v1"
    assert "C:" not in json.dumps(payload, sort_keys=True)
    assert "mor" + "ok" not in json.dumps(payload, sort_keys=True).casefold()
