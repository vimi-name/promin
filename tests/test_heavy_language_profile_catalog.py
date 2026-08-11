from __future__ import annotations

import json
from pathlib import Path

from promin.init_profiles import ToolOutcome
from promin.language_analysis import load_language_profile


ROOT = Path(__file__).resolve().parents[1]
PROFILE_ROOT = ROOT / "language_profiles"

EXPECTED = {
    "c-family-semantic.json": ("c-family-semantic", ("c", "cpp")),
    "csharp-semantic.json": ("csharp-semantic", ("csharp",)),
    "jvm-semantic.json": ("jvm-semantic", ("java", "kotlin", "scala", "groovy")),
    "javascript-typescript-semantic.json": (
        "javascript-typescript-semantic",
        ("javascript", "typescript"),
    ),
    "python-semantic.json": ("python-semantic", ("python",)),
    "open-source-tooling.json": (
        "open-source-tooling",
        ("build", "documentation", "static-analysis"),
    ),
    "weak-host-fallback.json": ("weak-host-fallback", ("generic",)),
}


def test_heavy_language_profile_catalog_is_strict_and_generic() -> None:
    available = {path.name for path in PROFILE_ROOT.glob("*.json")}
    assert set(EXPECTED) <= available

    for filename, (profile_id, languages) in EXPECTED.items():
        profile = load_language_profile(PROFILE_ROOT / filename)
        payload = json.dumps(profile.document, ensure_ascii=False, sort_keys=True)

        assert profile.profile_id == profile_id
        assert profile.languages == languages
        assert profile.document["claims"] == {
            "acceptancePass": False,
            "passCredit": False,
            "productAcceptancePass": False,
            "releaseApproved": False,
        }
        assert profile.document["artifactPolicy"]["defaultMode"] == "minimal"
        if filename != "c-family-semantic.json":
            assert profile.document["artifactPolicy"]["diagnosticRoot"].startswith(
                "host-local-"
            )
            assert profile.document["artifactPolicy"]["forensicRoot"].startswith(
                "host-local-"
            )
        assert "mor" + "ok" not in payload.casefold()
        assert "to" + "wer" not in payload.casefold()
        assert "C:\\" not in payload


def test_weak_host_profile_records_unavailability_without_credit() -> None:
    weak_host = load_language_profile(PROFILE_ROOT / "weak-host-fallback.json")
    rule = next(
        item
        for item in weak_host.document["compilerFailureProfiles"]
        if item["id"] == "optional-tool-unavailable"
    )

    assert weak_host.documentation["recommended"] is False
    assert weak_host.verification["recommended"] == []
    assert weak_host.verification["optional"] == ["optional-tool-unavailable"]
    assert rule["classification"] == "REVIEW"
    assert rule["requiresCompilerDiagnostic"] is False
    assert "UNAVAILABLE" in rule["message"]

    outcome = ToolOutcome(
        tool_id="optional-tool-unavailable",
        state="UNAVAILABLE",
        required=False,
        detail="weak-host fallback has no optional tool installation",
    ).as_record()
    assert outcome["state"] == "UNAVAILABLE"
    assert outcome["pass_credit"] is False
    assert outcome["acceptance_pass"] is False
