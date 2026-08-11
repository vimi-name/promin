from __future__ import annotations

import json
from pathlib import Path

import pytest

from promin.language_catalog import (
    LanguageCatalogError,
    compose_language_capabilities,
    load_language_catalog,
)


ROOT = Path(__file__).resolve().parents[1]


def _profile(
    profile_id: str,
    languages: list[str],
    *,
    user_choice: str = "ask",
) -> dict[str, object]:
    stem = profile_id.removesuffix("-semantic")
    return {
        "schema": "promin.language-capability-profile.v1",
        "profileId": profile_id,
        "languages": languages,
        "sourceExtensions": [f".{stem[:3]}", f".{stem[:3]}i"],
        "documentation": {
            "recommended": True,
            "userChoice": user_choice,
            "primary": [f"{stem}-reference"],
            "optional": [f"{stem}-api"],
        },
        "verification": {
            "cheapRequired": [],
            "recommended": [f"{stem}-lint"],
            "optional": [f"{stem}-format"],
        },
        "artifactPolicy": {
            "defaultMode": "minimal",
            "trackedSummary": True,
            "diagnosticRoot": "host-local-diagnostic",
            "forensicRoot": "host-local-forensic",
        },
        "staticCapabilities": [f"{stem}-static"],
        "claims": {
            "acceptancePass": False,
            "passCredit": False,
            "productAcceptancePass": False,
            "releaseApproved": False,
        },
    }


def _write_catalog(tmp_path: Path) -> Path:
    profiles = tmp_path / "language_profiles"
    profiles.mkdir()
    documents = {
        "c-family-semantic.json": _profile("c-family-semantic", ["c", "cpp"]),
        "csharp-semantic.json": _profile("csharp-semantic", ["csharp"], user_choice="accept"),
        "java-semantic.json": _profile("java-semantic", ["java"]),
        "javascript-semantic.json": _profile(
            "javascript-semantic", ["javascript", "typescript"]
        ),
        "python-semantic.json": _profile("python-semantic", ["python"]),
    }
    for name, document in documents.items():
        (profiles / name).write_text(
            json.dumps(document, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )
    return profiles


def _available_catalog_capabilities() -> dict[str, dict[str, str]]:
    families = ("c-family", "csharp", "java", "javascript", "python")
    result: dict[str, dict[str, str]] = {}
    for family in families:
        result[f"{family}-static"] = {"status": "AVAILABLE", "detail": "host observation"}
        result[f"{family}-lint"] = {"status": "AVAILABLE", "detail": "host observation"}
        result[f"{family}-reference"] = {"status": "AVAILABLE", "detail": "host observation"}
        result[f"{family}-api"] = {"status": "AVAILABLE", "detail": "host observation"}
    return result


def test_catalog_composes_all_supported_families_with_exact_digests(
    tmp_path: Path,
) -> None:
    catalog = load_language_catalog(_write_catalog(tmp_path))
    result = compose_language_capabilities(
        catalog,
        languages=("c++", "C#", "java", "js", "python"),
        availability=_available_catalog_capabilities(),
        overrides={
            "c-family-semantic": {
                "documentation": {"mode": "custom", "items": ["c-family-api"]},
                "tools": {
                    "mode": "custom",
                    "items": ["c-family-lint", "c-family-format"],
                },
            },
            "javascript-semantic": {
                "documentation": {"mode": "accept", "items": []},
                "tools": {"mode": "decline", "items": []},
            },
        },
    )

    assert [profile.profile_id for profile in catalog.profiles] == [
        "c-family-semantic",
        "csharp-semantic",
        "java-semantic",
        "javascript-semantic",
        "python-semantic",
    ]
    assert result["status"] == "AVAILABLE"
    assert result["language_families"] == [
        "c-family",
        "csharp",
        "java",
        "javascript",
        "python",
    ]
    assert result["selected_profile_ids"] == [
        "c-family-semantic",
        "csharp-semantic",
        "java-semantic",
        "javascript-semantic",
        "python-semantic",
    ]
    assert result["selected_static_capabilities"] == [
        "c-family-static",
        "csharp-static",
        "java-static",
        "javascript-static",
        "python-static",
    ]
    assert "c-family-api" in result["selected_documentation"]
    assert "csharp-reference" in result["selected_documentation"]
    assert "javascript-reference" in result["selected_documentation"]
    assert "java-reference" not in result["selected_documentation"]
    assert "c-family-format" in result["selected_tools"]
    assert "javascript-lint" not in result["selected_tools"]
    assert result["claims"] == {
        "acceptance_pass": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
        "release_approved": False,
    }
    assert len(catalog.catalog_digest) == 64
    assert len(result["composition_digest"]) == 64


def test_catalog_uses_existing_rich_c_family_profile_without_reinterpreting_it() -> None:
    catalog = load_language_catalog(ROOT / "language_profiles")

    profile = catalog.profile("c-family-semantic")
    assert profile.profile_id == "c-family-semantic"
    assert profile.language_family == "c-family"
    assert "module-owner-import-graph" in profile.static_capabilities
    assert len(profile.profile_digest) == 64
    assert len(profile.source_digest) == 64


def test_installed_catalog_selects_c_family_csharp_java_javascript_and_python() -> None:
    catalog = load_language_catalog(ROOT / "language_profiles")
    result = compose_language_capabilities(
        catalog,
        languages=("c", "csharp", "java", "javascript", "python"),
    )

    assert result["selected_profile_ids"] == [
        "c-family-semantic",
        "csharp-semantic",
        "javascript-typescript-semantic",
        "jvm-semantic",
        "python-semantic",
    ]
    assert result["language_families"] == [
        "c-family",
        "csharp",
        "java",
        "javascript",
        "python",
    ]
    assert result["status"] == "SKIPPED"
    assert all(item["status"] == "SKIPPED" for item in result["availability_results"])
    assert result["pass_credit"] is False


def test_catalog_returns_unavailable_for_a_missing_supported_profile_without_credit(
    tmp_path: Path,
) -> None:
    catalog = load_language_catalog(_write_catalog(tmp_path))
    profile_root = tmp_path / "language_profiles"
    (profile_root / "java-semantic.json").unlink()
    catalog_without_java = load_language_catalog(profile_root)

    result = compose_language_capabilities(
        catalog_without_java,
        languages=("java",),
        availability={},
    )

    assert result["status"] == "UNAVAILABLE"
    assert result["unresolved_languages"] == ["java"]
    assert result["pass_credit"] is False
    assert result["acceptance_pass"] is False
    assert catalog.catalog_digest != catalog_without_java.catalog_digest


def test_catalog_rejects_unbounded_override_and_pass_as_availability(
    tmp_path: Path,
) -> None:
    catalog = load_language_catalog(_write_catalog(tmp_path))

    with pytest.raises(LanguageCatalogError, match="declared"):
        compose_language_capabilities(
            catalog,
            languages=("python",),
            overrides={
                "python-semantic": {
                    "tools": {"mode": "custom", "items": ["invented-compiler"]}
                }
            },
        )

    with pytest.raises(LanguageCatalogError, match="PASS"):
        compose_language_capabilities(
            catalog,
            languages=("python",),
            availability={"python-static": {"status": "PASS", "detail": "not a probe"}},
        )


def test_catalog_rejects_duplicate_json_keys_and_binds_override_into_digest(
    tmp_path: Path,
) -> None:
    profiles = _write_catalog(tmp_path)
    catalog = load_language_catalog(profiles)
    availability = _available_catalog_capabilities()

    baseline = compose_language_capabilities(
        catalog,
        languages=("python",),
        availability=availability,
    )
    changed = compose_language_capabilities(
        catalog,
        languages=("python",),
        availability=availability,
        overrides={
            "python-semantic": {
                "documentation": {"mode": "custom", "items": ["python-api"]}
            }
        },
    )
    assert baseline["composition_digest"] != changed["composition_digest"]

    malformed = tmp_path / "malformed"
    malformed.mkdir()
    (malformed / "duplicate.json").write_text(
        '{"schema":"promin.language-capability-profile.v1",'
        '"schema":"promin.language-capability-profile.v1"}',
        encoding="utf-8",
    )
    with pytest.raises(LanguageCatalogError, match="duplicate"):
        load_language_catalog(malformed)


def test_catalog_rejects_true_claim_and_unbounded_capability_profile(tmp_path: Path) -> None:
    claimed = tmp_path / "claimed"
    claimed.mkdir()
    document = _profile("python-semantic", ["python"])
    claims = document["claims"]
    assert isinstance(claims, dict)
    claims["passCredit"] = True
    (claimed / "profile.json").write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(LanguageCatalogError, match="claims"):
        load_language_catalog(claimed)

    bounded = tmp_path / "bounded"
    bounded.mkdir()
    document = _profile("python-semantic", ["python"])
    document["staticCapabilities"] = [f"static-{index}" for index in range(65)]
    (bounded / "profile.json").write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(LanguageCatalogError, match="bounded"):
        load_language_catalog(bounded)
