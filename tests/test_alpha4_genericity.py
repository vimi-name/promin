from __future__ import annotations

import json
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def _load_json(relative: str) -> dict[str, object]:
    return json.loads((PACKAGE_ROOT / relative).read_text(encoding="utf-8"))


def test_generic_standard_assets_have_exact_neutral_membership() -> None:
    presets = PACKAGE_ROOT / "presets"
    profiles = PACKAGE_ROOT / "profiles"

    assert {path.name for path in presets.iterdir() if path.is_file()} == {
        "semantic-standard.json"
    }
    assert (profiles / "c-family-development.json").is_file()
    assert (profiles / "README.md").is_file()


def test_generic_standard_assets_are_profile_driven() -> None:
    preset = _load_json("presets/semantic-standard.json")
    c_family = _load_json("profiles/c-family-development.json")

    assert preset["preset_id"] == "semantic-standard"
    assert preset["version"] == "1.0.0-alpha.4"
    assert preset["default_profile"] == "baseline"
    assert set(preset["profiles"]) == {"baseline", "balanced", "extended"}
    assert preset["default_profile"] in preset["profiles"]

    assert c_family["profile_id"] == "c-family-development"
    assert c_family["category"] == "language"
    assert c_family["defaults"] == {
        "documentation": "profile-driven",
        "language_family": "c-family",
        "verification": "profile-driven",
    }
    assert c_family["authority_effect"] == "none"


def test_genericity_docs_describe_capability_selection() -> None:
    profile_readme = (PACKAGE_ROOT / "profiles" / "README.md").read_text(
        encoding="utf-8"
    )
    catalog = (PACKAGE_ROOT / "docs" / "PROFILE_CATALOG_UA.md").read_text(
        encoding="utf-8"
    )
    scope = (PACKAGE_ROOT / "docs" / "ALPHA_SCOPE_UA.md").read_text(
        encoding="utf-8"
    )

    assert "Product-specific profiles belong to an explicitly selected" in profile_readme
    assert "c-family-development" in catalog
    assert "generic C-family" in scope
