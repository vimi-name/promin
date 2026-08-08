from __future__ import annotations

import json
from pathlib import Path

from promin.experience import apply_plan, experience_status, next_proposal, resolve_plan
from promin.skills import create_skill


def test_guided_plan_detects_web_without_questions_or_scan(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"react": "latest", "@supabase/supabase-js": "latest"}}),
        encoding="utf-8",
    )
    (tmp_path / "src" / "app.tsx").write_text("export const App = () => null;\n", encoding="utf-8")
    plan = resolve_plan(tmp_path, goal="Audit and stabilize the web project")
    assert plan["project_mode"] == "existing-code"
    assert "web-application" in plan["profile_layers"]
    assert plan["question_count_before_plan"] == 0
    assert plan["preflight"]["full_repository_scan"] is False
    assert plan["manual_digest_operations"] == 0


def test_profiles_detect_android_windows_and_vibe(tmp_path: Path) -> None:
    (tmp_path / "AndroidManifest.xml").write_text("<manifest/>\n", encoding="utf-8")
    (tmp_path / "settings.gradle.kts").write_text("rootProject.name = \"sample\"\n", encoding="utf-8")
    (tmp_path / "sample.sln").write_text("Microsoft Visual Studio Solution File\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "legacy-copy.kt").write_text("fun a() = 1\n", encoding="utf-8")
    plan = resolve_plan(tmp_path)
    assert "android-application" in plan["profile_layers"]
    assert "windows-development" in plan["profile_layers"]
    assert "vibe-recovery" in plan["profile_layers"]


def test_guided_apply_keeps_first_work_card_package_defined(tmp_path: Path) -> None:
    plan = resolve_plan(tmp_path, goal="Create a small reliable tool", language="en")
    result = apply_plan(tmp_path, plan)
    assert result["status"] == "created"
    assert result["product_tree_scans_before_plan"] == 0
    status = experience_status(tmp_path)
    assert status["initialized"] is True
    assert status["project_mode"] == "greenfield"
    card_result = next_proposal(tmp_path)
    assert card_result["status"] == "PENDING_PACKAGE_DEFINED_WORK_CARD"
    assert result["first_work_card"] is None
    config = json.loads((tmp_path / ".promin" / "generated" / "config-view" / "project.json").read_text(encoding="utf-8"))
    assert config["goal"] == "Create a small reliable tool"
    repeated = apply_plan(tmp_path, plan)
    assert repeated["status"] == "idempotent"


def test_project_local_skill_is_discovered_but_never_grants_authority(tmp_path: Path) -> None:
    created = create_skill(
        tmp_path,
        name="local-review",
        description="Review a bounded local change without authority.",
        body="# Local review\n\nInspect the requested paths and report evidence.\n",
        capabilities=("review.local",),
        hosts=("generic",),
        platforms=("linux", "windows", "macos"),
        security_scope="read-only",
        portable=False,
    )
    assert created["skill"]["skill_id"] == "local-review"
    plan = resolve_plan(tmp_path, goal="Review the project")
    assert [item["skill_id"] for item in plan["available_skills"]] == ["local-review"]
    assert plan["available_skills"][0]["authority"] is False
    assert plan["available_skills"][0]["pass_credit"] is False


def test_bundle_root_resolves_canonical_standard_package() -> None:
    from promin.resources import bundle_root

    root = bundle_root()
    assert (root / "core" / "promin.manifest.json").is_file()
    assert (root / "presets" / "semantic-standard.json").is_file()
