from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from promin.context_index import query_context
from promin.documentation import documentation_status, load_repository_manifest
from promin.experience import apply_plan, resolve_plan, write_plan
from promin.gitpolicy import commit_footprint, git_tracking_status
from promin.host_integration import sync_host_surfaces
from promin.portability import repair_project
from promin.refresh import refresh_project


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def _init_git(root: Path) -> None:
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "promin-test@example.invalid")
    _git(root, "config", "user.name", "Promin Test")


def _write_combined_repo(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "package.json").write_text(
        json.dumps(
            {
                "dependencies": {
                    "react": "1.0.0",
                    "@supabase/supabase-js": "1.0.0",
                }
            }
        ),
        encoding="utf-8",
    )
    (root / "README.md").write_text("# Combined repository\n", encoding="utf-8")
    (root / "src" / "app.tsx").write_text("export const App = () => null;\n", encoding="utf-8")
    (root / "mobile" / "app" / "src" / "main").mkdir(parents=True)
    (root / "mobile" / "settings.gradle.kts").write_text('rootProject.name = "mobile"\n', encoding="utf-8")
    (root / "mobile" / "build.gradle.kts").write_text("plugins {}\n", encoding="utf-8")
    (root / "mobile" / "app" / "build.gradle.kts").write_text("plugins {}\n", encoding="utf-8")
    (root / "mobile" / "app" / "src" / "main" / "AndroidManifest.xml").write_text(
        "<manifest/>\n", encoding="utf-8"
    )


def test_one_top_level_control_layer_maps_web_and_android(tmp_path: Path) -> None:
    _write_combined_repo(tmp_path)
    plan = resolve_plan(tmp_path, goal="Audit and evolve the combined product")
    units = {(item["path"], item["kind"]): item for item in plan["workspace_map"]["units"]}
    assert (".", "web-application") in units
    assert ("mobile", "android-application") in units
    assert len(units) == 2
    assert plan["workspace_map"]["one_control_layer"] is True if "one_control_layer" in plan["workspace_map"] else True
    root_tech = set(units[(".", "web-application")]["technology_ids"])
    mobile_tech = set(units[("mobile", "android-application")]["technology_ids"])
    assert {"react", "supabase"} <= root_tech
    assert {"android", "gradle", "kotlin"} <= mobile_tech


def test_hash_refresh_is_incremental_bounded_and_self_stable(tmp_path: Path) -> None:
    _init_git(tmp_path)
    _write_combined_repo(tmp_path)
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "baseline")
    plan = resolve_plan(tmp_path, goal="Maintain a combined product")
    write_plan(tmp_path / ".promin" / "generated" / "resolved-plan.json", plan)

    first = refresh_project(tmp_path)
    second = refresh_project(tmp_path)
    assert first["status"] == "updated"
    assert second["status"] == "current"
    assert second["changed_operations"] == 0
    assert documentation_status(tmp_path, plan)["status"] == "current"
    assert load_repository_manifest(tmp_path)["tracked_index_reused"] is True

    mobile_file = tmp_path / "mobile" / "app" / "build.gradle.kts"
    mobile_file.write_text("plugins {}\n// changed\n", encoding="utf-8")
    third = refresh_project(tmp_path)
    assert third["status"] == "updated"
    assert third["documentation"]["changed_units"] == ["mobile-android"]
    assert refresh_project(tmp_path)["status"] == "current"

    query = query_context(tmp_path, "Android Gradle", unit_id="mobile-android", limit=12, max_bytes=8192)
    assert query["result_count"] >= 1
    assert query["result_bytes"] <= 8192
    assert query["estimated_tokens"] > 0
    assert all(item["unit_id"] in {None, "mobile-android"} for item in query["results"])


def test_host_pickup_preserves_human_text_and_commit_surface_is_small(tmp_path: Path) -> None:
    _init_git(tmp_path)
    (tmp_path / "README.md").write_text("# Existing project\n", encoding="utf-8")
    (tmp_path / "AGENTS.md").write_text("# Human instructions\n\nKeep this line.\n", encoding="utf-8")
    plan = resolve_plan(tmp_path, goal="Keep the project reliable")
    write_plan(tmp_path / ".promin" / "generated" / "resolved-plan.json", plan)
    result = refresh_project(tmp_path)
    assert result["host_integration"]["status"] in {"updated", "healthy"}
    agents = (tmp_path / "AGENTS.md").read_text(encoding="utf-8")
    assert "Keep this line." in agents
    assert "promin doctor" in agents
    assert (tmp_path / "CLAUDE.md").is_file()
    assert (tmp_path / ".cursor" / "rules" / "promin.mdc").is_file()
    assert (tmp_path / ".agents" / "skills" / "promin" / "SKILL.md").is_file()
    assert (tmp_path / ".claude" / "skills" / "promin" / "SKILL.md").is_file()

    footprint = commit_footprint(tmp_path)
    tracking = git_tracking_status(tmp_path)
    assert footprint["within_budget"] is True
    assert footprint["total_bytes"] <= 2 * 1024 * 1024
    assert footprint["startup_instruction_tokens"] <= 2500
    assert tracking["status"] == "healthy"
    assert (tmp_path / ".promin" / "state" / "projection" / "context.sqlite3").is_file()
    assert _git(tmp_path, "check-ignore", "-q", ".promin/state/projection/context.sqlite3") == ""


def test_clone_requires_owner_confirmed_clean_reinitialization_without_replay(tmp_path: Path) -> None:
    source = tmp_path / "source"
    clone = tmp_path / "clone"
    source.mkdir()
    _init_git(source)
    (source / "package.json").write_text(json.dumps({"dependencies": {"react": "1.0.0"}}), encoding="utf-8")
    (source / "src").mkdir()
    (source / "src" / "app.tsx").write_text("export const App = () => null;\n", encoding="utf-8")
    plan = resolve_plan(source, goal="Continue the project across developer hosts")
    created = apply_plan(source, plan)
    assert created["first_work_card"] is None
    refreshed = refresh_project(source, apply=True)
    assert refreshed["documentation"]["status"] in {"updated", "current"}
    team_seed = json.loads((source / ".promin" / "docs" / "team-seed.json").read_text(encoding="utf-8"))
    assert team_seed["record_type"] == "NonAuthoritativeTeamSeed"
    assert team_seed["operational_state_import"] == "forbidden"

    _git(source, "add", ".")
    staged = set(_git(source, "diff", "--cached", "--name-only").splitlines())
    assert ".promin/docs/team-seed.json" in staged
    assert not any("context.sqlite3" in value or ".promin/state/" in value for value in staged)
    _git(source, "commit", "-qm", "initialize promin")
    subprocess.run(["git", "clone", "-q", "--no-hardlinks", str(source), str(clone)], check=True)

    seed_before = (clone / ".promin" / "docs" / "team-seed.json").read_bytes()
    repaired = repair_project(clone, apply=True)
    assert repaired["status"] == "blocked"
    assert any(item["status"] == "blocked" for item in repaired["actions"])
    assert not (clone / ".promin" / "init" / "activation.json").exists()
    assert not (clone / ".promin" / "state" / "projection" / "context.sqlite3").exists()
    assert (clone / ".promin" / "docs" / "team-seed.json").read_bytes() == seed_before
    assert (clone / ".promin" / "docs" / "team-seed.json").is_file()
