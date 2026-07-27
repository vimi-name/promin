from __future__ import annotations

import json
from pathlib import Path

from promin.context_index import query_context
from promin.experience import resolve_plan, write_plan
from promin.refresh import refresh_project


def test_one_control_layer_navigates_web_and_android_units(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"react": "1.0.0", "@supabase/supabase-js": "1.0.0"}}),
        encoding="utf-8",
    )
    (tmp_path / "src" / "app.tsx").write_text("export const App = () => null;\n", encoding="utf-8")
    (tmp_path / "mobile" / "app" / "src" / "main").mkdir(parents=True)
    (tmp_path / "mobile" / "settings.gradle.kts").write_text('rootProject.name = "mobile"\n', encoding="utf-8")
    (tmp_path / "mobile" / "app" / "src" / "main" / "AndroidManifest.xml").write_text("<manifest/>\n", encoding="utf-8")

    plan = resolve_plan(tmp_path, goal="Audit the combined product")
    units = {item["unit_id"]: item for item in plan["workspace_map"]["units"]}
    assert {"root-web", "mobile-android"} <= set(units)
    assert "web-application" in plan["profile_layers"]
    assert "android-application" in plan["profile_layers"]

    write_plan(tmp_path / ".promin" / "generated" / "resolved-plan.json", plan)
    refresh_project(tmp_path)
    result = query_context(
        tmp_path,
        "Android manifest Gradle",
        unit_id="mobile-android",
        max_bytes=4096,
    )
    assert result["result_count"] >= 1
    assert all(item["unit_id"] in {None, "mobile-android"} for item in result["results"])
