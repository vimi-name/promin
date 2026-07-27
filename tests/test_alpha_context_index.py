from __future__ import annotations

import json
from pathlib import Path

from promin.context_index import query_context
from promin.experience import resolve_plan, write_plan
from promin.refresh import refresh_project


def test_context_query_is_bounded_and_uses_project_unit(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"react": "1.0.0"}}), encoding="utf-8"
    )
    (tmp_path / "src" / "app.tsx").write_text(
        "export const App = () => null;\n", encoding="utf-8"
    )
    plan = resolve_plan(tmp_path, goal="Maintain a bounded web context")
    write_plan(tmp_path / ".promin" / "generated" / "resolved-plan.json", plan)
    refresh_project(tmp_path)

    result = query_context(tmp_path, "React app", limit=12, max_bytes=4096)

    assert result["record_type"] == "ContextQueryResult"
    assert result["result_count"] >= 1
    assert result["result_bytes"] <= 4096
    assert result["estimated_tokens"] > 0
    assert result["authority"] is False
    assert result["pass_credit"] is False
