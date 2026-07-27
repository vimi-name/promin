from __future__ import annotations

import json
from pathlib import Path

from promin.experience import apply_plan, resolve_plan
from promin.portability import doctor_with_portability, repair_project


def test_doctor_is_healthy_after_guided_init_and_repair_is_reversible(tmp_path: Path) -> None:
    plan = resolve_plan(tmp_path, goal="Create a portable project")
    apply_plan(tmp_path, plan)
    diagnosis = doctor_with_portability(tmp_path, replay=False)
    assert diagnosis["host_changed"] is False
    assert diagnosis["canonical_absolute_path_issues"] == []
    projection = tmp_path / ".promin" / "state" / "projection"
    if projection.exists():
        for child in projection.iterdir():
            if child.is_file():
                child.unlink()
    planned = repair_project(tmp_path, apply=False)
    assert planned["product_files_modified"] is False
    assert planned["pass_credit"] is False


def test_absolute_path_in_alpha_config_is_reported(tmp_path: Path) -> None:
    plan = resolve_plan(tmp_path, goal="Create a portable project")
    apply_plan(tmp_path, plan)
    config = tmp_path / ".promin" / "generated" / "config-view" / "project.json"
    value = json.loads(config.read_text(encoding="utf-8"))
    value["references"] = ["C:/private/host/path"]
    config.write_text(json.dumps(value), encoding="utf-8")
    diagnosis = doctor_with_portability(tmp_path, replay=False)
    assert diagnosis["canonical_absolute_path_issues"]
    assert diagnosis["status"] == "degraded"


def test_routine_doctor_does_not_create_unbounded_derived_generations(tmp_path: Path) -> None:
    plan = resolve_plan(tmp_path, goal="Create a portable project")
    apply_plan(tmp_path, plan)
    for _ in range(5):
        diagnosis = doctor_with_portability(tmp_path, replay=False)
        assert diagnosis["core"]["components"]["recovery"]["status"] == "healthy"
    event_root = tmp_path / ".promin" / "state" / "events"
    index_generations = [path for path in (event_root / "derived-index").iterdir() if path.is_dir()]
    authority_generations = [path for path in (event_root / "journal-authority").iterdir() if path.is_dir()]
    assert len(index_generations) <= 2
    assert len(authority_generations) <= 2
