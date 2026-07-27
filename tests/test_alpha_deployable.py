from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from promin.audit import audit_project
from promin.experience import apply_plan, next_proposal, resolve_plan
from promin.portability import doctor_with_portability, repair_project


def _product_snapshot(root: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative.startswith((".promin/", ".promin-host/")):
            continue
        if relative in {"AGENTS.md", "CLAUDE.md", ".gitignore"}:
            continue
        if relative.startswith((
            ".agents/skills/promin/",
            ".claude/skills/promin/",
            ".cursor/rules/promin.",
            ".cursor/skills/promin/",
        )):
            continue
        result[relative] = path.read_bytes()
    return result


def test_adg0_shadow_deployment_flow(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "supabase").mkdir()
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "scripts": {"test": "vitest"},
                "dependencies": {
                    "react": "19.0.0",
                    "@supabase/supabase-js": "2.49.0",
                },
            }
        ),
        encoding="utf-8",
    )
    source = "export const App = () => null;\n"
    (tmp_path / "src" / "app.tsx").write_text(source, encoding="utf-8")
    # Duplicate-like naming is a bounded signal for Vibe Recovery, not a deletion order.
    (tmp_path / "src" / "app-copy.tsx").write_text(source, encoding="utf-8")
    before = _product_snapshot(tmp_path)

    plan = resolve_plan(tmp_path, goal="Audit and stabilize this web project", language="en")
    assert plan["question_count_before_plan"] == 0
    assert plan["preflight"]["full_repository_scan"] is False
    assert "web-application" in plan["profile_layers"]
    assert "vibe-recovery" in plan["profile_layers"]

    created = apply_plan(tmp_path, plan)
    assert created["status"] == "created"
    assert created["product_tree_scans_before_plan"] == 0
    assert created["first_work_card"]["record_type"] == "WorkCard"

    repeated = apply_plan(tmp_path, plan)
    assert repeated["status"] == "idempotent"

    doctor = doctor_with_portability(tmp_path, replay=False)
    assert doctor["status"] in {"healthy", "degraded"}
    assert doctor["canonical_absolute_path_issues"] == []
    assert doctor["host_specific_provider_path_count"] >= 1

    next_result = next_proposal(tmp_path)
    assert next_result["status"] == "ready"
    assert next_result["work_card"]["orchestration_required"] is True

    audit = audit_project(tmp_path, build_plan=True, max_files=1000)
    assert audit["pass_credit"] is False
    assert audit["product_acceptance_pass"] is False

    # A fresh process can read the same operational state.
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    completed = subprocess.run(
        [sys.executable, "-m", "promin", "--root", str(tmp_path), "status"],
        check=True,
        capture_output=True,
        env=environment,
        timeout=60,
    )
    restarted = json.loads(completed.stdout)
    assert restarted["status"] in {"ready", "ready-for-inventory"}

    projection = tmp_path / ".promin" / "state" / "projection"
    if projection.exists():
        shutil.rmtree(projection)
    repair = repair_project(tmp_path, apply=True)
    assert "rebuilt-projection" in repair["performed"]
    assert projection.exists()

    assert _product_snapshot(tmp_path) == before
