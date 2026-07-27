from __future__ import annotations

from pathlib import Path

from promin.experience import apply_plan, resolve_plan
from promin.skills import create_skill
from promin.system_check import run_system_check


def test_system_check_reports_managed_skill_without_authority(tmp_path: Path) -> None:
    plan = resolve_plan(tmp_path, goal="Create a small reliable tool")
    apply_plan(tmp_path, plan)
    create_skill(
        tmp_path,
        name="bounded-review",
        description="Review a bounded Task and return evidence.",
        body="# Bounded review\n\nDo not exceed the current Task or authority.\n",
        portable=True,
    )

    result = run_system_check(tmp_path)
    skill = next(item for item in result["checks"] if item["check_id"] == "SYS-SKILL-001")
    assert skill["status"] == "pass"
    assert skill["evidence"]["managed_count"] >= 1
    assert result["authority"] is False
    assert result["pass_credit"] is False


def test_doctor_checklist_is_available_through_the_public_cli(tmp_path: Path) -> None:
    from promin.__main__ import _parser, _run

    plan = resolve_plan(tmp_path, goal="Create a small reliable tool")
    apply_plan(tmp_path, plan)
    args = _parser().parse_args(["--root", str(tmp_path), "doctor", "--checklist"])
    result = _run(args)
    assert result["record_type"] == "ProminSystemChecklist"
    assert result["fail_count"] == 0
    assert result["authority"] is False
    assert result["pass_credit"] is False
