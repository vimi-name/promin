from __future__ import annotations

from pathlib import Path

from promin.__main__ import _parser
from promin.experience import resolve_plan, write_plan
from promin.host_integration import sync_host_surfaces


def test_alpha_cli_exposes_operational_support_commands() -> None:
    parser = _parser()
    for argv in (
        ["refresh", "--plan-only"],
        ["context", "repository architecture"],
        ["skills", "list"],
        ["skills", "request", "security review"],
    ):
        parsed = parser.parse_args(argv)
        assert parsed.workflow == argv[0]


def test_host_pickup_preserves_human_content_and_references_real_commands(
    tmp_path: Path,
) -> None:
    (tmp_path / "AGENTS.md").write_text(
        "# Human instructions\n\nKeep this line.\n", encoding="utf-8"
    )
    plan = resolve_plan(tmp_path, goal="Maintain the project")
    write_plan(tmp_path / ".promin" / "generated" / "resolved-plan.json", plan)

    result = sync_host_surfaces(tmp_path, language="en", apply=True)

    assert result["status"] in {"updated", "healthy"}
    agents = (tmp_path / "AGENTS.md").read_text(encoding="utf-8")
    assert "Keep this line." in agents
    for command in (
        "promin doctor",
        "promin next",
        "promin context",
        "promin refresh",
        "promin audit",
        "promin skills list",
    ):
        assert command in agents
