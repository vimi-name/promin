from __future__ import annotations

from pathlib import Path

import pytest

from promin.experience import compile_core_plans, resolve_plan


@pytest.mark.parametrize(
    ("relative_path", "payload"),
    [
        (None, None),
        ("README.md", "# Undetermined project\n"),
        ("src/component.unknown", "opaque project content\n"),
    ],
    ids=("empty", "documentation-only", "unknown-source-suffix"),
)
def test_insufficient_repository_evidence_keeps_a_generic_unknown_language_contour(
    tmp_path: Path,
    relative_path: str | None,
    payload: str | None,
) -> None:
    if relative_path is not None:
        target = tmp_path / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(payload), encoding="utf-8")

    plan = resolve_plan(
        tmp_path,
        goal="Create only what repository evidence justifies",
        language="en",
    )

    assert plan["detected_technologies"] == []
    assert plan["profile_layers"] == ["general-development", "ask", "en"]
    assert [item["profile_id"] for item in plan["profile_resolution"]] == [
        "general-development",
        "ask",
        "en",
    ]
    assert plan["material_unknowns"] == [
        "repository language and toolchain remain unknown after bounded preflight; no language profile was inferred"
    ]
    assert plan["preflight"]["full_repository_scan"] is False
    assert plan["authority"] is False
    assert plan["pass_credit"] is False
    assert plan["init_capability_selection"]["authority_granted"] is False
    assert plan["init_capability_selection"]["pass_credit"] is False
    assert plan["init_capability_selection"]["acceptance_pass"] is False


@pytest.mark.parametrize("suffix", (".c", ".cpp"))
def test_physical_c_or_cpp_source_evidence_selects_c_family_profile(
    tmp_path: Path,
    suffix: str,
) -> None:
    source = tmp_path / "src" / f"main{suffix}"
    source.parent.mkdir()
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")

    plan = resolve_plan(tmp_path, goal="Audit the native project", language="en")

    technologies = {item["technology"]: item for item in plan["detected_technologies"]}
    assert set(technologies) == {"cpp"}
    assert technologies["cpp"]["sources"] == [f"src/main{suffix}"]
    assert "c-family-development" in plan["profile_layers"]
    assert any(
        item["profile_id"] == "c-family-development"
        and item["reason"] == "C++/CMake project matches studio baseline"
        for item in plan["profile_resolution"]
    )
    assert plan["authority"] is False
    assert plan["pass_credit"] is False


def test_non_c_language_evidence_never_selects_c_family_tools(tmp_path: Path) -> None:
    source = tmp_path / "src" / "main.py"
    source.parent.mkdir()
    source.write_text("raise SystemExit(0)\n", encoding="utf-8")

    plan = resolve_plan(tmp_path, goal="Audit the Python project", language="en")

    assert [item["technology"] for item in plan["detected_technologies"]] == [
        "python"
    ]
    assert plan["profile_layers"] == ["general-development", "ask", "en"]
    assert "c-family-development" not in {
        item["profile_id"] for item in plan["profile_resolution"]
    }
    assert plan["authority"] is False
    assert plan["pass_credit"] is False


def test_generic_unknown_language_init_preserves_the_minimal_core_plan(
    tmp_path: Path,
) -> None:
    plan = resolve_plan(
        tmp_path,
        goal="Initialize a minimal evidence-first project",
        language="en",
    )

    core_plans = compile_core_plans(plan, tmp_path)

    assert core_plans["project.json"]["preset_id"] == "semantic-standard"
    assert core_plans["project.json"]["operating_profile"] == "baseline"
    assert core_plans["project.json"]["resolved_profile"]["layers"] == [
        "general-development",
        "ask",
        "en",
    ]
    assert core_plans["standards.json"] == {
        "record_type": "StandardsInit",
        "bindings": [],
    }
    assert [
        item["capability_id"] for item in core_plans["technologies.json"]["bindings"]
    ] == [
        "control-runtime",
        "shape-validation",
        "content-identity",
        "local-serialization",
        "query-projection",
    ]
    assert len(core_plans["licenses.json"]["bindings"]) == 5
    assert plan["authority"] is False
    assert plan["pass_credit"] is False
