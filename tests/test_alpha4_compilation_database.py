from __future__ import annotations

import json
from pathlib import Path

import pytest

from promin.compilation_database import (
    CompilationDatabaseError,
    ensure_semantic_tool_precondition,
    verify_compilation_database,
)
from promin.language_analysis import GateStatus


def _write_database(root: Path, rows: list[dict[str, object]]) -> Path:
    path = root / "compile_commands.json"
    path.write_text(json.dumps(rows), encoding="utf-8")
    return path


def _row(root: Path, arguments: list[str] | None = None) -> dict[str, object]:
    source = root / "src" / "unit.cpp"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("int unit() { return 1; }\n", encoding="utf-8")
    return {
        "directory": str(root),
        "file": str(source),
        "arguments": arguments or ["c++", "-c", str(source), "-o", "unit.o"],
    }


def test_compilation_database_requires_canonical_physical_compile_rows(tmp_path: Path) -> None:
    row = _row(tmp_path)
    report = verify_compilation_database(_write_database(tmp_path, [row]), tmp_path)

    assert report.status is GateStatus.PASS, report.errors
    assert report.command_count == 1
    assert report.commands[0].source_path == "src/unit.cpp"
    assert report.commands[0].driver_identity
    assert report.digest


def test_missing_database_is_unavailable_and_cannot_start_semantic_tool(tmp_path: Path) -> None:
    report = verify_compilation_database(tmp_path / "compile_commands.json", tmp_path)

    assert report.status is GateStatus.UNAVAILABLE
    with pytest.raises(CompilationDatabaseError, match="canonical compilation database"):
        ensure_semantic_tool_precondition(report, "clang-tidy")


def test_non_compile_and_conflicting_duplicate_commands_fail_closed(tmp_path: Path) -> None:
    non_compile = _row(tmp_path, ["c++", "src/unit.cpp", "-o", "app"])
    report = verify_compilation_database(_write_database(tmp_path, [non_compile]), tmp_path)
    assert report.status is GateStatus.FAIL
    assert any("compile intent" in error for error in report.errors)

    first = _row(tmp_path)
    second = dict(first)
    second["arguments"] = ["c++", "-std=c++23", "-c", str(tmp_path / "src" / "unit.cpp")]
    report = verify_compilation_database(_write_database(tmp_path, [first, second]), tmp_path)
    assert report.status is GateStatus.FAIL
    assert any("conflicting commands" in error for error in report.errors)


def test_equivalent_duplicate_is_collapsed_and_path_escape_fails(tmp_path: Path) -> None:
    first = _row(tmp_path)
    report = verify_compilation_database(_write_database(tmp_path, [first, dict(first)]), tmp_path)
    assert report.status is GateStatus.PASS
    assert report.command_count == 1

    project = tmp_path / "separate-project"
    project.mkdir()
    escaped = dict(first)
    escaped["file"] = str(tmp_path / "outside.cpp")
    (tmp_path / "outside.cpp").write_text("int x;\n", encoding="utf-8")
    report = verify_compilation_database(_write_database(project, [escaped]), project)
    assert report.status is GateStatus.FAIL
    assert any("outside project root" in error for error in report.errors)
