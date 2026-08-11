from __future__ import annotations

import hashlib
import json
from pathlib import Path
from time import perf_counter

import pytest

from promin.compilation_database import verify_compilation_database
from promin.language_analysis import (
    GateStatus,
    assess_bounded_semantic_scope,
    assess_configured_tools,
    assess_ownership_transfer_sequence,
    load_language_profile,
)
from promin.semantic_scope import affected_semantic_scope, build_module_graph


ROOT = Path(__file__).resolve().parents[1]


def _digest(label: str) -> str:
    return hashlib.sha256(f"heavy-language-analysis:{label}".encode("utf-8")).hexdigest()


def _profile():
    return load_language_profile(ROOT / "language_profiles" / "c-family-semantic.json")


def _tool_receipt(tool_id: str, status: GateStatus = GateStatus.PASS) -> dict[str, object]:
    successful = status in {GateStatus.PASS, GateStatus.SAFE}
    return {
        "tool_id": tool_id,
        "status": status.value,
        "input_digest": _digest(f"input:{tool_id}") if successful else None,
        "configuration_digest": _digest(f"configuration:{tool_id}") if successful else None,
        "scope_count": 2048,
        "elapsed_seconds": 0.125,
        "reason": None if successful else f"{tool_id} is not available on this host",
    }


def _large_reverse_graph(size: int) -> dict[str, tuple[str, ...]]:
    paths = tuple(f"src/unit-{index:05d}.cpp" for index in range(size))
    return {
        path: tuple(paths[next_index] for next_index in range(index + 1, min(size, index + 4)))
        for index, path in enumerate(paths)
    }


@pytest.mark.performance
def test_large_module_graph_receipt_is_deterministic_and_explicitly_bounded() -> None:
    graph_input = _large_reverse_graph(2048)
    started = perf_counter()
    graph = build_module_graph(graph_input)
    reordered_graph = build_module_graph(dict(reversed(tuple(graph_input.items()))))
    scope = affected_semantic_scope(
        changed_paths=("src/unit-00000.cpp",),
        graph=graph,
        compilation_database_digest=_digest("compdb"),
        compilation_database_sources=tuple(graph_input),
        max_depth=2048,
        max_files=256,
    )
    admission = assess_bounded_semantic_scope(
        traversal_status=scope.status,
        graph_digest=scope.graph_digest,
        compilation_database_digest=scope.compilation_database_digest,
        changed_paths=scope.changed_paths,
        selected_paths=scope.paths,
        max_depth=scope.max_depth,
        max_files=scope.max_files,
        truncated=scope.truncated,
        errors=scope.errors,
    )
    elapsed = perf_counter() - started

    assert graph.digest == reordered_graph.digest
    assert scope.status is GateStatus.UNAVAILABLE
    assert scope.truncated is True
    assert scope.paths == tuple(sorted(scope.paths))
    assert len(scope.paths) == 256
    assert admission.status is GateStatus.UNAVAILABLE
    assert admission.selected_count == 256
    assert admission.pass_credit is False
    assert admission.acceptance_pass is False
    assert elapsed < 8.0


def test_configured_tool_receipts_have_no_implicit_tool_or_credit() -> None:
    profile = _profile()
    selected = ("canonical-compilation-database", "clangd")
    assessment = assess_configured_tools(
        profile,
        tool_receipts=(_tool_receipt(item) for item in selected),
        required_tools=selected,
        max_receipts=4,
    )

    assert assessment.status is GateStatus.PASS
    assert assessment.required_tools == selected
    assert assessment.unavailable_tools == ()
    assert assessment.pass_credit is False
    assert assessment.product_acceptance_pass is False

    missing = assess_configured_tools(
        profile,
        tool_receipts=(_tool_receipt("clangd"),),
        required_tools=selected,
        max_receipts=4,
    )
    assert missing.status is GateStatus.UNAVAILABLE
    assert missing.unavailable_tools == ("canonical-compilation-database",)

    bounded = assess_configured_tools(
        profile,
        tool_receipts=(_tool_receipt(item) for item in selected),
        required_tools=selected,
        max_receipts=1,
    )
    assert bounded.status is GateStatus.UNAVAILABLE
    assert bounded.truncated is True


def _transfer(index: int) -> dict[str, object]:
    return {
        "transfer_id": f"transfer-{index:05d}",
        "source_id": f"value-{index:05d}",
        "destination_id": f"value-{index + 1:05d}",
        "source_category": "by-value",
        "destination_category": "owned-value",
        "source_observable_after_transfer": True,
        "postcondition": "explicit-reset",
        "source_scope": "operation:bounded-flow",
        "destination_scope": "operation:bounded-flow",
    }


@pytest.mark.performance
def test_streaming_ownership_transfer_analysis_detects_duplicate_ownership() -> None:
    profile = _profile()
    started = perf_counter()
    safe = assess_ownership_transfer_sequence(
        profile,
        transfers=(_transfer(index) for index in range(2048)),
        max_transfers=2048,
        max_recorded_findings=8,
        max_identity_length=128,
    )
    elapsed = perf_counter() - started

    assert safe.status is GateStatus.SAFE
    assert safe.transfer_count == 2048
    assert safe.safe_transfer_count == 2048
    assert safe.findings == ()
    assert safe.pass_credit is False
    assert safe.acceptance_pass is False
    assert elapsed < 8.0

    repeated = _transfer(0)
    repeated["transfer_id"] = "transfer-duplicate"
    repeated["destination_id"] = "value-duplicate"
    duplicate = assess_ownership_transfer_sequence(
        profile,
        transfers=(_transfer(0), repeated),
        max_transfers=4,
        max_recorded_findings=8,
        max_identity_length=128,
    )
    assert duplicate.status is GateStatus.FAIL
    assert duplicate.proven_transfer_count == 1
    assert any(finding.rule_id == "duplicate-transfer-source" for finding in duplicate.findings)

    bounded = assess_ownership_transfer_sequence(
        profile,
        transfers=(_transfer(index) for index in range(2)),
        max_transfers=1,
        max_recorded_findings=8,
        max_identity_length=128,
    )
    assert bounded.status is GateStatus.UNAVAILABLE
    assert bounded.transfer_count == 1


@pytest.mark.performance
def test_bounded_compilation_database_is_source_profiled_and_scales(tmp_path: Path) -> None:
    profile = _profile()
    rows: list[dict[str, object]] = []
    started = perf_counter()
    for index in range(192):
        source = tmp_path / "src" / f"unit-{index:04d}.cpp"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(f"int unit_{index}() {{ return {index}; }}\n", encoding="utf-8")
        rows.append(
            {
                "directory": str(tmp_path),
                "file": str(source),
                "arguments": ["c++", "-c", str(source), "-o", f"unit-{index:04d}.o"],
            }
        )
    database = tmp_path / "compile_commands.json"
    database.write_text(json.dumps(rows), encoding="utf-8")
    report = verify_compilation_database(
        database,
        tmp_path,
        max_database_bytes=512 * 1024,
        max_rows=len(rows),
        allowed_source_extensions=profile.source_extensions,
    )
    elapsed = perf_counter() - started

    assert report.status is GateStatus.PASS, report.errors
    assert report.row_count == len(rows)
    assert report.command_count == len(rows)
    assert report.database_bytes is not None
    assert report.allowed_source_extensions == tuple(sorted(profile.source_extensions))
    assert report.pass_credit is False
    assert report.acceptance_pass is False
    assert elapsed < 8.0

    row_bound = verify_compilation_database(
        database,
        tmp_path,
        max_database_bytes=512 * 1024,
        max_rows=len(rows) - 1,
        allowed_source_extensions=profile.source_extensions,
    )
    assert row_bound.status is GateStatus.UNAVAILABLE
    assert row_bound.command_count == 0

    byte_bound = verify_compilation_database(
        database,
        tmp_path,
        max_database_bytes=1,
        max_rows=len(rows),
        allowed_source_extensions=profile.source_extensions,
    )
    assert byte_bound.status is GateStatus.UNAVAILABLE
    assert byte_bound.command_count == 0

    unsupported_source = tmp_path / "src" / "unsupported.txt"
    unsupported_source.write_text("not a C-family input\n", encoding="utf-8")
    database.write_text(
        json.dumps(
            [
                {
                    "directory": str(tmp_path),
                    "file": str(unsupported_source),
                    "arguments": ["c++", "-c", str(unsupported_source), "-o", "unsupported.o"],
                }
            ]
        ),
        encoding="utf-8",
    )
    unsupported = verify_compilation_database(
        database,
        tmp_path,
        max_database_bytes=512 * 1024,
        max_rows=1,
        allowed_source_extensions=profile.source_extensions,
    )
    assert unsupported.status is GateStatus.FAIL
    assert any("extension" in error for error in unsupported.errors)
