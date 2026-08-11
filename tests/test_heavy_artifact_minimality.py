from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from promin.artifact_policy import (
    DOCS_ROOT,
    ArtifactBudget,
    ArtifactPolicyError,
    HostArtifactRetention,
    build_document_manifest,
    collect_host_local_artifacts,
    plan_host_local_retention,
    validate_document_payloads,
)
from promin.documentation import sync_documentation
from promin.experience import resolve_plan


def test_tracked_document_budget_rejects_high_file_count_bytes_and_case_collisions() -> None:
    file_budget = ArtifactBudget(
        max_file_bytes=32,
        max_file_count=3,
        max_compact_report_bytes=16,
        max_total_bytes=64,
    )
    many_files = {
        DOCS_ROOT / "normative" / f"item-{index}.md": b"# short\n"
        for index in range(4)
    }
    with pytest.raises(ArtifactPolicyError, match="file-count budget"):
        validate_document_payloads(many_files, budget=file_budget)

    byte_budget = ArtifactBudget(
        max_file_bytes=32,
        max_file_count=8,
        max_compact_report_bytes=16,
        max_total_bytes=11,
    )
    with pytest.raises(ArtifactPolicyError, match="total-byte budget"):
        validate_document_payloads(
            {
                DOCS_ROOT / "one.md": b"# one\n",
                DOCS_ROOT / "two.md": b"# two\n",
            },
            budget=byte_budget,
        )

    with pytest.raises(ArtifactPolicyError, match="casefold collision"):
        validate_document_payloads(
            {
                ".promin/docs/Contract.md": b"# one\n",
                ".promin/docs/contract.md": b"# two\n",
            }
        )


def test_tracked_docs_reject_superseded_history_and_duplicate_current_slots() -> None:
    with pytest.raises(ArtifactPolicyError, match="superseded/history"):
        validate_document_payloads(
            {DOCS_ROOT / "history" / "previous-summary.md": b"# previous\n"}
        )

    with pytest.raises(ArtifactPolicyError, match="one current compact report"):
        validate_document_payloads(
            {
                DOCS_ROOT / "a" / "current-summary.json": b"{}\n",
                DOCS_ROOT / "b" / "current-summary.md": b"# summary\n",
            }
        )


def test_host_local_retention_plans_before_deleting_high_volume_diagnostics(tmp_path: Path) -> None:
    diagnostics = tmp_path / "builds" / "analysis"
    diagnostics.mkdir(parents=True)
    old = diagnostics / "old-inventory.json"
    old.write_bytes(b"old-detail")
    fresh = diagnostics / "fresh-inventory.json"
    fresh.write_bytes(b"ok")
    now_ns = 200_000_000_000
    os.utime(old, ns=(10_000_000_000, 10_000_000_000))
    os.utime(fresh, ns=(now_ns, now_ns))
    retention = HostArtifactRetention(
        max_age_seconds=60,
        max_file_count=1,
        max_total_bytes=4,
    )

    plan = plan_host_local_retention(
        tmp_path,
        artifact_class="diagnostic-inventory",
        retention=retention,
        now_ns=now_ns,
    )
    assert plan["status"] == "planned"
    assert [item["path"] for item in plan["scheduled"]] == [
        "builds/analysis/old-inventory.json"
    ]
    assert all(not item["path"].startswith(".promin/docs/") for item in plan["scheduled"])

    dry_run = collect_host_local_artifacts(
        tmp_path,
        artifact_class="diagnostic-inventory",
        retention=retention,
        now_ns=now_ns,
        apply=False,
    )
    assert dry_run["status"] == "planned"
    assert old.exists()

    collected = collect_host_local_artifacts(
        tmp_path,
        artifact_class="diagnostic-inventory",
        retention=retention,
        now_ns=now_ns,
        apply=True,
    )
    assert collected["status"] == "collected"
    assert collected["removed"] == ["builds/analysis/old-inventory.json"]
    assert not old.exists()
    assert fresh.exists()


def test_generated_boilerplate_has_no_quality_credit_and_large_workspace_stays_bounded(
    tmp_path: Path,
) -> None:
    manifest = build_document_manifest(
        {DOCS_ROOT / "generated-contract.md": b"# Generated\nDo not edit.\n"},
        metadata={"generated": True},
    )
    quality = manifest["files"][0]["documentation_quality"]
    assert quality["coverage_credit"] is False
    assert quality["status"] == "uncredited-generated-boilerplate"

    plan = resolve_plan(tmp_path, goal="Keep a large generic workspace minimal")
    plan["workspace_map"] = {
        "workspace_kind": "multi-unit",
        "units": [
            {
                "unit_id": f"unit-{index:04}",
                "path": f"components/unit-{index:04}",
                "kind": "project-unit",
                "technology_ids": ["generic-tooling", "x" * 2048],
                "profile_layers": ["minimal"],
                "confidence": "known",
            }
            for index in range(320)
        ],
        "relations": [
            {"from": f"unit-{index:04}", "to": f"unit-{index + 1:04}", "kind": "uses"}
            for index in range(319)
        ],
    }

    result = sync_documentation(tmp_path, plan, apply=True)
    workspace = json.loads((tmp_path / DOCS_ROOT / "workspace-map.json").read_text(encoding="utf-8"))
    workspace_markdown = (tmp_path / DOCS_ROOT / "WORKSPACE_MAP.md").read_text(encoding="utf-8")

    assert result["artifact_mode"] == "minimal"
    assert result["tracked_documentation_bytes"] <= 8 * 1024 * 1024
    assert workspace["source_unit_count"] == 320
    assert workspace["omitted_unit_count"] > 0
    assert workspace["source_relation_count"] == 319
    assert workspace["omitted_relation_count"] > 0
    assert len(workspace["units"]) < workspace["source_unit_count"]
    assert 0 < workspace_markdown.count("| `unit-") < len(workspace["units"])
    assert "detailed units remain host-local" in workspace_markdown
