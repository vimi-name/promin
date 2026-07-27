from __future__ import annotations

import json
from pathlib import Path

from promin.audit import audit_project
from promin.telemetry import heartbeat, record_observation


def test_telemetry_aggregates_repeated_failures_and_redacts_secrets(tmp_path: Path) -> None:
    record_observation(
        tmp_path,
        kind="provider.invoke",
        status="failed",
        duration_ms=12.5,
        details={"component": "web", "reason": "timeout", "token": "secret-value"},
    )
    record_observation(
        tmp_path,
        kind="provider.invoke",
        status="failed",
        duration_ms=7.5,
        details={"component": "web", "reason": "timeout", "token": "different-secret"},
    )

    hb = heartbeat(tmp_path)
    assert hb["record_type"] == "ProminHeartbeat"
    assert hb["active_fingerprints"] == 1
    assert hb["observation_count"] == 2
    assert hb["authority"] is False
    store = json.loads(
        (tmp_path / ".promin" / "state" / "observations" / "aggregates.json").read_text(encoding="utf-8")
    )
    aggregate = next(iter(store["fingerprints"].values()))
    assert aggregate["occurrence_count"] == 2
    assert aggregate["details"]["token"] == "[REDACTED]"


def test_runtime_audit_is_bounded_non_authoritative_and_proposes_repairs(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    duplicate = "export const value = 1;\n"
    (tmp_path / "src" / "feature.ts").write_text(duplicate, encoding="utf-8")
    (tmp_path / "src" / "feature-copy.ts").write_text(duplicate, encoding="utf-8")
    (tmp_path / "src" / "large.ts").write_text("x\n" * 1200, encoding="utf-8")

    result = audit_project(tmp_path, build_plan=True, max_files=100, max_total_bytes=1024 * 1024)

    assert result["record_type"] == "ProminRuntimeAudit"
    assert result["authority"] is False
    assert result["pass_credit"] is False
    assert result["product_acceptance_pass"] is False
    assert result["files_examined"] == 3
    assert result["duplicate_clusters"]
    assert any(item["finding_kind"] == "large-file" for item in result["findings"])
    assert result["plan_proposal"]["record_type"] == "PlanProposal"
    assert result["plan_proposal"]["authority"] is False
