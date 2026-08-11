from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = PACKAGE_ROOT / "tools" / "promin_saturation.py"
SPEC = importlib.util.spec_from_file_location(
    "promin_saturation_storage_budget_tool",
    TOOL_PATH,
)
assert SPEC is not None and SPEC.loader is not None
saturation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(saturation)


def _performance_contract() -> dict[str, object]:
    return {
        "thresholds": {
            "database_bytes_max": 402_653_184,
            "commit_bytes_per_changed_record_max": 32_768,
        }
    }


def _space(*, free_bytes: int, volume_id: str = "test:volume") -> dict[str, object]:
    total_bytes = 1_000_000_000_000
    return {
        "volume_id": volume_id,
        "total_bytes": total_bytes,
        "used_bytes": total_bytes - free_bytes,
        "free_bytes": free_bytes,
    }


def test_growth_plan_preserves_the_exact_workload_and_uses_profile_ceilings() -> None:
    plan = saturation._storage_growth_plan(
        _performance_contract(),
        files=100_000,
        queries=600,
        reuse_product=False,
    )

    assert plan["workload"] == {
        "physical_files": 100_000,
        "runtime_queries": 600,
        "core_valid_relations": 198_999,
        "workload_reduced": False,
    }
    assert plan["workspace_components"]["canonical_projection_database_bytes"] == 402_653_184
    assert plan["workspace_components"]["event_and_derived_state_bytes"] > 12_000_000_000
    assert plan["workspace_planned_growth_bytes"] == sum(
        plan["workspace_components"].values()
    )
    assert plan["output_planned_growth_bytes"] == sum(plan["output_components"].values())


def test_preflight_groups_same_volume_once_and_emits_no_credit_failure_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    output = tmp_path / "evidence"
    telemetry = saturation._StorageRunTelemetry(
        workspace,
        output,
        archive=None,
        performance_contract=_performance_contract(),
        files=100_000,
        queries=600,
        reuse_product=False,
        headroom_bytes=1024,
    )
    planned = (
        telemetry.plan["workspace_planned_growth_bytes"]
        + telemetry.plan["output_planned_growth_bytes"]
    )
    free_bytes = planned + 1024 - 1
    monkeypatch.setattr(
        saturation,
        "_disk_space_record",
        lambda _path: _space(free_bytes=free_bytes),
    )

    with pytest.raises(saturation.StorageBudgetError) as captured:
        telemetry.prepare()
    assert captured.value.failure_code == "storage-preflight-insufficient"
    assert telemetry.preflight["status"] == "fail"
    assert len(telemetry.preflight["volumes"]) == 1
    volume = telemetry.preflight["volumes"][0]
    assert volume["roles"] == ["output", "workspace"]
    assert volume["planned_growth_bytes"] == planned
    assert volume["required_free_bytes"] == planned + 1024

    receipt_path = telemetry.publish_failure(
        captured.value,
        captured.value.failure_code,
    )
    assert receipt_path == output / "saturation-storage-failure.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    digest = receipt.pop("receipt_digest")
    assert digest == saturation._digest(receipt)
    assert receipt["status"] == "fail"
    assert receipt["failure_code"] == "storage-preflight-insufficient"
    assert receipt["pass_credit"] is False
    assert receipt["acceptance_pass"] is False
    assert receipt["product_acceptance_pass"] is False
    assert receipt["workload"]["workload_reduced"] is False
    assert receipt["workload"]["physical_files"] == 100_000
    assert not (output / ".storage-failure-reserve.bin").exists()


def test_unavailable_free_space_fails_closed_instead_of_becoming_a_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "evidence"
    telemetry = saturation._StorageRunTelemetry(
        tmp_path / "workspace",
        output,
        archive=None,
        performance_contract=_performance_contract(),
        files=100_000,
        queries=600,
        reuse_product=False,
        headroom_bytes=1024,
    )

    def unavailable(_path: Path) -> dict[str, object]:
        raise saturation.StorageBudgetError(
            "free-space provider unavailable",
            failure_code="storage-telemetry-unavailable",
        )

    monkeypatch.setattr(saturation, "_disk_space_record", unavailable)
    with pytest.raises(saturation.StorageBudgetError) as captured:
        telemetry.prepare()
    assert captured.value.failure_code == "storage-telemetry-unavailable"
    assert telemetry.preflight["telemetry_available"] is False
    assert telemetry.preflight["status"] == "fail"
    receipt_path = telemetry.publish_failure(captured.value, captured.value.failure_code)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "fail"
    assert receipt["pass_credit"] is False
    assert receipt["storage"]["preflight"]["telemetry_available"] is False


def test_preexisting_output_is_rejected_without_deleting_its_files(tmp_path: Path) -> None:
    output = tmp_path / "evidence"
    output.mkdir()
    sentinel = output / ".storage-failure-reserve.bin"
    sentinel.write_bytes(b"user-owned")
    telemetry = saturation._StorageRunTelemetry(
        tmp_path / "workspace",
        output,
        archive=None,
        performance_contract=_performance_contract(),
        files=100_000,
        queries=600,
        reuse_product=False,
        headroom_bytes=1024,
    )

    with pytest.raises(saturation.SaturationError, match="output directory already exists"):
        telemetry.prepare()
    telemetry.stop()
    assert sentinel.read_bytes() == b"user-owned"


def test_database_and_phase_measurements_report_exact_logical_bytes(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    generation = workspace / ".promin" / "state" / "events" / "derived-index" / ("a" * 32)
    projection = workspace / ".promin" / "state" / "projection"
    generation.mkdir(parents=True)
    projection.mkdir(parents=True)
    (generation / "state-binding.sqlite3").write_bytes(b"s" * 17)
    (generation / "event-identities.sqlite3").write_bytes(b"e" * 19)
    (generation / "state-binding.sqlite3-wal").write_bytes(b"w" * 23)
    (generation / "state-binding.sqlite3-journal").write_bytes(b"r" * 27)
    (projection / "promin.sqlite3").write_bytes(b"p" * 29)
    checkpoint = workspace / ".promin" / "state" / "events" / "journal-checkpoint.json"
    checkpoint.write_bytes(b"c" * 31)
    derived_state = workspace / ".promin" / "state" / "events" / "derived-state"
    derived_state.mkdir()
    (derived_state / "other.json").write_bytes(b"d" * 13)
    derived_rows = workspace / ".promin" / "state" / "events" / "derived-rows"
    derived_rows.mkdir()
    runtime_name = hashlib.sha256(b"runtime").hexdigest() + ".sqlite3"
    (derived_rows / runtime_name).write_bytes(b"q" * 37)

    measured = saturation._database_storage_measurement(workspace)
    assert measured["database_file_count"] == 6
    assert measured["database_logical_bytes"] == 17 + 19 + 23 + 27 + 29 + 37
    assert measured["journal_checkpoint_logical_bytes"] == 31
    assert measured["runtime_derived_checkpoint_logical_bytes"] == 37
    assert measured["derived_state_logical_bytes"] == 13
    assert measured["observed_control_storage_bytes"] == 17 + 19 + 23 + 27 + 29 + 37 + 31 + 13
    assert {value["path"] for value in measured["database_files"]} == {
        ".promin/state/events/derived-index/" + ("a" * 32) + "/event-identities.sqlite3",
        ".promin/state/events/derived-index/" + ("a" * 32) + "/state-binding.sqlite3",
        ".promin/state/events/derived-index/" + ("a" * 32) + "/state-binding.sqlite3-journal",
        ".promin/state/events/derived-index/" + ("a" * 32) + "/state-binding.sqlite3-wal",
        ".promin/state/events/derived-rows/" + runtime_name,
        ".promin/state/projection/promin.sqlite3",
    }
    assert measured["runtime_derived_checkpoint_path"] == (
        ".promin/state/events/derived-rows/" + runtime_name
    )
    tree = saturation._tree_logical_measurement(workspace / ".promin" / "state")
    assert tree["logical_bytes"] == measured["observed_control_storage_bytes"]
    assert tree["regular_files"] == 8


def test_commit_telemetry_captures_database_checkpoint_and_free_space_without_shrinking(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    output = tmp_path / "evidence"
    generation = workspace / ".promin" / "state" / "events" / "derived-index" / ("b" * 32)
    generation.mkdir(parents=True)
    (generation / "state-binding.sqlite3").write_bytes(b"x" * 101)
    (workspace / ".promin" / "state" / "events" / "journal-checkpoint.json").write_bytes(
        b"y" * 37
    )
    derived_rows = workspace / ".promin" / "state" / "events" / "derived-rows"
    derived_rows.mkdir()
    (derived_rows / (hashlib.sha256(b"runtime").hexdigest() + ".sqlite3")).write_bytes(
        b"z" * 43
    )
    free = {"bytes": 100_000_000_000}
    monkeypatch.setattr(
        saturation,
        "_disk_space_record",
        lambda _path: _space(free_bytes=free["bytes"]),
    )
    telemetry = saturation._StorageRunTelemetry(
        workspace,
        output,
        archive=None,
        performance_contract=_performance_contract(),
        files=100_000,
        queries=600,
        reuse_product=False,
        headroom_bytes=1024,
    )
    telemetry.prepare()
    telemetry.record_commit(
        {
            "sequence": 1,
            "phase": "physical-relation-corpus",
            "checkpoint_written": True,
            "checkpoint_bytes": 37,
            "physical_payload_bytes": 4096,
        }
    )
    telemetry.measure_phase("semantic-ingestion")
    telemetry.measure_phase("physical-generation")
    telemetry.measure_phase("inventory")
    telemetry.measure_phase("projection")
    telemetry.measure_phase("runtime-queries")
    telemetry.stop_for_publication()

    checkpoint = telemetry.checkpoint_measurements[0]
    assert checkpoint["database_logical_bytes"] == 144
    assert checkpoint["journal_checkpoint_logical_bytes"] == 37
    assert checkpoint["runtime_derived_checkpoint_logical_bytes"] == 43
    assert checkpoint["observed_control_storage_bytes"] == 181
    assert checkpoint["free_bytes_by_volume"] == [free["bytes"]]
    bound = telemetry.bound_phase_payload("semantic-ingestion")
    assert bound["commit_checkpoint_count"] == 1
    assert bound["commit_checkpoints"] == telemetry.checkpoint_measurements
    assert bound["commit_checkpoint_volume_order"] == [
        {"volume_id": "test:volume", "roles": ["output", "workspace"]}
    ]
    assert telemetry.bound_phase_payload("result")["workload_reduced"] is False
    telemetry.stop()


def test_runtime_headroom_breach_and_nested_sqlite_full_error_are_terminal_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    free = {"bytes": 100_000_000_000}
    monkeypatch.setattr(
        saturation,
        "_disk_space_record",
        lambda _path: _space(free_bytes=free["bytes"]),
    )
    telemetry = saturation._StorageRunTelemetry(
        tmp_path / "workspace",
        tmp_path / "evidence",
        archive=None,
        performance_contract=_performance_contract(),
        files=100_000,
        queries=600,
        reuse_product=False,
        headroom_bytes=4096,
    )
    telemetry.prepare()
    free["bytes"] = 4095
    with pytest.raises(saturation.StorageBudgetError) as captured:
        telemetry.record_commit(
            {
                "sequence": 1,
                "phase": "physical-relation-corpus",
                "checkpoint_written": False,
                "checkpoint_bytes": 0,
                "physical_payload_bytes": 1,
            }
        )
    assert captured.value.failure_code == "storage-headroom-exhausted"
    assert telemetry.failure_code(captured.value) == "storage-headroom-exhausted"
    telemetry.stop()

    try:
        try:
            raise sqlite3.OperationalError("database or disk is full")
        except sqlite3.OperationalError as inner:
            raise RuntimeError("derived checkpoint publication failed") from inner
    except RuntimeError as outer:
        assert saturation._storage_failure_code(outer) == "storage-write-exhausted"
