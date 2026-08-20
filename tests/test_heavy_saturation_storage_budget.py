from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

from promin import evidence


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
        "profile_id": "portable-local-v1",
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


def _binding_identity(binding: dict[str, object]) -> dict[str, object]:
    identity = dict(binding)
    binding_digest = identity.pop("binding_digest")
    assert binding_digest == saturation._digest(identity)
    return identity


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


def test_storage_guard_persists_generic_saturation_rejection_after_prepare(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    output = tmp_path / "evidence"
    archive = tmp_path / "promin-candidate.zip"
    archive_payload = b"exact candidate archive payload\n"
    archive.write_bytes(archive_payload)
    sentinel = workspace / "preserved.txt"
    reason = "controlled non-storage saturation rejection"
    monkeypatch.setattr(
        saturation,
        "_disk_space_record",
        lambda _path: _space(free_bytes=100_000_000_000),
    )

    @saturation._guard_storage_run
    def reject_after_prepare(
        selected_workspace: Path,
        selected_output: Path,
        *,
        archive: Path | None = None,
        files: int = 100_000,
        queries: int = 600,
        reuse_product: bool = False,
        performance_profile: str = "portable-local-v1",
    ) -> dict[str, object]:
        del archive, files, queries, reuse_product, performance_profile
        assert selected_workspace == workspace.resolve()
        assert selected_output == output.resolve()
        selected_workspace.mkdir(parents=True, exist_ok=False)
        sentinel.write_bytes(b"preserve this workspace")
        raise saturation.SaturationError(reason)

    with pytest.raises(saturation.SaturationError, match=reason):
        reject_after_prepare(
            workspace,
            output,
            archive=archive,
            files=100_000,
            queries=600,
            reuse_product=False,
            performance_profile="portable-local-v1",
        )

    receipt_path = output / "saturation-failure.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_digest = receipt.pop("receipt_digest")
    assert receipt_digest == saturation._digest(receipt)
    assert receipt["schema"] == "promin.saturation-failure.v1"
    assert receipt["record_type"] == "SaturationFailure"
    assert receipt["status"] == "rejected"
    assert receipt["failure_code"] == "saturation-rejected"
    assert receipt["reason"] == reason
    assert receipt["exception_type"] == "SaturationError"
    assert receipt["pass_credit"] is False
    assert receipt["acceptance_pass"] is False
    assert receipt["product_acceptance_pass"] is False
    assert receipt["public_release_approved"] is False
    performance_contract = saturation._load_performance_contract("portable-local-v1")
    assert receipt["workload"] == {
        "physical_files": 100_000,
        "runtime_queries": 600,
        "core_valid_relations": 198_999,
        "performance_profile": "portable-local-v1",
        "performance_contract_digest": saturation._digest(performance_contract),
        "reuse_product": False,
        "workload_reduced": False,
    }
    archive_identity = _binding_identity(receipt["archive_binding"])
    assert archive_identity == {
        "available": True,
        "requested_path": str(archive.resolve()),
        "resolved_path": str(archive.resolve()),
        "name": archive.name,
        "bytes": len(archive_payload),
        "sha256": hashlib.sha256(archive_payload).hexdigest(),
    }
    tool_payload = TOOL_PATH.read_bytes()
    tool_identity = _binding_identity(receipt["tool_binding"])
    assert tool_identity == {
        "path": "tools/promin_saturation.py",
        "resolved_path": str(TOOL_PATH.resolve()),
        "bytes": len(tool_payload),
        "sha256": hashlib.sha256(tool_payload).hexdigest(),
    }
    storage_identity = _binding_identity(receipt["storage"])
    assert storage_identity["growth_plan"] == saturation._storage_growth_plan(
        performance_contract,
        files=100_000,
        queries=600,
        reuse_product=False,
    )
    assert storage_identity["headroom_bytes"] == 8 * 1024**3
    assert receipt["storage"]["preflight"]["status"] == "pass"
    assert [
        measurement["phase"]
        for measurement in receipt["storage"]["phase_measurements"]
    ] == ["preflight"]
    assert receipt["workspace"] == {
        "path": str(workspace.resolve()),
        "exists": True,
        "preservation_verified": False,
    }
    assert set(output.iterdir()) == {receipt_path}
    assert not (output / "saturation-storage-failure.json").exists()
    assert not (output / "saturation-result.json").exists()
    assert not (output / ".storage-failure-reserve.bin").exists()
    assert not (workspace / "saturation-failure.json").exists()
    assert sentinel.read_bytes() == b"preserve this workspace"


def test_terminal_headroom_observation_promotes_rejection_to_storage_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    output = tmp_path / "evidence"
    free = {"bytes": 100_000_000_000}
    reason = "controlled failure after the final work boundary"
    monkeypatch.setattr(
        saturation,
        "_disk_space_record",
        lambda _path: _space(free_bytes=free["bytes"]),
    )
    monkeypatch.setattr(saturation, "_STORAGE_SAMPLE_INTERVAL_SECONDS", 60.0)

    @saturation._guard_storage_run
    def reject_after_terminal_disk_pressure(
        selected_workspace: Path,
        selected_output: Path,
        *,
        archive: Path | None = None,
        files: int = 100_000,
        queries: int = 600,
        reuse_product: bool = False,
        performance_profile: str = "portable-local-v1",
    ) -> dict[str, object]:
        del archive, files, queries, reuse_product, performance_profile
        assert selected_workspace == workspace.resolve()
        assert selected_output == output.resolve()
        free["bytes"] = saturation._DEFAULT_STORAGE_HEADROOM_BYTES - 1
        raise saturation.SaturationError(reason)

    with pytest.raises(saturation.StorageBudgetError) as captured:
        reject_after_terminal_disk_pressure(workspace, output)

    assert captured.value.failure_code == "storage-headroom-exhausted"
    receipt_path = output / "saturation-storage-failure.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_digest = receipt.pop("receipt_digest")
    assert receipt_digest == saturation._digest(receipt)
    assert receipt["status"] == "fail"
    assert receipt["failure_code"] == "storage-headroom-exhausted"
    assert receipt["reason"] == reason
    assert receipt["storage"]["headroom_breach"] == {
        "volume_id": "test:volume",
        "roles": ["output", "workspace"],
        "free_bytes": saturation._DEFAULT_STORAGE_HEADROOM_BYTES - 1,
        "required_headroom_bytes": saturation._DEFAULT_STORAGE_HEADROOM_BYTES,
    }
    assert not (output / "saturation-failure.json").exists()
    assert not (output / "saturation-result.json").exists()
    assert not (output / ".storage-failure-reserve.bin").exists()


def test_guard_does_not_mutate_replacement_at_acquired_output_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    output = tmp_path / "evidence"
    acquired_output = tmp_path / "acquired-evidence"
    reason = "controlled failure after output identity replacement"
    replacement_files = {
        ".storage-failure-reserve.bin": b"replacement-owned reserve",
        "saturation-result.json": b"replacement-owned result",
        "user-owned.bin": b"replacement-owned payload",
    }
    monkeypatch.setattr(
        saturation,
        "_disk_space_record",
        lambda _path: _space(free_bytes=100_000_000_000),
    )
    monkeypatch.setattr(saturation, "_STORAGE_SAMPLE_INTERVAL_SECONDS", 60.0)

    @saturation._guard_storage_run
    def replace_output_identity_then_reject(
        selected_workspace: Path,
        selected_output: Path,
        *,
        archive: Path | None = None,
        files: int = 100_000,
        queries: int = 600,
        reuse_product: bool = False,
        performance_profile: str = "portable-local-v1",
    ) -> dict[str, object]:
        del archive, files, queries, reuse_product, performance_profile
        assert selected_workspace == workspace.resolve()
        assert selected_output == output.resolve()
        selected_output.rename(acquired_output)
        selected_output.mkdir()
        for name, payload in replacement_files.items():
            (selected_output / name).write_bytes(payload)
        raise saturation.SaturationError(reason)

    with pytest.raises(saturation.StorageBudgetError) as captured:
        replace_output_identity_then_reject(workspace, output)

    assert captured.value.failure_code == "storage-telemetry-unavailable"
    assert set(output.iterdir()) == {
        output / name for name in replacement_files
    }
    assert {
        path.name: path.read_bytes()
        for path in output.iterdir()
        if path.is_file()
    } == replacement_files
    assert not (output / "saturation-failure.json").exists()
    assert not (output / "saturation-storage-failure.json").exists()
    assert acquired_output.is_dir()


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


def test_published_failed_saturation_evidence_binds_validated_semantic_ingestion_for_phase_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A structural failed result must validate its real raw phase log before publication."""

    output = tmp_path / "evidence"
    raw_directory = output / "raw"
    raw_directory.mkdir(parents=True)
    inventory_payload = b"inventory-stream\n"
    query_payload = b"query-results\n"
    process_payload = b"process-samples\n"
    continuation_payload = b""
    phase_payload = b"phase-log\n"

    observation = {
        "sequence": 1,
        "phase": "semantic-corpus",
        "command_id": "semantic-ingestion-0001",
        "batch_digest": "b" * 64,
        "duration_ms": 1.0,
        "changed_records": 1,
        "physical_payload_bytes": 1,
        "bytes_per_changed_record": 1.0,
        "checkpoint_written": True,
        "checkpoint_count": 1,
        "checkpoint_bytes": 1,
        "checkpoint_tail_batches": 0,
        "checkpoint_tail_bytes": 0,
    }
    semantic_ingestion = {
        "record_type": "SemanticIngestionMetrics",
        "elapsed_seconds": 1.0,
        "commit_count": 1,
        "changed_records": 1,
        "physical_payload_bytes": 1,
        "bytes_per_changed_record": 1.0,
        "p95_ms": 1.0,
        "p99_ms": 1.0,
        "checkpoint_count": 1,
        "checkpoint_writes": 1,
        "observations": [observation],
        "result_digest": evidence.canonical_digest([observation]),
    }
    query_classes = (
        "broad",
        "content-high-cardinality",
        "content-probe",
        "miss",
        "hostile-content",
        "hostile-exact",
        "exact-artifact",
    )
    query_rows = [{} for _ in range(600)]
    page_digest = "d" * 64
    query_mix = {
        query_class: sum(
            1
            for index in range(len(query_rows))
            if query_classes[index % len(query_classes)] == query_class
        )
        for query_class in query_classes
    }
    class_latency = {
        query_class: {
            "count": count,
            "p50": 1.0,
            "p95": 1.0,
            "p99": 1.0,
        }
        for query_class, count in sorted(query_mix.items())
    }
    search = {
        "runtime_query_budget": {"top_k": 1},
        "actual_runtime_queries": len(query_rows),
        "query_mix": dict(sorted(query_mix.items())),
        "depth_counts": {"1": len(query_rows)},
        "query_class_depths": {
            query_class: [1] for query_class in sorted(query_mix)
        },
        "query_class_latency_ms": class_latency,
        "p50_ms": 1.0,
        "p95_ms": 1.0,
        "p99_ms": 1.0,
        "result_digest": evidence.canonical_digest([page_digest] * len(query_rows)),
        "pages_observed": len(query_rows),
        "continuations_checked": 0,
        "explicit_truncations": 0,
        "maximum_continuation_token_bytes": 0,
        "selected_closure_chains": len(query_rows),
        "forced_continuation_chains": 0,
        "forced_union_matches": 0,
        "forced_depths": [],
        "broad_query_refinement_required": True,
        "high_cardinality_terms_verified": True,
        "content_search_verified": True,
        "miss_behavior_verified": True,
        "hostile_proxy_content_verified": True,
        "exact_artifact_search_verified": True,
    }
    phase_samples = [
        {"elapsed_ns": 0, "rss_bytes": 10},
        {"elapsed_ns": 1, "rss_bytes": 20},
    ]
    phase_summary = {
        "baseline_bytes": 10,
        "peak_bytes": 20,
        "incremental_peak_bytes": 10,
    }
    incremental_ratio = round(10 / len(inventory_payload), 9)
    absolute_ratio = round(20 / len(inventory_payload), 9)
    resources = {
        "inventory_stage_rss": phase_summary,
        "projection_stage_rss": phase_summary,
        "inventory_pipeline_peak_rss_bytes": 20,
        "inventory_pipeline_incremental_peak_bytes": 10,
        "inventory_absolute_rss_amplification": absolute_ratio,
        "inventory_incremental_memory_amplification": incremental_ratio,
        "memory_amplification_metric": {
            "metric_id": "inventory-incremental-peak-over-stream-bytes",
            "numerator": "inventory_pipeline_incremental_peak_bytes",
            "denominator": "inventory_stream_bytes",
            "numerator_bytes": 10,
            "denominator_bytes": len(inventory_payload),
            "ratio": incremental_ratio,
            "threshold_max": 32.0,
            "within_threshold": True,
        },
        "peak_rss_bytes": 20,
    }
    operation = {
        "record_type": "SaturationOperationMetrics",
        "evidence_class": "harness_generated",
        "product_acceptance_credit": False,
        "status": "fail",
        "process_exit_code": 1,
        "invocation_exit_code": 1,
        "physical": {},
        "inventory": {},
        "projection": {},
        "search": search,
        "resources": resources,
        "performance": {},
        "contract_predicates": {},
        "semantic_ingestion": semantic_ingestion,
    }
    operation_payload = evidence.canonical_bytes(operation)
    raw_payloads = {
        "raw/inventory-stream.jsonl": inventory_payload,
        "raw/query-results.jsonl": query_payload,
        "raw/process-samples.json": process_payload,
        "raw/continuation-state-manifest.jsonl": continuation_payload,
        "raw/phase-log.jsonl": phase_payload,
        "raw/operation-metrics.json": operation_payload,
    }
    for relative, payload in raw_payloads.items():
        (output / relative).write_bytes(payload)

    artifacts = [
        {
            "role": role,
            "path": relative,
            "media_type": media_type,
            "sha256": hashlib.sha256(raw_payloads[relative]).hexdigest(),
            "bytes": len(raw_payloads[relative]),
            "records": records,
        }
        for role, relative, media_type, records in (
            ("inventory-stream", "raw/inventory-stream.jsonl", "application/x-ndjson", 100_000),
            ("query-results", "raw/query-results.jsonl", "application/x-ndjson", 600),
            ("process-samples", "raw/process-samples.json", "application/json", 4),
            ("continuation-state-manifest", "raw/continuation-state-manifest.jsonl", "application/x-ndjson", 0),
            ("phase-log", "raw/phase-log.jsonl", "application/x-ndjson", 6),
            ("operation-metrics", "raw/operation-metrics.json", "application/json", 1),
        )
    ]

    class InventoryRows:
        def __len__(self) -> int:
            return 100_000

        def __iter__(self):
            for index in range(100_000):
                yield {
                    "path": f"artifacts/{index:06d}.txt",
                    "digest": "a" * 64,
                    "size": 0,
                    "search_text": "",
                }

    inventory_identity = hashlib.sha256()
    for row in InventoryRows():
        inventory_identity.update(
            evidence.canonical_bytes(
                {key: row[key] for key in ("path", "digest", "size")}
            )
        )
    manifest_identity = {
        "record_type": "SaturationRawArtifactManifest",
        "path_scope": "saturation-result-directory",
        "evidence_class": "harness_generated",
        "product_acceptance_credit": False,
        "artifacts": artifacts,
        "artifact_count": len(artifacts),
        "inventory_stream_digest": hashlib.sha256(inventory_payload).hexdigest(),
        "inventory_identity_digest": inventory_identity.hexdigest(),
    }
    verification = {
        "status": "fail",
        "physical": operation["physical"],
        "inventory": operation["inventory"],
        "projection": operation["projection"],
        "search": search,
        "resources": resources,
        "performance": operation["performance"],
        "contract_predicates": operation["contract_predicates"],
        "raw_artifact_manifest": {
            **manifest_identity,
            "manifest_digest": evidence.canonical_digest(manifest_identity),
        },
        "invocation": {"exit_code": 1},
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "public_release_approved": False,
    }
    process_samples = {
        "record_type": "SaturationProcessSamples",
        "sample_interval_ms": 50,
        "lifetime_peak_rss_bytes": 20,
        "phases": [
            {"phase": "inventory", "summary": phase_summary, "samples": phase_samples},
            {"phase": "projection", "summary": phase_summary, "samples": phase_samples},
        ],
    }
    phase_rows = [
        {"order": 1, "phase": "physical-generation", "elapsed_ms": 0},
        {"order": 2, "phase": "inventory", "elapsed_ms": 0},
        {
            "order": 3,
            "phase": "semantic-ingestion",
            "elapsed_ms": round(semantic_ingestion["elapsed_seconds"] * 1000),
        },
        {"order": 4, "phase": "projection", "elapsed_ms": 0},
        {"order": 5, "phase": "runtime-queries", "elapsed_ms": 0},
        {
            "order": 6,
            "phase": "result",
            "status": "fail",
            "process_exit_code": 1,
            "invocation_exit_code": 1,
        },
    ]
    original_parse_raw_json = evidence._parse_raw_json

    def parse_raw_json(payload: bytes, label: str) -> dict:
        if label == "saturation operation metrics":
            return original_parse_raw_json(payload, label)
        assert label == "process samples"
        return process_samples

    def parse_raw_jsonl(payload: bytes, label: str, **_kwargs: object):
        if label == "inventory stream":
            return InventoryRows()
        if label == "query results":
            return query_rows
        assert label == "phase log"
        return phase_rows

    def recompute_raw_query_result(
        _row: object,
        *,
        expected_index: int,
        top_k: int,
    ) -> dict:
        assert top_k == 1
        return {
            "query_class": query_classes[expected_index % len(query_classes)],
            "depth": 1,
            "elapsed_ms": 1.0,
            "class_verified": True,
            "reference": {
                "page_digests": [page_digest],
                "pages": 1,
                "continuation_pages": 0,
                "first_truncated": False,
                "maximum_token_bytes": 0,
            },
            "forced": None,
        }

    monkeypatch.setattr(evidence, "_parse_raw_json", parse_raw_json)
    monkeypatch.setattr(evidence, "_parse_raw_jsonl", parse_raw_jsonl)
    monkeypatch.setattr(
        evidence,
        "_recompute_raw_query_result",
        recompute_raw_query_result,
    )
    monkeypatch.setattr(
        evidence,
        "_validate_saturation_continuation_state",
        lambda *_args: [],
    )

    def structural_validation(document: dict, **kwargs: object) -> dict:
        assert kwargs["require_pass"] is False
        assert document["status"] == "fail"
        assert evidence._validate_saturation_raw_artifacts(
            document,
            source_path=kwargs["source_path"],
            evidence_root=kwargs["evidence_root"],
        )["operation"]["semantic_ingestion"] == semantic_ingestion
        return document

    monkeypatch.setattr(
        saturation,
        "validate_saturation_evidence",
        structural_validation,
    )
    published = saturation._publish_completed_saturation_result(
        output,
        verification,
        candidate_binding={"candidate_binding_digest": "c" * 64},
    )

    assert published == verification
    assert json.loads((output / "saturation-result.json").read_text(encoding="utf-8")) == verification
    for claim in (
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
        "public_release_approved",
    ):
        assert published[claim] is False
