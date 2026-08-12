from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from promin.canonical import canonical_bytes, digest_value


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = PACKAGE_ROOT / "tools" / "promin_performance_model.py"
SPEC = importlib.util.spec_from_file_location(
    "promin_performance_model_tool",
    TOOL_PATH,
)
assert SPEC is not None and SPEC.loader is not None
performance_model = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(performance_model)


NO_CLAIMS = {
    "acceptance_pass": False,
    "pass_credit": False,
    "performance_acceptance": False,
    "product_acceptance_pass": False,
    "release_eligible": False,
}


def _binding(value: dict[str, object]) -> dict[str, object]:
    bound = dict(value)
    bound["binding_digest"] = digest_value(value)
    return bound


def _phase_measurement(
    phase: str,
    database_files: list[dict[str, object]],
) -> dict[str, object]:
    database_bytes = sum(int(item["logical_bytes"]) for item in database_files)
    return {
        "record_type": "SaturationPhaseStorageMeasurement",
        "phase": phase,
        "database_file_count": len(database_files),
        "database_files": database_files,
        "database_logical_bytes": database_bytes,
        "journal_checkpoint_logical_bytes": 1_275,
        "runtime_derived_checkpoint_logical_bytes": 123_269_120,
        "observed_control_storage_bytes": database_bytes + 1_275,
    }


def _r5_checkpoint_tail() -> list[dict[str, object]]:
    writes = {
        1_127: 86_302_720,
        1_205: 92_459_008,
        1_283: 98_619_392,
        1_361: 104_783_872,
        1_439: 110_944_256,
        1_517: 117_108_736,
        1_595: 123_269_120,
    }
    result: list[dict[str, object]] = []
    runtime_checkpoint_bytes = 80_134_144
    database_start = 534_994_944
    database_growth = 795_394_048 - database_start
    for sequence in range(1_093, 1_605):
        written = sequence in writes
        if written:
            runtime_checkpoint_bytes = writes[sequence]
        database_bytes = database_start + (
            database_growth * (sequence - 1_093) // (1_604 - 1_093)
        )
        checkpoint_bytes = writes.get(sequence, 0)
        result.append(
            {
                "sequence": sequence,
                "phase": "physical-relation-corpus",
                "operation_sequence": sequence,
                "checkpoint_written": written,
                "runtime_checkpoint_bytes": checkpoint_bytes,
                "physical_payload_bytes": 1_425_000 + checkpoint_bytes,
                "database_logical_bytes": database_bytes,
                "journal_checkpoint_logical_bytes": 1_275,
                "runtime_derived_checkpoint_logical_bytes": runtime_checkpoint_bytes,
                "observed_control_storage_bytes": database_bytes + 1_275,
                "free_bytes_by_volume": [198_000_000_000],
            }
        )
    return result


def _r5_failure_receipt() -> dict[str, object]:
    event_identity = {
        "path": (
            ".promin/state/events/derived-index/generation/"
            "event-identities.sqlite3"
        ),
        "logical_bytes": 34_562_048,
    }
    state_binding = {
        "path": (
            ".promin/state/events/derived-index/generation/"
            "state-binding.sqlite3"
        ),
        "logical_bytes": 637_562_880,
    }
    derived_rows = {
        "path": ".promin/state/events/derived-rows/runtime.sqlite3",
        "logical_bytes": 123_269_120,
    }
    projection = {
        "path": ".promin/state/projection/promin.sqlite3",
        "logical_bytes": 378_454_016,
    }
    semantic_files = [event_identity, state_binding, derived_rows]
    early_files = [
        {**event_identity, "logical_bytes": 12_288},
        {**state_binding, "logical_bytes": 12_288},
    ]
    tail = _r5_checkpoint_tail()
    storage = _binding(
        {
            "phase_measurements": [
                _phase_measurement("preflight", []),
                _phase_measurement("physical-generation", early_files),
                _phase_measurement("inventory", early_files),
                _phase_measurement("semantic-ingestion", semantic_files),
                _phase_measurement("projection", [*semantic_files, projection]),
            ],
            "commit_checkpoint_count": 1_604,
            "commit_checkpoint_digest": "c" * 64,
            "commit_checkpoint_tail": tail,
        }
    )
    body: dict[str, object] = {
        "schema": "promin.saturation-failure.v1",
        "record_type": "SaturationFailure",
        "status": "rejected",
        "failure_code": "saturation-rejected",
        "reason": "controlled post-projection query rejection",
        "exception_type": "SaturationError",
        "started_at": "2026-08-12T05:38:18Z",
        "completed_at": "2026-08-12T09:06:30Z",
        "saturation_result_written": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "public_release_approved": False,
        "workload": {
            "physical_files": 100_000,
            "runtime_queries": 600,
            "core_valid_relations": 198_999,
            "performance_profile": "portable-local-v1",
            "performance_contract_digest": "a" * 64,
            "reuse_product": False,
            "workload_reduced": False,
        },
        "archive_binding": _binding(
            {
                "available": True,
                "name": "promin-1.0.0-alpha.4-heavy-verified-r5.zip",
                "bytes": 8_935_870,
                "sha256": "1" * 64,
            }
        ),
        "tool_binding": _binding(
            {
                "path": "tools/promin_saturation.py",
                "bytes": 200_000,
                "sha256": "2" * 64,
            }
        ),
        "storage": storage,
        "workspace": {
            "path": "D:/ProminValidation/synthetic-r5/workspace",
            "exists": True,
            "preservation_verified": False,
        },
    }
    return {**body, "receipt_digest": digest_value(body)}


def _write_receipt(path: Path) -> Path:
    path.write_bytes(canonical_bytes(_r5_failure_receipt()))
    return path


def _journal_checkpoint() -> dict[str, object]:
    body: dict[str, object] = {
        "record_type": "DerivedJournalCheckpoint",
        "version": 3,
        "authoritative": False,
        "batch_count": 1_604,
        "event_count": 200_603,
        "state_binding_update_count": 200_603,
        "head": {
            "sequence": 1_604,
            "batch_id": "b:" + "3" * 48,
            "batch_digest": "4" * 64,
        },
    }
    return {**body, "checkpoint_digest": digest_value(body)}


def _operation_metrics() -> dict[str, object]:
    observations: list[dict[str, object]] = []
    for sequence in range(1, 54):
        written = sequence == 35
        observations.append(
            {
                "sequence": sequence,
                "phase": (
                    "semantic-corpus"
                    if sequence <= 37
                    else "physical-relation-corpus"
                ),
                "checkpoint_written": written,
                "checkpoint_bytes": 1_250_000 if written else 0,
                "physical_payload_bytes": 1_280_000 if written else 30_000,
                "duration_ms": 20.0 if written else 2.0,
            }
        )
    semantic = {
        "commit_count": 53,
        "changed_records": 2_043,
        "elapsed_seconds": 42.0,
        "observations": observations,
        "result_digest": digest_value(observations),
    }
    return {
        "record_type": "SaturationOperationMetrics",
        "product_acceptance_credit": False,
        "status": "fail",
        "physical": {"files": 1_000},
        "projection": {
            "initial_inventory_passes": 1,
            "rebuild_inventory_passes": 1,
            "entity_count": 1_053,
            "relation_count": 1_990,
            "database_bytes": 3_784_540,
            "elapsed_ms": 1_200,
        },
        "semantic_ingestion": semantic,
    }


def _prediction(report: dict[str, object], files: int) -> dict[str, object]:
    predictions = report["predictions"]
    assert isinstance(predictions, list)
    return next(item for item in predictions if item["physical_files"] == files)


def test_r5_fixture_models_deterministic_1k_10k_100k_without_credit(
    tmp_path: Path,
) -> None:
    receipt = _write_receipt(tmp_path / "saturation-failure.json")

    first = performance_model.build_performance_model(receipt_path=receipt)
    second = performance_model.build_performance_model(receipt_path=receipt)

    assert first == second
    assert first["schema"] == "promin.performance-complexity-model.v1"
    assert first["status"] == "diagnostic-model"
    assert first["claims"] == NO_CLAIMS
    assert first["thresholds_evaluated"] is False
    sealed = dict(first)
    model_digest = sealed.pop("model_digest")
    assert model_digest == digest_value(sealed)
    assert [item["physical_files"] for item in first["predictions"]] == [
        1_000,
        10_000,
        100_000,
    ]

    at_100k = _prediction(first, 100_000)
    metrics = at_100k["metrics"]
    assert at_100k["claims"] == NO_CLAIMS
    assert metrics["core_valid_relations"]["value"] == 198_999
    assert metrics["semantic_commits"]["value"] == 1_604
    assert metrics["state_binding_updates"]["value"] == 200_603
    assert metrics["state_binding_select_statements"]["value"] == 4_812
    assert metrics["projection_entities"]["value"] == 101_604
    assert metrics["projection_rebuilds"]["value"] == 2
    assert metrics["projection_rows_processed"]["value"] == 601_206
    assert metrics["runtime_checkpoint_writes"]["value"] == 21
    assert metrics["event_identity_database_bytes"]["value"] == 34_562_048
    assert metrics["state_binding_database_bytes"]["value"] == 637_562_880
    assert metrics["derived_rows_database_bytes"]["value"] == 123_269_120
    assert metrics["projection_database_bytes"]["value"] == 378_454_016
    assert metrics["semantic_commits"]["classification"] == "derived"
    assert metrics["runtime_checkpoint_bytes"]["classification"] == "estimated"

    tail = first["observed_checkpoint_tail"]
    assert tail["checkpoint_write_sequences"]["value"] == [
        1_127,
        1_205,
        1_283,
        1_361,
        1_439,
        1_517,
        1_595,
    ]
    assert tail["checkpoint_cadence_commits"]["value"] == 78
    assert tail["checkpoint_cadence_commits"]["classification"] == "observed"
    assert 0.0 < tail["checkpoint_payload_share"]["value"] < 1.0
    assert first["complexity"]["runtime_checkpoint_bytes"]["order"] == (
        "O(N^2 / B)"
    )


def test_sql_statement_geometry_is_derived_from_frozen_eventstore_source(
    tmp_path: Path,
) -> None:
    source = PACKAGE_ROOT / "promin" / "events.py"
    geometry = performance_model.derive_state_binding_sql_geometry(source)

    assert geometry["source"]["sha256"]
    assert geometry["source"]["classification"] == "source-derived"
    assert geometry["normal_path"] == {
        "binding_helper_calls_per_commit": 2,
        "node_union_helper_calls_per_commit": 1,
        "legacy_depth_range_helper_calls_per_commit": 0,
        "binding_select_statements_per_commit": 2,
        "node_union_select_statements_per_commit": 1,
        "select_statements_per_commit": 3,
        "storage_mode_pragma_statements_per_commit": 2,
    }
    assert geometry["derivation"]["pragma_excluded_from_select_count"] is True

    report = performance_model.build_performance_model(
        receipt_path=_write_receipt(tmp_path / "saturation-failure.json"),
    )
    assert report["algorithm_source"]["sha256"] == geometry["source"]["sha256"]
    assert report["algorithm_shape"][
        "state_binding_select_statements_per_commit"
    ] == geometry["normal_path"]["select_statements_per_commit"]


def test_bound_phase_log_and_journal_checkpoint_supply_observed_metrics(
    tmp_path: Path,
) -> None:
    receipt = _write_receipt(tmp_path / "saturation-failure.json")
    phase_log = tmp_path / "phase-log.jsonl"
    phase_rows = [
        {
            "order": 3,
            "phase": "semantic-ingestion",
            "status": "completed",
            "elapsed_ms": 6_903_000,
        },
        {
            "order": 4,
            "phase": "projection",
            "status": "completed",
            "elapsed_ms": 120_000,
        },
    ]
    phase_log.write_bytes(b"".join(canonical_bytes(row) for row in phase_rows))
    checkpoint_path = tmp_path / "journal-checkpoint.json"
    checkpoint_path.write_bytes(canonical_bytes(_journal_checkpoint()))

    report = performance_model.build_performance_model(
        receipt_path=receipt,
        phase_artifact_paths=[phase_log, checkpoint_path],
    )

    baseline = report["baseline"]["metrics"]
    assert baseline["semantic_commits"] == {
        "value": 1_604,
        "classification": "observed",
        "basis": "bound DerivedJournalCheckpoint batch_count",
    }
    assert baseline["state_binding_updates"] == {
        "value": 200_603,
        "classification": "observed",
        "basis": "bound DerivedJournalCheckpoint state_binding_update_count",
    }
    assert baseline["semantic_ingestion_seconds"]["value"] == 6_903.0
    assert baseline["semantic_ingestion_seconds"]["classification"] == "observed"
    assert baseline["projection_seconds"]["value"] == 120.0
    assert [source["integrity"]["classification"] for source in report["sources"]] == [
        "self-sealed",
        "sha256-bound-only",
        "self-sealed",
    ]
    at_10k = _prediction(report, 10_000)["metrics"]
    assert at_10k["semantic_ingestion_seconds"]["classification"] == "estimated"
    assert at_10k["semantic_ingestion_seconds"]["value"] > 0
    assert report["claims"] == NO_CLAIMS


def test_receipt_or_supplemental_digest_tampering_is_rejected(tmp_path: Path) -> None:
    receipt_value = _r5_failure_receipt()
    receipt_value["reason"] = "tampered after sealing"
    receipt = tmp_path / "saturation-failure.json"
    receipt.write_bytes(canonical_bytes(receipt_value))

    with pytest.raises(
        performance_model.PerformanceModelError,
        match="receipt_digest",
    ):
        performance_model.build_performance_model(receipt_path=receipt)

    valid_receipt = _write_receipt(tmp_path / "valid-saturation-failure.json")
    checkpoint = _journal_checkpoint()
    checkpoint["event_count"] = 200_602
    checkpoint_path = tmp_path / "journal-checkpoint.json"
    checkpoint_path.write_bytes(canonical_bytes(checkpoint))
    with pytest.raises(
        performance_model.PerformanceModelError,
        match="checkpoint_digest",
    ):
        performance_model.build_performance_model(
            receipt_path=valid_receipt,
            phase_artifact_paths=[checkpoint_path],
        )


def test_bound_operation_metrics_can_form_a_phase_artifact_only_model(
    tmp_path: Path,
) -> None:
    operation_path = tmp_path / "operation-metrics.json"
    operation_path.write_bytes(canonical_bytes(_operation_metrics()))

    report = performance_model.build_performance_model(
        phase_artifact_paths=[operation_path]
    )

    assert report["sources"][0]["integrity"]["classification"] == (
        "nested-digest-verified"
    )
    assert report["baseline"]["physical_files"] == 1_000
    assert report["baseline"]["metrics"]["core_valid_relations"]["value"] == 1_990
    assert report["baseline"]["metrics"]["semantic_commits"]["value"] == 53
    assert report["baseline"]["metrics"]["state_binding_updates"]["value"] == 2_043
    assert _prediction(report, 1_000)["metrics"]["projection_entities"]["value"] == 1_053
    assert report["claims"] == NO_CLAIMS


def test_cli_writes_the_same_canonical_claim_free_model(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    receipt = _write_receipt(tmp_path / "saturation-failure.json")
    output = tmp_path / "performance-model.json"

    exit_code = performance_model.main(
        [
            "--receipt",
            str(receipt),
            "--targets",
            "1000,10000,100000",
            "--output",
            str(output),
        ]
    )

    assert exit_code == 0
    emitted = capsys.readouterr().out.encode("utf-8")
    assert emitted == output.read_bytes()
    parsed = json.loads(emitted)
    assert parsed["claims"] == NO_CLAIMS
    assert parsed["model_digest"]
