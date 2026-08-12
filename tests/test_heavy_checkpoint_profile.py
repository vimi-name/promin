"""Focused checks for the bounded, claim-free checkpoint profiler."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = PACKAGE_ROOT / "tools" / "promin_checkpoint_profile.py"
SPEC = importlib.util.spec_from_file_location("promin_checkpoint_profile", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
profile = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = profile
SPEC.loader.exec_module(profile)


CLAIM_FIELDS = {
    "claim",
    "pass_credit",
    "acceptance_pass",
    "product_acceptance_pass",
    "performance_acceptance",
    "release_eligible",
}


def _assert_no_credit(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in CLAIM_FIELDS:
                assert item is False
            _assert_no_credit(item)
    elif isinstance(value, list):
        for item in value:
            _assert_no_credit(item)


def test_default_workload_is_bounded_and_covers_checkpoint_and_batch_boundaries() -> None:
    assert profile.DEFAULT_ROW_COUNTS == (1_000, 10_000, 20_000)
    assert profile.DEFAULT_BATCH_SIZES == (1, 2, 127, 128)
    assert max(profile.DEFAULT_ROW_COUNTS) == profile.MAX_PROFILE_ROWS == 20_000
    assert 199_000 not in profile.DEFAULT_ROW_COUNTS
    assert profile.MAX_CADENCE_BATCHES == 128


@pytest.mark.performance
def test_real_eventstore_profile_measures_rows_pages_resources_and_policy_boundary(
    tmp_path: Path,
) -> None:
    report = profile.build_profile(
        tmp_path / "work",
        row_counts=(8, 16),
        batch_sizes=(1, 2, 127, 128),
        cadence_max_batches=1,
    )

    assert report["schema"] == profile.PROFILE_SCHEMA
    assert report["status"] == "diagnostic-complete"
    assert report["configuration"] == {
        "relation_row_counts": [8, 16],
        "relation_batch_sizes": [1, 2, 127, 128],
        "cadence_max_batches": 1,
        "full_requested_batch_boundary_selected": True,
        "workload_bounded": True,
    }
    assert report["scope"] == {
        "route": "eventstore-supported-normalized-derived-row-diagnostic",
        "normalized_relation_section": "40.relations.records",
        "eventstore_commit_exercised": True,
        "eventstore_state_binding_exercised": True,
        "eventstore_tail_compaction_exercised": True,
        "eventstore_sqlite_checkpoint_exercised": True,
        "promin_service_authorization_exercised": False,
        "full_runtime_checkpoint_reconstruction_exercised": False,
        "diagnostic_only": True,
    }
    assert report["policy"]["max_events_per_batch"] == 128
    assert report["policy"]["max_relations_per_task_batch"] == 127

    cardinality = report["checkpoint_cardinality"]
    assert [item["relation_rows"] for item in cardinality] == [8, 16]
    assert [item["rows_written"] for item in cardinality] == [8, 16]
    for item in cardinality:
        assert item["status"] == "diagnostic-observed"
        assert item["authoritative"] is False
        assert item["normalized_section"] == "40.relations.records"
        assert item["logical_row_bytes"] > 0
        assert item["physical_database_bytes"] > 0
        assert item["sqlite"]["rows"] == item["rows_written"]
        assert item["sqlite"]["page_count"] >= 3
        assert item["sqlite"]["page_size_bytes"] > 0
        assert (
            item["sqlite"]["allocated_page_bytes"]
            == item["sqlite"]["page_count"] * item["sqlite"]["page_size_bytes"]
        )
        measurement = item["measurement"]
        assert measurement["wall_seconds"] >= 0
        assert measurement["cpu_seconds"] >= 0
        assert measurement["rss_source"] in {
            "windows-process-memory-counters",
            "linux-proc-status",
            "resource-rusage-peak",
            "unavailable",
        }
        assert measurement["rss_after_bytes"] is None or measurement["rss_after_bytes"] > 0

    lanes = {
        item["relation_batch_size"]: item
        for item in report["batch_boundary_and_compaction"]
    }
    for batch_size in (1, 2, 127):
        lane = lanes[batch_size]
        assert lane["admitted"] is True
        assert lane["total_events_per_admitted_batch"] == batch_size + 1
        assert lane["commits_observed"] == 1
        assert lane["relations_committed"] == batch_size
        assert lane["compaction_cadence"]["observed"] is False
        assert lane["compaction_cadence"]["tail_batches"] == 1
        assert lane["compaction_cadence"]["tail_bytes"] > 0
    rejected = lanes[128]
    assert rejected["status"] == "policy-rejected"
    assert rejected["admitted"] is False
    assert rejected["total_events_attempted"] == 129
    assert rejected["head_unchanged"] is True
    assert rejected["rejection_type"] == "EventStoreError"
    assert rejected["rejection_reason"] == "atomic batch exceeds the event ceiling"
    assert rejected["compaction_cadence"] is None
    _assert_no_credit(report)


def test_cardinality_rewrites_one_normalized_sqlite_checkpoint_file(
    tmp_path: Path,
) -> None:
    work = tmp_path / "work"
    report = profile.build_profile(
        work,
        row_counts=(4, 32),
        batch_sizes=(128,),
        cadence_max_batches=1,
    )

    observations = report["checkpoint_cardinality"]
    assert observations[1]["logical_row_bytes"] > observations[0]["logical_row_bytes"]
    assert (
        observations[1]["physical_database_bytes"]
        >= observations[0]["physical_database_bytes"]
    )
    derived_root = work / "cardinality-events" / "derived-rows"
    sqlite_files = list(derived_root.glob("*.sqlite3"))
    assert len(sqlite_files) == 1
    assert sqlite_files[0].stat().st_size == observations[-1]["physical_database_bytes"]
    _assert_no_credit(report)


@pytest.mark.parametrize(
    ("value", "label", "maximum", "strict", "message"),
    (
        ("1,1", "row counts", 20_000, True, "duplicates"),
        ("2,1", "row counts", 20_000, True, "strictly increasing"),
        ("20001", "row counts", 20_000, True, "1 through 20000"),
        ("0", "batch sizes", 128, False, "1 through 128"),
        ("129", "batch sizes", 128, False, "1 through 128"),
    ),
)
def test_cli_integer_contract_rejects_unbounded_or_ambiguous_inputs(
    value: str,
    label: str,
    maximum: int,
    strict: bool,
    message: str,
) -> None:
    with pytest.raises(profile.CheckpointProfileError, match=message):
        profile.parse_positive_integers(
            value,
            label=label,
            maximum=maximum,
            strictly_increasing=strict,
        )


def test_work_root_and_output_are_create_only(tmp_path: Path) -> None:
    existing_work = tmp_path / "existing-work"
    existing_work.mkdir()
    with pytest.raises(profile.CheckpointProfileError, match="must not already exist"):
        profile.build_profile(
            existing_work,
            row_counts=(1,),
            batch_sizes=(128,),
            cadence_max_batches=1,
        )

    output = tmp_path / "profile.json"
    report = {"record_type": "CheckpointProfileDiagnostic", **profile._claims()}
    profile._write_report(output, report)
    original = output.read_bytes()
    with pytest.raises(profile.CheckpointProfileError, match="already exists"):
        profile._write_report(output, report)
    assert output.read_bytes() == original
