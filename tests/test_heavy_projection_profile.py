from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from promin.canonical import canonical_bytes
from promin.projection import Projection
from tools import promin_projection_profile as profile


def _tiny_public_projection_profile(tmp_path: Path) -> dict:
    """Exercise instrumentation without claiming a fixed-size benchmark run."""

    contracts = profile._compile_runtime_contracts()
    inventory, inventory_manifest = profile._build_inventory_stream(tmp_path, 16)
    assert inventory_manifest["entry_count"] == 16
    store, event_manifest = profile._build_event_stream(tmp_path, 16, contracts)
    assert event_manifest["event_count"] == 16
    projection = Projection(
        tmp_path / "projection" / "promin.sqlite3",
        profile.TOKEN_KEY,
        implementation_closure_digest=profile.IMPLEMENTATION_CLOSURE_DIGEST,
        limits=contracts.projection_limits,
        relation_domains=contracts.relation_domains,
    )
    try:
        return profile.profile_projection_rebuild(projection, store, inventory)
    finally:
        store.close()


def _profile_projection(
    tmp_path: Path,
    *,
    size: int,
) -> tuple[object, Projection]:
    """Build one disposable public projection for hot-path behavior checks."""

    contracts = profile._compile_runtime_contracts()
    inventory, _inventory_manifest = profile._build_inventory_stream(tmp_path, size)
    store, _event_manifest = profile._build_event_stream(tmp_path, size, contracts)
    projection = Projection(
        tmp_path / "projection" / "promin.sqlite3",
        profile.TOKEN_KEY,
        implementation_closure_digest=profile.IMPLEMENTATION_CLOSURE_DIGEST,
        limits=contracts.projection_limits,
        relation_domains=contracts.relation_domains,
    )
    projection.rebuild(store, inventory=inventory)
    return store, projection


def _resume_binding(projection: Projection) -> dict[str, str]:
    return {
        field: f"profile-readonly-{index}"
        for index, field in enumerate(projection.limits.required_resume_binding_fields)
    }


def test_complete_first_search_uses_only_a_read_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A complete first page has no continuation state to persist."""

    store, projection = _profile_projection(tmp_path, size=1)
    try:
        def unexpected_mutable_connection() -> None:
            raise AssertionError("complete first search opened a mutable connection")

        monkeypatch.setattr(
            projection,
            "_connect_mutable",
            unexpected_mutable_connection,
        )

        result = projection.search("synthetic", resume_binding=_resume_binding(projection))

        assert result["truncated"] is False
        assert result["continuation"] is None
        assert len(result["entities"]) == 1
    finally:
        store.close()


def test_truncated_first_search_persists_its_continuation_after_read_probe(
    tmp_path: Path,
) -> None:
    """A first page becomes mutable only when it has resumable state to write."""

    store, projection = _profile_projection(tmp_path, size=16)
    try:
        binding = _resume_binding(projection)
        first = projection.search("synthetic", resume_binding=binding)

        assert first["truncated"] is True
        assert first["continuation"] is not None

        continued = projection.continue_search(
            first["continuation"]["token"],
            resume_binding=binding,
        )

        assert continued["stream_cursor"] == first["next_stream_cursor"]
        assert continued["head_digest"] == first["head_digest"]
    finally:
        store.close()


def test_incremental_reads_relation_does_not_rescan_dependency_dag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only DEPENDS_ON mutations can invalidate the dependency-cycle proof."""

    store, projection = _profile_projection(tmp_path, size=16)
    try:
        head = store.head()["batch_digest"]
        task = profile._task(2, head)
        store.commit(
            profile._command(2, task, head),
            auxiliary_relations=(
                profile._relation(
                    99_999,
                    source_id=task["task_id"],
                    target_index=0,
                ),
            ),
            created_at=profile.CREATED_AT,
        )

        def unexpected_dependency_scan(_connection: object) -> None:
            raise AssertionError("READS-only batch rescanned DEPENDS_ON graph")

        monkeypatch.setattr(
            Projection,
            "_validate_dependency_graph_acyclic",
            staticmethod(unexpected_dependency_scan),
        )

        result = projection.apply_committed_batch(store)

        assert result["status"] == "updated"
        assert result["changed_records"] == 2
        assert projection.require_current(store)["head_sequence"] == store.head()["sequence"]
    finally:
        store.close()


def test_incremental_dependency_relation_still_validates_acyclicity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A DEPENDS_ON mutation keeps the exact acyclicity validation boundary."""

    store, projection = _profile_projection(tmp_path, size=16)
    try:
        head = store.head()["batch_digest"]
        task = profile._task(2, head)
        dependency = {
            **profile._relation(
                100_000,
                source_id=task["task_id"],
                target_index=0,
            ),
            "kind": "DEPENDS_ON",
            "target_type": "Task",
            "target_id": "task:projection-profile:00000001",
        }
        store.commit(
            profile._command(2, task, head),
            auxiliary_relations=(dependency,),
            created_at=profile.CREATED_AT,
        )
        calls: list[tuple[object, ...]] = []
        original = Projection._validate_dependency_graph_acyclic

        def observe_dependency_scan(connection: object) -> None:
            calls.append(())
            original(connection)

        monkeypatch.setattr(
            Projection,
            "_validate_dependency_graph_acyclic",
            staticmethod(observe_dependency_scan),
        )

        result = projection.apply_committed_batch(store)

        assert result["status"] == "updated"
        assert calls == [()]
        assert projection.require_current(store)["head_sequence"] == store.head()["sequence"]
    finally:
        store.close()


def test_projection_profiler_uses_real_public_rebuild_and_reports_raw_metrics(
    tmp_path: Path,
) -> None:
    measured = _tiny_public_projection_profile(tmp_path)

    assert measured["claim"] is False
    assert measured["pass_credit"] is False
    assert measured["rebuild_seam"] == {
        "name": "Projection.rebuild",
        "public_method": True,
        "implementation_replaced": False,
        "sqlite_trace_observational": True,
    }

    for rebuild in (measured["first"], measured["second"]):
        assert rebuild["claim"] is False
        assert rebuild["pass_credit"] is False
        assert rebuild["public_result"]["event_count"] == 16
        assert rebuild["public_result"]["inventory_entries"] == 16
        assert rebuild["public_result"]["inventory_passes"] == 1
        assert rebuild["public_result"]["product_passes"] == 0

        phase = rebuild["phase_metrics"]
        assert phase["wall_ns"] > 0
        assert phase["cpu_ns"] > 0
        assert phase["rss_sample_count"] >= 0
        assert "rss_peak_bytes" in phase
        assert "rss_incremental_peak_bytes" in phase
        if os.name == "nt":
            assert phase["rss_supported"] is True
            assert phase["rss_peak_bytes"] > 0

        trace = rebuild["sqlite_trace"]
        assert trace["statement_count"] > 32
        assert trace["connection_total_changes"] > 32
        assert trace["semantic_row_write_statements"] >= 1
        assert trace["semantic_shard_recomputations"] == 256
        assert trace["semantic_shard_unique_count"] == 256
        assert trace["semantic_shard_min"] == 0
        assert trace["semantic_shard_max"] == 255
        assert trace["semantic_shard_full_coverage_observed"] is True
        assert trace["statements_by_operation"]["INSERT"] > 32

        database = rebuild["sqlite_database"]
        assert database["independent_readback_connection"] is True
        assert database["file_bytes"] > 0
        assert database["allocated_page_bytes"] == (
            database["page_size_bytes"] * database["page_count"]
        )
        assert database["used_page_bytes"] <= database["allocated_page_bytes"]
        assert database["row_counts"]["entities"] == 18
        assert database["row_counts"]["relations"] == 14
        assert database["row_counts"]["operational_order"] == 2
        assert database["row_counts"]["semantic_rows"] == 32
        assert database["row_counts"]["semantic_shards"] == 256
        assert database["metadata"]["semantic_digest"] == rebuild[
            "public_result"
        ]["semantic_digest"]

    comparison = measured["comparison"]
    assert comparison["row_counts_equal"] is True
    assert comparison["semantic_digest_equal"] is True
    assert comparison["readback_semantic_digest_equal"] is True
    assert comparison["first_public_digest_matches_readback"] is True
    assert comparison["second_public_digest_matches_readback"] is True
    assert comparison["entity_count_equal"] is True
    assert comparison["relation_count_equal"] is True
    assert comparison["observational_only"] is True
    assert comparison["performance_claim"] is False
    assert comparison["pass_credit"] is False
    assert comparison["wall_second_over_first"] is not None
    assert comparison["cpu_second_over_first"] is not None


def test_inventory_fixture_is_canonical_persisted_jsonl(tmp_path: Path) -> None:
    inventory, manifest = profile._build_inventory_stream(tmp_path, 16)
    assert inventory.stream_path is not None
    lines = inventory.stream_path.read_bytes().splitlines(keepends=True)

    assert len(lines) == 16
    assert sum(map(len, lines)) == manifest["stream_bytes"]
    assert all(canonical_bytes(json.loads(line)) == line for line in lines)
    assert [json.loads(line)["path"] for line in lines] == sorted(
        json.loads(line)["path"] for line in lines
    )


def test_only_fixed_profile_sizes_can_produce_benchmark_reports(
    tmp_path: Path,
) -> None:
    assert profile.FIXED_PROFILE_SIZES == (1_000, 4_000, 10_000)

    with pytest.raises(profile.ProfileError, match="profile size must be one of"):
        profile.run_profile_case(tmp_path / "rejected", 999)
    with pytest.raises(SystemExit):
        profile._parser().parse_args(["--size", "100000"])


def test_service_adapter_fails_closed_before_non_service_rebuild() -> None:
    with pytest.raises(
        profile.ProfileError,
        match="requires a ProminService instance",
    ):
        profile.profile_service_rebuild(object(), None)
