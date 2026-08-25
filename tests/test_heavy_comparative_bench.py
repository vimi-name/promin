"""Focused contract checks for the claim-free comparative benchmark harness."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


PACKAGE_ROOT = Path(__file__).parents[1]
BENCH_PATH = PACKAGE_ROOT / "tools" / "promin_comparative_bench.py"
SPEC = importlib.util.spec_from_file_location("promin_comparative_bench", BENCH_PATH)
assert SPEC is not None and SPEC.loader is not None
bench = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bench
SPEC.loader.exec_module(bench)


def _config(**changes: object):
    values: dict[str, object] = {
        "sizes": (1, 2, 3),
        "warmup_runs": 0,
        "measured_runs": 1,
        "sampling_interval_ms": 5,
        "scenarios": ("empty",),
        "operations": ("query",),
    }
    values.update(changes)
    return bench.BenchmarkConfig(**values)


def test_plan_is_explicitly_unexecuted_and_never_claims_acceptance() -> None:
    plan = bench.build_plan(
        bench.BenchmarkConfig(
            sizes=(16, 64, 256),
            warmup_runs=1,
            measured_runs=3,
            sampling_interval_ms=5,
            scenarios=("promin", "markdown", "empty"),
            operations=("init", "update", "query", "docs"),
        )
    )
    assert plan["schema"] == "promin.comparative-benchmark.v1"
    assert plan["execution"] == {
        "performed": False,
        "status": "planned",
        "full_comparison_scope_selected": True,
        "expected_bucket_count": 72,
        "reason": "Use --execute to collect host-local evidence; planned output has no measurements.",
    }
    assert plan["results"] == []
    assert plan["scaling_checks"] == []
    assert plan["claim"] is False
    assert plan["pass_credit"] is False
    assert plan["acceptance_pass"] is False
    assert plan["product_acceptance_pass"] is False


def test_full_scope_classification_requires_exact_fixed_sizes() -> None:
    full_report = bench.build_plan(
        bench.BenchmarkConfig(
            sizes=(16, 64, 256),
            warmup_runs=1,
            measured_runs=3,
            sampling_interval_ms=5,
            scenarios=("promin", "markdown", "empty"),
            operations=("init", "update", "query", "docs"),
        )
    )
    expanded_report = bench.build_plan(
        bench.BenchmarkConfig(
            sizes=(16, 64, 256, 512),
            warmup_runs=1,
            measured_runs=3,
            sampling_interval_ms=5,
            scenarios=("promin", "markdown", "empty"),
            operations=("init", "update", "query", "docs"),
        )
    )

    assert full_report["execution"]["full_comparison_scope_selected"] is True
    assert full_report["execution"]["expected_bucket_count"] == 72
    assert expanded_report["execution"]["full_comparison_scope_selected"] is False
    assert expanded_report["execution"]["expected_bucket_count"] == 96


def test_expected_bucket_keys_match_independent_fixed_scope_cartesian_product() -> None:
    full_config = bench.BenchmarkConfig(
        sizes=(16, 64, 256),
        warmup_runs=1,
        measured_runs=3,
        sampling_interval_ms=5,
        scenarios=("promin", "markdown", "empty"),
        operations=("init", "update", "query", "docs"),
    )
    expected = frozenset(
        (scenario, operation, temperature, size)
        for scenario in ("promin", "markdown", "empty")
        for operation in ("init", "update", "query", "docs")
        for temperature in ("cold", "warm")
        for size in (16, 64, 256)
    )

    actual = bench.expected_bucket_keys(full_config)
    assert actual == expected
    assert len(actual) == 72
    assert all(
        len(key) == 4
        and isinstance(key[0], str)
        and isinstance(key[1], str)
        and isinstance(key[2], str)
        and isinstance(key[3], int)
        for key in actual
    )


def test_bucket_closure_accepts_exact_unique_result_keys() -> None:
    config = _config(scenarios=("empty",), operations=("query",))
    expected = bench.expected_bucket_keys(config)
    results = [
        {"scenario": scenario, "operation": operation, "temperature": temperature, "size": size}
        for scenario, operation, temperature, size in expected
    ]

    closure = bench.result_key_closure(expected, results)

    assert closure["complete"] is True
    assert closure["claim"] is False
    assert closure["pass_credit"] is False
    assert closure["expected_bucket_count"] == 6
    assert closure["observed_bucket_count"] == 6
    assert closure["unique_bucket_count"] == 6
    assert closure["missing"] == []
    assert closure["unexpected"] == []
    assert closure["duplicate"] == []


@pytest.mark.parametrize(
    ("mutation", "expected_missing", "expected_unexpected", "expected_duplicate"),
    (
        (lambda results: results[:-1], 1, 0, 0),
        (lambda results: results[:-1] + [results[0]], 1, 0, 1),
        (lambda results: results + [{"scenario": "promin", "operation": "init", "temperature": "cold", "size": 999}], 0, 1, 0),
    ),
)
def test_bucket_closure_rejects_incomplete_or_nonunique_result_keys(
    mutation,
    expected_missing: int,
    expected_unexpected: int,
    expected_duplicate: int,
) -> None:
    config = _config(scenarios=("empty",), operations=("query",))
    expected = bench.expected_bucket_keys(config)
    results = [
        {"scenario": scenario, "operation": operation, "temperature": temperature, "size": size}
        for scenario, operation, temperature, size in expected
    ]

    closure = bench.result_key_closure(expected, mutation(results))

    assert closure["complete"] is False
    assert closure["claim"] is False
    assert closure["pass_credit"] is False
    assert closure["missing_count"] == expected_missing
    assert closure["unexpected_count"] == expected_unexpected
    assert closure["duplicate_count"] == expected_duplicate


def test_bucket_closure_ignores_malformed_keys_for_completion() -> None:
    config = _config(scenarios=("empty",), operations=("query",))
    expected = bench.expected_bucket_keys(config)
    results = [
        {"scenario": scenario, "operation": operation, "temperature": temperature, "size": size}
        for scenario, operation, temperature, size in expected
    ]
    results[-1] = {"scenario": "empty", "operation": "query", "temperature": "cold", "size": True}

    closure = bench.result_key_closure(expected, results)

    assert closure["complete"] is False
    assert closure["claim"] is False
    assert closure["pass_credit"] is False
    assert closure["observed_bucket_count"] == 6
    assert closure["unexpected_count"] == 0


def test_full_scope_factor_order_is_ignored_but_subsets_are_partial() -> None:
    reordered_full = bench.BenchmarkConfig(
        sizes=(16, 64, 256),
        scenarios=("empty", "promin", "markdown"),
        operations=("docs", "query", "init", "update"),
    )
    subset = bench.BenchmarkConfig(
        sizes=(16, 64, 256),
        scenarios=("promin", "markdown"),
        operations=("init", "update", "query", "docs"),
    )

    assert bench.build_plan(reordered_full)["execution"]["full_comparison_scope_selected"] is True
    assert bench.build_plan(subset)["execution"]["full_comparison_scope_selected"] is False


def test_sizes_require_three_strictly_increasing_workloads() -> None:
    assert bench.parse_sizes("1,2,3") == (1, 2, 3)
    with pytest.raises(bench.ComparativeBenchError, match="at least three"):
        bench.parse_sizes("1,2")
    with pytest.raises(bench.ComparativeBenchError, match="strictly increasing"):
        bench.parse_sizes("3,2,1")
    with pytest.raises(bench.ComparativeBenchError, match="strictly increasing"):
        bench.parse_sizes("1,1,2")


def test_percentile_and_scaling_check_use_observed_p95_without_pass_credit() -> None:
    assert bench.percentile([1.0, 10.0], 0.50) == 5.5
    results = [
        {
            "scenario": "promin",
            "operation": "query",
            "temperature": "cold",
            "size": size,
            "latency_ms": {"p50": value, "p95": value, "p99": value},
        }
        for size, value in ((1, 1.0), (2, 3.0), (4, 9.0))
    ]
    checks = bench.scaling_checks(results, sizes=(1, 2, 4))
    assert len(checks) == 1
    check = checks[0]
    assert check["status"] == "review-required"
    assert check["claim"] is False
    assert check["pass_credit"] is False
    assert all(interval["superlinear_indicator"] is True for interval in check["p95_intervals"])


def test_markdown_docs_case_measures_real_filesystem_work(tmp_path: Path) -> None:
    root = tmp_path / "markdown-docs"
    prepared = bench.prepare_case(root, scenario="markdown", operation="docs", size=2)
    result = bench.measure_case(root, scenario="markdown", operation="docs", size=2, sampling_interval_ms=5)
    assert prepared["storage_before"]["file_count"] == 3
    assert result["operation_result"] == {
        "route": "markdown-index",
        "status": "updated",
        "indexed_documents": 3,
        "index_bytes": result["operation_result"]["index_bytes"],
    }
    assert (root / "docs" / "INDEX.md").is_file()
    assert result["measurement"]["wall_ms"] >= 0
    assert result["measurement"]["cpu_ms"] >= 0
    assert result["storage_after"]["total_bytes"] > prepared["storage_before"]["total_bytes"]


def test_public_promin_route_refuses_to_turn_an_invalid_init_into_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "promin-init"
    root.mkdir()
    bench._seed_markdown_source(root, 1)
    activation = root / ".promin" / "init" / "activation.json"
    activation.parent.mkdir(parents=True)
    activation.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(bench, "_call_promin_cli", lambda _arguments: {"record_type": "Unexpected", "status": "ok"})
    with pytest.raises(bench.ComparativeBenchError, match="verified activation"):
        bench._promin_init(root, 1)


@pytest.mark.parametrize("record_type", ("InitializationResult", "InitResult"))
def test_public_promin_route_accepts_both_existing_init_result_envelopes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    record_type: str,
) -> None:
    root = tmp_path / record_type
    root.mkdir()
    bench._seed_markdown_source(root, 1)
    activation = root / ".promin" / "init" / "activation.json"
    activation.parent.mkdir(parents=True)
    activation.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        bench,
        "_call_promin_cli",
        lambda _arguments: {
            "record_type": record_type,
            "status": "created",
            "project_mode": "specification",
        },
    )
    result = bench._promin_init(root, 1)
    assert result == {
        "route": "promin-public-cli:init",
        "status": "created",
        "activation_present": True,
        "project_mode": "specification",
    }


def test_isolated_worker_resolves_the_checked_out_public_promin_init_route(tmp_path: Path) -> None:
    config = _config(scenarios=("promin",), operations=("init",))
    root = tmp_path / "promin-worker-init"
    with bench._WorkerClient() as worker:
        prepared = worker.request(
            bench._request_payload(
                root,
                action="prepare",
                scenario="promin",
                operation="init",
                size=1,
                config=config,
            )
        )
        measured = worker.request(
            bench._request_payload(
                root,
                action="measure",
                scenario="promin",
                operation="init",
                size=1,
                config=config,
            )
    )
    assert prepared["status"] == "ok"
    # A changing shared candidate can truthfully reject init (for example, an
    # implementation-closure drift).  That is evidence to retain, not a test
    # excuse to synthesize success.  What this regression test fixes is the
    # previous launcher shadow: ``tools/promin.py`` must never replace the
    # checked-out ``promin`` package in an isolated worker.
    assert measured["status"] in {"ok", "error"}
    if measured["status"] == "ok":
        sample = measured["sample"]
        assert sample["operation_result"]["route"] == "promin-public-cli:init"
        assert sample["operation_result"]["activation_present"] is True
        assert sample["storage_after"]["control_bytes"] > 0
    else:
        reason = str(measured.get("reason", ""))
        assert "No module named 'promin.__main__'" not in reason
        assert "'promin' is not a package" not in reason


def test_isolated_empty_run_emits_percentiles_rss_storage_and_scaling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # This is a micro smoke for metric serialization; fixed-scope execution is
    # covered separately and partial CLI execution is rejected by contract.
    monkeypatch.setattr(bench, "_require_fixed_execution_scope", lambda _config: None)
    report = bench.run_benchmark(_config(), fixture_root=tmp_path / "fixtures")
    assert report["claim"] is False
    assert report["pass_credit"] is False
    assert report["execution"]["performed"] is True
    assert report["execution"]["status"] == "completed"
    assert report["execution"]["all_samples_succeeded"] is True
    assert len(report["results"]) == 6  # three sizes x cold/warm
    assert len(report["scaling_checks"]) == 2
    for result in report["results"]:
        assert result["status"] == "measured"
        assert set(result["latency_ms"]) == {"p50", "p95", "p99"}
        assert set(result["cpu_ms"]) == {"p50", "p95", "p99"}
        assert set(result["storage_total_bytes"]) == {"p50", "p95", "p99"}
        sample = result["samples"][0]
        assert sample["measurement"]["rss"]["available"] in {True, False}
        assert sample["storage_after"] == {
            "file_count": 0,
            "total_bytes": 0,
            "markdown_bytes": 0,
            "control_bytes": 0,
        }


def test_fixed_execution_scope_is_exactly_the_72_bucket_public_route() -> None:
    config = bench.BenchmarkConfig(
        sizes=(16, 64, 256),
        scenarios=("promin", "markdown", "empty"),
        operations=("init", "update", "query", "docs"),
    )

    assert bench.fixed_full_scope_selected(config) is True
    assert len(bench.expected_bucket_keys(config)) == 72
    assert bench.FIXED_BUCKET_COUNT == 72
    assert bench._base_report(config, executed=True)["config"] == {
        "sizes": [16, 64, 256],
        "warmup_runs": 1,
        "measured_runs": 3,
        "sampling_interval_ms": 5,
        "scenarios": ["promin", "markdown", "empty"],
        "operations": ["init", "update", "query", "docs"],
        "temperatures": ["cold", "warm"],
        "execution_order": "sequential; no benchmark samples run concurrently",
        "fixed_workload": True,
        "fixed_bucket_count": 72,
    }


@pytest.mark.parametrize(
    "config",
    (
        _config(sizes=(1, 2, 3)),
        bench.BenchmarkConfig(
            sizes=(16, 64, 256),
            scenarios=("promin", "markdown"),
            operations=("init", "update", "query", "docs"),
        ),
        bench.BenchmarkConfig(
            sizes=(16, 64, 256),
            scenarios=("promin", "markdown", "empty"),
            operations=("init", "update", "query"),
        ),
    ),
)
def test_execution_rejects_a_partial_route_instead_of_silently_shrinking_workload(config) -> None:
    with pytest.raises(bench.ComparativeBenchError, match="fixed 72-bucket scope"):
        bench._require_fixed_execution_scope(config)


def test_cli_partial_execution_emits_failure_envelope_without_claims(tmp_path: Path) -> None:
    output = tmp_path / "partial.json"
    exit_code = bench.main(
        [
            "--execute",
            "--sizes",
            "1,2,3",
            "--scenarios",
            "empty",
            "--operations",
            "query",
            "--output",
            str(output),
        ]
    )
    failure = json.loads(output.read_text(encoding="utf-8"))
    assert exit_code == 2
    assert failure["schema"] == "promin.comparative-benchmark.v1"
    assert failure["record_type"] == "ProminComparativeBenchmarkFailure"
    assert failure["execution"] == {"performed": True, "status": "failed"}
    assert failure["claim"] is False
    assert failure["pass_credit"] is False
    assert failure["acceptance_pass"] is False
    assert "fixed 72-bucket scope" in failure["reason"]


def test_default_benchmark_contract_keeps_one_warmup_and_three_measured_repetitions() -> None:
    config = bench.BenchmarkConfig()
    assert config.sizes == (16, 64, 256)
    assert config.warmup_runs == 1
    assert config.measured_runs == 3
    assert config.scenarios == ("promin", "markdown", "empty")
    assert config.operations == ("init", "update", "query", "docs")
    plan = bench.build_plan(config)
    assert plan["config"]["warmup_runs"] == 1
    assert plan["config"]["measured_runs"] == 3
    assert plan["execution"]["expected_bucket_count"] == 72


@pytest.mark.parametrize("operation", ("update", "query", "docs"))
def test_real_local_fixture_exercises_promin_public_routes(
    tmp_path: Path,
    operation: str,
) -> None:
    root = tmp_path / operation
    config = _config(scenarios=("promin",), operations=(operation,))
    try:
        prepared = bench.prepare_case(root, scenario="promin", operation=operation, size=2)
        measured = bench.measure_case(root, scenario="promin", operation=operation, size=2, sampling_interval_ms=5)
    except bench.ComparativeBenchError as exc:
        # The checked-out candidate may reject the real public init precondition
        # on implementation-closure drift. Preserve that evidence; never turn
        # it into a synthetic success or benchmark credit.
        assert "implementation closure drift" in str(exc)
        return

    assert prepared["storage_before"]["file_count"] >= 3
    expected_route = {"update": "refresh", "query": "context", "docs": "refresh"}[operation]
    assert measured["operation_result"]["route"] == f"promin-public-cli:{expected_route}"
    assert measured["operation_result"]["status"] in {"ok", "updated", "created"}
    assert measured["measurement"]["wall_ms"] >= 0
    assert measured["measurement"]["cpu_ms"] >= 0
    assert measured["storage_after"]["file_count"] >= measured["storage_before"]["file_count"]
    assert config.warmup_runs == 0
    assert config.measured_runs == 1


def test_comparative_report_has_no_truthy_acceptance_or_performance_claims() -> None:
    report = bench.build_plan(
        bench.BenchmarkConfig(
            sizes=(16, 64, 256),
            scenarios=("promin", "markdown", "empty"),
            operations=("init", "update", "query", "docs"),
        )
    )
    forbidden = {"claim", "pass_credit", "acceptance_pass", "product_acceptance_pass", "performance_acceptance"}

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if key in forbidden:
                    assert child is False, (key, child)
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(report)
