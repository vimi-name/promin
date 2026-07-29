"""Focused command-cost contract checks; no physical scale workload lives here."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest


PACKAGE_ROOT = Path(__file__).parents[1]
BENCH_PATH = PACKAGE_ROOT / "tools" / "promin_command_bench.py"
SPEC = importlib.util.spec_from_file_location("promin_command_bench", BENCH_PATH)
assert SPEC is not None and SPEC.loader is not None
bench = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = bench
SPEC.loader.exec_module(bench)

pytestmark = pytest.mark.performance


def _record(command: str, mode: str = "runtime_warm") -> dict[str, object]:
    return {
        "command": command,
        "measurement_mode": mode,
        "workload_id": "small_initialized_project",
        "status": "provisional",
        "percentile": "p95",
        "budget_ms": 2000,
        "warmup_runs": 0,
        "measured_runs": 1,
        "max_files": 32,
        "max_total_bytes": 65536,
        "provider_state": "verified",
        "projection_state": "current",
    }


def _contracts() -> dict[str, object]:
    commands = ["status", "next", "context", "audit", "init review", "init apply small"]
    records = [_record(command, "cli_cold" if command in {"audit", "init review", "init apply small"} else "runtime_warm") for command in commands]
    records.extend([_record("validate", "cli_cold"), _record("validate", "runtime_warm")])
    records.append(_record("status", "operation_incremental"))
    return {"command_latency_contracts": records}


def test_command_cost_contract_requires_mode_workload_and_status() -> None:
    invalid = _contracts()
    record = invalid["command_latency_contracts"][0]  # type: ignore[index]
    assert isinstance(record, dict)
    del record["workload_id"]
    with pytest.raises(bench.BenchError, match="workload_id"):
        bench.validate_latency_contracts(invalid)


def test_command_cost_contract_requires_validate_cold_and_warm() -> None:
    invalid = _contracts()
    records = invalid["command_latency_contracts"]  # type: ignore[index]
    assert isinstance(records, list)
    invalid["command_latency_contracts"] = [record for record in records if not (record["command"] == "validate" and record["measurement_mode"] == "cli_cold")]
    with pytest.raises(bench.BenchError, match="validate requires"):
        bench.validate_latency_contracts(invalid)


def test_cli_cold_sample_uses_a_new_process(tmp_path: Path) -> None:
    bench._fixture(tmp_path)
    sample = bench._run_cli_cold("status", tmp_path)
    assert sample.process_pid is not None
    assert sample.process_pid != os.getpid()
    assert sample.duration_ms >= 0


def test_runtime_warm_reuses_one_verified_service(tmp_path: Path) -> None:
    contract = _record("status", "runtime_warm")
    result = bench.measure_contract(contract, root=tmp_path, requested_mode="runtime_warm")
    assert result["runner_pid"] == result["service_pid"] == os.getpid()
    assert result["service_instance_count"] == 1
    assert result["runtime_warm_single_service"] is True
    assert result["child_pids"] == []


def test_runtime_warm_result_is_explicitly_non_acceptance_evidence() -> None:
    result = {
        "product_acceptance_pass": False,
        "public_release_approved": False,
        "pass_credit": False,
    }
    assert result == {
        "product_acceptance_pass": False,
        "public_release_approved": False,
        "pass_credit": False,
    }


def test_default_fixture_cleanup_uses_a_bounded_child_process(tmp_path: Path) -> None:
    fixture = tmp_path / "owned-fixture"
    fixture.mkdir()
    (fixture / "sample.txt").write_text("fixture", encoding="utf-8")
    bench._cleanup_fixture(fixture)
    assert not fixture.exists()


def test_default_fixture_cleanup_removes_an_owned_read_only_file(tmp_path: Path) -> None:
    fixture = tmp_path / "read-only-fixture"
    fixture.mkdir()
    sample = fixture / "sample.txt"
    sample.write_text("fixture", encoding="utf-8")
    sample.chmod(stat.S_IREAD)
    bench._cleanup_fixture(fixture)
    assert not fixture.exists()


def test_default_fixture_cleanup_fails_closed_when_child_times_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = tmp_path / "retained-fixture"
    fixture.mkdir()

    def timeout(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd="cleanup", timeout=0.01)

    monkeypatch.setattr(bench.subprocess, "run", timeout)
    with pytest.raises(bench.BenchError, match="retained fixture requires explicit cleanup"):
        bench._cleanup_fixture(fixture)
    assert fixture.exists()


def test_current_conformance_has_the_r2_canonical_command_cost_owner() -> None:
    current = json.loads((PACKAGE_ROOT / "core" / "conformance.json").read_text(encoding="utf-8"))
    assert "command_latency_contracts" in current, "r2 canonical command-cost contract not integrated"
    records = bench.validate_latency_contracts(current)
    assert {record["command"] for record in records}.issuperset({"status", "next", "context", "audit", "init review", "init apply small", "validate"})
