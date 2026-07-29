from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import promin.init as init_module


ROOT = Path(__file__).parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from promin_validate import verify_reconciliation_path_ownership  # noqa: E402


def test_rec_006_path_ownership_gate_passes() -> None:
    report = verify_reconciliation_path_ownership(ROOT)

    assert report["gate_id"] == "REC-006"
    assert report["status"] == "pass", report["violations"]
    assert report["pass_credit"] is True
    assert report["identity"]["definitions"] == ["promin/platform_paths.py"]
    assert report["process_transport"]["provider_subprocess_run_count"] == 1
    assert report["temporary_boundaries"]["all_routed_through_platform_owner"] is True


def test_provider_process_creation_has_one_owner() -> None:
    source = (ROOT / "promin" / "init.py").read_text(encoding="utf-8")

    assert source.count("subprocess.run(") == 1
    assert "def _run_identity_process" in source
    assert "def _run_provider_process" in source
    assert "executable=_spawn_provider_executable" in source
    assert "subprocess_path(_init_identity_path" not in source


def test_provider_argv_builder_never_adds_transport_prefix() -> None:
    source = inspect.getsource(init_module._spawn_provider_argv)

    assert "subprocess_path" not in source
    assert "_init_identity_path" in source


def test_runtime_temporary_directories_have_one_identity_owner() -> None:
    offenders: list[str] = []
    for path in sorted((ROOT / "promin").glob("*.py")):
        if path.name == "platform_paths.py":
            continue
        source = path.read_text(encoding="utf-8")
        if "TemporaryDirectory(" in source:
            offenders.append(path.relative_to(ROOT).as_posix())

    assert offenders == []


def test_portability_workflow_targets_split_reconciliation_lanes() -> None:
    workflow = (ROOT / ".github" / "workflows" / "alpha-portability.yml").read_text(
        encoding="utf-8"
    )

    for lane in (
        "test_alpha3_reconciliation_static.py",
        "test_alpha3_reconciliation_paths.py",
        "test_alpha3_reconciliation_windows.py",
        "test_alpha3_reconciliation_performance.py",
        "test_alpha3_reconciliation_package.py",
    ):
        assert lane in workflow
    assert "test_alpha3_reconciliation.py" not in workflow


def test_command_latency_contract_has_one_canonical_measured_shape() -> None:
    conformance = json.loads((ROOT / "core" / "conformance.json").read_text(encoding="utf-8"))

    assert "command_latency_contracts" in conformance
    assert "command_latency_budgets_ms" not in conformance
    assert "command_latency_workloads" not in conformance
    records = conformance["command_latency_contracts"]
    assert isinstance(records, list) and records
    required = {
        "command",
        "measurement_mode",
        "workload_id",
        "status",
        "percentile",
        "budget_ms",
        "warmup_runs",
        "measured_runs",
        "max_files",
        "max_total_bytes",
        "provider_state",
        "projection_state",
    }
    commands = {"status", "next", "context", "audit", "init review", "init apply small", "validate"}
    observed_commands = {record["command"] for record in records}
    assert commands <= observed_commands
    for record in records:
        assert required <= set(record)
        assert record["measurement_mode"] in {
            "cli_cold",
            "runtime_warm",
            "operation_incremental",
        }
        assert record["status"] in {"enforced", "provisional"}
        assert record["percentile"] == "p95"
    validate_modes = {
        record["measurement_mode"]
        for record in records
        if record["command"] == "validate"
    }
    assert {"cli_cold", "runtime_warm"} <= validate_modes


def test_shard_manifest_defines_bounded_reconciliation_lanes() -> None:
    manifest = json.loads((ROOT / "tests" / "ALPHA3_R2_TEST_SHARDS.json").read_text(encoding="utf-8"))

    assert manifest["record_type"] == "ProminAlpha3R2TestShards"
    assert manifest["non_scale_selector"] == "not scale"
    assert manifest["unexpected_skip_policy"] == "fail"
    shards = manifest["shards"]
    assert [shard["id"] for shard in shards] == [
        "static",
        "paths",
        "aliased-temp-tree",
        "windows-integration",
        "performance",
        "core-contracts",
        "mutations",
        "service-cli",
        "package",
        "alpha-experience",
    ]
    for shard in shards:
        assert set(shard) == {
            "id",
            "command",
            "test_files",
            "expected_markers",
            "timeout_seconds",
            "allowed_skips",
            "evidence_output",
        }
        assert shard["command"].startswith("python -m pytest ")
        assert isinstance(shard["timeout_seconds"], int) and shard["timeout_seconds"] > 0
        assert shard["allowed_skips"] == 0
        assert shard["evidence_output"].startswith("external/")
        assert shard["test_files"]
        assert all(path.startswith("tests/test_") and path.endswith(".py") for path in shard["test_files"])
        for path in shard["test_files"]:
            assert path in shard["command"]
    declared = [path for shard in shards for path in shard["test_files"]]
    discovered = sorted(
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "tests").glob("test_*.py")
    )
    assert len(declared) == len(set(declared))
    assert sorted(declared) == discovered
