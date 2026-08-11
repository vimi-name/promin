from __future__ import annotations

import inspect
import json
import subprocess
import sys
from pathlib import Path

import promin.init as init_module
from promin.selector_shards import load_selector_shard_manifest


ROOT = Path(__file__).parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from promin_validate import verify_reconciliation_path_ownership  # noqa: E402


def test_rec_006_path_ownership_gate_passes() -> None:
    report = verify_reconciliation_path_ownership(ROOT)

    assert report["gate_id"] == "REC-006"
    assert report["status"] == "pass", report["violations"]
    assert report["pass_credit"] is False
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


def test_portability_workflow_declares_windows_runtime_and_static_other_platforms() -> None:
    workflow = (ROOT / ".github" / "workflows" / "alpha-portability.yml").read_text(
        encoding="utf-8"
    )

    for lane in (
        "test_alpha4_genericity.py",
        "test_alpha4_static_admission.py",
        "test_alpha4_selector_shards.py",
        "test_alpha3_reconciliation_static.py",
        "test_alpha4_windows_publication.py",
        "test_alpha4_recovery_locks.py",
        "test_alpha4_extensions_clean_init.py",
        "test_alpha3_reconciliation_windows.py",
        "test_alpha3_reconciliation_aliased_temp_tree.py",
    ):
        assert lane in workflow
    assert "declared-platform-static-validation" in workflow
    assert "Linux/macOS are intentionally static-only" in workflow
    assert "macos-aliased-paths" not in workflow
    assert "python: ['3.12', '3.13', '3.14']" in workflow


def test_repository_checkout_policy_preserves_text_payload_lf(tmp_path: Path) -> None:
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")

    assert "* text=auto eol=lf" in attributes
    assert "human/*.pdf binary" in attributes

    git_dir = tmp_path / "attribute-check.git"
    subprocess.run(
        ["git", "init", "--bare", str(git_dir)],
        check=True,
        capture_output=True,
        text=True,
    )
    result = subprocess.run(
        [
            "git",
            f"--git-dir={git_dir}",
            f"--work-tree={ROOT}",
            "check-attr",
            "text",
            "eol",
            "--",
            "promin/init.py",
            "MANIFEST.json",
            "README.md",
            "human/promin_main_ua.pdf",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    attributes_by_path: dict[str, dict[str, str]] = {}
    for line in result.stdout.splitlines():
        path, attribute, value = line.split(": ", maxsplit=2)
        attributes_by_path.setdefault(path, {})[attribute] = value

    for path in ("promin/init.py", "MANIFEST.json", "README.md"):
        assert attributes_by_path[path] == {"text": "auto", "eol": "lf"}
    assert attributes_by_path["human/promin_main_ua.pdf"] == {
        "text": "unset",
        "eol": "unset",
    }


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


def test_shard_manifest_defines_exact_alpha4_non_scale_coverage() -> None:
    manifest_path = ROOT / "tests" / "ALPHA4_TEST_SHARDS.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validated = load_selector_shard_manifest(manifest_path)

    assert manifest["schema"] == "promin.selector-shards.v1"
    assert manifest["selector_set_id"] == "standard-alpha4-non-scale-v1"
    assert manifest["marker_expression"] == "not scale"
    assert manifest["selector_count"] == len(manifest["selectors"])
    assert manifest["per_process"] == {
        "timeout_seconds": 600,
        "memory_bytes": 1073741824,
    }
    assert manifest["aggregate"] == {"timeout_seconds": 3600}
    assert validated["selector_count"] == manifest["selector_count"]
    shards = manifest["shards"]
    assert len(shards) == 7
    assert {shard["id"] for shard in shards} == {
        "core-state",
        "experience-portability",
        "reconciliation-paths",
        "alpha4-policies",
        "service-distribution",
        "heavy-hardening",
        "scale-search",
    }
    for shard in shards:
        assert shard["selectors"]
        assert shard["limits"] == manifest["per_process"]
        assert all(path.startswith("tests/test_") and path.endswith(".py") for path in shard["selectors"])
    declared = [path for shard in shards for path in shard["selectors"]]
    discovered = sorted(
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "tests").glob("test_*.py")
    )
    assert len(declared) == len(set(declared))
    assert sorted(declared) == discovered
