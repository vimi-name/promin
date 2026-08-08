from __future__ import annotations

import json
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

from promin.selector_shards import (
    SelectorShardError,
    load_selector_shard_manifest,
    run_selector_shard,
    validate_selector_shard_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "tests" / "ALPHA4_TEST_SHARDS.json"


def _fixture_manifest(
    selector: str,
    *,
    timeout_seconds: int = 30,
) -> dict[str, object]:
    return {
        "schema": "promin.selector-shards.v1",
        "selector_set_id": "runner-fixture",
        "marker_expression": "not scale",
        "selectors": [selector],
        "selector_count": 1,
        "per_process": {
            "timeout_seconds": timeout_seconds,
            "memory_bytes": 512 * 1024 * 1024,
        },
        "aggregate": {"timeout_seconds": timeout_seconds * 2},
        "shards": [
            {
                "id": "fixture",
                "selectors": [selector],
                "limits": {
                    "timeout_seconds": timeout_seconds,
                    "memory_bytes": 512 * 1024 * 1024,
                },
            }
        ],
    }


def test_alpha4_plan_has_exact_current_test_file_coverage() -> None:
    manifest = load_selector_shard_manifest(PLAN_PATH)
    expected = tuple(
        sorted(
            f"tests/{path.name}"
            for path in (ROOT / "tests").glob("test_*.py")
        )
    )

    result = validate_selector_shard_manifest(
        manifest,
        expected_selectors=expected,
    )

    assert manifest["marker_expression"] == "not scale"
    assert result["coverage"]["exact"] is True
    assert result["coverage"]["duplicates"] == []
    assert result["coverage"]["extra"] == []
    assert result["coverage"]["missing"] == []
    assert result["per_process"] == {
        "timeout_seconds": 600,
        "memory_bytes": 1024 * 1024 * 1024,
    }
    assert result["acceptance_pass"] is False
    assert result["pass_credit"] is False


def test_loader_rejects_duplicate_json_keys_before_runner_can_spawn(
    tmp_path: Path,
) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"schema":"promin.selector-shards.v1",'
        '"schema":"promin.selector-shards.v1"}',
        encoding="utf-8",
    )

    with pytest.raises(SelectorShardError):
        load_selector_shard_manifest(path)


def test_runner_validates_loaded_manifest_before_spawning(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    selector = "tests/test_fast.py"
    invalid = _fixture_manifest(selector)
    shard = invalid["shards"]
    assert isinstance(shard, list)
    assert isinstance(shard[0], dict)
    limits = shard[0]["limits"]
    assert isinstance(limits, dict)
    limits["timeout_seconds"] = 29

    with patch("promin.selector_shards.subprocess.run") as spawn:
        with pytest.raises(SelectorShardError):
            run_selector_shard(
                invalid,
                "fixture",
                project_root=project,
                python_executable=sys.executable,
            )
    spawn.assert_not_called()


def test_runner_executes_a_validated_shard_or_reports_unavailable(tmp_path: Path) -> None:
    project = tmp_path / "project"
    tests = project / "tests"
    tests.mkdir(parents=True)
    (tests / "test_fast.py").write_text(
        "def test_fast() -> None:\n"
        "    assert True\n",
        encoding="utf-8",
    )
    selector = "tests/test_fast.py"
    manifest_path = tmp_path / "runner-manifest.json"
    manifest_path.write_text(
        json.dumps(_fixture_manifest(selector), sort_keys=True),
        encoding="utf-8",
    )
    manifest = load_selector_shard_manifest(manifest_path)

    receipt = run_selector_shard(
        manifest,
        "fixture",
        project_root=project,
        python_executable=sys.executable,
    )

    assert receipt["id"] == "fixture"
    assert receipt["selector_digest"] == manifest["selector_digest"]
    assert receipt["timeout_seconds"] == 30
    assert receipt["memory_bytes"] == 512 * 1024 * 1024
    assert receipt["acceptance_pass"] is False
    assert receipt["pass_credit"] is False
    assert receipt["status"] in {"PASS", "UNAVAILABLE"}
    if receipt["status"] == "PASS":
        assert receipt["semantic_failure"] is False
        assert receipt["exit_code"] == 0
    else:
        assert receipt["semantic_failure"] is False


def test_runner_timeout_is_not_a_semantic_failure_or_credit(tmp_path: Path) -> None:
    project = tmp_path / "project"
    tests = project / "tests"
    tests.mkdir(parents=True)
    (tests / "test_slow.py").write_text(
        "import time\n\n"
        "def test_slow() -> None:\n"
        "    time.sleep(2)\n",
        encoding="utf-8",
    )
    manifest_path = tmp_path / "timeout-manifest.json"
    manifest_path.write_text(
        json.dumps(
            _fixture_manifest("tests/test_slow.py", timeout_seconds=1),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    manifest = load_selector_shard_manifest(manifest_path)

    receipt = run_selector_shard(
        manifest,
        "fixture",
        project_root=project,
        python_executable=sys.executable,
    )

    assert receipt["status"] in {"TIMEOUT", "UNAVAILABLE"}
    assert receipt["semantic_failure"] is False
    assert receipt["acceptance_pass"] is False
    assert receipt["pass_credit"] is False
    if receipt["status"] == "TIMEOUT":
        assert receipt["exit_code"] is None
