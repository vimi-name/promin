from __future__ import annotations

from copy import deepcopy

import pytest

from promin.selector_shards import (
    SelectorShardError,
    build_selector_shard_manifest,
    record_selector_aggregate,
    validate_selector_shard_manifest,
)


SELECTORS = (
    "tests/test_a.py::test_one",
    "tests/test_b.py::test_two",
    "tests/test_c.py::test_three",
    "tests/test_d.py::test_four",
)


def _manifest() -> dict[str, object]:
    return build_selector_shard_manifest(
        SELECTORS,
        shard_count=2,
        timeout_seconds=45,
        memory_bytes=512 * 1024 * 1024,
        aggregate_timeout_seconds=180,
    )


def test_selector_shards_have_exact_coverage_and_identical_safety_limits() -> None:
    manifest = _manifest()
    result = validate_selector_shard_manifest(manifest, expected_selectors=SELECTORS)

    assert result["coverage"]["exact"] is True
    assert result["coverage"]["missing"] == []
    assert result["coverage"]["duplicates"] == []
    assert result["per_process"] == {
        "timeout_seconds": 45,
        "memory_bytes": 512 * 1024 * 1024,
    }
    assert all(shard["limits"] == result["per_process"] for shard in manifest["shards"])
    assert result["acceptance_pass"] is False
    assert result["pass_credit"] is False


def test_selector_shards_reject_duplicate_or_changed_limits() -> None:
    duplicate = deepcopy(_manifest())
    duplicate["shards"][1]["selectors"].append(SELECTORS[0])
    with pytest.raises(SelectorShardError, match="duplicate"):
        validate_selector_shard_manifest(duplicate, expected_selectors=SELECTORS)

    mismatched = deepcopy(_manifest())
    mismatched["shards"][0]["limits"]["timeout_seconds"] = 44
    with pytest.raises(SelectorShardError, match="limits"):
        validate_selector_shard_manifest(mismatched, expected_selectors=SELECTORS)


def test_aggregate_timeout_is_not_a_semantic_failure_or_credit() -> None:
    manifest = _manifest()
    rows = [
        {"id": shard["id"], "status": "PASS", "elapsed_seconds": 1.0}
        for shard in manifest["shards"]
    ]
    receipt = record_selector_aggregate(
        manifest,
        rows,
        aggregate_elapsed_seconds=181.0,
        expected_selectors=SELECTORS,
    )

    assert receipt["status"] == "TIMEOUT"
    assert receipt["semantic_failure"] is False
    assert receipt["pass_credit"] is False
    assert receipt["acceptance_pass"] is False


def test_missing_terminal_shard_receipt_is_invalid_harness() -> None:
    manifest = _manifest()
    receipt = record_selector_aggregate(
        manifest,
        [{"id": manifest["shards"][0]["id"], "status": "PASS", "elapsed_seconds": 1.0}],
        aggregate_elapsed_seconds=1.0,
        expected_selectors=SELECTORS,
    )

    assert receipt["status"] == "INVALID_HARNESS"
    assert receipt["semantic_failure"] is False
    assert receipt["pass_credit"] is False
