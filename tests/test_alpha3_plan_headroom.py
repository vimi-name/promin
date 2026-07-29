from __future__ import annotations

import json
from pathlib import Path

import pytest

from promin.canonical import canonical_bytes
from promin.experience import resolve_plan


def _headroom_preflight() -> dict[str, object]:
    """Four real units plus 3,000 bounded entries in a stable order."""

    roots = ("a", "b", "c", "d")
    suffixes = (
        "js",
        "ts",
        "py",
        "kt",
        "java",
        "cpp",
        "cs",
        "rs",
        "go",
        "swift",
        "dart",
    )
    paths: list[str] = []
    for root in roots:
        paths.append(f"{root}/package.json")
        paths.extend(f"{root}/{root}{index:04d}" for index in range(749))
    paths.extend(f"a/f{index}.{suffix}" for index, suffix in enumerate(suffixes))
    paths.extend(f"a/x{index}.js" for index in range(9))
    return {
        "root_name": "headroom",
        "entries": [
            {
                "path": path,
                "kind": "file",
                "size_bytes": 300_000 if Path(path).suffix else 1,
                "suffix": Path(path).suffix.casefold(),
            }
            for path in paths
        ],
        "manifest_samples": {
            f"{root}/package.json": json.dumps({"dependencies": {}})
            for root in roots
        },
        "truncated": False,
        "entry_count": len(paths),
        "bytes_read": 0,
        "max_files": 10_000,
        "max_bytes": 2 * 1024 * 1024,
        "max_depth": 4,
        "full_repository_scan": False,
        "git": {},
    }


def test_resolved_plan_keeps_ten_percent_headroom_without_losing_aggregate_truth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import promin.experience as experience

    preflight = _headroom_preflight()
    monkeypatch.setattr(experience, "bounded_preflight", lambda *_args, **_kwargs: preflight)
    first = resolve_plan(tmp_path, goal="Audit")

    reversed_preflight = dict(preflight)
    reversed_preflight["entries"] = list(reversed(preflight["entries"]))  # type: ignore[index]
    monkeypatch.setattr(
        experience, "bounded_preflight", lambda *_args, **_kwargs: reversed_preflight
    )
    second = resolve_plan(tmp_path, goal="Audit")

    assert len(preflight["entries"]) >= 3_000  # type: ignore[arg-type]
    assert len(first["workspace_map"]["units"]) >= 4
    assert len(first["detected_technologies"]) >= 12
    assert len(canonical_bytes(first)) <= 8192 * 90 // 100
    assert canonical_bytes(first) == canonical_bytes(second)

    large = next(
        signal
        for signal in first["repository_signals"]
        if signal["signal"] == "large-source-files"
    )
    assert large["total_count"] == 20
    assert large["example_count_complete"] is True
    assert large["examples_truncated"] is True
    assert len(large["examples"]) < large["total_count"]
    # The four manifest-backed Node facts are technology evidence too; the
    # large-file aggregate remains the exact count of only the 20 source files.
    assert sum(item["total_source_count"] for item in first["detected_technologies"]) == 24

    assert {
        (item["operation"], item["model_tier"])
        for item in first["operation_profiles"]
    } == {
        ("repository-preflight", "tool-only"),
        ("exact-search", "tool-only"),
        ("file-classification", "micro"),
        ("plan-refinement", "standard"),
        ("implementation", "standard"),
        ("semantic-deduplication", "strong"),
        ("security-review", "strong"),
        ("release-or-destructive-decision", "critical-review"),
        ("concurrent-change-reconciliation", "strong"),
    }
