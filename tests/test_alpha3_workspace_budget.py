from __future__ import annotations

import json
from pathlib import Path

import pytest

from promin.canonical import canonical_bytes
from promin.experience import resolve_plan


def _mixed_workspace_preflight() -> dict[str, object]:
    roots = ("apps/web", "apps/mobile", "services/api")
    suffixes = ("js", "ts", "py", "kt", "java", "cpp", "cs", "rs", "go", "swift")
    paths: list[str] = []
    for root in roots:
        paths.append(f"{root}/package.json")
        for index in range(667):
            suffix = suffixes[index % len(suffixes)]
            paths.append(
                f"{root}/nested-project-segment/deeper-source-segment/file-{index:04d}.{suffix}"
            )
    return {
        "root_name": "mixed-workspace",
        "entries": [
            {
                "path": path,
                "kind": "file",
                "size_bytes": 1,
                "suffix": Path(path).suffix.casefold(),
            }
            for path in paths
        ],
        "manifest_samples": {
            f"{root}/package.json": json.dumps(
                {"dependencies": {"react": "1", "expo": "1", "express": "1"}}
            )
            for root in roots
        },
        "truncated": False,
        "entry_count": len(paths),
        "bytes_read": 0,
        "max_files": 10_000,
        "max_bytes": 2 * 1024 * 1024,
        "max_depth": 8,
        "full_repository_scan": False,
        "git": {},
    }


def test_workspace_map_samples_unit_details_without_losing_exact_source_totals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import promin.experience as experience

    preflight = _mixed_workspace_preflight()
    monkeypatch.setattr(experience, "bounded_preflight", lambda *_args, **_kwargs: preflight)
    first = resolve_plan(tmp_path, goal="Audit a mixed technology workspace")

    reversed_preflight = dict(preflight)
    reversed_preflight["entries"] = list(reversed(preflight["entries"]))  # type: ignore[index]
    monkeypatch.setattr(
        experience, "bounded_preflight", lambda *_args, **_kwargs: reversed_preflight
    )
    second = resolve_plan(tmp_path, goal="Audit a mixed technology workspace")

    workspace = first["workspace_map"]
    units = workspace["units"]
    assert len(preflight["entries"]) >= 2_000  # type: ignore[arg-type]
    assert len(units) == 3
    assert len(first["detected_technologies"]) >= 10
    assert len(canonical_bytes(first)) <= 8192
    assert canonical_bytes(first) == canonical_bytes(second)

    assert sum(unit["total_source_count"] for unit in units) == 2_001
    for unit in units:
        assert unit["total_source_count"] == 667
        assert unit["total_technology_count"] >= 10
        assert len(unit["technology_ids"]) <= 4
        assert len(unit["source_suffix_counts"]) <= 4
        assert sum(unit["source_suffix_counts"].values()) <= unit["total_source_count"]
