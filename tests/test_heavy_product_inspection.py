from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from promin.product_inspection import (
    InspectionLimits,
    ProductInspectionError,
    inspect_product,
    serialize_product_inspection,
)


def _product_fixture(root: Path) -> None:
    (root / "src").mkdir()
    (root / "docs").mkdir()
    (root / "tools").mkdir()
    (root / ".promin" / "docs").mkdir(parents=True)
    (root / ".promin-host" / "recovery").mkdir(parents=True)

    (root / "src" / "main.py").write_text(
        "from .worker import run\n"
        "if __name__ == '__main__':\n"
        "    run()\n",
        encoding="utf-8",
    )
    (root / "src" / "worker.py").write_text(
        "def run():\n"
        "    for value in range(2):\n"
        "        if value:\n"
        "            return value\n"
        "    return 0\n",
        encoding="utf-8",
    )
    (root / "docs" / "ARCHITECTURE.md").write_text("# Architecture\n", encoding="utf-8")
    (root / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.20)\n", encoding="utf-8")
    (root / "compile_commands.json").write_text("[]\n", encoding="utf-8")
    (root / ".promin" / "docs" / "current-summary.md").write_text("# Summary\n", encoding="utf-8")
    (root / ".promin-host" / "recovery" / "restore-plan.json").write_text("{}\n", encoding="utf-8")
    (root / "tools" / "payload.bin").write_bytes(b"\x00binary\x00payload")
    (root / ".env").write_text("TOKEN=local-only\n", encoding="utf-8")


def test_product_inspection_is_deterministic_client_safe_and_non_crediting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _product_fixture(tmp_path)

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("product inspection crossed an operational boundary")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    first = inspect_product(tmp_path)
    second = inspect_product(tmp_path)

    assert first == second
    assert first["schema"] == "promin.product-inspection.v1"
    assert first["status"] == "COMPLETE"
    assert first["claims"] == {
        "acceptance_pass": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
        "release_eligible": False,
        "runtime_validated": False,
    }

    machine = first["machine"]
    assert machine["inventory"]["file_count"] == 9
    assert machine["architecture"]["source_file_count"] == 2
    assert machine["architecture"]["dependency_signals"]["lexical_candidate_count"] >= 1
    assert machine["documentation"]["status"] == "DECLARED"
    assert {item["id"] for item in machine["tool_profiles"] if item["status"] == "DECLARED"} >= {
        "cmake",
        "compilation-database",
    }
    assert machine["recovery_capability"]["status"] == "DECLARED"
    assert machine["static_risk"]["status"] == "REVIEW"
    assert machine["evidence_confidence"]["runtime_execution"] is False

    machine_json = serialize_product_inspection(first, audience="machine")
    client_json = serialize_product_inspection(first, audience="client")
    assert machine_json == serialize_product_inspection(second, audience="machine")
    assert json.loads(machine_json)["record_type"] == "ProductInspectionMachineReport"
    client = json.loads(client_json)
    assert client["record_type"] == "ProductInspectionClientSummary"
    assert str(tmp_path) not in client_json
    assert "sample_paths" not in client_json
    assert "TOKEN=local-only" not in machine_json
    promoted = {**first, "claims": {**first["claims"], "acceptance_pass": True}}
    with pytest.raises(ProductInspectionError, match="promoted claims"):
        serialize_product_inspection(promoted, audience="client")


def test_product_inspection_uses_generic_custom_documentation_and_tool_profiles(
    tmp_path: Path,
) -> None:
    (tmp_path / "units").mkdir()
    (tmp_path / "guides").mkdir()
    (tmp_path / "units" / "feature.domain").write_text("branch when\n", encoding="utf-8")
    (tmp_path / "guides" / "overview.guide").write_text("Overview\n", encoding="utf-8")
    (tmp_path / "tool.config").write_text("enabled=true\n", encoding="utf-8")
    (tmp_path / "recover.plan").write_text("recover\n", encoding="utf-8")

    report = inspect_product(
        tmp_path,
        profile={
            "profile_id": "custom-static-inspection",
            "source_extensions": [".domain"],
            "documentation_extensions": [".guide"],
            "documentation_directories": ["guides"],
            "tool_markers": {"generic-tool": ["tool.config"]},
            "recovery_markers": ["recover.plan"],
        },
    )

    machine = report["machine"]
    assert machine["profile"]["id"] == "custom-static-inspection"
    assert machine["architecture"]["source_extensions"] == {".domain": 1}
    assert machine["documentation"]["status"] == "DECLARED"
    assert machine["tool_profiles"] == [
        {"id": "generic-tool", "marker_count": 1, "status": "DECLARED"}
    ]
    assert machine["recovery_capability"]["status"] == "DECLARED"

    with pytest.raises(ProductInspectionError, match="safe relative"):
        inspect_product(
            tmp_path,
            profile={
                "profile_id": "bad-profile",
                "source_extensions": [".domain"],
                "documentation_extensions": [".guide"],
                "documentation_directories": ["guides"],
                "tool_markers": {"generic-tool": ["../tool.config"]},
                "recovery_markers": ["recover.plan"],
            },
        )


def test_product_inspection_large_tree_stays_bounded_and_compact(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    for index in range(1200):
        (source / f"unit_{index:04d}.py").write_text(
            "def inspect(value):\n"
            "    if value:\n"
            "        return value\n"
            "    return 0\n",
            encoding="utf-8",
        )

    limits = InspectionLimits(
        max_entries=2_000,
        max_total_bytes=8 * 1024 * 1024,
        max_file_bytes=64 * 1024,
        max_hotspots=7,
        max_risk_samples=5,
    )
    first = inspect_product(tmp_path, limits=limits)
    second = inspect_product(tmp_path, limits=limits)

    assert first == second
    assert first["status"] == "COMPLETE"
    assert first["machine"]["inventory"]["file_count"] == 1_200
    assert len(first["machine"]["hotspots"]["items"]) == 7
    assert first["machine"]["hotspots"]["items"] == sorted(
        first["machine"]["hotspots"]["items"],
        key=lambda item: (-item["bytes"], -item["lexical_branch_signals"], item["path"]),
    )
    assert len(serialize_product_inspection(first, audience="client")) < 6_000


def test_product_inspection_keeps_a_budget_truncation_partial_and_non_crediting(
    tmp_path: Path,
) -> None:
    (tmp_path / "large.txt").write_bytes(b"x" * 128)

    report = inspect_product(
        tmp_path,
        limits=InspectionLimits(
            max_entries=10,
            max_total_bytes=64,
            max_file_bytes=64,
            max_hotspots=2,
            max_risk_samples=2,
        ),
    )

    assert report["status"] == "PARTIAL"
    assert report["machine"]["inventory"]["tree_digest"] is None
    assert report["machine"]["static_risk"]["by_code"] == {
        "tree-byte-budget-exceeded": 1
    }
    assert report["claims"]["pass_credit"] is False


def test_product_inspection_excludes_only_exact_host_transients_and_keeps_product_cache(
    tmp_path: Path,
) -> None:
    (tmp_path / "product" / "cache").mkdir(parents=True)
    (tmp_path / "promin").mkdir()
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / ".pytest_cache" / "v").mkdir(parents=True)
    (tmp_path / ".mypy_cache").mkdir()
    (tmp_path / ".ruff_cache").mkdir()
    (tmp_path / "htmlcov").mkdir()
    (tmp_path / "product" / "cache" / "retained.bin").write_bytes(b"product-cache")
    (tmp_path / "promin" / "recovery.py").write_text("def recover(): pass\n", encoding="utf-8")
    (tmp_path / "promin" / "revalidation.py").write_text("def revalidate(): pass\n", encoding="utf-8")
    (tmp_path / "__pycache__" / "module.pyc").write_bytes(b"pyc")
    (tmp_path / ".pytest_cache" / "v" / "state").write_bytes(b"pytest")
    (tmp_path / ".mypy_cache" / "state").write_bytes(b"mypy")
    (tmp_path / ".ruff_cache" / "state").write_bytes(b"ruff")
    (tmp_path / ".coverage").write_bytes(b"coverage")
    (tmp_path / "htmlcov" / "index.html").write_text("generated\n", encoding="utf-8")

    report = inspect_product(tmp_path)
    machine = report["machine"]
    excluded = machine["inventory"]["excluded_host_transient"]

    assert report["status"] == "COMPLETE"
    assert excluded["file_count"] == 6
    assert set(excluded["by_reason"]) == {
        "__pycache__",
        ".coverage",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "htmlcov",
    }
    assert excluded["total_bytes"] == sum(
        item["total_bytes"] for item in excluded["by_reason"].values()
    )
    assert all(item["file_count"] == 1 for item in excluded["by_reason"].values())
    assert machine["inventory"]["file_count"] == 3
    assert all("pycache" not in item["path"] for item in machine["hotspots"]["items"])
    assert any(item["path"] == "product/cache/retained.bin" for item in machine["hotspots"]["items"])
    assert machine["recovery_capability"] == {
        "status": "DECLARED",
        "marker_count": 2,
        "execution": "NOT_ATTEMPTED",
        "recovery_verified": False,
    }
