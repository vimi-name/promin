from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from promin.artifact_policy import (
    ARTIFACT_CLASSES,
    DEFAULT_ARTIFACT_POLICY,
    DOCS_ROOT,
    ArtifactPolicyError,
    artifact_output_path,
    build_document_manifest,
    classify_archive_path,
    validate_document_payloads,
    validate_extension_descriptor,
    validate_tracked_extensions,
    validate_tracked_docs,
)
from promin.documentation import sync_documentation
from promin.experience import resolve_plan
import promin.experience as experience_module
import promin.refresh as refresh_module


def test_minimal_policy_keeps_detailed_artifacts_host_local(tmp_path: Path) -> None:
    assert DEFAULT_ARTIFACT_POLICY.default_mode == "minimal"
    assert set(ARTIFACT_CLASSES) == {
        "portable-normative-doc",
        "compact-current-report",
        "diagnostic-inventory",
        "forensic-log",
        "runtime-evidence",
        "cache",
        "recovery-backup",
    }

    with pytest.raises(ArtifactPolicyError, match="explicit diagnostic or forensic mode"):
        artifact_output_path(
            tmp_path,
            artifact_class="diagnostic-inventory",
            name="inventory.json",
            mode="minimal",
        )

    diagnostic = artifact_output_path(
        tmp_path,
        artifact_class="diagnostic-inventory",
        name="inventory.json",
        mode="diagnostic",
    )
    forensic = artifact_output_path(
        tmp_path,
        artifact_class="forensic-log",
        name="run.log",
        mode="forensic",
    )
    assert diagnostic == tmp_path / "builds" / "analysis" / "inventory.json"
    assert forensic == tmp_path / ".promin" / "logs" / "run.log"
    assert DOCS_ROOT.as_posix() not in diagnostic.relative_to(tmp_path).as_posix()
    assert DOCS_ROOT.as_posix() not in forensic.relative_to(tmp_path).as_posix()

    with pytest.raises(ArtifactPolicyError, match="declares compact-current-report"):
        artifact_output_path(
            tmp_path,
            artifact_class="portable-normative-doc",
            name="current-summary.json",
        )


def test_document_manifest_has_typed_compact_records_and_rejects_detail() -> None:
    payloads = {
        DOCS_ROOT / "PROJECT_CONTEXT.md": b"# Context\n",
        DOCS_ROOT / "current-summary.json": b"{}\n",
    }
    manifest = build_document_manifest(payloads)

    records = {entry["path"]: entry for entry in manifest["files"]}
    assert records[".promin/docs/PROJECT_CONTEXT.md"]["artifact_class"] == "portable-normative-doc"
    assert records[".promin/docs/current-summary.json"]["artifact_class"] == "compact-current-report"
    assert manifest["default_mode"] == "minimal"

    with pytest.raises(ArtifactPolicyError, match="detailed operational artifact"):
        validate_document_payloads(
            {DOCS_ROOT / "module-inventory.tsv": b"path\tsha256\n"}
        )
    with pytest.raises(ArtifactPolicyError, match="UTF-8 text"):
        validate_document_payloads(
            {DOCS_ROOT / "PROJECT_CONTEXT.md": b"\xff"}
        )


def test_tracked_docs_are_bounded_and_archive_classification_is_context_aware(tmp_path: Path) -> None:
    docs = tmp_path / DOCS_ROOT
    docs.mkdir(parents=True)
    (docs / "PROJECT_CONTEXT.md").write_text("# Context\n", encoding="utf-8")

    result = validate_tracked_docs(tmp_path)
    assert result["file_count"] == 1
    assert result["within_budget"] is True
    assert classify_archive_path("src/Evidence/Providers.cpp") == "project-content"
    assert classify_archive_path(".promin/evidence/run.json") == "runtime-evidence"

    (docs / "module-inventory.tsv").write_text("path\tsha256\n", encoding="utf-8")
    with pytest.raises(ArtifactPolicyError, match="detailed operational artifact"):
        validate_tracked_docs(tmp_path)


def test_typed_extensions_stay_below_the_docs_boundary(tmp_path: Path) -> None:
    descriptor = validate_extension_descriptor(
        {
            "extension_id": "source-map",
            "extension_type": "analysis",
            "root": ".promin/docs/extensions/source-map",
        }
    )
    assert descriptor["root"] == ".promin/docs/extensions/source-map"

    extension_file = tmp_path / DOCS_ROOT / "extensions" / "source-map" / "README.md"
    extension_file.parent.mkdir(parents=True)
    extension_file.write_text("# Extension\n", encoding="utf-8")
    docs = validate_tracked_docs(tmp_path)
    extensions = validate_tracked_extensions(tmp_path)
    assert docs["file_count"] == 0
    assert extensions["file_count"] == 1
    assert extensions["files"][0]["artifact_class"] == "tracked-extension"

    with pytest.raises(ArtifactPolicyError, match=r"\.promin/docs/extensions/<id>"):
        validate_extension_descriptor(
            {
                "extension_id": "source-map",
                "extension_type": "analysis",
                "root": ".promin/docs/extension/source-map",
            }
        )


def test_documentation_seed_never_reads_sqlite_or_exports_live_work(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plan = resolve_plan(tmp_path, goal="Create a generic project")
    projection = tmp_path / ".promin" / "state" / "projection" / "promin.sqlite3"
    projection.parent.mkdir(parents=True)
    projection.write_bytes(b"not a seed input")

    def forbidden_connect(*args: object, **kwargs: object) -> object:
        raise AssertionError("documentation seed must not query SQLite or a projection")

    monkeypatch.setattr(sqlite3, "connect", forbidden_connect)
    result = sync_documentation(tmp_path, plan, apply=True)
    seed = json.loads((tmp_path / DOCS_ROOT / "team-seed.json").read_text(encoding="utf-8"))

    assert result["artifact_mode"] == "minimal"
    assert seed["record_type"] == "NonAuthoritativeTeamSeed"
    assert seed["work_card_derivation"] == "after-activation"
    assert seed["operational_state_import"] == "forbidden"
    assert "active_tasks" not in seed
    assert "active_findings" not in seed
    assert "latest_candidate" not in seed


def test_refresh_reset_preserves_projection_and_removes_only_local_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    projection = tmp_path / ".promin" / "state" / "projection" / "promin.sqlite3"
    projection.parent.mkdir(parents=True)
    projection.write_bytes(b"projection must remain untouched")
    cache = tmp_path / ".promin" / "cache" / "documentation" / "state.json"
    cache.parent.mkdir(parents=True)
    cache.write_bytes(b"derived cache")

    monkeypatch.setattr(experience_module, "load_resolved_plan", lambda root: {"reporting_language": "en"})
    monkeypatch.setattr(refresh_module, "ensure_git_policy", lambda *args, **kwargs: {"status": "healthy", "changed": []})
    monkeypatch.setattr(
        refresh_module,
        "sync_documentation",
        lambda *args, **kwargs: {"status": "healthy", "written": [], "removed": [], "changed_units": []},
    )
    monkeypatch.setattr(
        refresh_module,
        "sync_context_index",
        lambda *args, **kwargs: {"status": "healthy", "bytes": 0, "record_count": 0},
    )
    monkeypatch.setattr(refresh_module, "sync_host_surfaces", lambda *args, **kwargs: {"status": "healthy"})
    monkeypatch.setattr(
        refresh_module,
        "sync_commit_surface",
        lambda *args, **kwargs: {"status": "healthy", "footprint": {"startup_instruction_tokens": 0, "total_bytes": 0}},
    )
    monkeypatch.setattr(refresh_module, "record_observation", lambda *args, **kwargs: None)

    result = refresh_module.refresh_project(tmp_path, reset_derived=True)

    assert projection.read_bytes() == b"projection must remain untouched"
    assert not cache.exists()
    assert result["reset_paths"] == [".promin/cache"]
