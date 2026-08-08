from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from promin.artifact_policy import (
    ArtifactPolicyError,
    DOCS_ROOT,
    build_document_manifest,
    validate_control_docs_shell,
)
from promin.gitpolicy import ensure_git_policy


def _write_minimal_docs_shell(root: Path) -> Path:
    control = root / ".promin"
    docs = root / DOCS_ROOT
    docs.mkdir(parents=True)
    payloads = {DOCS_ROOT / "PROJECT_CONTEXT.md": b"# Context\n"}
    (docs / "PROJECT_CONTEXT.md").write_bytes(payloads[DOCS_ROOT / "PROJECT_CONTEXT.md"])
    manifest = build_document_manifest(payloads)
    (docs / "documentation-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    (control / ".gitignore").write_text("*\n!docs/\n!docs/**\n", encoding="utf-8")
    return control


def test_docs_shell_is_accepted_and_git_policy_tracks_docs_not_portable(tmp_path: Path) -> None:
    control = _write_minimal_docs_shell(tmp_path)
    result = validate_control_docs_shell(control)
    policy = ensure_git_policy(tmp_path, apply=True)

    assert result["status"] == "valid"
    assert ".promin/docs" in policy["tracked_roots"]
    assert ".promin/portable" not in policy["tracked_roots"]
    assert "!.promin/docs/**" in (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert "!docs/**" in (control / ".gitignore").read_text(encoding="utf-8")


def test_docs_shell_rejects_host_local_or_detailed_artifacts(tmp_path: Path) -> None:
    control = _write_minimal_docs_shell(tmp_path)
    local = control / "docs" / "run.log"
    local.write_text("host transcript", encoding="utf-8")

    with pytest.raises(ArtifactPolicyError, match="detailed operational artifact"):
        validate_control_docs_shell(control)


def test_git_ignore_allows_docs_and_keeps_operational_state_local(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    docs = tmp_path / DOCS_ROOT
    docs.mkdir(parents=True)
    (docs / "PROJECT_CONTEXT.md").write_text("# Context\n", encoding="utf-8")
    local = tmp_path / ".promin" / "state" / "projection" / "promin.sqlite3"
    local.parent.mkdir(parents=True)
    local.write_bytes(b"local")

    ensure_git_policy(tmp_path, apply=True)

    tracked = subprocess.run(
        ["git", "-C", str(tmp_path), "check-ignore", "-q", "--", ".promin/docs/PROJECT_CONTEXT.md"],
        check=False,
    )
    ignored = subprocess.run(
        ["git", "-C", str(tmp_path), "check-ignore", "-q", "--", ".promin/state/projection/promin.sqlite3"],
        check=False,
    )
    assert tracked.returncode == 1
    assert ignored.returncode == 0
