from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path

import pytest

from promin.dynamic_handoff import validate_dynamic_handoff
from promin.static_admission import StaticAdmissionError, run_static_admission


def _handoff() -> dict[str, object]:
    return validate_dynamic_handoff(
        {
            "id": "live-render-proof",
            "status": "PENDING_DYNAMIC",
            "allowed_write_scope": ["artifacts/render/**"],
            "forbidden": ["synthetic-pass-credit"],
            "required_evidence": ["captured-render"],
            "acceptance_predicate": "The live route records bound evidence.",
            "invalidation_class": "BODY_ONLY",
            "stop_conditions": ["input identity changes"],
        }
    )


def _static_root(tmp_path: Path) -> Path:
    (tmp_path / "README.md").write_text("portable source\n", encoding="utf-8")
    docs = tmp_path / ".promin" / "docs"
    docs.mkdir(parents=True)
    (docs / "current-summary.md").write_text("# Compact summary\n", encoding="utf-8")
    return tmp_path


def test_static_admission_composes_exact_static_gates_and_keeps_claims_false(
    tmp_path: Path,
) -> None:
    result = run_static_admission(_static_root(tmp_path), profile="minimal", handoff=_handoff())

    assert result["status"] == "PASS"
    assert [check["kind"] for check in result["checks"]] == [
        "source",
        "documentation",
        "portability",
        "handoff",
    ]
    assert all(check["status"] == "PASS" for check in result["checks"])
    assert result["claims"] == {
        "compiler_validated": False,
        "runtime_validated": False,
        "acceptance_pass": False,
        "pass_credit": False,
    }
    assert result["product_acceptance_pass"] is False
    assert result["release_eligible"] is False
    assert result["effects"] == {
        "provider_invocations": 0,
        "configure_invocations": 0,
        "build_invocations": 0,
        "runtime_invocations": 0,
        "sqlite_connections": 0,
    }


def test_static_admission_does_not_call_provider_build_runtime_or_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _static_root(tmp_path)
    database = root / "state.sqlite3"
    database.write_bytes(b"not-a-real-database")
    before = database.read_bytes()

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("static admission called an external execution boundary")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    result = run_static_admission(root, profile="minimal", handoff=_handoff())

    assert result["status"] == "PASS"
    assert database.read_bytes() == before


def test_static_admission_fails_closed_for_operational_document_payload(
    tmp_path: Path,
) -> None:
    root = _static_root(tmp_path)
    (root / ".promin" / "docs" / "providers.json").write_text("{}\n", encoding="utf-8")

    result = run_static_admission(root, profile="minimal", handoff=_handoff())

    assert result["status"] == "FAIL"
    assert result["pass_credit"] is False
    documentation = next(check for check in result["checks"] if check["kind"] == "documentation")
    assert documentation["status"] == "FAIL"


def test_static_admission_rejects_unknown_profile() -> None:
    with pytest.raises(StaticAdmissionError, match="profile"):
        run_static_admission(Path.cwd(), profile="runtime", handoff=_handoff())
