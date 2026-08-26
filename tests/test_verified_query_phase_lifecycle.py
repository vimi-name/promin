from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_verified_query_phase import (
    _check_phase_close_fails_closed_on_structural_authority_tamper_and_releases_lock,
    _check_phase_close_rejects_projection_semantic_binding_drift,
    _check_phase_entry_failure_releases_writer_lock_and_does_not_activate_phase,
    _check_phase_operation_failure_still_closes_and_releases_writer_lock,
    _check_service_close_rejects_live_phase_until_phase_closes,
)


def test_phase_close_fails_closed_on_structural_authority_tamper_and_releases_lock(
    tmp_path: Path,
) -> None:
    _check_phase_close_fails_closed_on_structural_authority_tamper_and_releases_lock(tmp_path)


def test_phase_close_rejects_projection_semantic_binding_drift(
    tmp_path: Path,
) -> None:
    _check_phase_close_rejects_projection_semantic_binding_drift(tmp_path)


def test_phase_entry_failure_releases_writer_lock_and_does_not_activate_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _check_phase_entry_failure_releases_writer_lock_and_does_not_activate_phase(
        tmp_path, monkeypatch
    )


def test_phase_operation_failure_still_closes_and_releases_writer_lock(
    tmp_path: Path,
) -> None:
    _check_phase_operation_failure_still_closes_and_releases_writer_lock(tmp_path)


def test_service_close_rejects_live_phase_until_phase_closes(tmp_path: Path) -> None:
    _check_service_close_rejects_live_phase_until_phase_closes(tmp_path)
