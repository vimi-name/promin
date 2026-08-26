from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_verified_query_phase import (
    _check_phase_close_ignores_continuation_persistence_byte_growth,
    _check_phase_close_rejects_physical_content_binding_drift,
    _check_phase_reuses_validated_projection_status_for_search_and_renewal,
    _check_public_search_remains_fresh_after_phase_close,
)


def test_public_search_remains_fresh_after_phase_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _check_public_search_remains_fresh_after_phase_close(tmp_path, monkeypatch)


def test_phase_reuses_validated_projection_status_for_search_and_renewal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _check_phase_reuses_validated_projection_status_for_search_and_renewal(tmp_path, monkeypatch)


def test_phase_close_rejects_physical_content_binding_drift(tmp_path: Path) -> None:
    _check_phase_close_rejects_physical_content_binding_drift(tmp_path)


def test_phase_close_ignores_continuation_persistence_byte_growth(tmp_path: Path) -> None:
    _check_phase_close_ignores_continuation_persistence_byte_growth(tmp_path)
