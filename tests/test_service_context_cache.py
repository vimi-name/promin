from __future__ import annotations

from pathlib import Path

import pytest

from test_service_cli import (
    _check_projection_rebuild_forces_full_activation_verification,
    _check_read_context_accepts_installed_preset_on_long_path,
    _check_read_context_is_reused_only_while_activation_files_are_unchanged,
)


def test_read_context_is_reused_only_while_activation_files_are_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _check_read_context_is_reused_only_while_activation_files_are_unchanged(
        tmp_path,
        monkeypatch,
    )


def test_projection_rebuild_forces_full_activation_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _check_projection_rebuild_forces_full_activation_verification(
        tmp_path,
        monkeypatch,
    )


def test_read_context_accepts_installed_preset_on_long_path(
    tmp_path: Path,
) -> None:
    _check_read_context_accepts_installed_preset_on_long_path(tmp_path)
