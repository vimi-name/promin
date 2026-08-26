from __future__ import annotations

from pathlib import Path

from test_service_cli import (
    _check_team_signed_cli_init_doctor_status_validate_and_internal_commit,
)


def test_team_signed_cli_init_doctor_status_validate_and_internal_commit(
    tmp_path: Path,
) -> None:
    _check_team_signed_cli_init_doctor_status_validate_and_internal_commit(
        tmp_path
    )
