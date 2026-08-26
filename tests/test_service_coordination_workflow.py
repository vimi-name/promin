from __future__ import annotations

from pathlib import Path

from test_service_cli import (
    _check_authorized_continuation_rejects_public_derived_authenticator,
    _check_next_uses_separate_query_and_holder_grants,
    _check_projection_rebuild_keeps_latest_lease_lifecycle_state,
)


def test_projection_rebuild_keeps_latest_lease_lifecycle_state(tmp_path: Path) -> None:
    _check_projection_rebuild_keeps_latest_lease_lifecycle_state(tmp_path)


def test_next_uses_separate_query_and_holder_grants(tmp_path: Path) -> None:
    _check_next_uses_separate_query_and_holder_grants(tmp_path)


def test_authorized_continuation_rejects_public_derived_authenticator(
    tmp_path: Path,
) -> None:
    _check_authorized_continuation_rejects_public_derived_authenticator(tmp_path)
