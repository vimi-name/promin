from __future__ import annotations

from pathlib import Path

import pytest

from test_service_cli import (
    _check_doctor_never_promotes_tampered_projection_authority,
    _check_inventory_content_is_searchable_without_putting_source_text_in_payload,
    _check_inventory_rebuild_uses_verified_one_proxy_rows_only,
    _check_runtime_cache_advances_on_local_commit_and_invalidates_on_external_head,
)


def test_inventory_rebuild_uses_verified_one_proxy_rows_only(tmp_path: Path) -> None:
    _check_inventory_rebuild_uses_verified_one_proxy_rows_only(tmp_path)


def test_inventory_content_is_searchable_without_putting_source_text_in_payload(
    tmp_path: Path,
) -> None:
    _check_inventory_content_is_searchable_without_putting_source_text_in_payload(
        tmp_path
    )


def test_runtime_cache_advances_on_local_commit_and_invalidates_on_external_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _check_runtime_cache_advances_on_local_commit_and_invalidates_on_external_head(
        tmp_path,
        monkeypatch,
    )


def test_doctor_never_promotes_tampered_projection_authority(tmp_path: Path) -> None:
    _check_doctor_never_promotes_tampered_projection_authority(tmp_path)
