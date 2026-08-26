from __future__ import annotations

from pathlib import Path

from test_service_cli import (
    _check_import_grant_revocation_uses_command_bound_schema_only,
    _check_service_bootstrap_task_relations_and_replay,
    _check_service_resolves_distinct_transition_and_holder_grants,
)


def test_service_bootstrap_task_relations_and_replay(tmp_path: Path) -> None:
    _check_service_bootstrap_task_relations_and_replay(tmp_path)


def test_import_grant_revocation_uses_command_bound_schema_only(tmp_path: Path) -> None:
    _check_import_grant_revocation_uses_command_bound_schema_only(tmp_path)


def test_service_resolves_distinct_transition_and_holder_grants(tmp_path: Path) -> None:
    _check_service_resolves_distinct_transition_and_holder_grants(tmp_path)
