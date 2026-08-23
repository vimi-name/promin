from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from promin.canonical import digest_value
from promin.service import ImmutableQueryPhaseActiveError, ProminService, ServiceError
from tests.test_service_cli import (
    _at,
    _command,
    _grant,
    _grant_authorization,
    _initialized_service,
)


@pytest.fixture(scope="module")
def _initialized_project(tmp_path_factory: pytest.TempPathFactory) -> Path:
    base = tmp_path_factory.mktemp("verified-commit-phase-base")
    service, _authority, _initialized = _initialized_service(base)
    root = service.root
    service.close()
    return root


@pytest.fixture
def service_fixture(_initialized_project: Path, tmp_path: Path):
    isolated_root = tmp_path / "project"
    shutil.copytree(_initialized_project, isolated_root)
    service = ProminService(isolated_root)
    authority = service._context().plans["authority.json"]
    initialized = service._context().activation
    activation = initialized["activation_digest"]
    issued_at = _at()
    manager = _grant(
        authority, activation, issued_at,
        grant_id="grant:phase-manager", capability="authority.manage"
    )
    bootstrap = _command(
        activation_digest=activation, command_id="command:phase-bootstrap",
        command_kind="grant.issue", payload=manager, expected_head=None,
        issued_at=issued_at,
        authorization={
            "kind": "root", "subject_id": "owner", "proofs": [{
                "kind": "local-root-command", "subject_id": "owner",
                "authority_init_digest": digest_value(authority),
                "signed_intent_digest": "pending",
            }]
        },
    )
    bootstrap["authorization"]["proofs"][0]["signed_intent_digest"] = bootstrap[
        "intent_digest"
    ]
    head = service.commit(bootstrap)["batch_digest"]
    return service, manager, activation, issued_at, head


def _grant_command(authority, activation, issued_at, issuer, *, grant_id, expected_head):
    grant = _grant(
        authority, activation, issued_at, grant_id=grant_id,
        capability="projection.read", issuer=issuer
    )
    return _command(
        activation_digest=activation, command_id="command:" + grant_id,
        command_kind="grant.issue", payload=grant, expected_head=expected_head,
        issued_at=issued_at, authorization=_grant_authorization(issuer)
    )


def test_service_commit_is_fresh_after_verified_phase_close(service_fixture) -> None:
    service, manager, activation, issued_at, head = service_fixture
    authority = service._context().plans["authority.json"]
    phase = service.begin_verified_commit_phase(max_operations=1)
    first = _grant_command(authority, activation, issued_at, manager,
                           grant_id="grant:phase-first", expected_head=head)
    first_result = phase.commit(first)
    phase.close()
    second = _grant_command(authority, activation, issued_at, manager,
                            grant_id="grant:phase-public",
                            expected_head=first_result["batch_digest"])
    second_result = service.commit(second)
    assert [first_result["outcome"], second_result["outcome"]] == ["committed", "committed"]
    assert second_result["facts"]["sequence"] == first_result["facts"]["sequence"] + 1
    service.close()


def test_active_verified_phase_rejects_same_service_mutation_recovery_and_close(service_fixture) -> None:
    service, manager, activation, issued_at, head = service_fixture
    command = _grant_command(service._context().plans["authority.json"], activation,
                             issued_at, manager, grant_id="grant:phase-rejected",
                             expected_head=head)
    phase = service.begin_verified_commit_phase(max_operations=1)
    with pytest.raises(ImmutableQueryPhaseActiveError, match="mutation"):
        service.commit(command)
    with pytest.raises(ImmutableQueryPhaseActiveError, match="recovery"):
        service.doctor(replay=False)
    with pytest.raises(ServiceError, match="active"):
        service.close()
    phase.close()
    service.close()


def test_verified_phase_preserves_prepare_hook_and_result_order(service_fixture, monkeypatch: pytest.MonkeyPatch) -> None:
    service, manager, activation, issued_at, head = service_fixture
    authority = service._context().plans["authority.json"]
    prepare_calls: list[str] = []
    original_prepare = service._prepare_commit

    def counted_prepare(context, view, command_value, relations):
        prepare_calls.append(command_value["command_id"])
        return original_prepare(context, view, command_value, relations)

    monkeypatch.setattr(service, "_prepare_commit", counted_prepare)
    phase = service.begin_verified_commit_phase(max_operations=2)
    first = _grant_command(authority, activation, issued_at, manager,
                           grant_id="grant:phase-ordered-first", expected_head=head)
    first_result = phase.commit(first)
    second = _grant_command(authority, activation, issued_at, manager,
                            grant_id="grant:phase-ordered-second",
                            expected_head=first_result["batch_digest"])
    second_result = phase.commit(second)
    phase.close()
    assert prepare_calls == ["command:grant:phase-ordered-first", "command:grant:phase-ordered-second"]
    assert [first_result["facts"]["sequence"], second_result["facts"]["sequence"]] == [
        second_result["facts"]["sequence"] - 1, second_result["facts"]["sequence"]
    ]
    service.close()


def test_verified_phase_error_cleanup_releases_phase_for_new_operation(service_fixture, monkeypatch: pytest.MonkeyPatch) -> None:
    service, manager, activation, issued_at, head = service_fixture
    authority = service._context().plans["authority.json"]
    original_prepare = service._prepare_commit

    def fail_once(context, view, command_value, relations):
        monkeypatch.setattr(service, "_prepare_commit", original_prepare)
        raise ServiceError("prepare hook failure")

    monkeypatch.setattr(service, "_prepare_commit", fail_once)
    phase = service.begin_verified_commit_phase(max_operations=1)
    command = _grant_command(authority, activation, issued_at, manager,
                             grant_id="grant:phase-error", expected_head=head)
    with pytest.raises(ServiceError, match="prepare hook failure"):
        phase.commit(command)
    with pytest.raises(ServiceError):
        phase.close()
    retry = _grant_command(authority, activation, issued_at, manager,
                           grant_id="grant:phase-retry", expected_head=head)
    assert service.commit(retry)["outcome"] == "committed"
    service.close()
