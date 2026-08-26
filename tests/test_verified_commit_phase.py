from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import promin.service as service_module
from promin.canonical import digest_value
from promin.events import EventStore, EventStoreError
from promin.service import ProminService, ServiceError
from tests.test_heavy_event_batching import NOW, _command, _store
from tests.test_service_cli import (
    _at,
    _command as _service_command,
    _grant,
    _grant_authorization,
    _initialized_service,
)


@pytest.fixture(scope="module")
def _service_project(tmp_path_factory: pytest.TempPathFactory) -> Path:
    base = tmp_path_factory.mktemp("vcp")
    service, _authority, _initialized = _initialized_service(base)
    root = service.root
    service.close()
    return root


@pytest.fixture
def service_fixture(_service_project: Path, tmp_path: Path):
    isolated_root = tmp_path / "project"
    shutil.copytree(_service_project, isolated_root)
    service = ProminService(isolated_root)
    authority = service._context().plans["authority.json"]
    initialized = service._context().activation
    activation = initialized["activation_digest"]
    issued_at = _at()
    manager = _grant(
        authority,
        activation,
        issued_at,
        grant_id="grant:phase-manager",
        capability="authority.manage",
    )
    bootstrap = _service_command(
        activation_digest=activation,
        command_id="command:phase-bootstrap",
        command_kind="grant.issue",
        payload=manager,
        expected_head=None,
        issued_at=issued_at,
        authorization={
            "kind": "root",
            "subject_id": "owner",
            "proofs": [
                {
                    "kind": "local-root-command",
                    "subject_id": "owner",
                    "authority_init_digest": digest_value(authority),
                    "signed_intent_digest": "pending",
                }
            ],
        },
    )
    bootstrap["authorization"]["proofs"][0]["signed_intent_digest"] = bootstrap[
        "intent_digest"
    ]
    head = service.commit(bootstrap)["batch_digest"]
    return service, manager, activation, issued_at, head


def _grant_command(authority, activation, issued_at, issuer, *, grant_id, expected_head):
    grant = _grant(
        authority,
        activation,
        issued_at,
        grant_id=grant_id,
        capability="projection.read",
        issuer=issuer,
    )
    return _service_command(
        activation_digest=activation,
        command_id="command:" + grant_id,
        command_kind="grant.issue",
        payload=grant,
        expected_head=expected_head,
        issued_at=issued_at,
        authorization=_grant_authorization(issuer),
    )


def _commit_chain_command(index: int, expected_head: str | None) -> dict:
    return _command(index, expected_head=expected_head)


def test_verified_commit_phase_verifies_admission_and_close_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path / "events")
    verifier = EventStore._verify_authority_prefix_locked
    calls = 0

    def counted(instance, *args, **kwargs):
        nonlocal calls
        calls += 1
        return verifier(instance, *args, **kwargs)

    monkeypatch.setattr(EventStore, "_verify_authority_prefix_locked", counted)
    phase = store.begin_verified_commit_phase(max_operations=3)
    assert calls == 1
    first = phase.commit(_commit_chain_command(1, None), created_at=NOW)
    second = phase.commit(
        _commit_chain_command(2, first["batch_digest"]), created_at=NOW
    )
    third = phase.commit(
        _commit_chain_command(3, second["batch_digest"]), created_at=NOW
    )
    assert [first["outcome"], second["outcome"], third["outcome"]] == [
        "committed",
        "committed",
        "committed",
    ]
    assert calls == 1
    phase.close()
    assert calls == 2


def test_verified_commit_phase_chains_exact_order_and_envelopes(tmp_path: Path) -> None:
    store = _store(tmp_path / "events")
    phase = store.begin_verified_commit_phase(max_operations=3)
    results = []
    expected_head = None
    for index in range(1, 4):
        result = phase.commit(
            _commit_chain_command(index, expected_head), created_at=NOW
        )
        results.append(result)
        expected_head = result["batch_digest"]
    phase.close()

    envelopes = [store.read_envelope(result["batch_digest"]) for result in results]
    assert [envelope["batch"]["sequence"] for envelope in envelopes] == [1, 2, 3]
    assert [envelope["command"]["command_id"] for envelope in envelopes] == [
        "command:batch:0001",
        "command:batch:0002",
        "command:batch:0003",
    ]
    assert [
        envelope["batch"]["previous_digest"] for envelope in envelopes
    ] == [None, results[0]["batch_digest"], results[1]["batch_digest"]]


@pytest.mark.parametrize("max_operations", [0, -1, True, False, 1.0, "2"])
def test_verified_commit_phase_rejects_invalid_operation_budget(
    tmp_path: Path, max_operations
) -> None:
    store = _store(tmp_path / "events")
    with pytest.raises(EventStoreError, match="max_operations"):
        store.begin_verified_commit_phase(max_operations=max_operations)


def test_verified_commit_phase_exhaustion_nesting_and_closed_use(tmp_path: Path) -> None:
    store = _store(tmp_path / "events")
    phase = store.begin_verified_commit_phase(max_operations=1)
    with pytest.raises(EventStoreError):
        store.begin_verified_commit_phase(max_operations=1)
    first = phase.commit(_commit_chain_command(1, None), created_at=NOW)
    with pytest.raises(EventStoreError, match="exhausted"):
        phase.commit(
            _commit_chain_command(2, first["batch_digest"]), created_at=NOW
        )
    phase.close()
    with pytest.raises(EventStoreError, match="closed"):
        phase.commit(_commit_chain_command(2, None), created_at=NOW)


def test_verified_commit_phase_poisoned_by_operation_exception_and_releases_lock(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "events")
    phase = store.begin_verified_commit_phase(max_operations=2)
    invalid = _commit_chain_command(1, None)
    invalid["expected_head_digest"] = "f" * 64
    with pytest.raises(EventStoreError):
        phase.commit(invalid, created_at=NOW)
    with pytest.raises(EventStoreError, match="poison"):
        phase.commit(_commit_chain_command(1, None), created_at=NOW)
    with pytest.raises(EventStoreError):
        phase.close()
    # A failed operation and fail-closed close must not strand the single-writer lock.
    store.refresh()
    recovered_phase = store.begin_verified_commit_phase(max_operations=1)
    recovered_phase.close()


def test_verified_commit_phase_close_releases_writer_lock(tmp_path: Path) -> None:
    store = _store(tmp_path / "events")
    phase = store.begin_verified_commit_phase(max_operations=1)
    phase.commit(_commit_chain_command(1, None), created_at=NOW)
    phase.close()
    assert store.refresh()["sequence"] == 1


def test_service_verified_phase_reuses_admitted_binding_per_operation(
    service_fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, manager, activation, issued_at, head = service_fixture
    authority = service._context().plans["authority.json"]
    original = service_module._fast_implementation_stat_fingerprint
    calls = 0

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(
        service_module, "_fast_implementation_stat_fingerprint", counted
    )
    phase = service.begin_verified_commit_phase(max_operations=2)
    admitted_calls = calls
    first = _grant_command(
        authority,
        activation,
        issued_at,
        manager,
        grant_id="grant:phase-binding-first",
        expected_head=head,
    )
    first_result = phase.commit(first)
    second = _grant_command(
        authority,
        activation,
        issued_at,
        manager,
        grant_id="grant:phase-binding-second",
        expected_head=first_result["batch_digest"],
    )
    second_result = phase.commit(second)

    assert calls == admitted_calls
    assert [first_result["facts"]["sequence"], second_result["facts"]["sequence"]] == [
        2,
        3,
    ]
    phase.close()
    assert calls == admitted_calls + 1
    service.close()


def test_service_verified_phase_close_catches_binding_drift_after_operations(
    service_fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, manager, activation, issued_at, head = service_fixture
    authority = service._context().plans["authority.json"]
    phase = service.begin_verified_commit_phase(max_operations=1)
    command = _grant_command(
        authority,
        activation,
        issued_at,
        manager,
        grant_id="grant:phase-binding-close",
        expected_head=head,
    )
    result = phase.commit(command)
    assert result["facts"]["sequence"] == 2
    monkeypatch.setattr(
        service_module,
        "_fast_implementation_stat_fingerprint",
        lambda *args, **kwargs: "0" * 64,
    )

    with pytest.raises(ServiceError, match="binding"):
        phase.close()

    assert phase._closed is True
    assert service._active_verified_commit_phase is None
    service.close()


def test_service_verified_phase_close_releases_event_phase_after_binding_drift(
    service_fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _manager, _activation, _issued_at, _head = service_fixture
    phase = service.begin_verified_commit_phase(max_operations=1)
    monkeypatch.setattr(
        service_module,
        "_fast_implementation_stat_fingerprint",
        lambda *args, **kwargs: "0" * 64,
    )

    with pytest.raises(ServiceError, match="binding"):
        phase.close()

    monkeypatch.undo()
    fresh_phase = service.begin_verified_commit_phase(max_operations=1)
    fresh_phase.close()
    service.close()
