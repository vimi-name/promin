from __future__ import annotations

import os

import pytest

import promin.service as service_module
from promin.service import ServiceError

from tests.test_verified_commit_phase_service import (
    _grant_command,
    _initialized_project,
    service_fixture,
)


def test_verified_phase_reuses_admitted_activation_binding(service_fixture, monkeypatch):
    service, manager, activation, issued_at, head = service_fixture
    authority = service._context().plans["authority.json"]
    calls = 0
    original = service_module._fast_implementation_stat_fingerprint

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(service_module, "_fast_implementation_stat_fingerprint", counted)
    phase = service.begin_verified_commit_phase(max_operations=2)
    admitted_calls = calls
    first = _grant_command(
        authority, activation, issued_at, manager,
        grant_id="grant:binding-first", expected_head=head,
    )
    first_result = phase.commit(first)
    second = _grant_command(
        authority, activation, issued_at, manager,
        grant_id="grant:binding-second", expected_head=first_result["batch_digest"],
    )
    phase.commit(second)
    assert admitted_calls >= 1
    assert calls == admitted_calls + 2
    phase.close()
    assert calls == admitted_calls + 3
    service.close()


def test_verified_phase_rejects_implementation_binding_drift(service_fixture, monkeypatch):
    service, manager, activation, issued_at, head = service_fixture
    authority = service._context().plans["authority.json"]
    phase = service.begin_verified_commit_phase(max_operations=1)
    monkeypatch.setattr(
        service_module,
        "_implementation_closure_digest",
        lambda _context: "f" * 64,
    )
    command = _grant_command(
        authority, activation, issued_at, manager,
        grant_id="grant:binding-drift", expected_head=head,
    )
    with pytest.raises(ServiceError, match="binding"):
        phase.commit(command)
    monkeypatch.undo()
    phase.close()
    service.close()


def test_verified_phase_rejects_physical_bound_file_drift(service_fixture):
    service, manager, activation, issued_at, head = service_fixture
    authority = service._context().plans["authority.json"]
    phase = service.begin_verified_commit_phase(max_operations=1)
    _label, bound_path, _kind = next(
        item
        for item in phase._binding.bindings
        if item[2] == "file" and item[1].is_relative_to(service.root)
    )
    original_stat = bound_path.stat()
    try:
        os.utime(
            bound_path,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns + 1_000_000),
        )
        command = _grant_command(
            authority, activation, issued_at, manager,
            grant_id="grant:physical-binding-drift", expected_head=head,
        )
        with pytest.raises(ServiceError, match="binding"):
            phase.commit(command)
        with pytest.raises(ServiceError, match="binding"):
            phase.close()
    finally:
        os.utime(
            bound_path,
            ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
        )
        service.close()


def test_verified_phase_close_revalidates_activation_bytes(service_fixture, monkeypatch):
    service, _manager, _activation, _issued_at, _head = service_fixture
    phase = service.begin_verified_commit_phase(max_operations=1)
    original = service_module._fast_implementation_stat_fingerprint
    monkeypatch.setattr(
        service_module,
        "_fast_implementation_stat_fingerprint",
        lambda *args, **kwargs: "0" * 64,
    )
    with pytest.raises(ServiceError, match="binding"):
        phase.close()
    service.close()


def test_public_commit_is_fresh_after_phase_binding_cleanup(service_fixture, monkeypatch):
    service, manager, activation, issued_at, head = service_fixture
    authority = service._context().plans["authority.json"]
    phase = service.begin_verified_commit_phase(max_operations=1)
    phase.close()
    assert service._active_verified_commit_phase is None
    command = _grant_command(
        authority, activation, issued_at, manager,
        grant_id="grant:binding-public", expected_head=head,
    )
    monkeypatch.setattr(
        service_module,
        "verify_before_mutation",
        lambda root: (_ for _ in ()).throw(AssertionError("public route was not fresh")),
    )
    with pytest.raises(AssertionError, match="public route was not fresh"):
        service.commit(command)
    service.close()


def test_verified_phase_lifecycle_clears_binding_after_close(service_fixture):
    service, _manager, _activation, _issued_at, _head = service_fixture
    phase = service.begin_verified_commit_phase(max_operations=1)
    assert phase._binding is not None
    phase.close()
    assert phase._binding is None
    assert service._active_verified_commit_phase is None
    service.close()
