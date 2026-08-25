from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import threading
import time
from types import SimpleNamespace

import pytest

from promin.canonical import canonical_bytes
from promin.events import EventStoreError, VerifiedQueryLease, _WriterLock
from promin.projection import ProjectionError
from promin.service import ImmutableQueryPhaseActiveError, ServiceError
from tests.test_service_cli import (
    _at,
    _bind_mutation,
    _command,
    _grant_authorization,
    _leased_service,
    _mutation_card,
)


def _phase_fixture(tmp_path: Path):
    service, grants, task, lease, head = _leased_service(tmp_path)
    service.rebuild()
    return service, grants, task, lease, head


def _query_kwargs(grants: dict[str, dict], *, now: datetime | None = None) -> dict:
    return {
        "query": "grant",
        "depth": 1,
        "subject_id": grants["reader"]["subject_id"],
        "grant_id": grants["reader"]["grant_id"],
        "now": now or datetime.now(timezone.utc).replace(microsecond=0),
        "ttl_seconds": 60,
        "budget": {
            "max_bytes": 8192,
            "max_entities": 2,
            "max_relations": 2,
            "max_fanout_per_entity": 2,
            "top_k": 8,
        },
    }


def test_phase_verifies_authority_once_on_entry_and_once_on_close(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    original = service._event_store(service._context(), recover_publications=False)
    count = 0
    verifier = type(original)._verify_authority_prefix_locked

    def counted(store, *args, **kwargs):
        nonlocal count
        count += 1
        return verifier(store, *args, **kwargs)

    monkeypatch.setattr(type(original), "_verify_authority_prefix_locked", counted)
    now = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=1)
    first = service.search(**_query_kwargs(grants, now=now))
    second = service.search(**_query_kwargs(grants, now=now))
    renew_kwargs = {
        "token": first["continuation"]["token"],
        "query": "grant",
        "depth": 1,
        "subject_id": grants["reader"]["subject_id"],
        "grant_id": grants["reader"]["grant_id"],
        "budget": _query_kwargs(grants)["budget"],
        "now": now,
        "ttl_seconds": 60,
    }
    ordinary_renew = service.renew_search(**renew_kwargs)
    assert count == 3

    phase = service.begin_immutable_query_phase(max_operations=3)
    phase_first = phase.search(**_query_kwargs(grants, now=now))
    phase_second = phase.search(**_query_kwargs(grants, now=now))
    phase_renew = phase.renew_search(**renew_kwargs)
    assert canonical_bytes(phase_first) == canonical_bytes(first)
    assert canonical_bytes(phase_second) == canonical_bytes(second)
    assert canonical_bytes(phase_renew) == canonical_bytes(ordinary_renew)
    phase.close()
    assert count == 5
    service.close()


@pytest.mark.parametrize("value", [0, -1, True, False, 1.0, "2"])
def test_phase_rejects_non_positive_or_non_integer_budget(tmp_path: Path, value) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    with pytest.raises(EventStoreError, match="max_operations"):
        service.begin_immutable_query_phase(max_operations=value)
    assert service.search(**_query_kwargs(grants))["record_type"] == "RetrievalPage"
    service.close()


def test_phase_rejects_nested_closed_exhausted_and_cross_service_use(tmp_path: Path) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    other, _other_grants, _other_task, _other_lease, _other_head = _phase_fixture(
        tmp_path / "other"
    )
    phase = service.begin_immutable_query_phase(max_operations=1)
    with pytest.raises(ServiceError, match="nested"):
        service.begin_immutable_query_phase(max_operations=1)
    with pytest.raises(ServiceError, match="service"):
        other._use_immutable_query_phase(phase, "search", _query_kwargs(grants))
    phase.search(**_query_kwargs(grants))
    with pytest.raises(ServiceError, match="exhausted"):
        phase.search(**_query_kwargs(grants))
    phase.close()
    with pytest.raises(ServiceError, match="closed"):
        phase.search(**_query_kwargs(grants))
    service.close()
    other.close()


def test_phase_preserves_per_operation_authorization_and_expiry_checks(tmp_path: Path) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    invalid_subject = _query_kwargs(grants)
    invalid_subject["subject_id"] = "not-owner"
    def capture(call):
        try:
            call()
        except Exception as exc:
            return type(exc), str(exc)
        raise AssertionError("expected query authorization failure")

    expired = _query_kwargs(
        grants,
        now=datetime.strptime(grants["reader"]["expires_at"], "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=timezone.utc)
        + timedelta(seconds=1),
    )
    ordinary_subject_error = capture(lambda: service.search(**invalid_subject))
    ordinary_expired_error = capture(lambda: service.search(**expired))
    phase = service.begin_immutable_query_phase(max_operations=3)
    assert ordinary_subject_error == capture(lambda: phase.search(**invalid_subject))
    assert ordinary_expired_error == capture(lambda: phase.search(**expired))
    phase.close()
    service.close()


def test_phase_rejects_invalid_grant_and_continuation_then_closes_cleanly(
    tmp_path: Path,
) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    phase = service.begin_immutable_query_phase(max_operations=3)
    invalid_grant = _query_kwargs(grants)
    invalid_grant["grant_id"] = "grant:missing"
    with pytest.raises(ServiceError, match="query Grant is unresolved"):
        phase.search(**invalid_grant)
    invalid_continuation = _query_kwargs(grants)
    invalid_continuation["continuation_token"] = "not-a-continuation-token"
    with pytest.raises(ProjectionError, match="continuation"):
        phase.search(**invalid_continuation)
    phase.close()
    service.search(**_query_kwargs(grants))
    service.close()


def test_phase_close_fails_closed_on_structural_authority_tamper_and_releases_lock(
    tmp_path: Path,
) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    phase = service.begin_immutable_query_phase(max_operations=1)
    phase.search(**_query_kwargs(grants))
    store = phase._lease.store
    authority_head = store.authority_head_path
    authority = json.loads(authority_head.read_text(encoding="utf-8"))
    authority["head"] = []
    authority_head.write_bytes(canonical_bytes(authority))
    with pytest.raises(EventStoreError, match="verified query authority head binding is malformed"):
        phase.close()
    with pytest.raises(ServiceError, match="closed"):
        phase.search(**_query_kwargs(grants))
    # Recovery itself proves the original non-reentrant writer lock was released.
    store.refresh()
    service.close()


def test_phase_close_rejects_projection_semantic_binding_drift(
    tmp_path: Path,
) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    phase = service.begin_immutable_query_phase(max_operations=1)
    phase.search(**_query_kwargs(grants))
    with sqlite3.connect(str(service._projection(service._context()).db_path)) as connection:
        connection.execute(
            "UPDATE metadata SET value=? WHERE key='semantic_digest'",
            ("0" * 64,),
        )
        connection.commit()
    with pytest.raises(ProjectionError, match="projection semantic metadata differs"):
        phase.close()
    with pytest.raises(ServiceError, match="closed"):
        phase.search(**_query_kwargs(grants))
    service.close()


def test_phase_entry_failure_releases_writer_lock_and_does_not_activate_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    store = service._immutable_query_phase_store(service._context())

    def fail_entry(instance, *args, **kwargs):
        raise EventStoreError("entry refresh failure")

    with monkeypatch.context() as patch:
        patch.setattr(type(store), "_refresh_from_disk_locked", fail_entry)
        with pytest.raises(EventStoreError, match="entry refresh failure"):
            service.begin_immutable_query_phase(max_operations=1)
    assert service._active_immutable_query_phase is None
    # The original writer lock can be acquired after the entry exception.
    store.refresh()
    service.search(**_query_kwargs(grants))
    service.close()


def test_phase_operation_failure_still_closes_and_releases_writer_lock(
    tmp_path: Path,
) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    phase = service.begin_immutable_query_phase(max_operations=2)
    invalid_grant = _query_kwargs(grants)
    invalid_grant["grant_id"] = "grant:missing"
    with pytest.raises(ServiceError, match="query Grant is unresolved"):
        phase.search(**invalid_grant)
    phase.close()
    service.search(**_query_kwargs(grants))
    service.close()


def test_service_close_rejects_live_phase_until_phase_closes(
    tmp_path: Path,
) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    phase = service.begin_immutable_query_phase(max_operations=1)
    with pytest.raises(ServiceError, match="immutable query phase is active"):
        service.close()
    phase.search(**_query_kwargs(grants))
    phase.close()
    service.close()


def test_begin_publication_race_with_service_close_is_serialized(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    projection_entered = threading.Event()
    release_projection = threading.Event()
    close_done = threading.Event()
    begin_result: list[object] = []
    begin_errors: list[BaseException] = []
    close_errors: list[BaseException] = []
    original_projection = service._projection

    def paused_projection(context):
        projection = original_projection(context)
        projection_entered.set()
        release_projection.wait(timeout=30)
        return projection

    monkeypatch.setattr(service, "_projection", paused_projection)

    def begin_worker() -> None:
        try:
            begin_result.append(service.begin_immutable_query_phase(max_operations=1))
        except BaseException as exc:  # pragma: no cover - diagnostic thread handoff.
            begin_errors.append(exc)

    def close_worker() -> None:
        try:
            service.close()
        except BaseException as exc:
            close_errors.append(exc)
        finally:
            close_done.set()

    begin_thread = threading.Thread(target=begin_worker)
    begin_thread.start()
    assert projection_entered.wait(timeout=30)
    close_thread = threading.Thread(target=close_worker)
    close_thread.start()
    assert not close_done.wait(timeout=0.2)
    release_projection.set()
    begin_thread.join(timeout=30)
    close_thread.join(timeout=30)
    assert not begin_errors
    assert len(begin_result) == 1
    assert len(close_errors) == 1
    assert isinstance(close_errors[0], ServiceError)
    assert str(close_errors[0]) == "cannot close while immutable query phase is active"
    phase = begin_result[0]
    assert phase is not None
    phase.search(**_query_kwargs(grants))
    phase.close()
    service.close()


def test_event_store_admission_is_atomic_with_phase_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    context = service._context()
    store = service._event_store(context, recover_publications=False)
    guard_entered = threading.Event()
    phase_store_entered = threading.Event()
    phase_ready = threading.Event()
    release_guard = threading.Event()
    entry_errors: list[BaseException] = []
    phase_result: list[object] = []
    store.lock_timeout = 0.1
    original_reject = service._reject_active_immutable_query_phase

    def paused_reject(operation: str) -> None:
        original_reject(operation)
        if operation == "recovery or refresh":
            guard_entered.set()
            assert release_guard.wait(timeout=30)

    monkeypatch.setattr(service, "_reject_active_immutable_query_phase", paused_reject)
    original_phase_store = service._immutable_query_phase_store

    def observed_phase_store(phase_context):
        phase_store_entered.set()
        return original_phase_store(phase_context)

    monkeypatch.setattr(service, "_immutable_query_phase_store", observed_phase_store)
    original_begin_locked = service._begin_immutable_query_phase_locked

    def observed_begin_locked(max_operations=1):
        phase = original_begin_locked(max_operations)
        phase_ready.set()
        return phase

    monkeypatch.setattr(service, "_begin_immutable_query_phase_locked", observed_begin_locked)

    def entry_worker() -> None:
        try:
            service._event_store(context, recover_publications=False)
        except BaseException as exc:
            entry_errors.append(exc)

    def phase_worker() -> None:
        try:
            phase_result.append(service.begin_immutable_query_phase(max_operations=1))
        except BaseException as exc:  # pragma: no cover - diagnostic thread handoff.
            entry_errors.append(exc)

    entry_thread = threading.Thread(target=entry_worker)
    phase_thread = threading.Thread(target=phase_worker)
    entry_thread.start()
    assert guard_entered.wait(timeout=30)
    phase_thread.start()
    # The lifecycle admission barrier must cover the complete EventStore
    # admission and phase publication sequence.  While the competing entry is
    # paused inside its guard, a phase may not acquire its lease, publish an
    # active phase, or otherwise bypass that barrier.  Merely observing the
    # pre-publication None state would not prove this ordering.
    assert not phase_store_entered.wait(timeout=0.2)
    assert not phase_ready.is_set()
    release_guard.set()
    entry_thread.join(timeout=30)
    phase_thread.join(timeout=30)
    assert not entry_thread.is_alive()
    assert not phase_thread.is_alive()
    assert len(phase_result) == 1
    assert not entry_errors
    phase = phase_result[0]
    phase.search(**_query_kwargs(grants))
    phase.close()
    service.close()


def test_initialize_admission_is_atomic_with_phase_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    guard_entered = threading.Event()
    phase_store_entered = threading.Event()
    phase_ready = threading.Event()
    release_guard = threading.Event()
    release_initialize = threading.Event()
    initialize_called = threading.Event()
    initialize_errors: list[BaseException] = []
    phase_result: list[object] = []
    initialize_error = RuntimeError("initialize_project was reached")

    def fail_initialize(_request) -> None:
        initialize_called.set()
        assert release_initialize.wait(timeout=30)
        raise initialize_error

    monkeypatch.setattr("promin.service.initialize_project", fail_initialize)
    original_reject = service._reject_active_immutable_query_phase

    def paused_reject(operation: str) -> None:
        original_reject(operation)
        if operation == "initialization":
            guard_entered.set()
            assert release_guard.wait(timeout=30)

    monkeypatch.setattr(service, "_reject_active_immutable_query_phase", paused_reject)
    original_phase_store = service._immutable_query_phase_store

    def observed_phase_store(phase_context):
        phase_store_entered.set()
        return original_phase_store(phase_context)

    monkeypatch.setattr(service, "_immutable_query_phase_store", observed_phase_store)
    original_begin_locked = service._begin_immutable_query_phase_locked

    def observed_begin_locked(max_operations=1):
        phase = original_begin_locked(max_operations)
        phase_ready.set()
        return phase

    monkeypatch.setattr(service, "_begin_immutable_query_phase_locked", observed_begin_locked)
    request = SimpleNamespace(project_root=service.root)

    def initialize_worker() -> None:
        try:
            service.initialize(request)
        except BaseException as exc:
            initialize_errors.append(exc)

    def phase_worker() -> None:
        try:
            phase_result.append(service.begin_immutable_query_phase(max_operations=1))
        except BaseException as exc:  # pragma: no cover - diagnostic thread handoff.
            initialize_errors.append(exc)

    initialize_thread = threading.Thread(target=initialize_worker)
    phase_thread = threading.Thread(target=phase_worker)
    initialize_thread.start()
    assert guard_entered.wait(timeout=30)
    phase_thread.start()
    phase_store_entered.wait(timeout=2)
    release_guard.set()
    assert initialize_called.wait(timeout=30)
    # The lifecycle lock must keep phase publication behind the already
    # admitted initialization operation. The unfixed guard-only path lets the
    # phase publish while initialize_project is still in flight.
    assert not phase_ready.is_set()
    release_initialize.set()
    initialize_thread.join(timeout=30)
    phase_thread.join(timeout=30)
    assert not initialize_thread.is_alive()
    assert not phase_thread.is_alive()
    assert len(phase_result) == 1
    assert len(initialize_errors) == 1
    assert initialize_errors[0] is initialize_error
    phase = phase_result[0]
    phase.search(**_query_kwargs(grants))
    phase.close()
    service.close()


def test_verified_query_lease_entry_preserves_primary_exception_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _grants, _task, _lease, _head = _phase_fixture(tmp_path)
    store = service._immutable_query_phase_store(service._context())
    original_error = EventStoreError("primary lease entry failure")
    cleanup_error = RuntimeError("lease cleanup failure")
    original_exit = _WriterLock.__exit__

    def fail_entry(_instance, *args, **kwargs):
        raise original_error

    def cleanup_then_fail(lock, *args, **kwargs):
        original_exit(lock, *args, **kwargs)
        raise cleanup_error

    monkeypatch.setattr(type(store), "_refresh_from_disk_locked", fail_entry)
    monkeypatch.setattr(_WriterLock, "__exit__", cleanup_then_fail)
    with pytest.raises(EventStoreError) as raised:
        VerifiedQueryLease(store, 1)
    assert raised.value is original_error
    service.close()


def test_same_thread_commit_is_rejected_before_eventstore_reentry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, grants, task, lease, head = _phase_fixture(tmp_path)
    context = service._context()
    activation_digest = context.activation["activation_digest"]
    card = _mutation_card(
        service,
        task,
        lease,
        grants["holder"],
        grants["reader"],
        "task.transition",
    )
    command = _bind_mutation(
        _command(
            activation_digest=activation_digest,
            command_id="command:phase-reentry-rejected",
            command_kind="task.transition",
            payload={
                "task_id": task["task_id"],
                "from_state": "LEASED",
                "to_state": "RUNNING",
                "reason": "phase reentry regression",
            },
            expected_head=head,
            issued_at=_at(),
            authorization=_grant_authorization(grants["holder"]),
            effect_scope=[{"kind": "task", "value": task["task_id"]}],
        ),
        card,
        grants["holder"],
    )
    phase = service.begin_immutable_query_phase(max_operations=1)
    opened = False
    original_open = type(phase._lease.store)._open_or_recover

    def bounded_open(store, *args, **kwargs):
        nonlocal opened
        opened = True
        store.lock_timeout = 0.01
        return original_open(store, *args, **kwargs)

    monkeypatch.setattr(type(phase._lease.store), "_open_or_recover", bounded_open)
    started = time.monotonic()
    with pytest.raises(ImmutableQueryPhaseActiveError, match="mutation"):
        service.commit(command, workcard=card)
    assert time.monotonic() - started < 5.0
    assert not opened
    phase.search(**_query_kwargs(grants))
    phase.close()
    service.close()


def test_same_thread_recovery_is_rejected_before_eventstore_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    phase = service.begin_immutable_query_phase(max_operations=1)
    opened = False
    original_open = type(phase._lease.store)._open_or_recover

    def bounded_open(store, *args, **kwargs):
        nonlocal opened
        opened = True
        store.lock_timeout = 0.01
        return original_open(store, *args, **kwargs)

    monkeypatch.setattr(type(phase._lease.store), "_open_or_recover", bounded_open)
    with pytest.raises(ImmutableQueryPhaseActiveError, match="recovery"):
        service.doctor(replay=False)
    assert not opened
    phase.search(**_query_kwargs(grants))
    phase.close()
    service.close()


def test_mutation_cleanup_preserves_original_exception_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, _grants, _task, _lease, _head = _phase_fixture(tmp_path)
    original_error = EventStoreError("original mutation failure")

    def fail_context(*args, **kwargs):
        raise original_error

    def fail_cleanup(*args, **kwargs):
        raise ServiceError("cleanup failure")

    monkeypatch.setattr(service, "_context", fail_context)
    monkeypatch.setattr(service, "_clear_query_runtime", fail_cleanup)
    with pytest.raises(EventStoreError) as raised:
        service.commit({})
    assert raised.value is original_error


def test_public_search_remains_fresh_after_phase_close(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    store = service._event_store(service._context(), recover_publications=False)
    count = 0
    verifier = type(store)._verify_authority_prefix_locked

    def counted(instance, *args, **kwargs):
        nonlocal count
        count += 1
        return verifier(instance, *args, **kwargs)

    monkeypatch.setattr(type(store), "_verify_authority_prefix_locked", counted)
    phase = service.begin_immutable_query_phase(max_operations=1)
    phase.search(**_query_kwargs(grants))
    phase.close()
    service.search(**_query_kwargs(grants))
    service.search(**_query_kwargs(grants))
    assert count == 4
    service.close()


def test_phase_reuses_validated_projection_status_for_search_and_renewal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    status_calls = 0
    original_status_connection = type(service._projection(service._context()))._status_connection

    def counted_status(instance, connection):
        nonlocal status_calls
        status_calls += 1
        return original_status_connection(instance, connection)

    monkeypatch.setattr(
        "promin.projection.Projection._status_connection", counted_status
    )
    now = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=1)
    phase = service.begin_immutable_query_phase(max_operations=2)
    assert status_calls == 1
    first = phase.search(**_query_kwargs(grants, now=now))
    assert status_calls == 1
    assert first["continuation"] is not None
    phase.renew_search(
        token=first["continuation"]["token"],
        query="grant",
        depth=1,
        subject_id=grants["reader"]["subject_id"],
        grant_id=grants["reader"]["grant_id"],
        budget=_query_kwargs(grants)["budget"],
        now=now,
        ttl_seconds=60,
    )
    assert status_calls == 1
    phase.close()
    assert status_calls == 2
    service.close()


def test_phase_close_rejects_physical_content_binding_drift(tmp_path: Path) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    phase = service.begin_immutable_query_phase(max_operations=1)
    phase.search(**_query_kwargs(grants))
    projection = phase._projection
    with sqlite3.connect(str(projection.db_path)) as connection:
        connection.execute(
            "UPDATE metadata SET value=? WHERE key='inventory_content_index_digest'",
            ("f" * 64,),
        )
        connection.commit()
    with pytest.raises(ProjectionError, match="content index metadata"):
        phase.close()
    with pytest.raises(ServiceError, match="closed"):
        phase.search(**_query_kwargs(grants))
    service.close()


def test_phase_close_ignores_continuation_persistence_byte_growth(tmp_path: Path) -> None:
    service, grants, _task, _lease, _head = _phase_fixture(tmp_path)
    phase = service.begin_immutable_query_phase(max_operations=1)
    result = phase.search(**_query_kwargs(grants))
    assert result["continuation"] is not None
    with sqlite3.connect(str(phase._projection.db_path)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM continuations").fetchone()[0] == 1
    phase.close()
    service.close()
