from __future__ import annotations

import promin.service as service_module
from promin.service import ProminService


class _CloseProbe:
    def __init__(self) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1


def test_service_close_releases_cached_event_stores_once(tmp_path) -> None:
    service = ProminService(tmp_path)
    shared = _CloseProbe()
    service._read_store = shared
    service._mutation_store = shared
    service._read_store_key = ("read", "closure")
    service._mutation_store_key = ("mutation", "closure")
    service._query_runtime_key = ("activation", "closure", 1, "batch", "digest")
    service._query_runtime_value = object()

    service.close()

    assert shared.close_calls == 1
    assert service._read_store is None
    assert service._mutation_store is None
    assert service._read_store_key is None
    assert service._mutation_store_key is None
    assert service._query_runtime_key is None
    assert service._query_runtime_value is None

    service.close()

    assert shared.close_calls == 1


def test_service_context_manager_releases_cached_event_store(tmp_path) -> None:
    probe = _CloseProbe()

    with ProminService(tmp_path) as service:
        service._read_store = probe

    assert probe.close_calls == 1


def test_cache_replacement_closes_retired_event_stores(tmp_path, monkeypatch) -> None:
    service = ProminService(tmp_path)
    retired_read = _CloseProbe()
    retired_mutation = _CloseProbe()
    replacement_read = _CloseProbe()
    replacement_mutation = _CloseProbe()
    service._read_store = retired_read
    service._read_store_key = ("retired", "read")
    service._mutation_store = retired_mutation
    service._mutation_store_key = ("retired", "mutation")
    context = object()
    created = iter((replacement_read, replacement_mutation))

    monkeypatch.setattr(service_module, "EventStore", lambda *_args, **_kwargs: next(created))
    monkeypatch.setattr(
        service_module,
        "_activation",
        lambda _context: {"activation_digest": "a" * 64},
    )
    monkeypatch.setattr(
        service_module,
        "_implementation_closure_digest",
        lambda _context: "b" * 64,
    )
    monkeypatch.setattr(service_module, "_event_store_policy", lambda _context: object())
    monkeypatch.setattr(service_module, "_event_store_validators", lambda _context: {})
    monkeypatch.setattr(
        service_module,
        "_recover_evidence_publications",
        lambda _root, _context, _store: None,
    )

    assert service._event_store(context, recover_publications=False) is replacement_read
    assert service._mutation_event_store(context, object()) is replacement_mutation
    assert retired_read.close_calls == 1
    assert retired_mutation.close_calls == 1
    assert replacement_read.close_calls == 0
    assert replacement_mutation.close_calls == 0

    service.close()

    assert replacement_read.close_calls == 1
    assert replacement_mutation.close_calls == 1
