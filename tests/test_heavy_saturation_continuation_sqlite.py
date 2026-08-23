from __future__ import annotations

import hashlib
import base64
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from promin.canonical import canonical_bytes
from tools import promin_saturation as saturation


_BUDGET = {
    "max_bytes": 8192,
    "max_entities": 2,
    "max_relations": 2,
    "max_fanout_per_entity": 1,
    "top_k": 1,
}


def _projection(tmp_path: Path) -> tuple[Path, Path]:
    workspace = tmp_path / "workspace"
    database = workspace / ".promin" / "state" / "projection" / "promin.sqlite3"
    database.parent.mkdir(parents=True)
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "CREATE TABLE continuations("
            "handle TEXT PRIMARY KEY,row_digest TEXT NOT NULL,"
            "payload_json TEXT NOT NULL,expires_at TEXT NOT NULL"
            ") WITHOUT ROWID"
        )
        connection.commit()
    finally:
        connection.close()
    return workspace, database


def _insert_continuation(
    database: Path,
    *,
    handle: str,
    payload: dict[str, Any],
    cursor: int,
) -> dict[str, Any]:
    payload_bytes = canonical_bytes(payload)
    row_digest = hashlib.sha256(payload_bytes).hexdigest()
    expiry = "2026-08-13T00:15:00Z"
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "INSERT INTO continuations(handle,row_digest,payload_json,expires_at) "
            "VALUES(?,?,?,?)",
            (handle, row_digest, payload_bytes.decode("utf-8"), expiry),
        )
        connection.commit()
    finally:
        connection.close()
    return {
        "version": 2,
        "traversal": "typed-bfs-v2",
        "token": f"promin-v2.{handle}.{row_digest}.signature",
        "cursor": cursor,
        "expiry": expiry,
        "activation_digest": "a" * 64,
        "head_digest": "b" * 64,
        "projection_digest": "c" * 64,
        "implementation_closure_digest": "d" * 64,
        "ranking": "bm25-v1",
        "depth": 1,
        "budget_digest": "e" * 64,
        "resume_binding_digest": "f" * 64,
    }


def _delete_continuation(database: Path, continuation: dict[str, Any]) -> None:
    handle = continuation["token"].split(".")[1]
    connection = sqlite3.connect(database)
    try:
        connection.execute("DELETE FROM continuations WHERE handle=?", (handle,))
        connection.commit()
    finally:
        connection.close()


def _stored_rows(database: Path) -> list[tuple[Any, ...]]:
    connection = sqlite3.connect(database)
    try:
        return list(
            connection.execute(
                "SELECT handle,row_digest,payload_json,expires_at "
                "FROM continuations ORDER BY handle"
            )
        )
    finally:
        connection.close()


def _page(
    *,
    entity_id: str,
    continuation: dict[str, Any] | None,
    stream_cursor: int,
) -> dict[str, Any]:
    truncated = continuation is not None
    page: dict[str, Any] = {
        "query": "grant",
        "depth": 1,
        "budget": dict(_BUDGET),
        "ranking": "bm25-v1",
        "entities": [{"id": entity_id}],
        "relations": [],
        "evidence": [],
        "truncated": truncated,
        "stream_cursor": stream_cursor,
        "refinement_required": False,
        "refinement_hints": [],
        "selected_seed_count": 1,
        "unselected_matches_traversable": False,
        "silent_truncation": False,
        "selected_closure_complete": not truncated,
    }
    if continuation is not None:
        page.update(
            {
                "continuation": continuation,
                "continuation_version": 2,
                "next_stream_cursor": continuation["cursor"],
            }
        )
    return page


def test_dirty_sqlite_continuation_baseline_is_rejected(tmp_path: Path) -> None:
    workspace, database = _projection(tmp_path)
    _insert_continuation(
        database,
        handle="preexisting",
        payload={"query": "old", "cursor": 1},
        cursor=1,
    )

    with pytest.raises(saturation.SaturationError, match="baseline is not empty"):
        saturation._ContinuationStateObserver(workspace)


def test_each_continuation_is_measured_before_its_consuming_search(
    tmp_path: Path,
) -> None:
    workspace, database = _projection(tmp_path)
    observer = saturation._ContinuationStateObserver(workspace)
    first_payload = {"query": "grant", "cursor": 1, "private": "first secret"}
    second_payload = {"query": "grant", "cursor": 2, "private": "second secret"}
    first_continuation = _insert_continuation(
        database,
        handle=base64.urlsafe_b64encode(b"first-handle-001").rstrip(b"=").decode("ascii"),
        payload=first_payload,
        cursor=1,
    )
    first_parts = first_continuation["token"].split(".")
    first_continuation["token"] = ".".join((*first_parts[:3], "s" * 43))
    expected_sizes = [len(canonical_bytes(first_payload))]

    class RecordingRuntime:
        calls = 0

        def search(self, *_args: Any, **kwargs: Any) -> dict[str, Any]:
            assert kwargs["continuation_token"] in {
                first_continuation["token"],
                second_continuation.get("token"),
            }
            self.calls += 1
            measurements = observer.measurement_rows()
            assert len(measurements) == self.calls
            assert measurements[-1] == {
                "rows": 1,
                "maximum_bytes": expected_sizes[-1],
                "total_bytes": expected_sizes[-1],
            }
            if self.calls == 1:
                _delete_continuation(database, first_continuation)
                second_continuation.update(
                    _insert_continuation(
                        database,
                        handle=base64.urlsafe_b64encode(b"second-handle-01").rstrip(b"=").decode("ascii"),
                        payload=second_payload,
                        cursor=2,
                    )
                )
                second_parts = second_continuation["token"].split(".")
                second_continuation["token"] = ".".join(
                    (*second_parts[:3], "s" * 43)
                )
                expected_sizes.append(len(canonical_bytes(second_payload)))
                return _page(
                    entity_id="entity:second",
                    continuation=second_continuation,
                    stream_cursor=1,
                )
            _delete_continuation(database, second_continuation)
            return _page(
                entity_id="entity:final",
                continuation=None,
                stream_cursor=2,
            )

    second_continuation: dict[str, Any] = {}
    runtime = RecordingRuntime()
    drained = saturation._drain_pages(
        runtime,
        _page(
            entity_id="entity:first",
            continuation=first_continuation,
            stream_cursor=0,
        ),
        _BUDGET,
        query_grant={"subject_id": "owner", "grant_id": "reader"},
        ttl_seconds=900,
        continuation_observer=observer,
        clock=lambda: datetime(2026, 8, 13, 0, 0, tzinfo=timezone.utc),
    )

    assert runtime.calls == 2
    assert drained["continuation_pages"] == 2
    assert len(observer.measurement_rows()) == 2
    assert len(observer.manifest_rows()) == 2
    assert _stored_rows(database) == []


def test_drain_pages_routes_continuations_through_immutable_phase(
    tmp_path: Path,
) -> None:
    workspace, database = _projection(tmp_path)
    observer = saturation._ContinuationStateObserver(workspace)
    continuation = _insert_continuation(
        database,
        handle=base64.urlsafe_b64encode(b"phase-handle-001").rstrip(b"=").decode("ascii"),
        payload={"query": "grant", "cursor": 1},
        cursor=1,
    )
    token_parts = continuation["token"].split(".")
    continuation["token"] = ".".join((*token_parts[:3], "s" * 43))

    class OrdinaryRuntime:
        def search(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise AssertionError("ordinary runtime search bypassed immutable phase")

    class ImmutablePhase:
        def __init__(self) -> None:
            self.search_calls = 0

        def search(self, *_args: Any, **kwargs: Any) -> dict[str, Any]:
            self.search_calls += 1
            assert kwargs["continuation_token"] == continuation["token"]
            _delete_continuation(database, continuation)
            return _page(
                entity_id="entity:phase-final",
                continuation=None,
                stream_cursor=1,
            )

        def renew_search(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise AssertionError("renewal was not expected in this phase witness")

    phase = ImmutablePhase()
    drained = saturation._drain_pages(
        OrdinaryRuntime(),
        _page(
            entity_id="entity:phase-first",
            continuation=continuation,
            stream_cursor=0,
        ),
        _BUDGET,
        query_grant={"subject_id": "owner", "grant_id": "reader"},
        ttl_seconds=900,
        continuation_observer=observer,
        clock=lambda: datetime(2026, 8, 13, 0, 0, tzinfo=timezone.utc),
        query_phase=phase,
    )

    assert phase.search_calls == 1
    assert drained["continuation_pages"] == 1
    assert drained["phase_operations"] == 1
    assert _stored_rows(database) == []


def test_depth_one_multi_page_chain_stays_within_contract_phase_budget(
    tmp_path: Path,
) -> None:
    workspace, database = _projection(tmp_path)
    observer = saturation._ContinuationStateObserver(workspace)

    def make_continuation(index: int) -> dict[str, Any]:
        handle = base64.urlsafe_b64encode(
            f"depth-one-{index:06d}".encode("ascii").ljust(16, b"0")
        ).rstrip(b"=").decode("ascii")
        continuation = _insert_continuation(
            database,
            handle=handle,
            payload={"query": "grant", "cursor": index},
            cursor=index,
        )
        parts = continuation["token"].split(".")
        continuation["token"] = ".".join((*parts[:3], "s" * 43))
        return continuation

    continuations = [make_continuation(index) for index in range(1, 4)]

    class BudgetedPhase:
        def __init__(self) -> None:
            self.remaining = saturation._query_phase_operation_budget(
                [{"depth": 1}], 0, continuation_page_limit=3
            )
            self.calls = 0

        def search(self, *_args: Any, **kwargs: Any) -> dict[str, Any]:
            assert self.remaining > 0
            self.remaining -= 1
            self.calls += 1
            token = kwargs["continuation_token"]
            current_index = next(
                index
                for index, continuation in enumerate(continuations)
                if continuation["token"] == token
            )
            _delete_continuation(database, continuations[current_index])
            next_continuation = (
                continuations[current_index + 1]
                if current_index + 1 < len(continuations)
                else None
            )
            return _page(
                entity_id=f"entity:depth-one:{self.calls}",
                continuation=next_continuation,
                stream_cursor=self.calls,
            )

        def renew_search(self, *_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise AssertionError("unexpected renewal in depth-one chain")

    phase = BudgetedPhase()
    drained = saturation._drain_pages(
        object(),
        _page(
            entity_id="entity:depth-one:first",
            continuation=continuations[0],
            stream_cursor=0,
        ),
        _BUDGET,
        query_grant={"subject_id": "owner", "grant_id": "reader"},
        ttl_seconds=900,
        continuation_observer=observer,
        clock=lambda: datetime(2026, 8, 13, 0, 0, tzinfo=timezone.utc),
        query_phase=phase,
    )

    assert phase.calls == 3
    assert drained["continuation_pages"] == 3
    assert drained["phase_operations"] == 3
    assert phase.remaining == 4
    assert _stored_rows(database) == []


def test_manifest_is_deterministic_digest_bound_and_does_not_leak_payload(
    tmp_path: Path,
) -> None:
    workspace, database = _projection(tmp_path)
    observer = saturation._ContinuationStateObserver(workspace)
    payloads = (
        ("private-handle-z", {"query": "secret-z", "cursor": 2}),
        ("private-handle-a", {"query": "secret-a", "cursor": 1}),
    )
    continuations = [
        _insert_continuation(database, handle=handle, payload=payload, cursor=index)
        for index, (handle, payload) in enumerate(payloads, start=1)
    ]

    observer.observe(continuations[0])
    observer.observe(continuations[1])
    rows = observer.manifest_rows()
    first_digest = saturation._digest(rows)

    assert rows == sorted(rows, key=lambda row: row["path"])
    assert observer.manifest_rows() == rows
    assert saturation._digest(observer.manifest_rows()) == first_digest
    assert all(set(row) == {"path", "sha256", "bytes"} for row in rows)
    assert all(row["path"].endswith(row["sha256"]) for row in rows)
    assert observer.metrics() == {
        "files": 2,
        "maximum_bytes": max(row["bytes"] for row in rows),
        "total_bytes": sum(row["bytes"] for row in rows),
        "preexisting_files_excluded": 0,
    }
    published = b"".join(canonical_bytes(row) for row in rows)
    for handle, payload in payloads:
        assert handle.encode("utf-8") not in published
        assert payload["query"].encode("utf-8") not in published


def test_repeated_measurement_deduplicates_manifest_but_keeps_actual_samples(
    tmp_path: Path,
) -> None:
    workspace, database = _projection(tmp_path)
    observer = saturation._ContinuationStateObserver(workspace)
    continuation = _insert_continuation(
        database,
        handle="repeat-handle",
        payload={"query": "repeat", "cursor": 1},
        cursor=1,
    )

    observer.observe(continuation)
    observer.observe(continuation)

    assert len(observer.manifest_rows()) == 1
    assert len(observer.measurement_rows()) == 2
    assert observer.measurement_rows()[0] == observer.measurement_rows()[1]


def test_observer_enforces_live_row_and_payload_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row_workspace, row_database = _projection(tmp_path / "rows")
    row_observer = saturation._ContinuationStateObserver(row_workspace)
    monkeypatch.setattr(saturation, "_CONTINUATION_STATE_ROWS_MAX", 1)
    first = _insert_continuation(
        row_database,
        handle="row-one",
        payload={"query": "one"},
        cursor=1,
    )
    _insert_continuation(
        row_database,
        handle="row-two",
        payload={"query": "two"},
        cursor=2,
    )
    with pytest.raises(saturation.SaturationError, match="row ceiling"):
        row_observer.observe(first)
    assert row_observer.manifest_rows() == []
    assert row_observer.measurement_rows() == []

    payload_workspace, payload_database = _projection(tmp_path / "payload")
    payload_observer = saturation._ContinuationStateObserver(payload_workspace)
    monkeypatch.setattr(saturation, "_CONTINUATION_STATE_BYTES_MAX", 32)
    oversized = _insert_continuation(
        payload_database,
        handle="oversized",
        payload={"private": "x" * 64},
        cursor=1,
    )
    with pytest.raises(saturation.SaturationError, match="byte ceiling"):
        payload_observer.observe(oversized)
    assert payload_observer.manifest_rows() == []
    assert payload_observer.measurement_rows() == []

    sample_workspace, sample_database = _projection(tmp_path / "samples")
    sample_observer = saturation._ContinuationStateObserver(sample_workspace)
    monkeypatch.setattr(saturation, "_CONTINUATION_STATE_OBSERVATIONS_MAX", 1)
    repeated = _insert_continuation(
        sample_database,
        handle="sample-row",
        payload={"query": "sample"},
        cursor=1,
    )
    sample_observer.observe(repeated)
    with pytest.raises(saturation.SaturationError, match="sample ceiling"):
        sample_observer.observe(repeated)
    assert len(sample_observer.manifest_rows()) == 1
    assert len(sample_observer.measurement_rows()) == 1


def test_observer_requires_the_token_selected_sqlite_row(tmp_path: Path) -> None:
    workspace, database = _projection(tmp_path)
    observer = saturation._ContinuationStateObserver(workspace)
    continuation = _insert_continuation(
        database,
        handle="selected-row",
        payload={"query": "selected"},
        cursor=1,
    )
    missing = dict(continuation)
    missing["token"] = missing["token"].replace("selected-row", "missing-row")
    with pytest.raises(saturation.SaturationError, match="row is missing"):
        observer.observe(missing)

    mismatched = dict(continuation)
    parts = mismatched["token"].split(".")
    parts[2] = "0" * 64
    mismatched["token"] = ".".join(parts)
    with pytest.raises(saturation.SaturationError, match="differs from token"):
        observer.observe(mismatched)

    assert observer.manifest_rows() == []
    assert observer.measurement_rows() == []


def test_observer_uses_ordinary_read_only_sqlite_uri_without_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace, database = _projection(tmp_path)
    original_connect = sqlite3.connect
    connections: list[tuple[object, dict[str, object]]] = []
    statements: list[str] = []

    def traced_connect(database_value: object, *args: Any, **kwargs: Any):
        connections.append((database_value, dict(kwargs)))
        connection = original_connect(database_value, *args, **kwargs)
        if isinstance(database_value, str) and database_value.endswith("?mode=ro"):
            connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(saturation.sqlite3, "connect", traced_connect)
    observer = saturation._ContinuationStateObserver(workspace)
    continuation = _insert_continuation(
        database,
        handle="readonly-row",
        payload={"query": "readonly", "cursor": 1},
        cursor=1,
    )
    before = _stored_rows(database)
    observer.observe(continuation)
    after = _stored_rows(database)

    readonly_calls = [call for call in connections if isinstance(call[0], str)]
    assert len(readonly_calls) == 2
    assert all(str(database_value).endswith("?mode=ro") for database_value, _ in readonly_calls)
    assert all("immutable=1" not in str(database_value) for database_value, _ in readonly_calls)
    assert all(options == {"uri": True, "isolation_level": None} for _, options in readonly_calls)
    normalized = [" ".join(statement.split()).upper() for statement in statements]
    assert normalized.count("PRAGMA QUERY_ONLY=ON") == 2
    assert not any(
        statement.startswith(("INSERT ", "UPDATE ", "DELETE ", "REPLACE "))
        for statement in normalized
    )
    assert before == after
