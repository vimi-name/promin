from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping
from unittest import mock

import pytest

import promin.events as events_module
import promin.windows_event_history as history_module
from promin.events import CommitReadView, CommitStateSnapshot, EventStore
from promin.windows_event_history import WindowsEventHistorySeal

# Reuse the exact compiled max-batch policy and command preparation seam.  This
# file measures the production EventStore path; it does not define another
# storage authority or a reduced event format for the diagnostic.
from test_heavy_event_batching import (  # type: ignore[import-not-found]
    ACTIVATION,
    ACTIVATION_RECORD_DIGEST,
    IMPLEMENTATION_CLOSURE,
    NOW,
    POLICY,
    _command,
    _prepare_commit,
)


_PROFILE_HISTORIES = (64, 256, 1024)


def _constant_commit_state(
    view: CommitReadView,
    _envelopes: Any,
) -> CommitStateSnapshot:
    """Return the exact bound HEAD without adding an unrelated replay cost."""

    return CommitStateSnapshot(
        (),
        view.head_sequence,
        view.head_digest,
        view.current_state_binding_digest,
    )


def _store(root: Path) -> EventStore:
    return EventStore(
        root,
        ACTIVATION,
        activation_record_digest=ACTIVATION_RECORD_DIGEST,
        implementation_closure_digest=IMPLEMENTATION_CLOSURE,
        policy=POLICY,
        compiled_record_validator=lambda _definition, _value, **_kwargs: True,
        command_validator=lambda _value, **_kwargs: True,
        authorization_validator=lambda _value, **_kwargs: True,
        event_validator=lambda _value, **_kwargs: True,
        commit_state_loader=_constant_commit_state,
        commit_prepare_callback=_prepare_commit,
        derived_state_validator=lambda _name, _state, **_kwargs: True,
    )


def _profile_relations(batch_index: int) -> list[dict[str, Any]]:
    task_id = f"task:batch:{batch_index:04d}"
    return [
        {
            "record_type": "Relation",
            "relation_id": f"relation:io:{batch_index:04d}:{offset:03d}",
            "kind": "READS",
            "source_type": "Task",
            "source_id": task_id,
            "target_type": "Artifact",
            "target_id": f"artifact:io:{batch_index:04d}:{offset:03d}",
            "activation_digest": ACTIVATION,
            "created_at": NOW,
        }
        for offset in range(127)
    ]


class _CountedConnection:
    """Transparent SQLite connection probe for one bounded commit."""

    def __init__(
        self,
        connection: Any,
        *,
        kind: str,
        counts: Counter[str],
    ) -> None:
        self._connection = connection
        self._kind = kind
        self._counts = counts

    @staticmethod
    def _normalized(sql: str) -> str:
        return " ".join(sql.split()).upper()

    def execute(self, sql: str, parameters: Iterable[Any] = ()) -> Any:
        bound = tuple(parameters)
        normalized = self._normalized(sql)
        if normalized == "BEGIN IMMEDIATE":
            self._counts["sqlite_begin_immediate"] += 1
            self._counts[f"{self._kind}_transactions"] += 1
        elif normalized == "COMMIT":
            self._counts["sqlite_commits"] += 1
        elif normalized == "ROLLBACK":
            self._counts["sqlite_rollbacks"] += 1
        if self._kind == "state_binding":
            if normalized.startswith("WITH RECURSIVE KEY_OFFSET(OFFSET) AS ("):
                self._counts["state_union_selects"] += 1
                if len(bound) == 1 and isinstance(bound[0], bytes):
                    self._counts["state_union_leaf_keys"] += len(bound[0]) // 32
            elif normalized.startswith(
                "WITH RECURSIVE AFFECTED(OFFSET, PREFIX_BYTES, PREFIX) AS ("
            ):
                self._counts["state_union_selects"] += 1
                if len(bound) == 1 and isinstance(bound[0], bytes):
                    payload = bound[0]
                    offset = 0
                    while offset < len(payload):
                        prefix_bytes = payload[offset] - 1
                        if prefix_bytes < 0 or offset + 1 + prefix_bytes > len(payload):
                            raise AssertionError(
                                "state union path payload is malformed"
                            )
                        self._counts["state_union_path_keys"] += 1
                        if prefix_bytes == 32:
                            self._counts["state_union_leaf_keys"] += 1
                        offset += 1 + prefix_bytes
            elif normalized.startswith(
                "SELECT PREFIX, DIGEST, CHILDREN FROM NODE WHERE DEPTH = ?"
            ):
                self._counts["state_range_selects"] += 1
                self._counts["state_range_select_keys"] += len(bound) - 1
            elif normalized.startswith("UPDATE BINDING SET HEAD_SEQUENCE = ?"):
                self._counts["state_binding_row_updates"] += 1
        elif normalized.startswith(
            "SELECT EVENT_ID FROM EVENT_IDENTITY WHERE EVENT_ID IN ("
        ):
            self._counts["event_identity_range_selects"] += 1
            self._counts["event_identity_range_select_keys"] += len(bound)
        return self._connection.execute(sql, bound)

    def executemany(self, sql: str, parameters: Iterable[Iterable[Any]]) -> Any:
        rows = tuple(tuple(row) for row in parameters)
        normalized = self._normalized(sql)
        if self._kind == "state_binding":
            if normalized.startswith("DELETE FROM NODE WHERE DEPTH = ?"):
                self._counts["state_node_delete_rows"] += len(rows)
            elif normalized.startswith("INSERT INTO NODE(DEPTH, PREFIX, DIGEST, CHILDREN)"):
                self._counts["state_node_upsert_rows"] += len(rows)
        elif normalized.startswith("INSERT INTO EVENT_IDENTITY("):
            self._counts["event_identity_insert_rows"] += len(rows)
        return self._connection.executemany(sql, rows)

    def close(self) -> None:
        self._connection.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class _SeedConnection:
    """Keep fixture population deterministic without timing durability setup."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def execute(self, sql: str, parameters: Iterable[Any] = ()) -> Any:
        normalized = " ".join(sql.split()).upper()
        if normalized == "PRAGMA SYNCHRONOUS=FULL":
            return self._connection.execute("PRAGMA synchronous=OFF")
        return self._connection.execute(sql, tuple(parameters))

    def executemany(self, sql: str, parameters: Iterable[Iterable[Any]]) -> Any:
        return self._connection.executemany(sql, parameters)

    def close(self) -> None:
        self._connection.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


def _seed_to_history(store: EventStore, target_batches: int) -> None:
    """Populate valid bytes quickly; every measured commit is unpatched.

    Reopening after this helper runs the production byte-for-byte verifier,
    validates both SQLite indexes, and acquires the real Windows seal.  The
    helper merely avoids spending this non-scale test on fsync latency and an
    O(history) seal check for every *setup* commit.
    """

    store.close()
    original_state_connection = store._state_binding_connection
    original_event_connection = store._event_identity_connection

    def direct_write(path: Path, payload: bytes) -> None:
        os.makedirs(events_module._native_os_path(path.parent), exist_ok=True)
        with open(events_module._native_os_path(path), "wb") as stream:
            stream.write(payload)

    def state_connection(
        generation: str,
        *,
        create: bool = False,
    ) -> _SeedConnection:
        return _SeedConnection(
            original_state_connection(generation, create=create)
        )

    def event_connection(
        generation: str,
        *,
        create: bool = False,
    ) -> _SeedConnection:
        return _SeedConnection(
            original_event_connection(generation, create=create)
        )

    with (
        mock.patch.object(store, "_refresh_from_disk_locked", lambda: None),
        mock.patch.object(
            store,
            "_try_activate_windows_history_after_commit_locked",
            lambda **_kwargs: None,
        ),
        mock.patch.object(store, "_state_binding_connection", state_connection),
        mock.patch.object(store, "_event_identity_connection", event_connection),
        mock.patch("promin.events._write_atomic", direct_write),
        mock.patch("promin.events._fsync_directory", lambda _path: None),
        mock.patch.object(events_module.os, "fsync", lambda _descriptor: None),
    ):
        while store.head()["sequence"] < target_batches:
            batch_index = store.head()["sequence"] + 1
            store.commit(
                _command(batch_index, store.head()["batch_digest"]),
                created_at=NOW,
            )
    assert store.head()["sequence"] == target_batches


def _classify_atomic_write(store: EventStore, path: Path) -> str:
    if path.parent == store.pending:
        return "pending"
    if path.parent == store.journal:
        return "journal"
    if path == store.authority_head_path:
        return "authority_root"
    if path == store.head_path:
        return "head"
    if path == store.checkpoint_path:
        return "journal_checkpoint"
    if store.authority_root in path.parents:
        return "authority_segment"
    if store.index_root in path.parents:
        return "derived_index_package"
    return "other"


def _observe_max_batch_commit(
    store: EventStore,
    *,
    history_batches: int,
) -> dict[str, Any]:
    history = store._windows_event_history
    assert history is not None and history.is_bound
    assert history.held_file_count == history_batches * 2
    preexisting_held = {path.absolute() for path in history._held}
    authority_generation = history.authority_generation
    assert authority_generation is not None
    authority_directory = (store.authority_root / authority_generation).absolute()
    journal_directory = store.journal.absolute()
    root_directory = store.root.absolute()

    counts: Counter[str] = Counter()
    atomic_kinds: Counter[str] = Counter()
    original_write_atomic = events_module._write_atomic
    original_fsync = events_module.os.fsync
    original_fsync_directory = events_module._fsync_directory
    original_matching_paths = events_module._matching_paths
    original_state_connection = EventStore._state_binding_connection
    original_event_connection = EventStore._event_identity_connection
    original_prefix_verifier = EventStore._verify_authority_prefix_locked
    original_checkpoint = EventStore._write_journal_checkpoint
    original_fast_validate = WindowsEventHistorySeal.validate_fast
    original_advance_control = WindowsEventHistorySeal.advance_verified_control
    original_hold_new = WindowsEventHistorySeal.hold_new_existing
    original_query_witness = history_module._query_witness
    original_child_names = history_module._child_names

    def counted_write_atomic(path: Path, payload: bytes) -> None:
        counts["atomic_writes"] += 1
        atomic_kinds[_classify_atomic_write(store, path)] += 1
        original_write_atomic(path, payload)

    def counted_fsync(descriptor: int) -> None:
        counts["python_file_fsyncs"] += 1
        original_fsync(descriptor)

    def counted_fsync_directory(path: Path) -> None:
        counts["directory_fsync_attempts"] += 1
        original_fsync_directory(path)

    def counted_matching_paths(directory: Path, pattern: str) -> list[Path]:
        paths = original_matching_paths(directory, pattern)
        counts["pathname_prefix_scans"] += 1
        counts["pathname_prefix_members"] += len(paths)
        return paths

    def counted_state_connection(
        instance: EventStore,
        generation: str,
        *,
        create: bool = False,
    ) -> _CountedConnection:
        counts["state_sqlite_opens"] += 1
        return _CountedConnection(
            original_state_connection(instance, generation, create=create),
            kind="state_binding",
            counts=counts,
        )

    def counted_event_connection(
        instance: EventStore,
        generation: str,
        *,
        create: bool = False,
    ) -> _CountedConnection:
        counts["event_identity_sqlite_opens"] += 1
        return _CountedConnection(
            original_event_connection(instance, generation, create=create),
            kind="event_identity",
            counts=counts,
        )

    def counted_prefix_verifier(
        instance: EventStore,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        counts["full_byte_prefix_verifications"] += 1
        return original_prefix_verifier(instance, *args, **kwargs)

    def counted_checkpoint(
        instance: EventStore,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        counts["journal_checkpoint_writes"] += 1
        return original_checkpoint(instance, *args, **kwargs)

    def counted_fast_validate(
        seal: WindowsEventHistorySeal,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        counts["windows_fast_validations"] += 1
        original_fast_validate(seal, *args, **kwargs)

    def counted_advance_control(
        seal: WindowsEventHistorySeal,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        counts["windows_control_advances"] += 1
        original_advance_control(seal, *args, **kwargs)

    def counted_hold_new(
        seal: WindowsEventHistorySeal,
        *args: Any,
        **kwargs: Any,
    ) -> str:
        counts["windows_new_file_holds"] += 1
        return original_hold_new(seal, *args, **kwargs)

    def counted_query_witness(handle: int, path: Path) -> Any:
        absolute = path.absolute()
        if absolute in preexisting_held:
            counts["preexisting_immutable_witness_queries"] += 1
        elif (
            absolute.parent in {journal_directory, authority_directory}
            and absolute.suffix == ".json"
        ):
            counts["new_immutable_witness_queries"] += 1
        return original_query_witness(handle, path)

    def counted_child_names(directory: Path) -> frozenset[str]:
        names = original_child_names(directory)
        absolute = directory.absolute()
        if absolute == root_directory:
            kind = "root"
        elif absolute == journal_directory:
            kind = "journal"
        elif absolute == authority_directory:
            kind = "authority"
        else:
            kind = "other"
        counts[f"{kind}_directory_enumerations"] += 1
        counts[f"{kind}_directory_entries_scanned"] += len(names)
        return names

    batch_index = history_batches + 1
    command = _command(batch_index, store.head()["batch_digest"])
    relations = _profile_relations(batch_index)
    with (
        mock.patch("promin.events._write_atomic", counted_write_atomic),
        mock.patch.object(events_module.os, "fsync", counted_fsync),
        mock.patch("promin.events._fsync_directory", counted_fsync_directory),
        mock.patch("promin.events._matching_paths", counted_matching_paths),
        mock.patch.object(
            EventStore, "_state_binding_connection", counted_state_connection
        ),
        mock.patch.object(
            EventStore, "_event_identity_connection", counted_event_connection
        ),
        mock.patch.object(
            EventStore,
            "_verify_authority_prefix_locked",
            counted_prefix_verifier,
        ),
        mock.patch.object(
            EventStore, "_write_journal_checkpoint", counted_checkpoint
        ),
        mock.patch.object(
            WindowsEventHistorySeal, "validate_fast", counted_fast_validate
        ),
        mock.patch.object(
            WindowsEventHistorySeal,
            "advance_verified_control",
            counted_advance_control,
        ),
        mock.patch.object(
            WindowsEventHistorySeal, "hold_new_existing", counted_hold_new
        ),
        mock.patch("promin.windows_event_history._query_witness", counted_query_witness),
        mock.patch("promin.windows_event_history._child_names", counted_child_names),
    ):
        result = store.commit(command, auxiliary_relations=relations, created_at=NOW)

    assert result["outcome"] == "committed"
    assert store.head()["sequence"] == history_batches + 1
    assert store._windows_event_history is history
    metrics = store.last_commit_write_metrics()
    profile: dict[str, Any] = {
        "history_batches": history_batches,
        "target_batch_events": 128,
        "held_files_before": history_batches * 2,
        **dict(sorted(counts.items())),
        "atomic_write_kinds": dict(sorted(atomic_kinds.items())),
        "state_node_rows_reported": metrics["state_binding_node_writes"],
    }
    for key in (
        "full_byte_prefix_verifications",
        "pathname_prefix_scans",
        "pathname_prefix_members",
        "sqlite_rollbacks",
        "state_node_delete_rows",
        "state_range_selects",
        "state_range_select_keys",
        "state_union_selects",
        "state_union_leaf_keys",
        "state_union_path_keys",
        "preexisting_immutable_witness_queries",
        "new_immutable_witness_queries",
        "journal_directory_enumerations",
        "journal_directory_entries_scanned",
        "authority_directory_enumerations",
        "authority_directory_entries_scanned",
    ):
        profile.setdefault(key, 0)
    return profile


@pytest.mark.performance
@pytest.mark.skipif(os.name != "nt", reason="real Windows EventStore seal path")
def test_max_batch_commit_io_counts_at_64_256_1024_sealed_histories(
    tmp_path: Path,
) -> None:
    """Non-scale operation profile: count work; do not claim timed saturation."""

    assert POLICY.max_events_per_batch == 128
    store = _store(tmp_path / "events")
    profiles: list[dict[str, Any]] = []
    try:
        for history_batches in _PROFILE_HISTORIES:
            _seed_to_history(store, history_batches)
            store = _store(tmp_path / "events")
            history = store._windows_event_history
            assert history is not None and history.is_bound
            profiles.append(
                _observe_max_batch_commit(
                    store,
                    history_batches=history_batches,
                )
            )
    finally:
        store.close()

    for profile in profiles:
        history_batches = profile["history_batches"]
        assert profile["full_byte_prefix_verifications"] == 0
        assert profile["pathname_prefix_scans"] == 0
        assert profile["windows_fast_validations"] == 1
        assert profile["windows_control_advances"] == 1
        assert profile["windows_new_file_holds"] == 2
        assert profile["preexisting_immutable_witness_queries"] == 4 * history_batches
        assert profile["new_immutable_witness_queries"] == 6
        assert profile["journal_directory_enumerations"] == 3
        assert profile["authority_directory_enumerations"] == 3
        assert profile["journal_directory_entries_scanned"] == 3 * history_batches + 2
        assert profile["authority_directory_entries_scanned"] == 3 * history_batches + 2

        assert profile["atomic_writes"] == 7
        assert profile["atomic_write_kinds"] == {
            "authority_root": 1,
            "authority_segment": 1,
            "derived_index_package": 1,
            "head": 1,
            "journal": 1,
            "journal_checkpoint": 1,
            "pending": 1,
        }
        assert profile["python_file_fsyncs"] == 8
        assert profile["directory_fsync_attempts"] == 13
        assert profile["journal_checkpoint_writes"] == 1

        assert profile["state_sqlite_opens"] == 2
        assert profile["event_identity_sqlite_opens"] == 2
        assert profile["sqlite_begin_immediate"] == 2
        assert profile["sqlite_commits"] == 2
        assert profile["sqlite_rollbacks"] == 0
        assert profile["state_binding_transactions"] == 1
        assert profile["event_identity_transactions"] == 1
        assert profile["event_identity_range_selects"] == 1
        assert profile["event_identity_range_select_keys"] == 128
        assert profile["event_identity_insert_rows"] == 128

        # The batch-union path replaces one indexed SELECT at every persisted
        # sparse-tree byte depth with one bounded recursive CTE carrying the
        # exact 128 leaf keys.  Row writes remain proportional to touched paths.
        assert profile["state_union_selects"] == 1
        assert profile["state_union_leaf_keys"] == 128
        assert profile["state_range_selects"] == 0
        assert profile["state_range_select_keys"] == 0
        assert profile["state_binding_row_updates"] == 1
        assert profile["state_node_delete_rows"] == 0
        assert profile["state_node_upsert_rows"] == profile["state_node_rows_reported"]
        assert profile["state_union_path_keys"] == profile["state_node_rows_reported"]
        assert 128 <= profile["state_node_upsert_rows"] <= 128 * 33

    assert [
        profile["preexisting_immutable_witness_queries"] for profile in profiles
    ] == [256, 1024, 4096]
    assert [
        profile["journal_directory_entries_scanned"]
        + profile["authority_directory_entries_scanned"]
        for profile in profiles
    ] == [388, 1540, 6148]
    # The sparse-tree write contour stays bounded by the 128-event batch while
    # exact physical seal work grows with retained immutable history.  At 1,024
    # batches, directory-member inspections alone exceed state-node row writes;
    # this is operation-count evidence, not a latency or acceptance claim.
    assert (
        profiles[-1]["journal_directory_entries_scanned"]
        + profiles[-1]["authority_directory_entries_scanned"]
        > profiles[-1]["state_node_upsert_rows"]
    )

    # Make the exact diagnostic visible in a focused ``pytest -s`` run.  This
    # is operation-count evidence only; it cannot produce performance pass
    # credit or replace the physical 100k saturation route.
    print(json.dumps(profiles, sort_keys=True, separators=(",", ":")))
