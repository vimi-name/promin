from __future__ import annotations

import hashlib
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

import pytest

from promin.events import EventStore
from test_heavy_event_batching import NOW, _command, _reads_relations, _store


_GENERATION = re.compile(r"^[0-9a-f]{32}$")
_SQLITE_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")


@dataclass(frozen=True)
class _SqliteStorage:
    binding_version: int
    file_bytes: int
    page_size: int
    page_count: int
    freelist_count: int
    node_count: int


def _generation_names(root: Path) -> list[str]:
    return sorted(
        path.name
        for path in root.iterdir()
        if path.is_dir() and not path.is_symlink() and _GENERATION.fullmatch(path.name)
    )


def _retained_file_bytes(root: Path) -> int:
    return sum(
        path.stat().st_size
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    )


def _sqlite_storage(path: Path) -> _SqliteStorage:
    uri = f"file:{path.as_posix()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        page_size = connection.execute("PRAGMA page_size").fetchone()[0]
        page_count = connection.execute("PRAGMA page_count").fetchone()[0]
        freelist_count = connection.execute("PRAGMA freelist_count").fetchone()[0]
        node_count = connection.execute("SELECT COUNT(*) FROM node").fetchone()[0]
        binding_version = connection.execute(
            "SELECT version FROM binding WHERE singleton = 1"
        ).fetchone()[0]
    return _SqliteStorage(
        binding_version=binding_version,
        file_bytes=path.stat().st_size,
        page_size=page_size,
        page_count=page_count,
        freelist_count=freelist_count,
        node_count=node_count,
    )


def _assert_no_sqlite_sidecars(path: Path) -> None:
    assert not [
        sidecar
        for suffix in _SQLITE_SIDECAR_SUFFIXES
        if (sidecar := path.with_name(path.name + suffix)).exists()
    ]


def _assert_only_active_generations(store: EventStore) -> None:
    index_generation = store._index_generation
    authority_generation = store._authority_generation
    assert isinstance(index_generation, str)
    assert isinstance(authority_generation, str)
    assert _generation_names(store.index_root) == [index_generation]
    assert _generation_names(store.authority_root) == [authority_generation]


@pytest.mark.performance
def test_commit_recovery_and_rebuild_keep_one_active_generation_with_linear_bytes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    retained_at: dict[int, int] = {}
    expected_head: str | None = None

    try:
        for batch_count in range(1, 9):
            command = _command(9400 + batch_count, expected_head)
            result = store.commit(
                command,
                auxiliary_relations=_reads_relations(
                    command["payload"]["task_id"],
                    7,
                ),
                created_at=NOW,
            )
            expected_head = result["batch_digest"]
            if batch_count in (2, 4, 8):
                retained_at[batch_count] = _retained_file_bytes(root)

        assert retained_at[2] < retained_at[4] < retained_at[8]
        growth_2_to_4 = retained_at[4] - retained_at[2]
        growth_4_to_8 = retained_at[8] - retained_at[4]
        assert growth_4_to_8 <= (growth_2_to_4 * 5) // 2
        assert retained_at[8] <= retained_at[4] * 2 + 64 * 1024

        expected_state_root = store._state_binding_digest
        expected_head_value = store.head()
        retained_before_recovery = retained_at[8]
        previous_index_generation = store._index_generation
        previous_authority_generation = store._authority_generation

        for _attempt in range(3):
            store.recover()
            assert store.head() == expected_head_value
            assert store._state_binding_digest == expected_state_root
            assert store._index_generation != previous_index_generation
            assert store._authority_generation != previous_authority_generation
            _assert_only_active_generations(store)
            assert _retained_file_bytes(root) <= (
                retained_before_recovery * 5 // 4 + 64 * 1024
            )

            state_path = store._state_binding_index_path(store._index_generation)
            state_storage = _sqlite_storage(state_path)
            assert state_storage.file_bytes == (
                state_storage.page_size * state_storage.page_count
            )
            assert state_storage.freelist_count <= 1
            _assert_no_sqlite_sidecars(state_path)
            previous_index_generation = store._index_generation
            previous_authority_generation = store._authority_generation

        disposable_path = store._state_binding_index_path(store._index_generation)
        disposable_generation = store._index_generation
    finally:
        store.close()

    # A stale physical layout is disposable.  Opening it must rebuild from the
    # authoritative journal and remove the generation that forced the rebuild.
    with closing(sqlite3.connect(disposable_path)) as connection:
        connection.execute("UPDATE binding SET version = 2 WHERE singleton = 1")
        connection.commit()

    rebuilt = _store(root)
    try:
        assert rebuilt.checkpoint_status()["open_mode"] == "full-replay-fallback"
        assert rebuilt.head() == expected_head_value
        assert rebuilt._state_binding_digest == expected_state_root
        assert rebuilt._index_generation != disposable_generation
        _assert_only_active_generations(rebuilt)
        assert not disposable_path.parent.exists()
        rebuilt_path = rebuilt._state_binding_index_path(rebuilt._index_generation)
        assert _sqlite_storage(rebuilt_path).binding_version == 3
        _assert_no_sqlite_sidecars(rebuilt_path)
        assert _retained_file_bytes(root) <= (
            retained_before_recovery * 5 // 4 + 64 * 1024
        )
    finally:
        rebuilt.close()


@pytest.mark.performance
def test_v3_set_delete_churn_reclaims_pages_and_never_retains_sidecars(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "events")
    generation = store._index_generation
    assert isinstance(generation, str)
    path = store._state_binding_index_path(generation)
    baseline = _sqlite_storage(path)
    assert baseline.binding_version == 3
    root_digest = store._genesis_state_binding_digest
    update_count = 0
    sequence = 0

    try:
        for cycle in range(6):
            sets = tuple(
                {
                    "leaf_type": "Relation",
                    "leaf_id": f"relation:retention:{cycle:02d}:{index:03d}",
                    "operation": "set",
                    "value_digest": hashlib.sha256(
                        f"{cycle}:{index}".encode("ascii")
                    ).hexdigest(),
                }
                for index in range(64)
            )
            next_root, overlay = store._stage_state_binding_delta(
                generation,
                sets,
                prior_sequence=sequence,
                prior_root_digest=root_digest,
                prior_update_count=update_count,
            )
            sequence += 1
            store._publish_state_binding_delta(
                generation,
                sequence=sequence,
                prior_root_digest=root_digest,
                prior_update_count=update_count,
                root_digest=next_root,
                delta_count=len(sets),
                overlay=overlay,
            )
            root_digest = next_root
            update_count += len(sets)
            populated = _sqlite_storage(path)
            assert populated.node_count > baseline.node_count
            assert populated.freelist_count <= 1
            _assert_no_sqlite_sidecars(path)

            deletes = tuple(
                {
                    "leaf_type": update["leaf_type"],
                    "leaf_id": update["leaf_id"],
                    "operation": "delete",
                }
                for update in sets
            )
            next_root, overlay = store._stage_state_binding_delta(
                generation,
                deletes,
                prior_sequence=sequence,
                prior_root_digest=root_digest,
                prior_update_count=update_count,
            )
            sequence += 1
            store._publish_state_binding_delta(
                generation,
                sequence=sequence,
                prior_root_digest=root_digest,
                prior_update_count=update_count,
                root_digest=next_root,
                delta_count=len(deletes),
                overlay=overlay,
            )
            root_digest = next_root
            update_count += len(deletes)

            reclaimed = _sqlite_storage(path)
            assert reclaimed.node_count == baseline.node_count
            assert reclaimed.freelist_count <= 1
            assert reclaimed.page_count <= baseline.page_count + 2
            assert reclaimed.file_bytes <= baseline.file_bytes + 2 * baseline.page_size
            assert reclaimed.file_bytes == reclaimed.page_count * reclaimed.page_size
            _assert_no_sqlite_sidecars(path)

        assert root_digest == store._genesis_state_binding_digest
    finally:
        store.close()
