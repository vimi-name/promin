from __future__ import annotations

import hashlib
import random
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from promin.events import (
    _STATE_DEFAULT_DIGESTS,
    DerivedCheckpointError,
    _state_binding_root_from_leaves,
    _decode_state_storage_children,
    _encode_state_storage_children,
    _state_storage_parent_digest,
)
from test_heavy_event_batching import (
    ACTIVATION,
    ACTIVATION_RECORD_DIGEST,
    NOW,
    _command,
    _reads_relations,
    _restored_leaves,
    _store,
)


def _reference_root(values: dict[tuple[str, str], str]) -> str:
    return _state_binding_root_from_leaves(
        {
            "leaf_type": leaf_type,
            "leaf_id": leaf_id,
            "value_digest": value_digest,
        }
        for (leaf_type, leaf_id), value_digest in sorted(values.items())
    )


def test_byte_boundary_storage_matches_full_binary_root_for_random_set_delete(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "events")
    generation = store._index_generation
    assert isinstance(generation, str)
    reference: dict[tuple[str, str], str] = {
        ("Activation", ACTIVATION): ACTIVATION_RECORD_DIGEST
    }
    prior_root = store._genesis_state_binding_digest
    prior_update_count = 0
    sequence = 0
    randomizer = random.Random(0xA4_100_000)

    try:
        for batch_index in range(16):
            updates: list[dict[str, str]] = []
            selected = randomizer.sample(range(512), 64)
            for item_index in selected:
                identity = ("Relation", f"relation:storage:{item_index:04d}")
                if identity in reference and randomizer.random() < 0.35:
                    updates.append(
                        {
                            "leaf_type": identity[0],
                            "leaf_id": identity[1],
                            "operation": "delete",
                        }
                    )
                    reference.pop(identity)
                else:
                    value_digest = hashlib.sha256(
                        f"{batch_index}:{item_index}".encode("ascii")
                    ).hexdigest()
                    updates.append(
                        {
                            "leaf_type": identity[0],
                            "leaf_id": identity[1],
                            "operation": "set",
                            "value_digest": value_digest,
                        }
                    )
                    reference[identity] = value_digest
            updates.sort(key=lambda value: (value["leaf_type"], value["leaf_id"]))
            root_digest, overlay = store._stage_state_binding_delta(
                generation,
                tuple(updates),
                prior_sequence=sequence,
                prior_root_digest=prior_root,
                prior_update_count=prior_update_count,
            )
            assert root_digest == _reference_root(reference)
            sequence += 1
            store._publish_state_binding_delta(
                generation,
                sequence=sequence,
                prior_root_digest=prior_root,
                prior_update_count=prior_update_count,
                root_digest=root_digest,
                delta_count=len(updates),
                overlay=overlay,
            )
            prior_root = root_digest
            prior_update_count += len(updates)

        path = store._state_binding_index_path(generation)
        with closing(sqlite3.connect(path)) as connection:
            stored_nodes = connection.execute("SELECT COUNT(*) FROM node").fetchone()[0]
            depths = {
                row[0]
                for row in connection.execute("SELECT DISTINCT depth FROM node")
            }
            binding = connection.execute(
                "SELECT version, algorithm, head_sequence, update_count, root_digest "
                "FROM binding WHERE singleton=1"
            ).fetchone()
        assert depths <= set(range(0, 257, 8))
        assert stored_nodes <= len(reference) * 33 + 1
        assert binding == (
            3,
            "typed-sparse-merkle-v1",
            sequence,
            prior_update_count,
            prior_root,
        )
        assert path.stat().st_size < 32 * 1024 * 1024
    finally:
        store.close()


@pytest.mark.parametrize("old_version", (1, 2))
def test_old_derived_index_rebuilds_to_v3_without_changing_authoritative_root(
    tmp_path: Path,
    old_version: int,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    command = _command(9100)
    relations = _reads_relations(command["payload"]["task_id"], 31)
    try:
        result = store.commit(command, auxiliary_relations=relations, created_at=NOW)
        expected_root = store.validate_state_binding_leaves(
            _restored_leaves(command, relations),
            expected_head=store.head(),
        )
        generation = store._index_generation
        assert isinstance(generation, str)
        path = store._state_binding_index_path(generation)
    finally:
        store.close()

    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            "UPDATE binding SET version=? WHERE singleton=1",
            (old_version,),
        )
        connection.commit()

    reopened = _store(root)
    try:
        assert reopened.head()["batch_digest"] == result["batch_digest"]
        assert (
            reopened.validate_state_binding_leaves(
                _restored_leaves(command, relations),
                expected_head=reopened.head(),
            )
            == expected_root
        )
        rebuilt_generation = reopened._index_generation
        assert isinstance(rebuilt_generation, str)
        with closing(
            sqlite3.connect(reopened._state_binding_index_path(rebuilt_generation))
        ) as connection:
            binding = connection.execute(
                "SELECT version, algorithm, root_digest FROM binding WHERE singleton=1"
            ).fetchone()
        assert binding == (3, "typed-sparse-merkle-v1", expected_root)
    finally:
        reopened.close()


def test_root_child_payload_tamper_rebuilds_disposable_index(
    tmp_path: Path,
) -> None:
    root = tmp_path / "events"
    store = _store(root)
    command = _command(9200)
    relations = _reads_relations(command["payload"]["task_id"], 17)
    try:
        result = store.commit(command, auxiliary_relations=relations, created_at=NOW)
        expected_root = store.validate_state_binding_leaves(
            _restored_leaves(command, relations),
            expected_head=store.head(),
        )
        generation = store._index_generation
        assert isinstance(generation, str)
        path = store._state_binding_index_path(generation)
    finally:
        store.close()

    with closing(sqlite3.connect(path)) as connection:
        row = connection.execute(
            "SELECT digest, children FROM node WHERE depth = 0 AND prefix = ?",
            (b"",),
        ).fetchone()
        assert row is not None
        stored_root, children_payload = row
        children = _decode_state_storage_children(children_payload)
        unused_edge = next(edge for edge in range(256) if edge not in children)
        children[unused_edge] = _STATE_DEFAULT_DIGESTS[8]
        aliased_payload = _encode_state_storage_children(children)
        assert aliased_payload != children_payload
        assert stored_root.hex() == expected_root
        assert _state_storage_parent_digest(0, children) == stored_root
        connection.execute(
            "UPDATE node SET children = ? WHERE depth = 0 AND prefix = ?",
            (aliased_payload, b""),
        )
        connection.commit()

    reopened = _store(root)
    try:
        assert reopened.head()["batch_digest"] == result["batch_digest"]
        assert reopened._index_generation != generation
        assert (
            reopened.validate_state_binding_leaves(
                _restored_leaves(command, relations),
                expected_head=reopened.head(),
            )
            == expected_root
        )
    finally:
        reopened.close()


def test_publication_rejects_overlay_root_binding_mismatch(tmp_path: Path) -> None:
    store = _store(tmp_path / "events")
    generation = store._index_generation
    assert isinstance(generation, str)
    update = {
        "leaf_type": "Relation",
        "leaf_id": "relation:storage:root-mismatch",
        "operation": "set",
        "value_digest": hashlib.sha256(b"root-mismatch").hexdigest(),
    }
    try:
        computed_root, overlay = store._stage_state_binding_delta(
            generation,
            (update,),
            prior_sequence=0,
            prior_root_digest=store._genesis_state_binding_digest,
            prior_update_count=0,
        )
        assert computed_root != "0" * 64
        with pytest.raises(
            DerivedCheckpointError,
            match="overlay root differs from publication binding",
        ):
            store._publish_state_binding_delta(
                generation,
                sequence=1,
                prior_root_digest=store._genesis_state_binding_digest,
                prior_update_count=0,
                root_digest="0" * 64,
                delta_count=1,
                overlay=overlay,
            )
        store._validate_state_binding_index(
            generation,
            head_sequence=0,
            update_count=0,
            root_digest=store._genesis_state_binding_digest,
        )
    finally:
        store.close()
