from __future__ import annotations

import hashlib
import random
import sqlite3
from collections.abc import Callable
from pathlib import Path

from promin.events import (
    _STATE_BINDING_STORAGE_STRIDE,
    _STATE_DEFAULT_DIGESTS,
    _STATE_TREE_DEPTH,
    _state_binding_root_from_leaves,
    _state_leaf_key_digest,
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


def _updates(count: int = 128) -> tuple[dict[str, str], ...]:
    values = [
        {
            "leaf_type": "Relation",
            "leaf_id": f"relation:batch-union:{index:04d}",
            "operation": "set",
            "value_digest": hashlib.sha256(
                f"batch-union-value:{index:04d}".encode("ascii")
            ).hexdigest(),
        }
        for index in range(count)
    ]
    return tuple(sorted(values, key=lambda value: (value["leaf_type"], value["leaf_id"])))


def _trace_state_connections(
    store: object,
) -> tuple[list[str], Callable[[], None]]:
    statements: list[str] = []
    original = store._state_binding_connection  # type: ignore[attr-defined]

    def traced(generation: str, *, create: bool = False) -> sqlite3.Connection:
        connection = original(generation, create=create)
        connection.set_trace_callback(statements.append)
        return connection

    store._state_binding_connection = traced  # type: ignore[attr-defined]

    def restore() -> None:
        store._state_binding_connection = original  # type: ignore[attr-defined]

    return statements, restore


def _affected_storage_identities(
    updates: tuple[dict[str, str], ...],
) -> set[tuple[int, bytes]]:
    keys = {_state_leaf_key_digest(update) for update in updates}
    return {
        (depth, key[: depth // _STATE_BINDING_STORAGE_STRIDE])
        for depth in range(
            0,
            _STATE_TREE_DEPTH + _STATE_BINDING_STORAGE_STRIDE,
            _STATE_BINDING_STORAGE_STRIDE,
        )
        for key in keys
    }


def test_128_leaf_stage_uses_one_path_union_and_preserves_exact_root(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "events")
    generation = store._index_generation
    assert isinstance(generation, str)
    updates = _updates()
    affected = _affected_storage_identities(updates)
    try:
        first_root, first_overlay = store._stage_state_binding_delta(
            generation,
            updates,
            prior_sequence=0,
            prior_root_digest=store._genesis_state_binding_digest,
            prior_update_count=0,
        )
        store._publish_state_binding_delta(
            generation,
            sequence=1,
            prior_root_digest=store._genesis_state_binding_digest,
            prior_update_count=0,
            root_digest=first_root,
            delta_count=len(updates),
            overlay=first_overlay,
        )
        changed_updates = tuple(
            {
                **update,
                "value_digest": hashlib.sha256(
                    f"changed:{index:04d}".encode("ascii")
                ).hexdigest(),
            }
            for index, update in enumerate(updates)
        )
        statements, restore = _trace_state_connections(store)
        storage_rows_read = -1
        original_union = store._state_storage_union_rows

        def traced_union(
            connection: sqlite3.Connection,
            keys: object,
        ) -> dict[tuple[int, bytes], tuple[bytes, dict[int, bytes]]]:
            nonlocal storage_rows_read
            result = original_union(connection, keys)  # type: ignore[arg-type]
            storage_rows_read = len(result)
            return result

        store._state_storage_union_rows = traced_union
        try:
            root_digest, overlay = store._stage_state_binding_delta(
                generation,
                changed_updates,
                prior_sequence=1,
                prior_root_digest=first_root,
                prior_update_count=len(updates),
            )
        finally:
            store._state_storage_union_rows = original_union
            restore()
    finally:
        store.close()

    node_selects = [
        statement
        for statement in statements
        if statement.lstrip().upper().startswith(("SELECT", "WITH"))
        and " NODE " in f" {statement.upper()} "
    ]
    expected_root = _state_binding_root_from_leaves(
        (
            {
                "leaf_type": "Activation",
                "leaf_id": ACTIVATION,
                "value_digest": ACTIVATION_RECORD_DIGEST,
            },
            *changed_updates,
        )
    )
    assert root_digest == expected_root
    assert set(overlay) == affected
    assert storage_rows_read == len(affected)
    assert len(node_selects) == 1
    assert len(overlay) < len(updates) * (
        _STATE_TREE_DEPTH // _STATE_BINDING_STORAGE_STRIDE + 1
    )
    assert overlay[(0, b"")][0] != _STATE_DEFAULT_DIGESTS[0]


def test_path_union_randomized_set_delete_and_shared_prefixes_match_reference(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "events")
    generation = store._index_generation
    assert isinstance(generation, str)
    reference: dict[tuple[str, str], str] = {
        ("Activation", ACTIVATION): ACTIVATION_RECORD_DIGEST
    }
    prior_root = store._genesis_state_binding_digest
    prior_count = 0
    sequence = 0
    randomizer = random.Random(0xA4_BA7C)
    try:
        for batch_index in range(12):
            updates: list[dict[str, str]] = []
            # The common textual stem intentionally exercises many candidate
            # identities; SHA-256 key derivation independently decides actual
            # byte-prefix collisions.
            for item_index in randomizer.sample(range(256), 96):
                identity = ("Relation", f"relation:union:shared:{item_index:03d}")
                if identity in reference and randomizer.random() < 0.45:
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
            next_root, overlay = store._stage_state_binding_delta(
                generation,
                tuple(updates),
                prior_sequence=sequence,
                prior_root_digest=prior_root,
                prior_update_count=prior_count,
            )
            assert next_root == _state_binding_root_from_leaves(
                {
                    "leaf_type": leaf_type,
                    "leaf_id": leaf_id,
                    "value_digest": value_digest,
                }
                for (leaf_type, leaf_id), value_digest in sorted(reference.items())
            )
            sequence += 1
            store._publish_state_binding_delta(
                generation,
                sequence=sequence,
                prior_root_digest=prior_root,
                prior_update_count=prior_count,
                root_digest=next_root,
                delta_count=len(updates),
                overlay=overlay,
            )
            prior_root = next_root
            prior_count += len(updates)
    finally:
        store.close()


def test_path_union_128_event_crash_reopen_and_idempotent_replay(
    tmp_path: Path,
) -> None:
    root = tmp_path / "events"
    command = _command(9701)
    relations = _reads_relations(command["payload"]["task_id"], 127)
    store = _store(root)
    try:
        from promin.events import SimulatedCrash

        try:
            store.commit(
                command,
                auxiliary_relations=relations,
                created_at=NOW,
                crash_hook=lambda point: point == "after_batch",
            )
        except SimulatedCrash:
            pass
        else:
            raise AssertionError("crash hook did not interrupt the 128-event commit")
    finally:
        store.close()

    reopened = _store(root)
    try:
        envelope = reopened.read_envelope(reopened.head()["batch_digest"])
        assert len(envelope["batch"]["state_binding_delta"]) == 128
        assert (
            reopened.validate_state_binding_leaves(
                _restored_leaves(command, relations),
                expected_head=reopened.head(),
            )
            == envelope["batch"]["state_binding_digest"]
        )
        assert (
            reopened.commit(
                command,
                auxiliary_relations=relations,
                created_at=NOW,
            )["outcome"]
            == "idempotent-replay"
        )
    finally:
        reopened.close()
