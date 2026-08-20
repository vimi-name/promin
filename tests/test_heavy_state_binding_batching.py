from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from test_heavy_event_batching import (
    NOW,
    POLICY,
    _command,
    _reads_relations,
    _store,
)
from promin.events import state_binding_leaf_id


def _batch_relations(batch_index: int) -> list[dict[str, object]]:
    """Return one exact maximum READS payload with globally unique leaves."""

    task_id = f"task:batch:{batch_index:04d}"
    values: list[dict[str, object]] = []
    for offset, relation in enumerate(_reads_relations(task_id, 127)):
        value = dict(relation)
        value["relation_id"] = f"relation:compact:{batch_index:04d}:{offset:03d}"
        value["target_id"] = f"artifact:compact:{batch_index:04d}:{offset:03d}"
        values.append(value)
    return values


def test_relation_batches_use_compact_leaf_buckets_without_changing_root_or_replay(
    tmp_path: Path,
) -> None:
    """READS leaves stay individual while derived index state stays compact."""

    root = tmp_path / "events"
    store = _store(root)
    leaves: list[dict[str, object]] = []
    expected_digest: str | None = None
    try:
        for batch_index in range(1, 9):
            command = _command(batch_index, store.head()["batch_digest"])
            relations = _batch_relations(batch_index)
            result = store.commit(
                command,
                auxiliary_relations=relations,
                created_at=NOW,
            )
            assert result["outcome"] == "committed"
            leaves.append({"leaf_type": "Task", "value": dict(command["payload"])})
            leaves.extend(
                {"leaf_type": "Relation", "value": dict(relation)}
                for relation in relations
            )
            expected_digest = store.read_envelope(result["batch_digest"])["batch"][
                "state_binding_digest"
            ]

        assert expected_digest is not None
        ordered_leaves = sorted(
            leaves,
            key=lambda leaf: (
                str(leaf["leaf_type"]),
                state_binding_leaf_id(
                    POLICY, str(leaf["leaf_type"]), leaf["value"]
                ),
            ),
        )
        assert (
            store.validate_state_binding_leaves(ordered_leaves, expected_head=store.head())
            == expected_digest
        )
        generation = store._index_generation
        assert isinstance(generation, str)
        path = store._state_binding_index_path(generation)
        with closing(sqlite3.connect(path)) as connection:
            leaf_count = connection.execute(
                "SELECT count(*) FROM compact_leaf"
            ).fetchone()[0]
            bucket_count = connection.execute(
                "SELECT count(*) FROM compact_bucket"
            ).fetchone()[0]
            node_count = connection.execute("SELECT count(*) FROM node").fetchone()[0]
            page_bytes = (
                connection.execute("PRAGMA page_count").fetchone()[0]
                * connection.execute("PRAGMA page_size").fetchone()[0]
            )
        assert leaf_count == 1 + len(leaves)  # immutable Activation plus exact leaves
        assert 1 <= bucket_count <= leaf_count
        # Exact individual leaf witnesses are retained for touched-path
        # recovery, but the 30 lower intermediate levels are not.
        assert node_count < leaf_count * 2
        assert page_bytes < 4 * 1024 * 1024
    finally:
        store.close()

    reopened = _store(root)
    try:
        assert reopened.head()["sequence"] == 8
        assert (
            reopened.validate_state_binding_leaves(
                ordered_leaves,
                expected_head=reopened.head(),
            )
            == expected_digest
        )
    finally:
        reopened.close()
