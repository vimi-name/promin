from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any, Mapping

import pytest

import promin.projection as projection_module
from promin.projection import Projection
from tools import promin_projection_profile as profile


def _projection(tmp_path: Path, name: str) -> Projection:
    contracts = profile._compile_runtime_contracts()
    return Projection(
        tmp_path / name / "promin.sqlite3",
        profile.TOKEN_KEY,
        implementation_closure_digest=profile.IMPLEMENTATION_CLOSURE_DIGEST,
        limits=contracts.projection_limits,
        relation_domains=contracts.relation_domains,
    )


def _semantic_location(key: str) -> tuple[int, int]:
    """The stable first two SHA-256 bytes select a shard and leaf bucket."""

    digest = hashlib.sha256(key.encode("utf-8")).digest()
    return digest[0], digest[1]


def _semantic_keys(path: Path) -> set[str]:
    with sqlite3.connect(path) as connection:
        return {
            str(row[0])
            for row in connection.execute("SELECT key FROM semantic_rows")
        }


def test_incremental_127_reads_rehashes_only_changed_leaf_rows_and_matches_rebuild(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 127-READS tail must not replay unchanged rows from affected shards."""

    contracts = profile._compile_runtime_contracts()
    inventory, _manifest = profile._build_inventory_stream(tmp_path, 512)
    store, _events = profile._build_event_stream(tmp_path, 512, contracts)
    projection = _projection(tmp_path, "incremental")
    try:
        projection.rebuild(store, inventory=inventory)
        expected_head = store.head()["batch_digest"]
        task = profile._task(1_000_000, expected_head)
        relations = tuple(
            profile._relation(
                1_000_000 + index,
                source_id=task["task_id"],
                target_index=index % 512,
            )
            for index in range(127)
        )
        assert len(relations) == 127
        store.commit(
            profile._command(1_000_000, task, expected_head),
            auxiliary_relations=relations,
            created_at=profile.CREATED_AT,
        )

        changed_keys = {
            "entity:" + task["task_id"],
            *(
                "relation:" + str(relation["relation_id"])
                for relation in relations
            ),
        }
        changed_locations = {_semantic_location(key) for key in changed_keys}

        # Observe the preimage that is actually serialized into every semantic
        # leaf commitment.  It is a stable functional seam: the complete
        # semantic digest is derived from these committed row digests.
        serialized_rows: list[tuple[int, tuple[str, ...]]] = []
        original_digest_value = projection_module.digest_value

        def observe_semantic_leaf(value: Any) -> str:
            if (
                isinstance(value, Mapping)
                and value.get("algorithm")
                == projection_module._SEMANTIC_DIGEST_ALGORITHM
                and "rows" in value
            ):
                serialized_rows.append(
                    (
                        int(value["shard"]),
                        tuple(str(row["key"]) for row in value["rows"]),
                    )
                )
            return original_digest_value(value)

        monkeypatch.setattr(projection_module, "digest_value", observe_semantic_leaf)
        updated = projection.apply_committed_batch(store)
        assert updated["status"] == "updated"

        all_keys = _semantic_keys(projection.db_path)
        expected_leaf_keys = {
            key
            for key in all_keys
            if _semantic_location(key) in changed_locations
        }
        changed_shards = {shard for shard, _bucket in changed_locations}
        full_shard_keys = {
            key
            for key in all_keys
            if _semantic_location(key)[0] in changed_shards
        }
        observed_leaf_keys = {
            key for _shard, keys in serialized_rows for key in keys
        }

        # The exact changed buckets are the only row sequences that may be
        # reserialized/rehashed.  In particular, an unchanged row in the same
        # root shard but a different leaf bucket must stay cached.
        assert observed_leaf_keys == expected_leaf_keys
        assert changed_keys <= observed_leaf_keys
        assert len(serialized_rows) == len(changed_locations)
        assert full_shard_keys - expected_leaf_keys
        assert len(observed_leaf_keys) < len(full_shard_keys)

        rebuilt = _projection(tmp_path, "rebuilt").rebuild(store, inventory=inventory)
        assert projection.semantic_digest() == rebuilt["semantic_digest"]
        assert projection.require_current(store)["semantic_digest"] == rebuilt[
            "semantic_digest"
        ]
    finally:
        store.close()
