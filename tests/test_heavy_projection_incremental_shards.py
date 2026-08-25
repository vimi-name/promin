from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

import pytest

from promin.contracts import validate_definition
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


def test_inventory_rebuild_is_deterministic_and_fails_closed_on_stream_corruption(
    tmp_path: Path,
) -> None:
    """The bounded physical stream has one stable digest and no partial publish."""

    contracts = profile._compile_runtime_contracts()
    inventory, manifest = profile._build_inventory_stream(tmp_path, 1_025)
    store, _events = profile._build_event_stream(tmp_path, 1, contracts)
    first = _projection(tmp_path, "first")
    second = _projection(tmp_path, "second")
    try:
        first_result = first.rebuild(store, inventory=inventory)
        second_result = second.rebuild(store, inventory=inventory)

        assert first_result["inventory_entries"] == 1_025
        assert first_result["inventory_proxies"] == 1_025
        assert first_result["semantic_digest"] == second_result["semantic_digest"]
        assert first_result["semantic_digest"] == first.semantic_digest()
        assert manifest["stream_digest"] == inventory.stream_digest
        assert manifest["inventory_digest"] == inventory.inventory_digest

        assert inventory.stream_path is not None
        original = inventory.stream_path.read_bytes()
        corrupted = original.replace(
            b"projection profile synthetic source 00000100",
            b"projection profile corrupted source 00000100",
            1,
        )
        assert len(corrupted) == len(original)
        inventory.stream_path.write_bytes(corrupted)
        try:
            with pytest.raises(projection_module.ProjectionError, match="stream digest mismatch"):
                first.rebuild(store, inventory=inventory)
        finally:
            inventory.stream_path.write_bytes(original)

        assert first.semantic_digest() == first_result["semantic_digest"]
        assert first.require_current(store)["semantic_digest"] == first_result[
            "semantic_digest"
        ]
    finally:
        store.close()


def test_compact_physical_task_artifact_endpoint_is_exact_path_bound_and_typed(
    tmp_path: Path,
) -> None:
    """Compact physical inventory resolves through the public typed-closure route."""

    contracts = profile._compile_runtime_contracts()
    inventory, _manifest = profile._build_inventory_stream(tmp_path, 4)
    compact_inventory = replace(inventory, retain_artifact_entities=False)
    store, _events = profile._build_event_stream(tmp_path, 1, contracts)
    projection = _projection(tmp_path, "compact-endpoint")
    task = profile._task(700, store.head()["batch_digest"])
    store.commit(
        profile._command(
            700,
            task,
            store.head()["batch_digest"],
        ),
        auxiliary_relations=(
            profile._relation(
                700,
                source_id=task["task_id"],
                target_index=0,
            ),
        ),
        created_at=profile.CREATED_AT,
    )
    try:
        rebuilt = projection.rebuild(store, inventory=compact_inventory)
        binding = {
            field: f"compact-endpoint-{index}"
            for index, field in enumerate(projection.limits.required_resume_binding_fields)
        }
        task_page = projection.search(
            task["task_id"],
            depth=1,
            resume_binding=binding,
            now=profile.CREATED_AT,
        )
        validate_definition(contracts.schema, "RetrievalPage", task_page)
        artifact_id = profile._artifact_id(0)
        artifact_path = "product/record-00000000.txt"
        artifact_digest = hashlib.sha256(
            b"projection-profile-payload-00000000"
        ).hexdigest()

        assert rebuilt["inventory_storage_mode"] == "physical-inventory-buckets-v1"
        assert task_page["depth"] == 1
        assert task_page["truncated"] is False
        assert {row["id"] for row in task_page["entities"]} == {
            task["task_id"],
            artifact_id,
        }
        artifact = next(row for row in task_page["entities"] if row["id"] == artifact_id)
        assert artifact["entity_type"] == "Artifact"
        assert artifact["data_class"] == "untrusted-source"
        assert artifact["payload"]["inventory_path"] == artifact_path
        assert artifact["payload"]["digest"] == artifact_digest
        assert task_page["relations"][0]["source_id"] == task["task_id"]
        assert task_page["relations"][0]["target_id"] == artifact_id

        with sqlite3.connect(projection.db_path) as connection:
            assert connection.execute(
                "SELECT COUNT(*) FROM entities WHERE id=? AND entity_type='Artifact'",
                (artifact_id,),
            ).fetchone()[0] == 0
            assert connection.execute(
                "SELECT COUNT(*) FROM entity_fts WHERE id=?", (artifact_id,)
            ).fetchone()[0] == 0
            assert connection.execute(
                "SELECT COUNT(*) FROM semantic_rows WHERE key=? OR key LIKE ?",
                (artifact_id, f"%{artifact_id}"),
            ).fetchone()[0] == 0

        exact_path = projection.search(
            artifact_path,
            depth=1,
            resume_binding=binding,
            now=profile.CREATED_AT,
        )
        assert exact_path["entities"][0]["id"] == artifact_id
        assert artifact_id in {row["id"] for row in exact_path["entities"]}
        assert exact_path["entities"][0]["payload"]["digest"] == artifact_digest
        assert projection.search(
            "product/record-00000000-corrupted.txt",
            depth=1,
            resume_binding=binding,
            now=profile.CREATED_AT,
        )["entities"] == []
    finally:
        store.close()
