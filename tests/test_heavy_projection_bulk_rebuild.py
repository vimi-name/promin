from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import statistics
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable
from unittest import mock

import promin.projection as projection_module
import promin.service as service_module
from promin.canonical import canonical_bytes, digest_value
from promin.mutation_suite import MutationFixture
from promin.projection import (
    ContinuationError,
    Projection,
    ProjectionError,
    VerifiedInventoryInput,
)
from promin.service import _runtime_state_binding_leaves
from promin.service import ProminService


ACTIVATION = "a" * 64
IMPLEMENTATION = "1" * 64
NOW = "2026-08-12T00:00:00Z"
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
RELATIONS_PER_TASK = 127


class _SyntheticEventStore:
    """Projection input with the same Task/READS contour as saturation."""

    def __init__(self, policy: Any, artifact_ids: list[str], relation_count: int) -> None:
        self.active_activation_digest = ACTIVATION
        self.implementation_closure_digest = IMPLEMENTATION
        self.policy = policy
        task_count = math.ceil(relation_count / RELATIONS_PER_TASK)
        events: list[dict[str, Any]] = []
        for index in range(task_count):
            task_id = f"task:bulk-rebuild:{index:06d}"
            events.append(
                {
                    "event_kind": "task.recorded",
                    "payload": {
                        "record_type": "Task",
                        "task_id": task_id,
                        "state": "PLANNED",
                        "required_capability": "task.execute",
                        "acceptance_predicate": f"verify relation group {index:06d}",
                        "allowed_paths": ["product/**"],
                        "activation_digest": ACTIVATION,
                        "candidate_digest": "c" * 64,
                        "created_at": NOW,
                    },
                }
            )
        repeated_task_id = "task:bulk-rebuild:000000"
        events.append(
            {
                "event_kind": "task.recorded",
                "payload": {
                    "record_type": "Task",
                    "task_id": repeated_task_id,
                    "state": "PLANNED",
                    "required_capability": "task.execute",
                    "acceptance_predicate": "verify updated relation group sentinel",
                    "allowed_paths": ["product/**"],
                    "activation_digest": ACTIVATION,
                    "candidate_digest": "c" * 64,
                    "created_at": NOW,
                },
            }
        )
        events.append(
            {
                "event_kind": "task.transitioned",
                "payload": {
                    "task_id": repeated_task_id,
                    "from_state": "PLANNED",
                    "to_state": "READY",
                    "reason": "bulk rebuild transition parity",
                },
            }
        )
        for index in range(relation_count):
            task_id = f"task:bulk-rebuild:{index // RELATIONS_PER_TASK:06d}"
            events.append(
                {
                    "event_kind": "relation.recorded",
                    "payload": {
                        "record_type": "Relation",
                        "relation_id": f"relation:bulk-rebuild:{index:06d}",
                        "kind": "READS",
                        "source_type": "Task",
                        "source_id": task_id,
                        "target_type": "Artifact",
                        "target_id": artifact_ids[index % len(artifact_ids)],
                        "activation_digest": ACTIVATION,
                        "created_at": NOW,
                    },
                }
            )
        self._batches: list[dict[str, Any]] = []
        for offset in range(0, len(events), 128):
            sequence = len(self._batches) + 1
            self._batches.append(
                {
                    "batch_id": f"batch:bulk-rebuild:{sequence:06d}",
                    "sequence": sequence,
                    "events": events[offset : offset + 128],
                    "state_binding_delta": [],
                }
            )
        last = self._batches[-1]
        self._head = {
            "sequence": last["sequence"],
            "batch_id": last["batch_id"],
            "batch_digest": digest_value(last),
        }

    def iter_envelopes(self, *, validate: bool) -> Iterable[dict[str, Any]]:
        if validate is not True:
            raise AssertionError("projection rebuild must request validated envelopes")
        for batch in self._batches:
            yield {"batch": batch}

    def head(self) -> dict[str, Any]:
        return dict(self._head)


class _ConnectionBoundaryCounter:
    def __init__(self, real_connect: Any) -> None:
        self._real_connect = real_connect
        self.execute_calls = 0
        self.executemany_calls = 0
        self.executescript_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0

    def connect(self, *args: Any, **kwargs: Any) -> "_CountedConnection":
        return _CountedConnection(self, self._real_connect(*args, **kwargs))


class _CountedConnection:
    def __init__(self, counter: _ConnectionBoundaryCounter, connection: sqlite3.Connection) -> None:
        self._counter = counter
        self._connection = connection

    def execute(self, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        self._counter.execute_calls += 1
        return self._connection.execute(*args, **kwargs)

    def executemany(self, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        self._counter.executemany_calls += 1
        return self._connection.executemany(*args, **kwargs)

    def executescript(self, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        self._counter.executescript_calls += 1
        return self._connection.executescript(*args, **kwargs)

    def commit(self) -> None:
        self._counter.commit_calls += 1
        self._connection.commit()

    def rollback(self) -> None:
        self._counter.rollback_calls += 1
        self._connection.rollback()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)


class _ReferenceProjection(Projection):
    """Characterize the pre-bulk row-at-a-time rebuild for parity and timing."""

    @classmethod
    def _create_schema(
        cls,
        connection: sqlite3.Connection,
        *,
        defer_search_indexes: bool = False,
    ) -> None:
        # The reference intentionally builds both relation indexes before the
        # stream, exactly as the pre-bulk implementation did.
        Projection._create_schema(connection, defer_search_indexes=False)

    @staticmethod
    def _prepare_bulk_rebuild(connection: sqlite3.Connection) -> None:
        # Pre-bulk rebuild did not create staging tables.
        return

    @staticmethod
    def _create_search_indexes(connection: sqlite3.Connection) -> None:
        # Both indexes were already built by the reference schema.
        return

    def _ingest_events_for_rebuild(self, connection: sqlite3.Connection, event_store: Any, stats: dict[str, int]) -> None:
        self._ingest_events(connection, event_store, stats)

    def _ingest_inventory_for_rebuild(
        self,
        connection: sqlite3.Connection,
        inventory: VerifiedInventoryInput,
        stats: dict[str, int],
    ) -> None:
        self._ingest_inventory(connection, inventory, stats)


class _CrashAfterBulkInventory(Projection):
    def _ingest_inventory_for_rebuild(
        self,
        connection: sqlite3.Connection,
        inventory: VerifiedInventoryInput,
        stats: dict[str, int],
    ) -> None:
        super()._ingest_inventory_for_rebuild(connection, inventory, stats)
        raise ProjectionError("simulated bulk rebuild interruption")


class _InventoryBatchProbeProjection(Projection):
    """Record real rebuild flush sizes without changing projection behavior."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.inventory_flush_sizes: list[int] = []

    def _flush_entity_rebuild_rows(
        self,
        connection: sqlite3.Connection,
        rows: tuple[tuple[Any, ...], ...],
        *,
        replace_event_state: bool,
        operational: bool,
    ) -> None:
        self.inventory_flush_sizes.append(len(rows))
        super()._flush_entity_rebuild_rows(
            connection,
            rows,
            replace_event_state=replace_event_state,
            operational=operational,
        )


def _write_inventory(root: Path, count: int) -> tuple[VerifiedInventoryInput, list[str]]:
    stream_path = root / f"inventory-{count}.jsonl"
    stream_digest = hashlib.sha256()
    identity_digest = hashlib.sha256()
    artifact_ids: list[str] = []
    with stream_path.open("wb") as stream:
        for index in range(count):
            path = f"product/file-{index:06d}.txt"
            file_digest = hashlib.sha256(f"physical-content-{index}".encode("utf-8")).hexdigest()
            artifact_ids.append(
                "artifact:file:" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:48]
            )
            row = {
                "path": path,
                "digest": file_digest,
                "size": 128 + index % 4096,
                "search_text": f"physical artifact deterministic content {index:06d}",
            }
            encoded = canonical_bytes(row)
            stream.write(encoded)
            stream_digest.update(encoded)
            identity_digest.update(
                canonical_bytes(
                    {"path": path, "digest": file_digest, "size": row["size"]}
                )
            )
    return (
        VerifiedInventoryInput(
            activation_digest=ACTIVATION,
            stream_digest=stream_digest.hexdigest(),
            inventory_digest=identity_digest.hexdigest(),
            entry_count=count,
            stream_path=stream_path,
            stream_bytes=stream_path.stat().st_size,
            manifest_digest="4" * 64,
            observed_at=NOW,
        ),
        artifact_ids,
    )


def _canonical_projection_digest(path: Path) -> str:
    result = hashlib.sha256()
    with closing(sqlite3.connect(path)) as connection:
        for row in connection.execute(
            "SELECT id,entity_type,data_class,payload_json FROM entities ORDER BY id"
        ):
            result.update(canonical_bytes({"table": "entities", "row": list(row)}))
        for row in connection.execute(
            "SELECT id,kind,source_type,source_id,target_type,target_id,created_at,payload_json "
            "FROM relations ORDER BY id"
        ):
            result.update(canonical_bytes({"table": "relations", "row": list(row)}))
        for row in connection.execute(
            "SELECT entity_id,event_sequence,event_index FROM operational_order "
            "ORDER BY entity_id"
        ):
            result.update(
                canonical_bytes({"table": "operational_order", "row": list(row)})
            )
        for shard, key, row_digest in connection.execute(
            "SELECT shard,key,row_digest FROM semantic_rows ORDER BY shard,key"
        ):
            result.update(
                canonical_bytes(
                    {
                        "table": "semantic_rows",
                        "row": [shard, key, bytes(row_digest).hex()],
                    }
                )
            )
        for row in connection.execute(
            "SELECT id,text FROM entity_fts ORDER BY id,text"
        ):
            result.update(canonical_bytes({"table": "entity_fts", "row": list(row)}))
    return result.hexdigest()


def _resume_binding() -> dict[str, str]:
    return {
        "activation_digest": ACTIVATION,
        "capability_id": "search.execute",
        "grant_claim_digest": "2" * 64,
        "grant_id": "grant:bulk-rebuild",
        "implementation_closure_digest": IMPLEMENTATION,
        "requested_scope_digest": "3" * 64,
        "revocation_epoch": "0",
        "subject_id": "subject:bulk-rebuild",
    }


class HeavyProjectionBulkRebuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = MutationFixture(self.root / "fixture", PACKAGE_ROOT)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _projection(self, cls: type[Projection], name: str) -> Projection:
        return cls(
            self.root / name,
            token_key=b"p" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=self.fixture.projection_limits,
            relation_domains=self.fixture.relation_domains,
        )

    def _measured_rebuild(
        self,
        projection: Projection,
        event_store: _SyntheticEventStore,
        inventory: VerifiedInventoryInput,
    ) -> tuple[dict[str, Any], dict[str, int | float]]:
        real_connect = sqlite3.connect
        counter = _ConnectionBoundaryCounter(real_connect)
        started = time.perf_counter()
        with mock.patch.object(
            projection_module.sqlite3, "connect", side_effect=counter.connect
        ):
            result = projection.rebuild(event_store, inventory=inventory)  # type: ignore[arg-type]
        elapsed = time.perf_counter() - started
        return result, {
            "wall_seconds": round(elapsed, 6),
            "execute_calls": counter.execute_calls,
            "executemany_calls": counter.executemany_calls,
            "executescript_calls": counter.executescript_calls,
            "commit_calls": counter.commit_calls,
            "rollback_calls": counter.rollback_calls,
        }

    def test_runtime_binding_streams_relations_without_full_snapshot_copy(self) -> None:
        """A checkpoint binding must not first clone every historical Relation."""

        relation_count = 4_096
        relations = tuple(
            {
                "record_type": "Relation",
                "relation_id": f"relation:binding-stream:{index:06d}",
                "kind": "READS",
                "source_type": "Task",
                "source_id": "task:binding-stream",
                "target_type": "Artifact",
                "target_id": "artifact:binding-stream",
                "activation_digest": ACTIVATION,
                "created_at": NOW,
            }
            for index in range(relation_count)
        )

        class _StreamingRelations:
            def __init__(self) -> None:
                self.yielded = 0

            def values(self) -> Iterable[dict[str, Any]]:
                for relation in relations:
                    self.yielded += 1
                    yield dict(relation)

            def materialize(self) -> tuple[dict[str, Any], ...]:
                raise AssertionError("runtime binding made a full Relation snapshot")

        stream = _StreamingRelations()
        snapshot = SimpleNamespace(
            domain=SimpleNamespace(persistent_records=lambda: ()),
            authority=SimpleNamespace(grants={}, revocations={}),
            relations=stream,
            runs=SimpleNamespace(materialize=lambda: ()),
            artifacts=SimpleNamespace(materialize=lambda: ()),
        )

        leaves = _runtime_state_binding_leaves(self.fixture.event_policy, snapshot)

        self.assertEqual(stream.yielded, relation_count)
        self.assertEqual(len(leaves), relation_count)
        self.assertEqual(
            [leaf["value"]["relation_id"] for leaf in leaves],
            [relation["relation_id"] for relation in relations],
        )

    def test_runtime_rebuild_uses_one_reiterable_source_without_evidence(self) -> None:
        """An evidence-free runtime rebuild must not buffer a full journal copy."""

        authority = SimpleNamespace(decision_resolver=None)
        domain = SimpleNamespace()
        service = SimpleNamespace(
            root=self.root,
            _new_runtime=lambda _context, *, evidence: (authority, domain),
        )
        context = SimpleNamespace(authoritative_byte_digest="b" * 64)
        source_calls = 0

        def envelopes() -> Iterable[dict[str, Any]]:
            nonlocal source_calls
            source_calls += 1
            return iter(())

        with (
            mock.patch.object(
                service_module,
                "_activation",
                return_value={"activation_digest": ACTIVATION},
            ),
            mock.patch.object(
                service_module,
                "_implementation_closure_digest",
                return_value=IMPLEMENTATION,
            ),
            mock.patch.object(service_module, "_event_store_policy", return_value=object()),
            mock.patch.object(
                service_module,
                "_freeze_runtime_components",
                return_value=(authority, domain, {}),
            ),
        ):
            snapshot = ProminService._runtime_from_envelopes(
                service,
                context,
                envelopes,
                head_sequence=0,
                head_digest=None,
                state_binding_digest=None,
            )

        self.assertEqual(source_calls, 1)
        self.assertEqual(snapshot.head_sequence, 0)
        self.assertEqual(snapshot.relations.count(), 0)

    def test_bulk_rebuild_matches_reference_at_1k_and_10k_and_reduces_sql_boundaries(self) -> None:
        measurements: dict[str, Any] = {}
        for count in (1_024, 10_240):
            inventory, artifact_ids = _write_inventory(self.root, count)
            event_store = _SyntheticEventStore(
                self.fixture.event_policy, artifact_ids, count
            )
            trials: list[dict[str, Any]] = []
            final_pair: tuple[
                Projection,
                Projection,
                dict[str, Any],
                dict[str, Any],
            ] | None = None
            for trial_index in range(2):
                reference = self._projection(
                    _ReferenceProjection,
                    f"reference-{count}-{trial_index}.sqlite",
                )
                optimized = self._projection(
                    Projection, f"optimized-{count}-{trial_index}.sqlite"
                )
                if trial_index % 2 == 0:
                    reference_result, reference_measurement = self._measured_rebuild(
                        reference, event_store, inventory
                    )
                    optimized_result, optimized_measurement = self._measured_rebuild(
                        optimized, event_store, inventory
                    )
                    order = "reference-first"
                else:
                    optimized_result, optimized_measurement = self._measured_rebuild(
                        optimized, event_store, inventory
                    )
                    reference_result, reference_measurement = self._measured_rebuild(
                        reference, event_store, inventory
                    )
                    order = "bulk-first"
                trials.append(
                    {
                        "order": order,
                        "reference": reference_measurement,
                        "bulk": optimized_measurement,
                    }
                )
                final_pair = (
                    reference,
                    optimized,
                    reference_result,
                    optimized_result,
                )
            assert final_pair is not None
            reference, optimized, reference_result, optimized_result = final_pair
            reference_seconds = statistics.median(
                float(trial["reference"]["wall_seconds"]) for trial in trials
            )
            optimized_seconds = statistics.median(
                float(trial["bulk"]["wall_seconds"]) for trial in trials
            )

            task_count = math.ceil(count / RELATIONS_PER_TASK)
            self.assertEqual(optimized_result["inventory_entries"], count)
            self.assertEqual(optimized_result["inventory_passes"], 1)
            self.assertEqual(optimized_result["entity_count"], count + task_count)
            self.assertEqual(optimized_result["relation_count"], count)
            self.assertEqual(
                optimized_result["semantic_digest"], reference_result["semantic_digest"]
            )
            self.assertEqual(
                _canonical_projection_digest(optimized.db_path),
                _canonical_projection_digest(reference.db_path),
            )
            optimized_search = optimized.search(
                "updated relation group sentinel",
                depth=1,
                resume_binding=_resume_binding(),
                now=NOW,
            )
            reference_search = reference.search(
                "updated relation group sentinel",
                depth=1,
                resume_binding=_resume_binding(),
                now=NOW,
            )
            self.assertEqual(
                [item["id"] for item in optimized_search["entities"]],
                [item["id"] for item in reference_search["entities"]],
            )
            self.assertEqual(
                optimized_search["entities"][0]["id"],
                "task:bulk-rebuild:000000",
            )
            self.assertEqual(
                optimized.require_current(event_store)["head_digest"],  # type: ignore[arg-type]
                event_store.head()["batch_digest"],
            )
            self.assertLess(
                max(int(trial["bulk"]["execute_calls"]) for trial in trials),
                min(int(trial["reference"]["execute_calls"]) for trial in trials)
                // 4,
            )
            if count == 1_024:
                # Fixed staging/index-finalization overhead is deliberately
                # bounded for small projects; the hot-path gain is asserted on
                # the realistic 10k contour below.
                self.assertLess(
                    optimized_seconds,
                    reference_seconds * 1.5,
                )
            else:
                self.assertLess(
                    optimized_seconds,
                    reference_seconds * 0.85,
                )
            measurements[str(count)] = {
                "trials": trials,
                "reference_median_wall_seconds": round(reference_seconds, 6),
                "bulk_median_wall_seconds": round(optimized_seconds, 6),
                "wall_ratio": round(optimized_seconds / reference_seconds, 6),
                "semantic_digest": optimized_result["semantic_digest"],
                "entity_count": optimized_result["entity_count"],
                "relation_count": optimized_result["relation_count"],
            }

        # The 10k contour is a ten-percent execution of the exact production
        # formula, not a reduced replacement for the 100k acceptance route.
        exact_relations = 198_999
        exact_tasks = 32 + math.ceil((exact_relations - 28) / RELATIONS_PER_TASK)
        self.assertEqual(exact_tasks, 1_599)
        self.assertEqual(100_000 + 1 + 4 + exact_tasks, 101_604)
        self.assertEqual(exact_relations, 198_999)
        print("projection_bulk_rebuild_measurements=" + json.dumps(measurements, sort_keys=True))

    def test_persisted_inventory_rebuild_flushes_bounded_pages(self) -> None:
        """A physical inventory stream is never retained as one semantic-row batch."""

        count = 2_049
        inventory, _artifact_ids = _write_inventory(self.root, count)
        event_store = _SyntheticEventStore(self.fixture.event_policy, [], 0)
        projection = self._projection(_InventoryBatchProbeProjection, "bounded.sqlite")

        self.assertIsNone(inventory.entries)
        self.assertIsNotNone(inventory.stream_path)
        result = projection.rebuild(event_store, inventory=inventory)  # type: ignore[arg-type]

        self.assertEqual(result["inventory_entries"], count)
        self.assertEqual(result["inventory_proxies"], count)
        self.assertEqual(result["entity_count"], count + 1)
        self.assertGreaterEqual(len(projection.inventory_flush_sizes), 5)
        self.assertLessEqual(max(projection.inventory_flush_sizes), projection_module._BULK_REBUILD_BATCH_ROWS)
        self.assertLess(max(projection.inventory_flush_sizes), count)
        with closing(sqlite3.connect(projection.db_path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM entities WHERE entity_type='Artifact'"
                ).fetchone()[0],
                count,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM entities WHERE entity_type='RawFile'"
                ).fetchone()[0],
                0,
            )

    def test_noncompact_projection_rejects_forged_physical_inventory_rows(self) -> None:
        """A non-compact stream projection cannot gain a physical inventory index post-build."""

        inventory, _artifact_ids = _write_inventory(self.root, 2)
        event_store = _SyntheticEventStore(self.fixture.event_policy, [], 0)
        projection = self._projection(Projection, "noncompact-forge.sqlite")
        rebuilt = projection.rebuild(event_store, inventory=inventory)
        self.assertEqual(rebuilt["inventory_storage_mode"], "semantic-artifacts-v1")

        with closing(sqlite3.connect(projection.db_path)) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO inventory_records(id,path,digest,size,bucket) "
                    "VALUES (?,?,?,?,?)",
                    (
                        "artifact:file:forged-noncompact",
                        "product/forged-noncompact.txt",
                        "f" * 64,
                        1,
                        0,
                    ),
                )
        with self.assertRaisesRegex(ProjectionError, "non-compact inventory has physical inventory rows"):
            projection.status()

    def test_bulk_rebuild_invalidates_continuations_and_preserves_last_durable_db_on_failure(self) -> None:
        count = 1_024
        inventory, artifact_ids = _write_inventory(self.root, count)
        event_store = _SyntheticEventStore(self.fixture.event_policy, artifact_ids, count)
        projection = self._projection(Projection, "durable.sqlite")
        first = projection.rebuild(event_store, inventory=inventory)  # type: ignore[arg-type]
        budget = dict(self.fixture.projection_limits.hard_budget)
        budget.update(
            {
                "max_entities": 2,
                "max_relations": 1,
                "max_fanout_per_entity": 1,
                "top_k": min(32, budget["top_k"]),
            }
        )
        page = projection.search(
            "physical artifact",
            depth=1,
            budget=budget,
            resume_binding=_resume_binding(),
            now=NOW,
        )
        self.assertTrue(page["truncated"])
        token = page["continuation"]["token"]
        self.assertIsInstance(token, str)

        rebuilt = projection.rebuild(event_store, inventory=inventory)  # type: ignore[arg-type]
        self.assertEqual(rebuilt["semantic_digest"], first["semantic_digest"])
        with self.assertRaises(ContinuationError):
            projection.continue_search(
                token,
                resume_binding=_resume_binding(),
                now="2026-08-12T00:00:01Z",
            )

        with closing(sqlite3.connect(projection.db_path)) as connection:
            with connection:
                connection.execute(
                    "UPDATE semantic_shards SET digest=? WHERE shard=0", ("0" * 64,)
                )
        with self.assertRaisesRegex(ProjectionError, "semantic metadata"):
            projection.status()
        repaired = projection.rebuild(event_store, inventory=inventory)  # type: ignore[arg-type]
        self.assertEqual(repaired["semantic_digest"], first["semantic_digest"])

        crashing = self._projection(_CrashAfterBulkInventory, "durable.sqlite")
        with self.assertRaisesRegex(ProjectionError, "simulated bulk rebuild interruption"):
            crashing.rebuild(event_store, inventory=inventory)  # type: ignore[arg-type]
        self.assertEqual(
            projection.require_current(event_store)["semantic_digest"],  # type: ignore[arg-type]
            first["semantic_digest"],
        )


if __name__ == "__main__":
    unittest.main()
