"""Disposable SQLite projection, typed closure search, and continuations."""

from __future__ import annotations

import base64
import copy
from collections import OrderedDict, deque
import contextlib
import datetime as _datetime
import functools
import hashlib
import hmac
import itertools
import json
import os
import re
import sqlite3
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence

from .canonical import (
    CanonicalError,
    ParseLimits,
    canonical_bytes,
    digest_value,
    format_utc_second,
    parse_json_strict,
)
from .events import (
    EventStore,
    EventStoreError,
    EventStorePolicy,
    parse_timestamp,
    state_binding_leaf_id,
    utc_now,
)
from .platform_paths import filesystem_path, sqlite_path


_BUDGET_FIELDS = frozenset(
    {"max_bytes", "max_entities", "max_relations", "max_fanout_per_entity", "top_k"}
)
# Match one unicode61-compatible word at a time. Punctuation and underscore
# must split terms because FTS5 detail=none cannot evaluate phrase queries.
_QUERY_TOKEN = re.compile(r"[^\W_]+", re.UNICODE)
_DIGEST = re.compile(r"[0-9a-f]{64}")
_SEMANTIC_SHARD_COUNT = 256
_SEMANTIC_DIGEST_ALGORITHM = "semantic-shards-v2"
_PROJECTION_STORAGE_LAYOUT = "semantic-row-digest-commitment-v4"
_SEMANTIC_BUCKET_COUNT = 256
_SEMANTIC_GROUP_WIDTH = 16
_SEMANTIC_GROUP_COUNT = _SEMANTIC_BUCKET_COUNT // _SEMANTIC_GROUP_WIDTH
_BULK_REBUILD_BATCH_ROWS = 512
_BULK_SQL_VALUE_ROWS = 64
_SEARCH_ROUTE = "search-v1"
_READY_FRONTIER_ROUTE = "ready-frontier-v1"
_READY_FRONTIER_ORDERING = ("created_at-ascending", "task_id-ascending")
_INVENTORY_RESERVED_PAYLOAD_FIELDS = {
    "data_class",
    "inventory_digest",
    "inventory_path",
    "inventory_size",
    "provenance",
    "provenance_class",
    "source_digest",
    "source_path",
    "trust_class",
}
class ProjectionError(RuntimeError):
    """Projection is missing, stale, corrupt, or queried outside its bounds."""


class ContinuationError(ProjectionError):
    """A continuation is invalid, expired, stale, or bound to another query."""


@dataclass(frozen=True)
class ProjectionLimits:
    """Verified Core/preset limits injected into the disposable query runtime."""

    record_type: str
    token_version: int
    ranking_algorithm_id: str
    traversal_algorithm_id: str
    dependency_depth_hard_max: int
    continuation_ttl_seconds_max: int
    selected_profile_id: str
    selected_profile_digest: str
    policy_digest: str
    event_store_policy: EventStorePolicy
    persistent_entity_types: tuple[str, ...]
    default_budget: Mapping[str, int]
    hard_budget: Mapping[str, int]
    default_depth: int
    depth_min: int
    depth_max: int
    default_ttl_seconds: int
    ttl_min_seconds: int
    ttl_max_seconds: int
    max_token_bytes: int
    max_continuation_state_bytes: int
    max_query_bytes: int
    min_result_bytes: int
    max_resume_binding_fields: int
    max_resume_binding_key_chars: int
    max_resume_binding_value_bytes: int
    max_resume_binding_bytes: int
    required_resume_binding_fields: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.record_type != "ProjectionLimits":
            raise ProjectionError("projection limits record_type is invalid")
        if (
            not isinstance(self.token_version, int)
            or isinstance(self.token_version, bool)
            or self.token_version < 1
        ):
            raise ProjectionError("projection token version must be positive")
        for field in ("ranking_algorithm_id", "traversal_algorithm_id"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value:
                raise ProjectionError(f"projection {field} is invalid")
        if not isinstance(self.selected_profile_id, str) or not self.selected_profile_id:
            raise ProjectionError("selected projection profile ID is invalid")
        if (
            not isinstance(self.selected_profile_digest, str)
            or _DIGEST.fullmatch(self.selected_profile_digest) is None
        ):
            raise ProjectionError("selected projection profile digest is invalid")
        if (
            not isinstance(self.policy_digest, str)
            or _DIGEST.fullmatch(self.policy_digest) is None
        ):
            raise ProjectionError("projection limits policy digest is invalid")
        if not isinstance(self.event_store_policy, EventStorePolicy):
            raise ProjectionError("projection requires a verified EventStorePolicy")
        if (
            not isinstance(self.persistent_entity_types, tuple)
            or not self.persistent_entity_types
            or len(self.persistent_entity_types)
            != len(set(self.persistent_entity_types))
            or any(
                not isinstance(entity_type, str) or not entity_type
                for entity_type in self.persistent_entity_types
            )
            or {"Activation", "Relation"} & set(self.persistent_entity_types)
            or not set(self.persistent_entity_types)
            <= self.event_store_policy.allowed_state_binding_leaf_type_set
        ):
            raise ProjectionError("persistent graph entity kinds are invalid")
        default = self._budget(self.default_budget, "default")
        hard = self._budget(self.hard_budget, "hard")
        if any(default[key] > hard[key] for key in _BUDGET_FIELDS):
            raise ProjectionError("default query budget exceeds the verified hard ceiling")
        for field in (
            "default_depth", "depth_min", "depth_max", "default_ttl_seconds",
            "ttl_min_seconds", "ttl_max_seconds", "max_token_bytes", "max_query_bytes",
            "max_continuation_state_bytes",
            "min_result_bytes", "max_resume_binding_fields",
            "max_resume_binding_key_chars", "max_resume_binding_value_bytes",
            "max_resume_binding_bytes", "dependency_depth_hard_max",
            "continuation_ttl_seconds_max",
        ):
            value = getattr(self, field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ProjectionError(f"projection limit {field} must be a positive integer")
        if not self.depth_min <= self.default_depth <= self.depth_max:
            raise ProjectionError("default query depth is outside the verified range")
        if self.depth_max != self.dependency_depth_hard_max:
            raise ProjectionError("query depth maximum differs from compiled Core")
        if not self.ttl_min_seconds <= self.default_ttl_seconds <= self.ttl_max_seconds:
            raise ProjectionError("default continuation TTL is outside the verified range")
        if self.ttl_max_seconds != self.continuation_ttl_seconds_max:
            raise ProjectionError("continuation TTL maximum differs from compiled Core")
        if self.max_token_bytes > 256:
            raise ProjectionError("continuation token ceiling exceeds 256 bytes")
        if self.min_result_bytes > hard["max_bytes"]:
            raise ProjectionError("minimum result bytes exceed the hard byte ceiling")
        if (
            not isinstance(self.required_resume_binding_fields, tuple)
            or not self.required_resume_binding_fields
            or len(self.required_resume_binding_fields)
            != len(set(self.required_resume_binding_fields))
            or any(
                not isinstance(field, str) or not field
                for field in self.required_resume_binding_fields
            )
            or len(self.required_resume_binding_fields)
            > self.max_resume_binding_fields
        ):
            raise ProjectionError("required continuation binding fields are invalid")
        object.__setattr__(self, "default_budget", MappingProxyType(default))
        object.__setattr__(self, "hard_budget", MappingProxyType(hard))
        identity = self.as_compiled(include_policy_digest=False)
        if digest_value(identity) != self.policy_digest:
            raise ProjectionError("projection limits policy digest mismatch")

    def as_compiled(self, *, include_policy_digest: bool = True) -> dict[str, Any]:
        value = {
            "record_type": self.record_type,
            "token_version": self.token_version,
            "ranking_algorithm_id": self.ranking_algorithm_id,
            "traversal_algorithm_id": self.traversal_algorithm_id,
            "dependency_depth_hard_max": self.dependency_depth_hard_max,
            "continuation_ttl_seconds_max": self.continuation_ttl_seconds_max,
            "selected_profile_id": self.selected_profile_id,
            "selected_profile_digest": self.selected_profile_digest,
            "persistent_entity_types": list(self.persistent_entity_types),
            "default_budget": dict(self.default_budget),
            "hard_budget": dict(self.hard_budget),
            "default_depth": self.default_depth,
            "depth_min": self.depth_min,
            "depth_max": self.depth_max,
            "default_ttl_seconds": self.default_ttl_seconds,
            "ttl_min_seconds": self.ttl_min_seconds,
            "ttl_max_seconds": self.ttl_max_seconds,
            "max_token_bytes": self.max_token_bytes,
            "max_continuation_state_bytes": self.max_continuation_state_bytes,
            "max_query_bytes": self.max_query_bytes,
            "min_result_bytes": self.min_result_bytes,
            "max_resume_binding_fields": self.max_resume_binding_fields,
            "max_resume_binding_key_chars": self.max_resume_binding_key_chars,
            "max_resume_binding_value_bytes": self.max_resume_binding_value_bytes,
            "max_resume_binding_bytes": self.max_resume_binding_bytes,
            "required_resume_binding_fields": list(
                self.required_resume_binding_fields
            ),
        }
        if include_policy_digest:
            value["policy_digest"] = self.policy_digest
        return value

    @property
    def persistent_entity_type_set(self) -> frozenset[str]:
        return frozenset(self.persistent_entity_types)

    @staticmethod
    def _budget(value: Mapping[str, int], label: str) -> dict[str, int]:
        if not isinstance(value, Mapping) or set(value) != _BUDGET_FIELDS:
            raise ProjectionError(f"{label} query budget fields mismatch")
        checked = dict(value)
        if any(
            not isinstance(item, int) or isinstance(item, bool) or item < 0
            for item in checked.values()
        ):
            raise ProjectionError(f"{label} query budget values are invalid")
        if (
            checked["max_bytes"] < 1
            or checked["max_entities"] < 1
            or checked["max_fanout_per_entity"] < 1
            or checked["top_k"] < 1
        ):
            raise ProjectionError(f"{label} query budget minimum violated")
        return checked


_RankedRows = tuple[tuple[str, int, float], ...]
_RankedResult = tuple[_RankedRows, bool, tuple[str, ...]]


class RankedCandidateCache:
    """Bounded process-local cache for deterministic projection seed ranking."""

    def __init__(self, *, max_entries: int = 1_024) -> None:
        if not isinstance(max_entries, int) or isinstance(max_entries, bool) or not 1 <= max_entries <= 4_096:
            raise ProjectionError("ranked candidate cache size must be 1..4096")
        self.max_entries = max_entries
        self._entries: OrderedDict[tuple[Any, ...], _RankedResult] = OrderedDict()
        self._lock = threading.RLock()

    @staticmethod
    def _freeze(
        value: tuple[list[dict[str, Any]], bool, list[str]],
    ) -> _RankedResult:
        ranked, refinement_required, hints = value
        return (
            tuple((row["id"], int(row["tier"]), float(row["score"])) for row in ranked),
            bool(refinement_required),
            tuple(hints),
        )

    @staticmethod
    def _thaw(value: _RankedResult) -> tuple[list[dict[str, Any]], bool, list[str]]:
        ranked, refinement_required, hints = value
        return (
            [
                {"id": entity_id, "tier": tier, "score": score}
                for entity_id, tier, score in ranked
            ],
            refinement_required,
            list(hints),
        )

    def resolve(
        self,
        key: tuple[Any, ...],
        loader: Callable[[], tuple[list[dict[str, Any]], bool, list[str]]],
    ) -> tuple[list[dict[str, Any]], bool, list[str]]:
        with self._lock:
            cached = self._entries.get(key)
            if cached is not None:
                self._entries.move_to_end(key)
                return self._thaw(cached)
        loaded = self._freeze(loader())
        with self._lock:
            cached = self._entries.get(key)
            if cached is None:
                self._entries[key] = loaded
                self._entries.move_to_end(key)
                while len(self._entries) > self.max_entries:
                    self._entries.popitem(last=False)
                cached = loaded
            else:
                self._entries.move_to_end(key)
            return self._thaw(cached)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


@dataclass(frozen=True)
class VerifiedInventoryInput:
    """Manifest-verified inventory handed to the disposable projection.

    The service constructs this marker only after reloading and verifying the
    persisted inventory manifest.  Projection still rechecks all bindings and
    the raw stream digest before publishing a database.
    """

    activation_digest: str
    stream_digest: str
    entry_count: int
    entries: tuple[Mapping[str, Any], ...] | None = None
    inventory_digest: str | None = None
    stream_path: Path | None = None
    stream_bytes: int | None = None
    manifest_digest: str | None = None
    observed_at: str | None = None
    product_tree_passes: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.activation_digest, str) or not _DIGEST.fullmatch(self.activation_digest):
            raise ProjectionError("verified inventory Activation digest must be SHA-256")
        if not isinstance(self.stream_digest, str) or not _DIGEST.fullmatch(self.stream_digest):
            raise ProjectionError("verified inventory stream digest must be SHA-256")
        if not isinstance(self.entry_count, int) or isinstance(self.entry_count, bool) or self.entry_count < 0:
            raise ProjectionError("verified inventory entry count is invalid")
        if self.product_tree_passes != 1:
            raise ProjectionError("verified inventory must represent exactly one product-tree pass")
        inventory_digest = self.stream_digest if self.inventory_digest is None else self.inventory_digest
        if not isinstance(inventory_digest, str) or not _DIGEST.fullmatch(inventory_digest):
            raise ProjectionError("verified inventory identity digest must be SHA-256")
        object.__setattr__(self, "inventory_digest", inventory_digest)
        if self.stream_path is None:
            if not isinstance(self.entries, tuple):
                raise ProjectionError("verified in-memory inventory entries must be an immutable tuple")
            object.__setattr__(self, "entries", tuple(copy.deepcopy(value) for value in self.entries))
            if self.stream_bytes is not None or self.manifest_digest is not None:
                raise ProjectionError("in-memory inventory cannot claim persisted stream bindings")
            return
        if self.entries is not None:
            raise ProjectionError("persisted inventory cannot also carry materialized entries")
        path = Path(self.stream_path)
        try:
            state = path.lstat()
        except OSError as exc:
            raise ProjectionError(f"verified inventory stream is unavailable: {exc}") from exc
        if path.is_symlink() or not path.is_file():
            raise ProjectionError("verified inventory stream must be a regular non-link file")
        if not isinstance(self.stream_bytes, int) or isinstance(self.stream_bytes, bool) or self.stream_bytes < 0:
            raise ProjectionError("verified inventory stream byte count is invalid")
        if state.st_size != self.stream_bytes:
            raise ProjectionError("verified inventory stream byte count is stale")
        if not isinstance(self.manifest_digest, str) or not _DIGEST.fullmatch(self.manifest_digest):
            raise ProjectionError("verified inventory manifest digest must be SHA-256")
        object.__setattr__(self, "stream_path", path.resolve(strict=True))


def compile_relation_domains(semantic_model: Mapping[str, Any]) -> dict[str, tuple[frozenset[str], frozenset[str]]]:
    """Compile relation domain/range from the canonical semantic owner."""

    relations = semantic_model.get("relations")
    if not isinstance(relations, list):
        raise ProjectionError("semantic model lacks relations")
    compiled: dict[str, tuple[frozenset[str], frozenset[str]]] = {}
    for relation in relations:
        if not isinstance(relation, dict) or set(relation) < {"kind", "source", "target"}:
            raise ProjectionError("semantic relation definition is invalid")
        kind = relation["kind"]
        source = relation["source"]
        target = relation["target"]
        if not isinstance(kind, str) or not isinstance(source, list) or not source or not isinstance(target, list) or not target:
            raise ProjectionError("semantic relation domain/range is invalid")
        if kind in compiled:
            raise ProjectionError("duplicate semantic relation kind")
        compiled[kind] = (frozenset(source), frozenset(target))
    return compiled


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        # sqlite closes and fsyncs its file; replace uses write-through below.
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _replace_durable(source: Path, destination: Path) -> None:
    if os.name == "nt":
        import ctypes

        flags = 0x1 | 0x8
        if not ctypes.windll.kernel32.MoveFileExW(
            str(filesystem_path(source)), str(filesystem_path(destination)), flags
        ):
            raise OSError(ctypes.get_last_error(), "MoveFileExW failed", str(destination))
    else:
        os.replace(source, destination)
    _fsync_directory(destination.parent)


def _entity_text(entity_id: str, entity_type: str, payload: Mapping[str, Any]) -> str:
    scalar: list[str] = [entity_id, entity_type]

    def collect(value: Any) -> None:
        if isinstance(value, str):
            if not _DIGEST.fullmatch(value):
                scalar.append(value)
        elif isinstance(value, list):
            for item in value:
                collect(item)
        elif isinstance(value, dict):
            for key in sorted(value):
                if not key.endswith("_digest") and key not in {"created_at", "digest"}:
                    collect(value[key])

    collect(payload)
    return " ".join(scalar)


def _canonical_now(value: str | _datetime.datetime | None) -> str:
    if value is None:
        return utc_now()
    if isinstance(value, str):
        parse_timestamp(value)
        return value
    if not isinstance(value, _datetime.datetime) or value.tzinfo is None or value.utcoffset() != _datetime.timedelta(0):
        raise ProjectionError("query time must be canonical UTC text or an aware UTC datetime")
    try:
        return format_utc_second(value)
    except CanonicalError as exc:
        raise ProjectionError("query time must be an exact UTC second") from exc


class Projection:
    """One rebuildable SQLite projection; no method grants authority."""

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        token_key: bytes,
        *,
        implementation_closure_digest: str,
        limits: ProjectionLimits,
        relation_domains: Mapping[str, tuple[Iterable[str], Iterable[str]]] | None = None,
        ranked_candidate_cache: RankedCandidateCache | None = None,
    ) -> None:
        if not isinstance(token_key, bytes) or len(token_key) < 32:
            raise ProjectionError("continuation token key must contain at least 32 bytes")
        if (
            not isinstance(implementation_closure_digest, str)
            or not _DIGEST.fullmatch(implementation_closure_digest)
        ):
            raise ProjectionError("implementation closure digest must be SHA-256")
        self.db_path = Path(db_path)
        self.token_key = bytes(token_key)
        self.implementation_closure_digest = implementation_closure_digest
        if not isinstance(limits, ProjectionLimits):
            raise ProjectionError("projection limits must be a verified ProjectionLimits value")
        self.limits = limits
        self.relation_domains = {
            kind: (frozenset(source), frozenset(target))
            for kind, (source, target) in (relation_domains or {}).items()
        }
        if ranked_candidate_cache is not None and not isinstance(
            ranked_candidate_cache, RankedCandidateCache
        ):
            raise ProjectionError("ranked candidate cache has an invalid type")
        self.ranked_candidate_cache = ranked_candidate_cache

    def _entity_identity(
        self, payload: Mapping[str, Any]
    ) -> tuple[str, str] | None:
        entity_type = payload.get("record_type")
        if entity_type not in self.limits.persistent_entity_type_set:
            return None
        try:
            entity_id = state_binding_leaf_id(
                self.limits.event_store_policy,
                entity_type,
                payload,
            )
        except EventStoreError as exc:
            raise ProjectionError(
                f"{entity_type} graph identity differs from compiled Core"
            ) from exc
        return entity_type, entity_id

    def rebuild(
        self,
        event_store: EventStore,
        *,
        inventory: VerifiedInventoryInput | None = None,
    ) -> dict[str, Any]:
        """Build from authoritative events and an optional verified inventory."""

        if event_store.active_activation_digest == "":
            raise ProjectionError("event store lacks Activation")
        if getattr(event_store, "implementation_closure_digest", None) != self.implementation_closure_digest:
            raise ProjectionError("event store implementation closure differs from projection runtime")
        if (
            not isinstance(getattr(event_store, "policy", None), EventStorePolicy)
            or event_store.policy.policy_digest
            != self.limits.event_store_policy.policy_digest
        ):
            raise ProjectionError("event store policy differs from projection identity policy")
        if inventory is not None and not isinstance(inventory, VerifiedInventoryInput):
            raise ProjectionError("projection inventory must be a verified InventoryResult marker")
        if inventory is not None and inventory.activation_digest != event_store.active_activation_digest:
            raise ProjectionError("verified inventory Activation differs from event store")
        os.makedirs(filesystem_path(self.db_path.parent), exist_ok=True)
        descriptor, temp_name = tempfile.mkstemp(
            prefix=".p-", suffix=".tmp", dir=filesystem_path(self.db_path.parent)
        )
        os.close(descriptor)
        temporary = Path(temp_name)
        stats = {
            "inventory_entries": 0,
            "inventory_proxies": 0,
            "inventory_relations": 0,
            "inventory_passes": 1 if inventory is not None else 0,
            "product_passes": 0,
            "event_count": 0,
            "synthetic_task_count": 0,
            "inventory_stream_bytes": 0,
        }
        try:
            connection = sqlite3.connect(sqlite_path(temporary))
            try:
                self._create_schema(connection, defer_search_indexes=True)
                self._prepare_bulk_rebuild(connection)
                connection.execute("BEGIN IMMEDIATE")
                self._ingest_events_for_rebuild(connection, event_store, stats)
                if inventory is not None:
                    self._ingest_inventory_for_rebuild(connection, inventory, stats)
                self._validate_relation_closure(connection)
                self._create_search_indexes(connection)
                self._validate_dependency_graph_acyclic(connection)
                self._recompute_semantic_shards(
                    connection,
                    range(_SEMANTIC_SHARD_COUNT),
                    full_rebuild=True,
                )
                head = event_store.head()
                projection_digest = self._semantic_digest_connection(connection)
                entity_count, relation_count = self._read_projection_cardinality(connection)
                metadata = {
                    "activation_digest": event_store.active_activation_digest,
                    "head_digest": head["batch_digest"] or "",
                    "head_sequence": str(head["sequence"]),
                    "semantic_digest": projection_digest,
                    "entity_count": str(entity_count),
                    "relation_count": str(relation_count),
                    "inventory_entries": str(stats["inventory_entries"]),
                    "inventory_proxies": str(stats["inventory_proxies"]),
                    "inventory_relations": str(stats["inventory_relations"]),
                    "inventory_passes": str(stats["inventory_passes"]),
                    "product_passes": "0",
                    "event_count": str(stats["event_count"]),
                    "implementation_closure_digest": self.implementation_closure_digest,
                    "built_at": utc_now(),
                    "projection_authoritative": "false",
                    "semantic_digest_algorithm": _SEMANTIC_DIGEST_ALGORITHM,
                    "storage_layout": _PROJECTION_STORAGE_LAYOUT,
                    "incremental_commit_count": "0",
                    "incremental_changed_records": "0",
                    "projection_compaction_count": "1",
                }
                connection.executemany("INSERT INTO metadata(key,value) VALUES (?,?)", sorted(metadata.items()))
                connection.commit()
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                connection.close()
            with open(filesystem_path(temporary), "r+b") as stream:
                os.fsync(stream.fileno())
            _replace_durable(temporary, self.db_path)
            raw_file_proxy_ratio = (
                stats["inventory_proxies"] / stats["inventory_entries"]
                if stats["inventory_entries"]
                else 1.0
            )
            projection_bytes = os.stat(filesystem_path(self.db_path)).st_size
            inventory_projection_amplification = (
                projection_bytes / stats["inventory_stream_bytes"]
                if stats["inventory_stream_bytes"]
                else 0.0
            )
            return {
                "activation_digest": event_store.active_activation_digest,
                "head_digest": head["batch_digest"],
                "head_sequence": head["sequence"],
                "semantic_digest": projection_digest,
                "entity_count": entity_count,
                "relation_count": relation_count,
                **stats,
                "raw_file_proxy_ratio": raw_file_proxy_ratio,
                "synthetic_task_ratio": 0.0,
                "projection_db_bytes": projection_bytes,
                "inventory_projection_amplification": inventory_projection_amplification,
                "implementation_closure_digest": self.implementation_closure_digest,
                "projection_authoritative": False,
            }
        except (sqlite3.Error, EventStoreError) as exc:
            raise ProjectionError(f"projection rebuild failed: {exc}") from exc
        finally:
            try:
                os.unlink(filesystem_path(temporary))
            except FileNotFoundError:
                pass

    @classmethod
    def _create_schema(
        cls,
        connection: sqlite3.Connection,
        *,
        defer_search_indexes: bool = False,
    ) -> None:
        if defer_search_indexes:
            # This database is an unpublished disposable temp file.  SQLite's
            # rollback journal cannot protect the authoritative event stream
            # and only amplifies every rebuild write.  A failed build is
            # discarded; a successful build is closed, explicitly fsynced,
            # then atomically replaces the last durable projection.
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA synchronous=OFF")
            connection.execute("PRAGMA locking_mode=EXCLUSIVE")
        else:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
        connection.executescript(
            """
            PRAGMA foreign_keys=ON;
            PRAGMA page_size=4096;
            PRAGMA temp_store=MEMORY;
            CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
            CREATE TABLE entities(
              id TEXT PRIMARY KEY,
              entity_type TEXT NOT NULL,
              data_class TEXT NOT NULL,
              payload_json TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE projection_cardinality(
              singleton INTEGER PRIMARY KEY CHECK(singleton=1),
              entity_count INTEGER NOT NULL CHECK(entity_count>=0),
              relation_count INTEGER NOT NULL CHECK(relation_count>=0)
            ) WITHOUT ROWID;
            INSERT INTO projection_cardinality(singleton,entity_count,relation_count)
            VALUES(1,0,0);
            CREATE TRIGGER entities_cardinality_after_insert
            AFTER INSERT ON entities
            BEGIN
              UPDATE projection_cardinality
              SET entity_count=entity_count+1
              WHERE singleton=1;
            END;
            CREATE TRIGGER entities_cardinality_after_delete
            AFTER DELETE ON entities
            BEGIN
              UPDATE projection_cardinality
              SET entity_count=entity_count-1
              WHERE singleton=1;
            END;
            CREATE TABLE operational_order(
              entity_id TEXT PRIMARY KEY,
              event_sequence INTEGER NOT NULL,
              event_index INTEGER NOT NULL,
              FOREIGN KEY(entity_id) REFERENCES entities(id) ON DELETE CASCADE
            ) WITHOUT ROWID;
            CREATE TABLE relations(
              id TEXT PRIMARY KEY,
              kind TEXT NOT NULL,
              source_type TEXT NOT NULL,
              source_id TEXT NOT NULL,
              target_type TEXT NOT NULL,
              target_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              payload_json TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TRIGGER relations_cardinality_after_insert
            AFTER INSERT ON relations
            BEGIN
              UPDATE projection_cardinality
              SET relation_count=relation_count+1
              WHERE singleton=1;
            END;
            CREATE TRIGGER relations_cardinality_after_delete
            AFTER DELETE ON relations
            BEGIN
              UPDATE projection_cardinality
              SET relation_count=relation_count-1
              WHERE singleton=1;
            END;
            CREATE TABLE semantic_rows(
              shard INTEGER NOT NULL,
              bucket INTEGER NOT NULL CHECK(bucket>=0 AND bucket<256),
              key TEXT NOT NULL,
              row_digest BLOB NOT NULL CHECK(typeof(row_digest)='blob' AND length(row_digest)=32),
              PRIMARY KEY(shard,key),
              UNIQUE(shard,bucket,key)
            ) WITHOUT ROWID;
            CREATE TABLE semantic_bucket_commitments(
              shard INTEGER NOT NULL,
              bucket INTEGER NOT NULL CHECK(bucket>=0 AND bucket<256),
              row_count INTEGER NOT NULL CHECK(row_count>0),
              digest TEXT NOT NULL,
              PRIMARY KEY(shard,bucket)
            ) WITHOUT ROWID;
            CREATE TABLE semantic_group_commitments(
              shard INTEGER NOT NULL,
              group_index INTEGER NOT NULL CHECK(group_index>=0 AND group_index<16),
              row_count INTEGER NOT NULL CHECK(row_count>0),
              digest TEXT NOT NULL,
              PRIMARY KEY(shard,group_index)
            ) WITHOUT ROWID;
            CREATE TABLE semantic_shards(
              shard INTEGER PRIMARY KEY,
              row_count INTEGER NOT NULL,
              digest TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE continuations(
              handle TEXT PRIMARY KEY,
              row_digest TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              expires_at TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE INDEX continuations_expiry ON continuations(expires_at,handle);
            CREATE TABLE ready_frontiers(
              state_id TEXT PRIMARY KEY,
              frontier_digest TEXT NOT NULL,
              activation_digest TEXT NOT NULL,
              head_digest TEXT,
              projection_digest TEXT NOT NULL,
              task_count INTEGER NOT NULL,
              evaluated_task_count INTEGER NOT NULL,
              blocked_task_count INTEGER NOT NULL,
              expires_at TEXT NOT NULL
            ) WITHOUT ROWID;
            CREATE TABLE ready_frontier_tasks(
              state_id TEXT NOT NULL,
              ordinal INTEGER NOT NULL,
              task_id TEXT NOT NULL,
              task_digest TEXT NOT NULL,
              selection_json TEXT NOT NULL,
              PRIMARY KEY(state_id,ordinal),
              UNIQUE(state_id,task_id),
              FOREIGN KEY(state_id) REFERENCES ready_frontiers(state_id) ON DELETE CASCADE
            ) WITHOUT ROWID;
            CREATE VIRTUAL TABLE entity_fts USING fts5(
              id UNINDEXED,
              text,
              tokenize='unicode61',
              detail='none'
            );
            CREATE TEMP TABLE semantic_dirty_buckets(
              shard INTEGER NOT NULL,
              bucket INTEGER NOT NULL,
              PRIMARY KEY(shard,bucket)
            ) WITHOUT ROWID;
            """
        )
        if not defer_search_indexes:
            cls._create_search_indexes(connection)

    @staticmethod
    def _create_search_indexes(connection: sqlite3.Connection) -> None:
        """Build relation read indexes after a rebuild's append-only load."""

        connection.execute(
            "CREATE INDEX IF NOT EXISTS relations_dependency_kind "
            "ON relations(kind,source_id,target_id,id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS relations_source "
            "ON relations(source_id,kind,target_id,id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS relations_target "
            "ON relations(target_id,kind,source_id,id)"
        )

    @staticmethod
    def _prepare_bulk_rebuild(connection: sqlite3.Connection) -> None:
        """Create bounded staging tables used only by a fresh disposable build."""

        connection.executescript(
            """
            CREATE TEMP TABLE projection_entity_stage(
              id TEXT PRIMARY KEY,
              entity_type TEXT NOT NULL,
              data_class TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              search_text TEXT NOT NULL,
              event_sequence INTEGER,
              event_index INTEGER,
              shard INTEGER NOT NULL,
              bucket INTEGER NOT NULL,
              semantic_key TEXT NOT NULL,
              row_digest BLOB NOT NULL
            ) WITHOUT ROWID;
            CREATE TEMP TABLE projection_entity_changes(
              id TEXT PRIMARY KEY,
              entity_type TEXT NOT NULL,
              data_class TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              search_text TEXT NOT NULL,
              event_sequence INTEGER,
              event_index INTEGER,
              shard INTEGER NOT NULL,
              bucket INTEGER NOT NULL,
              semantic_key TEXT NOT NULL,
              row_digest BLOB NOT NULL
            ) WITHOUT ROWID;
            CREATE TEMP TABLE projection_relation_stage(
              id TEXT PRIMARY KEY,
              kind TEXT NOT NULL,
              source_type TEXT NOT NULL,
              source_id TEXT NOT NULL,
              target_type TEXT NOT NULL,
              target_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              shard INTEGER NOT NULL,
              bucket INTEGER NOT NULL,
              semantic_key TEXT NOT NULL,
              row_digest BLOB NOT NULL
            ) WITHOUT ROWID;
            CREATE TEMP TABLE projection_relation_changes(
              id TEXT PRIMARY KEY,
              kind TEXT NOT NULL,
              source_type TEXT NOT NULL,
              source_id TEXT NOT NULL,
              target_type TEXT NOT NULL,
              target_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              shard INTEGER NOT NULL,
              bucket INTEGER NOT NULL,
              semantic_key TEXT NOT NULL,
              row_digest BLOB NOT NULL
            ) WITHOUT ROWID;
            """
        )

    @staticmethod
    def _ensure_semantic_dirty_buckets(connection: sqlite3.Connection) -> None:
        """Track only this connection's uncommitted semantic leaf mutations."""

        connection.execute(
            """
            CREATE TEMP TABLE IF NOT EXISTS semantic_dirty_buckets(
              shard INTEGER NOT NULL,
              bucket INTEGER NOT NULL,
              PRIMARY KEY(shard,bucket)
            ) WITHOUT ROWID
            """
        )

    @staticmethod
    def _insert_bulk_values(
        connection: sqlite3.Connection,
        table: str,
        columns: Sequence[str],
        rows: Sequence[tuple[Any, ...]],
    ) -> None:
        """Cross the SQLite boundary once per bounded group, not once per row."""

        if not rows:
            return
        column_sql = ",".join(columns)
        row_placeholder = "(" + ",".join("?" for _ in columns) + ")"
        for offset in range(0, len(rows), _BULK_SQL_VALUE_ROWS):
            selected = rows[offset : offset + _BULK_SQL_VALUE_ROWS]
            placeholders = ",".join(row_placeholder for _ in selected)
            parameters = tuple(itertools.chain.from_iterable(selected))
            connection.execute(
                f"INSERT INTO {table}({column_sql}) VALUES {placeholders}",
                parameters,
            )

    def _entity_rebuild_row(
        self,
        entity_id: str,
        entity_type: str,
        data_class: str,
        payload: Mapping[str, Any],
        *,
        search_text: str | None = None,
        event_sequence: int | None = None,
        event_index: int | None = None,
    ) -> tuple[Any, ...]:
        if (event_sequence is None) != (event_index is None):
            raise ProjectionError("operational entity event position is incomplete")
        if event_sequence is not None and (
            not isinstance(event_sequence, int)
            or isinstance(event_sequence, bool)
            or event_sequence < 1
            or not isinstance(event_index, int)
            or isinstance(event_index, bool)
            or event_index < 0
        ):
            raise ProjectionError("operational entity event position is invalid")
        payload_json = canonical_bytes(payload).decode("utf-8")
        text = _entity_text(entity_id, entity_type, payload)
        if search_text:
            text += " " + search_text
        semantic_key = f"entity:{entity_id}"
        semantic_shard, semantic_bucket = self._semantic_location(semantic_key)
        semantic_value = {
            "id": entity_id,
            "entity_type": entity_type,
            "data_class": data_class,
            "payload": dict(payload),
        }
        return (
            entity_id,
            entity_type,
            data_class,
            payload_json,
            text,
            event_sequence,
            event_index,
            semantic_shard,
            semantic_bucket,
            semantic_key,
            hashlib.sha256(canonical_bytes(semantic_value)).digest(),
        )

    def _relation_rebuild_row(
        self, relation: Mapping[str, Any]
    ) -> tuple[Any, ...]:
        required = {
            "record_type",
            "relation_id",
            "kind",
            "source_type",
            "source_id",
            "target_type",
            "target_id",
            "activation_digest",
            "created_at",
        }
        if (
            not isinstance(relation, Mapping)
            or set(relation) != required
            or relation["record_type"] != "Relation"
        ):
            raise ProjectionError("Relation fields mismatch")
        parse_timestamp(relation["created_at"])
        if not self.relation_domains:
            raise ProjectionError("relation domains are required to project typed relations")
        domain = self.relation_domains.get(relation["kind"])
        if (
            domain is None
            or relation["source_type"] not in domain[0]
            or relation["target_type"] not in domain[1]
        ):
            raise ProjectionError("Relation violates canonical domain/range")
        payload = dict(relation)
        payload_json = canonical_bytes(payload).decode("utf-8")
        semantic_key = f"relation:{relation['relation_id']}"
        semantic_shard, semantic_bucket = self._semantic_location(semantic_key)
        return (
            relation["relation_id"],
            relation["kind"],
            relation["source_type"],
            relation["source_id"],
            relation["target_type"],
            relation["target_id"],
            relation["created_at"],
            payload_json,
            semantic_shard,
            semantic_bucket,
            semantic_key,
            hashlib.sha256(canonical_bytes(payload)).digest(),
        )

    @classmethod
    def _flush_entity_rebuild_rows(
        cls,
        connection: sqlite3.Connection,
        rows: Sequence[tuple[Any, ...]],
        *,
        replace_event_state: bool,
        operational: bool,
    ) -> None:
        if not rows:
            return
        connection.execute("DELETE FROM projection_entity_stage")
        connection.execute("DELETE FROM projection_entity_changes")
        cls._insert_bulk_values(
            connection,
            "projection_entity_stage",
            (
                "id",
                "entity_type",
                "data_class",
                "payload_json",
                "search_text",
                "event_sequence",
                "event_index",
                "shard",
                "bucket",
                "semantic_key",
                "row_digest",
            ),
            rows,
        )
        if not replace_event_state:
            collision = connection.execute(
                """
                SELECT stage.id
                FROM projection_entity_stage AS stage
                JOIN entities AS current ON current.id=stage.id
                WHERE current.entity_type<>stage.entity_type
                   OR current.data_class<>stage.data_class
                   OR current.payload_json<>stage.payload_json
                ORDER BY stage.id LIMIT 1
                """
            ).fetchone()
            if collision is not None:
                raise ProjectionError(f"entity ID collision: {collision[0]}")
        changed_predicate = (
            "current.id IS NULL OR current.entity_type<>stage.entity_type "
            "OR current.data_class<>stage.data_class "
            "OR current.payload_json<>stage.payload_json"
            if replace_event_state
            else "current.id IS NULL"
        )
        connection.execute(
            """
            INSERT INTO projection_entity_changes
            SELECT stage.*
            FROM projection_entity_stage AS stage
            LEFT JOIN entities AS current ON current.id=stage.id
            WHERE """
            + changed_predicate
        )
        replaces_existing = connection.execute(
            """
            SELECT 1
            FROM projection_entity_changes AS changed
            JOIN entities AS current ON current.id=changed.id
            LIMIT 1
            """
        ).fetchone() is not None
        if replaces_existing:
            connection.execute(
                """
                DELETE FROM entity_fts
                WHERE id IN (
                  SELECT changed.id
                  FROM projection_entity_changes AS changed
                  JOIN entities AS current ON current.id=changed.id
                )
                """
            )
        if replaces_existing:
            connection.execute(
                """
                DELETE FROM entities
                WHERE id IN (
                  SELECT changed.id
                  FROM projection_entity_changes AS changed
                  JOIN entities AS current ON current.id=changed.id
                )
                """
            )
        connection.execute(
            """
            INSERT INTO entities(id,entity_type,data_class,payload_json)
            SELECT id,entity_type,data_class,payload_json
            FROM projection_entity_changes
            """
        )
        connection.execute(
            """
            INSERT INTO entity_fts(id,text)
            SELECT id,search_text FROM projection_entity_changes
            """
        )
        if operational:
            connection.execute(
                """
                INSERT OR REPLACE INTO operational_order(
                  entity_id,event_sequence,event_index
                )
                SELECT id,event_sequence,event_index
                FROM projection_entity_changes
                WHERE event_sequence IS NOT NULL
                """
            )
        connection.execute(
            """
            INSERT OR REPLACE INTO semantic_rows(shard,bucket,key,row_digest)
            SELECT shard,bucket,semantic_key,row_digest
            FROM projection_entity_changes
            """
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO semantic_dirty_buckets(shard,bucket)
            SELECT shard,bucket FROM projection_entity_changes
            """
        )

    @classmethod
    def _flush_relation_rebuild_rows(
        cls,
        connection: sqlite3.Connection,
        rows: Sequence[tuple[Any, ...]],
    ) -> None:
        if not rows:
            return
        connection.execute("DELETE FROM projection_relation_stage")
        connection.execute("DELETE FROM projection_relation_changes")
        cls._insert_bulk_values(
            connection,
            "projection_relation_stage",
            (
                "id",
                "kind",
                "source_type",
                "source_id",
                "target_type",
                "target_id",
                "created_at",
                "payload_json",
                "shard",
                "bucket",
                "semantic_key",
                "row_digest",
            ),
            rows,
        )
        collision = connection.execute(
            """
            SELECT stage.id
            FROM projection_relation_stage AS stage
            JOIN relations AS current ON current.id=stage.id
            WHERE current.payload_json<>stage.payload_json
            ORDER BY stage.id LIMIT 1
            """
        ).fetchone()
        if collision is not None:
            raise ProjectionError(f"relation ID collision: {collision[0]}")
        connection.execute(
            """
            INSERT INTO projection_relation_changes
            SELECT stage.*
            FROM projection_relation_stage AS stage
            LEFT JOIN relations AS current ON current.id=stage.id
            WHERE current.id IS NULL
            """
        )
        connection.execute(
            """
            INSERT INTO relations(
              id,kind,source_type,source_id,target_type,target_id,created_at,payload_json
            )
            SELECT id,kind,source_type,source_id,target_type,target_id,created_at,payload_json
            FROM projection_relation_changes
            """
        )
        connection.execute(
            """
            INSERT INTO semantic_rows(shard,bucket,key,row_digest)
            SELECT shard,bucket,semantic_key,row_digest
            FROM projection_relation_changes
            """
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO semantic_dirty_buckets(shard,bucket)
            SELECT shard,bucket FROM projection_relation_changes
            """
        )

    def _ingest_events_for_rebuild(
        self,
        connection: sqlite3.Connection,
        event_store: EventStore,
        stats: dict[str, int],
    ) -> None:
        entity_rows: dict[str, tuple[Any, ...]] = {}
        relation_rows: dict[str, tuple[Any, ...]] = {}

        def flush_entities() -> None:
            if not entity_rows:
                return
            self._flush_entity_rebuild_rows(
                connection,
                tuple(entity_rows.values()),
                replace_event_state=True,
                operational=True,
            )
            entity_rows.clear()

        def flush_relations() -> None:
            if not relation_rows:
                return
            self._flush_relation_rebuild_rows(
                connection, tuple(relation_rows.values())
            )
            relation_rows.clear()

        def flush_all() -> None:
            flush_entities()
            flush_relations()

        for envelope in event_store.iter_envelopes(validate=True):
            batch = envelope["batch"]
            for event_index, event in enumerate(batch["events"]):
                stats["event_count"] += 1
                event_kind = event["event_kind"]
                payload = event["payload"]
                if event_kind == "task.transitioned" or (
                    event_kind == "decision.recorded"
                    and payload.get("decision_kind") in {"resolve", "waive"}
                ):
                    flush_all()
                    self._apply_event(
                        connection,
                        event,
                        state_binding_delta=batch["state_binding_delta"],
                        event_sequence=batch["sequence"],
                        event_index=event_index,
                    )
                    continue
                if event_kind == "relation.recorded":
                    row = self._relation_rebuild_row(payload)
                    previous = relation_rows.get(row[0])
                    if previous is not None:
                        if previous[7] != row[7]:
                            raise ProjectionError(f"relation ID collision: {row[0]}")
                    else:
                        relation_rows[row[0]] = row
                    if len(relation_rows) >= _BULK_REBUILD_BATCH_ROWS:
                        flush_relations()
                    continue
                identity = self._entity_identity(payload)
                if identity is None:
                    continue
                entity_type, entity_id = identity
                row = self._entity_rebuild_row(
                    entity_id,
                    entity_type,
                    "operational-record",
                    payload,
                    event_sequence=batch["sequence"],
                    event_index=event_index,
                )
                previous = entity_rows.get(entity_id)
                if previous is not None and previous[1:4] != row[1:4]:
                    # A changed repeated entity used to be deleted/reinserted
                    # at this exact stream position. Flush first so FTS rowid
                    # ordering and latest operational_order remain identical.
                    flush_entities()
                if previous is None or previous[1:4] != row[1:4]:
                    entity_rows[entity_id] = row
                if len(entity_rows) >= _BULK_REBUILD_BATCH_ROWS:
                    flush_entities()
        flush_all()

    def _ingest_events(self, connection: sqlite3.Connection, event_store: EventStore, stats: dict[str, int]) -> None:
        for envelope in event_store.iter_envelopes(validate=True):
            batch = envelope["batch"]
            for event_index, event in enumerate(batch["events"]):
                stats["event_count"] += 1
                self._apply_event(
                    connection,
                    event,
                    state_binding_delta=batch["state_binding_delta"],
                    event_sequence=batch["sequence"],
                    event_index=event_index,
                )

    def _apply_event(
        self,
        connection: sqlite3.Connection,
        event: Mapping[str, Any],
        *,
        state_binding_delta: Sequence[Mapping[str, Any]],
        event_sequence: int,
        event_index: int,
    ) -> tuple[set[int], list[str], int]:
        """Apply one event and return changed shards, Relations, and records."""

        event_kind = event["event_kind"]
        payload = event["payload"]
        if event_kind == "task.transitioned":
            return {
                self._apply_task_transition(
                    connection,
                    payload,
                    event_sequence=event_sequence,
                    event_index=event_index,
                )
            }, [], 1
        if event_kind == "relation.recorded":
            shard = self._insert_relation(connection, payload)
            return ({shard} if shard is not None else set()), [payload["relation_id"]], int(shard is not None)

        changed_shards: set[int] = set()
        changed_records = 0
        identity = self._entity_identity(payload)
        if identity is not None:
            entity_type, entity_id = identity
            shard = self._insert_entity(
                connection,
                entity_id,
                entity_type,
                "operational-record",
                payload,
                replace_event_state=True,
                event_sequence=event_sequence,
                event_index=event_index,
            )
            if shard is not None:
                changed_shards.add(shard)
                changed_records += 1
        if event_kind == "decision.recorded" and payload.get("decision_kind") in {
            "resolve",
            "waive",
        }:
            disposition_shard = self._apply_finding_disposition(
                connection,
                payload,
                state_binding_delta=state_binding_delta,
                event_sequence=event_sequence,
                event_index=event_index,
            )
            changed_shards.add(disposition_shard)
            changed_records += 1
        return changed_shards, [], changed_records

    def _apply_finding_disposition(
        self,
        connection: sqlite3.Connection,
        decision: Mapping[str, Any],
        *,
        state_binding_delta: Sequence[Mapping[str, Any]],
        event_sequence: int,
        event_index: int,
    ) -> int:
        if decision.get("target_type") != "Finding":
            raise ProjectionError("Finding disposition Decision has the wrong target type")
        finding_id = decision.get("target_id")
        if not isinstance(finding_id, str) or not finding_id:
            raise ProjectionError("Finding disposition target ID is invalid")
        row = connection.execute(
            "SELECT entity_type,data_class,payload_json FROM entities WHERE id=?",
            (finding_id,),
        ).fetchone()
        if row is None or row[:2] != ("Finding", "operational-record"):
            raise ProjectionError("Finding disposition target is unresolved")
        try:
            finding = parse_json_strict(row[2].encode("utf-8"))
        except CanonicalError as exc:
            raise ProjectionError("Finding disposition target is noncanonical") from exc
        finding_digest = digest_value(finding)
        if (
            finding.get("status") != "OPEN"
            or decision.get("target_digest") != finding_digest
            or decision.get("finding_digest") != finding_digest
        ):
            raise ProjectionError("Finding disposition differs from the exact OPEN Finding")
        updated = copy.deepcopy(finding)
        updated["status"] = (
            "RESOLVED" if decision["decision_kind"] == "resolve" else "WAIVED"
        )
        updated["blocking"] = False
        updated["disposition_decision_id"] = decision["decision_id"]
        finding_updates = [
            value
            for value in state_binding_delta
            if value.get("leaf_type") == "Finding"
            and value.get("leaf_id") == finding_id
        ]
        if (
            len(finding_updates) != 1
            or finding_updates[0].get("operation") != "set"
            or finding_updates[0].get("value_digest") != digest_value(updated)
        ):
            raise ProjectionError(
                "Finding disposition differs from its committed state-binding delta"
            )
        shard = self._insert_entity(
            connection,
            finding_id,
            "Finding",
            "operational-record",
            updated,
            replace_event_state=True,
            event_sequence=event_sequence,
            event_index=event_index,
        )
        if shard is None:
            raise ProjectionError("Finding disposition did not change its target")
        return shard

    def _apply_task_transition(
        self,
        connection: sqlite3.Connection,
        transition: Mapping[str, Any],
        *,
        event_sequence: int,
        event_index: int,
    ) -> int:
        required = {"task_id", "from_state", "to_state", "reason"}
        if not isinstance(transition, Mapping) or set(transition) != required:
            raise ProjectionError("Task transition fields mismatch")
        if not all(isinstance(transition[field], str) and transition[field] for field in required):
            raise ProjectionError("Task transition fields must be nonempty text")
        row = connection.execute(
            "SELECT entity_type,data_class,payload_json FROM entities WHERE id=?",
            (transition["task_id"],),
        ).fetchone()
        if row is None or row[0] != "Task":
            raise ProjectionError("Task transition references an unresolved Task")
        payload = json.loads(row[2])
        if payload.get("record_type") != "Task" or payload.get("task_id") != transition["task_id"]:
            raise ProjectionError("Task transition projection identity mismatch")
        if payload.get("state") != transition["from_state"]:
            raise ProjectionError("Task transition from_state is stale in projection")
        payload["state"] = transition["to_state"]
        changed_shard = self._insert_entity(
            connection,
            transition["task_id"],
            "Task",
            row[1],
            payload,
            replace_event_state=True,
            event_sequence=event_sequence,
            event_index=event_index,
        )
        if changed_shard is None:
            raise ProjectionError("Task transition did not change its projected Task")
        return changed_shard

    def _ingest_inventory_for_rebuild(
        self,
        connection: sqlite3.Connection,
        inventory: VerifiedInventoryInput,
        stats: dict[str, int],
    ) -> None:
        identity_stream = hashlib.sha256()
        persisted_stream = hashlib.sha256()
        previous_path: str | None = None
        persisted = inventory.stream_path is not None
        if not persisted:
            assert inventory.entries is not None
            source: Iterable[tuple[Mapping[str, Any], bytes | None]] = (
                (row, None) for row in inventory.entries
            )
        else:
            source = self._iter_persisted_inventory(inventory, persisted_stream)
        entity_rows: dict[str, tuple[Any, ...]] = {}

        def flush_entities() -> None:
            if not entity_rows:
                return
            self._flush_entity_rebuild_rows(
                connection,
                tuple(entity_rows.values()),
                replace_event_state=False,
                operational=False,
            )
            entity_rows.clear()

        for row, encoded_line in source:
            stats["inventory_entries"] += 1
            if not isinstance(row, Mapping):
                raise ProjectionError("inventory row must be an object")
            required = (
                {"path", "digest", "size", "search_text"}
                if persisted
                else {"record_type", "path", "digest", "size", "semantic_proxy"}
            )
            if set(row) != required or (
                not persisted and row.get("record_type") != "InventoryProjectionRow"
            ):
                raise ProjectionError("InventoryProjectionRow fields mismatch")
            path = row["path"]
            file_digest = row["digest"]
            size = row["size"]
            self._validate_inventory_path(path)
            if previous_path is not None and path <= previous_path:
                raise ProjectionError("inventory paths must be strictly sorted and unique")
            previous_path = path
            if not isinstance(file_digest, str) or not _DIGEST.fullmatch(file_digest):
                raise ProjectionError("inventory digest must be SHA-256")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise ProjectionError("inventory size must be a nonnegative integer")
            identity = canonical_bytes(
                {"path": path, "digest": file_digest, "size": size}
            )
            identity_stream.update(identity)
            stats["inventory_stream_bytes"] += (
                len(encoded_line) if encoded_line is not None else len(identity)
            )

            expected_id = (
                "artifact:file:"
                + hashlib.sha256(path.encode("utf-8")).hexdigest()[:48]
            )
            search_text: str | None = None
            if persisted:
                search_text = row["search_text"]
                if (
                    not isinstance(search_text, str)
                    or len(search_text.encode("utf-8")) > 4096
                    or "\x00" in search_text
                ):
                    raise ProjectionError(
                        "inventory search text is invalid or exceeds 4096 bytes"
                    )
                payload = {
                    "record_type": "Artifact",
                    "artifact_id": expected_id,
                    "artifact_kind": "product",
                    "digest": file_digest,
                    "media_type": "application/octet-stream",
                    "size_bytes": size,
                    "retention_class": "project",
                    "inventory_path": path,
                    "inventory_digest": file_digest,
                    "inventory_size": size,
                }
                if inventory.observed_at is not None:
                    payload["created_at"] = inventory.observed_at
            else:
                payload = self._validated_inventory_proxy(
                    row["semantic_proxy"], expected_id, path, file_digest, size
                )
            projected = self._entity_rebuild_row(
                expected_id,
                "Artifact",
                "untrusted-source",
                payload,
                search_text=search_text,
            )
            pending = entity_rows.get(expected_id)
            if pending is not None:
                if pending[1:4] != projected[1:4]:
                    raise ProjectionError(f"entity ID collision: {expected_id}")
            else:
                entity_rows[expected_id] = projected
            if len(entity_rows) >= _BULK_REBUILD_BATCH_ROWS:
                flush_entities()
            stats["inventory_proxies"] += 1
        flush_entities()
        if stats["inventory_entries"] != inventory.entry_count:
            raise ProjectionError("verified inventory entry count mismatch")
        if identity_stream.hexdigest() != inventory.inventory_digest:
            raise ProjectionError("verified inventory identity digest mismatch")
        if persisted and persisted_stream.hexdigest() != inventory.stream_digest:
            raise ProjectionError("verified inventory stream digest mismatch")
        if stats["inventory_proxies"] != stats["inventory_entries"]:
            raise ProjectionError(
                "raw inventory must produce exactly one Artifact proxy per file"
            )

    def _ingest_inventory(
        self,
        connection: sqlite3.Connection,
        inventory: VerifiedInventoryInput,
        stats: dict[str, int],
    ) -> None:
        identity_stream = hashlib.sha256()
        persisted_stream = hashlib.sha256()
        previous_path: str | None = None
        if inventory.stream_path is None:
            assert inventory.entries is not None
            source: Iterable[tuple[Mapping[str, Any], bytes | None]] = (
                (row, None) for row in inventory.entries
            )
        else:
            source = self._iter_persisted_inventory(inventory, persisted_stream)
        for row, encoded_line in source:
            stats["inventory_entries"] += 1
            if not isinstance(row, Mapping):
                raise ProjectionError("inventory row must be an object")
            persisted = inventory.stream_path is not None
            required = {"path", "digest", "size", "search_text"} if persisted else {
                "record_type", "path", "digest", "size", "semantic_proxy"
            }
            if set(row) != required or (not persisted and row.get("record_type") != "InventoryProjectionRow"):
                raise ProjectionError("InventoryProjectionRow fields mismatch")
            path = row["path"]
            file_digest = row["digest"]
            size = row["size"]
            self._validate_inventory_path(path)
            if previous_path is not None and path <= previous_path:
                raise ProjectionError("inventory paths must be strictly sorted and unique")
            previous_path = path
            if not isinstance(file_digest, str) or not _DIGEST.fullmatch(file_digest):
                raise ProjectionError("inventory digest must be SHA-256")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise ProjectionError("inventory size must be a nonnegative integer")
            identity = canonical_bytes({"path": path, "digest": file_digest, "size": size})
            identity_stream.update(identity)
            stats["inventory_stream_bytes"] += len(encoded_line) if encoded_line is not None else len(identity)

            expected_id = "artifact:file:" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:48]
            search_text: str | None = None
            if persisted:
                search_text = row["search_text"]
                if (
                    not isinstance(search_text, str)
                    or len(search_text.encode("utf-8")) > 4096
                    or "\x00" in search_text
                ):
                    raise ProjectionError("inventory search text is invalid or exceeds 4096 bytes")
                payload = {
                    "record_type": "Artifact",
                    "artifact_id": expected_id,
                    "artifact_kind": "product",
                    "digest": file_digest,
                    "media_type": "application/octet-stream",
                    "size_bytes": size,
                    "retention_class": "project",
                    "inventory_path": path,
                    "inventory_digest": file_digest,
                    "inventory_size": size,
                }
                if inventory.observed_at is not None:
                    payload["created_at"] = inventory.observed_at
            else:
                payload = self._validated_inventory_proxy(
                    row["semantic_proxy"], expected_id, path, file_digest, size
                )
            self._insert_entity(
                connection,
                expected_id,
                "Artifact",
                "untrusted-source",
                payload,
                search_text=search_text,
            )
            stats["inventory_proxies"] += 1
        if stats["inventory_entries"] != inventory.entry_count:
            raise ProjectionError("verified inventory entry count mismatch")
        if identity_stream.hexdigest() != inventory.inventory_digest:
            raise ProjectionError("verified inventory identity digest mismatch")
        if inventory.stream_path is not None and persisted_stream.hexdigest() != inventory.stream_digest:
            raise ProjectionError("verified inventory stream digest mismatch")
        if stats["inventory_proxies"] != stats["inventory_entries"]:
            raise ProjectionError("raw inventory must produce exactly one Artifact proxy per file")

    @staticmethod
    def _iter_persisted_inventory(
        inventory: VerifiedInventoryInput,
        stream_digest: "hashlib._Hash",
    ) -> Iterator[tuple[Mapping[str, Any], bytes]]:
        assert inventory.stream_path is not None
        consumed = 0
        with inventory.stream_path.open("rb") as source:
            while True:
                line = source.readline(16_385)
                if not line:
                    break
                if len(line) > 16_384 or not line.endswith(b"\n"):
                    raise ProjectionError("persisted inventory JSONL row exceeds its bound or lacks newline")
                consumed += len(line)
                stream_digest.update(line)
                try:
                    row = json.loads(line.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError) as exc:
                    raise ProjectionError("persisted inventory JSONL row is invalid") from exc
                if not isinstance(row, dict) or canonical_bytes(row) != line:
                    raise ProjectionError("persisted inventory JSONL row is noncanonical")
                yield row, line
        if consumed != inventory.stream_bytes:
            raise ProjectionError("persisted inventory stream byte count changed")

    @staticmethod
    def _validate_inventory_path(path: Any) -> None:
        if (
            not isinstance(path, str)
            or not path
            or len(path.encode("utf-8")) > 4096
            or path.startswith("/")
            or "\\" in path
            or "\x00" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            raise ProjectionError("inventory path must be a normalized relative POSIX path")

    @staticmethod
    def _validated_inventory_proxy(
        proxy: Any,
        expected_id: str,
        path: str,
        file_digest: str,
        size: int,
    ) -> dict[str, Any]:
        if not isinstance(proxy, Mapping) or set(proxy) != {"id", "entity_type", "payload"}:
            raise ProjectionError("inventory semantic proxy fields mismatch")
        if proxy["id"] != expected_id or proxy["entity_type"] != "Artifact":
            raise ProjectionError("inventory semantic proxy identity is not runtime-derived")
        if not isinstance(proxy["payload"], Mapping):
            raise ProjectionError("inventory Artifact payload must be an object")
        payload = copy.deepcopy(dict(proxy["payload"]))
        if _INVENTORY_RESERVED_PAYLOAD_FIELDS & set(payload):
            raise ProjectionError("inventory Artifact payload contains reserved provenance")
        if payload.get("record_type") != "Artifact":
            raise ProjectionError("inventory semantic proxy must contain an Artifact")
        if payload.get("artifact_id") not in (None, expected_id):
            raise ProjectionError("inventory Artifact ID differs from runtime-derived identity")
        if payload.get("digest") not in (None, file_digest):
            raise ProjectionError("inventory Artifact digest differs from verified inventory")
        if payload.get("size_bytes") not in (None, size):
            raise ProjectionError("inventory Artifact size differs from verified inventory")
        payload["artifact_id"] = expected_id
        payload["digest"] = file_digest
        payload["size_bytes"] = size
        payload["inventory_path"] = path
        payload["inventory_digest"] = file_digest
        payload["inventory_size"] = size
        return payload

    def _insert_entity(
        self,
        connection: sqlite3.Connection,
        entity_id: str,
        entity_type: str,
        data_class: str,
        payload: Mapping[str, Any],
        *,
        replace_event_state: bool = False,
        search_text: str | None = None,
        event_sequence: int | None = None,
        event_index: int | None = None,
    ) -> int | None:
        payload_json = canonical_bytes(payload).decode("utf-8")
        text = _entity_text(entity_id, entity_type, payload)
        if search_text:
            text += " " + search_text
        existing = connection.execute("SELECT entity_type,data_class,payload_json FROM entities WHERE id=?", (entity_id,)).fetchone()
        if existing is not None:
            if existing == (entity_type, data_class, payload_json):
                return None
            if not replace_event_state:
                raise ProjectionError(f"entity ID collision: {entity_id}")
            connection.execute("DELETE FROM entity_fts WHERE id=?", (entity_id,))
            connection.execute("DELETE FROM entities WHERE id=?", (entity_id,))
        connection.execute("INSERT INTO entities VALUES (?,?,?,?)", (entity_id, entity_type, data_class, payload_json))
        connection.execute("INSERT INTO entity_fts(id,text) VALUES (?,?)", (entity_id, text))
        if (event_sequence is None) != (event_index is None):
            raise ProjectionError("operational entity event position is incomplete")
        if event_sequence is not None:
            if (
                not isinstance(event_sequence, int)
                or isinstance(event_sequence, bool)
                or event_sequence < 1
                or not isinstance(event_index, int)
                or isinstance(event_index, bool)
                or event_index < 0
            ):
                raise ProjectionError("operational entity event position is invalid")
            connection.execute(
                "INSERT INTO operational_order VALUES (?,?,?)",
                (entity_id, event_sequence, event_index),
            )
        semantic_value = {
            "id": entity_id,
            "entity_type": entity_type,
            "data_class": data_class,
            "payload": dict(payload),
        }
        return self._upsert_semantic_row(
            connection, f"entity:{entity_id}", semantic_value
        )

    def _insert_relation(
        self, connection: sqlite3.Connection, relation: Mapping[str, Any]
    ) -> int | None:
        required = {
            "record_type", "relation_id", "kind", "source_type", "source_id", "target_type",
            "target_id", "activation_digest", "created_at",
        }
        if not isinstance(relation, Mapping) or set(relation) != required or relation["record_type"] != "Relation":
            raise ProjectionError("Relation fields mismatch")
        parse_timestamp(relation["created_at"])
        if not self.relation_domains:
            raise ProjectionError("relation domains are required to project typed relations")
        domain = self.relation_domains.get(relation["kind"])
        if domain is None or relation["source_type"] not in domain[0] or relation["target_type"] not in domain[1]:
            raise ProjectionError("Relation violates canonical domain/range")
        payload_json = canonical_bytes(dict(relation)).decode("utf-8")
        existing = connection.execute("SELECT payload_json FROM relations WHERE id=?", (relation["relation_id"],)).fetchone()
        if existing is not None:
            if existing[0] != payload_json:
                raise ProjectionError(f"relation ID collision: {relation['relation_id']}")
            return None
        connection.execute(
            "INSERT INTO relations VALUES (?,?,?,?,?,?,?,?)",
            (
                relation["relation_id"], relation["kind"], relation["source_type"], relation["source_id"],
                relation["target_type"], relation["target_id"], relation["created_at"], payload_json,
            ),
        )
        return self._upsert_semantic_row(
            connection, f"relation:{relation['relation_id']}", dict(relation)
        )

    @staticmethod
    def _semantic_location(key: str) -> tuple[int, int]:
        """Locate one row in its immutable two-level shard commitment."""

        key_digest = hashlib.sha256(key.encode("utf-8")).digest()
        return key_digest[0], key_digest[1]

    @classmethod
    def _semantic_shard(cls, key: str) -> int:
        return cls._semantic_location(key)[0]

    @classmethod
    def _semantic_bucket(cls, key: str) -> int:
        return cls._semantic_location(key)[1]

    @classmethod
    def _upsert_semantic_row(
        cls,
        connection: sqlite3.Connection,
        key: str,
        value: Mapping[str, Any],
    ) -> int:
        shard, bucket = cls._semantic_location(key)
        row_digest = hashlib.sha256(canonical_bytes(dict(value))).digest()
        connection.execute(
            "INSERT INTO semantic_rows(shard,bucket,key,row_digest) VALUES (?,?,?,?) "
            "ON CONFLICT(shard,key) DO UPDATE SET "
            "bucket=excluded.bucket,row_digest=excluded.row_digest",
            (shard, bucket, key, row_digest),
        )
        connection.execute(
            "INSERT OR IGNORE INTO semantic_dirty_buckets(shard,bucket) VALUES (?,?)",
            (shard, bucket),
        )
        return shard

    @staticmethod
    @functools.lru_cache(maxsize=None)
    def _empty_semantic_bucket_digest(shard: int, bucket: int) -> str:
        return digest_value(
            {
                "algorithm": _SEMANTIC_DIGEST_ALGORITHM,
                "shard": shard,
                "bucket": bucket,
                "rows": [],
            }
        )

    @classmethod
    def _semantic_bucket_digest(
        cls,
        shard: int,
        bucket: int,
        rows: Sequence[tuple[str, bytes]],
    ) -> str:
        return digest_value(
            {
                "algorithm": _SEMANTIC_DIGEST_ALGORITHM,
                "shard": shard,
                "bucket": bucket,
                "rows": [
                    {"key": key, "row_digest": bytes(row_digest).hex()}
                    for key, row_digest in rows
                ],
            }
        )

    @staticmethod
    @functools.lru_cache(maxsize=None)
    def _empty_semantic_group_digest(shard: int, group_index: int) -> str:
        buckets = tuple(
            (
                bucket,
                0,
                Projection._empty_semantic_bucket_digest(shard, bucket),
            )
            for bucket in range(
                group_index * _SEMANTIC_GROUP_WIDTH,
                (group_index + 1) * _SEMANTIC_GROUP_WIDTH,
            )
        )
        return Projection._semantic_group_digest(shard, group_index, buckets)

    @staticmethod
    def _semantic_group_digest(
        shard: int,
        group_index: int,
        buckets: Sequence[tuple[int, int, str]],
    ) -> str:
        if len(buckets) != _SEMANTIC_GROUP_WIDTH:
            raise ProjectionError("semantic group cache is incomplete")
        return digest_value(
            {
                "algorithm": _SEMANTIC_DIGEST_ALGORITHM,
                "shard": shard,
                "group": group_index,
                "buckets": [
                    {
                        "bucket": bucket,
                        "row_count": row_count,
                        "digest": digest,
                    }
                    for bucket, row_count, digest in buckets
                ],
            }
        )

    @staticmethod
    def _semantic_shard_digest(
        shard: int,
        groups: Sequence[tuple[int, int, str]],
    ) -> str:
        if len(groups) != _SEMANTIC_GROUP_COUNT:
            raise ProjectionError("semantic shard cache is incomplete")
        return digest_value(
            {
                "algorithm": _SEMANTIC_DIGEST_ALGORITHM,
                "shard": shard,
                "groups": [
                    {
                        "group": group_index,
                        "row_count": row_count,
                        "digest": digest,
                    }
                    for group_index, row_count, digest in groups
                ],
            }
        )

    @classmethod
    def _recompute_semantic_shards(
        cls,
        connection: sqlite3.Connection,
        shards: Iterable[int],
        *,
        full_rebuild: bool = False,
    ) -> None:
        requested_shards = sorted(set(shards))
        for shard in requested_shards:
            if not 0 <= shard < _SEMANTIC_SHARD_COUNT:
                raise ProjectionError("semantic shard index is outside its bound")
        if full_rebuild:
            cls._rebuild_semantic_shard_commitments(connection, requested_shards)
            connection.execute("DELETE FROM semantic_dirty_buckets")
            return

        placeholders = ",".join("?" for _ in requested_shards)
        dirty_rows = (
            list(
                connection.execute(
                    "SELECT shard,bucket FROM semantic_dirty_buckets "
                    f"WHERE shard IN ({placeholders}) ORDER BY shard,bucket",
                    tuple(requested_shards),
                )
            )
            if requested_shards
            else []
        )
        if not dirty_rows:
            return
        changed_groups: set[tuple[int, int]] = set()
        for shard, bucket in dirty_rows:
            rows = list(
                connection.execute(
                    "SELECT key,row_digest FROM semantic_rows "
                    "WHERE shard=? AND bucket=? ORDER BY key",
                    (shard, bucket),
                )
            )
            if rows:
                connection.execute(
                    "INSERT INTO semantic_bucket_commitments(shard,bucket,row_count,digest) "
                    "VALUES (?,?,?,?) ON CONFLICT(shard,bucket) DO UPDATE SET "
                    "row_count=excluded.row_count,digest=excluded.digest",
                    (
                        shard,
                        bucket,
                        len(rows),
                        cls._semantic_bucket_digest(shard, bucket, rows),
                    ),
                )
            else:
                connection.execute(
                    "DELETE FROM semantic_bucket_commitments WHERE shard=? AND bucket=?",
                    (shard, bucket),
                )
            changed_groups.add((shard, bucket // _SEMANTIC_GROUP_WIDTH))

        changed_shards: set[int] = set()
        for shard, group_index in sorted(changed_groups):
            bucket_rows = {
                int(bucket): (int(row_count), str(digest))
                for bucket, row_count, digest in connection.execute(
                    "SELECT bucket,row_count,digest FROM semantic_bucket_commitments "
                    "WHERE shard=? AND bucket>=? AND bucket<? ORDER BY bucket",
                    (
                        shard,
                        group_index * _SEMANTIC_GROUP_WIDTH,
                        (group_index + 1) * _SEMANTIC_GROUP_WIDTH,
                    ),
                )
            }
            buckets = tuple(
                (
                    bucket,
                    *bucket_rows.get(
                        bucket,
                        (0, cls._empty_semantic_bucket_digest(shard, bucket)),
                    ),
                )
                for bucket in range(
                    group_index * _SEMANTIC_GROUP_WIDTH,
                    (group_index + 1) * _SEMANTIC_GROUP_WIDTH,
                )
            )
            row_count = sum(value[1] for value in buckets)
            if row_count:
                connection.execute(
                    "INSERT INTO semantic_group_commitments(shard,group_index,row_count,digest) "
                    "VALUES (?,?,?,?) ON CONFLICT(shard,group_index) DO UPDATE SET "
                    "row_count=excluded.row_count,digest=excluded.digest",
                    (
                        shard,
                        group_index,
                        row_count,
                        cls._semantic_group_digest(shard, group_index, buckets),
                    ),
                )
            else:
                connection.execute(
                    "DELETE FROM semantic_group_commitments "
                    "WHERE shard=? AND group_index=?",
                    (shard, group_index),
                )
            changed_shards.add(shard)

        for shard in sorted(changed_shards):
            group_rows = {
                int(group_index): (int(row_count), str(digest))
                for group_index, row_count, digest in connection.execute(
                    "SELECT group_index,row_count,digest FROM semantic_group_commitments "
                    "WHERE shard=? ORDER BY group_index",
                    (shard,),
                )
            }
            groups = tuple(
                (
                    group_index,
                    *group_rows.get(
                        group_index,
                        (
                            0,
                            cls._empty_semantic_group_digest(shard, group_index),
                        ),
                    ),
                )
                for group_index in range(_SEMANTIC_GROUP_COUNT)
            )
            connection.execute(
                "INSERT INTO semantic_shards(shard,row_count,digest) VALUES (?,?,?) "
                "ON CONFLICT(shard) DO UPDATE SET row_count=excluded.row_count,digest=excluded.digest",
                (
                    shard,
                    sum(value[1] for value in groups),
                    cls._semantic_shard_digest(shard, groups),
                ),
            )
        connection.execute(
            "DELETE FROM semantic_dirty_buckets "
            f"WHERE shard IN ({placeholders})",
            tuple(requested_shards),
        )

    @classmethod
    def _rebuild_semantic_shard_commitments(
        cls,
        connection: sqlite3.Connection,
        shards: Sequence[int],
    ) -> None:
        """Build all cache rows in bounded SQLite batches during a full rebuild."""

        connection.execute("DELETE FROM semantic_bucket_commitments")
        connection.execute("DELETE FROM semantic_group_commitments")
        connection.execute("DELETE FROM semantic_shards")
        bucket_commitments: list[tuple[int, int, int, str]] = []
        group_commitments: list[tuple[int, int, int, str]] = []
        shard_commitments: list[tuple[int, int, str]] = []
        for shard in shards:
            bucket_rows: dict[int, list[tuple[str, bytes]]] = {}
            for bucket, key, row_digest in connection.execute(
                "SELECT bucket,key,row_digest FROM semantic_rows "
                "WHERE shard=? ORDER BY bucket,key",
                (shard,),
            ):
                bucket_rows.setdefault(int(bucket), []).append(
                    (str(key), bytes(row_digest))
                )
            cached_buckets: dict[int, tuple[int, str]] = {}
            for bucket, rows in sorted(bucket_rows.items()):
                digest = cls._semantic_bucket_digest(shard, bucket, rows)
                cached_buckets[bucket] = (len(rows), digest)
                bucket_commitments.append((shard, bucket, len(rows), digest))
            cached_groups: dict[int, tuple[int, str]] = {}
            for group_index in range(_SEMANTIC_GROUP_COUNT):
                buckets = tuple(
                    (
                        bucket,
                        *cached_buckets.get(
                            bucket,
                            (0, cls._empty_semantic_bucket_digest(shard, bucket)),
                        ),
                    )
                    for bucket in range(
                        group_index * _SEMANTIC_GROUP_WIDTH,
                        (group_index + 1) * _SEMANTIC_GROUP_WIDTH,
                    )
                )
                row_count = sum(value[1] for value in buckets)
                if not row_count:
                    continue
                digest = cls._semantic_group_digest(shard, group_index, buckets)
                cached_groups[group_index] = (row_count, digest)
                group_commitments.append((shard, group_index, row_count, digest))
            groups = tuple(
                (
                    group_index,
                    *cached_groups.get(
                        group_index,
                        (0, cls._empty_semantic_group_digest(shard, group_index)),
                    ),
                )
                for group_index in range(_SEMANTIC_GROUP_COUNT)
            )
            shard_commitments.append(
                (
                    shard,
                    sum(value[1] for value in groups),
                    cls._semantic_shard_digest(shard, groups),
                )
            )
        cls._insert_bulk_values(
            connection,
            "semantic_bucket_commitments",
            ("shard", "bucket", "row_count", "digest"),
            bucket_commitments,
        )
        cls._insert_bulk_values(
            connection,
            "semantic_group_commitments",
            ("shard", "group_index", "row_count", "digest"),
            group_commitments,
        )
        # Keep one observable write per bounded root shard.  The profiler uses
        # this exact 256-root trace as evidence that a rebuild sealed every
        # semantic partition; the row/bucket cache inserts above remain bulk.
        for shard, row_count, digest in shard_commitments:
            connection.execute(
                "INSERT INTO semantic_shards(shard,row_count,digest) VALUES (?,?,?)",
                (shard, row_count, digest),
            )

    @staticmethod
    def _validate_relation_closure(connection: sqlite3.Connection) -> None:
        broken = connection.execute(
            """
            SELECT r.id,r.source_type,r.source_id,r.target_type,r.target_id,
                   source.entity_type,target.entity_type
            FROM relations AS r
            LEFT JOIN entities AS source ON source.id=r.source_id
            LEFT JOIN entities AS target ON target.id=r.target_id
            WHERE source.id IS NULL OR target.id IS NULL
               OR source.entity_type<>r.source_type OR target.entity_type<>r.target_type
            ORDER BY r.id LIMIT 1
            """
        ).fetchone()
        if broken is not None:
            raise ProjectionError(
                "typed Relation endpoint is missing or has the wrong entity type: " + broken[0]
            )

    @staticmethod
    def _validate_dependency_graph_acyclic(
        connection: sqlite3.Connection,
    ) -> None:
        """Reject any cycle in the exact current Task DEPENDS_ON graph."""

        task_ids = {
            row[0]
            for row in connection.execute(
                "SELECT id FROM entities WHERE entity_type='Task'"
            )
        }
        outgoing = {task_id: set() for task_id in task_ids}
        indegree = {task_id: 0 for task_id in task_ids}
        for source_id, target_id in connection.execute(
            """
            SELECT source_id,target_id FROM relations
            WHERE kind='DEPENDS_ON'
            ORDER BY source_id,target_id,id
            """
        ):
            if source_id not in task_ids or target_id not in task_ids:
                raise ProjectionError("DEPENDS_ON references a non-current Task")
            if target_id in outgoing[source_id]:
                continue
            outgoing[source_id].add(target_id)
            indegree[target_id] += 1
        ready = deque(sorted(task_id for task_id, degree in indegree.items() if degree == 0))
        visited = 0
        while ready:
            task_id = ready.popleft()
            visited += 1
            for target_id in sorted(outgoing[task_id]):
                indegree[target_id] -= 1
                if indegree[target_id] == 0:
                    ready.append(target_id)
        if visited != len(task_ids):
            raise ProjectionError("DEPENDS_ON graph contains a cycle")

    @staticmethod
    def _validate_changed_relation_closure(
        connection: sqlite3.Connection, relation_ids: Iterable[str]
    ) -> None:
        selected = sorted(set(relation_ids))
        if not selected:
            return
        placeholders = ",".join("?" for _ in selected)
        broken = connection.execute(
            f"""
            SELECT r.id,r.source_type,r.source_id,r.target_type,r.target_id,
                   source.entity_type,target.entity_type
            FROM relations AS r
            LEFT JOIN entities AS source ON source.id=r.source_id
            LEFT JOIN entities AS target ON target.id=r.target_id
            WHERE r.id IN ({placeholders})
              AND (source.id IS NULL OR target.id IS NULL
                   OR source.entity_type<>r.source_type OR target.entity_type<>r.target_type)
            ORDER BY r.id LIMIT 1
            """,
            selected,
        ).fetchone()
        if broken is not None:
            raise ProjectionError(
                "changed Relation endpoint is missing or has the wrong entity type: "
                + broken[0]
            )

    def apply_committed_batch(
        self,
        event_store: EventStore,
        *,
        crash_hook: Callable[[str], Any] | None = None,
    ) -> dict[str, Any]:
        """Stream every missing authoritative batch into one projection commit."""

        if not os.path.isfile(filesystem_path(self.db_path)):
            return {
                "status": "missing",
                "projection_authoritative": False,
                "changed_records": 0,
                "changed_shards": 0,
                "physical_payload_bytes": 0,
                "bytes_per_changed_record": 0.0,
            }
        if event_store.active_activation_digest == "":
            raise ProjectionError("event store lacks Activation")
        if event_store.implementation_closure_digest != self.implementation_closure_digest:
            raise ProjectionError(
                "event store implementation closure differs from projection runtime"
            )
        before = self.status()
        current_head = event_store.head()
        if (
            before["head_sequence"] == current_head["sequence"]
            and before["head_digest"] == current_head["batch_digest"]
        ):
            return {
                "status": "already-current",
                "projection_authoritative": False,
                "changed_records": 0,
                "changed_shards": 0,
                "physical_payload_bytes": 0,
                "bytes_per_changed_record": 0.0,
            }
        if (
            before["activation_digest"] != event_store.active_activation_digest
            or before["head_sequence"] > current_head["sequence"]
            or (
                before["head_sequence"] == current_head["sequence"]
                and before["head_digest"] != current_head["batch_digest"]
            )
        ):
            return {
                "status": "stale-rebuild-required",
                "projection_authoritative": False,
                "changed_records": 0,
                "changed_shards": 0,
                "physical_payload_bytes": 0,
                "bytes_per_changed_record": 0.0,
            }
        if before["head_sequence"] == 0:
            if before["head_digest"] is not None:
                raise ProjectionError("empty projection HEAD has a batch digest")
            bound_head = {"sequence": 0, "batch_id": None, "batch_digest": None}
        else:
            if not isinstance(before["head_digest"], str):
                raise ProjectionError("projection HEAD digest is missing")
            try:
                prior = event_store.read_envelope(before["head_digest"])["batch"]
            except EventStoreError:
                return {
                    "status": "stale-rebuild-required",
                    "projection_authoritative": False,
                    "changed_records": 0,
                    "changed_shards": 0,
                    "physical_payload_bytes": 0,
                    "bytes_per_changed_record": 0.0,
                }
            if prior["sequence"] != before["head_sequence"]:
                raise ProjectionError("projection HEAD sequence and digest disagree")
            bound_head = {
                "sequence": prior["sequence"],
                "batch_id": prior["batch_id"],
                "batch_digest": before["head_digest"],
            }

        before_bytes = os.stat(filesystem_path(self.db_path)).st_size
        changed_shards: set[int] = set()
        changed_relations: list[str] = []
        dependency_graph_changed = False
        changed_records = 0
        logical_payload_bytes = 0
        applied_batches = 0
        applied_events = 0
        final_head = dict(bound_head)
        connection = sqlite3.connect(sqlite_path(self.db_path))
        try:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            self._ensure_semantic_dirty_buckets(connection)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM continuations")
            connection.execute("DELETE FROM ready_frontiers")
            for envelope in event_store.iter_envelopes_after(bound_head):
                batch = envelope["batch"]
                for event_index, event in enumerate(batch["events"]):
                    event_shards, relation_ids, event_changed_records = (
                        self._apply_event(
                            connection,
                            event,
                            state_binding_delta=batch["state_binding_delta"],
                            event_sequence=batch["sequence"],
                            event_index=event_index,
                        )
                    )
                    changed_shards.update(event_shards)
                    changed_relations.extend(relation_ids)
                    dependency_graph_changed = dependency_graph_changed or (
                        event_changed_records > 0
                        and event["event_kind"] == "relation.recorded"
                        and event["payload"]["kind"] == "DEPENDS_ON"
                    )
                    changed_records += event_changed_records
                    logical_payload_bytes += len(canonical_bytes(event["payload"]))
                    applied_events += 1
                applied_batches += 1
                final_head = {
                    "sequence": batch["sequence"],
                    "batch_id": batch["batch_id"],
                    "batch_digest": digest_value(batch),
                }
            if applied_batches == 0:
                raise ProjectionError("incremental projection tail is empty")
            self._validate_changed_relation_closure(connection, changed_relations)
            if dependency_graph_changed:
                self._validate_dependency_graph_acyclic(connection)
            self._recompute_semantic_shards(connection, changed_shards)
            semantic_digest = self._semantic_digest_connection(connection)
            entity_count, relation_count = self._read_projection_cardinality(connection)
            metadata_updates = {
                "head_digest": final_head["batch_digest"] or "",
                "head_sequence": str(final_head["sequence"]),
                "semantic_digest": semantic_digest,
                "entity_count": str(entity_count),
                "relation_count": str(relation_count),
                "event_count": str(before["event_count"] + applied_events),
                "built_at": utc_now(),
                "incremental_commit_count": str(
                    before["incremental_commit_count"] + applied_batches
                ),
                "incremental_changed_records": str(
                    before["incremental_changed_records"] + changed_records
                ),
            }
            connection.executemany(
                "UPDATE metadata SET value=? WHERE key=?",
                [(value, key) for key, value in sorted(metadata_updates.items())],
            )
            logical_payload_bytes += len(canonical_bytes(metadata_updates))
            if crash_hook is not None and crash_hook("before_projection_commit"):
                raise ProjectionError("simulated crash before projection commit")
            connection.commit()
            if crash_hook is not None and crash_hook("after_projection_commit"):
                raise ProjectionError("simulated crash after projection commit")
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        after_bytes = os.stat(filesystem_path(self.db_path)).st_size
        growth_bytes = max(0, after_bytes - before_bytes)
        physical_payload_bytes = logical_payload_bytes + growth_bytes
        return {
            "status": "updated",
            "projection_authoritative": False,
            "head": final_head,
            "semantic_digest": semantic_digest,
            "changed_records": changed_records,
            "changed_shards": len(changed_shards),
            "logical_payload_bytes": logical_payload_bytes,
            "projection_growth_bytes": growth_bytes,
            "physical_payload_bytes": physical_payload_bytes,
            "bytes_per_changed_record": (
                round(physical_payload_bytes / changed_records, 6)
                if changed_records
                else 0.0
            ),
        }

    def status(self) -> dict[str, Any]:
        with self._connect_readonly() as connection:
            return self._status_connection(connection)

    def _status_connection(self, connection: sqlite3.Connection) -> dict[str, Any]:
        metadata = dict(connection.execute("SELECT key,value FROM metadata"))
        required = {
            "activation_digest", "head_digest", "head_sequence", "semantic_digest", "entity_count",
            "relation_count", "inventory_entries", "inventory_proxies", "inventory_relations",
            "inventory_passes", "product_passes", "event_count", "built_at", "projection_authoritative",
            "implementation_closure_digest", "semantic_digest_algorithm",
            "storage_layout",
            "incremental_commit_count", "incremental_changed_records",
            "projection_compaction_count",
        }
        if set(metadata) != required:
            raise ProjectionError("projection metadata is incomplete or unknown")
        if metadata["projection_authoritative"] != "false":
            raise ProjectionError(
                "projection authority metadata must be exactly 'false'"
            )
        if metadata["implementation_closure_digest"] != self.implementation_closure_digest:
            raise ProjectionError("projection implementation closure is stale")
        if metadata["semantic_digest_algorithm"] != _SEMANTIC_DIGEST_ALGORITHM:
            raise ProjectionError("projection semantic digest algorithm is stale")
        if metadata["storage_layout"] != _PROJECTION_STORAGE_LAYOUT:
            raise ProjectionError("projection storage layout is stale")
        semantic_digest = self._semantic_digest_connection(connection)
        if metadata["semantic_digest"] != semantic_digest:
            raise ProjectionError("projection semantic metadata differs from its snapshot")
        numeric_keys = (
            "head_sequence", "entity_count", "relation_count", "inventory_entries",
            "inventory_proxies", "inventory_relations", "inventory_passes",
            "product_passes", "event_count", "incremental_commit_count",
            "incremental_changed_records", "projection_compaction_count",
        )
        try:
            numeric = {key: int(metadata[key]) for key in numeric_keys}
            page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
            page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        except (TypeError, ValueError, sqlite3.Error) as exc:
            raise ProjectionError("projection metadata numeric value is invalid") from exc
        if any(value < 0 for value in numeric.values()) or page_count < 0 or page_size < 1:
            raise ProjectionError("projection metadata numeric value is outside its range")
        if (
            not _DIGEST.fullmatch(metadata["activation_digest"])
            or not _DIGEST.fullmatch(metadata["semantic_digest"])
            or (
                numeric["head_sequence"] == 0
                and metadata["head_digest"] != ""
            )
            or (
                numeric["head_sequence"] > 0
                and not _DIGEST.fullmatch(metadata["head_digest"])
            )
            or numeric["event_count"] < numeric["head_sequence"]
            or numeric["inventory_proxies"] > numeric["inventory_entries"]
            or numeric["inventory_passes"] not in {0, 1}
            or numeric["product_passes"] != 0
        ):
            raise ProjectionError("projection metadata binding is invalid")
        try:
            parse_timestamp(metadata["built_at"])
            actual_entity_count, actual_relation_count = self._read_projection_cardinality(
                connection
            )
        except (EventStoreError, sqlite3.Error, TypeError, ValueError) as exc:
            raise ProjectionError("projection snapshot counts are unreadable") from exc
        if (
            actual_entity_count != numeric["entity_count"]
            or actual_relation_count != numeric["relation_count"]
        ):
            raise ProjectionError("projection metadata counts differ from its snapshot")
        inventory_entries = numeric["inventory_entries"]
        inventory_proxies = numeric["inventory_proxies"]
        return {
            **metadata,
            "head_digest": metadata["head_digest"] or None,
            "head_sequence": numeric["head_sequence"],
            "entity_count": numeric["entity_count"],
            "relation_count": numeric["relation_count"],
            "inventory_entries": inventory_entries,
            "inventory_proxies": inventory_proxies,
            "inventory_relations": numeric["inventory_relations"],
            "inventory_passes": numeric["inventory_passes"],
            "product_passes": numeric["product_passes"],
            "event_count": numeric["event_count"],
            "incremental_commit_count": numeric["incremental_commit_count"],
            "incremental_changed_records": numeric["incremental_changed_records"],
            "projection_compaction_count": numeric["projection_compaction_count"],
            "raw_file_proxy_ratio": inventory_proxies / inventory_entries if inventory_entries else 1.0,
            "synthetic_task_count": 0,
            "synthetic_task_ratio": 0.0,
            "projection_db_bytes": page_count * page_size,
            "projection_authoritative": False,
        }

    @staticmethod
    def _read_projection_cardinality(
        connection: sqlite3.Connection,
    ) -> tuple[int, int]:
        try:
            rows = connection.execute(
                """
                SELECT entity_count,relation_count
                FROM projection_cardinality
                WHERE singleton=1
                """
            ).fetchall()
        except sqlite3.Error as exc:
            raise ProjectionError("projection snapshot counts are unreadable") from exc
        if len(rows) != 1:
            raise ProjectionError("projection snapshot counts are unreadable")
        entity_count, relation_count = rows[0]
        if (
            type(entity_count) is not int
            or type(relation_count) is not int
            or entity_count < 0
            or relation_count < 0
        ):
            raise ProjectionError("projection snapshot counts are unreadable")
        return entity_count, relation_count

    def require_current(self, event_store: EventStore) -> dict[str, Any]:
        status = self.status()
        head = event_store.head()
        if status["activation_digest"] != event_store.active_activation_digest:
            raise ProjectionError("projection Activation is stale")
        if getattr(event_store, "implementation_closure_digest", None) != self.implementation_closure_digest:
            raise ProjectionError("projection implementation closure differs from event store")
        if status["head_digest"] != head["batch_digest"] or status["head_sequence"] != head["sequence"]:
            raise ProjectionError("projection HEAD is stale")
        return status

    def semantic_digest(self) -> str:
        with self._connect_readonly() as connection:
            status = self._status_connection(connection)
            return status["semantic_digest"]

    @staticmethod
    def _semantic_digest_connection(connection: sqlite3.Connection) -> str:
        rows = list(
            connection.execute(
                "SELECT shard,row_count,digest FROM semantic_shards ORDER BY shard"
            )
        )
        if len(rows) != _SEMANTIC_SHARD_COUNT or any(
            shard != expected for expected, (shard, _count, _digest) in enumerate(rows)
        ):
            raise ProjectionError("projection semantic shard set is incomplete")
        if any(
            not isinstance(row_digest, str) or not _DIGEST.fullmatch(row_digest)
            for _shard, _count, row_digest in rows
        ):
            raise ProjectionError("projection semantic shard digest is invalid")
        return digest_value(
            {
                "algorithm": _SEMANTIC_DIGEST_ALGORITHM,
                "shards": [
                    {
                        "shard": shard,
                        "row_count": row_count,
                        "digest": row_digest,
                    }
                    for shard, row_count, row_digest in rows
                ],
            }
        )

    def search(
        self,
        query: str,
        *,
        depth: int | None = None,
        budget: Mapping[str, int] | None = None,
        ranking: str | None = None,
        continuation_token: str | None = None,
        resume_binding: Mapping[str, str] | None = None,
        now: str | _datetime.datetime | None = None,
        ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        resolved_depth = self.limits.default_depth if depth is None else depth
        resolved_ttl = (
            self.limits.default_ttl_seconds
            if ttl_seconds is None
            else ttl_seconds
        )
        resolved_ranking = (
            self.limits.ranking_algorithm_id if ranking is None else ranking
        )
        if continuation_token is not None:
            return self._continue_bound(
                continuation_token,
                query=query,
                depth=resolved_depth,
                budget=budget,
                ranking=resolved_ranking,
                resume_binding=resume_binding,
                now=now,
                ttl_seconds=resolved_ttl,
            )
        normalized_query = self._normalize_query(query)
        checked_budget = self._validate_budget(
            self.limits.default_budget if budget is None else budget
        )
        checked_binding = self._validate_resume_binding(resume_binding)
        if (
            not isinstance(resolved_depth, int)
            or isinstance(resolved_depth, bool)
            or not self.limits.depth_min <= resolved_depth <= self.limits.depth_max
        ):
            raise ProjectionError("search depth is outside the verified range")
        if resolved_ranking != self.limits.ranking_algorithm_id:
            raise ProjectionError("unsupported deterministic ranking")
        if (
            not isinstance(resolved_ttl, int)
            or isinstance(resolved_ttl, bool)
            or not self.limits.ttl_min_seconds
            <= resolved_ttl
            <= self.limits.ttl_max_seconds
        ):
            raise ProjectionError("continuation TTL is outside the verified range")
        if resolved_depth > 0 and checked_budget["max_relations"] < 1:
            raise ProjectionError("positive-depth search requires a positive relation budget")
        issued_at = _canonical_now(now)
        expiry = format_utc_second(
            parse_timestamp(issued_at)
            + _datetime.timedelta(seconds=resolved_ttl)
        )
        database_path = self.db_path
        # A complete first page has no persistent state.  Keep its snapshot
        # genuinely read-only, and only rerun through the mutable route when
        # truncation requires an externally resumable continuation receipt.
        with self._connect_readonly(db_path=database_path) as connection:
            initial_result = self._search_page(
                normalized_query,
                resolved_depth,
                checked_budget,
                resolved_ranking,
                0,
                issued_at,
                expiry,
                resolved_ttl,
                checked_binding,
                connection=connection,
                persist_continuation=False,
                database_path=database_path,
            )
        if not initial_result["truncated"]:
            return initial_result
        with self._connect_mutable(db_path=database_path) as connection:
            return self._search_page(
                normalized_query,
                resolved_depth,
                checked_budget,
                resolved_ranking,
                0,
                issued_at,
                expiry,
                resolved_ttl,
                checked_binding,
                connection=connection,
                database_path=database_path,
            )

    def ready_frontier(
        self,
        *,
        resume_binding: Mapping[str, str],
        limit: int | None = None,
        budget: Mapping[str, int] | None = None,
        now: str | _datetime.datetime | None = None,
        ttl_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Derive one bounded ReadyFrontier page from the current projection DAG."""

        checked_budget = self._validate_budget(
            self.limits.default_budget if budget is None else budget
        )
        page_limit = checked_budget["top_k"] if limit is None else limit
        if (
            not isinstance(page_limit, int)
            or isinstance(page_limit, bool)
            or not 1 <= page_limit <= checked_budget["top_k"]
        ):
            raise ProjectionError("ReadyFrontier page limit is outside the budget")
        checked_budget["top_k"] = page_limit
        checked_binding = self._validate_resume_binding(resume_binding)
        resolved_ttl = (
            self.limits.default_ttl_seconds
            if ttl_seconds is None
            else ttl_seconds
        )
        if (
            not isinstance(resolved_ttl, int)
            or isinstance(resolved_ttl, bool)
            or not self.limits.ttl_min_seconds
            <= resolved_ttl
            <= self.limits.ttl_max_seconds
        ):
            raise ProjectionError("continuation TTL is outside the verified range")
        issued_at = _canonical_now(now)
        expiry = format_utc_second(
            parse_timestamp(issued_at)
            + _datetime.timedelta(seconds=resolved_ttl)
        )
        with self._connect_mutable() as connection:
            status = self._status_connection(connection)
            self._validate_resume_snapshot_binding(checked_binding, status)
            eligible, evaluated_count, blocked_count, frontier_digest = (
                self._eligible_ready_tasks(connection, status)
            )
            task_records = tuple(
                parse_json_strict(
                    connection.execute(
                        "SELECT payload_json FROM entities WHERE id=?",
                        (item["task_id"],),
                    ).fetchone()[0].encode("utf-8")
                )
                for item in eligible
            )
            complete_frontier = {
                "record_type": "ReadyFrontier",
                "activation_digest": status["activation_digest"],
                "head_digest": status["head_digest"],
                "projection_digest": status["semantic_digest"],
                "ordering": list(_READY_FRONTIER_ORDERING),
                "ready_tasks": eligible,
                "evaluated_task_count": evaluated_count,
                "blocked_task_count": blocked_count,
                "cycle_count": 0,
                "truncated": False,
                "continuation": None,
                "silent_truncation": False,
                "projection_authoritative": False,
            }
            self._validate_ready_frontier(
                complete_frontier,
                task_records,
                status,
                connection,
            )
            state_id = digest_value(
                {
                    "frontier_digest": frontier_digest,
                    "issued_at": issued_at,
                    "expiry": expiry,
                    "budget": checked_budget,
                    "resume_binding": checked_binding,
                }
            )
            connection.execute(
                "DELETE FROM ready_frontiers WHERE expires_at<=?",
                (issued_at,),
            )
            connection.execute(
                "INSERT OR REPLACE INTO ready_frontiers VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    state_id,
                    frontier_digest,
                    status["activation_digest"],
                    status["head_digest"],
                    status["semantic_digest"],
                    len(eligible),
                    evaluated_count,
                    blocked_count,
                    expiry,
                ),
            )
            connection.executemany(
                "INSERT INTO ready_frontier_tasks VALUES (?,?,?,?,?)",
                [
                    (
                        state_id,
                        ordinal,
                        item["task_id"],
                        item["task_digest"],
                        canonical_bytes(item).decode("utf-8"),
                    )
                    for ordinal, item in enumerate(eligible)
                ],
            )
            return self._ready_frontier_page(
                state_id,
                frontier_digest,
                checked_budget,
                0,
                issued_at,
                expiry,
                resolved_ttl,
                checked_binding,
                connection=connection,
            )

    def work_card_projection(
        self,
        task_id: str,
        *,
        task_digest: str,
        resume_binding: Mapping[str, str],
        budget: Mapping[str, int] | None = None,
    ) -> dict[str, Any]:
        """Materialize one exact selected Task without recomputing eligibility."""

        if not isinstance(task_id, str) or not task_id:
            raise ProjectionError("selected WorkCard Task ID is invalid")
        if not isinstance(task_digest, str) or _DIGEST.fullmatch(task_digest) is None:
            raise ProjectionError("selected WorkCard Task digest is invalid")
        checked_budget = self._validate_budget(
            self.limits.default_budget if budget is None else budget
        )
        checked_binding = self._validate_resume_binding(resume_binding)
        with self._connect_readonly() as connection:
            status = self._status_connection(connection)
            self._validate_resume_snapshot_binding(checked_binding, status)
            entity = self._entity_row(connection, task_id)
            if (
                entity["entity_type"] != "Task"
                or entity["data_class"] != "operational-record"
                or entity["source_digest"] != task_digest
            ):
                raise ProjectionError("selected WorkCard Task is stale or substituted")
            result = {
                "record_type": "WorkCardProjection",
                "activation_digest": status["activation_digest"],
                "head_digest": status["head_digest"],
                "projection_digest": status["semantic_digest"],
                "task_id": task_id,
                "task_digest": task_digest,
                "task": entity,
                "budget": checked_budget,
                "projection_authoritative": False,
            }
            if len(canonical_bytes(result)) > checked_budget["max_bytes"]:
                raise ProjectionError("WorkCardProjection exceeds its byte budget")
            return result

    def continue_search(
        self,
        token: str,
        *,
        resume_binding: Mapping[str, str],
        now: str | _datetime.datetime | None = None,
    ) -> dict[str, Any]:
        current_time = _canonical_now(now)
        checked_binding = self._validate_resume_binding(resume_binding)
        with self._connect_mutable() as connection:
            payload = self._decode_token(connection, token, current_time)
            if payload["resume_binding"] != checked_binding:
                raise ContinuationError("continuation authorization binding mismatch")
            if payload["route"] == _READY_FRONTIER_ROUTE:
                return self._ready_frontier_page(
                    payload["frontier_state_id"],
                    payload["frontier_digest"],
                    payload["budget"],
                    payload["cursor"],
                    payload["issued_at"],
                    payload["expiry"],
                    payload["ttl_seconds"],
                    payload["resume_binding"],
                    token_binding=payload,
                    connection=connection,
                )
            if payload["route"] != _SEARCH_ROUTE:
                raise ContinuationError("continuation route is unsupported")
            return self._search_page(
                payload["query"],
                payload["depth"],
                payload["budget"],
                payload["ranking"],
                payload["cursor"],
                payload["issued_at"],
                payload["expiry"],
                payload["ttl_seconds"],
                payload["resume_binding"],
                token_binding=payload,
                connection=connection,
            )

    def renew_search(
        self,
        token: str,
        *,
        query: str,
        depth: int,
        budget: Mapping[str, int],
        ranking: str,
        resume_binding: Mapping[str, str],
        now: str | _datetime.datetime | None = None,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        """Issue a fresh token for an authenticated, still-valid search cursor."""

        current_time = _canonical_now(now)
        checked_budget = self._validate_budget(budget)
        expected = {
            "query": self._normalize_query(query),
            "depth": depth,
            "budget": checked_budget,
            "ranking": ranking,
            "ttl_seconds": ttl_seconds,
            "resume_binding": self._validate_resume_binding(resume_binding),
        }
        if (
            not isinstance(ttl_seconds, int)
            or isinstance(ttl_seconds, bool)
            or not self.limits.ttl_min_seconds <= ttl_seconds <= self.limits.ttl_max_seconds
        ):
            raise ContinuationError("continuation TTL is invalid")
        with self._connect_mutable() as connection:
            payload = self._decode_token(connection, token, current_time)
            if payload["route"] != _SEARCH_ROUTE:
                raise ContinuationError("continuation route binding mismatch")
            for key, value in expected.items():
                if payload[key] != value:
                    raise ContinuationError(f"continuation {key} binding mismatch")
            status = self._status_connection(connection)
            self._validate_token_snapshot_binding(payload, status)
            issued_at = current_time
            expiry = format_utc_second(
                parse_timestamp(issued_at)
                + _datetime.timedelta(seconds=ttl_seconds)
            )
            renewed_payload = dict(payload)
            renewed_payload["issued_at"] = issued_at
            renewed_payload["expiry"] = expiry
            renewed_token = self._encode_token(connection, renewed_payload)
            return {
                "record_type": "ContinuationRenewal",
                "version": self.limits.token_version,
                "traversal": self.limits.traversal_algorithm_id,
                "token": renewed_token,
                "query": payload["query"],
                "budget": payload["budget"],
                "cursor": payload["cursor"],
                "issued_at": issued_at,
                "expiry": expiry,
                "ttl_seconds": ttl_seconds,
                "activation_digest": payload["activation_digest"],
                "head_digest": payload["head_digest"],
                "projection_digest": payload["projection_digest"],
                "implementation_closure_digest": payload["implementation_closure_digest"],
                "ranking": payload["ranking"],
                "depth": payload["depth"],
                "resume_binding": payload["resume_binding"],
                "budget_digest": digest_value(payload["budget"]),
                "resume_binding_digest": digest_value(payload["resume_binding"]),
            }

    def _continue_bound(
        self,
        token: str,
        *,
        query: str,
        depth: int,
        budget: Mapping[str, int] | None,
        ranking: str,
        resume_binding: Mapping[str, str] | None,
        now: str | _datetime.datetime | None,
        ttl_seconds: int,
    ) -> dict[str, Any]:
        current_time = _canonical_now(now)
        checked_budget = self._validate_budget(
            self.limits.default_budget if budget is None else budget
        )
        expected = {
            "query": self._normalize_query(query),
            "depth": depth,
            "budget": checked_budget,
            "ranking": ranking,
            "ttl_seconds": ttl_seconds,
            "resume_binding": self._validate_resume_binding(resume_binding),
        }
        with self._connect_mutable() as connection:
            payload = self._decode_token(connection, token, current_time)
            if payload["route"] != _SEARCH_ROUTE:
                raise ContinuationError("continuation route binding mismatch")
            for key, value in expected.items():
                if payload[key] != value:
                    raise ContinuationError(f"continuation {key} binding mismatch")
            return self._search_page(
                payload["query"],
                depth,
                checked_budget,
                ranking,
                payload["cursor"],
                payload["issued_at"],
                payload["expiry"],
                ttl_seconds,
                payload["resume_binding"],
                token_binding=payload,
                connection=connection,
            )

    def _search_page(
        self,
        query: str,
        depth: int,
        budget: dict[str, int],
        ranking: str,
        cursor: int,
        issued_at: str,
        expiry: str,
        ttl_seconds: int,
        resume_binding: dict[str, str] | None,
        token_binding: Mapping[str, Any] | None = None,
        connection: sqlite3.Connection | None = None,
        persist_continuation: bool = True,
        database_path: Path | None = None,
    ) -> dict[str, Any]:
        if cursor < 0:
            raise ContinuationError("continuation cursor is negative")
        connection_context = (
            self._connect_mutable()
            if connection is None
            else contextlib.nullcontext(connection)
        )
        with connection_context as connection:
            status = self._status_connection(connection)
            if token_binding is not None:
                self._validate_token_snapshot_binding(token_binding, status)
            ranked, refinement_required, refinement_hints = self._ranked_candidates_for_status(
                connection,
                query,
                budget["top_k"],
                ranking=ranking,
                status=status,
                database_path=database_path,
            )
            # Replaying this unique event stream recovers BFS visited/emitted state
            # exactly while keeping the signed continuation bounded to one cursor.
            stream = enumerate(self._iter_typed_closure(connection, ranked, depth))
            page_events: list[tuple[int, dict[str, Any]]] = []
            page_seeds: set[int] = set()
            page_edges: set[tuple[int, str, int, int]] = set()
            fanout: dict[tuple[int, str, int], int] = {}
            entity_count = 0
            relation_count = 0
            next_cursor = cursor
            has_more = False
            stream_length = 0

            for event_index, event in stream:
                stream_length = event_index + 1
                if event_index < cursor:
                    continue
                if event_index > cursor and not page_events:
                    raise ContinuationError("continuation cursor exceeds result stream")
                seed_index = event["seed_index"]
                if seed_index not in page_seeds and len(page_seeds) >= budget["top_k"]:
                    has_more = True
                    break
                edge_key = event["edge_key"]
                if edge_key is not None and edge_key not in page_edges:
                    source_key = edge_key[:3]
                    if fanout.get(source_key, 0) >= budget["max_fanout_per_entity"]:
                        has_more = True
                        break
                    page_edges.add(edge_key)
                    fanout[source_key] = fanout.get(source_key, 0) + 1
                if event["kind"] == "entity" and entity_count >= budget["max_entities"]:
                    has_more = True
                    break
                if event["kind"] == "relation" and relation_count >= budget["max_relations"]:
                    has_more = True
                    break
                page_events.append((event_index, event))
                page_seeds.add(seed_index)
                entity_count += event["kind"] == "entity"
                relation_count += event["kind"] == "relation"
                next_cursor = event_index + 1
            else:
                if cursor > stream_length:
                    raise ContinuationError("continuation cursor exceeds result stream")

            if not page_events and has_more:
                raise ProjectionError("search budget cannot advance the continuation")

            while True:
                result = self._build_search_result(
                    connection=connection,
                    query=query,
                    depth=depth,
                    budget=budget,
                    ranking=ranking,
                    status=status,
                    cursor=cursor,
                    next_cursor=next_cursor,
                    issued_at=issued_at,
                    expiry=expiry,
                    ttl_seconds=ttl_seconds,
                    resume_binding=resume_binding,
                    page_events=page_events,
                    truncated=has_more,
                    effective_top_k=len(page_seeds),
                    selected_seed_count=len(ranked),
                    refinement_required=refinement_required,
                    refinement_hints=refinement_hints,
                    persist_continuation=persist_continuation,
                )
                if len(canonical_bytes(result)) <= budget["max_bytes"]:
                    if not page_events and has_more:
                        raise ProjectionError("max_bytes cannot advance the continuation")
                    return result
                if not page_events:
                    raise ProjectionError("max_bytes cannot hold continuation metadata")
                if persist_continuation:
                    self._discard_continuation(connection, result)
                removed_index, _ = page_events.pop()
                next_cursor = removed_index
                has_more = True
                page_seeds = {event["seed_index"] for _, event in page_events}

    def _build_search_result(
        self,
        *,
        connection: sqlite3.Connection,
        query: str,
        depth: int,
        budget: dict[str, int],
        ranking: str,
        status: Mapping[str, Any],
        cursor: int,
        next_cursor: int,
        issued_at: str,
        expiry: str,
        ttl_seconds: int,
        resume_binding: dict[str, str] | None,
        page_events: list[tuple[int, dict[str, Any]]],
        truncated: bool,
        effective_top_k: int,
        selected_seed_count: int,
        refinement_required: bool,
        refinement_hints: list[str],
        persist_continuation: bool = True,
    ) -> dict[str, Any]:
        continuation = None
        if truncated:
            token_payload = {
                "route": _SEARCH_ROUTE,
                "version": self.limits.token_version,
                "traversal": self.limits.traversal_algorithm_id,
                "query": query,
                "activation_digest": status["activation_digest"],
                "head_digest": status["head_digest"],
                "head_sequence": status["head_sequence"],
                "projection_digest": status["semantic_digest"],
                "implementation_closure_digest": status["implementation_closure_digest"],
                "ranking": ranking,
                "budget": budget,
                "resume_binding": resume_binding,
                "depth": depth,
                "cursor": next_cursor,
                "issued_at": issued_at,
                "expiry": expiry,
                "ttl_seconds": ttl_seconds,
            }
            token = self._encode_token(
                connection,
                token_payload,
                persist=persist_continuation,
            )
            continuation = {
                "version": self.limits.token_version,
                "traversal": self.limits.traversal_algorithm_id,
                "token": token,
                "cursor": next_cursor,
                "expiry": expiry,
                "activation_digest": status["activation_digest"],
                "head_digest": status["head_digest"],
                "projection_digest": status["semantic_digest"],
                "implementation_closure_digest": status["implementation_closure_digest"],
                "ranking": ranking,
                "depth": depth,
                "budget_digest": digest_value(budget),
                "resume_binding_digest": digest_value(resume_binding),
            }
        return {
            "record_type": "RetrievalPage",
            "query": query,
            "activation_digest": status["activation_digest"],
            "depth": depth,
            "ranking": ranking,
            "budget": budget,
            "head_digest": status["head_digest"],
            "projection_digest": status["semantic_digest"],
            "entities": [event["row"] for _, event in page_events if event["kind"] == "entity"],
            "relations": [event["row"] for _, event in page_events if event["kind"] == "relation"],
            "evidence": [],
            "truncated": truncated,
            "continuation": continuation,
            "continuation_version": self.limits.token_version,
            "stream_cursor": cursor,
            "next_stream_cursor": next_cursor,
            "effective_top_k": effective_top_k,
            "selected_seed_count": selected_seed_count,
            "refinement_required": refinement_required,
            "refinement_hints": refinement_hints,
            "unselected_matches_traversable": False,
            "selected_closure_complete": not truncated,
            "silent_truncation": False,
            "projection_authoritative": False,
        }

    def _eligible_ready_tasks(
        self,
        connection: sqlite3.Connection,
        status: Mapping[str, Any],
    ) -> tuple[list[dict[str, Any]], int, int, str]:
        """Resolve the exact current ReadyFrontier from the typed DAG."""

        records: dict[str, dict[str, Any]] = {}
        record_digests: dict[str, str] = {}
        records_by_type: dict[str, dict[str, dict[str, Any]]] = {
            "Task": {},
            "Run": {},
            "GateResult": {},
            "Finding": {},
        }
        for entity_id, entity_type, data_class, payload_json in connection.execute(
            """
            SELECT id,entity_type,data_class,payload_json FROM entities
            WHERE entity_type IN ('Task','Run','GateResult','Finding')
            ORDER BY entity_type,id
            """
        ):
            if data_class != "operational-record":
                continue
            try:
                payload = json.loads(payload_json)
            except json.JSONDecodeError as exc:
                raise ProjectionError("operational graph row is not JSON") from exc
            if (
                not isinstance(payload, dict)
                or payload.get("record_type") != entity_type
                or payload.get("activation_digest") != status["activation_digest"]
            ):
                raise ProjectionError("operational graph row binding is invalid")
            records[entity_id] = payload
            record_digests[entity_id] = hashlib.sha256(
                payload_json.encode("utf-8")
            ).hexdigest()
            records_by_type[entity_type][entity_id] = payload

        tasks = records_by_type["Task"]
        dependencies = {task_id: [] for task_id in tasks}
        open_blockers: set[str] = set()
        findings = records_by_type["Finding"]
        for kind, source_type, source_id, target_type, target_id in connection.execute(
            """
            SELECT kind,source_type,source_id,target_type,target_id FROM relations
            WHERE kind IN ('DEPENDS_ON','BLOCKS')
            ORDER BY kind,source_id,target_id,id
            """
        ):
            if kind == "DEPENDS_ON":
                if (
                    source_type != "Task"
                    or target_type != "Task"
                    or source_id not in tasks
                    or target_id not in tasks
                ):
                    raise ProjectionError("DEPENDS_ON references a non-current Task")
                dependencies[source_id].append(target_id)
            elif (
                source_type == "Finding"
                and target_type == "Task"
                and target_id in tasks
            ):
                finding = findings.get(source_id)
                if (
                    finding is None
                    or finding.get("finding_id") != source_id
                ):
                    raise ProjectionError("BLOCKS references a non-current Finding")
                if finding.get("status") == "OPEN" and finding.get("blocking") is True:
                    open_blockers.add(target_id)
        for task_id, values in dependencies.items():
            dependencies[task_id] = sorted(set(values))

        gates: dict[tuple[str, str], dict[str, Any]] = {}
        for gate in records_by_type["GateResult"].values():
            task_id = gate.get("task_id")
            definition_digest = gate.get("definition_digest")
            if (
                not isinstance(task_id, str)
                or task_id not in tasks
                or not isinstance(definition_digest, str)
                or _DIGEST.fullmatch(definition_digest) is None
            ):
                raise ProjectionError("GateResult currentness binding is invalid")
            key = (task_id, definition_digest)
            if key in gates:
                raise ProjectionError("current GateResult identity is duplicated")
            gates[key] = gate

        def accepted(task_id: str) -> tuple[bool, list[str]]:
            task = tasks[task_id]
            if task.get("state") != "COMPLETED":
                return False, []
            bindings = task.get("gate_run_definitions")
            if not isinstance(bindings, list) or not 1 <= len(bindings) <= 64:
                raise ProjectionError("Task gate-run definitions are not exact")
            result_digests: list[str] = []
            seen_definitions: set[str] = set()
            for binding in bindings:
                if not isinstance(binding, dict) or set(binding) != {
                    "definition_digest",
                    "definition",
                }:
                    raise ProjectionError("Task gate-run definition binding is invalid")
                definition_digest = binding["definition_digest"]
                definition = binding["definition"]
                if (
                    not isinstance(definition_digest, str)
                    or _DIGEST.fullmatch(definition_digest) is None
                    or definition_digest in seen_definitions
                    or not isinstance(definition, dict)
                    or digest_value(definition) != definition_digest
                ):
                    raise ProjectionError("Task gate-run definition digest is invalid")
                seen_definitions.add(definition_digest)
                gate = gates.get((task_id, definition_digest))
                if gate is None:
                    return False, []
                run_id = gate.get("run_id")
                run = (
                    records_by_type["Run"].get(run_id)
                    if isinstance(run_id, str)
                    else None
                )
                if (
                    run is None
                    or gate.get("run_digest") != digest_value(run)
                    or run.get("task_id") != task_id
                    or run.get("definition_digest") != definition_digest
                    or run.get("activation_digest") != task.get("activation_digest")
                    or run.get("candidate_digest") != task.get("candidate_digest")
                    or gate.get("status") != "pass"
                    or gate.get("outcome") != "pass"
                    or gate.get("pass_credit") is not True
                    or gate.get("activation_digest") != task.get("activation_digest")
                    or gate.get("candidate_digest") != task.get("candidate_digest")
                ):
                    return False, []
                result_digests.append(digest_value(gate))
            return True, sorted(result_digests)

        ready_state_tasks = [
            (task_id, task)
            for task_id, task in tasks.items()
            if task.get("state") == "READY"
        ]
        eligible: list[dict[str, Any]] = []
        blocked_count = 0
        for task_id, task in ready_state_tasks:
            dependency_results = [accepted(item) for item in dependencies[task_id]]
            if task_id in open_blockers or not all(
                result[0] for result in dependency_results
            ):
                blocked_count += 1
                continue
            created_at = task.get("created_at")
            candidate_digest = task.get("candidate_digest")
            acceptance_predicate = task.get("acceptance_predicate")
            try:
                parse_timestamp(created_at)
            except (EventStoreError, TypeError) as exc:
                raise ProjectionError("Ready Task created_at is invalid") from exc
            if (
                not isinstance(candidate_digest, str)
                or _DIGEST.fullmatch(candidate_digest) is None
                or not isinstance(acceptance_predicate, str)
                or not acceptance_predicate
            ):
                raise ProjectionError("Ready Task semantic binding is invalid")
            eligible.append(
                {
                    "task_id": task_id,
                    "task_digest": record_digests[task_id],
                    "created_at": created_at,
                    "candidate_digest": candidate_digest,
                    "acceptance_predicate": acceptance_predicate,
                    "dependency_task_ids": dependencies[task_id],
                    "gate_result_digests": sorted(
                        digest
                        for _accepted, digests in dependency_results
                        for digest in digests
                    ),
                }
            )
        eligible.sort(key=lambda item: (item["created_at"], item["task_id"]))
        frontier_digest = digest_value(
            {
                "record_type": "ReadyFrontierSelection",
                "activation_digest": status["activation_digest"],
                "head_digest": status["head_digest"],
                "projection_digest": status["semantic_digest"],
                "ordering": list(_READY_FRONTIER_ORDERING),
                "ready_tasks": eligible,
                "evaluated_task_count": len(ready_state_tasks),
                "blocked_task_count": blocked_count,
                "cycle_count": 0,
            }
        )
        return eligible, len(ready_state_tasks), blocked_count, frontier_digest

    def _validate_ready_frontier(
        self,
        frontier: Mapping[str, Any],
        task_records: tuple[dict[str, Any], ...],
        status: Mapping[str, Any],
        connection: sqlite3.Connection,
    ) -> dict[str, Any]:
        required = {
            "record_type",
            "activation_digest",
            "head_digest",
            "projection_digest",
            "ordering",
            "ready_tasks",
            "evaluated_task_count",
            "blocked_task_count",
            "cycle_count",
            "truncated",
            "continuation",
            "silent_truncation",
            "projection_authoritative",
        }
        if not isinstance(frontier, Mapping) or set(frontier) != required:
            raise ProjectionError("ReadyFrontier fields mismatch")
        checked = copy.deepcopy(dict(frontier))
        if (
            checked["record_type"] != "ReadyFrontier"
            or checked["activation_digest"] != status["activation_digest"]
            or checked["head_digest"] != status["head_digest"]
            or checked["projection_digest"] != status["semantic_digest"]
            or checked["ordering"] != list(_READY_FRONTIER_ORDERING)
            or checked["truncated"] is not False
            or checked["continuation"] is not None
            or checked["silent_truncation"] is not False
            or checked["projection_authoritative"] is not False
            or checked["cycle_count"] != 0
        ):
            raise ProjectionError("ReadyFrontier owner or snapshot binding mismatch")
        for field in (
            "evaluated_task_count",
            "blocked_task_count",
            "cycle_count",
        ):
            value = checked[field]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ProjectionError("ReadyFrontier count is invalid")
        ready_tasks = checked["ready_tasks"]
        if (
            not isinstance(ready_tasks, list)
            or len(ready_tasks) != len(task_records)
            or len(ready_tasks) + checked["blocked_task_count"]
            > checked["evaluated_task_count"]
        ):
            raise ProjectionError("ReadyFrontier task accounting mismatch")
        task_fields = {
            "task_id",
            "task_digest",
            "created_at",
            "candidate_digest",
            "acceptance_predicate",
            "dependency_task_ids",
            "gate_result_digests",
        }
        order: list[tuple[str, str]] = []
        seen: set[str] = set()
        for frontier_task, record in zip(ready_tasks, task_records):
            if not isinstance(frontier_task, Mapping) or set(frontier_task) != task_fields:
                raise ProjectionError("ReadyFrontier task fields mismatch")
            task = dict(frontier_task)
            task_id = task["task_id"]
            if (
                not isinstance(task_id, str)
                or not task_id
                or task_id in seen
                or not isinstance(task["acceptance_predicate"], str)
                or not task["acceptance_predicate"]
                or _DIGEST.fullmatch(str(task["task_digest"])) is None
                or _DIGEST.fullmatch(str(task["candidate_digest"])) is None
            ):
                raise ProjectionError("ReadyFrontier task identity is invalid")
            try:
                parse_timestamp(task["created_at"])
            except EventStoreError as exc:
                raise ProjectionError("ReadyFrontier task time is invalid") from exc
            for field, digest_items in (
                ("dependency_task_ids", False),
                ("gate_result_digests", True),
            ):
                values = task[field]
                if (
                    not isinstance(values, list)
                    or values != sorted(values)
                    or len(values) != len(set(values))
                    or any(
                        not isinstance(value, str)
                        or not value
                        or (digest_items and _DIGEST.fullmatch(value) is None)
                        for value in values
                    )
                ):
                    raise ProjectionError(f"ReadyFrontier {field} is invalid")
            if (
                not isinstance(record, dict)
                or record.get("record_type") != "Task"
                or record.get("task_id") != task_id
                or digest_value(record) != task["task_digest"]
            ):
                raise ProjectionError("ReadyFrontier Task record digest mismatch")
            stored = connection.execute(
                "SELECT entity_type,data_class,payload_json FROM entities WHERE id=?",
                (task_id,),
            ).fetchone()
            encoded = canonical_bytes(record).decode("utf-8")
            if stored != ("Task", "operational-record", encoded):
                raise ProjectionError("ReadyFrontier Task differs from current projection")
            seen.add(task_id)
            order.append((task["created_at"], task_id))
        if order != sorted(order):
            raise ProjectionError("ReadyFrontier tasks are not in owner order")
        return checked

    def _validate_ready_frontier_state(
        self,
        connection: sqlite3.Connection,
        *,
        state_id: str,
        frontier_digest: str,
        status: Mapping[str, Any],
        task_records: tuple[dict[str, Any], ...] | None,
        expiry: str,
    ) -> dict[str, int]:
        header = connection.execute(
            """
            SELECT frontier_digest,activation_digest,head_digest,
                   projection_digest,task_count,evaluated_task_count,
                   blocked_task_count,expires_at
            FROM ready_frontiers WHERE state_id=?
            """,
            (state_id,),
        ).fetchone()
        if (
            header is None
            or header[0] != frontier_digest
            or header[1] != status["activation_digest"]
            or header[2] != status["head_digest"]
            or header[3] != status["semantic_digest"]
            or not isinstance(header[4], int)
            or header[4] < 0
            or not isinstance(header[5], int)
            or header[5] < header[4]
            or not isinstance(header[6], int)
            or not 0 <= header[6] <= header[5]
            or header[7] != expiry
        ):
            raise ContinuationError("ReadyFrontier continuation state is stale")
        rows = list(
            connection.execute(
                """
                SELECT ordinal,task_id,task_digest,selection_json
                FROM ready_frontier_tasks WHERE state_id=? ORDER BY ordinal
                """,
                (state_id,),
            )
        )
        if len(rows) != header[4] or any(
            ordinal != expected
            or not isinstance(task_id, str)
            or not task_id
            or _DIGEST.fullmatch(task_digest) is None
            or not isinstance(selection_json, str)
            for expected, (ordinal, task_id, task_digest, selection_json) in enumerate(rows)
        ):
            raise ContinuationError("ReadyFrontier continuation rows are incomplete")
        for _ordinal, task_id, task_digest, selection_json in rows:
            try:
                selection = parse_json_strict(selection_json.encode("utf-8"))
            except CanonicalError as exc:
                raise ContinuationError(
                    "ReadyFrontier selection row is noncanonical"
                ) from exc
            if (
                not isinstance(selection, dict)
                or selection.get("task_id") != task_id
                or selection.get("task_digest") != task_digest
            ):
                raise ContinuationError("ReadyFrontier selection row is substituted")
        if task_records is not None and (
            len(task_records) != len(rows)
            or any(
                record.get("task_id") != task_id
                or digest_value(record) != task_digest
                for record, (_ordinal, task_id, task_digest, _selection) in zip(task_records, rows)
            )
        ):
            raise ProjectionError("ReadyFrontier stored task binding mismatch")
        for _ordinal, task_id, task_digest, _selection in rows:
            stored = connection.execute(
                "SELECT entity_type,data_class,payload_json FROM entities WHERE id=?",
                (task_id,),
            ).fetchone()
            if (
                stored is None
                or stored[0] != "Task"
                or stored[1] != "operational-record"
                or hashlib.sha256(stored[2].encode("utf-8")).hexdigest()
                != task_digest
            ):
                raise ContinuationError(
                    "ReadyFrontier Task is missing or substituted in projection"
                )
        return {
            "task_count": header[4],
            "evaluated_task_count": header[5],
            "blocked_task_count": header[6],
        }

    def _iter_ready_frontier(
        self, connection: sqlite3.Connection, state_id: str
    ) -> Iterator[dict[str, Any]]:
        for ordinal, selection_json in connection.execute(
            """
            SELECT ordinal,selection_json FROM ready_frontier_tasks
            WHERE state_id=? ORDER BY ordinal
            """,
            (state_id,),
        ):
            selection = parse_json_strict(selection_json.encode("utf-8"))
            if not isinstance(selection, dict):
                raise ContinuationError("ReadyFrontier selection row is invalid")
            yield {"ordinal": ordinal, "selection": selection}

    def _ready_frontier_page(
        self,
        state_id: str,
        frontier_digest: str,
        budget: dict[str, int],
        cursor: int,
        issued_at: str,
        expiry: str,
        ttl_seconds: int,
        resume_binding: dict[str, str],
        *,
        token_binding: Mapping[str, Any] | None = None,
        connection: sqlite3.Connection,
    ) -> dict[str, Any]:
        if cursor < 0:
            raise ContinuationError("ReadyFrontier continuation cursor is negative")
        status = self._status_connection(connection)
        if token_binding is not None:
            self._validate_token_snapshot_binding(token_binding, status)
        state = self._validate_ready_frontier_state(
            connection,
            state_id=state_id,
            frontier_digest=frontier_digest,
            status=status,
            task_records=None,
            expiry=expiry,
        )
        task_count = state["task_count"]
        if cursor > task_count:
            raise ContinuationError("ReadyFrontier continuation cursor exceeds stream")
        page_limit = min(budget["top_k"], budget["max_entities"])
        page_tasks = [
            item["selection"]
            for item in itertools.islice(
                self._iter_ready_frontier(connection, state_id),
                cursor,
                cursor + page_limit,
            )
        ]
        next_cursor = cursor + len(page_tasks)
        has_more = next_cursor < task_count
        if not page_tasks and has_more:
            raise ProjectionError("ReadyFrontier budget cannot advance continuation")
        while True:
            result = self._build_ready_frontier_result(
                connection=connection,
                state_id=state_id,
                frontier_digest=frontier_digest,
                budget=budget,
                status=status,
                cursor=cursor,
                next_cursor=next_cursor,
                issued_at=issued_at,
                expiry=expiry,
                ttl_seconds=ttl_seconds,
                resume_binding=resume_binding,
                ready_tasks=page_tasks,
                truncated=has_more,
                evaluated_task_count=state["evaluated_task_count"],
                blocked_task_count=state["blocked_task_count"],
            )
            if len(canonical_bytes(result)) <= budget["max_bytes"]:
                if not page_tasks and has_more:
                    raise ProjectionError("max_bytes cannot advance ReadyFrontier")
                if not has_more:
                    connection.execute(
                        "DELETE FROM ready_frontiers WHERE state_id=?",
                        (state_id,),
                    )
                return result
            if not page_tasks:
                raise ProjectionError("max_bytes cannot hold continuation metadata")
            self._discard_continuation(connection, result)
            page_tasks.pop()
            next_cursor -= 1
            has_more = True

    def _build_ready_frontier_result(
        self,
        *,
        connection: sqlite3.Connection,
        state_id: str,
        frontier_digest: str,
        budget: dict[str, int],
        status: Mapping[str, Any],
        cursor: int,
        next_cursor: int,
        issued_at: str,
        expiry: str,
        ttl_seconds: int,
        resume_binding: dict[str, str],
        ready_tasks: list[dict[str, Any]],
        truncated: bool,
        evaluated_task_count: int,
        blocked_task_count: int,
    ) -> dict[str, Any]:
        continuation = None
        if truncated:
            token_payload = {
                "route": _READY_FRONTIER_ROUTE,
                "version": self.limits.token_version,
                "traversal": self.limits.traversal_algorithm_id,
                "query": _READY_FRONTIER_ROUTE,
                "activation_digest": status["activation_digest"],
                "head_digest": status["head_digest"],
                "head_sequence": status["head_sequence"],
                "projection_digest": status["semantic_digest"],
                "implementation_closure_digest": status[
                    "implementation_closure_digest"
                ],
                "ranking": self.limits.ranking_algorithm_id,
                "budget": budget,
                "resume_binding": resume_binding,
                "depth": self.limits.depth_min,
                "cursor": next_cursor,
                "issued_at": issued_at,
                "expiry": expiry,
                "ttl_seconds": ttl_seconds,
                "frontier_state_id": state_id,
                "frontier_digest": frontier_digest,
            }
            token = self._encode_token(connection, token_payload)
            continuation = {
                "version": self.limits.token_version,
                "traversal": self.limits.traversal_algorithm_id,
                "token": token,
                "cursor": next_cursor,
                "expiry": expiry,
                "activation_digest": status["activation_digest"],
                "head_digest": status["head_digest"],
                "projection_digest": status["semantic_digest"],
                "implementation_closure_digest": status[
                    "implementation_closure_digest"
                ],
                "ranking": self.limits.ranking_algorithm_id,
                "depth": self.limits.depth_min,
                "budget_digest": digest_value(budget),
                "resume_binding_digest": digest_value(resume_binding),
            }
        return {
            "record_type": "ReadyFrontier",
            "activation_digest": status["activation_digest"],
            "head_digest": status["head_digest"],
            "projection_digest": status["semantic_digest"],
            "ordering": list(_READY_FRONTIER_ORDERING),
            "ready_tasks": copy.deepcopy(ready_tasks),
            "evaluated_task_count": evaluated_task_count,
            "blocked_task_count": blocked_task_count,
            "cycle_count": 0,
            "truncated": truncated,
            "continuation": continuation,
            "silent_truncation": False,
            "projection_authoritative": False,
        }

    @staticmethod
    def _ranked_candidates(
        connection: sqlite3.Connection,
        query: str,
        top_k: int,
    ) -> tuple[list[dict[str, Any]], bool, list[str]]:
        exact = connection.execute("SELECT id FROM entities WHERE id=?", (query,)).fetchone()
        if exact is not None:
            return ([{"id": exact[0], "tier": 0, "score": 0.0}], False, [])
        ranked: list[dict[str, Any]] = []
        tokens = _QUERY_TOKEN.findall(query)
        expression = " AND ".join(f'"{token.replace(chr(34), chr(34) * 2)}"' for token in tokens)
        rows = connection.execute(
            "SELECT id,bm25(entity_fts) AS score FROM entity_fts "
            "WHERE entity_fts MATCH ? ORDER BY score ASC,id ASC LIMIT ?",
            (expression, top_k + 1),
        )
        seen = {row["id"] for row in ranked}
        for entity_id, score in rows:
            if entity_id not in seen:
                ranked.append({"id": entity_id, "tier": 1, "score": float(score)})
                seen.add(entity_id)
        refinement_required = len(ranked) > top_k
        selected = ranked[:top_k]
        hints = (
            ["add an exact ID or path term", "add a distinguishing content term"]
            if refinement_required
            else []
        )
        return selected, refinement_required, hints

    def _ranked_candidates_for_status(
        self,
        connection: sqlite3.Connection,
        query: str,
        top_k: int,
        *,
        ranking: str,
        status: Mapping[str, Any],
        database_path: Path | None = None,
    ) -> tuple[list[dict[str, Any]], bool, list[str]]:
        cache = self.ranked_candidate_cache
        if cache is None:
            return self._ranked_candidates(connection, query, top_k)
        key = (
            str((self.db_path if database_path is None else database_path).resolve()),
            self.implementation_closure_digest,
            status["activation_digest"],
            status["head_sequence"],
            status["head_digest"],
            status["semantic_digest"],
            ranking,
            query,
            top_k,
        )
        return cache.resolve(
            key,
            lambda: self._ranked_candidates(connection, query, top_k),
        )

    @staticmethod
    def _add_entity(connection: sqlite3.Connection, entity_id: str, entities: dict[str, dict[str, Any]]) -> bool:
        if entity_id in entities:
            return True
        row = connection.execute(
            "SELECT id,entity_type,data_class,payload_json FROM entities WHERE id=?",
            (entity_id,),
        ).fetchone()
        if row is None:
            return False
        entities[row[0]] = {
            "id": row[0],
            "entity_type": row[1],
            "data_class": row[2],
            "payload": json.loads(row[3]),
            "source_digest": hashlib.sha256(row[3].encode("utf-8")).hexdigest(),
        }
        return True

    @staticmethod
    def _entity_row(connection: sqlite3.Connection, entity_id: str) -> dict[str, Any]:
        entities: dict[str, dict[str, Any]] = {}
        if not Projection._add_entity(connection, entity_id, entities):
            raise ProjectionError(f"typed closure entity is missing: {entity_id}")
        return entities[entity_id]

    def _iter_typed_closure(
        self,
        connection: sqlite3.Connection,
        ranked: Iterable[Mapping[str, Any]],
        depth: int,
    ) -> Iterator[dict[str, Any]]:
        """Yield each reachable entity/relation once in deterministic BFS order."""

        emitted_entities: set[str] = set()
        emitted_relations: set[str] = set()
        for seed_index, candidate in enumerate(ranked):
            seed_id = candidate["id"]
            if seed_id not in emitted_entities:
                emitted_entities.add(seed_id)
                yield {
                    "kind": "entity",
                    "row": self._entity_row(connection, seed_id),
                    "seed_index": seed_index,
                    "edge_key": None,
                }
            frontier = [seed_id]
            visited = {seed_id}
            for layer in range(depth):
                next_frontier: list[str] = []
                for entity_id in sorted(frontier):
                    rows = connection.execute(
                        """
                        SELECT id,kind,source_type,source_id,target_type,target_id,created_at,payload_json
                        FROM relations WHERE source_id=? OR target_id=?
                        ORDER BY kind,source_id,target_id,id
                        """,
                        (entity_id, entity_id),
                    )
                    for edge_index, row in enumerate(rows):
                        other = row[5] if row[3] == entity_id else row[3]
                        if other not in visited:
                            visited.add(other)
                            next_frontier.append(other)
                        edge_key = (seed_index, entity_id, layer, edge_index)
                        if other not in emitted_entities:
                            emitted_entities.add(other)
                            yield {
                                "kind": "entity",
                                "row": self._entity_row(connection, other),
                                "seed_index": seed_index,
                                "edge_key": edge_key,
                            }
                        if row[0] not in emitted_relations:
                            emitted_relations.add(row[0])
                            yield {
                                "kind": "relation",
                                "row": json.loads(row[7]),
                                "seed_index": seed_index,
                                "edge_key": edge_key,
                            }
                frontier = sorted(set(next_frontier))
                if not frontier:
                    break

    def _normalize_query(self, query: str) -> str:
        if not isinstance(query, str):
            raise ProjectionError("query must be text")
        normalized = " ".join(query.strip().split())
        if not normalized or len(normalized.encode("utf-8")) > self.limits.max_query_bytes:
            raise ProjectionError("query is empty or exceeds the verified byte ceiling")
        if not _QUERY_TOKEN.search(normalized):
            raise ProjectionError("query lacks searchable tokens")
        return normalized

    def _validate_budget(self, budget: Mapping[str, int]) -> dict[str, int]:
        if not isinstance(budget, Mapping) or set(budget) != _BUDGET_FIELDS:
            raise ProjectionError("search budget fields mismatch")
        checked = dict(budget)
        if any(not isinstance(value, int) or isinstance(value, bool) for value in checked.values()):
            raise ProjectionError("search budgets must be integers")
        if (
            checked["max_bytes"] < self.limits.min_result_bytes
            or checked["max_entities"] < 1
            or checked["max_relations"] < 0
        ):
            raise ProjectionError("search budget minimum violated")
        if checked["max_fanout_per_entity"] < 1 or checked["top_k"] < 1:
            raise ProjectionError("search budget minimum violated")
        hard = self.limits.hard_budget
        if any(checked[key] > hard[key] for key in checked):
            raise ProjectionError("search budget exceeds the Core hard ceiling")
        return checked

    def _validate_resume_binding(self, binding: Mapping[str, str] | None) -> dict[str, str]:
        if (
            not isinstance(binding, Mapping)
            or set(binding) != set(self.limits.required_resume_binding_fields)
        ):
            raise ProjectionError("continuation authorization binding fields mismatch")
        checked: dict[str, str] = {}
        for key, value in binding.items():
            if (
                not isinstance(key, str)
                or not re.fullmatch(
                    rf"[a-z][a-z0-9_]{{0,{self.limits.max_resume_binding_key_chars - 1}}}",
                    key,
                )
                or not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > self.limits.max_resume_binding_value_bytes
            ):
                raise ProjectionError("continuation resume binding field is invalid")
            checked[key] = value
        if len(canonical_bytes(checked)) > self.limits.max_resume_binding_bytes:
            raise ProjectionError("continuation resume binding exceeds its verified byte ceiling")
        return dict(sorted(checked.items()))

    def _encode_token(
        self,
        connection: sqlite3.Connection,
        payload: Mapping[str, Any],
        *,
        persist: bool = True,
    ) -> str:
        payload_bytes = canonical_bytes(
            dict(payload),
            limits=ParseLimits(max_bytes=self.limits.max_continuation_state_bytes),
        )
        row_digest = hashlib.sha256(payload_bytes).hexdigest()
        handle_bytes = hmac.new(
            self.token_key,
            (
                f"promin:continuation-handle:{self.limits.token_version}:"
                f"{row_digest}"
            ).encode("ascii"),
            hashlib.sha256,
        ).digest()[:16]
        handle = base64.urlsafe_b64encode(handle_bytes).rstrip(b"=").decode("ascii")
        body = (
            f"promin-v{self.limits.token_version}.{handle}.{row_digest}"
        ).encode("ascii")
        signature = hmac.new(self.token_key, body, hashlib.sha256).digest()
        signature_text = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
        token = body.decode("ascii") + "." + signature_text
        if len(token.encode("ascii")) > self.limits.max_token_bytes:
            raise ProjectionError("continuation token exceeds its verified byte ceiling")
        if not persist:
            return token
        connection.execute(
            "DELETE FROM continuations WHERE expires_at<=?",
            (payload["issued_at"],),
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO continuations(handle,row_digest,payload_json,expires_at)
            VALUES (?,?,?,?)
            """,
            (handle, row_digest, payload_bytes.decode("utf-8"), payload["expiry"]),
        )
        stored = connection.execute(
            "SELECT row_digest,payload_json,expires_at FROM continuations WHERE handle=?",
            (handle,),
        ).fetchone()
        if stored != (
            row_digest,
            payload_bytes.decode("utf-8"),
            payload["expiry"],
        ):
            raise ProjectionError("continuation handle collision or row substitution")
        return token

    def _decode_token(
        self,
        connection: sqlite3.Connection,
        token: str,
        now: str,
    ) -> dict[str, Any]:
        if (
            not isinstance(token, str)
            or len(token.encode("utf-8")) > self.limits.max_token_bytes
            or token.count(".") != 3
        ):
            raise ContinuationError("continuation token format is invalid")
        version_text, handle, row_digest, signature_text = token.split(".")
        if (
            version_text != f"promin-v{self.limits.token_version}"
            or re.fullmatch(r"[A-Za-z0-9_-]{22}", handle) is None
            or _DIGEST.fullmatch(row_digest) is None
        ):
            raise ContinuationError("continuation handle binding is invalid")
        try:
            decoded_handle = base64.urlsafe_b64decode(
                handle + "=" * (-len(handle) % 4)
            )
        except (ValueError, UnicodeError) as exc:
            raise ContinuationError("continuation handle encoding is invalid") from exc
        if (
            len(decoded_handle) != 16
            or base64.urlsafe_b64encode(decoded_handle).rstrip(b"=").decode("ascii")
            != handle
        ):
            raise ContinuationError("continuation handle encoding is noncanonical")
        body = f"{version_text}.{handle}.{row_digest}".encode("ascii")
        try:
            signature = base64.urlsafe_b64decode(signature_text + "=" * (-len(signature_text) % 4))
            canonical_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
            if signature_text != canonical_signature:
                raise ContinuationError("continuation signature encoding is noncanonical")
            expected = hmac.new(self.token_key, body, hashlib.sha256).digest()
            if not hmac.compare_digest(signature, expected):
                raise ContinuationError("continuation signature mismatch")
            row = connection.execute(
                """
                SELECT row_digest,payload_json,expires_at
                FROM continuations WHERE handle=?
                """,
                (handle,),
            ).fetchone()
            if row is None or row[0] != row_digest:
                raise ContinuationError("continuation state is missing or substituted")
            decoded = row[1].encode("utf-8")
            payload = parse_json_strict(
                decoded,
                limits=ParseLimits(
                    max_bytes=self.limits.max_continuation_state_bytes
                ),
            )
        except (ValueError, UnicodeError, CanonicalError) as exc:
            raise ContinuationError("continuation token is invalid") from exc
        if (
            canonical_bytes(
                payload,
                limits=ParseLimits(
                    max_bytes=self.limits.max_continuation_state_bytes
                ),
            )
            != decoded
            or hashlib.sha256(decoded).hexdigest() != row_digest
            or row[2] != payload.get("expiry")
        ):
            raise ContinuationError("continuation state row is noncanonical or tampered")
        common_required = {
            "route", "version", "traversal", "query", "activation_digest", "head_digest", "head_sequence",
            "projection_digest", "ranking", "budget", "depth", "cursor", "issued_at", "expiry",
            "ttl_seconds", "implementation_closure_digest", "resume_binding",
        }
        if not isinstance(payload, dict) or payload.get("route") not in {
            _SEARCH_ROUTE,
            _READY_FRONTIER_ROUTE,
        }:
            raise ContinuationError("continuation route is invalid")
        required = (
            common_required
            if payload["route"] == _SEARCH_ROUTE
            else common_required | {"frontier_state_id", "frontier_digest"}
        )
        if set(payload) != required:
            raise ContinuationError("continuation payload is noncanonical or incomplete")
        if payload["route"] == _READY_FRONTIER_ROUTE and (
            _DIGEST.fullmatch(payload["frontier_state_id"])
            if isinstance(payload["frontier_state_id"], str)
            else None
        ) is None:
            raise ContinuationError("ReadyFrontier continuation state ID is invalid")
        if payload["route"] == _READY_FRONTIER_ROUTE and (
            not isinstance(payload["frontier_digest"], str)
            or _DIGEST.fullmatch(payload["frontier_digest"]) is None
        ):
            raise ContinuationError("ReadyFrontier continuation digest is invalid")
        if payload["version"] != self.limits.token_version:
            raise ContinuationError("continuation version is unsupported")
        if payload["traversal"] != self.limits.traversal_algorithm_id:
            raise ContinuationError("continuation traversal is unsupported")
        if (
            not isinstance(payload["ttl_seconds"], int)
            or isinstance(payload["ttl_seconds"], bool)
            or not self.limits.ttl_min_seconds
            <= payload["ttl_seconds"]
            <= self.limits.ttl_max_seconds
        ):
            raise ContinuationError("continuation TTL is invalid")
        try:
            current_time = parse_timestamp(now)
            issued_at = parse_timestamp(payload["issued_at"])
            expiry = parse_timestamp(payload["expiry"])
        except EventStoreError as exc:
            raise ContinuationError("continuation time binding is invalid") from exc
        expected_expiry = issued_at + _datetime.timedelta(seconds=payload["ttl_seconds"])
        if expiry != expected_expiry:
            raise ContinuationError("continuation expiry does not match its TTL")
        if current_time < issued_at:
            raise ContinuationError("continuation is not yet valid")
        if current_time >= expiry:
            raise ContinuationError("continuation expired")
        try:
            normalized_query = self._normalize_query(payload["query"])
            payload["budget"] = self._validate_budget(payload["budget"])
            payload["resume_binding"] = self._validate_resume_binding(payload["resume_binding"])
        except ProjectionError as exc:
            raise ContinuationError("continuation query or budget binding is invalid") from exc
        if normalized_query != payload["query"]:
            raise ContinuationError("continuation query is not normalized")
        if payload["ranking"] != self.limits.ranking_algorithm_id:
            raise ContinuationError("continuation ranking is unsupported")
        if (
            not isinstance(payload["depth"], int)
            or isinstance(payload["depth"], bool)
            or not self.limits.depth_min <= payload["depth"] <= self.limits.depth_max
        ):
            raise ContinuationError("continuation depth is invalid")
        if (
            payload["route"] == _SEARCH_ROUTE
            and payload["depth"] > 0
            and payload["budget"]["max_relations"] < 1
        ):
            raise ContinuationError("positive-depth continuation requires a positive relation budget")
        if not isinstance(payload["cursor"], int) or isinstance(payload["cursor"], bool) or payload["cursor"] < 0:
            raise ContinuationError("continuation cursor is invalid")
        return payload

    @staticmethod
    def _discard_continuation(
        connection: sqlite3.Connection,
        result: Mapping[str, Any],
    ) -> None:
        continuation = result.get("continuation")
        if not isinstance(continuation, Mapping):
            return
        token = continuation.get("token")
        if not isinstance(token, str) or token.count(".") != 3:
            return
        _version, handle, row_digest, _signature = token.split(".")
        connection.execute(
            "DELETE FROM continuations WHERE handle=? AND row_digest=?",
            (handle, row_digest),
        )

    @staticmethod
    def _validate_resume_snapshot_binding(
        binding: Mapping[str, str], status: Mapping[str, Any]
    ) -> None:
        if (
            binding.get("activation_digest") != status["activation_digest"]
            or binding.get("implementation_closure_digest")
            != status["implementation_closure_digest"]
        ):
            raise ProjectionError(
                "continuation authorization differs from the projection snapshot"
            )

    @staticmethod
    def _validate_token_snapshot_binding(
        payload: Mapping[str, Any], status: Mapping[str, Any]
    ) -> None:
        bindings = {
            "activation_digest": status["activation_digest"],
            "head_digest": status["head_digest"],
            "head_sequence": status["head_sequence"],
            "projection_digest": status["semantic_digest"],
            "implementation_closure_digest": status["implementation_closure_digest"],
        }
        for key, value in bindings.items():
            if payload.get(key) != value:
                raise ContinuationError(f"continuation {key} is stale")

    @contextlib.contextmanager
    def _connect_readonly(
        self,
        *,
        db_path: Path | None = None,
    ) -> Iterator[sqlite3.Connection]:
        selected_path = self.db_path if db_path is None else db_path
        if not os.path.isfile(filesystem_path(selected_path)):
            raise ProjectionError("projection database does not exist")
        database_path = sqlite_path(selected_path)
        connection: sqlite3.Connection | None = None
        try:
            if database_path.startswith("\\\\?\\"):
                # SQLite accepts an extended Windows filename for a direct
                # connection, but its URI parser treats the transport prefix
                # as an invalid authority.  The existing-file check above
                # prevents creation; query_only keeps this connection read-only.
                connection = sqlite3.connect(database_path, isolation_level=None)
            else:
                uri = Path(database_path).absolute().as_uri() + "?mode=ro"
                connection = sqlite3.connect(uri, uri=True, isolation_level=None)
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise ProjectionError(f"projection database cannot be opened: {exc}") from exc
        assert connection is not None
        try:
            yield connection
        finally:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            connection.close()

    @contextlib.contextmanager
    def _connect_mutable(
        self,
        *,
        db_path: Path | None = None,
    ) -> Iterator[sqlite3.Connection]:
        selected_path = self.db_path if db_path is None else db_path
        if not os.path.isfile(filesystem_path(selected_path)):
            raise ProjectionError("projection database does not exist")
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(sqlite_path(selected_path), isolation_level=None)
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise ProjectionError(f"projection database cannot be opened: {exc}") from exc
        assert connection is not None
        try:
            yield connection
            connection.execute("COMMIT")
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()
