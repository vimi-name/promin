"""Authoritative, append-only Promin event batches.

The journal stores the validated command beside its Core ``EventBatch``.  The
command is required for event-time authorization during replay; the projection
is deliberately not used as authority.
"""

from __future__ import annotations

import base64
import copy
import contextlib
import datetime as _datetime
import errno
import fnmatch
import hashlib
import inspect
import itertools
import math
import os
import re
import shutil
import sqlite3
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Iterable, Iterator, Mapping, MutableMapping, TypeVar

from .canonical import (
    CanonicalError,
    ParseLimits,
    canonical_bytes,
    digest_value,
    format_utc_second,
    parse_json_strict,
    parse_utc_second,
)
_DERIVED_STATE_LIMITS = ParseLimits(max_bytes=16 * 1024 * 1024)
_DERIVED_ROWS_MANIFEST_LIMITS = ParseLimits(max_bytes=16 * 1024)
_DERIVED_ROWS_INDEX_VERSION = 1
_RUNTIME_ROWS_V2_INDEX_VERSION = 2
_RUNTIME_ROWS_V2_NAME = "runtime"
_RUNTIME_ROWS_V2_BUCKET_BYTES = 2
_DERIVED_ROWS_INSERT_BATCH = 512
_DERIVED_ROWS_TRANSCRIPT_GENESIS = hashlib.sha256(
    b"promin:derived-rows-v1:genesis"
).hexdigest()
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DERIVED_ROW_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_INDEX_GENERATION = re.compile(r"^[0-9a-f]{32}$")
_EVENT_IDENTITY_INDEX_NAME = "event-identities.sqlite3"
_EVENT_IDENTITY_INDEX_VERSION = 1
_STATE_BINDING_INDEX_NAME = "state-binding.sqlite3"
_STATE_BINDING_INDEX_VERSION = 3
_STATE_BINDING_ALGORITHM = "typed-sparse-merkle-v1"
_STATE_TREE_DEPTH = 256
_STATE_BINDING_STORAGE_STRIDE = 8
# ``node`` preserves the two byte-boundary levels needed to update the
# canonical root plus individual leaf witnesses for touched-path recovery.
# The 29 lower intermediate byte levels are represented as bounded leaf
# buckets.  This is derived storage only; the public algorithm remains the
# exact 256-level Core sparse-Merkle tree.
_STATE_BINDING_COMPACT_PARTITION_BYTES = 2
_STATE_BINDING_COMPACT_PARTITION_DEPTH = (
    _STATE_BINDING_COMPACT_PARTITION_BYTES * 8
)
_STATE_BINDING_COMMITMENT_LIMITS = ParseLimits(max_bytes=4 * 1024)

_RESERVED_SECRET_FIELDS = {
    "continuation_secret",
    "continuation_secret_bytes",
    "continuation_secret_material",
    "continuation_secret_path",
    "hmac_key",
    "hmac_key_bytes",
    "hmac_key_material",
    "hmac_key_path",
    "key_material",
    "key_material_path",
    "mac_key",
    "mac_key_bytes",
    "mac_key_material",
    "mac_key_path",
    "private_key",
    "private_key_bytes",
    "private_key_material",
    "private_key_path",
    "secret",
    "secret_bytes",
    "secret_material",
    "secret_path",
    "secrets",
    "signing_key",
    "signing_key_bytes",
    "signing_key_material",
    "signing_key_path",
    "token_key",
    "token_key_bytes",
    "token_key_material",
    "token_key_path",
}
_RESERVED_SECRET_PATH_MARKER = ".promin/state/secrets"

_local_writer_locks: MutableMapping[str, threading.Lock] = {}
_local_writer_guard = threading.Lock()
T = TypeVar("T")


class EventStoreError(RuntimeError):
    """Base failure for journal validation, recovery, or mutation."""


class CommandConflict(EventStoreError):
    """A unique identity or expected HEAD conflicts with committed history."""


class JournalCorruption(EventStoreError):
    """The authoritative journal cannot be validated as one linear history."""


class DerivedCheckpointError(EventStoreError):
    """A disposable checkpoint cannot be proven to match authoritative events."""


class ImplementationClosureMismatch(EventStoreError):
    """Existing event state is bound to another implementation closure."""


class SimulatedCrash(EventStoreError):
    """Raised by a test crash hook after a named durable write point."""


@dataclass(frozen=True)
class ReplayResult:
    state: Any
    head: dict[str, Any]
    batch_count: int
    event_count: int
    semantic_digest: str


@dataclass(frozen=True)
class EventStorePolicy:
    """Exact compiled Core policy injected into the journal runtime."""

    record_type: str
    authority_model_digest: str
    max_command_bytes: int
    max_envelope_bytes: int
    max_state_binding_bytes: int
    max_state_binding_updates_per_batch: int
    max_events_per_batch: int
    max_requested_scope_items: int
    derived_tail_batch_threshold: int
    derived_tail_byte_threshold: int
    runtime_overlay_compaction_depth: int
    command_required_fields: tuple[str, ...]
    command_conditional_fields: tuple[str, ...]
    command_mutation_fields: tuple[str, ...]
    lease_bound_command_kinds: tuple[str, ...]
    lease_bound_task_transition_states: tuple[str, ...]
    command_to_primary_event: tuple[tuple[str, str], ...]
    allowed_state_binding_leaf_types: tuple[str, ...]
    state_binding_identity_rules: Mapping[str, Mapping[str, Any]]
    state_binding_algorithm_contract: Mapping[str, Any]
    state_binding_value_rules: Mapping[str, Mapping[str, Any]]
    canonical_timestamp_contract: Mapping[str, Any]
    genesis_previous_authority_commitment: str
    genesis_event_semantic_digest: str
    policy_digest: str

    @classmethod
    def from_compiled(cls, value: Mapping[str, Any]) -> "EventStorePolicy":
        """Construct from an already schema-validated compiled policy record."""

        if not isinstance(value, Mapping):
            raise EventStoreError("compiled event store policy must be an object")
        expected = {
            "record_type", "authority_model_digest", "max_command_bytes",
            "max_envelope_bytes", "max_state_binding_bytes",
            "max_state_binding_updates_per_batch", "max_events_per_batch",
            "max_requested_scope_items", "derived_tail_batch_threshold",
            "derived_tail_byte_threshold", "runtime_overlay_compaction_depth",
            "command_required_fields", "command_conditional_fields",
            "command_mutation_fields",
            "lease_bound_command_kinds", "lease_bound_task_transition_states",
            "command_to_primary_event", "allowed_state_binding_leaf_types",
            "state_binding_identity_rules", "state_binding_algorithm_contract",
            "state_binding_value_rules", "canonical_timestamp_contract",
            "genesis_previous_authority_commitment",
            "genesis_event_semantic_digest", "policy_digest",
        }
        if set(value) != expected:
            raise EventStoreError("compiled event store policy fields mismatch")
        try:
            normalized = parse_json_strict(canonical_bytes(dict(value)))
            return cls(
                record_type=normalized["record_type"],
                authority_model_digest=normalized["authority_model_digest"],
                max_command_bytes=normalized["max_command_bytes"],
                max_envelope_bytes=normalized["max_envelope_bytes"],
                max_state_binding_bytes=normalized["max_state_binding_bytes"],
                max_state_binding_updates_per_batch=normalized[
                    "max_state_binding_updates_per_batch"
                ],
                max_events_per_batch=normalized["max_events_per_batch"],
                max_requested_scope_items=normalized["max_requested_scope_items"],
                derived_tail_batch_threshold=normalized[
                    "derived_tail_batch_threshold"
                ],
                derived_tail_byte_threshold=normalized[
                    "derived_tail_byte_threshold"
                ],
                runtime_overlay_compaction_depth=normalized[
                    "runtime_overlay_compaction_depth"
                ],
                command_required_fields=tuple(normalized["command_required_fields"]),
                command_conditional_fields=tuple(
                    normalized["command_conditional_fields"]
                ),
                command_mutation_fields=tuple(normalized["command_mutation_fields"]),
                lease_bound_command_kinds=tuple(
                    normalized["lease_bound_command_kinds"]
                ),
                lease_bound_task_transition_states=tuple(
                    normalized["lease_bound_task_transition_states"]
                ),
                command_to_primary_event=tuple(
                    tuple(pair) for pair in normalized["command_to_primary_event"]
                ),
                allowed_state_binding_leaf_types=tuple(
                    normalized["allowed_state_binding_leaf_types"]
                ),
                state_binding_identity_rules=normalized[
                    "state_binding_identity_rules"
                ],
                state_binding_algorithm_contract=normalized[
                    "state_binding_algorithm_contract"
                ],
                state_binding_value_rules=normalized[
                    "state_binding_value_rules"
                ],
                canonical_timestamp_contract=normalized[
                    "canonical_timestamp_contract"
                ],
                genesis_previous_authority_commitment=normalized[
                    "genesis_previous_authority_commitment"
                ],
                genesis_event_semantic_digest=normalized[
                    "genesis_event_semantic_digest"
                ],
                policy_digest=normalized["policy_digest"],
            )
        except (CanonicalError, KeyError, TypeError, ValueError) as exc:
            raise EventStoreError(f"compiled event store policy is invalid: {exc}") from exc

    def __post_init__(self) -> None:
        if self.record_type != "EventStorePolicy":
            raise EventStoreError("event store policy record_type is invalid")
        for field in (
            "authority_model_digest", "genesis_previous_authority_commitment",
            "genesis_event_semantic_digest", "policy_digest",
        ):
            value = getattr(self, field)
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise EventStoreError(f"event store policy {field} is not SHA-256")
        for field in (
            "max_command_bytes",
            "max_envelope_bytes",
            "max_state_binding_bytes",
            "max_state_binding_updates_per_batch",
            "max_events_per_batch",
            "max_requested_scope_items",
            "derived_tail_batch_threshold",
            "derived_tail_byte_threshold",
            "runtime_overlay_compaction_depth",
        ):
            value = getattr(self, field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise EventStoreError(f"{field} must be a positive integer")
        if (
            self.max_command_bytes > self.max_envelope_bytes
            or self.max_state_binding_bytes > self.max_envelope_bytes
            or self.max_state_binding_updates_per_batch > self.max_events_per_batch
        ):
            raise EventStoreError("event store policy ceilings are internally inconsistent")
        sequence_fields = (
            (self.command_required_fields, "command required field"),
            (self.command_conditional_fields, "command conditional field"),
            (self.command_mutation_fields, "command mutation field"),
            (self.lease_bound_command_kinds, "lease-bound command kind"),
            (
                self.lease_bound_task_transition_states,
                "lease-bound task transition state",
            ),
            (
                self.allowed_state_binding_leaf_types,
                "allowed state-binding leaf type",
            ),
        )
        for values, label in sequence_fields:
            if (
                not isinstance(values, tuple)
                or not values
                or len(values) != len(set(values))
                or any(not isinstance(value, str) or not value for value in values)
            ):
                raise EventStoreError(f"{label} policy is empty, duplicated, or invalid")
        if self.command_conditional_fields != ("definition_digest",):
            raise EventStoreError(
                "command conditional fields differ from the exact runtime surface"
            )
        mapping = dict(self.command_to_primary_event)
        if len(mapping) != len(self.command_to_primary_event) or not mapping:
            raise EventStoreError("primary event mapping is empty or duplicated")
        if any(
            not isinstance(key, str)
            or not key
            or not isinstance(value, str)
            or not value
            for key, value in self.command_to_primary_event
        ):
            raise EventStoreError("primary event mapping contains an invalid value")
        if len(set(mapping.values())) != len(mapping):
            raise EventStoreError("primary event mapping contains a duplicate event kind")
        required_fields = frozenset(self.command_required_fields)
        mutation_fields = frozenset(self.command_mutation_fields)
        runtime_fields = {
            "record_type", "command_id", "command_kind", "subject_id",
            "activation_digest", "idempotency_key", "requested_scope",
            "expected_head_digest", "issued_at", "payload", "intent_digest",
            "authorization",
        }
        if not runtime_fields <= required_fields:
            raise EventStoreError(
                "command field policy omits an EventStore runtime field"
            )
        mutation_runtime_fields = {
            "workcard_task_id", "holder_authorization", "lease_id",
            "lease_generation", "fencing_token", "workcard_digest",
            "context_digest",
        }
        if (
            self.lease_bound_command_kinds
            or self.lease_bound_task_transition_states
        ) and not mutation_runtime_fields <= mutation_fields:
            raise EventStoreError(
                "mutation field policy omits an EventStore runtime field"
            )
        try:
            identity_rules = parse_json_strict(
                canonical_bytes(dict(self.state_binding_identity_rules))
            )
            algorithm = parse_json_strict(
                canonical_bytes(dict(self.state_binding_algorithm_contract))
            )
            value_rules = parse_json_strict(
                canonical_bytes(dict(self.state_binding_value_rules))
            )
            timestamp_contract = parse_json_strict(
                canonical_bytes(dict(self.canonical_timestamp_contract))
            )
        except (CanonicalError, TypeError, ValueError) as exc:
            raise EventStoreError(
                f"event store policy is not canonical JSON: {exc}"
            ) from exc
        if set(identity_rules) != set(self.allowed_state_binding_leaf_types):
            raise EventStoreError("state-binding identity rules do not cover exact leaf types")
        for leaf_type, rule in identity_rules.items():
            if not isinstance(rule, dict) or set(rule) not in (
                {"id_fields", "identity_mode"},
                {
                    "digest_algorithm", "digest_hex_chars", "digest_input",
                    "id_fields", "identity_mode", "prefix",
                },
            ):
                raise EventStoreError(f"state-binding identity rule is invalid: {leaf_type}")
            fields = rule.get("id_fields")
            mode = rule.get("identity_mode")
            if (
                not isinstance(fields, list)
                or not fields
                or len(fields) != len(set(fields))
                or any(not isinstance(field, str) or not field for field in fields)
                or mode not in {"direct", "typed_digest_id"}
                or (mode == "direct")
                is not (len(fields) == 1 and "prefix" not in rule)
                or (
                    mode == "typed_digest_id"
                    and (
                        not isinstance(rule.get("prefix"), str)
                        or not rule["prefix"]
                        or rule.get("digest_algorithm") != "sha256"
                        or rule.get("digest_input")
                        != "canonical-ordered-id-field-values"
                        or not isinstance(rule.get("digest_hex_chars"), int)
                        or isinstance(rule.get("digest_hex_chars"), bool)
                        or not 1 <= rule["digest_hex_chars"] <= 64
                    )
                )
            ):
                raise EventStoreError(f"state-binding identity rule is invalid: {leaf_type}")
        if set(value_rules) != set(self.allowed_state_binding_leaf_types):
            raise EventStoreError("state-binding value rules do not cover exact leaf types")
        value_event_kinds: list[str] = []
        for leaf_type, rule in value_rules.items():
            if not isinstance(rule, dict) or set(rule) != {
                "event_kinds", "value_definition", "value_digest_rule"
            }:
                raise EventStoreError(
                    f"state-binding value rule is invalid: {leaf_type}"
                )
            event_kinds = rule["event_kinds"]
            if (
                not isinstance(event_kinds, list)
                or len(event_kinds) != len(set(event_kinds))
                or any(not isinstance(kind, str) or not kind for kind in event_kinds)
                or any(
                    not isinstance(rule[field], str) or not rule[field]
                    for field in ("value_definition", "value_digest_rule")
                )
            ):
                raise EventStoreError(
                    f"state-binding value rule is invalid: {leaf_type}"
                )
            if (leaf_type == "Activation") is not (event_kinds == []):
                raise EventStoreError(
                    "only the pre-journal Activation leaf may omit event kinds"
                )
            value_event_kinds.extend(event_kinds)
        expected_value_event_kinds = {
            *dict(self.command_to_primary_event).values(),
            "relation.recorded",
        }
        if (
            len(value_event_kinds) != len(set(value_event_kinds))
            or set(value_event_kinds) != expected_value_event_kinds
        ):
            raise EventStoreError(
                "state-binding value rules do not cover exact event kinds"
            )
        expected_algorithm = {
            "delete_rule": "delete maps the keyed leaf to empty_leaf",
            "delta_order": ["leaf_type-ascending", "leaf_id-ascending"],
            "depth": _STATE_TREE_DEPTH,
            "depth_encoding": "unsigned-16-bit-big-endian",
            "empty_leaf_domain_utf8": "promin:typed-sparse-merkle-v1:empty-leaf",
            "internal_node_domain_utf8": "promin:typed-sparse-merkle-v1:node\u0000",
            "internal_node_rule": (
                "sha256(domain + depth_uint16_be + left_32_bytes + right_32_bytes)"
            ),
            "leaf_domain_utf8": "promin:typed-sparse-merkle-v1:leaf\u0000",
            "leaf_key_rule": (
                "sha256(canonical bytes of exact object leaf_type and leaf_id)"
            ),
            "set_leaf_rule": (
                "sha256(domain + leaf_key_32_bytes + value_digest_32_bytes)"
            ),
        }
        if algorithm != expected_algorithm:
            raise EventStoreError("state-binding algorithm differs from runtime")
        expected_timestamp_contract = {
            "calendar": "proleptic-gregorian",
            "format": "utc-second-z",
            "formatter_api": (
                "promin.canonical.format_utc_second(value: datetime) -> str"
            ),
            "fractional_seconds": "reject",
            "normalization": "identity-round-trip",
            "offset": "Z-only",
            "parser_api": (
                "promin.canonical.parse_utc_second(value: str) -> "
                "timezone-aware UTC datetime"
            ),
            "pattern": (
                "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:"
                "[0-9]{2}:[0-9]{2}Z$"
            ),
            "real_calendar_validation": True,
            "resolution_seconds": 1,
            "year_max": 9999,
            "year_min": 1,
        }
        if timestamp_contract != expected_timestamp_contract:
            raise EventStoreError("canonical timestamp contract differs from runtime")
        identity = {
            "record_type": self.record_type,
            "authority_model_digest": self.authority_model_digest,
            "max_command_bytes": self.max_command_bytes,
            "max_envelope_bytes": self.max_envelope_bytes,
            "max_state_binding_bytes": self.max_state_binding_bytes,
            "max_state_binding_updates_per_batch": (
                self.max_state_binding_updates_per_batch
            ),
            "max_events_per_batch": self.max_events_per_batch,
            "max_requested_scope_items": self.max_requested_scope_items,
            "derived_tail_batch_threshold": self.derived_tail_batch_threshold,
            "derived_tail_byte_threshold": self.derived_tail_byte_threshold,
            "runtime_overlay_compaction_depth": (
                self.runtime_overlay_compaction_depth
            ),
            "command_required_fields": list(self.command_required_fields),
            "command_conditional_fields": list(self.command_conditional_fields),
            "command_mutation_fields": list(self.command_mutation_fields),
            "lease_bound_command_kinds": list(self.lease_bound_command_kinds),
            "lease_bound_task_transition_states": list(
                self.lease_bound_task_transition_states
            ),
            "command_to_primary_event": [
                list(pair) for pair in self.command_to_primary_event
            ],
            "allowed_state_binding_leaf_types": list(
                self.allowed_state_binding_leaf_types
            ),
            "state_binding_identity_rules": identity_rules,
            "state_binding_algorithm_contract": algorithm,
            "state_binding_value_rules": value_rules,
            "canonical_timestamp_contract": timestamp_contract,
            "genesis_previous_authority_commitment": (
                self.genesis_previous_authority_commitment
            ),
            "genesis_event_semantic_digest": self.genesis_event_semantic_digest,
        }
        if digest_value(identity) != self.policy_digest:
            raise EventStoreError("event store policy digest mismatch")
        object.__setattr__(
            self,
            "state_binding_identity_rules",
            MappingProxyType(
                {
                    key: MappingProxyType(
                        {
                            field: tuple(item) if isinstance(item, list) else item
                            for field, item in rule.items()
                        }
                    )
                    for key, rule in identity_rules.items()
                }
            ),
        )
        object.__setattr__(
            self,
            "state_binding_algorithm_contract",
            MappingProxyType(
                {
                    key: tuple(value) if isinstance(value, list) else value
                    for key, value in algorithm.items()
                }
            ),
        )
        object.__setattr__(
            self,
            "state_binding_value_rules",
            MappingProxyType(
                {
                    key: MappingProxyType(
                        {
                            field: tuple(item) if isinstance(item, list) else item
                            for field, item in rule.items()
                        }
                    )
                    for key, rule in value_rules.items()
                }
            ),
        )
        object.__setattr__(
            self,
            "canonical_timestamp_contract",
            MappingProxyType(dict(timestamp_contract)),
        )

    @property
    def primary_events(self) -> Mapping[str, str]:
        return MappingProxyType(dict(self.command_to_primary_event))

    def as_compiled(self) -> dict[str, Any]:
        identity_rules = {
            leaf_type: {
                field: list(value) if isinstance(value, tuple) else value
                for field, value in rule.items()
            }
            for leaf_type, rule in self.state_binding_identity_rules.items()
        }
        algorithm = {
            field: list(value) if isinstance(value, tuple) else value
            for field, value in self.state_binding_algorithm_contract.items()
        }
        value_rules = {
            leaf_type: {
                field: list(value) if isinstance(value, tuple) else value
                for field, value in rule.items()
            }
            for leaf_type, rule in self.state_binding_value_rules.items()
        }
        return {
            "record_type": self.record_type,
            "authority_model_digest": self.authority_model_digest,
            "max_command_bytes": self.max_command_bytes,
            "max_envelope_bytes": self.max_envelope_bytes,
            "max_state_binding_bytes": self.max_state_binding_bytes,
            "max_state_binding_updates_per_batch": (
                self.max_state_binding_updates_per_batch
            ),
            "max_events_per_batch": self.max_events_per_batch,
            "max_requested_scope_items": self.max_requested_scope_items,
            "derived_tail_batch_threshold": self.derived_tail_batch_threshold,
            "derived_tail_byte_threshold": self.derived_tail_byte_threshold,
            "runtime_overlay_compaction_depth": (
                self.runtime_overlay_compaction_depth
            ),
            "command_required_fields": list(self.command_required_fields),
            "command_conditional_fields": list(self.command_conditional_fields),
            "command_mutation_fields": list(self.command_mutation_fields),
            "lease_bound_command_kinds": list(self.lease_bound_command_kinds),
            "lease_bound_task_transition_states": list(
                self.lease_bound_task_transition_states
            ),
            "command_to_primary_event": [
                list(pair) for pair in self.command_to_primary_event
            ],
            "allowed_state_binding_leaf_types": list(
                self.allowed_state_binding_leaf_types
            ),
            "state_binding_identity_rules": identity_rules,
            "state_binding_algorithm_contract": algorithm,
            "state_binding_value_rules": value_rules,
            "canonical_timestamp_contract": dict(
                self.canonical_timestamp_contract
            ),
            "genesis_previous_authority_commitment": (
                self.genesis_previous_authority_commitment
            ),
            "genesis_event_semantic_digest": self.genesis_event_semantic_digest,
            "policy_digest": self.policy_digest,
        }

    @property
    def command_required_field_set(self) -> frozenset[str]:
        return frozenset(self.command_required_fields)

    @property
    def command_mutation_field_set(self) -> frozenset[str]:
        return frozenset(self.command_mutation_fields)

    @property
    def command_conditional_field_set(self) -> frozenset[str]:
        return frozenset(self.command_conditional_fields)

    @property
    def lease_bound_command_kind_set(self) -> frozenset[str]:
        return frozenset(self.lease_bound_command_kinds)

    @property
    def lease_bound_task_transition_state_set(self) -> frozenset[str]:
        return frozenset(self.lease_bound_task_transition_states)

    @property
    def allowed_state_binding_leaf_type_set(self) -> frozenset[str]:
        return frozenset(self.allowed_state_binding_leaf_types)

    @property
    def state_binding_event_leaf_types(self) -> Mapping[str, str]:
        return MappingProxyType(
            {
                event_kind: leaf_type
                for leaf_type, rule in self.state_binding_value_rules.items()
                for event_kind in rule["event_kinds"]
            }
        )


def state_binding_leaf_id(
    policy: EventStorePolicy,
    leaf_type: str,
    value: Mapping[str, Any],
) -> str:
    """Derive one typed authority-leaf ID from the exact compiled Core rule."""

    if not isinstance(policy, EventStorePolicy):
        raise EventStoreError("state-binding identity requires EventStorePolicy")
    rule = policy.state_binding_identity_rules.get(leaf_type)
    if rule is None or not isinstance(value, Mapping):
        raise EventStoreError("state-binding identity leaf or value is invalid")
    identity_values: list[str] = []
    for field in rule["id_fields"]:
        item = value.get(field)
        # Grant state leaves wrap the immutable Grant with current revocation
        # state.  Their identity remains the nested Grant ID.
        if item is None and leaf_type == "Grant":
            grant = value.get("grant")
            if isinstance(grant, Mapping):
                item = grant.get(field)
        if not isinstance(item, str) or not _ID.fullmatch(item):
            raise EventStoreError(
                f"state-binding {leaf_type} identity field is invalid: {field}"
            )
        identity_values.append(item)
    if rule["identity_mode"] == "direct":
        leaf_id = identity_values[0]
    else:
        digest = hashlib.sha256(canonical_bytes(identity_values)).hexdigest()
        leaf_id = rule["prefix"] + digest[: rule["digest_hex_chars"]]
    if not _ID.fullmatch(leaf_id):
        raise EventStoreError("derived state-binding leaf ID is invalid")
    return leaf_id


def state_binding_value_digest(
    policy: EventStorePolicy,
    leaf_type: str,
    value: Mapping[str, Any],
    *,
    event_kind: str | None,
) -> str:
    """Digest a validated authority value under its exact Core event binding."""

    if not isinstance(policy, EventStorePolicy):
        raise EventStoreError("state-binding value requires EventStorePolicy")
    rule = policy.state_binding_value_rules.get(leaf_type)
    if rule is None or not isinstance(value, Mapping):
        raise EventStoreError("state-binding value leaf or payload is invalid")
    if event_kind is None:
        if rule["event_kinds"]:
            raise EventStoreError("state-binding value requires a Core-owned event kind")
    elif event_kind not in rule["event_kinds"]:
        raise EventStoreError("event kind does not own this state-binding leaf")
    if value.get("record_type") != rule["value_definition"]:
        raise EventStoreError("state-binding value definition differs from Core")
    return digest_value(_deep_thaw(value))


@dataclass(frozen=True)
class CommitReadView:
    """Immutable journal identity visible to a prepare callback under its lock."""

    activation_digest: str
    implementation_closure_digest: str
    head_sequence: int
    head_batch_id: str | None
    head_digest: str | None
    batch_count: int
    event_count: int
    event_semantic_digest: str
    authority_prefix_digest: str
    current_state_binding_digest: str | None
    current_state_binding_trusted: bool
    state: Any

    @property
    def head(self) -> Mapping[str, Any]:
        return MappingProxyType(
            {
                "sequence": self.head_sequence,
                "batch_id": self.head_batch_id,
                "batch_digest": self.head_digest,
            }
        )


@dataclass(frozen=True)
class CommitStateSnapshot:
    """Immutable semantic state bound to the exact locked journal HEAD/root."""

    state: Any
    head_sequence: int
    head_digest: str | None
    state_binding_digest: str | None


@dataclass(frozen=True)
class PreparedCommit:
    """Batch inputs approved against one exact CommitReadView."""

    auxiliary_relations: tuple[Mapping[str, Any], ...]
    state_binding_delta: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        if not isinstance(self.auxiliary_relations, tuple):
            raise EventStoreError("prepared auxiliary relations must be an immutable tuple")
        if not isinstance(self.state_binding_delta, tuple):
            raise EventStoreError("prepared state binding delta must be an immutable tuple")


@dataclass(frozen=True)
class _ValidatedPreparedCommit:
    auxiliary_relations: tuple[dict[str, Any], ...]
    state_binding_delta: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class _CompactStateBindingOverlay:
    """One derived compact-index change with the canonical root proof.

    Individual leaves remain separate database rows and are replayed from the
    journal exactly as before.  Only the disposable intermediate sparse-tree
    rows below the 16-bit partition boundary are omitted.
    """

    node_rows: Mapping[tuple[int, bytes], tuple[bytes, bytes]]
    leaf_deletes: tuple[bytes, ...]
    leaf_upserts: tuple[tuple[bytes, bytes, bytes], ...]
    bucket_deletes: tuple[bytes, ...]
    bucket_upserts: tuple[tuple[bytes, bytes], ...]


@dataclass(frozen=True)
class _CommittedEnvelopeWitness:
    """One-use in-process binding for the envelope just durably committed.

    It is intentionally not a persisted checkpoint and never proves a prior
    journal prefix.  The next authoritative refresh still re-reads that
    prefix byte-for-byte.  Its sole purpose is to avoid immediately repeating
    that scan when the caller asks for the exact envelope returned by the
    same successful ``commit`` call.
    """

    root_identity: str
    activation_digest: str
    implementation_closure_digest: str
    index_generation: str
    authority_generation: str
    authority_root_digest: str
    head: dict[str, Any]
    journal_file: str
    journal_payload: bytes
    journal_payload_digest: str
    command_payload: bytes
    command_payload_digest: str
    binding_digest: str

    def bindings(self) -> dict[str, Any]:
        return {
            "record_type": "CommittedEnvelopeWitness",
            "version": 1,
            "root_identity": self.root_identity,
            "activation_digest": self.activation_digest,
            "implementation_closure_digest": self.implementation_closure_digest,
            "index_generation": self.index_generation,
            "authority_generation": self.authority_generation,
            "authority_root_digest": self.authority_root_digest,
            "head": copy.deepcopy(self.head),
            "journal_file": self.journal_file,
            "journal_payload_digest": self.journal_payload_digest,
            "command_payload_digest": self.command_payload_digest,
        }


def _extend_event_semantic_digest(previous: str, event: Mapping[str, Any]) -> str:
    """Extend a deterministic event transcript without retaining prior bytes."""

    if not _DIGEST.fullmatch(previous):
        raise EventStoreError("event semantic digest is invalid")
    return digest_value({"previous_digest": previous, "event": dict(event)})


def _extend_derived_rows_transcript(
    previous: str,
    *,
    section: str,
    key: str,
    payload_digest: str,
) -> str:
    """Extend the ordered disposable-row transcript without retaining rows."""

    if (
        not isinstance(previous, str)
        or not _DIGEST.fullmatch(previous)
        or not isinstance(section, str)
        or not _DERIVED_ROW_ID.fullmatch(section)
        or not isinstance(key, str)
        or not _DERIVED_ROW_ID.fullmatch(key)
        or not isinstance(payload_digest, str)
        or not _DIGEST.fullmatch(payload_digest)
    ):
        raise DerivedCheckpointError("derived row transcript input is invalid")
    return digest_value(
        {
            "previous_digest": previous,
            "section": section,
            "key": key,
            "payload_digest": payload_digest,
        }
    )


def _authority_commitment(
    *,
    previous_commitment: str,
    sequence: int,
    previous_batch_digest: str | None,
    event_count: int,
    event_semantic_digest: str,
    state_binding_update_count: int,
    state_binding_digest: str | None,
) -> str:
    return digest_value(
        {
            "previous_authority_commitment": previous_commitment,
            "sequence": sequence,
            "previous_batch_digest": previous_batch_digest,
            "event_count": event_count,
            "event_semantic_digest": event_semantic_digest,
            "state_binding_update_count": state_binding_update_count,
            "state_binding_digest": state_binding_digest,
        }
    )


def _state_internal_digest(depth: int, left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(
        b"promin:typed-sparse-merkle-v1:node\x00"
        + depth.to_bytes(2, "big")
        + left
        + right
    ).digest()


def _state_default_digests() -> tuple[bytes, ...]:
    values = [b""] * (_STATE_TREE_DEPTH + 1)
    values[_STATE_TREE_DEPTH] = hashlib.sha256(
        b"promin:typed-sparse-merkle-v1:empty-leaf"
    ).digest()
    for depth in range(_STATE_TREE_DEPTH - 1, -1, -1):
        values[depth] = _state_internal_digest(
            depth, values[depth + 1], values[depth + 1]
        )
    return tuple(values)


_STATE_DEFAULT_DIGESTS = _state_default_digests()
_EMPTY_STATE_BINDING_DIGEST = _STATE_DEFAULT_DIGESTS[0].hex()


def _state_leaf_key_digest(update: Mapping[str, Any]) -> bytes:
    return bytes.fromhex(
        digest_value(
            {
                "leaf_type": update["leaf_type"],
                "leaf_id": update["leaf_id"],
            }
        )
    )


def _state_leaf_digest(key_digest: bytes, value_digest: str) -> bytes:
    return hashlib.sha256(
        b"promin:typed-sparse-merkle-v1:leaf\x00"
        + key_digest
        + bytes.fromhex(value_digest)
    ).digest()


def _state_prefix(key_digest: bytes, depth: int) -> bytes:
    if not 0 <= depth <= _STATE_TREE_DEPTH:
        raise DerivedCheckpointError("state binding tree depth is invalid")
    if depth == 0:
        return b""
    byte_count = (depth + 7) // 8
    prefix = bytearray(key_digest[:byte_count])
    remainder = depth % 8
    if remainder:
        prefix[-1] &= (0xFF << (8 - remainder)) & 0xFF
    return bytes(prefix)


def _state_storage_parent_digest(
    parent_depth: int,
    children: Mapping[int, bytes],
) -> bytes:
    """Reduce one stored byte edge to the exact binary sparse-tree parent.

    The authority algorithm remains the 256-level typed binary tree.  The
    derived SQLite index materializes only byte-boundary levels and rebuilds
    the seven omitted internal levels plus the boundary parent on demand.
    This is a storage representation only; every internal digest still uses
    its original absolute binary depth and domain separator.
    """

    if (
        parent_depth < 0
        or parent_depth + _STATE_BINDING_STORAGE_STRIDE > _STATE_TREE_DEPTH
        or parent_depth % _STATE_BINDING_STORAGE_STRIDE != 0
    ):
        raise DerivedCheckpointError("state binding storage depth is invalid")
    level: dict[int, bytes] = {}
    for edge, node_digest in children.items():
        if (
            not isinstance(edge, int)
            or isinstance(edge, bool)
            or not 0 <= edge <= 255
            or not isinstance(node_digest, bytes)
            or len(node_digest) != 32
        ):
            raise DerivedCheckpointError("state binding storage child is invalid")
        if node_digest != _STATE_DEFAULT_DIGESTS[
            parent_depth + _STATE_BINDING_STORAGE_STRIDE
        ]:
            level[edge] = node_digest
    for depth in range(
        parent_depth + _STATE_BINDING_STORAGE_STRIDE - 1,
        parent_depth - 1,
        -1,
    ):
        parents: dict[int, bytes] = {}
        for slot in {edge >> 1 for edge in level}:
            node_digest = _state_internal_digest(
                depth,
                level.get(slot << 1, _STATE_DEFAULT_DIGESTS[depth + 1]),
                level.get((slot << 1) | 1, _STATE_DEFAULT_DIGESTS[depth + 1]),
            )
            if node_digest != _STATE_DEFAULT_DIGESTS[depth]:
                parents[slot] = node_digest
        level = parents
    if not level:
        return _STATE_DEFAULT_DIGESTS[parent_depth]
    if set(level) != {0}:
        raise DerivedCheckpointError("state binding byte subtree did not reduce")
    return level[0]


def _encode_state_storage_children(children: Mapping[int, bytes]) -> bytes:
    payload = bytearray()
    for edge, node_digest in sorted(children.items()):
        if (
            not isinstance(edge, int)
            or isinstance(edge, bool)
            or not 0 <= edge <= 255
            or not isinstance(node_digest, bytes)
            or len(node_digest) != 32
        ):
            raise DerivedCheckpointError("state binding child payload is invalid")
        payload.append(edge)
        payload.extend(node_digest)
    return bytes(payload)


def _decode_state_storage_children(payload: Any) -> dict[int, bytes]:
    if not isinstance(payload, bytes) or len(payload) % 33 != 0 or len(payload) > 256 * 33:
        raise DerivedCheckpointError("state binding child payload is malformed")
    children: dict[int, bytes] = {}
    previous = -1
    for offset in range(0, len(payload), 33):
        edge = payload[offset]
        if edge <= previous:
            raise DerivedCheckpointError("state binding child payload order is invalid")
        previous = edge
        children[edge] = payload[offset + 1 : offset + 33]
    return children


def _single_state_leaf_tree(
    *, leaf_type: str, leaf_id: str, value_digest: str
) -> tuple[str, dict[tuple[int, bytes], bytes]]:
    """Build the canonical sparse-tree nodes for one non-event genesis leaf."""

    update = {
        "leaf_type": leaf_type,
        "leaf_id": leaf_id,
        "operation": "set",
        "value_digest": value_digest,
    }
    key_digest = _state_leaf_key_digest(update)
    current = _state_leaf_digest(key_digest, value_digest)
    nodes: dict[tuple[int, bytes], bytes] = {
        (_STATE_TREE_DEPTH, _state_prefix(key_digest, _STATE_TREE_DEPTH)): current
    }
    for child_depth in range(_STATE_TREE_DEPTH, 0, -1):
        bit_index = child_depth - 1
        sibling = _STATE_DEFAULT_DIGESTS[child_depth]
        parent_depth = child_depth - 1
        if key_digest[bit_index // 8] & (1 << (7 - (bit_index % 8))):
            current = _state_internal_digest(parent_depth, sibling, current)
        else:
            current = _state_internal_digest(parent_depth, current, sibling)
        nodes[(parent_depth, _state_prefix(key_digest, parent_depth))] = current
    return current.hex(), nodes


def _state_binding_root_from_leaves(
    leaves: Iterable[Mapping[str, str]],
) -> str:
    """Recompute the typed sparse-Merkle root from one complete leaf set."""

    current: dict[bytes, bytes] = {}
    for leaf in leaves:
        key_digest = _state_leaf_key_digest(leaf)
        if key_digest in current:
            raise DerivedCheckpointError("state binding leaves contain a duplicate key")
        current[key_digest] = _state_leaf_digest(key_digest, leaf["value_digest"])
    if not current:
        return _EMPTY_STATE_BINDING_DIGEST
    for parent_depth in range(_STATE_TREE_DEPTH - 1, -1, -1):
        child_depth = parent_depth + 1
        grouped: dict[bytes, list[bytes | None]] = {}
        for child_prefix, child_digest in current.items():
            parent_prefix = _state_prefix(child_prefix, parent_depth)
            pair = grouped.setdefault(parent_prefix, [None, None])
            side = (
                1
                if child_prefix[parent_depth // 8]
                & (1 << (7 - (parent_depth % 8)))
                else 0
            )
            if pair[side] is not None:
                raise DerivedCheckpointError(
                    "state binding leaves collide below the current tree depth"
                )
            pair[side] = child_digest
        current = {
            parent_prefix: _state_internal_digest(
                parent_depth,
                pair[0] or _STATE_DEFAULT_DIGESTS[child_depth],
                pair[1] or _STATE_DEFAULT_DIGESTS[child_depth],
            )
            for parent_prefix, pair in grouped.items()
        }
    root = current.get(b"")
    if root is None or len(current) != 1:
        raise DerivedCheckpointError("state binding leaves did not reduce to one root")
    return root.hex()


def _state_binding_partition_root(
    *,
    partition: bytes,
    leaf_values: Mapping[bytes, bytes],
) -> bytes:
    """Compute one exact sparse-tree node at the compact partition depth.

    ``compact_leaf`` stores the individual 256-bit leaf keys and exact value
    digests.  Replaying their lower subtree on demand is deterministic and
    yields the same node the full byte-boundary representation would have
    materialised at depth 16.
    """

    if (
        not isinstance(partition, bytes)
        or len(partition) != _STATE_BINDING_COMPACT_PARTITION_BYTES
    ):
        raise DerivedCheckpointError("state binding compact partition is invalid")
    current: dict[bytes, bytes] = {}
    for key_digest, value_digest in leaf_values.items():
        if (
            not isinstance(key_digest, bytes)
            or len(key_digest) != 32
            or key_digest[:_STATE_BINDING_COMPACT_PARTITION_BYTES] != partition
            or not isinstance(value_digest, bytes)
            or len(value_digest) != 32
            or key_digest in current
        ):
            raise DerivedCheckpointError("state binding compact leaf is invalid")
        current[key_digest] = hashlib.sha256(
            b"promin:typed-sparse-merkle-v1:leaf\x00"
            + key_digest
            + value_digest
        ).digest()
    if not current:
        return _STATE_DEFAULT_DIGESTS[_STATE_BINDING_COMPACT_PARTITION_DEPTH]
    for parent_depth in range(
        _STATE_TREE_DEPTH - 1,
        _STATE_BINDING_COMPACT_PARTITION_DEPTH - 1,
        -1,
    ):
        child_depth = parent_depth + 1
        grouped: dict[bytes, list[bytes | None]] = {}
        for child_prefix, child_digest in current.items():
            parent_prefix = _state_prefix(child_prefix, parent_depth)
            pair = grouped.setdefault(parent_prefix, [None, None])
            side = (
                1
                if child_prefix[parent_depth // 8]
                & (1 << (7 - (parent_depth % 8)))
                else 0
            )
            if pair[side] is not None:
                raise DerivedCheckpointError(
                    "state binding compact leaves collide below the current tree depth"
                )
            pair[side] = child_digest
        current = {
            parent_prefix: _state_internal_digest(
                parent_depth,
                pair[0] or _STATE_DEFAULT_DIGESTS[child_depth],
                pair[1] or _STATE_DEFAULT_DIGESTS[child_depth],
            )
            for parent_prefix, pair in grouped.items()
        }
    root = current.get(partition)
    if root is None or len(current) != 1:
        raise DerivedCheckpointError(
            "state binding compact partition did not reduce to one root"
        )
    return root


def _normalize_state_binding_delta(
    value: Any,
    *,
    policy: EventStorePolicy,
) -> tuple[dict[str, Any], ...]:
    try:
        limits = ParseLimits(max_bytes=policy.max_state_binding_bytes)
        normalized = parse_json_strict(
            canonical_bytes(list(value), limits=limits), limits=limits
        )
    except (CanonicalError, TypeError, ValueError) as exc:
        raise EventStoreError(
            f"state binding delta is not bounded canonical JSON: {exc}"
        ) from exc
    if (
        not isinstance(normalized, list)
        or not 1 <= len(normalized) <= policy.max_state_binding_updates_per_batch
    ):
        raise EventStoreError("state binding delta count is outside its policy ceiling")
    identities: list[tuple[str, str]] = []
    for update in normalized:
        if not isinstance(update, dict):
            raise EventStoreError("state binding update must be an object")
        operation = update.get("operation")
        required = {"leaf_type", "leaf_id", "operation"}
        if operation == "set":
            required.add("value_digest")
        elif operation != "delete":
            raise EventStoreError("state binding update operation is invalid")
        if set(update) != required:
            raise EventStoreError("state binding update fields mismatch")
        for field in ("leaf_type", "leaf_id"):
            if not isinstance(update[field], str) or not _ID.fullmatch(update[field]):
                raise EventStoreError(f"state binding update {field} is invalid")
        if update["leaf_type"] not in policy.allowed_state_binding_leaf_type_set:
            raise EventStoreError("state binding update leaf_type is not Core-owned")
        if operation == "set" and (
            not isinstance(update["value_digest"], str)
            or not _DIGEST.fullmatch(update["value_digest"])
        ):
            raise EventStoreError("state binding update value digest is invalid")
        identities.append((update["leaf_type"], update["leaf_id"]))
    if len(identities) != len(set(identities)):
        raise EventStoreError("state binding delta contains a duplicate leaf")
    if identities != sorted(identities):
        raise EventStoreError("state binding delta must use canonical leaf order")
    return tuple(normalized)


def _validate_state_binding_event_correspondence(
    delta: tuple[dict[str, Any], ...],
    event_values: Iterable[tuple[str, Mapping[str, Any]]],
    *,
    policy: EventStorePolicy,
) -> None:
    expected: list[tuple[str, str, str, Mapping[str, Any]]] = []
    additional_owned_identities: set[tuple[str, str]] = set()
    event_leaf_types = policy.state_binding_event_leaf_types
    for event_kind, payload in event_values:
        leaf_type = event_leaf_types.get(event_kind)
        if leaf_type is None:
            raise EventStoreError("event kind lacks a Core state-binding value rule")
        expected.append(
            (
                leaf_type,
                state_binding_leaf_id(policy, leaf_type, payload),
                event_kind,
                payload,
            )
        )
        if event_kind == "decision.recorded" and payload.get(
            "decision_kind"
        ) in {"resolve", "waive"}:
            target_id = payload.get("target_id")
            if (
                payload.get("target_type") != "Finding"
                or not isinstance(target_id, str)
                or not _ID.fullmatch(target_id)
            ):
                raise EventStoreError(
                    "Finding disposition event target is invalid"
                )
            additional_owned_identities.add(("Finding", target_id))
    expected.sort(key=lambda item: (item[0], item[1]))
    updates = {
        (item["leaf_type"], item["leaf_id"]): item
        for item in delta
    }
    for leaf_type, leaf_id, event_kind, payload in expected:
        update = updates.get((leaf_type, leaf_id))
        if update is None:
            raise EventStoreError(
                "state binding delta omits a command event leaf"
            )
        if update["operation"] != "set":
            raise EventStoreError(
                "current Core event kinds require a set state-binding update"
            )
        value_rule = policy.state_binding_value_rules[leaf_type]
        if payload.get("record_type") == value_rule["value_definition"]:
            expected_digest = state_binding_value_digest(
                policy,
                leaf_type,
                payload,
                event_kind=event_kind,
            )
            if update["value_digest"] != expected_digest:
                raise EventStoreError(
                    "state binding value digest differs from exact Event payload"
                )
    event_owned_identities = {
        (leaf_type, leaf_id) for leaf_type, leaf_id, _kind, _payload in expected
    }
    exact_identities = event_owned_identities | additional_owned_identities
    if set(updates) != exact_identities:
        raise EventStoreError(
            "state binding delta differs from the complete event-owned leaf set"
        )
    for identity in additional_owned_identities:
        if updates[identity]["operation"] != "set":
            raise EventStoreError(
                "Finding disposition must set the complete post-state Finding"
            )


def utc_now() -> str:
    return format_utc_second(
        _datetime.datetime.now(_datetime.timezone.utc).replace(microsecond=0)
    )


def parse_timestamp(value: str) -> _datetime.datetime:
    try:
        return parse_utc_second(value)
    except CanonicalError as exc:
        raise EventStoreError("timestamp must be a canonical real UTC second") from exc


def command_intent_identity(command: Mapping[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(value) for key, value in command.items() if key not in {"intent_digest", "authorization"}}


def _commit_effect_digest(command: Mapping[str, Any], relations: Iterable[Mapping[str, Any]]) -> str:
    return digest_value(
        {
            "command_digest": digest_value(command),
            "auxiliary_relations": list(relations),
        }
    )


def normalize_command(
    command: Mapping[str, Any],
    *,
    policy: EventStorePolicy,
) -> dict[str, Any]:
    """Strictly normalize the Core CommandRequest before any authorization."""

    if not isinstance(command, Mapping):
        raise EventStoreError("command must be an object")
    fields = set(command)
    required_fields = policy.command_required_field_set
    conditional_fields = policy.command_conditional_field_set
    mutation_policy_fields = policy.command_mutation_field_set
    allowed_fields = required_fields | conditional_fields | mutation_policy_fields
    if not required_fields <= fields or not fields <= allowed_fields:
        missing = sorted(required_fields - fields)
        unknown = sorted(fields - allowed_fields)
        raise EventStoreError(f"command fields mismatch; missing={missing}, unknown={unknown}")
    try:
        command_limits = ParseLimits(max_bytes=policy.max_command_bytes)
        encoded = canonical_bytes(dict(command), limits=command_limits)
        normalized = parse_json_strict(encoded, limits=command_limits)
    except CanonicalError as exc:
        raise EventStoreError(f"command is not bounded canonical JSON: {exc}") from exc
    _reject_reserved_secret_fields(normalized, surface="command")
    if normalized["record_type"] != "CommandRequest":
        raise EventStoreError("command record_type must be CommandRequest")
    for field in ("command_id", "subject_id"):
        if not isinstance(normalized[field], str) or not _ID.fullmatch(normalized[field]):
            raise EventStoreError(f"{field} is not a canonical ID")
    key = normalized["idempotency_key"]
    if not isinstance(key, str) or not (16 <= len(key) <= 128) or not _ID.fullmatch(key):
        raise EventStoreError("idempotency_key is not canonical")
    if normalized["command_kind"] not in policy.primary_events:
        raise EventStoreError("command_kind is not supported by Core")
    for field in ("activation_digest", "intent_digest"):
        if not isinstance(normalized[field], str) or not _DIGEST.fullmatch(normalized[field]):
            raise EventStoreError(f"{field} is not a SHA-256 digest")
    expected = normalized["expected_head_digest"]
    if expected is not None and (not isinstance(expected, str) or not _DIGEST.fullmatch(expected)):
        raise EventStoreError("expected_head_digest must be null or SHA-256")
    if (
        not isinstance(normalized["requested_scope"], list)
        or not 1
        <= len(normalized["requested_scope"])
        <= policy.max_requested_scope_items
    ):
        raise EventStoreError("requested_scope count is outside its Core ceiling")
    if not isinstance(normalized["payload"], dict) or not normalized["payload"]:
        raise EventStoreError("command payload must be a nonempty object")
    if not isinstance(normalized["authorization"], dict) or not normalized["authorization"]:
        raise EventStoreError("command authorization must be a nonempty object")
    if normalized["command_kind"] in {"run.record", "gate.record"}:
        definition_digest = normalized.get("definition_digest")
        if (
            not isinstance(definition_digest, str)
            or not _DIGEST.fullmatch(definition_digest)
            or normalized["payload"].get("definition_digest")
            != definition_digest
        ):
            raise EventStoreError(
                "command definition_digest differs from its Run/GateResult payload"
            )
    elif conditional_fields & fields:
        raise EventStoreError(
            "command kind cannot carry operation-bound definition fields"
        )
    if _contains_null(normalized["payload"]) or _contains_null(normalized["authorization"]):
        raise EventStoreError("critical command payload and authorization cannot contain null")
    mutation_fields = mutation_policy_fields & fields
    payload = normalized["payload"]
    requires_mutation_binding = normalized["command_kind"] in policy.lease_bound_command_kind_set or (
        normalized["command_kind"] == "task.transition"
        and payload.get("to_state")
        in policy.lease_bound_task_transition_state_set
    )
    if requires_mutation_binding and mutation_fields != mutation_policy_fields:
        missing = sorted(mutation_policy_fields - mutation_fields)
        raise EventStoreError(f"lease-bound command fields mismatch; missing={missing}")
    if not requires_mutation_binding and mutation_fields:
        raise EventStoreError("non-lease command cannot carry mutation binding fields")
    if requires_mutation_binding:
        holder_authorization = normalized["holder_authorization"]
        if not isinstance(holder_authorization, dict) or not holder_authorization:
            raise EventStoreError("holder_authorization must be a nonempty object")
        if _contains_null(holder_authorization):
            raise EventStoreError("holder_authorization cannot contain null")
        for field in ("workcard_task_id", "lease_id"):
            if not isinstance(normalized[field], str) or not _ID.fullmatch(normalized[field]):
                raise EventStoreError(f"{field} is not a canonical ID")
        for field in ("lease_generation", "fencing_token"):
            if not isinstance(normalized[field], int) or isinstance(normalized[field], bool) or normalized[field] < 1:
                raise EventStoreError(f"{field} must be a positive integer")
        for field in ("workcard_digest", "context_digest"):
            if not isinstance(normalized[field], str) or not _DIGEST.fullmatch(normalized[field]):
                raise EventStoreError(f"{field} is not a SHA-256 digest")
    parse_timestamp(normalized["issued_at"])
    if digest_value(command_intent_identity(normalized)) != normalized["intent_digest"]:
        raise EventStoreError("command intent digest mismatch")
    return normalized


def _contains_null(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, dict):
        return any(_contains_null(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_null(item) for item in value)
    return False


def _reject_reserved_secret_fields(
    value: Any,
    *,
    surface: str,
    error_type: type[EventStoreError] = EventStoreError,
) -> None:
    """Keep operational key material out of all persisted event surfaces."""

    pending: list[Any] = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, Mapping):
            for key, item in current.items():
                normalized_key = (
                    re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
                    if isinstance(key, str)
                    else ""
                )
                if normalized_key in _RESERVED_SECRET_FIELDS:
                    raise error_type(
                        f"{surface} contains reserved operational key material field"
                    )
                pending.append(item)
        elif isinstance(current, (list, tuple)):
            pending.extend(current)
        elif isinstance(current, str):
            normalized_path = current.replace("\\", "/").casefold()
            if _RESERVED_SECRET_PATH_MARKER in normalized_path:
                raise error_type(f"{surface} contains a reserved operational key path")


def _invoke_validator(validator: Callable[..., Any] | None, value: dict[str, Any], *, evaluation_time: str, command: dict[str, Any] | None = None) -> None:
    if not callable(validator):
        raise EventStoreError("required runtime validator is unavailable")
    signature = inspect.signature(validator)
    accepts_kwargs = any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in signature.parameters.values())
    kwargs: dict[str, Any] = {}
    if accepts_kwargs or "evaluation_time" in signature.parameters:
        kwargs["evaluation_time"] = evaluation_time
    if command is not None and (accepts_kwargs or "command" in signature.parameters):
        kwargs["command"] = command
    outcome = validator(value, **kwargs)
    if outcome is False:
        raise EventStoreError("validator denied the record")


def _invoke_compiled_record_validator(
    validator: Callable[..., Any] | None,
    definition: str,
    value: Mapping[str, Any],
    *,
    evaluation_time: str,
    operation: str,
    error_type: type[EventStoreError] = EventStoreError,
) -> None:
    if not callable(validator):
        raise error_type(f"compiled {definition} validator is unavailable")
    try:
        outcome = validator(
            definition,
            copy.deepcopy(dict(value)),
            evaluation_time=evaluation_time,
            operation=operation,
        )
    except Exception as exc:
        if isinstance(exc, error_type):
            raise
        raise error_type(f"compiled {definition} validation failed: {exc}") from exc
    if outcome is False:
        raise error_type(f"compiled {definition} validator denied the record")


def _deep_thaw(value: Any) -> Any:
    """Convert immutable commit views into canonical JSON-compatible values."""

    if isinstance(value, Mapping):
        return {str(key): _deep_thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_deep_thaw(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_deep_thaw(item) for item in value), key=repr)
    return value


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _deep_freeze(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_deep_freeze(item) for item in value)
    if isinstance(value, set | frozenset):
        return frozenset(_deep_freeze(item) for item in value)
    return value


def _invoke_derived_state_validator(
    validator: Callable[..., Any] | None,
    name: str,
    state: Any,
    expected_binding_digest: str,
) -> None:
    if validator is None:
        raise DerivedCheckpointError(
            "derived state has no injected journal-state binding validator"
        )
    try:
        outcome = validator(
            name,
            copy.deepcopy(state),
            expected_binding_digest=expected_binding_digest,
        )
    except Exception as exc:
        if isinstance(exc, DerivedCheckpointError):
            raise
        raise DerivedCheckpointError(
            f"derived state journal binding validation failed: {exc}"
        ) from exc
    if outcome is False:
        raise DerivedCheckpointError("derived state differs from journal-owned state binding")
    if isinstance(outcome, str) and outcome != expected_binding_digest:
        raise DerivedCheckpointError("derived state binding digest is stale")


def _fsync_directory(path: Path) -> None:
    """Flush directory metadata where the host exposes that operation.

    Windows atomic replacement uses MOVEFILE_WRITE_THROUGH below; a directory
    handle flush is attempted as an additional durability barrier.
    """

    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_file = kernel32.CreateFileW
            create_file.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            create_file.restype = wintypes.HANDLE
            handle = create_file(
                _windows_native_path(path),
                0x80000000,
                0x7,
                None,
                3,
                0x02000000,
                None,
            )
            invalid = wintypes.HANDLE(-1).value
            if handle != invalid:
                try:
                    kernel32.FlushFileBuffers(handle)
                finally:
                    kernel32.CloseHandle(handle)
        except (AttributeError, OSError, ValueError):
            pass
        return
    descriptor = os.open(
        _native_os_path(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _windows_native_path(path: Path) -> str:
    absolute = str(path.absolute())
    if absolute.startswith("\\\\?\\"):
        return absolute
    if absolute.startswith("\\\\"):
        return "\\\\?\\UNC\\" + absolute[2:]
    return "\\\\?\\" + absolute


def _native_os_path(path: Path) -> str | Path:
    return _windows_native_path(path) if os.name == "nt" else path


def _path_exists(path: Path) -> bool:
    return os.path.exists(_native_os_path(path))


def _has_entries(path: Path) -> bool:
    with os.scandir(_native_os_path(path)) as entries:
        return next(entries, None) is not None


def _matching_paths(directory: Path, pattern: str) -> list[Path]:
    """Return logical child paths after native-boundary enumeration.

    Event state keeps ordinary canonical ``Path`` values for identities and
    diagnostics. On Windows, only directory enumeration needs the
    extended-length spelling; rebuilding children from names keeps that
    transport detail out of state and records.
    """

    with os.scandir(_native_os_path(directory)) as entries:
        return [
            directory / entry.name
            for entry in entries
            if fnmatch.fnmatchcase(entry.name, pattern)
        ]


def _child_paths(directory: Path) -> list[Path]:
    with os.scandir(_native_os_path(directory)) as entries:
        return [directory / entry.name for entry in entries]


def _is_directory(path: Path) -> bool:
    return os.path.isdir(_native_os_path(path))


def _is_symlink(path: Path) -> bool:
    return os.path.islink(_native_os_path(path))


def _modified_time_ns(path: Path) -> int:
    return os.stat(_native_os_path(path), follow_symlinks=False).st_mtime_ns


def _read_bytes(path: Path) -> bytes:
    with open(_native_os_path(path), "rb") as stream:
        return stream.read()


def _unlink(path: Path, *, missing_ok: bool = False) -> None:
    try:
        os.unlink(_native_os_path(path))
    except FileNotFoundError:
        if not missing_ok:
            raise


def _replace_durable(source: Path, destination: Path) -> None:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        flags = 0x1 | 0x8  # MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        move_file = kernel32.MoveFileExW
        move_file.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        move_file.restype = wintypes.BOOL
        if not move_file(
            _windows_native_path(source),
            _windows_native_path(destination),
            flags,
        ):
            error = ctypes.get_last_error()
            raise OSError(error, "MoveFileExW failed", str(destination))
    else:
        os.replace(_native_os_path(source), _native_os_path(destination))
    _fsync_directory(destination.parent)


def _write_atomic(path: Path, payload: bytes) -> None:
    os.makedirs(_native_os_path(path.parent), exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".p-", suffix=".tmp", dir=_native_os_path(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _replace_durable(temporary, path)
    finally:
        _unlink(temporary, missing_ok=True)


def _local_lock(path: Path) -> threading.Lock:
    key = os.path.normcase(str(path.absolute()))
    with _local_writer_guard:
        return _local_writer_locks.setdefault(key, threading.Lock())


class _WriterLock:
    def __init__(self, path: Path, timeout: float) -> None:
        self.path = path
        self.timeout = timeout
        self.descriptor: int | None = None
        self.local = _local_lock(path)
        self.os_locked = False

    def __enter__(self) -> "_WriterLock":
        deadline = time.monotonic() + self.timeout
        if not self.local.acquire(timeout=max(0.0, self.timeout)):
            raise EventStoreError("single-writer lock timeout")
        try:
            self.descriptor = os.open(
                _native_os_path(self.path), os.O_CREAT | os.O_RDWR, 0o600
            )
            if os.fstat(self.descriptor).st_size == 0:
                os.write(self.descriptor, b"\0")
                os.fsync(self.descriptor)
            while True:
                try:
                    self._lock_os_byte()
                    self.os_locked = True
                    break
                except OSError as exc:
                    if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                        raise
                    if time.monotonic() >= deadline:
                        raise EventStoreError("single-writer lock timeout")
                    time.sleep(0.02)
            os.lseek(self.descriptor, 0, os.SEEK_SET)
            os.ftruncate(self.descriptor, 0)
            os.write(
                self.descriptor,
                canonical_bytes(
                    {
                        "pid": os.getpid(),
                        "thread_id": threading.get_ident(),
                        "acquired_at": utc_now(),
                        "token": uuid.uuid4().hex,
                    }
                ),
            )
            os.fsync(self.descriptor)
            _fsync_directory(self.path.parent)
            return self
        except BaseException:
            if self.descriptor is not None:
                try:
                    if self.os_locked:
                        self._unlock_os_byte()
                finally:
                    os.close(self.descriptor)
                    self.descriptor = None
                    self.os_locked = False
            self.local.release()
            raise

    def _lock_os_byte(self) -> None:
        assert self.descriptor is not None
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(self.descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock_os_byte(self) -> None:
        assert self.descriptor is not None
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(self.descriptor, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(self.descriptor, fcntl.LOCK_UN)

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        try:
            if self.descriptor is not None:
                try:
                    if self.os_locked:
                        self._unlock_os_byte()
                finally:
                    self.os_locked = False
                    os.close(self.descriptor)
                    self.descriptor = None
        finally:
            self.local.release()


class VerifiedQueryLease:
    """Opaque, finite read lease with an entry/exit authority proof."""

    def __init__(self, store: "EventStore", max_operations: int) -> None:
        if (
            not isinstance(max_operations, int)
            or isinstance(max_operations, bool)
            or max_operations <= 0
        ):
            raise EventStoreError("max_operations must be a positive integer")
        self._store = store
        self._remaining = max_operations
        self._closed = False
        self._lock = _WriterLock(store.lock_path, store.lock_timeout)
        self._lock.__enter__()
        try:
            store._refresh_from_disk_locked()
            self._binding = self._binding_locked()
        except BaseException as original_error:
            self._closed = True
            try:
                self._lock.__exit__(None, None, None)
            except BaseException as cleanup_error:
                try:
                    original_error.add_note(
                        "verified query lease entry cleanup failed: "
                        f"{type(cleanup_error).__name__}: {cleanup_error}"
                    )
                except BaseException:
                    pass
            raise

    def _binding_locked(self) -> tuple[Any, ...]:
        store = self._store
        try:
            authority = store._read_canonical_object(
                store.authority_head_path,
                limits=ParseLimits(max_bytes=store.policy.max_command_bytes),
            )
        except (CanonicalError, DerivedCheckpointError, OSError) as exc:
            raise EventStoreError("verified query authority binding is unreadable") from exc
        if not isinstance(authority, Mapping):
            raise EventStoreError("verified query authority binding is malformed")
        authority_head = authority.get("head")
        if not isinstance(authority_head, Mapping):
            raise EventStoreError("verified query authority head binding is malformed")
        try:
            authority_head_items = tuple(sorted(authority_head.items()))
        except (TypeError, ValueError) as exc:
            raise EventStoreError(
                "verified query authority head binding is not orderable"
            ) from exc
        return (
            store._root_identity,
            store.active_activation_digest,
            store.implementation_closure_digest,
            tuple(sorted(store.head().items())),
            authority.get("activation_digest"),
            authority.get("implementation_closure_digest"),
            authority_head_items,
            authority.get("generation"),
            authority.get("root_digest"),
            authority.get("authority_prefix_digest"),
            authority.get("state_binding_digest"),
            authority.get("event_semantic_digest"),
            authority.get("state_binding_update_count"),
            store._semantic_digest,
        )

    @property
    def store(self) -> "EventStore":
        if self._closed:
            raise EventStoreError("verified query lease is closed")
        return self._store

    @property
    def remaining_operations(self) -> int:
        return self._remaining

    @property
    def binding(self) -> tuple[Any, ...]:
        if self._closed:
            raise EventStoreError("verified query lease is closed")
        return self._binding

    def consume_operation(self) -> None:
        if self._closed:
            raise EventStoreError("verified query lease is closed")
        if self._remaining <= 0:
            raise EventStoreError("verified query lease operation budget is exhausted")
        self._remaining -= 1

    def close(self) -> None:
        if self._closed:
            raise EventStoreError("verified query lease is closed")
        mismatch = False
        error: BaseException | None = None
        try:
            try:
                if self._binding_locked() != self._binding:
                    mismatch = True
            except BaseException as exc:
                mismatch = True
                error = exc
            try:
                self._store._refresh_from_disk_locked()
                if self._binding_locked() != self._binding:
                    mismatch = True
            except BaseException as exc:
                mismatch = True
                if error is None:
                    error = exc
        except BaseException as exc:
            mismatch = True
            if error is None:
                error = exc
        finally:
            self._closed = True
            try:
                self._lock.__exit__(None, None, None)
            except BaseException as exc:
                if error is None:
                    error = exc
        if error is not None:
            if isinstance(error, EventStoreError):
                raise error
            raise EventStoreError("verified query lease close failed") from error
        if mismatch:
            raise EventStoreError("verified query lease binding changed")

    def __enter__(self) -> "VerifiedQueryLease":
        if self._closed:
            raise EventStoreError("verified query lease is closed")
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


_VERIFIED_QUERY_PHASE_TOKEN = object()


class VerifiedCommitPhase:
    """Finite commit phase admitted by one full authority verification.

    The phase deliberately does not retain the writer lock between operations:
    service post-commit work may run between calls.  Each operation takes the
    normal lock and checks the bounded durable control-file binding before
    entering the shared commit mechanics.  A failed operation poisons the
    phase and requires an explicit close before another phase can be admitted.
    """

    def __init__(self, store: "EventStore", max_operations: int) -> None:
        if (
            not isinstance(max_operations, int)
            or isinstance(max_operations, bool)
            or max_operations <= 0
        ):
            raise EventStoreError("max_operations must be a positive integer")
        self._store = store
        self._remaining = max_operations
        self._closed = False
        self._poison: BaseException | None = None
        self._binding: tuple[Any, ...]
        with _WriterLock(store.lock_path, store.lock_timeout):
            if store._verified_commit_phase_active:
                raise EventStoreError("verified commit phase is already active")
            store._refresh_from_disk_locked()
            self._binding = store._verified_commit_binding_locked()
            store._verified_commit_phase_active = True

    @property
    def remaining_operations(self) -> int:
        return self._remaining

    @property
    def head(self) -> dict[str, Any]:
        if self._closed:
            raise EventStoreError("verified commit phase is closed")
        return self._store.head()

    def _ensure_open(self) -> None:
        if self._closed:
            raise EventStoreError("verified commit phase is closed")
        if self._poison is not None:
            raise EventStoreError("verified commit phase is poisoned") from self._poison
        if self._remaining <= 0:
            raise EventStoreError("verified commit phase operation budget is exhausted")

    def commit(
        self,
        command: Mapping[str, Any],
        *,
        auxiliary_relations: Iterable[Mapping[str, Any]] = (),
        created_at: str | None = None,
        crash_hook: Callable[[str], Any] | None = None,
    ) -> dict[str, Any]:
        self._ensure_open()
        store = self._store
        try:
            with _WriterLock(store.lock_path, store.lock_timeout):
                if store._verified_commit_binding_locked() != self._binding:
                    raise EventStoreError("verified commit phase binding changed")
                if store._verified_commit_phase_in_progress:
                    raise EventStoreError("verified commit phase operation is already active")
                store._verified_commit_phase_token = self
                store._verified_commit_phase_in_progress = True
                try:
                    result = store.commit(
                        command,
                        auxiliary_relations=auxiliary_relations,
                        created_at=created_at,
                        crash_hook=crash_hook,
                    )
                finally:
                    store._verified_commit_phase_in_progress = False
                    store._verified_commit_phase_token = None
                self._binding = store._verified_commit_binding_locked()
                self._remaining -= 1
                return result
        except BaseException as exc:
            self._poison = exc
            raise

    def close(self) -> None:
        if self._closed:
            raise EventStoreError("verified commit phase is closed")
        error: BaseException | None = self._poison
        mismatch = False
        try:
            with _WriterLock(self._store.lock_path, self._store.lock_timeout):
                try:
                    if self._store._verified_commit_binding_locked() != self._binding:
                        mismatch = True
                except BaseException as exc:
                    mismatch = True
                    if error is None:
                        error = exc
                try:
                    self._store._strict_refresh_from_disk_locked()
                    if self._store._verified_commit_binding_locked() != self._binding:
                        mismatch = True
                except BaseException as exc:
                    if error is None:
                        error = exc
        except BaseException as exc:
            if error is None:
                error = exc
        finally:
            self._closed = True
            self._store._verified_commit_phase_active = False
            self._store._verified_commit_phase_token = None
            self._store._verified_commit_phase_in_progress = False
        if error is not None:
            if isinstance(error, EventStoreError):
                raise error
            raise EventStoreError("verified commit phase close failed") from error
        if mismatch:
            raise EventStoreError("verified commit phase binding changed")

    def __enter__(self) -> "VerifiedCommitPhase":
        self._ensure_open()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


class EventStore:
    """Single-writer, crash-recoverable authoritative event journal."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        active_activation_digest: str,
        *,
        activation_record_digest: str,
        implementation_closure_digest: str,
        policy: EventStorePolicy,
        compiled_record_validator: Callable[..., Any],
        command_validator: Callable[..., Any],
        authorization_validator: Callable[..., Any],
        event_validator: Callable[..., Any],
        commit_state_loader: Callable[[CommitReadView, Callable[[], Iterator[dict[str, Any]]]], Any] | None = None,
        commit_prepare_callback: Callable[..., PreparedCommit] | None = None,
        derived_state_validator: Callable[..., Any] | None = None,
        max_events_per_batch: int | None = None,
        lock_timeout: float = 10.0,
        _phase_token: object | None = None,
    ) -> None:
        if not _DIGEST.fullmatch(active_activation_digest):
            raise EventStoreError("active activation digest must be SHA-256")
        if not isinstance(activation_record_digest, str) or not _DIGEST.fullmatch(
            activation_record_digest
        ):
            raise EventStoreError("installed Activation record digest must be SHA-256")
        if not isinstance(implementation_closure_digest, str) or not _DIGEST.fullmatch(
            implementation_closure_digest
        ):
            raise EventStoreError("implementation closure digest must be SHA-256")
        if not isinstance(policy, EventStorePolicy):
            raise EventStoreError("event store policy must be EventStorePolicy")
        if not callable(compiled_record_validator):
            raise EventStoreError("compiled record validator is required")
        for validator, label in (
            (command_validator, "command"),
            (authorization_validator, "authorization"),
            (event_validator, "event"),
        ):
            if not callable(validator):
                raise EventStoreError(f"{label} validator is required")
        _invoke_compiled_record_validator(
            compiled_record_validator,
            "EventStorePolicy",
            policy.as_compiled(),
            evaluation_time=utc_now(),
            operation="read",
        )
        resolved_batch_ceiling = (
            policy.max_events_per_batch
            if max_events_per_batch is None
            else max_events_per_batch
        )
        if (
            not isinstance(resolved_batch_ceiling, int)
            or isinstance(resolved_batch_ceiling, bool)
            or not 1 <= resolved_batch_ceiling <= policy.max_events_per_batch
        ):
            raise EventStoreError(
                "event batch ceiling must be positive and within the injected Core policy"
            )
        if (
            not isinstance(lock_timeout, (int, float))
            or isinstance(lock_timeout, bool)
            or not math.isfinite(lock_timeout)
            or lock_timeout <= 0
        ):
            raise EventStoreError("lock_timeout must be a finite positive number")
        self.root = Path(root)
        self._root_identity = str(self.root.absolute())
        self.journal = self.root / "journal"
        self.pending = self.root / "pending"
        self.head_path = self.root / "HEAD.json"
        self.checkpoint_path = self.root / "journal-checkpoint.json"
        self.authority_root = self.root / "journal-authority"
        self.authority_head_path = self.root / "journal-authority-root.json"
        self.implementation_binding_path = self.root / "implementation-closure.json"
        self.index_root = self.root / "derived-index"
        self.derived_state_root = self.root / "derived-state"
        self.derived_rows_root = self.root / "derived-rows"
        self.lock_path = self.root / "writer.lock"
        self.active_activation_digest = active_activation_digest
        self.activation_record_digest = activation_record_digest
        self.implementation_closure_digest = implementation_closure_digest
        self.command_validator = command_validator
        self.authorization_validator = authorization_validator
        self.event_validator = event_validator
        self.compiled_record_validator = compiled_record_validator
        self.commit_state_loader = commit_state_loader
        self.commit_prepare_callback = commit_prepare_callback
        self.derived_state_validator = derived_state_validator
        self.policy = policy
        self.max_events_per_batch = resolved_batch_ceiling
        self.lock_timeout = lock_timeout
        self._head = self._empty_head()
        self._committed_envelope_witness: _CommittedEnvelopeWitness | None = None
        self._command_ids: dict[str, tuple[str, dict[str, Any]]] = {}
        self._idempotency: dict[tuple[str, str, str], tuple[str, dict[str, Any]]] = {}
        self._batch_ids: set[str] = set()
        self._event_ids: set[str] = set()
        self._index_generation: str | None = None
        self._batch_count = 0
        self._event_count = 0
        self._semantic_digest = self.policy.genesis_event_semantic_digest
        self._authority_generation: str | None = None
        self._authority_prefix_digest = (
            self.policy.genesis_previous_authority_commitment
        )
        (
            self._genesis_state_binding_digest,
            self._genesis_state_binding_nodes,
        ) = _single_state_leaf_tree(
            leaf_type="Activation",
            leaf_id=self.active_activation_digest,
            value_digest=self.activation_record_digest,
        )
        self._state_binding_digest: str | None = self._genesis_state_binding_digest
        self._state_binding_update_count = 0
        self._open_mode = "unopened"
        self._fallback_reason: str | None = None
        self._derived_state_issues: dict[str, str | None] = {}
        self._derived_rows_issues: dict[str, str | None] = {}
        self._last_commit_write_metrics = self._empty_commit_write_metrics()
        self._verified_commit_phase_active = False
        self._verified_commit_phase_token: VerifiedCommitPhase | None = None
        self._verified_commit_phase_in_progress = False
        os.makedirs(_native_os_path(self.root), exist_ok=True)
        os.makedirs(_native_os_path(self.journal), exist_ok=True)
        os.makedirs(_native_os_path(self.pending), exist_ok=True)
        os.makedirs(_native_os_path(self.authority_root), exist_ok=True)
        os.makedirs(_native_os_path(self.index_root), exist_ok=True)
        os.makedirs(_native_os_path(self.derived_state_root), exist_ok=True)
        os.makedirs(_native_os_path(self.derived_rows_root), exist_ok=True)
        self._verify_or_create_implementation_binding()
        if _phase_token is not _VERIFIED_QUERY_PHASE_TOKEN:
            self._open_or_recover()

    @classmethod
    def _for_verified_query_phase(cls, *args: Any, **kwargs: Any) -> "EventStore":
        kwargs["_phase_token"] = _VERIFIED_QUERY_PHASE_TOKEN
        return cls(*args, **kwargs)

    def begin_verified_query_lease(self, max_operations: int) -> VerifiedQueryLease:
        """Open one finite authority-verified read phase under the writer lock."""

        return VerifiedQueryLease(self, max_operations)

    def begin_verified_commit_phase(self, max_operations: int) -> VerifiedCommitPhase:
        """Open a finite authority-verified commit phase."""

        return VerifiedCommitPhase(self, max_operations)

    def _verified_commit_binding_locked(self) -> tuple[Any, ...]:
        """Read the bounded durable binding used between phase operations."""

        try:
            disk_head = self._read_disk_head()
            tail_digest = None
            if disk_head["sequence"] > 0:
                tail_path = self._journal_path_for_sequence(disk_head["sequence"])
                tail_payload = _read_bytes(tail_path)
                if len(tail_payload) > self.policy.max_envelope_bytes:
                    raise EventStoreError("verified commit phase tail binding exceeds its limit")
                tail_digest = hashlib.sha256(tail_payload).hexdigest()
            authority = self._read_canonical_object(
                self.authority_head_path,
                limits=ParseLimits(max_bytes=self.policy.max_command_bytes),
            )
        except (CanonicalError, DerivedCheckpointError, JournalCorruption, OSError) as exc:
            raise EventStoreError("verified commit phase binding is unreadable") from exc
        if not isinstance(authority, Mapping):
            raise EventStoreError("verified commit phase binding is malformed")
        required = {
            "record_type", "version", "authoritative", "activation_digest",
            "implementation_closure_digest", "generation", "head", "segment_count",
            "event_count", "event_semantic_digest", "authority_prefix_digest",
            "state_binding_update_count", "state_binding_digest", "root_digest",
        }
        if set(authority) != required or authority.get("record_type") != "JournalPrefixRoot":
            raise EventStoreError("verified commit phase binding is malformed")
        supplied_root_digest = authority.get("root_digest")
        unsigned = dict(authority)
        unsigned.pop("root_digest", None)
        if (
            not isinstance(supplied_root_digest, str)
            or not _DIGEST.fullmatch(supplied_root_digest)
            or digest_value(unsigned) != supplied_root_digest
        ):
            raise EventStoreError("verified commit phase binding digest is invalid")
        try:
            authority_head = self._validate_head_value(dict(authority["head"]))
        except (DerivedCheckpointError, TypeError, ValueError) as exc:
            raise EventStoreError("verified commit phase head binding is malformed") from exc
        if (
            authority["version"] != 1
            or authority["authoritative"] is not False
            or authority["activation_digest"] != self.active_activation_digest
            or authority["implementation_closure_digest"] != self.implementation_closure_digest
            or authority_head != disk_head
            or authority["segment_count"] != disk_head["sequence"]
        ):
            raise EventStoreError("verified commit phase binding changed")
        return (
            self._root_identity,
            self.active_activation_digest,
            self.implementation_closure_digest,
            tuple(sorted(disk_head.items())),
            tail_digest,
            authority["generation"],
            authority["root_digest"],
            authority["authority_prefix_digest"],
            authority["state_binding_digest"],
            authority["event_semantic_digest"],
            authority["event_count"],
            authority["state_binding_update_count"],
        )

    @staticmethod
    def _empty_head() -> dict[str, Any]:
        return {"sequence": 0, "batch_id": None, "batch_digest": None}

    def head(self) -> dict[str, Any]:
        """O(1) lookup of the last durably committed batch identity."""

        return copy.deepcopy(self._head)

    def _clear_committed_envelope_witness(self) -> None:
        """Discard the one-use post-commit continuation, if any."""

        self._committed_envelope_witness = None

    def _record_committed_envelope_witness(
        self,
        *,
        envelope: Mapping[str, Any],
        payload: bytes,
        journal_path: Path,
        head: Mapping[str, Any],
        authority_root: Mapping[str, Any],
    ) -> None:
        """Record one exact durable envelope without making it authority.

        A failed witness construction must never turn a completed journal
        append into a failed command result.  The regular read route remains
        available and will fully verify the prefix.
        """

        self._clear_committed_envelope_witness()
        index_generation = self._index_generation
        authority_generation = self._authority_generation
        checked_head = self._validate_head_value(dict(head))
        authority_root_digest = authority_root.get("root_digest")
        if (
            index_generation is None
            or authority_generation is None
            or not isinstance(authority_root_digest, str)
            or not _DIGEST.fullmatch(authority_root_digest)
            or authority_root.get("generation") != authority_generation
            or checked_head["sequence"] < 1
            or not isinstance(checked_head["batch_id"], str)
            or not isinstance(checked_head["batch_digest"], str)
            or journal_path.parent != self.journal
            or Path(journal_path.name).name != journal_path.name
        ):
            return
        expected_file_id = hashlib.sha256(
            checked_head["batch_id"].encode("utf-8")
        ).hexdigest()
        expected_name = f"{checked_head['sequence']:020d}-{expected_file_id}.json"
        if journal_path.name != expected_name:
            return
        expected_payload_digest = hashlib.sha256(payload).hexdigest()
        try:
            canonical_envelope = canonical_bytes(
                dict(envelope),
                limits=ParseLimits(max_bytes=self.policy.max_envelope_bytes),
            )
            command = envelope.get("command")
            if not isinstance(command, Mapping):
                return
            command_payload = canonical_bytes(
                dict(command),
                limits=ParseLimits(max_bytes=self.policy.max_command_bytes),
            )
        except (CanonicalError, TypeError, ValueError):
            return
        if canonical_envelope != payload:
            return
        command_payload_digest = hashlib.sha256(command_payload).hexdigest()
        bindings = {
            "record_type": "CommittedEnvelopeWitness",
            "version": 1,
            "root_identity": self._root_identity,
            "activation_digest": self.active_activation_digest,
            "implementation_closure_digest": self.implementation_closure_digest,
            "index_generation": index_generation,
            "authority_generation": authority_generation,
            "authority_root_digest": authority_root_digest,
            "head": checked_head,
            "journal_file": journal_path.name,
            "journal_payload_digest": expected_payload_digest,
            "command_payload_digest": command_payload_digest,
        }
        self._committed_envelope_witness = _CommittedEnvelopeWitness(
            root_identity=self._root_identity,
            activation_digest=self.active_activation_digest,
            implementation_closure_digest=self.implementation_closure_digest,
            index_generation=index_generation,
            authority_generation=authority_generation,
            authority_root_digest=authority_root_digest,
            head=checked_head,
            journal_file=journal_path.name,
            journal_payload=payload,
            journal_payload_digest=expected_payload_digest,
            command_payload=command_payload,
            command_payload_digest=command_payload_digest,
            binding_digest=digest_value(bindings),
        )

    def _witness_authority_root_matches_locked(
        self, witness: _CommittedEnvelopeWitness
    ) -> bool:
        try:
            value = self._read_canonical_object(
                self.authority_head_path,
                limits=ParseLimits(max_bytes=self.policy.max_command_bytes),
            )
        except (CanonicalError, DerivedCheckpointError, OSError):
            return False
        required = {
            "record_type", "version", "authoritative", "activation_digest",
            "implementation_closure_digest", "generation", "head", "segment_count",
            "event_count", "event_semantic_digest", "authority_prefix_digest",
            "state_binding_update_count", "state_binding_digest", "root_digest",
        }
        if set(value) != required:
            return False
        supplied_digest = value.pop("root_digest")
        if (
            not isinstance(supplied_digest, str)
            or not _DIGEST.fullmatch(supplied_digest)
            or digest_value(value) != supplied_digest
        ):
            return False
        return (
            value.get("record_type") == "JournalPrefixRoot"
            and value.get("version") == 1
            and value.get("authoritative") is False
            and value.get("activation_digest") == witness.activation_digest
            and value.get("implementation_closure_digest")
            == witness.implementation_closure_digest
            and value.get("generation") == witness.authority_generation
            and value.get("head") == witness.head
            and value.get("segment_count") == witness.head["sequence"]
            and supplied_digest == witness.authority_root_digest
        )

    def _witness_checkpoint_matches_locked(
        self, witness: _CommittedEnvelopeWitness
    ) -> bool:
        try:
            value = self._read_canonical_object(
                self.checkpoint_path,
                limits=ParseLimits(max_bytes=self.policy.max_command_bytes),
            )
        except (CanonicalError, DerivedCheckpointError, OSError):
            return False
        required = {
            "record_type", "version", "authoritative", "activation_digest", "head",
            "batch_count", "event_count", "semantic_digest", "index_generation",
            "last_journal_file", "last_journal_file_digest", "implementation_closure_digest",
            "authority_generation", "authority_prefix_digest", "authority_root_digest",
            "state_binding_update_count", "state_binding_digest", "checkpoint_digest",
        }
        if set(value) != required:
            return False
        supplied_digest = value.pop("checkpoint_digest")
        if (
            not isinstance(supplied_digest, str)
            or not _DIGEST.fullmatch(supplied_digest)
            or digest_value(value) != supplied_digest
        ):
            return False
        return (
            value.get("record_type") == "DerivedJournalCheckpoint"
            and value.get("version") == 3
            and value.get("authoritative") is False
            and value.get("activation_digest") == witness.activation_digest
            and value.get("implementation_closure_digest")
            == witness.implementation_closure_digest
            and value.get("head") == witness.head
            and value.get("batch_count") == witness.head["sequence"]
            and value.get("index_generation") == witness.index_generation
            and value.get("authority_generation") == witness.authority_generation
            and value.get("authority_root_digest") == witness.authority_root_digest
            and value.get("last_journal_file") == witness.journal_file
            and value.get("last_journal_file_digest")
            == witness.journal_payload_digest
        )

    def _consume_committed_envelope_witness_locked(
        self,
        batch_digest: str,
        command_payload: bytes,
    ) -> dict[str, Any] | None:
        """Return the sole post-commit continuation or require a normal refresh.

        This crosses exactly one writer-lock release.  It checks the current
        HEAD, journal tail, authority root, and checkpoint by bytes, then is
        consumed.  Older-prefix changes remain the responsibility of the next
        regular authority refresh, which this opaque own-envelope continuation
        never replaces.  In particular, it is not a general proof of the
        older prefix after the writer lock has been released.
        """

        witness = self._committed_envelope_witness
        self._clear_committed_envelope_witness()
        if (
            witness is None
            or batch_digest != witness.head["batch_digest"]
            or command_payload != witness.command_payload
            or hashlib.sha256(command_payload).hexdigest()
            != witness.command_payload_digest
        ):
            return None
        if (
            witness.root_identity != self._root_identity
            or witness.activation_digest != self.active_activation_digest
            or witness.implementation_closure_digest
            != self.implementation_closure_digest
            or witness.index_generation != self._index_generation
            or witness.authority_generation != self._authority_generation
            or witness.head != self._head
            or digest_value(witness.bindings()) != witness.binding_digest
        ):
            return None
        try:
            if self._read_disk_head() != witness.head:
                return None
            if not self._witness_authority_root_matches_locked(witness):
                return None
            if not self._witness_checkpoint_matches_locked(witness):
                return None
            expected_file_id = hashlib.sha256(
                witness.head["batch_id"].encode("utf-8")
            ).hexdigest()
            expected_name = (
                f"{witness.head['sequence']:020d}-{expected_file_id}.json"
            )
            if witness.journal_file != expected_name:
                return None
            raw = _read_bytes(self.journal / witness.journal_file)
            if (
                raw != witness.journal_payload
                or hashlib.sha256(raw).hexdigest()
                != witness.journal_payload_digest
            ):
                return None
            limits = ParseLimits(max_bytes=self.policy.max_envelope_bytes)
            envelope = parse_json_strict(raw, limits=limits)
            if canonical_bytes(envelope, limits=limits) != raw or not isinstance(
                envelope, dict
            ):
                return None
            _reject_reserved_secret_fields(
                envelope,
                surface="journal envelope",
                error_type=JournalCorruption,
            )
            batch = envelope.get("batch")
            if not isinstance(batch, dict):
                return None
            actual = self._validate_envelope(
                envelope,
                expected_sequence=witness.head["sequence"],
                expected_previous_digest=batch.get("previous_digest"),
                validate_runtime=False,
            )
            if actual != batch_digest:
                return None
            return copy.deepcopy(envelope)
        except (CanonicalError, EventStoreError, OSError, TypeError, ValueError):
            return None

    def _consume_non_authoritative_same_commit_receipt(
        self,
        command: Mapping[str, Any],
        batch_digest: str,
    ) -> dict[str, Any] | None:
        """Return one opaque same-commit receipt, never a public authority read.

        This internal continuation exists solely so the command service can
        bind its immediate result assembly to the exact bytes it has just
        committed.  It intentionally cannot establish integrity of older
        journal bytes after the lock release.  Callers that need authority,
        evidence promotion, cache/idempotency, or authorization must use the
        public ``read_envelope``/refresh route instead.
        """

        if (
            not isinstance(command, Mapping)
            or not isinstance(batch_digest, str)
            or not _DIGEST.fullmatch(batch_digest)
        ):
            return None
        try:
            command_payload = canonical_bytes(
                dict(command),
                limits=ParseLimits(max_bytes=self.policy.max_command_bytes),
            )
        except (CanonicalError, TypeError, ValueError):
            return None
        with _WriterLock(self.lock_path, self.lock_timeout):
            return self._consume_committed_envelope_witness_locked(
                batch_digest,
                command_payload,
            )

    def refresh(self) -> dict[str, Any]:
        """Refresh cached derived state from the authoritative HEAD under the writer lock."""

        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            return self.head()

    def checkpoint_status(self) -> dict[str, Any]:
        """Report the actual derived-open route without granting authority."""

        return {
            "record_type": "EventCheckpointStatus",
            "open_mode": self._open_mode,
            "fallback_reason": self._fallback_reason,
            "authoritative": False,
            "activation_digest": self.active_activation_digest,
            "implementation_closure_digest": self.implementation_closure_digest,
            "head": self.head(),
            "batch_count": self._batch_count,
            "event_count": self._event_count,
            "semantic_digest": self._semantic_digest,
            "authority_prefix_digest": self._authority_prefix_digest,
            "state_binding_available": self._state_binding_digest is not None,
            "state_binding_update_count": self._state_binding_update_count,
        }

    @staticmethod
    def _empty_commit_write_metrics() -> dict[str, int]:
        return {
            "changed_records": 0,
            "journal_authority_bytes": 0,
            "temporary_staging_bytes": 0,
            "head_bytes": 0,
            "derived_index_bytes": 0,
            "journal_checkpoint_bytes": 0,
            "state_binding_index_bytes": 0,
            "state_binding_updates": 0,
            "state_binding_node_writes": 0,
            "journal_checkpoint_writes": 0,
            "logical_final_bytes": 0,
            "physical_payload_bytes": 0,
        }

    def last_commit_write_metrics(self) -> dict[str, int]:
        """Return measured canonical payload bytes for the most recent commit call."""

        return copy.deepcopy(self._last_commit_write_metrics)

    def _has_existing_event_state(self) -> bool:
        return any(
            (
                _path_exists(self.head_path),
                _path_exists(self.checkpoint_path),
                _path_exists(self.authority_head_path),
                _has_entries(self.journal),
                _has_entries(self.authority_root),
                _has_entries(self.pending),
                _has_entries(self.index_root),
                _has_entries(self.derived_state_root),
                _has_entries(self.derived_rows_root),
            )
        )

    def _implementation_binding_value(self) -> dict[str, Any]:
        value = {
            "record_type": "ImplementationClosureBinding",
            "version": 1,
            "authoritative": False,
            "activation_digest": self.active_activation_digest,
            "activation_record_digest": self.activation_record_digest,
            "implementation_closure_digest": self.implementation_closure_digest,
        }
        value["binding_digest"] = digest_value(value)
        return value

    def _verify_or_create_implementation_binding(self) -> None:
        """Bind operational state without adding an Event authority surface."""

        if _path_exists(self.implementation_binding_path):
            self._verify_implementation_binding()
            return
        with _WriterLock(self.lock_path, self.lock_timeout):
            if not _path_exists(self.implementation_binding_path):
                if self._has_existing_event_state():
                    raise ImplementationClosureMismatch(
                        "implementation closure binding is missing for existing event state"
                    )
                _write_atomic(
                    self.implementation_binding_path,
                    canonical_bytes(self._implementation_binding_value()),
                )
                return
        self._verify_implementation_binding()

    def _verify_implementation_binding(self) -> None:
        try:
            value = self._read_canonical_object(
                self.implementation_binding_path,
                limits=ParseLimits(max_bytes=self.policy.max_command_bytes),
            )
        except (CanonicalError, DerivedCheckpointError, OSError) as exc:
            raise ImplementationClosureMismatch(
                "implementation closure binding is unreadable"
            ) from exc
        required = {
            "record_type",
            "version",
            "authoritative",
            "activation_digest",
            "activation_record_digest",
            "implementation_closure_digest",
            "binding_digest",
        }
        if (
            set(value) != required
            or value.get("record_type") != "ImplementationClosureBinding"
            or value.get("version") != 1
            or value.get("authoritative") is not False
        ):
            raise ImplementationClosureMismatch(
                "implementation closure binding fields mismatch"
            )
        supplied_digest = value.pop("binding_digest")
        if (
            not isinstance(supplied_digest, str)
            or not _DIGEST.fullmatch(supplied_digest)
            or digest_value(value) != supplied_digest
        ):
            raise ImplementationClosureMismatch(
                "implementation closure binding digest mismatch"
            )
        if value["activation_digest"] != self.active_activation_digest:
            raise ImplementationClosureMismatch(
                "implementation closure binding Activation mismatch"
            )
        if value["activation_record_digest"] != self.activation_record_digest:
            raise ImplementationClosureMismatch(
                "event state installed Activation record mismatch"
            )
        if (
            value["implementation_closure_digest"]
            != self.implementation_closure_digest
        ):
            raise ImplementationClosureMismatch(
                "event state implementation closure mismatch"
            )

    def _open_or_recover(self) -> None:
        self._clear_committed_envelope_witness()
        with _WriterLock(self.lock_path, self.lock_timeout):
            # A durable pending record means this open must replay/reconcile
            # the journal rather than first fully load a checkpoint that is
            # known to reject the same pending record.  Pending is never
            # trusted here; it merely selects the stricter recovery path.
            if _matching_paths(self.pending, "*.json"):
                self._fallback_reason = (
                    "DerivedCheckpointError: pending transaction requires recovery"
                )
                self._recover_locked()
                self._open_mode = "full-replay-fallback"
                return
            try:
                self._load_journal_checkpoint_locked()
            except (CanonicalError, DerivedCheckpointError, JournalCorruption, OSError) as exc:
                self._fallback_reason = f"{type(exc).__name__}: {exc}"
                self._recover_locked()
                self._open_mode = "full-replay-fallback"
            else:
                self._fallback_reason = None
                self._open_mode = "verified-checkpoint"

    def recover(self) -> dict[str, Any]:
        """Validate the full chain, repair HEAD, and remove resolved pending data."""

        with _WriterLock(self.lock_path, self.lock_timeout):
            result = self._recover_locked()
            self._open_mode = "full-replay-explicit"
            self._fallback_reason = None
            return result

    def close(self) -> None:
        """Release the transient same-commit continuation explicitly."""

        self._clear_committed_envelope_witness()

    def _recover_locked(self) -> dict[str, Any]:
        self._clear_committed_envelope_witness()
        head = self._empty_head()
        durable_head_present = _path_exists(self.head_path)
        durable_head = (
            self._read_disk_head()
            if durable_head_present
            else self._empty_head()
        )
        durable_prefix_head = self._empty_head()
        forward_journal_suffix: list[tuple[Path, dict[str, Any], str]] = []
        command_ids: dict[str, tuple[str, dict[str, Any]]] = {}
        idempotency: dict[tuple[str, str, str], tuple[str, dict[str, Any]]] = {}
        batch_ids: set[str] = set()
        event_ids: set[str] = set()
        event_count = 0
        state_binding_update_count = 0
        state_binding_digest: str | None = self._genesis_state_binding_digest
        semantic_digest = self.policy.genesis_event_semantic_digest
        index_generation = uuid.uuid4().hex
        authority_generation = uuid.uuid4().hex
        generation_root = self.index_root / index_generation
        os.makedirs(
            _native_os_path(self._authority_generation_root(authority_generation)),
            exist_ok=True,
        )
        for kind in (
            "command",
            "idempotency",
            "batch",
            "batch-digest",
            "packages",
        ):
            os.makedirs(_native_os_path(generation_root / kind), exist_ok=True)
        self._initialize_event_identity_index(index_generation)
        self._initialize_state_binding_index(index_generation)
        expected_sequence = 1
        previous_digest: str | None = None
        previous_authority_commitment = (
            self.policy.genesis_previous_authority_commitment
        )
        journal_paths = sorted(_matching_paths(self.journal, "*.json"))
        for path in journal_paths:
            envelope = self._read_envelope(path)
            batch_digest = self._validate_envelope(
                envelope,
                expected_sequence=expected_sequence,
                expected_previous_digest=previous_digest,
                validate_runtime=True,
                validation_operation="rebuild",
            )
            batch = envelope["batch"]
            replayed_head = {
                "sequence": batch["sequence"],
                "batch_id": batch["batch_id"],
                "batch_digest": batch_digest,
            }
            if batch["sequence"] == durable_head["sequence"]:
                durable_prefix_head = copy.deepcopy(replayed_head)
            elif batch["sequence"] > durable_head["sequence"]:
                forward_journal_suffix.append((path, envelope, batch_digest))
                if len(forward_journal_suffix) > 1:
                    raise JournalCorruption(
                        "journal contains more than one uncommitted suffix batch"
                    )
            command = envelope["command"]
            if batch["batch_id"] in batch_ids:
                raise JournalCorruption("duplicate batch_id")
            batch_ids.add(batch["batch_id"])
            command_digest = _commit_effect_digest(
                command,
                [event["payload"] for event in batch["events"] if event["event_kind"] == "relation.recorded"],
            )
            existing_command = command_ids.get(command["command_id"])
            if existing_command is not None:
                raise JournalCorruption("duplicate command_id")
            result = self._result(command, batch_digest, "committed", batch)
            command_ids[command["command_id"]] = (command_digest, result)
            id_key = (command["activation_digest"], command["subject_id"], command["idempotency_key"])
            if id_key in idempotency:
                raise JournalCorruption("duplicate idempotency identity")
            idempotency[id_key] = (command_digest, result)
            for event in batch["events"]:
                if event["event_id"] in event_ids:
                    raise JournalCorruption("duplicate event_id")
                event_ids.add(event["event_id"])
                semantic_digest = _extend_event_semantic_digest(semantic_digest, event)
                event_count += 1
            delta = tuple(batch["state_binding_delta"])
            computed_state_root, state_overlay = self._stage_compact_state_binding_delta(
                index_generation,
                delta,
                prior_sequence=batch["sequence"] - 1,
                prior_root_digest=state_binding_digest,
                prior_update_count=state_binding_update_count,
            )
            state_binding_update_count += len(delta)
            if (
                batch["state_binding_digest"] != computed_state_root
                or batch["cumulative_state_binding_update_count"]
                != state_binding_update_count
            ):
                raise JournalCorruption("journal state binding root mismatch")
            expected_authority_commitment = _authority_commitment(
                previous_commitment=previous_authority_commitment,
                sequence=batch["sequence"],
                previous_batch_digest=previous_digest,
                event_count=event_count,
                event_semantic_digest=semantic_digest,
                state_binding_update_count=state_binding_update_count,
                state_binding_digest=batch["state_binding_digest"],
            )
            if (
                batch["previous_authority_commitment"]
                != previous_authority_commitment
                or batch["authority_commitment"] != expected_authority_commitment
                or batch["cumulative_event_count"] != event_count
                or batch["event_semantic_digest"] != semantic_digest
            ):
                raise JournalCorruption("journal-owned prefix commitment mismatch")
            self._publish_compact_state_binding_delta(
                index_generation,
                sequence=batch["sequence"],
                prior_root_digest=state_binding_digest,
                prior_update_count=state_binding_update_count - len(delta),
                root_digest=computed_state_root,
                delta_count=len(delta),
                overlay=state_overlay,
            )
            state_binding_digest = computed_state_root
            self._write_authority_segment(
                generation=authority_generation,
                envelope=envelope,
                journal_path=path,
                journal_payload=_read_bytes(path),
            )
            self._write_envelope_index_entries(
                envelope,
                path,
                batch_digest,
                command_digest,
                result,
                index_generation,
                prior_event_count=event_count - len(batch["events"]),
            )
            head = replayed_head
            previous_digest = batch_digest
            previous_authority_commitment = expected_authority_commitment
            expected_sequence += 1
        self._validate_recovery_head_locked(
            durable_head=durable_head,
            durable_head_present=durable_head_present,
            durable_prefix_head=durable_prefix_head,
            replayed_head=head,
            forward_journal_suffix=forward_journal_suffix,
        )
        if durable_head != head:
            _write_atomic(self.head_path, canonical_bytes(head))
        committed_batch_ids = batch_ids
        for path in _matching_paths(self.pending, "*.json"):
            try:
                pending = self._read_envelope(path)
                if pending.get("batch", {}).get("batch_id") in committed_batch_ids:
                    _unlink(path, missing_ok=True)
                else:
                    # A pending-only transaction never became authoritative.
                    _unlink(path, missing_ok=True)
            except JournalCorruption:
                _unlink(path, missing_ok=True)
        _fsync_directory(self.pending)
        self._head = head
        self._command_ids = command_ids
        self._idempotency = idempotency
        self._batch_ids = batch_ids
        self._event_ids = event_ids
        self._index_generation = index_generation
        self._batch_count = head["sequence"]
        self._event_count = event_count
        self._semantic_digest = semantic_digest
        self._authority_generation = authority_generation
        self._authority_prefix_digest = (
            self.policy.genesis_previous_authority_commitment
            if not journal_paths
            else self._read_envelope(journal_paths[-1])["batch"]["authority_commitment"]
        )
        self._state_binding_digest = (
            self._genesis_state_binding_digest
            if not journal_paths
            else self._read_envelope(journal_paths[-1])["batch"]["state_binding_digest"]
        )
        self._state_binding_update_count = state_binding_update_count
        last_path = journal_paths[-1] if journal_paths else None
        authority_root = self._write_authority_root(
            generation=authority_generation,
            head=head,
            event_count=event_count,
            event_semantic_digest=semantic_digest,
            authority_prefix_digest=self._authority_prefix_digest,
            state_binding_digest=self._state_binding_digest,
            state_binding_update_count=state_binding_update_count,
        )
        journal_checkpoint = self._write_journal_checkpoint(
            head=head,
            batch_count=head["sequence"],
            event_count=event_count,
            semantic_digest=semantic_digest,
            index_generation=index_generation,
            last_journal_file=last_path.name if last_path is not None else None,
            last_journal_file_digest=(
                hashlib.sha256(_read_bytes(last_path)).hexdigest()
                if last_path is not None
                else None
            ),
            authority_root=authority_root,
            state_binding_update_count=state_binding_update_count,
        )
        # Recovery generations are disposable projections.  This sweep also
        # removes a partial generation left by an earlier failed replay before
        # checkpoint fallback retried.  Only the completed generation named by
        # the freshly written control records is retained; authoritative
        # history remains in ``journal/``.
        self._prune_recovery_generations(
            active_index_generation=index_generation,
            active_authority_generation=authority_generation,
        )
        return self.head()

    def _pending_proves_forward_journal_suffix_locked(
        self,
        durable_head: Mapping[str, Any],
        suffix: list[tuple[Path, dict[str, Any], str]],
    ) -> None:
        """Permit only the one crash-recoverable append staged in ``pending``.

        ``pending`` is deliberately not a second authority source.  It may
        advance an already validated durable HEAD only when it is the exact
        same canonical payload as the next linked journal batch.  The normal
        single-writer protocol has at most one such in-flight batch.
        """

        if len(suffix) != 1:
            raise JournalCorruption(
                "journal suffix beyond durable HEAD is not one pending transaction"
            )
        journal_path, envelope, batch_digest = suffix[0]
        batch = envelope.get("batch")
        if not isinstance(batch, dict):
            raise JournalCorruption("journal suffix lacks an EventBatch")
        if (
            batch.get("sequence") != durable_head["sequence"] + 1
            or batch.get("previous_digest") != durable_head["batch_digest"]
            or batch_digest != digest_value(batch)
            or not isinstance(batch.get("batch_id"), str)
        ):
            raise JournalCorruption("journal suffix is not linked to durable HEAD")
        batch_file_id = hashlib.sha256(
            batch["batch_id"].encode("utf-8")
        ).hexdigest()
        expected_journal_name = (
            f"{batch['sequence']:020d}-{batch_file_id}.json"
        )
        if journal_path.name != expected_journal_name:
            raise JournalCorruption("journal suffix filename differs from its batch identity")
        pending_path = self.pending / f"{batch_file_id}.json"
        try:
            journal_payload = _read_bytes(journal_path)
            pending_payload = _read_bytes(pending_path)
        except OSError as exc:
            raise JournalCorruption(
                "journal suffix lacks its exact pending transaction"
            ) from exc
        if pending_payload != journal_payload:
            raise JournalCorruption(
                "pending transaction differs from journal suffix bytes"
            )
        pending = self._read_envelope(pending_path)
        if pending != envelope:
            raise JournalCorruption(
                "pending transaction differs from journal suffix content"
            )

    def _validate_recovery_head_locked(
        self,
        *,
        durable_head: Mapping[str, Any],
        durable_head_present: bool,
        durable_prefix_head: Mapping[str, Any],
        replayed_head: Mapping[str, Any],
        forward_journal_suffix: list[tuple[Path, dict[str, Any], str]],
    ) -> None:
        """Refuse recovery that would lower or replace durable history."""

        checked_durable = self._validate_head_value(dict(durable_head))
        checked_prefix = self._validate_head_value(dict(durable_prefix_head))
        checked_replayed = self._validate_head_value(dict(replayed_head))
        if checked_durable["sequence"] > checked_replayed["sequence"]:
            raise JournalCorruption(
                "durable HEAD is ahead of the replayed journal prefix"
            )
        if checked_durable["sequence"] > 0 and checked_prefix != checked_durable:
            raise JournalCorruption(
                "durable HEAD differs from the replayed committed journal prefix"
            )
        if checked_durable["sequence"] == checked_replayed["sequence"]:
            if checked_replayed != checked_durable:
                raise JournalCorruption(
                    "replayed journal HEAD differs from durable HEAD"
                )
            return
        if checked_prefix != checked_durable:
            raise JournalCorruption(
                "journal suffix does not begin at the durable HEAD"
            )
        # A missing HEAD is harmless only for an empty genesis journal or the
        # single exact pending append written before HEAD's durability point.
        if not durable_head_present and checked_durable["sequence"] != 0:
            raise JournalCorruption("durable journal HEAD disappeared during recovery")
        self._pending_proves_forward_journal_suffix_locked(
            checked_durable,
            forward_journal_suffix,
        )

    @staticmethod
    def _prune_generation_root(
        root: Path,
        *,
        active_generation: str,
        retain: int = 1,
    ) -> None:
        if retain < 1:
            retain = 1
        candidates: list[tuple[int, str, Path]] = []
        try:
            entries = _child_paths(root)
        except OSError:
            return
        for path in entries:
            if (
                _is_symlink(path)
                or not _is_directory(path)
                or not _INDEX_GENERATION.fullmatch(path.name)
            ):
                continue
            try:
                modified = _modified_time_ns(path)
            except OSError:
                modified = 0
            candidates.append((modified, path.name, path))
        candidates.sort(reverse=True)
        keep = {active_generation}
        for _modified, name, _path in candidates:
            if len(keep) >= retain:
                break
            keep.add(name)
        changed = False
        for _modified, name, path in candidates:
            if name in keep:
                continue
            try:
                shutil.rmtree(_native_os_path(path))
                changed = True
            except OSError:
                # Cleanup is best effort.  A leftover disposable generation is
                # safer than turning a successful authoritative recovery into a
                # failed operation.
                continue
        if changed:
            try:
                _fsync_directory(root)
            except OSError:
                pass

    def _prune_recovery_generations(
        self,
        *,
        active_index_generation: str,
        active_authority_generation: str,
    ) -> None:
        self._prune_generation_root(
            self.index_root,
            active_generation=active_index_generation,
        )
        self._prune_generation_root(
            self.authority_root,
            active_generation=active_authority_generation,
        )

    @staticmethod
    def _validate_head_value(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != {"sequence", "batch_id", "batch_digest"}:
            raise DerivedCheckpointError("checkpoint HEAD fields mismatch")
        sequence = value["sequence"]
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise DerivedCheckpointError("checkpoint HEAD sequence is invalid")
        if sequence == 0:
            if value["batch_id"] is not None or value["batch_digest"] is not None:
                raise DerivedCheckpointError("empty checkpoint HEAD must use null identities")
        else:
            if not isinstance(value["batch_id"], str) or not _ID.fullmatch(value["batch_id"]):
                raise DerivedCheckpointError("checkpoint HEAD batch_id is invalid")
            if not isinstance(value["batch_digest"], str) or not _DIGEST.fullmatch(value["batch_digest"]):
                raise DerivedCheckpointError("checkpoint HEAD digest is invalid")
        return copy.deepcopy(value)

    @staticmethod
    def _read_canonical_object(path: Path, *, limits: ParseLimits = _DERIVED_STATE_LIMITS) -> dict[str, Any]:
        try:
            raw = _read_bytes(path)
            value = parse_json_strict(raw, limits=limits)
        except (OSError, CanonicalError) as exc:
            raise DerivedCheckpointError(f"derived file is unreadable: {path.name}") from exc
        if canonical_bytes(value, limits=limits) != raw or not isinstance(value, dict):
            raise DerivedCheckpointError(f"derived file is not a canonical object: {path.name}")
        return value

    def _authority_generation_root(self, generation: str) -> Path:
        return self.authority_root / generation

    def _authority_segment_path(self, generation: str, sequence: int) -> Path:
        return self._authority_generation_root(generation) / f"{sequence:020d}.json"

    def _write_authority_segment(
        self,
        *,
        generation: str,
        envelope: Mapping[str, Any],
        journal_path: Path,
        journal_payload: bytes,
    ) -> dict[str, Any]:
        batch = envelope["batch"]
        value = {
            "record_type": "JournalPrefixSegment",
            "version": 1,
            "authoritative": False,
            "activation_digest": self.active_activation_digest,
            "implementation_closure_digest": self.implementation_closure_digest,
            "generation": generation,
            "sequence": batch["sequence"],
            "journal_file": journal_path.name,
            "journal_file_digest": hashlib.sha256(journal_payload).hexdigest(),
            "batch_digest": digest_value(batch),
            "previous_authority_commitment": batch["previous_authority_commitment"],
            "authority_commitment": batch["authority_commitment"],
            "event_count": batch["cumulative_event_count"],
            "event_semantic_digest": batch["event_semantic_digest"],
            "state_binding_update_count": batch[
                "cumulative_state_binding_update_count"
            ],
            "state_binding_digest": batch["state_binding_digest"],
        }
        value["segment_digest"] = digest_value(value)
        _write_atomic(
            self._authority_segment_path(generation, batch["sequence"]),
            canonical_bytes(value),
        )
        return value

    def _write_authority_root(
        self,
        *,
        generation: str,
        head: Mapping[str, Any],
        event_count: int,
        event_semantic_digest: str,
        authority_prefix_digest: str,
        state_binding_digest: str | None,
        state_binding_update_count: int,
    ) -> dict[str, Any]:
        value = {
            "record_type": "JournalPrefixRoot",
            "version": 1,
            "authoritative": False,
            "activation_digest": self.active_activation_digest,
            "implementation_closure_digest": self.implementation_closure_digest,
            "generation": generation,
            "head": copy.deepcopy(dict(head)),
            "segment_count": head["sequence"],
            "event_count": event_count,
            "event_semantic_digest": event_semantic_digest,
            "authority_prefix_digest": authority_prefix_digest,
            "state_binding_update_count": state_binding_update_count,
            "state_binding_digest": state_binding_digest,
        }
        value["root_digest"] = digest_value(value)
        _write_atomic(self.authority_head_path, canonical_bytes(value))
        return value

    def _read_authority_segment(self, generation: str, sequence: int) -> dict[str, Any]:
        value = self._read_canonical_object(
            self._authority_segment_path(generation, sequence),
            limits=ParseLimits(max_bytes=self.policy.max_command_bytes),
        )
        required = {
            "record_type", "version", "authoritative", "activation_digest",
            "implementation_closure_digest", "generation", "sequence",
            "journal_file", "journal_file_digest", "batch_digest",
            "previous_authority_commitment", "authority_commitment", "event_count",
            "event_semantic_digest", "state_binding_update_count",
            "state_binding_digest", "segment_digest",
        }
        if set(value) != required or value.get("record_type") != "JournalPrefixSegment":
            raise DerivedCheckpointError("journal prefix segment fields mismatch")
        supplied = value.pop("segment_digest")
        if not isinstance(supplied, str) or not _DIGEST.fullmatch(supplied) or digest_value(value) != supplied:
            raise DerivedCheckpointError("journal prefix segment digest mismatch")
        value["segment_digest"] = supplied
        if (
            value["version"] != 1
            or value["authoritative"] is not False
            or value["activation_digest"] != self.active_activation_digest
            or value["implementation_closure_digest"] != self.implementation_closure_digest
            or value["generation"] != generation
            or value["sequence"] != sequence
        ):
            raise DerivedCheckpointError("journal prefix segment binding mismatch")
        return value

    def _verify_authority_prefix_locked(
        self,
        head: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        checked_head = self._validate_head_value(
            dict(self._read_disk_head() if head is None else head)
        )
        value = self._read_canonical_object(
            self.authority_head_path,
            limits=ParseLimits(max_bytes=self.policy.max_command_bytes),
        )
        required = {
            "record_type", "version", "authoritative", "activation_digest",
            "implementation_closure_digest", "generation", "head", "segment_count",
            "event_count", "event_semantic_digest", "authority_prefix_digest",
            "state_binding_update_count", "state_binding_digest", "root_digest",
        }
        if set(value) != required or value.get("record_type") != "JournalPrefixRoot":
            raise DerivedCheckpointError("journal prefix root fields mismatch")
        supplied_root_digest = value.pop("root_digest")
        if (
            not isinstance(supplied_root_digest, str)
            or not _DIGEST.fullmatch(supplied_root_digest)
            or digest_value(value) != supplied_root_digest
        ):
            raise DerivedCheckpointError("journal prefix root digest mismatch")
        value["root_digest"] = supplied_root_digest
        generation = value["generation"]
        if (
            value["version"] != 1
            or value["authoritative"] is not False
            or value["activation_digest"] != self.active_activation_digest
            or value["implementation_closure_digest"] != self.implementation_closure_digest
            or not isinstance(generation, str)
            or not _INDEX_GENERATION.fullmatch(generation)
            or self._validate_head_value(value["head"]) != checked_head
            or value["segment_count"] != checked_head["sequence"]
        ):
            raise DerivedCheckpointError("journal prefix root binding mismatch")
        generation_root = self._authority_generation_root(generation)
        if not _is_directory(generation_root):
            raise DerivedCheckpointError("journal prefix generation is missing")
        journal_paths = sorted(_matching_paths(self.journal, "*.json"))
        segment_paths = sorted(_matching_paths(generation_root, "*.json"))
        if len(journal_paths) != checked_head["sequence"] or len(segment_paths) != checked_head["sequence"]:
            raise DerivedCheckpointError("journal prefix does not cover the exact authoritative history")

        previous_batch_digest: str | None = None
        previous_authority_commitment = (
            self.policy.genesis_previous_authority_commitment
        )
        event_semantic_digest = self.policy.genesis_event_semantic_digest
        event_count = 0
        state_binding_update_count = 0
        state_binding_digest: str | None = self._genesis_state_binding_digest
        for sequence, (journal_path, segment_path) in enumerate(
            zip(journal_paths, segment_paths), start=1
        ):
            expected_segment_path = self._authority_segment_path(generation, sequence)
            if segment_path != expected_segment_path:
                raise DerivedCheckpointError("journal prefix segment name is missing or ambiguous")
            segment = self._read_authority_segment(generation, sequence)
            raw = _read_bytes(journal_path)
            if (
                segment["journal_file"] != journal_path.name
                or segment["journal_file_digest"] != hashlib.sha256(raw).hexdigest()
            ):
                raise DerivedCheckpointError("journal prefix file identity mismatch")
            envelope = self._read_envelope(journal_path)
            batch = envelope.get("batch")
            if not isinstance(batch, dict) or batch.get("sequence") != sequence:
                raise DerivedCheckpointError("journal prefix sequence differs from journal")
            if batch.get("previous_digest") != previous_batch_digest:
                raise DerivedCheckpointError("journal prefix batch chain mismatch")
            events = batch.get("events")
            if not isinstance(events, list) or not events:
                raise DerivedCheckpointError("journal prefix batch has no bounded event list")
            for event in events:
                if not isinstance(event, Mapping):
                    raise DerivedCheckpointError("journal prefix event is not an object")
                event_semantic_digest = _extend_event_semantic_digest(
                    event_semantic_digest, event
                )
                event_count += 1
            state_binding_digest = batch.get("state_binding_digest")
            if (
                not isinstance(state_binding_digest, str)
                or not _DIGEST.fullmatch(state_binding_digest)
            ):
                raise DerivedCheckpointError("journal-owned state binding is invalid")
            delta = batch.get("state_binding_delta")
            try:
                normalized_delta = _normalize_state_binding_delta(
                    delta, policy=self.policy
                )
            except EventStoreError as exc:
                raise DerivedCheckpointError(
                    f"journal-owned state binding delta is invalid: {exc}"
                ) from exc
            state_binding_update_count += len(normalized_delta)
            if batch.get("cumulative_state_binding_update_count") != state_binding_update_count:
                raise DerivedCheckpointError("journal state binding update count mismatch")
            expected_commitment = _authority_commitment(
                previous_commitment=previous_authority_commitment,
                sequence=sequence,
                previous_batch_digest=previous_batch_digest,
                event_count=event_count,
                event_semantic_digest=event_semantic_digest,
                state_binding_update_count=state_binding_update_count,
                state_binding_digest=state_binding_digest,
            )
            batch_digest = digest_value(batch)
            bindings = {
                "previous_authority_commitment": previous_authority_commitment,
                "authority_commitment": expected_commitment,
                "cumulative_event_count": event_count,
                "event_semantic_digest": event_semantic_digest,
            }
            if any(batch.get(key) != expected for key, expected in bindings.items()):
                raise DerivedCheckpointError("journal-owned prefix commitment mismatch")
            segment_bindings = {
                "batch_digest": batch_digest,
                "previous_authority_commitment": previous_authority_commitment,
                "authority_commitment": expected_commitment,
                "event_count": event_count,
                "event_semantic_digest": event_semantic_digest,
                "state_binding_update_count": state_binding_update_count,
                "state_binding_digest": state_binding_digest,
            }
            if any(segment.get(key) != expected for key, expected in segment_bindings.items()):
                raise DerivedCheckpointError("journal prefix segment differs from journal authority")
            previous_batch_digest = batch_digest
            previous_authority_commitment = expected_commitment

        if checked_head["sequence"] == 0:
            expected_head = self._empty_head()
        else:
            last_batch = self._read_envelope(journal_paths[-1])["batch"]
            expected_head = {
                "sequence": last_batch["sequence"],
                "batch_id": last_batch["batch_id"],
                "batch_digest": digest_value(last_batch),
            }
        if expected_head != checked_head:
            raise DerivedCheckpointError("journal prefix does not terminate at HEAD")
        if checked_head["sequence"] > 0 and state_binding_digest is None:
            raise DerivedCheckpointError(
                "nonempty journal prefix lacks a journal-owned state binding"
            )
        root_bindings = {
            "event_count": event_count,
            "event_semantic_digest": event_semantic_digest,
            "authority_prefix_digest": previous_authority_commitment,
            "state_binding_update_count": state_binding_update_count,
            "state_binding_digest": state_binding_digest,
        }
        if any(value.get(key) != expected for key, expected in root_bindings.items()):
            raise DerivedCheckpointError("journal prefix root differs from journal authority")
        return value

    def _write_journal_checkpoint(
        self,
        *,
        head: Mapping[str, Any],
        batch_count: int,
        event_count: int,
        semantic_digest: str,
        index_generation: str,
        last_journal_file: str | None,
        last_journal_file_digest: str | None,
        authority_root: Mapping[str, Any],
        state_binding_update_count: int,
    ) -> dict[str, Any]:
        value = {
            "record_type": "DerivedJournalCheckpoint",
            "version": 3,
            "authoritative": False,
            "activation_digest": self.active_activation_digest,
            "implementation_closure_digest": self.implementation_closure_digest,
            "head": copy.deepcopy(dict(head)),
            "batch_count": batch_count,
            "event_count": event_count,
            "semantic_digest": semantic_digest,
            "index_generation": index_generation,
            "last_journal_file": last_journal_file,
            "last_journal_file_digest": last_journal_file_digest,
            "authority_generation": authority_root["generation"],
            "authority_prefix_digest": authority_root["authority_prefix_digest"],
            "authority_root_digest": authority_root["root_digest"],
            "state_binding_update_count": state_binding_update_count,
            "state_binding_digest": authority_root["state_binding_digest"],
        }
        value["checkpoint_digest"] = digest_value(value)
        _write_atomic(self.checkpoint_path, canonical_bytes(value))
        return value

    def _load_journal_checkpoint_locked(
        self,
        *,
        verified_authority_root: Mapping[str, Any] | None = None,
    ) -> None:
        if not _path_exists(self.checkpoint_path):
            raise DerivedCheckpointError("journal checkpoint is missing")
        value = self._read_canonical_object(
            self.checkpoint_path,
            limits=ParseLimits(max_bytes=self.policy.max_command_bytes),
        )
        required = {
            "record_type", "version", "authoritative", "activation_digest", "head",
            "batch_count", "event_count", "semantic_digest", "index_generation",
            "last_journal_file", "last_journal_file_digest", "implementation_closure_digest",
            "authority_generation", "authority_prefix_digest", "authority_root_digest",
            "state_binding_update_count", "state_binding_digest", "checkpoint_digest",
        }
        if set(value) != required or value.get("record_type") != "DerivedJournalCheckpoint":
            raise DerivedCheckpointError("journal checkpoint fields mismatch")
        supplied_digest = value.pop("checkpoint_digest")
        if not isinstance(supplied_digest, str) or not _DIGEST.fullmatch(supplied_digest):
            raise DerivedCheckpointError("journal checkpoint digest is invalid")
        if digest_value(value) != supplied_digest:
            raise DerivedCheckpointError("journal checkpoint digest mismatch")
        value["checkpoint_digest"] = supplied_digest
        if value["version"] != 3 or value["authoritative"] is not False:
            raise DerivedCheckpointError("journal checkpoint version or authority marker is invalid")
        if value["activation_digest"] != self.active_activation_digest:
            raise DerivedCheckpointError("journal checkpoint Activation is stale")
        if value["implementation_closure_digest"] != self.implementation_closure_digest:
            raise ImplementationClosureMismatch(
                "journal checkpoint implementation closure mismatch"
            )
        head = self._validate_head_value(value["head"])
        disk_head = self._read_disk_head()
        if head != disk_head:
            raise DerivedCheckpointError("journal checkpoint HEAD is stale")
        if (
            not isinstance(value["batch_count"], int)
            or isinstance(value["batch_count"], bool)
            or value["batch_count"] != head["sequence"]
            or not isinstance(value["event_count"], int)
            or isinstance(value["event_count"], bool)
            or value["event_count"] < value["batch_count"]
            or not isinstance(value["state_binding_update_count"], int)
            or isinstance(value["state_binding_update_count"], bool)
            or value["state_binding_update_count"] < value["batch_count"]
        ):
            raise DerivedCheckpointError("journal checkpoint counts are invalid")
        if not isinstance(value["semantic_digest"], str) or not _DIGEST.fullmatch(value["semantic_digest"]):
            raise DerivedCheckpointError("journal checkpoint semantic digest is invalid")
        authority_root = (
            dict(verified_authority_root)
            if verified_authority_root is not None
            else self._verify_authority_prefix_locked(head)
        )
        authority_bindings = {
            "authority_generation": authority_root["generation"],
            "authority_prefix_digest": authority_root["authority_prefix_digest"],
            "authority_root_digest": authority_root["root_digest"],
            "state_binding_update_count": authority_root[
                "state_binding_update_count"
            ],
            "state_binding_digest": authority_root["state_binding_digest"],
            "semantic_digest": authority_root["event_semantic_digest"],
            "event_count": authority_root["event_count"],
        }
        if any(value.get(key) != expected for key, expected in authority_bindings.items()):
            raise DerivedCheckpointError(
                "journal checkpoint differs from the journal-owned prefix commitment"
            )
        generation = value["index_generation"]
        if not isinstance(generation, str) or not _INDEX_GENERATION.fullmatch(generation):
            raise DerivedCheckpointError("journal checkpoint index generation is invalid")
        generation_root = self.index_root / generation
        if not _is_directory(generation_root):
            raise DerivedCheckpointError("journal checkpoint index generation is missing")
        self._validate_event_identity_index(
            generation,
            head_sequence=head["sequence"],
            event_count=value["event_count"],
        )
        self._validate_state_binding_index(
            generation,
            head_sequence=head["sequence"],
            update_count=value["state_binding_update_count"],
            root_digest=value["state_binding_digest"],
        )
        if _matching_paths(self.pending, "*.json"):
            raise DerivedCheckpointError("pending transaction requires recovery")
        if head["sequence"] == 0:
            if value["last_journal_file"] is not None or value["last_journal_file_digest"] is not None:
                raise DerivedCheckpointError("empty journal checkpoint has a last file")
            if _matching_paths(self.journal, "*.json"):
                raise DerivedCheckpointError("empty journal checkpoint has committed data")
        else:
            file_name = value["last_journal_file"]
            file_digest = value["last_journal_file_digest"]
            if (
                not isinstance(file_name, str)
                or Path(file_name).name != file_name
                or not file_name.startswith(f"{head['sequence']:020d}-")
                or not isinstance(file_digest, str)
                or not _DIGEST.fullmatch(file_digest)
            ):
                raise DerivedCheckpointError("journal checkpoint last-file binding is invalid")
            last_path = self.journal / file_name
            try:
                raw = _read_bytes(last_path)
            except OSError as exc:
                raise DerivedCheckpointError("journal checkpoint last file is missing") from exc
            if hashlib.sha256(raw).hexdigest() != file_digest:
                raise DerivedCheckpointError("journal checkpoint last file digest mismatch")
            envelope = self._read_envelope(last_path)
            batch = envelope["batch"]
            batch_digest = self._validate_envelope(
                envelope,
                expected_sequence=head["sequence"],
                expected_previous_digest=batch.get("previous_digest"),
                validate_runtime=False,
            )
            if batch["batch_id"] != head["batch_id"] or batch_digest != head["batch_digest"]:
                raise DerivedCheckpointError("journal checkpoint does not bind authoritative HEAD")
            if _matching_paths(
                self.journal, f"{head['sequence'] + 1:020d}-*.json"
            ):
                raise DerivedCheckpointError("journal checkpoint omits a durable journal tail")
        self._head = head
        self._command_ids = {}
        self._idempotency = {}
        self._batch_ids = set()
        self._event_ids = set()
        self._index_generation = generation
        self._batch_count = value["batch_count"]
        self._event_count = value["event_count"]
        self._semantic_digest = value["semantic_digest"]
        self._authority_generation = authority_root["generation"]
        self._authority_prefix_digest = authority_root["authority_prefix_digest"]
        self._state_binding_digest = authority_root["state_binding_digest"]
        self._state_binding_update_count = authority_root[
            "state_binding_update_count"
        ]

    @staticmethod
    def _index_identity_digest(kind: str, identity: Any) -> str:
        return digest_value({"index_kind": kind, "identity": identity})

    def _index_entry_path(self, generation: str, kind: str, identity: Any) -> Path:
        digest = bytes.fromhex(self._index_identity_digest(kind, identity))
        filename = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return self.index_root / generation / kind / f"{filename}.json"

    def _event_identity_index_path(self, generation: str) -> Path:
        return self.index_root / generation / _EVENT_IDENTITY_INDEX_NAME

    def _event_identity_connection(
        self, generation: str, *, create: bool = False
    ) -> sqlite3.Connection:
        path = self._event_identity_index_path(generation)
        if not create and not _path_exists(path):
            raise DerivedCheckpointError("event identity index is missing")
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                _native_os_path(path),
                timeout=self.lock_timeout,
                isolation_level=None,
            )
            connection.execute(f"PRAGMA busy_timeout={int(self.lock_timeout * 1000)}")
            return connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise DerivedCheckpointError("event identity index is unavailable") from exc

    def _initialize_event_identity_index(self, generation: str) -> None:
        path = self._event_identity_index_path(generation)
        if _path_exists(path):
            raise DerivedCheckpointError("event identity index already exists")
        connection = self._event_identity_connection(generation, create=True)
        try:
            # DELETE is intentionally restated here because, unlike WAL, the
            # TRUNCATE selection would not persist across the short-lived
            # connections used by later publications.  Peak rollback-journal
            # bytes are measured by the saturation harness.
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE binding ("
                "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
                "version INTEGER NOT NULL, activation_digest TEXT NOT NULL, "
                "implementation_closure_digest TEXT NOT NULL, "
                "index_generation TEXT NOT NULL, head_sequence INTEGER NOT NULL, "
                "event_count INTEGER NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE event_identity ("
                "event_id TEXT PRIMARY KEY, package_name TEXT NOT NULL) WITHOUT ROWID"
            )
            connection.execute(
                "INSERT INTO binding VALUES (1, ?, ?, ?, ?, 0, 0)",
                (
                    _EVENT_IDENTITY_INDEX_VERSION,
                    self.active_activation_digest,
                    self.implementation_closure_digest,
                    generation,
                ),
            )
            connection.execute("COMMIT")
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise DerivedCheckpointError("event identity index initialization failed") from exc
        finally:
            connection.close()
        _fsync_directory(path.parent)

    def _event_identity_binding(self, connection: sqlite3.Connection) -> tuple[Any, ...]:
        try:
            row = connection.execute(
                "SELECT version, activation_digest, implementation_closure_digest, "
                "index_generation, head_sequence, event_count "
                "FROM binding WHERE singleton = 1"
            ).fetchone()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("event identity index binding is unreadable") from exc
        if row is None or len(row) != 6:
            raise DerivedCheckpointError("event identity index binding is missing")
        return row

    def _validate_event_identity_index(
        self,
        generation: str,
        *,
        head_sequence: int,
        event_count: int,
    ) -> None:
        path = self._event_identity_index_path(generation)
        if not _path_exists(path):
            raise DerivedCheckpointError("event identity index is missing")
        connection = self._event_identity_connection(generation)
        try:
            row = self._event_identity_binding(connection)
            expected = (
                _EVENT_IDENTITY_INDEX_VERSION,
                self.active_activation_digest,
                self.implementation_closure_digest,
                generation,
                head_sequence,
                event_count,
            )
            if row != expected:
                raise DerivedCheckpointError("event identity index binding is stale")
            try:
                indexed_count = connection.execute(
                    "SELECT COUNT(*) FROM event_identity"
                ).fetchone()
            except sqlite3.Error as exc:
                raise DerivedCheckpointError(
                    "event identity index rows are unreadable"
                ) from exc
            if indexed_count != (event_count,):
                raise DerivedCheckpointError("event identity index row count is stale")
        finally:
            connection.close()

    def _state_binding_index_path(self, generation: str) -> Path:
        return self.index_root / generation / _STATE_BINDING_INDEX_NAME

    def _state_binding_connection(
        self, generation: str, *, create: bool = False
    ) -> sqlite3.Connection:
        path = self._state_binding_index_path(generation)
        if not create and not _path_exists(path):
            raise DerivedCheckpointError("state binding index is missing")
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                _native_os_path(path),
                timeout=self.lock_timeout,
                isolation_level=None,
            )
            connection.execute(f"PRAGMA busy_timeout={int(self.lock_timeout * 1000)}")
            return connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise DerivedCheckpointError("state binding index is unavailable") from exc

    def _initialize_state_binding_index(self, generation: str) -> None:
        path = self._state_binding_index_path(generation)
        if _path_exists(path):
            raise DerivedCheckpointError("state binding index already exists")
        connection = self._state_binding_connection(generation, create=True)
        try:
            # Configure page relocation before the first schema object exists.
            # FULL auto-vacuum is part of SQLite's own atomic FULL-sync commit,
            # so deleting sparse-tree rows cannot leave an ever-growing
            # freelist and no separate unsafe VACUUM step is needed.
            connection.execute("PRAGMA auto_vacuum=FULL")
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE binding ("
                "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
                "version INTEGER NOT NULL, algorithm TEXT NOT NULL, "
                "activation_digest TEXT NOT NULL, "
                "activation_record_digest TEXT NOT NULL, "
                "implementation_closure_digest TEXT NOT NULL, "
                "index_generation TEXT NOT NULL, head_sequence INTEGER NOT NULL, "
                "update_count INTEGER NOT NULL, root_digest TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE node ("
                "depth INTEGER NOT NULL, prefix BLOB NOT NULL, digest BLOB NOT NULL, "
                "children BLOB NOT NULL, "
                "PRIMARY KEY(depth, prefix)) WITHOUT ROWID"
            )
            connection.execute(
                "CREATE TABLE compact_binding ("
                "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
                "partition_depth INTEGER NOT NULL, head_sequence INTEGER NOT NULL, "
                "update_count INTEGER NOT NULL, root_digest TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE compact_leaf ("
                "leaf_key BLOB PRIMARY KEY, bucket BLOB NOT NULL, "
                "value_digest BLOB NOT NULL) WITHOUT ROWID"
            )
            connection.execute(
                "CREATE INDEX compact_leaf_by_bucket "
                "ON compact_leaf(bucket, leaf_key)"
            )
            connection.execute(
                "CREATE TABLE compact_bucket ("
                "bucket BLOB PRIMARY KEY, digest BLOB NOT NULL) WITHOUT ROWID"
            )
            connection.execute(
                "INSERT INTO binding VALUES (1, ?, ?, ?, ?, ?, ?, 0, 0, ?)",
                (
                    _STATE_BINDING_INDEX_VERSION,
                    _STATE_BINDING_ALGORITHM,
                    self.active_activation_digest,
                    self.activation_record_digest,
                    self.implementation_closure_digest,
                    generation,
                    self._genesis_state_binding_digest,
                ),
            )
            activation_key = _state_leaf_key_digest(
                {
                    "leaf_type": "Activation",
                    "leaf_id": self.active_activation_digest,
                }
            )
            genesis_rows: list[tuple[int, bytes, bytes, bytes]] = []
            for (depth, prefix), node_digest in sorted(
                self._genesis_state_binding_nodes.items(),
                key=lambda item: (item[0][0], item[0][1]),
            ):
                if depth % _STATE_BINDING_STORAGE_STRIDE != 0:
                    continue
                if depth == _STATE_TREE_DEPTH:
                    children_payload = b""
                else:
                    edge = activation_key[depth // 8]
                    child_prefix = prefix + bytes((edge,))
                    child_digest = self._genesis_state_binding_nodes[
                        (depth + _STATE_BINDING_STORAGE_STRIDE, child_prefix)
                    ]
                    children_payload = _encode_state_storage_children(
                        {edge: child_digest}
                    )
                genesis_rows.append(
                    (depth, prefix, node_digest, children_payload)
                )
            connection.executemany(
                "INSERT INTO node(depth, prefix, digest, children) VALUES (?, ?, ?, ?)",
                genesis_rows,
            )
            activation_bucket = activation_key[:_STATE_BINDING_COMPACT_PARTITION_BYTES]
            activation_value_digest = bytes.fromhex(self.activation_record_digest)
            activation_partition_digest = _state_binding_partition_root(
                partition=activation_bucket,
                leaf_values={activation_key: activation_value_digest},
            )
            connection.execute(
                "INSERT INTO compact_binding VALUES (1, ?, 0, 0, ?)",
                (
                    _STATE_BINDING_COMPACT_PARTITION_DEPTH,
                    self._genesis_state_binding_digest,
                ),
            )
            connection.execute(
                "INSERT INTO compact_leaf(leaf_key, bucket, value_digest) "
                "VALUES (?, ?, ?)",
                (activation_key, activation_bucket, activation_value_digest),
            )
            connection.execute(
                "INSERT INTO compact_bucket(bucket, digest) VALUES (?, ?)",
                (activation_bucket, activation_partition_digest),
            )
            connection.execute("COMMIT")
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise DerivedCheckpointError("state binding index initialization failed") from exc
        finally:
            connection.close()
        _fsync_directory(path.parent)

    @staticmethod
    def _state_binding_binding(connection: sqlite3.Connection) -> tuple[Any, ...]:
        try:
            storage_mode = connection.execute("PRAGMA auto_vacuum").fetchone()
            if storage_mode != (1,):
                raise DerivedCheckpointError(
                    "state binding index lacks bounded page reclamation"
                )
            row = connection.execute(
                "SELECT version, algorithm, activation_digest, "
                "activation_record_digest, implementation_closure_digest, "
                "index_generation, head_sequence, "
                "update_count, root_digest FROM binding WHERE singleton = 1"
            ).fetchone()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("state binding index binding is unreadable") from exc
        if row is None or len(row) != 9:
            raise DerivedCheckpointError("state binding index binding is missing")
        return row

    @staticmethod
    def _compact_state_binding_binding(
        connection: sqlite3.Connection,
    ) -> tuple[Any, ...]:
        try:
            row = connection.execute(
                "SELECT partition_depth, head_sequence, update_count, root_digest "
                "FROM compact_binding WHERE singleton = 1"
            ).fetchone()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError(
                "compact state binding index binding is unreadable"
            ) from exc
        if (
            row is None
            or len(row) != 4
            or row[0] != _STATE_BINDING_COMPACT_PARTITION_DEPTH
            or not isinstance(row[1], int)
            or isinstance(row[1], bool)
            or row[1] < 0
            or not isinstance(row[2], int)
            or isinstance(row[2], bool)
            or row[2] < 0
            or not isinstance(row[3], str)
            or not _DIGEST.fullmatch(row[3])
        ):
            raise DerivedCheckpointError("compact state binding index binding is invalid")
        return row

    @staticmethod
    def _compact_state_rows(
        connection: sqlite3.Connection,
        buckets: Iterable[bytes],
    ) -> dict[bytes, tuple[bytes, dict[bytes, bytes]]]:
        """Load exact individual leaves for a bounded set of partitions."""

        selected = tuple(sorted(set(buckets)))
        if (
            not selected
            or any(
                not isinstance(bucket, bytes)
                or len(bucket) != _STATE_BINDING_COMPACT_PARTITION_BYTES
                for bucket in selected
            )
        ):
            raise DerivedCheckpointError("compact state binding bucket request is invalid")
        placeholders = ",".join("?" for _unused in selected)
        try:
            leaf_rows = connection.execute(
                "SELECT bucket, leaf_key, value_digest FROM compact_leaf "
                f"WHERE bucket IN ({placeholders}) ORDER BY bucket, leaf_key",
                selected,
            ).fetchall()
            bucket_rows = connection.execute(
                "SELECT bucket, digest FROM compact_bucket "
                f"WHERE bucket IN ({placeholders}) ORDER BY bucket",
                selected,
            ).fetchall()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError(
                "compact state binding rows are unreadable"
            ) from exc
        values: dict[bytes, dict[bytes, bytes]] = {bucket: {} for bucket in selected}
        for bucket, leaf_key, value_digest in leaf_rows:
            if (
                bucket not in values
                or not isinstance(leaf_key, bytes)
                or len(leaf_key) != 32
                or leaf_key[:_STATE_BINDING_COMPACT_PARTITION_BYTES] != bucket
                or not isinstance(value_digest, bytes)
                or len(value_digest) != 32
                or leaf_key in values[bucket]
            ):
                raise DerivedCheckpointError("compact state binding leaf row is invalid")
            values[bucket][leaf_key] = value_digest
        observed: dict[bytes, bytes] = {}
        for bucket, digest in bucket_rows:
            if (
                bucket not in values
                or bucket in observed
                or not isinstance(digest, bytes)
                or len(digest) != 32
                or digest
                == _STATE_DEFAULT_DIGESTS[_STATE_BINDING_COMPACT_PARTITION_DEPTH]
            ):
                raise DerivedCheckpointError("compact state binding bucket row is invalid")
            observed[bucket] = digest
        result: dict[bytes, tuple[bytes, dict[bytes, bytes]]] = {}
        default = _STATE_DEFAULT_DIGESTS[_STATE_BINDING_COMPACT_PARTITION_DEPTH]
        for bucket in selected:
            calculated = _state_binding_partition_root(
                partition=bucket,
                leaf_values=values[bucket],
            )
            stored = observed.get(bucket, default)
            if calculated != stored:
                raise DerivedCheckpointError(
                    "compact state binding bucket differs from its leaves"
                )
            result[bucket] = (stored, values[bucket])
        return result

    def _stage_compact_state_binding_delta(
        self,
        generation: str,
        delta: tuple[dict[str, Any], ...],
        *,
        prior_sequence: int,
        prior_root_digest: str | None,
        prior_update_count: int,
    ) -> tuple[str, _CompactStateBindingOverlay]:
        """Stage exact leaf changes without materialising their 240 lower levels."""

        connection = self._state_binding_connection(generation)
        current_root = bytes.fromhex(
            _EMPTY_STATE_BINDING_DIGEST
            if prior_root_digest is None
            else prior_root_digest
        )
        try:
            expected_binding = (
                _STATE_BINDING_INDEX_VERSION,
                _STATE_BINDING_ALGORITHM,
                self.active_activation_digest,
                self.activation_record_digest,
                self.implementation_closure_digest,
                generation,
                prior_sequence,
                prior_update_count,
                current_root.hex(),
            )
            if self._state_binding_binding(connection) != expected_binding:
                raise DerivedCheckpointError(
                    "state binding index is not at the previous HEAD"
                )
            if self._compact_state_binding_binding(connection) != (
                _STATE_BINDING_COMPACT_PARTITION_DEPTH,
                prior_sequence,
                prior_update_count,
                current_root.hex(),
            ):
                raise DerivedCheckpointError(
                    "compact state binding index is not at the previous HEAD"
                )
            leaf_keys = tuple(_state_leaf_key_digest(update) for update in delta)
            if len(leaf_keys) != len(set(leaf_keys)):
                raise DerivedCheckpointError("state binding leaf keys collide")
            buckets = tuple(
                sorted(
                    {
                        key[:_STATE_BINDING_COMPACT_PARTITION_BYTES]
                        for key in leaf_keys
                    }
                )
            )
            compact_rows = self._compact_state_rows(connection, buckets)
            legacy_leaf_rows = self._state_storage_rows(
                connection,
                _STATE_TREE_DEPTH,
                leaf_keys,
            )
            for key_digest in leaf_keys:
                bucket = key_digest[:_STATE_BINDING_COMPACT_PARTITION_BYTES]
                previous_value_digest = compact_rows[bucket][1].get(key_digest)
                expected_leaf = (
                    _STATE_DEFAULT_DIGESTS[_STATE_TREE_DEPTH]
                    if previous_value_digest is None
                    else hashlib.sha256(
                        b"promin:typed-sparse-merkle-v1:leaf\x00"
                        + key_digest
                        + previous_value_digest
                    ).digest()
                )
                if legacy_leaf_rows[key_digest][0] != expected_leaf:
                    raise DerivedCheckpointError(
                        "state binding touched compact leaf differs from its commitment"
                    )
            top_prefixes = tuple(sorted({bucket[:1] for bucket in buckets}))
            top_rows = self._state_storage_rows(connection, 8, top_prefixes)
            root_row = self._state_storage_rows(connection, 0, (b"",))[b""]
            if root_row[0] != current_root:
                raise DerivedCheckpointError("state binding index root is stale")

            updated_values = {
                bucket: dict(values)
                for bucket, (_digest, values) in compact_rows.items()
            }
            for update, key_digest in zip(delta, leaf_keys):
                bucket = key_digest[:_STATE_BINDING_COMPACT_PARTITION_BYTES]
                if update["operation"] == "set":
                    updated_values[bucket][key_digest] = bytes.fromhex(
                        update["value_digest"]
                    )
                else:
                    updated_values[bucket].pop(key_digest, None)

            leaf_deletes: list[bytes] = []
            leaf_upserts: list[tuple[bytes, bytes, bytes]] = []
            bucket_deletes: list[bytes] = []
            bucket_upserts: list[tuple[bytes, bytes]] = []
            bucket_changes: dict[bytes, tuple[bytes, bytes]] = {}
            default_partition = _STATE_DEFAULT_DIGESTS[
                _STATE_BINDING_COMPACT_PARTITION_DEPTH
            ]
            for bucket in buckets:
                old_digest, old_values = compact_rows[bucket]
                new_values = updated_values[bucket]
                for leaf_key in sorted(set(old_values) - set(new_values)):
                    leaf_deletes.append(leaf_key)
                for leaf_key in sorted(new_values):
                    if old_values.get(leaf_key) != new_values[leaf_key]:
                        leaf_upserts.append((leaf_key, bucket, new_values[leaf_key]))
                new_digest = _state_binding_partition_root(
                    partition=bucket,
                    leaf_values=new_values,
                )
                if new_digest == default_partition:
                    if old_digest != default_partition:
                        bucket_deletes.append(bucket)
                elif old_digest != new_digest:
                    bucket_upserts.append((bucket, new_digest))
                bucket_changes[bucket] = (old_digest, new_digest)

            node_rows: dict[tuple[int, bytes], tuple[bytes, bytes]] = {}
            parent_changes: dict[bytes, tuple[bytes, bytes]] = {}
            for parent_prefix in top_prefixes:
                old_parent, existing_children = top_rows[parent_prefix]
                children = dict(existing_children)
                for bucket in (
                    item for item in buckets if item[:1] == parent_prefix
                ):
                    old_child, new_child = bucket_changes[bucket]
                    edge = bucket[1]
                    if children.get(edge, default_partition) != old_child:
                        raise DerivedCheckpointError(
                            "compact state binding bucket differs from top tree"
                        )
                    if new_child == default_partition:
                        children.pop(edge, None)
                    else:
                        children[edge] = new_child
                new_parent = _state_storage_parent_digest(8, children)
                node_rows[(8, parent_prefix)] = (
                    new_parent,
                    _encode_state_storage_children(children),
                )
                parent_changes[parent_prefix] = (old_parent, new_parent)

            root_children = dict(root_row[1])
            default_parent = _STATE_DEFAULT_DIGESTS[8]
            for parent_prefix in sorted(parent_changes):
                old_parent, new_parent = parent_changes[parent_prefix]
                edge = parent_prefix[0]
                if root_children.get(edge, default_parent) != old_parent:
                    raise DerivedCheckpointError(
                        "compact state binding top node differs from root"
                    )
                if new_parent == default_parent:
                    root_children.pop(edge, None)
                else:
                    root_children[edge] = new_parent
            next_root = _state_storage_parent_digest(0, root_children)
            node_rows[(0, b"")] = (
                next_root,
                _encode_state_storage_children(root_children),
            )
            for key_digest in leaf_keys:
                bucket = key_digest[:_STATE_BINDING_COMPACT_PARTITION_BYTES]
                value_digest = updated_values[bucket].get(key_digest)
                leaf_digest = (
                    _STATE_DEFAULT_DIGESTS[_STATE_TREE_DEPTH]
                    if value_digest is None
                    else hashlib.sha256(
                        b"promin:typed-sparse-merkle-v1:leaf\x00"
                        + key_digest
                        + value_digest
                    ).digest()
                )
                node_rows[(_STATE_TREE_DEPTH, key_digest)] = (leaf_digest, b"")
            return (
                next_root.hex(),
                _CompactStateBindingOverlay(
                    node_rows=MappingProxyType(dict(node_rows)),
                    leaf_deletes=tuple(sorted(leaf_deletes)),
                    leaf_upserts=tuple(sorted(leaf_upserts)),
                    bucket_deletes=tuple(sorted(bucket_deletes)),
                    bucket_upserts=tuple(sorted(bucket_upserts)),
                ),
            )
        finally:
            connection.close()

    def _publish_compact_state_binding_delta(
        self,
        generation: str,
        *,
        sequence: int,
        prior_root_digest: str | None,
        prior_update_count: int,
        root_digest: str,
        delta_count: int,
        overlay: _CompactStateBindingOverlay,
    ) -> tuple[int, int]:
        """Publish one fully staged compact derived index transaction."""

        if not isinstance(overlay, _CompactStateBindingOverlay):
            raise DerivedCheckpointError("compact state binding overlay is invalid")
        connection = self._state_binding_connection(generation)
        previous_root = (
            _EMPTY_STATE_BINDING_DIGEST
            if prior_root_digest is None
            else prior_root_digest
        )
        try:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            expected_binding = (
                _STATE_BINDING_INDEX_VERSION,
                _STATE_BINDING_ALGORITHM,
                self.active_activation_digest,
                self.activation_record_digest,
                self.implementation_closure_digest,
                generation,
                sequence - 1,
                prior_update_count,
                previous_root,
            )
            if self._state_binding_binding(connection) != expected_binding:
                raise DerivedCheckpointError("state binding index publication is stale")
            if self._compact_state_binding_binding(connection) != (
                _STATE_BINDING_COMPACT_PARTITION_DEPTH,
                sequence - 1,
                prior_update_count,
                previous_root,
            ):
                raise DerivedCheckpointError(
                    "compact state binding index publication is stale"
                )
            root_row = overlay.node_rows.get((0, b""))
            if root_row is None or root_row[0].hex() != root_digest:
                raise DerivedCheckpointError(
                    "compact state binding overlay root differs from publication binding"
                )
            node_deletes: list[tuple[int, bytes]] = []
            node_upserts: list[tuple[int, bytes, bytes, bytes]] = []
            for (depth, prefix), (node_digest, children_payload) in sorted(
                overlay.node_rows.items(), key=lambda item: (item[0][0], item[0][1])
            ):
                if (
                    depth not in {0, 8, _STATE_TREE_DEPTH}
                    or not isinstance(prefix, bytes)
                    or len(prefix) != depth // 8
                    or not isinstance(node_digest, bytes)
                    or len(node_digest) != 32
                ):
                    raise DerivedCheckpointError("compact state binding node is invalid")
                children = _decode_state_storage_children(children_payload)
                if depth == _STATE_TREE_DEPTH:
                    if children:
                        raise DerivedCheckpointError(
                            "compact state binding leaf has children"
                        )
                else:
                    child_default = _STATE_DEFAULT_DIGESTS[depth + 8]
                    if any(value == child_default for value in children.values()):
                        raise DerivedCheckpointError(
                            "compact state binding node retains a default child"
                        )
                    if _state_storage_parent_digest(depth, children) != node_digest:
                        raise DerivedCheckpointError(
                            "compact state binding node children differ from its digest"
                        )
                if node_digest == _STATE_DEFAULT_DIGESTS[depth]:
                    node_deletes.append((depth, prefix))
                else:
                    node_upserts.append((depth, prefix, node_digest, children_payload))
            if node_deletes:
                connection.executemany(
                    "DELETE FROM node WHERE depth = ? AND prefix = ?", node_deletes
                )
            if node_upserts:
                connection.executemany(
                    "INSERT INTO node(depth, prefix, digest, children) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(depth, prefix) DO UPDATE SET "
                    "digest=excluded.digest, children=excluded.children",
                    node_upserts,
                )
            if overlay.leaf_deletes:
                connection.executemany(
                    "DELETE FROM compact_leaf WHERE leaf_key = ?",
                    ((leaf_key,) for leaf_key in overlay.leaf_deletes),
                )
            if overlay.leaf_upserts:
                connection.executemany(
                    "INSERT INTO compact_leaf(leaf_key, bucket, value_digest) "
                    "VALUES (?, ?, ?) ON CONFLICT(leaf_key) DO UPDATE SET "
                    "bucket=excluded.bucket, value_digest=excluded.value_digest",
                    overlay.leaf_upserts,
                )
            if overlay.bucket_deletes:
                connection.executemany(
                    "DELETE FROM compact_bucket WHERE bucket = ?",
                    ((bucket,) for bucket in overlay.bucket_deletes),
                )
            if overlay.bucket_upserts:
                connection.executemany(
                    "INSERT INTO compact_bucket(bucket, digest) VALUES (?, ?) "
                    "ON CONFLICT(bucket) DO UPDATE SET digest=excluded.digest",
                    overlay.bucket_upserts,
                )
            connection.execute(
                "UPDATE binding SET head_sequence = ?, update_count = ?, "
                "root_digest = ? WHERE singleton = 1",
                (sequence, prior_update_count + delta_count, root_digest),
            )
            connection.execute(
                "UPDATE compact_binding SET head_sequence = ?, update_count = ?, "
                "root_digest = ? WHERE singleton = 1",
                (sequence, prior_update_count + delta_count, root_digest),
            )
            connection.execute("COMMIT")
        except DerivedCheckpointError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise DerivedCheckpointError(
                "compact state binding index publication failed"
            ) from exc
        finally:
            connection.close()
        logical_bytes = (
            sum(
                2 + len(prefix) + len(node_digest) + len(children_payload)
                for (depth, prefix), (node_digest, children_payload) in overlay.node_rows.items()
            )
            + sum(len(leaf_key) for leaf_key in overlay.leaf_deletes)
            + sum(
                len(leaf_key) + len(bucket) + len(value_digest)
                for leaf_key, bucket, value_digest in overlay.leaf_upserts
            )
            + sum(len(bucket) for bucket in overlay.bucket_deletes)
            + sum(len(bucket) + len(digest) for bucket, digest in overlay.bucket_upserts)
        )
        return logical_bytes, len(overlay.node_rows)

    @staticmethod
    def _state_storage_rows(
        connection: sqlite3.Connection,
        depth: int,
        prefixes: Iterable[bytes],
    ) -> dict[bytes, tuple[bytes, dict[int, bytes]]]:
        """Fetch all affected byte-boundary rows with one indexed query."""

        selected = tuple(sorted(set(prefixes)))
        if (
            depth < 0
            or depth > _STATE_TREE_DEPTH
            or depth % _STATE_BINDING_STORAGE_STRIDE != 0
            or any(not isinstance(prefix, bytes) or len(prefix) != depth // 8 for prefix in selected)
        ):
            raise DerivedCheckpointError("state binding storage row request is invalid")
        if not selected:
            return {}
        placeholders = ",".join("?" for _unused in selected)
        try:
            rows = connection.execute(
                "SELECT prefix, digest, children FROM node "
                f"WHERE depth = ? AND prefix IN ({placeholders}) ORDER BY prefix",
                (depth, *selected),
            ).fetchall()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("state binding storage rows are unreadable") from exc
        observed: dict[bytes, tuple[bytes, dict[int, bytes]]] = {}
        for prefix, node_digest, children_payload in rows:
            if (
                prefix not in selected
                or prefix in observed
                or not isinstance(node_digest, bytes)
                or len(node_digest) != 32
            ):
                raise DerivedCheckpointError("state binding storage row is invalid")
            children = _decode_state_storage_children(children_payload)
            if depth == _STATE_TREE_DEPTH:
                if children:
                    raise DerivedCheckpointError("state binding leaf row has children")
            else:
                child_default = _STATE_DEFAULT_DIGESTS[
                    depth + _STATE_BINDING_STORAGE_STRIDE
                ]
                if any(value == child_default for value in children.values()):
                    raise DerivedCheckpointError(
                        "state binding storage row retains a default child"
                    )
                if _state_storage_parent_digest(depth, children) != node_digest:
                    raise DerivedCheckpointError("state binding storage row digest mismatch")
            if node_digest == _STATE_DEFAULT_DIGESTS[depth]:
                raise DerivedCheckpointError("state binding storage retains a default row")
            observed[prefix] = (node_digest, children)
        return {
            prefix: observed.get(prefix, (_STATE_DEFAULT_DIGESTS[depth], {}))
            for prefix in selected
        }

    @staticmethod
    def _state_storage_union_rows(
        connection: sqlite3.Connection,
        key_digests: Iterable[bytes],
    ) -> dict[tuple[int, bytes], tuple[bytes, dict[int, bytes]]]:
        """Fetch the union of all touched byte-boundary paths once.

        A maximum state-binding batch has 128 leaves and therefore at most
        4,224 distinct storage identities.  Loading one depth at a time still
        incurred 33 SQLite read round trips.  The sorted leaf keys are reduced
        to a unique path union in Python.  One bounded length-prefixed BLOB
        carries those identities into a recursive CTE, so every affected stored
        prefix is looked up at most once without a SQLite DISTINCT sort or
        dependence on a host's parameter ceiling.  The canonical v3 node table
        and its byte-for-byte representation remain unchanged.
        """

        selected_keys = tuple(sorted(set(key_digests)))
        if any(not isinstance(key_digest, bytes) or len(key_digest) != 32 for key_digest in selected_keys):
            raise DerivedCheckpointError("state binding storage union request is invalid")
        if not selected_keys:
            return {}
        selected = tuple(
            sorted(
                {
                    (depth, key_digest[: depth // _STATE_BINDING_STORAGE_STRIDE])
                    for key_digest in selected_keys
                    for depth in range(
                        0,
                        _STATE_TREE_DEPTH + _STATE_BINDING_STORAGE_STRIDE,
                        _STATE_BINDING_STORAGE_STRIDE,
                    )
                },
                key=lambda value: (value[0], value[1]),
            )
        )
        selected_set = set(selected)
        path_payload = b"".join(
            bytes((len(prefix) + 1,)) + prefix
            for _depth, prefix in selected
        )
        try:
            rows = connection.execute(
                "WITH RECURSIVE affected(offset, prefix_bytes, prefix) AS ("
                "SELECT 1, unicode(substr(?1, 1, 1)) - 1, "
                "substr(?1, 2, unicode(substr(?1, 1, 1)) - 1) "
                "UNION ALL SELECT offset + 1 + prefix_bytes, "
                "unicode(substr(?1, offset + 1 + prefix_bytes, 1)) - 1, "
                "substr(?1, offset + 2 + prefix_bytes, "
                "unicode(substr(?1, offset + 1 + prefix_bytes, 1)) - 1) "
                "FROM affected WHERE offset + 1 + prefix_bytes <= length(?1)) "
                "SELECT node.depth, node.prefix, node.digest, node.children "
                "FROM affected CROSS JOIN node "
                "WHERE node.depth = affected.prefix_bytes * 8 "
                "AND node.prefix = affected.prefix",
                (path_payload,),
            ).fetchall()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError(
                "state binding storage union rows are unreadable"
            ) from exc
        observed: dict[tuple[int, bytes], tuple[bytes, dict[int, bytes]]] = {}
        for depth, prefix, node_digest, children_payload in rows:
            identity = (depth, prefix)
            if (
                identity not in selected_set
                or identity in observed
                or not isinstance(node_digest, bytes)
                or len(node_digest) != 32
                or not isinstance(children_payload, bytes)
            ):
                raise DerivedCheckpointError("state binding storage union row is invalid")
            children = _decode_state_storage_children(children_payload)
            if depth == _STATE_TREE_DEPTH:
                if children:
                    raise DerivedCheckpointError("state binding leaf row has children")
            else:
                child_default = _STATE_DEFAULT_DIGESTS[
                    depth + _STATE_BINDING_STORAGE_STRIDE
                ]
                if any(value == child_default for value in children.values()):
                    raise DerivedCheckpointError(
                        "state binding storage row retains a default child"
                    )
                if _state_storage_parent_digest(depth, children) != node_digest:
                    raise DerivedCheckpointError(
                        "state binding storage row digest mismatch"
                    )
            if node_digest == _STATE_DEFAULT_DIGESTS[depth]:
                raise DerivedCheckpointError("state binding storage retains a default row")
            observed[identity] = (node_digest, children)
        return observed

    def _stage_state_binding_delta(
        self,
        generation: str,
        delta: tuple[dict[str, Any], ...],
        *,
        prior_sequence: int,
        prior_root_digest: str | None,
        prior_update_count: int,
    ) -> tuple[str, dict[tuple[int, bytes], tuple[bytes, bytes]]]:
        connection = self._state_binding_connection(generation)
        overlay: dict[tuple[int, bytes], tuple[bytes, bytes]] = {}
        current_root = bytes.fromhex(
            _EMPTY_STATE_BINDING_DIGEST
            if prior_root_digest is None
            else prior_root_digest
        )
        try:
            expected_binding = (
                _STATE_BINDING_INDEX_VERSION,
                _STATE_BINDING_ALGORITHM,
                self.active_activation_digest,
                self.activation_record_digest,
                self.implementation_closure_digest,
                generation,
                prior_sequence,
                prior_update_count,
                current_root.hex(),
            )
            if self._state_binding_binding(connection) != expected_binding:
                raise DerivedCheckpointError("state binding index is not at the previous HEAD")
            leaf_keys = tuple(_state_leaf_key_digest(update) for update in delta)
            if len(leaf_keys) != len(set(leaf_keys)):
                raise DerivedCheckpointError("state binding leaf keys collide")
            path_rows = self._state_storage_union_rows(
                connection,
                leaf_keys,
            )
            changed: dict[bytes, tuple[bytes, bytes]] = {}
            for update in delta:
                key_digest = _state_leaf_key_digest(update)
                leaf_digest = (
                    _state_leaf_digest(key_digest, update["value_digest"])
                    if update["operation"] == "set"
                    else _STATE_DEFAULT_DIGESTS[_STATE_TREE_DEPTH]
                )
                old_leaf = path_rows.get(
                    (_STATE_TREE_DEPTH, key_digest),
                    (_STATE_DEFAULT_DIGESTS[_STATE_TREE_DEPTH], {}),
                )[0]
                changed[key_digest] = (old_leaf, leaf_digest)
                overlay[(_STATE_TREE_DEPTH, key_digest)] = (leaf_digest, b"")

            for parent_depth in range(
                _STATE_TREE_DEPTH - _STATE_BINDING_STORAGE_STRIDE,
                -1,
                -_STATE_BINDING_STORAGE_STRIDE,
            ):
                grouped: dict[bytes, dict[int, tuple[bytes, bytes]]] = {}
                for child_prefix, pair in changed.items():
                    parent_prefix = child_prefix[:-1]
                    grouped.setdefault(parent_prefix, {})[child_prefix[-1]] = pair
                next_changed: dict[bytes, tuple[bytes, bytes]] = {}
                child_default = _STATE_DEFAULT_DIGESTS[
                    parent_depth + _STATE_BINDING_STORAGE_STRIDE
                ]
                for parent_prefix in sorted(grouped):
                    old_parent, existing_children = path_rows.get(
                        (parent_depth, parent_prefix),
                        (_STATE_DEFAULT_DIGESTS[parent_depth], {}),
                    )
                    children = dict(existing_children)
                    for edge, (old_child, new_child) in grouped[parent_prefix].items():
                        if children.get(edge, child_default) != old_child:
                            raise DerivedCheckpointError(
                                "state binding touched-path proof differs from stored child"
                            )
                        if new_child == child_default:
                            children.pop(edge, None)
                        else:
                            children[edge] = new_child
                    new_parent = _state_storage_parent_digest(parent_depth, children)
                    children_payload = _encode_state_storage_children(children)
                    overlay[(parent_depth, parent_prefix)] = (
                        new_parent,
                        children_payload,
                    )
                    next_changed[parent_prefix] = (old_parent, new_parent)
                changed = next_changed
            root_pair = changed.get(b"")
            if root_pair is None or root_pair[0] != current_root:
                raise DerivedCheckpointError(
                    "state binding touched-path proof differs from current root"
                )
            return root_pair[1].hex(), overlay
        finally:
            connection.close()

    def _publish_state_binding_delta(
        self,
        generation: str,
        *,
        sequence: int,
        prior_root_digest: str | None,
        prior_update_count: int,
        root_digest: str,
        delta_count: int,
        overlay: Mapping[tuple[int, bytes], tuple[bytes, bytes]],
    ) -> tuple[int, int]:
        connection = self._state_binding_connection(generation)
        previous_root = (
            _EMPTY_STATE_BINDING_DIGEST
            if prior_root_digest is None
            else prior_root_digest
        )
        try:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            expected_binding = (
                _STATE_BINDING_INDEX_VERSION,
                _STATE_BINDING_ALGORITHM,
                self.active_activation_digest,
                self.activation_record_digest,
                self.implementation_closure_digest,
                generation,
                sequence - 1,
                prior_update_count,
                previous_root,
            )
            if self._state_binding_binding(connection) != expected_binding:
                raise DerivedCheckpointError("state binding index publication is stale")
            root_row = overlay.get((0, b""))
            if root_row is None or root_row[0].hex() != root_digest:
                raise DerivedCheckpointError(
                    "state binding overlay root differs from publication binding"
                )
            deletes: list[tuple[int, bytes]] = []
            upserts: list[tuple[int, bytes, bytes, bytes]] = []
            for (depth, prefix), (node_digest, children_payload) in sorted(
                overlay.items(), key=lambda item: (item[0][0], item[0][1])
            ):
                if (
                    depth < 0
                    or depth > _STATE_TREE_DEPTH
                    or depth % _STATE_BINDING_STORAGE_STRIDE != 0
                    or not isinstance(prefix, bytes)
                    or len(prefix) != depth // 8
                    or not isinstance(node_digest, bytes)
                    or len(node_digest) != 32
                ):
                    raise DerivedCheckpointError("state binding overlay row is invalid")
                children = _decode_state_storage_children(children_payload)
                if depth == _STATE_TREE_DEPTH:
                    if children:
                        raise DerivedCheckpointError(
                            "state binding overlay leaf has children"
                        )
                else:
                    child_default = _STATE_DEFAULT_DIGESTS[
                        depth + _STATE_BINDING_STORAGE_STRIDE
                    ]
                    if any(value == child_default for value in children.values()):
                        raise DerivedCheckpointError(
                            "state binding overlay retains a default child"
                        )
                    if _state_storage_parent_digest(depth, children) != node_digest:
                        raise DerivedCheckpointError(
                            "state binding overlay children differ from their digest"
                        )
                if node_digest == _STATE_DEFAULT_DIGESTS[depth]:
                    deletes.append((depth, prefix))
                else:
                    upserts.append(
                        (depth, prefix, node_digest, children_payload)
                    )
            if deletes:
                connection.executemany(
                    "DELETE FROM node WHERE depth = ? AND prefix = ?",
                    deletes,
                )
            if upserts:
                connection.executemany(
                    "INSERT INTO node(depth, prefix, digest, children) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(depth, prefix) DO UPDATE SET "
                    "digest=excluded.digest, children=excluded.children",
                    upserts,
                )
            connection.execute(
                "UPDATE binding SET head_sequence = ?, update_count = ?, "
                "root_digest = ? WHERE singleton = 1",
                (sequence, prior_update_count + delta_count, root_digest),
            )
            connection.execute("COMMIT")
        except DerivedCheckpointError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise DerivedCheckpointError("state binding index publication failed") from exc
        finally:
            connection.close()
        logical_bytes = sum(
            2 + len(prefix) + len(node_digest) + len(children_payload)
            for (depth, prefix), (node_digest, children_payload) in overlay.items()
        )
        return logical_bytes, len(overlay)

    def _validate_state_binding_index(
        self,
        generation: str,
        *,
        head_sequence: int,
        update_count: int,
        root_digest: str | None,
    ) -> None:
        connection = self._state_binding_connection(generation)
        expected_root = (
            _EMPTY_STATE_BINDING_DIGEST if root_digest is None else root_digest
        )
        try:
            expected = (
                _STATE_BINDING_INDEX_VERSION,
                _STATE_BINDING_ALGORITHM,
                self.active_activation_digest,
                self.activation_record_digest,
                self.implementation_closure_digest,
                generation,
                head_sequence,
                update_count,
                expected_root,
            )
            if self._state_binding_binding(connection) != expected:
                raise DerivedCheckpointError("state binding index binding is stale")
            if self._compact_state_binding_binding(connection) != (
                _STATE_BINDING_COMPACT_PARTITION_DEPTH,
                head_sequence,
                update_count,
                expected_root,
            ):
                raise DerivedCheckpointError(
                    "compact state binding index binding is stale"
                )
            root_node = self._state_storage_rows(connection, 0, (b"",))[b""][0]
            if root_node.hex() != expected_root:
                raise DerivedCheckpointError("state binding index root node is stale")
        finally:
            connection.close()

    def _publish_event_identities(
        self,
        generation: str,
        *,
        sequence: int,
        package_name: str,
        event_ids: list[str],
        prior_event_count: int,
    ) -> None:
        connection = self._event_identity_connection(generation)
        try:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            binding = self._event_identity_binding(connection)
            expected_binding = (
                _EVENT_IDENTITY_INDEX_VERSION,
                self.active_activation_digest,
                self.implementation_closure_digest,
                generation,
                sequence - 1,
                prior_event_count,
            )
            if binding != expected_binding:
                raise DerivedCheckpointError("event identity index is not at the previous HEAD")
            connection.executemany(
                "INSERT INTO event_identity(event_id, package_name) VALUES (?, ?)",
                ((event_id, package_name) for event_id in event_ids),
            )
            connection.execute(
                "UPDATE binding SET head_sequence = ?, event_count = ? WHERE singleton = 1",
                (sequence, prior_event_count + len(event_ids)),
            )
            connection.execute("COMMIT")
        except DerivedCheckpointError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.IntegrityError as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise DerivedCheckpointError("derived event identity already exists") from exc
        except sqlite3.Error as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise DerivedCheckpointError("event identity index publication failed") from exc
        finally:
            connection.close()

    def _event_identity_package(self, generation: str, identity: Any) -> str | None:
        if not isinstance(identity, str) or not _ID.fullmatch(identity):
            raise DerivedCheckpointError("event identity lookup is invalid")
        connection = self._event_identity_connection(generation)
        try:
            row = connection.execute(
                "SELECT package_name FROM event_identity WHERE event_id = ?",
                (identity,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("event identity index lookup failed") from exc
        finally:
            connection.close()
        if row is None:
            return None
        if len(row) != 1 or not isinstance(row[0], str) or Path(row[0]).name != row[0]:
            raise DerivedCheckpointError("event identity index package binding is invalid")
        return row[0]

    def _write_envelope_index_entries(
        self,
        envelope: Mapping[str, Any],
        envelope_path: Path,
        batch_digest: str,
        command_effect_digest: str,
        result: Mapping[str, Any],
        generation: str,
        *,
        prior_event_count: int | None = None,
    ) -> int:
        command = envelope["command"]
        batch = envelope["batch"]
        command_value = {
            "commit_effect_digest": command_effect_digest,
            "result": copy.deepcopy(dict(result)),
        }
        entries: list[dict[str, Any]] = []

        def add(kind: str, identity: Any, value: Mapping[str, Any]) -> None:
            entry = {
                "record_type": "DerivedEventIndexEntry",
                "version": 1,
                "authoritative": False,
                "activation_digest": self.active_activation_digest,
                "index_generation": generation,
                "index_kind": kind,
                "identity": copy.deepcopy(identity),
                "sequence": batch["sequence"],
                "batch_digest": batch_digest,
                "journal_file": envelope_path.name,
                "value": copy.deepcopy(dict(value)),
            }
            entry["entry_digest"] = digest_value(entry)
            entries.append(entry)

        add("command", command["command_id"], command_value)
        idempotency_identity = [
            command["activation_digest"],
            command["subject_id"],
            command["idempotency_key"],
        ]
        add("idempotency", idempotency_identity, command_value)
        add("batch", batch["batch_id"], {"present": True})
        add("batch-digest", batch_digest, {"present": True})
        for event in batch["events"]:
            add("event", event["event_id"], {"present": True})

        package = {
            "record_type": "DerivedEventIndexBatch",
            "version": 1,
            "authoritative": False,
            "activation_digest": self.active_activation_digest,
            "index_generation": generation,
            "sequence": batch["sequence"],
            "batch_digest": batch_digest,
            "journal_file": envelope_path.name,
            "entry_count": len(entries),
            "entries": entries,
        }
        package["index_batch_digest"] = digest_value(package)
        payload = canonical_bytes(package)
        package_root = self.index_root / generation / "packages"
        os.makedirs(_native_os_path(package_root), exist_ok=True)
        package_path = package_root / (
            f"{batch['sequence']:020d}-{batch_digest}.json"
        )
        _write_atomic(package_path, payload)
        published_directories: set[Path] = set()
        for entry in entries:
            if entry["index_kind"] == "event":
                continue
            alias = self._index_entry_path(
                generation, entry["index_kind"], entry["identity"]
            )
            os.makedirs(_native_os_path(alias.parent), exist_ok=True)
            try:
                os.link(_native_os_path(package_path), _native_os_path(alias))
            except FileExistsError as exc:
                raise DerivedCheckpointError(
                    "derived index identity already exists"
                ) from exc
            published_directories.add(alias.parent)
        for directory in sorted(published_directories, key=lambda value: str(value)):
            _fsync_directory(directory)
        self._publish_event_identities(
            generation,
            sequence=batch["sequence"],
            package_name=package_path.name,
            event_ids=[event["event_id"] for event in batch["events"]],
            prior_event_count=(
                self._event_count
                if prior_event_count is None
                else prior_event_count
            ),
        )
        identity_bytes = sum(
            len(event["event_id"].encode("utf-8"))
            + len(package_path.name.encode("utf-8"))
            for event in batch["events"]
        )
        return len(payload) + identity_bytes

    def _read_index_entry(self, kind: str, identity: Any) -> dict[str, Any] | None:
        generation = self._index_generation
        if generation is None:
            raise DerivedCheckpointError("event index generation is unavailable")
        if kind == "event":
            package_name = self._event_identity_package(generation, identity)
            if package_name is None:
                return None
            path = self.index_root / generation / "packages" / package_name
        else:
            path = self._index_entry_path(generation, kind, identity)
        if not _path_exists(path):
            return None
        record = self._read_canonical_object(path, limits=_DERIVED_STATE_LIMITS)
        package_binding: tuple[int, str, str] | None = None
        if record.get("record_type") == "DerivedEventIndexBatch":
            batch_fields = {
                "record_type",
                "version",
                "authoritative",
                "activation_digest",
                "index_generation",
                "sequence",
                "batch_digest",
                "journal_file",
                "entry_count",
                "entries",
                "index_batch_digest",
            }
            supplied_batch_digest = record.pop("index_batch_digest", None)
            entries = record.get("entries")
            if (
                set(record) | {"index_batch_digest"} != batch_fields
                or record.get("version") != 1
                or record.get("authoritative") is not False
                or record.get("activation_digest") != self.active_activation_digest
                or record.get("index_generation") != generation
                or not isinstance(entries, list)
                or not 5 <= len(entries) <= self.max_events_per_batch + 4
                or record.get("entry_count") != len(entries)
                or not isinstance(supplied_batch_digest, str)
                or digest_value(record) != supplied_batch_digest
            ):
                raise DerivedCheckpointError("event index batch fields mismatch")
            matches = [
                value
                for value in entries
                if isinstance(value, dict)
                and value.get("index_kind") == kind
                and value.get("identity") == identity
            ]
            if len(matches) != 1:
                raise DerivedCheckpointError(
                    "event index batch does not contain one exact identity"
                )
            entry = copy.deepcopy(matches[0])
            package_binding = (
                record["sequence"],
                record["batch_digest"],
                record["journal_file"],
            )
        else:
            entry = record
        required = {
            "record_type", "version", "authoritative", "activation_digest", "index_generation",
            "index_kind", "identity", "sequence", "batch_digest", "journal_file", "value",
            "entry_digest",
        }
        if set(entry) != required or entry.get("record_type") != "DerivedEventIndexEntry":
            raise DerivedCheckpointError("event index entry fields mismatch")
        supplied_digest = entry.pop("entry_digest")
        if not isinstance(supplied_digest, str) or digest_value(entry) != supplied_digest:
            raise DerivedCheckpointError("event index entry digest mismatch")
        entry["entry_digest"] = supplied_digest
        if (
            entry["version"] != 1
            or entry["authoritative"] is not False
            or entry["activation_digest"] != self.active_activation_digest
            or entry["index_generation"] != generation
            or entry["index_kind"] != kind
            or entry["identity"] != identity
        ):
            raise DerivedCheckpointError("event index entry binding mismatch")
        sequence = entry["sequence"]
        file_name = entry["journal_file"]
        if (
            not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or not 1 <= sequence <= self._head["sequence"]
            or not isinstance(entry["batch_digest"], str)
            or not _DIGEST.fullmatch(entry["batch_digest"])
            or not isinstance(file_name, str)
            or Path(file_name).name != file_name
            or not file_name.startswith(f"{sequence:020d}-")
            or not isinstance(entry["value"], dict)
        ):
            raise DerivedCheckpointError("event index entry value is invalid")
        if package_binding is not None and package_binding != (
            sequence,
            entry["batch_digest"],
            file_name,
        ):
            raise DerivedCheckpointError("event index batch binding mismatch")
        envelope = self._read_envelope(self.journal / file_name)
        batch = envelope["batch"]
        actual_batch_digest = self._validate_envelope(
            envelope,
            expected_sequence=sequence,
            expected_previous_digest=batch.get("previous_digest"),
            validate_runtime=False,
        )
        if actual_batch_digest != entry["batch_digest"]:
            raise DerivedCheckpointError("event index entry journal digest mismatch")
        command = envelope["command"]
        command_effect_digest = _commit_effect_digest(
            command,
            [event["payload"] for event in batch["events"] if event["event_kind"] == "relation.recorded"],
        )
        expected_result = self._result(command, actual_batch_digest, "committed", batch)
        if kind == "command":
            actual_identity = command["command_id"]
            expected_value = {"commit_effect_digest": command_effect_digest, "result": expected_result}
        elif kind == "idempotency":
            actual_identity = [command["activation_digest"], command["subject_id"], command["idempotency_key"]]
            expected_value = {"commit_effect_digest": command_effect_digest, "result": expected_result}
        elif kind == "batch":
            actual_identity = batch["batch_id"]
            expected_value = {"present": True}
        elif kind == "batch-digest":
            actual_identity = actual_batch_digest
            expected_value = {"present": True}
        elif kind == "event":
            actual_identity = identity if any(event["event_id"] == identity for event in batch["events"]) else None
            expected_value = {"present": True}
        else:
            raise DerivedCheckpointError("event index kind is unknown")
        if actual_identity != identity or entry["value"] != expected_value:
            raise DerivedCheckpointError("event index entry differs from authoritative envelope")
        return entry

    def _indexed_command(self, command_id: str) -> tuple[str, dict[str, Any]] | None:
        existing = self._command_ids.get(command_id)
        if existing is not None:
            return existing
        entry = self._read_index_entry("command", command_id)
        if entry is None:
            return None
        value = entry["value"]
        existing = (value["commit_effect_digest"], copy.deepcopy(value["result"]))
        self._command_ids[command_id] = existing
        return existing

    def _indexed_idempotency(self, identity: tuple[str, str, str]) -> tuple[str, dict[str, Any]] | None:
        existing = self._idempotency.get(identity)
        if existing is not None:
            return existing
        entry = self._read_index_entry("idempotency", list(identity))
        if entry is None:
            return None
        value = entry["value"]
        existing = (value["commit_effect_digest"], copy.deepcopy(value["result"]))
        self._idempotency[identity] = existing
        return existing

    def _indexed_identity_exists(self, kind: str, identity: str) -> bool:
        in_memory = identity in (self._batch_ids if kind == "batch" else self._event_ids)
        if in_memory:
            return True
        return self._read_index_entry(kind, identity) is not None

    def _existing_event_identities(self, identities: list[str]) -> set[str]:
        existing = set(identities) & self._event_ids
        pending = sorted(set(identities) - existing)
        if not pending:
            return existing
        generation = self._index_generation
        if generation is None:
            raise DerivedCheckpointError("event index generation is unavailable")
        if any(not _ID.fullmatch(identity) for identity in pending):
            raise DerivedCheckpointError("event identity lookup is invalid")
        connection = self._event_identity_connection(generation)
        try:
            placeholders = ",".join("?" for _ in pending)
            rows = connection.execute(
                f"SELECT event_id FROM event_identity WHERE event_id IN ({placeholders})",
                pending,
            ).fetchall()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("event identity index lookup failed") from exc
        finally:
            connection.close()
        for row in rows:
            if len(row) != 1 or row[0] not in pending:
                raise DerivedCheckpointError("event identity index lookup is inconsistent")
            existing.add(row[0])
        return existing

    def _commit_read_view_locked(self) -> CommitReadView:
        base = CommitReadView(
            activation_digest=self.active_activation_digest,
            implementation_closure_digest=self.implementation_closure_digest,
            head_sequence=self._head["sequence"],
            head_batch_id=self._head["batch_id"],
            head_digest=self._head["batch_digest"],
            batch_count=self._batch_count,
            event_count=self._event_count,
            event_semantic_digest=self._semantic_digest,
            authority_prefix_digest=self._authority_prefix_digest,
            current_state_binding_digest=self._state_binding_digest,
            current_state_binding_trusted=self._state_binding_digest is not None,
            state=None,
        )
        if self.commit_state_loader is None:
            raise EventStoreError(
                "authoritative commit requires a journal state loader"
            )
        loaded = self.commit_state_loader(
            base,
            lambda: self._iter_envelopes_locked(validate=False),
        )
        if not isinstance(loaded, CommitStateSnapshot):
            raise EventStoreError(
                "journal state loader must return CommitStateSnapshot"
            )
        if (
            loaded.head_sequence != base.head_sequence
            or loaded.head_digest != base.head_digest
            or loaded.state_binding_digest != base.current_state_binding_digest
        ):
            raise JournalCorruption("journal state loader returned a stale state binding")
        if isinstance(loaded.state, (dict, list, set, bytearray)):
            raise EventStoreError("journal state loader returned mutable state")
        return CommitReadView(
            activation_digest=base.activation_digest,
            implementation_closure_digest=base.implementation_closure_digest,
            head_sequence=base.head_sequence,
            head_batch_id=base.head_batch_id,
            head_digest=base.head_digest,
            batch_count=base.batch_count,
            event_count=base.event_count,
            event_semantic_digest=base.event_semantic_digest,
            authority_prefix_digest=base.authority_prefix_digest,
            current_state_binding_digest=base.current_state_binding_digest,
            current_state_binding_trusted=True,
            state=loaded.state,
        )

    def _prepare_commit_locked(
        self,
        callback: Callable[..., PreparedCommit] | None,
        command: dict[str, Any],
        relations: list[dict[str, Any]],
    ) -> _ValidatedPreparedCommit:
        if callback is None:
            raise EventStoreError(
                "authoritative commit requires a state-bound prepare callback"
            )
        view = self._commit_read_view_locked()
        prepared = callback(
            view,
            _deep_freeze(copy.deepcopy(command)),
            _deep_freeze(copy.deepcopy(relations)),
        )
        if not isinstance(prepared, PreparedCommit):
            raise EventStoreError("commit prepare callback must return PreparedCommit")
        normalized_relations: list[dict[str, Any]] = []
        for relation in prepared.auxiliary_relations:
            try:
                relation_limits = ParseLimits(
                    max_bytes=self.policy.max_envelope_bytes
                )
                normalized = parse_json_strict(
                    canonical_bytes(dict(relation), limits=relation_limits),
                    limits=relation_limits,
                )
            except (CanonicalError, TypeError, ValueError) as exc:
                raise EventStoreError(
                    f"prepared Relation is not bounded canonical JSON: {exc}"
                ) from exc
            normalized_relations.append(normalized)
        if normalized_relations != relations:
            raise EventStoreError(
                "commit prepare callback changed the staged auxiliary Relations"
            )
        normalized_delta = _normalize_state_binding_delta(
            prepared.state_binding_delta,
            policy=self.policy,
        )
        _validate_state_binding_event_correspondence(
            normalized_delta,
            (
                (
                    self.policy.primary_events[command["command_kind"]],
                    command["payload"],
                ),
                *(
                    ("relation.recorded", relation)
                    for relation in normalized_relations
                ),
            ),
            policy=self.policy,
        )
        return _ValidatedPreparedCommit(
            tuple(normalized_relations),
            normalized_delta,
        )

    def _finish_durable_commit_after_non_authoritative_failure_locked(
        self,
        *,
        failure: Exception,
        envelope: Mapping[str, Any],
        payload: bytes,
        journal_path: Path,
        new_head: Mapping[str, Any],
        authority_segment: Mapping[str, Any],
        authority_root: Mapping[str, Any],
        result: Mapping[str, Any],
        command_effect_digest: str,
    ) -> dict[str, Any]:
        """Resolve an exact durable append after non-authoritative failure.

        ``HEAD.json`` is the commit linearization point.  Once it names this
        envelope, a later index/checkpoint/control/cleanup failure must not be
        reported as if the command rolled back.  Re-verify the complete
        journal-owned prefix under the still-held writer lock and invalidate
        the entire derived-index generation rather than trusting unknown
        partial finalization.  An existing pending marker is left for recovery;
        if unlink completed before its directory fsync failed, the exact bound
        checkpoint permits either durable directory outcome on reopen.
        """

        self._clear_committed_envelope_witness()
        checked_head = self._validate_head_value(dict(new_head))
        try:
            if self._read_disk_head() != checked_head:
                raise JournalCorruption(
                    "durable HEAD changed after non-authoritative finalization failed"
                )
            if _read_bytes(journal_path) != payload:
                raise JournalCorruption(
                    "durable journal bytes changed after non-authoritative finalization failed"
                )
            checked_envelope = self._read_envelope(journal_path)
            if checked_envelope != dict(envelope):
                raise JournalCorruption(
                    "durable envelope changed after non-authoritative finalization failed"
                )
            batch = checked_envelope["batch"]
            actual_batch_digest = self._validate_envelope(
                checked_envelope,
                expected_sequence=checked_head["sequence"],
                expected_previous_digest=batch.get("previous_digest"),
                validate_runtime=False,
            )
            if (
                batch["batch_id"] != checked_head["batch_id"]
                or actual_batch_digest != checked_head["batch_digest"]
            ):
                raise JournalCorruption(
                    "durable envelope differs from HEAD after non-authoritative failure"
                )
            verified_authority_root = self._verify_authority_prefix_locked(
                checked_head
            )
            if verified_authority_root != dict(authority_root):
                raise JournalCorruption(
                    "durable authority root changed after non-authoritative failure"
                )
        except (
            CanonicalError,
            DerivedCheckpointError,
            JournalCorruption,
            OSError,
        ) as authority_failure:
            raise JournalCorruption(
                "durable commit could not be resolved after non-authoritative "
                f"finalization failed: {type(failure).__name__}: {failure}"
            ) from authority_failure

        command = checked_envelope["command"]
        id_key = (
            command["activation_digest"],
            command["subject_id"],
            command["idempotency_key"],
        )
        checked_result = copy.deepcopy(dict(result))
        self._head = checked_head
        self._batch_count = checked_head["sequence"]
        self._event_count = batch["cumulative_event_count"]
        self._semantic_digest = batch["event_semantic_digest"]
        self._authority_generation = verified_authority_root["generation"]
        self._authority_prefix_digest = batch["authority_commitment"]
        self._state_binding_digest = batch["state_binding_digest"]
        self._state_binding_update_count = batch[
            "cumulative_state_binding_update_count"
        ]
        # The failed generation may contain any prefix of the attempted
        # publications.  No caller may consult it again.
        self._index_generation = None
        self._command_ids[command["command_id"]] = (
            command_effect_digest,
            checked_result,
        )
        self._idempotency[id_key] = (command_effect_digest, checked_result)
        self._batch_ids.add(batch["batch_id"])
        self._event_ids.update(event["event_id"] for event in batch["events"])
        self._open_mode = "authority-only-derived-unavailable"
        self._fallback_reason = (
            "post-HEAD non-authoritative finalization failed; authority was verified: "
            f"{type(failure).__name__}: {failure}"
        )

        authority_bytes = len(canonical_bytes(dict(authority_segment))) + len(
            canonical_bytes(verified_authority_root)
        )
        head_bytes = len(canonical_bytes(checked_head))
        logical_final_bytes = len(payload) + head_bytes + authority_bytes
        self._last_commit_write_metrics = {
            "changed_records": len(batch["events"]),
            "journal_authority_bytes": len(payload),
            "temporary_staging_bytes": len(payload),
            "head_bytes": head_bytes,
            "derived_index_bytes": 0,
            "journal_checkpoint_bytes": 0,
            "state_binding_index_bytes": 0,
            "state_binding_updates": len(batch["state_binding_delta"]),
            "state_binding_node_writes": 0,
            "journal_checkpoint_writes": 0,
            "logical_final_bytes": logical_final_bytes,
            "physical_payload_bytes": logical_final_bytes + len(payload),
        }
        return copy.deepcopy(checked_result)

    def commit(
        self,
        command: Mapping[str, Any],
        *,
        auxiliary_relations: Iterable[Mapping[str, Any]] = (),
        created_at: str | None = None,
        crash_hook: Callable[[str], Any] | None = None,
    ) -> dict[str, Any]:
        # A prior continuation is valid for one exact post-commit read only;
        # even a rejected later mutation must not extend that window.
        self._clear_committed_envelope_witness()
        try:
            command_payload = canonical_bytes(
                dict(command), limits=ParseLimits(max_bytes=self.policy.max_command_bytes)
            )
        except (CanonicalError, TypeError, ValueError) as exc:
            raise EventStoreError(f"command is not bounded canonical JSON: {exc}") from exc
        relation_inputs = list(
            itertools.islice(auxiliary_relations, self.max_events_per_batch)
        )
        if len(relation_inputs) + 1 > self.max_events_per_batch:
            raise EventStoreError("atomic batch exceeds the event ceiling")
        relations: list[dict[str, Any]] = []
        for relation in relation_inputs:
            try:
                relation_limits = ParseLimits(
                    max_bytes=self.policy.max_envelope_bytes
                )
                relations.append(
                    parse_json_strict(
                        canonical_bytes(dict(relation), limits=relation_limits),
                        limits=relation_limits,
                    )
                )
            except (CanonicalError, TypeError, ValueError) as exc:
                raise EventStoreError(
                    f"auxiliary Relation is not bounded canonical JSON: {exc}"
                ) from exc
        phase_token = self._verified_commit_phase_token
        if phase_token is not None and self._verified_commit_phase_in_progress is not True:
            raise EventStoreError("verified commit phase operation is not active")
        writer_scope = (
            contextlib.nullcontext()
            if phase_token is not None
            else _WriterLock(self.lock_path, self.lock_timeout)
        )
        with writer_scope:
            self._last_commit_write_metrics = self._empty_commit_write_metrics()
            if phase_token is None:
                self._refresh_from_disk_locked()
            normalized = normalize_command(
                parse_json_strict(
                    command_payload,
                    limits=ParseLimits(max_bytes=self.policy.max_command_bytes),
                ),
                policy=self.policy,
            )
            if normalized["activation_digest"] != self.active_activation_digest:
                raise CommandConflict("command Activation is not current")
            _invoke_compiled_record_validator(
                self.compiled_record_validator,
                "CommandRequest",
                normalized,
                evaluation_time=normalized["issued_at"],
                operation="commit",
            )
            relation_ids = [relation.get("relation_id") for relation in relations]
            if len(relation_ids) != len(set(relation_ids)):
                raise EventStoreError("auxiliary Relation IDs must be unique")
            command_digest = _commit_effect_digest(normalized, relations)
            try:
                existing = self._indexed_command(normalized["command_id"])
            except (DerivedCheckpointError, JournalCorruption) as exc:
                self._fallback_reason = f"{type(exc).__name__}: {exc}"
                self._recover_locked()
                self._open_mode = "full-replay-fallback"
                existing = self._indexed_command(normalized["command_id"])
            if existing is not None:
                if existing[0] == command_digest:
                    return self._as_idempotent(existing[1])
                raise CommandConflict("command_id is already bound to different content")
            id_key = (normalized["activation_digest"], normalized["subject_id"], normalized["idempotency_key"])
            try:
                existing = self._indexed_idempotency(id_key)
            except (DerivedCheckpointError, JournalCorruption) as exc:
                self._fallback_reason = f"{type(exc).__name__}: {exc}"
                self._recover_locked()
                self._open_mode = "full-replay-fallback"
                existing = self._indexed_idempotency(id_key)
            if existing is not None:
                if existing[0] == command_digest:
                    return self._as_idempotent(existing[1])
                raise CommandConflict("idempotency identity is already bound to different content")
            if normalized["expected_head_digest"] != self._head["batch_digest"]:
                raise CommandConflict("expected HEAD does not match current HEAD")
            prepared = self._prepare_commit_locked(
                self.commit_prepare_callback,
                normalized,
                relations,
            )
            relations = [copy.deepcopy(dict(value)) for value in prepared.auxiliary_relations]
            # Validate exactly once at the linearization point. Replay validates
            # again at the original event time, but a live commit must not
            # consume a stateful authorization/nonce validator twice.
            _invoke_validator(self.command_validator, normalized, evaluation_time=normalized["issued_at"])
            _invoke_validator(self.authorization_validator, normalized, evaluation_time=normalized["issued_at"])
            committed_at = created_at or utc_now()
            if parse_timestamp(committed_at) < parse_timestamp(normalized["issued_at"]):
                raise EventStoreError("batch cannot predate its command")
            if self._index_generation is None:
                raise DerivedCheckpointError("event index generation is unavailable")
            state_generation = self._index_generation
            prior_state_binding_digest = self._state_binding_digest
            prior_state_binding_update_count = self._state_binding_update_count
            try:
                state_binding_digest, state_binding_overlay = (
                    self._stage_compact_state_binding_delta(
                        state_generation,
                        prepared.state_binding_delta,
                        prior_sequence=self._head["sequence"],
                        prior_root_digest=prior_state_binding_digest,
                        prior_update_count=prior_state_binding_update_count,
                    )
                )
            except DerivedCheckpointError as exc:
                self._fallback_reason = f"{type(exc).__name__}: {exc}"
                self._recover_locked()
                self._open_mode = "full-replay-fallback"
                if self._index_generation is None:
                    raise DerivedCheckpointError("event index generation is unavailable")
                state_generation = self._index_generation
                prior_state_binding_digest = self._state_binding_digest
                prior_state_binding_update_count = self._state_binding_update_count
                state_binding_digest, state_binding_overlay = (
                    self._stage_compact_state_binding_delta(
                        state_generation,
                        prepared.state_binding_delta,
                        prior_sequence=self._head["sequence"],
                        prior_root_digest=prior_state_binding_digest,
                        prior_update_count=prior_state_binding_update_count,
                    )
                )
            envelope = self._build_envelope(
                normalized,
                relations,
                committed_at,
                command_digest,
                prepared.state_binding_delta,
                state_binding_digest,
            )
            batch = envelope["batch"]
            batch_digest = self._validate_envelope(
                envelope,
                expected_sequence=self._head["sequence"] + 1,
                expected_previous_digest=self._head["batch_digest"],
                validate_runtime=False,
                validation_operation="commit",
            )
            for event in batch["events"]:
                _invoke_validator(self.event_validator, event, evaluation_time=committed_at, command=normalized)
            identity_index_recovered = False
            try:
                if self._indexed_identity_exists("batch", batch["batch_id"]):
                    raise CommandConflict("batch_id collision")
                if self._existing_event_identities(
                    [event["event_id"] for event in batch["events"]]
                ):
                    raise CommandConflict("event_id collision")
            except (DerivedCheckpointError, JournalCorruption) as exc:
                self._fallback_reason = f"{type(exc).__name__}: {exc}"
                self._recover_locked()
                self._open_mode = "full-replay-fallback"
                identity_index_recovered = True
                if self._indexed_identity_exists("batch", batch["batch_id"]):
                    raise CommandConflict("batch_id collision")
                if self._existing_event_identities(
                    [event["event_id"] for event in batch["events"]]
                ):
                    raise CommandConflict("event_id collision")
            if identity_index_recovered:
                if self._index_generation is None:
                    raise DerivedCheckpointError("event index generation is unavailable")
                state_generation = self._index_generation
                prior_state_binding_digest = self._state_binding_digest
                prior_state_binding_update_count = self._state_binding_update_count
                recovered_root, state_binding_overlay = self._stage_compact_state_binding_delta(
                    state_generation,
                    prepared.state_binding_delta,
                    prior_sequence=self._head["sequence"],
                    prior_root_digest=prior_state_binding_digest,
                    prior_update_count=prior_state_binding_update_count,
                )
                if recovered_root != state_binding_digest:
                    raise JournalCorruption(
                        "state binding root changed during derived-index recovery"
                    )
            # Core IDs may contain ``:``; journal filenames remain portable.
            batch_file_id = hashlib.sha256(batch["batch_id"].encode("utf-8")).hexdigest()
            pending_path = self.pending / f"{batch_file_id}.json"
            journal_path = self.journal / f"{batch['sequence']:020d}-{batch_file_id}.json"
            try:
                payload = canonical_bytes(
                    envelope,
                    limits=ParseLimits(max_bytes=self.policy.max_envelope_bytes),
                )
            except CanonicalError as exc:
                raise EventStoreError(
                    f"journal envelope exceeds its canonical byte ceiling: {exc}"
                ) from exc
            _write_atomic(pending_path, payload)
            self._crash(crash_hook, "after_pending")
            _write_atomic(journal_path, payload)
            self._crash(crash_hook, "after_batch")
            new_head = {"sequence": batch["sequence"], "batch_id": batch["batch_id"], "batch_digest": batch_digest}
            if self._authority_generation is None:
                raise DerivedCheckpointError("journal prefix generation is unavailable")
            authority_segment = self._write_authority_segment(
                generation=self._authority_generation,
                envelope=envelope,
                journal_path=journal_path,
                journal_payload=payload,
            )
            self._crash(crash_hook, "after_authority_segment")
            authority_root = self._write_authority_root(
                generation=self._authority_generation,
                head=new_head,
                event_count=batch["cumulative_event_count"],
                event_semantic_digest=batch["event_semantic_digest"],
                authority_prefix_digest=batch["authority_commitment"],
                state_binding_digest=batch["state_binding_digest"],
                state_binding_update_count=batch[
                    "cumulative_state_binding_update_count"
                ],
            )
            self._crash(crash_hook, "after_authority_root")
            head_payload = canonical_bytes(new_head)
            _write_atomic(self.head_path, head_payload)
            self._crash(crash_hook, "after_head")
            self._crash(crash_hook, "before_checkpoint")
            result = self._result(normalized, batch_digest, "committed", batch)
            try:
                if self._index_generation is None:
                    raise DerivedCheckpointError(
                        "event index generation is unavailable"
                    )
                index_bytes = self._write_envelope_index_entries(
                    envelope,
                    journal_path,
                    batch_digest,
                    command_digest,
                    result,
                    self._index_generation,
                )
                state_index_bytes, state_node_writes = (
                    self._publish_compact_state_binding_delta(
                        state_generation,
                        sequence=batch["sequence"],
                        prior_root_digest=prior_state_binding_digest,
                        prior_update_count=prior_state_binding_update_count,
                        root_digest=batch["state_binding_digest"],
                        delta_count=len(prepared.state_binding_delta),
                        overlay=state_binding_overlay,
                    )
                )
            except (CanonicalError, DerivedCheckpointError, OSError) as exc:
                return self._finish_durable_commit_after_non_authoritative_failure_locked(
                    failure=exc,
                    envelope=envelope,
                    payload=payload,
                    journal_path=journal_path,
                    new_head=new_head,
                    authority_segment=authority_segment,
                    authority_root=authority_root,
                    result=result,
                    command_effect_digest=command_digest,
                )
            self._crash(crash_hook, "after_state_binding_index")
            index_bytes += state_index_bytes
            new_semantic_digest = batch["event_semantic_digest"]
            new_event_count = batch["cumulative_event_count"]
            new_state_binding_update_count = batch[
                "cumulative_state_binding_update_count"
            ]
            try:
                journal_checkpoint = self._write_journal_checkpoint(
                    head=new_head,
                    batch_count=new_head["sequence"],
                    event_count=new_event_count,
                    semantic_digest=new_semantic_digest,
                    index_generation=self._index_generation,
                    last_journal_file=journal_path.name,
                    last_journal_file_digest=hashlib.sha256(payload).hexdigest(),
                    authority_root=authority_root,
                    state_binding_update_count=new_state_binding_update_count,
                )
                journal_checkpoint_bytes = len(
                    canonical_bytes(journal_checkpoint)
                )
            except (
                CanonicalError,
                DerivedCheckpointError,
                JournalCorruption,
                OSError,
            ) as exc:
                return self._finish_durable_commit_after_non_authoritative_failure_locked(
                    failure=exc,
                    envelope=envelope,
                    payload=payload,
                    journal_path=journal_path,
                    new_head=new_head,
                    authority_segment=authority_segment,
                    authority_root=authority_root,
                    result=result,
                    command_effect_digest=command_digest,
                )
            self._crash(crash_hook, "after_checkpoint")
            try:
                _unlink(pending_path, missing_ok=True)
                _fsync_directory(self.pending)
            except OSError as exc:
                return self._finish_durable_commit_after_non_authoritative_failure_locked(
                    failure=exc,
                    envelope=envelope,
                    payload=payload,
                    journal_path=journal_path,
                    new_head=new_head,
                    authority_segment=authority_segment,
                    authority_root=authority_root,
                    result=result,
                    command_effect_digest=command_digest,
                )
            self._head = new_head
            self._batch_count = new_head["sequence"]
            self._event_count = new_event_count
            self._semantic_digest = new_semantic_digest
            self._authority_prefix_digest = batch["authority_commitment"]
            self._state_binding_digest = batch["state_binding_digest"]
            self._state_binding_update_count = new_state_binding_update_count
            self._command_ids[normalized["command_id"]] = (command_digest, result)
            self._idempotency[id_key] = (command_digest, result)
            self._batch_ids.add(batch["batch_id"])
            self._event_ids.update(event["event_id"] for event in batch["events"])
            authority_bytes = len(canonical_bytes(authority_segment)) + len(
                canonical_bytes(authority_root)
            )
            logical_final_bytes = (
                len(payload)
                + len(head_payload)
                + index_bytes
                + journal_checkpoint_bytes
                + authority_bytes
            )
            self._last_commit_write_metrics = {
                "changed_records": len(batch["events"]),
                "journal_authority_bytes": len(payload),
                "temporary_staging_bytes": len(payload),
                "head_bytes": len(head_payload),
                "derived_index_bytes": index_bytes,
                "journal_checkpoint_bytes": journal_checkpoint_bytes,
                "state_binding_index_bytes": state_index_bytes,
                "state_binding_updates": len(prepared.state_binding_delta),
                "state_binding_node_writes": state_node_writes,
                "journal_checkpoint_writes": 1,
                "logical_final_bytes": logical_final_bytes,
                "physical_payload_bytes": logical_final_bytes + len(payload),
            }
            self._record_committed_envelope_witness(
                envelope=envelope,
                payload=payload,
                journal_path=journal_path,
                head=new_head,
                authority_root=authority_root,
            )
            return copy.deepcopy(result)

    @staticmethod
    def _crash(hook: Callable[[str], Any] | None, point: str) -> None:
        if hook is not None and hook(point):
            raise SimulatedCrash(point)

    def _build_envelope(
        self,
        command: dict[str, Any],
        relations: list[dict[str, Any]],
        created_at: str,
        commit_effect_digest: str,
        state_binding_delta: tuple[dict[str, Any], ...],
        state_binding_digest: str,
    ) -> dict[str, Any]:
        command_digest = digest_value(command)
        batch_id = "b:" + hashlib.sha256((commit_effect_digest + ":batch").encode("ascii")).hexdigest()[:48]
        primary_id = "e:" + hashlib.sha256((commit_effect_digest + ":primary").encode("ascii")).hexdigest()[:48]
        events = [
            {
                "record_type": "Event",
                "event_id": primary_id,
                "event_kind": self.policy.primary_events[command["command_kind"]],
                "activation_digest": command["activation_digest"],
                "payload": copy.deepcopy(command["payload"]),
            }
        ]
        for relation in relations:
            self._validate_relation(relation, command["activation_digest"])
            relation_digest = digest_value(relation)
            events.append(
                {
                    "record_type": "Event",
                    "event_id": "e:" + hashlib.sha256((commit_effect_digest + ":relation:" + relation_digest).encode("ascii")).hexdigest()[:48],
                    "event_kind": "relation.recorded",
                    "activation_digest": command["activation_digest"],
                    "payload": relation,
                }
            )
        event_semantic_digest = self._semantic_digest
        for event in events:
            event_semantic_digest = _extend_event_semantic_digest(
                event_semantic_digest, event
            )
        cumulative_event_count = self._event_count + len(events)
        cumulative_state_binding_update_count = (
            self._state_binding_update_count + len(state_binding_delta)
        )
        authority_commitment = _authority_commitment(
            previous_commitment=self._authority_prefix_digest,
            sequence=self._head["sequence"] + 1,
            previous_batch_digest=self._head["batch_digest"],
            event_count=cumulative_event_count,
            event_semantic_digest=event_semantic_digest,
            state_binding_update_count=cumulative_state_binding_update_count,
            state_binding_digest=state_binding_digest,
        )
        batch = {
            "record_type": "EventBatch",
            "batch_id": batch_id,
            "sequence": self._head["sequence"] + 1,
            "previous_digest": self._head["batch_digest"],
            "created_at": created_at,
            "command_id": command["command_id"],
            "idempotency_key": command["idempotency_key"],
            "activation_record_digest": self.activation_record_digest,
            "events": events,
            "subject_id": command["subject_id"],
            "command_intent_digest": command["intent_digest"],
            "command_digest": command_digest,
            "authorization_digest": digest_value(command["authorization"]),
            "previous_authority_commitment": self._authority_prefix_digest,
            "authority_commitment": authority_commitment,
            "cumulative_event_count": cumulative_event_count,
            "event_semantic_digest": event_semantic_digest,
            "state_binding_delta": copy.deepcopy(list(state_binding_delta)),
            "cumulative_state_binding_update_count": (
                cumulative_state_binding_update_count
            ),
            "state_binding_digest": state_binding_digest,
        }
        return {"record_type": "JournalEnvelope", "command": command, "batch": batch}

    def _validate_envelope(
        self,
        envelope: dict[str, Any],
        *,
        expected_sequence: int,
        expected_previous_digest: str | None,
        validate_runtime: bool,
        validation_operation: str = "read",
    ) -> str:
        if set(envelope) != {"record_type", "command", "batch"} or envelope.get("record_type") != "JournalEnvelope":
            raise JournalCorruption("journal envelope fields mismatch")
        try:
            command = normalize_command(envelope["command"], policy=self.policy)
        except EventStoreError as exc:
            raise JournalCorruption(str(exc)) from exc
        _invoke_compiled_record_validator(
            self.compiled_record_validator,
            "CommandRequest",
            command,
            evaluation_time=command["issued_at"],
            operation=validation_operation,
            error_type=JournalCorruption,
        )
        batch = envelope["batch"]
        required = {
            "record_type", "batch_id", "sequence", "previous_digest", "created_at", "command_id",
            "idempotency_key", "activation_record_digest", "events", "subject_id", "command_intent_digest",
            "command_digest", "authorization_digest", "previous_authority_commitment",
            "authority_commitment", "cumulative_event_count", "event_semantic_digest",
            "state_binding_delta", "cumulative_state_binding_update_count",
            "state_binding_digest",
        }
        if not isinstance(batch, dict) or set(batch) != required or batch.get("record_type") != "EventBatch":
            raise JournalCorruption("EventBatch fields mismatch")
        if (
            batch["activation_record_digest"] != self.activation_record_digest
            or command["activation_digest"] != self.active_activation_digest
        ):
            raise JournalCorruption("journal Activation mismatch")
        if batch["sequence"] != expected_sequence or batch["previous_digest"] != expected_previous_digest:
            raise JournalCorruption("journal chain mismatch")
        if not _ID.fullmatch(batch["batch_id"]):
            raise JournalCorruption("batch_id is invalid")
        if (
            not isinstance(batch["previous_authority_commitment"], str)
            or not _DIGEST.fullmatch(batch["previous_authority_commitment"])
            or not isinstance(batch["authority_commitment"], str)
            or not _DIGEST.fullmatch(batch["authority_commitment"])
            or not isinstance(batch["cumulative_event_count"], int)
            or isinstance(batch["cumulative_event_count"], bool)
            or batch["cumulative_event_count"] < 1
            or not isinstance(batch["event_semantic_digest"], str)
            or not _DIGEST.fullmatch(batch["event_semantic_digest"])
            or not isinstance(batch["state_binding_digest"], str)
            or not _DIGEST.fullmatch(batch["state_binding_digest"])
            or not isinstance(batch["cumulative_state_binding_update_count"], int)
            or isinstance(batch["cumulative_state_binding_update_count"], bool)
            or batch["cumulative_state_binding_update_count"] < 1
        ):
            raise JournalCorruption("EventBatch authority commitment is invalid")
        try:
            state_binding_delta = _normalize_state_binding_delta(
                batch["state_binding_delta"], policy=self.policy
            )
        except EventStoreError as exc:
            raise JournalCorruption(str(exc)) from exc
        if batch["cumulative_state_binding_update_count"] < len(state_binding_delta):
            raise JournalCorruption("EventBatch state binding update count is invalid")
        parse_timestamp(batch["created_at"])
        if parse_timestamp(batch["created_at"]) < parse_timestamp(command["issued_at"]):
            raise JournalCorruption("batch predates command")
        bindings = {
            "command_id": command["command_id"],
            "idempotency_key": command["idempotency_key"],
            "subject_id": command["subject_id"],
            "command_intent_digest": command["intent_digest"],
            "command_digest": digest_value(command),
            "authorization_digest": digest_value(command["authorization"]),
        }
        for key, value in bindings.items():
            if batch[key] != value:
                raise JournalCorruption(f"batch command binding mismatch: {key}")
        events = batch["events"]
        if not isinstance(events, list) or not 1 <= len(events) <= self.max_events_per_batch:
            raise JournalCorruption("event count is outside the batch ceiling")
        if batch["cumulative_event_count"] < len(events):
            raise JournalCorruption("EventBatch cumulative event count is invalid")
        event_ids: set[str] = set()
        primary_kind = self.policy.primary_events[command["command_kind"]]
        primary_count = 0
        for event in events:
            if not isinstance(event, dict) or set(event) != {"record_type", "event_id", "event_kind", "activation_digest", "payload"}:
                raise JournalCorruption("Event fields mismatch")
            if event["record_type"] != "Event" or not _ID.fullmatch(event["event_id"]):
                raise JournalCorruption("Event identity is invalid")
            if event["event_id"] in event_ids:
                raise JournalCorruption("duplicate event ID inside batch")
            event_ids.add(event["event_id"])
            if event["activation_digest"] != self.active_activation_digest:
                raise JournalCorruption("Event Activation mismatch")
            if event["event_kind"] == primary_kind:
                primary_count += 1
                if event["payload"] != command["payload"]:
                    raise JournalCorruption("primary Event differs from command payload")
            elif event["event_kind"] == "relation.recorded":
                self._validate_relation(event["payload"], self.active_activation_digest)
            else:
                raise JournalCorruption("batch contains an unrelated auxiliary Event")
            if validate_runtime:
                _invoke_validator(self.event_validator, event, evaluation_time=batch["created_at"], command=command)
            _invoke_compiled_record_validator(
                self.compiled_record_validator,
                "Event",
                event,
                evaluation_time=batch["created_at"],
                operation=validation_operation,
                error_type=JournalCorruption,
            )
        if primary_count != 1:
            raise JournalCorruption("batch must contain exactly one primary Event")
        if events[0]["event_kind"] != primary_kind or any(
            event["event_kind"] != "relation.recorded" for event in events[1:]
        ):
            raise JournalCorruption("primary Event must be first and auxiliary Events must be Relations")
        try:
            _validate_state_binding_event_correspondence(
                state_binding_delta,
                (
                    (event["event_kind"], event["payload"])
                    for event in events
                ),
                policy=self.policy,
            )
        except EventStoreError as exc:
            raise JournalCorruption(str(exc)) from exc
        relations = [event["payload"] for event in events[1:]]
        commit_effect_digest = _commit_effect_digest(command, relations)
        expected_batch_id = "b:" + hashlib.sha256(
            (commit_effect_digest + ":batch").encode("ascii")
        ).hexdigest()[:48]
        expected_primary_id = "e:" + hashlib.sha256(
            (commit_effect_digest + ":primary").encode("ascii")
        ).hexdigest()[:48]
        if batch["batch_id"] != expected_batch_id or events[0]["event_id"] != expected_primary_id:
            raise JournalCorruption("batch or primary Event identity does not bind the complete command effect")
        for event, relation in zip(events[1:], relations):
            relation_digest = digest_value(relation)
            expected_event_id = "e:" + hashlib.sha256(
                (commit_effect_digest + ":relation:" + relation_digest).encode("ascii")
            ).hexdigest()[:48]
            if event["event_id"] != expected_event_id:
                raise JournalCorruption("auxiliary Event identity does not bind its Relation")
        if validate_runtime:
            _invoke_validator(self.command_validator, command, evaluation_time=command["issued_at"])
            _invoke_validator(self.authorization_validator, command, evaluation_time=command["issued_at"])
        _invoke_compiled_record_validator(
            self.compiled_record_validator,
            "EventBatch",
            batch,
            evaluation_time=batch["created_at"],
            operation=validation_operation,
            error_type=JournalCorruption,
        )
        return digest_value(batch)

    @staticmethod
    def _validate_relation(relation: Any, activation_digest: str) -> None:
        required = {
            "record_type", "relation_id", "kind", "source_type", "source_id", "target_type",
            "target_id", "activation_digest", "created_at",
        }
        if not isinstance(relation, dict) or set(relation) != required or relation.get("record_type") != "Relation":
            raise JournalCorruption("Relation fields mismatch")
        for field in ("relation_id", "kind", "source_type", "source_id", "target_type", "target_id"):
            if not isinstance(relation[field], str) or not _ID.fullmatch(relation[field]):
                raise JournalCorruption(f"Relation {field} is invalid")
        if relation["activation_digest"] != activation_digest:
            raise JournalCorruption("Relation Activation mismatch")
        parse_timestamp(relation["created_at"])

    def _iter_envelopes_locked(
        self, *, validate: bool = True
    ) -> Iterator[dict[str, Any]]:
        previous: str | None = None
        sequence = 1
        paths = sorted(_matching_paths(self.journal, "*.json"))
        for path in paths:
            envelope = self._read_envelope(path)
            if validate:
                previous = self._validate_envelope(
                    envelope,
                    expected_sequence=sequence,
                    expected_previous_digest=previous,
                    validate_runtime=True,
                    validation_operation="replay",
                )
            else:
                previous = digest_value(envelope["batch"])
            sequence += 1
            yield copy.deepcopy(envelope)

    def iter_envelopes(self, *, validate: bool = True) -> Iterator[dict[str, Any]]:
        """Iterate one lock-stable authoritative journal snapshot."""

        if validate is not True:
            raise EventStoreError("public journal replay cannot disable validation")
        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            yield from self._iter_envelopes_locked(validate=True)

    def _journal_path_for_sequence(self, sequence: int) -> Path:
        matches = _matching_paths(self.journal, f"{sequence:020d}-*.json")
        if len(matches) != 1:
            raise JournalCorruption(f"journal sequence {sequence} is missing or ambiguous")
        return matches[0]

    def _refresh_from_disk_locked(self) -> None:
        """Refresh deterministic journal authority from durable control files."""

        self._clear_committed_envelope_witness()
        try:
            disk_head = self._read_disk_head()
        except JournalCorruption as exc:
            self._fallback_reason = f"{type(exc).__name__}: {exc}"
            self._recover_locked()
            self._open_mode = "full-replay-fallback"
            return
        if disk_head == self._head:
            try:
                authority_root = self._verify_authority_prefix_locked(disk_head)
            except (CanonicalError, DerivedCheckpointError, JournalCorruption, OSError) as exc:
                self._fallback_reason = f"{type(exc).__name__}: {exc}"
                self._recover_locked()
                self._open_mode = "full-replay-fallback"
                return
            self._authority_generation = authority_root["generation"]
            self._authority_prefix_digest = authority_root[
                "authority_prefix_digest"
            ]
            self._state_binding_digest = authority_root["state_binding_digest"]
            self._state_binding_update_count = authority_root[
                "state_binding_update_count"
            ]
            return
        try:
            self._load_journal_checkpoint_locked()
        except (CanonicalError, DerivedCheckpointError, JournalCorruption, OSError) as exc:
            self._fallback_reason = f"{type(exc).__name__}: {exc}"
            self._recover_locked()
            self._open_mode = "full-replay-fallback"
        else:
            self._fallback_reason = None
            self._open_mode = "verified-checkpoint"

    def _strict_refresh_from_disk_locked(self) -> None:
        """Validate durable authority without recovery or control-file repair."""

        self._clear_committed_envelope_witness()
        disk_head = self._read_disk_head()
        authority_root = self._verify_authority_prefix_locked(disk_head)
        if _matching_paths(self.pending, "*.json"):
            raise DerivedCheckpointError("pending transaction requires recovery")
        if _path_exists(self.checkpoint_path):
            self._load_journal_checkpoint_locked(
                verified_authority_root=authority_root,
            )
        else:
            self._head = disk_head
            self._batch_count = disk_head["sequence"]
            self._event_count = authority_root["event_count"]
            self._semantic_digest = authority_root["event_semantic_digest"]
            self._authority_generation = authority_root["generation"]
            self._authority_prefix_digest = authority_root["authority_prefix_digest"]
            self._state_binding_digest = authority_root["state_binding_digest"]
            self._state_binding_update_count = authority_root[
                "state_binding_update_count"
            ]
        self._fallback_reason = None
        self._open_mode = "verified-checkpoint"

    def envelope_at_head(self) -> dict[str, Any] | None:
        """Read only the authoritative envelope named by current HEAD."""

        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            if self._head["sequence"] == 0:
                return None
            path = self._journal_path_for_sequence(self._head["sequence"])
            envelope = self._read_envelope(path)
            batch = envelope["batch"]
            batch_digest = self._validate_envelope(
                envelope,
                expected_sequence=self._head["sequence"],
                expected_previous_digest=batch.get("previous_digest"),
                validate_runtime=False,
            )
            if batch["batch_id"] != self._head["batch_id"] or batch_digest != self._head["batch_digest"]:
                raise JournalCorruption("HEAD envelope differs from authoritative HEAD")
            return copy.deepcopy(envelope)

    def read_envelope(self, batch_digest: str) -> dict[str, Any]:
        """Resolve one batch digest through a freshly verified journal prefix."""

        if not isinstance(batch_digest, str) or not _DIGEST.fullmatch(batch_digest):
            raise EventStoreError("batch digest is invalid")
        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            if batch_digest == self._head["batch_digest"]:
                path = self._journal_path_for_sequence(self._head["sequence"])
            else:
                try:
                    entry = self._read_index_entry("batch-digest", batch_digest)
                except (DerivedCheckpointError, JournalCorruption) as exc:
                    self._fallback_reason = f"{type(exc).__name__}: {exc}"
                    self._recover_locked()
                    self._open_mode = "full-replay-fallback"
                    entry = self._read_index_entry("batch-digest", batch_digest)
                if entry is None:
                    raise EventStoreError("batch digest is not committed")
                path = self.journal / entry["journal_file"]
            envelope = self._read_envelope(path)
            batch = envelope["batch"]
            actual = self._validate_envelope(
                envelope,
                expected_sequence=batch["sequence"],
                expected_previous_digest=batch.get("previous_digest"),
                validate_runtime=False,
            )
            if actual != batch_digest:
                raise JournalCorruption("resolved envelope digest mismatch")
            return copy.deepcopy(envelope)

    def iter_envelopes_after(
        self,
        checkpoint_head: Mapping[str, Any],
        *,
        validate: bool = True,
    ) -> Iterator[dict[str, Any]]:
        """Stream the authoritative delta after a bound HEAD under one read lock."""

        if validate is not True:
            raise EventStoreError("public delta replay cannot disable validation")
        bound_head = self._validate_head_value(dict(checkpoint_head))
        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            yield from self._envelopes_after_locked(bound_head, validate=True)

    def _envelopes_after_locked(
        self,
        bound_head: Mapping[str, Any],
        *,
        validate: bool,
    ) -> Iterator[dict[str, Any]]:
        current = self.head()
        if bound_head["sequence"] > current["sequence"]:
            raise DerivedCheckpointError("derived checkpoint is ahead of authoritative HEAD")
        if bound_head["sequence"] == current["sequence"]:
            if dict(bound_head) != current:
                raise DerivedCheckpointError("derived checkpoint HEAD is not authoritative")
            return
        previous_digest = bound_head["batch_digest"]
        last_batch: Mapping[str, Any] | None = None
        for sequence in range(bound_head["sequence"] + 1, current["sequence"] + 1):
            path = self._journal_path_for_sequence(sequence)
            envelope = self._read_envelope(path)
            previous_digest = self._validate_envelope(
                envelope,
                expected_sequence=sequence,
                expected_previous_digest=previous_digest,
                validate_runtime=validate,
                validation_operation="replay" if validate else "read",
            )
            last_batch = envelope["batch"]
            yield envelope
        if last_batch is None:
            raise JournalCorruption("delta replay omitted the authoritative tail")
        if (
            last_batch["batch_id"] != current["batch_id"]
            or previous_digest != current["batch_digest"]
        ):
            raise JournalCorruption("delta replay does not terminate at authoritative HEAD")

    def _derived_state_path(self, name: str) -> Path:
        if not isinstance(name, str) or not _ID.fullmatch(name):
            raise EventStoreError("derived state name is not a canonical ID")
        return self.derived_state_root / f"{hashlib.sha256(name.encode('utf-8')).hexdigest()}.json"

    def _journal_state_binding_for_head_locked(
        self, head: Mapping[str, Any]
    ) -> str | None:
        checked = self._validate_head_value(dict(head))
        if checked["sequence"] == 0:
            return self._genesis_state_binding_digest
        path = self._journal_path_for_sequence(checked["sequence"])
        envelope = self._read_envelope(path)
        batch = envelope["batch"]
        batch_digest = self._validate_envelope(
            envelope,
            expected_sequence=checked["sequence"],
            expected_previous_digest=batch.get("previous_digest"),
            validate_runtime=False,
        )
        if (
            batch["batch_id"] != checked["batch_id"]
            or batch_digest != checked["batch_digest"]
        ):
            raise DerivedCheckpointError(
                "derived state HEAD differs from journal authority"
            )
        return batch["state_binding_digest"]

    def validate_state_binding_commitments(
        self,
        commitments: Iterable[Mapping[str, Any]],
        *,
        expected_head: Mapping[str, Any],
    ) -> str:
        """Prove a streamed complete commitment set against journal HEAD.

        Each commitment is independently bounded canonical JSON.  This keeps
        the 16 MiB derived-record ceiling meaningful without imposing that
        ceiling on the aggregate state of a large project.  The existing
        typed sparse-Merkle root is still recomputed from the complete set;
        the compact SQLite node index is never accepted as the proof here.
        """

        def normalized_commitments() -> Iterator[dict[str, str]]:
            previous_identity: tuple[str, str] | None = None
            try:
                iterator = iter(commitments)
            except TypeError as exc:
                raise DerivedCheckpointError(
                    "restored state commitments are not iterable"
                ) from exc
            for commitment in iterator:
                if not isinstance(commitment, Mapping):
                    raise DerivedCheckpointError(
                        "restored state commitment must be an object"
                    )
                try:
                    normalized = parse_json_strict(
                        canonical_bytes(
                            dict(commitment),
                            limits=_STATE_BINDING_COMMITMENT_LIMITS,
                        ),
                        limits=_STATE_BINDING_COMMITMENT_LIMITS,
                    )
                except (CanonicalError, TypeError, ValueError) as exc:
                    raise DerivedCheckpointError(
                        f"restored state commitment is not bounded canonical JSON: {exc}"
                    ) from exc
                if not isinstance(normalized, dict) or set(normalized) != {
                    "leaf_type",
                    "leaf_id",
                    "value_digest",
                }:
                    raise DerivedCheckpointError(
                        "restored state commitment fields mismatch"
                    )
                leaf_type = normalized["leaf_type"]
                leaf_id = normalized["leaf_id"]
                value_digest = normalized["value_digest"]
                if (
                    not isinstance(leaf_type, str)
                    or leaf_type == "Activation"
                    or leaf_type
                    not in self.policy.allowed_state_binding_leaf_type_set
                ):
                    raise DerivedCheckpointError(
                        "restored state commitment type is not a non-Activation Core leaf"
                    )
                if not isinstance(leaf_id, str) or not _ID.fullmatch(leaf_id):
                    raise DerivedCheckpointError(
                        "restored state commitment leaf ID is invalid"
                    )
                if (
                    not isinstance(value_digest, str)
                    or not _DIGEST.fullmatch(value_digest)
                ):
                    raise DerivedCheckpointError(
                        "restored state commitment value digest is invalid"
                    )
                identity = (leaf_type, leaf_id)
                if previous_identity is not None and identity <= previous_identity:
                    raise DerivedCheckpointError(
                        "restored state commitments must use unique canonical leaf order"
                    )
                previous_identity = identity
                yield {
                    "leaf_type": leaf_type,
                    "leaf_id": leaf_id,
                    "value_digest": value_digest,
                }

        activation_leaf = {
            "leaf_type": "Activation",
            "leaf_id": self.active_activation_digest,
            "value_digest": self.activation_record_digest,
        }
        computed_root = _state_binding_root_from_leaves(
            itertools.chain((activation_leaf,), normalized_commitments())
        )
        checked_head = self._validate_head_value(dict(expected_head))
        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            if checked_head != self._head:
                raise DerivedCheckpointError(
                    "restored state commitments are bound to a stale journal HEAD"
                )
            journal_root = self._journal_state_binding_for_head_locked(checked_head)
            if journal_root is None or computed_root != journal_root:
                raise DerivedCheckpointError(
                    "restored state commitments do not reproduce the journal state binding"
                )
            return computed_root

    def validate_state_binding_leaves(
        self,
        leaves: Iterable[Mapping[str, Any]],
        *,
        expected_head: Mapping[str, Any],
    ) -> str:
        """Stream full restored values into the exact commitment verifier."""

        def commitments() -> Iterator[dict[str, str]]:
            try:
                iterator = iter(leaves)
            except TypeError as exc:
                raise DerivedCheckpointError(
                    "restored state leaves are not iterable"
                ) from exc
            for leaf in iterator:
                if not isinstance(leaf, Mapping):
                    raise DerivedCheckpointError(
                        "restored state leaf must be an object"
                    )
                try:
                    normalized = parse_json_strict(
                        canonical_bytes(dict(leaf), limits=_DERIVED_STATE_LIMITS),
                        limits=_DERIVED_STATE_LIMITS,
                    )
                except (CanonicalError, TypeError, ValueError) as exc:
                    raise DerivedCheckpointError(
                        f"restored state leaf is not bounded canonical JSON: {exc}"
                    ) from exc
                if not isinstance(normalized, dict) or set(normalized) != {
                    "leaf_type",
                    "value",
                }:
                    raise DerivedCheckpointError(
                        "restored state leaf fields mismatch"
                    )
                leaf_type = normalized["leaf_type"]
                value = normalized["value"]
                if (
                    not isinstance(leaf_type, str)
                    or leaf_type == "Activation"
                    or leaf_type
                    not in self.policy.allowed_state_binding_leaf_type_set
                ):
                    raise DerivedCheckpointError(
                        "restored state leaf type is not a non-Activation Core leaf"
                    )
                rule = self.policy.state_binding_value_rules[leaf_type]
                if (
                    not isinstance(value, dict)
                    or value.get("record_type") != rule["value_definition"]
                ):
                    raise DerivedCheckpointError(
                        "restored state value differs from its Core leaf definition"
                    )
                identity_value = value
                if leaf_type == "Grant":
                    identity_value = value.get("grant")
                    if not isinstance(identity_value, dict):
                        raise DerivedCheckpointError(
                            "restored Grant authority state lacks its identity owner"
                        )
                try:
                    leaf_id = state_binding_leaf_id(
                        self.policy,
                        leaf_type,
                        identity_value,
                    )
                except EventStoreError as exc:
                    raise DerivedCheckpointError(
                        "restored state value has no single Core-owned leaf identity"
                    ) from exc
                yield {
                    "leaf_type": leaf_type,
                    "leaf_id": leaf_id,
                    "value_digest": digest_value(value),
                }

        return self.validate_state_binding_commitments(
            commitments(),
            expected_head=expected_head,
        )

    def _derived_rows_path(self, name: str) -> Path:
        if not isinstance(name, str) or not _ID.fullmatch(name):
            raise EventStoreError("derived rows name is not a canonical ID")
        identity = hashlib.sha256(name.encode("utf-8")).hexdigest()
        return self.derived_rows_root / f"{identity}.sqlite3"

    @staticmethod
    def _derived_rows_layout(connection: sqlite3.Connection) -> str:
        """Identify the disposable layout without silently accepting drift."""

        try:
            objects = connection.execute(
                "SELECT type, name, tbl_name FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
            ).fetchall()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("derived rows schema is unreadable") from exc
        if not objects:
            return "empty"
        if objects == [
            ("table", "binding", "binding"),
            ("table", "derived_row", "derived_row"),
        ]:
            return "v1"
        if objects == [
            ("index", "runtime_v2_row_bucket", "derived_row"),
            ("table", "binding", "binding"),
            ("table", "derived_row", "derived_row"),
            ("table", "runtime_v2_bucket", "runtime_v2_bucket"),
            ("table", "runtime_v2_node", "runtime_v2_node"),
        ]:
            return "runtime-v2"
        raise DerivedCheckpointError("derived rows schema objects mismatch")

    @staticmethod
    def _validate_derived_rows_schema(connection: sqlite3.Connection) -> None:
        if EventStore._derived_rows_layout(connection) != "v1":
            raise DerivedCheckpointError("derived rows schema is not v1")
        try:
            binding_columns = connection.execute(
                "PRAGMA table_info(binding)"
            ).fetchall()
            row_columns = connection.execute(
                "PRAGMA table_info(derived_row)"
            ).fetchall()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("derived rows schema is unreadable") from exc
        if [
            (row[1], row[2], row[3], row[5]) for row in binding_columns
        ] != [
            ("singleton", "INTEGER", 0, 1),
            ("manifest", "BLOB", 1, 0),
        ]:
            raise DerivedCheckpointError("derived rows binding schema mismatch")
        if [(row[1], row[2], row[3], row[5]) for row in row_columns] != [
            ("section", "TEXT", 1, 1),
            ("key", "TEXT", 1, 2),
            ("payload", "BLOB", 1, 0),
            ("payload_digest", "TEXT", 1, 0),
        ]:
            raise DerivedCheckpointError("derived rows row schema mismatch")

    @staticmethod
    def _validate_runtime_rows_v2_schema(connection: sqlite3.Connection) -> None:
        if EventStore._derived_rows_layout(connection) != "runtime-v2":
            raise DerivedCheckpointError("derived rows schema is not runtime v2")
        try:
            binding_columns = connection.execute("PRAGMA table_info(binding)").fetchall()
            row_columns = connection.execute("PRAGMA table_info(derived_row)").fetchall()
            bucket_columns = connection.execute(
                "PRAGMA table_info(runtime_v2_bucket)"
            ).fetchall()
            node_columns = connection.execute(
                "PRAGMA table_info(runtime_v2_node)"
            ).fetchall()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("runtime v2 schema is unreadable") from exc
        if [(row[1], row[2], row[3], row[5]) for row in binding_columns] != [
            ("singleton", "INTEGER", 0, 1),
            ("manifest", "BLOB", 1, 0),
        ]:
            raise DerivedCheckpointError("runtime v2 binding schema mismatch")
        if [(row[1], row[2], row[3], row[5]) for row in row_columns] != [
            ("section", "TEXT", 1, 1),
            ("key", "TEXT", 1, 2),
            ("payload", "BLOB", 1, 0),
            ("payload_digest", "TEXT", 1, 0),
            ("identity_digest", "BLOB", 1, 0),
            ("bucket", "BLOB", 1, 0),
        ]:
            raise DerivedCheckpointError("runtime v2 row schema mismatch")
        if [(row[1], row[2], row[3], row[5]) for row in bucket_columns] != [
            ("bucket", "BLOB", 1, 1),
            ("digest", "BLOB", 1, 0),
        ]:
            raise DerivedCheckpointError("runtime v2 bucket schema mismatch")
        if [(row[1], row[2], row[3], row[5]) for row in node_columns] != [
            ("depth", "INTEGER", 1, 1),
            ("prefix", "BLOB", 1, 2),
            ("digest", "BLOB", 1, 0),
            ("children", "BLOB", 1, 0),
        ]:
            raise DerivedCheckpointError("runtime v2 node schema mismatch")

    @staticmethod
    def _read_derived_rows_manifest(
        connection: sqlite3.Connection,
    ) -> dict[str, Any]:
        try:
            rows = connection.execute(
                "SELECT singleton, manifest FROM binding"
            ).fetchall()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("derived rows binding is unreadable") from exc
        if (
            len(rows) != 1
            or rows[0][0] != 1
            or not isinstance(rows[0][1], bytes)
        ):
            raise DerivedCheckpointError("derived rows binding is missing")
        payload = rows[0][1]
        try:
            value = parse_json_strict(
                payload,
                limits=_DERIVED_ROWS_MANIFEST_LIMITS,
            )
            if canonical_bytes(
                value,
                limits=_DERIVED_ROWS_MANIFEST_LIMITS,
            ) != payload:
                raise DerivedCheckpointError(
                    "derived rows manifest is not canonical"
                )
        except CanonicalError as exc:
            raise DerivedCheckpointError(
                "derived rows manifest is invalid"
            ) from exc
        if not isinstance(value, dict):
            raise DerivedCheckpointError("derived rows manifest must be an object")
        return value

    def _validate_derived_rows_manifest_locked(
        self,
        name: str,
        manifest: Mapping[str, Any],
    ) -> dict[str, Any]:
        value = copy.deepcopy(dict(manifest))
        required = {
            "record_type",
            "version",
            "authoritative",
            "name",
            "activation_digest",
            "implementation_closure_digest",
            "head",
            "batch_count",
            "event_count",
            "event_semantic_digest",
            "authority_state_binding_digest",
            "checkpoint_count",
            "row_count",
            "row_transcript_digest",
            "checkpoint_digest",
        }
        if set(value) != required or value.get("record_type") != "DerivedRowsCheckpoint":
            raise DerivedCheckpointError("derived rows manifest fields mismatch")
        supplied_digest = value.pop("checkpoint_digest")
        if (
            not isinstance(supplied_digest, str)
            or not _DIGEST.fullmatch(supplied_digest)
            or digest_value(value) != supplied_digest
        ):
            raise DerivedCheckpointError("derived rows manifest digest mismatch")
        value["checkpoint_digest"] = supplied_digest
        if (
            value["version"] != _DERIVED_ROWS_INDEX_VERSION
            or value["authoritative"] is not False
            or value["name"] != name
            or value["activation_digest"] != self.active_activation_digest
            or value["implementation_closure_digest"]
            != self.implementation_closure_digest
        ):
            raise DerivedCheckpointError("derived rows manifest binding mismatch")
        head = self._validate_head_value(value["head"])
        value["head"] = head
        current = self._head
        if head["sequence"] > current["sequence"]:
            raise DerivedCheckpointError("derived rows checkpoint is ahead of HEAD")
        if head["sequence"] == current["sequence"] and head != current:
            raise DerivedCheckpointError(
                "derived rows checkpoint is bound to another HEAD"
            )
        if head["sequence"] == 0:
            event_count = 0
            event_semantic_digest = self.policy.genesis_event_semantic_digest
            state_binding_digest = self._genesis_state_binding_digest
        else:
            path = self._journal_path_for_sequence(head["sequence"])
            envelope = self._read_envelope(path)
            batch = envelope["batch"]
            batch_digest = self._validate_envelope(
                envelope,
                expected_sequence=head["sequence"],
                expected_previous_digest=batch.get("previous_digest"),
                validate_runtime=False,
            )
            if (
                batch["batch_id"] != head["batch_id"]
                or batch_digest != head["batch_digest"]
            ):
                raise DerivedCheckpointError(
                    "derived rows checkpoint HEAD differs from journal"
                )
            event_count = batch["cumulative_event_count"]
            event_semantic_digest = batch["event_semantic_digest"]
            state_binding_digest = batch["state_binding_digest"]
        for field in ("batch_count", "event_count", "checkpoint_count", "row_count"):
            item = value[field]
            if (
                not isinstance(item, int)
                or isinstance(item, bool)
                or item < (1 if field == "checkpoint_count" else 0)
            ):
                raise DerivedCheckpointError(
                    f"derived rows manifest {field} is invalid"
                )
        if (
            value["batch_count"] != head["sequence"]
            or value["event_count"] != event_count
            or value["event_semantic_digest"] != event_semantic_digest
            or value["authority_state_binding_digest"] != state_binding_digest
            or not isinstance(value["row_transcript_digest"], str)
            or not _DIGEST.fullmatch(value["row_transcript_digest"])
        ):
            raise DerivedCheckpointError("derived rows manifest content is stale")
        return value

    def _validate_runtime_rows_v2_manifest_locked(
        self,
        manifest: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Validate the versioned runtime-only derived binding.

        V2 deliberately has its own keyed commitment instead of reusing the
        v1 ordered transcript.  The v1 chain makes any middle update O(N),
        while this disposable cache must update only touched keys.  Journal
        ownership, HEAD binding, and all recovery behaviour remain identical.
        """

        value = copy.deepcopy(dict(manifest))
        required = {
            "record_type",
            "version",
            "authoritative",
            "name",
            "activation_digest",
            "implementation_closure_digest",
            "head",
            "batch_count",
            "event_count",
            "event_semantic_digest",
            "authority_state_binding_digest",
            "checkpoint_count",
            "row_count",
            "row_merkle_digest",
            "checkpoint_digest",
        }
        if (
            set(value) != required
            or value.get("record_type") != "DerivedRowsCheckpoint"
            or value.get("version") != _RUNTIME_ROWS_V2_INDEX_VERSION
            or value.get("name") != _RUNTIME_ROWS_V2_NAME
        ):
            raise DerivedCheckpointError("runtime v2 manifest fields mismatch")
        supplied_digest = value.pop("checkpoint_digest")
        if (
            not isinstance(supplied_digest, str)
            or not _DIGEST.fullmatch(supplied_digest)
            or digest_value(value) != supplied_digest
        ):
            raise DerivedCheckpointError("runtime v2 manifest digest mismatch")
        value["checkpoint_digest"] = supplied_digest
        if (
            value["authoritative"] is not False
            or value["activation_digest"] != self.active_activation_digest
            or value["implementation_closure_digest"]
            != self.implementation_closure_digest
        ):
            raise DerivedCheckpointError("runtime v2 manifest binding mismatch")
        head = self._validate_head_value(value["head"])
        value["head"] = head
        current = self._head
        if head["sequence"] > current["sequence"]:
            raise DerivedCheckpointError("runtime v2 checkpoint is ahead of HEAD")
        if head["sequence"] == current["sequence"] and head != current:
            raise DerivedCheckpointError(
                "runtime v2 checkpoint is bound to another HEAD"
            )
        if head["sequence"] == 0:
            event_count = 0
            event_semantic_digest = self.policy.genesis_event_semantic_digest
            state_binding_digest = self._genesis_state_binding_digest
        else:
            envelope = self._read_envelope(
                self._journal_path_for_sequence(head["sequence"])
            )
            batch = envelope["batch"]
            batch_digest = self._validate_envelope(
                envelope,
                expected_sequence=head["sequence"],
                expected_previous_digest=batch.get("previous_digest"),
                validate_runtime=False,
            )
            if (
                batch["batch_id"] != head["batch_id"]
                or batch_digest != head["batch_digest"]
            ):
                raise DerivedCheckpointError(
                    "runtime v2 checkpoint HEAD differs from journal"
                )
            event_count = batch["cumulative_event_count"]
            event_semantic_digest = batch["event_semantic_digest"]
            state_binding_digest = batch["state_binding_digest"]
        for field in ("batch_count", "event_count", "checkpoint_count", "row_count"):
            item = value[field]
            if (
                not isinstance(item, int)
                or isinstance(item, bool)
                or item < (1 if field == "checkpoint_count" else 0)
            ):
                raise DerivedCheckpointError(
                    f"runtime v2 manifest {field} is invalid"
                )
        if (
            value["batch_count"] != head["sequence"]
            or value["event_count"] != event_count
            or value["event_semantic_digest"] != event_semantic_digest
            or value["authority_state_binding_digest"] != state_binding_digest
            or not isinstance(value["row_merkle_digest"], str)
            or not _DIGEST.fullmatch(value["row_merkle_digest"])
        ):
            raise DerivedCheckpointError("runtime v2 manifest content is stale")
        return value

    @staticmethod
    def _runtime_rows_v2_identity_digest(section: str, key: str) -> bytes:
        return hashlib.sha256(
            b"promin:runtime-rows-v2:identity\x00"
            + canonical_bytes({"section": section, "key": key})
        ).digest()

    @staticmethod
    def _runtime_rows_v2_leaf_digest(
        identity_digest: bytes,
        payload_digest: str,
    ) -> bytes:
        if (
            not isinstance(identity_digest, bytes)
            or len(identity_digest) != 32
            or not isinstance(payload_digest, str)
            or not _DIGEST.fullmatch(payload_digest)
        ):
            raise DerivedCheckpointError("runtime v2 leaf identity is invalid")
        return hashlib.sha256(
            b"promin:runtime-rows-v2:leaf\x00"
            + identity_digest
            + bytes.fromhex(payload_digest)
        ).digest()

    @staticmethod
    def _runtime_rows_v2_empty_bucket_digest() -> bytes:
        return hashlib.sha256(b"promin:runtime-rows-v2:empty-bucket").digest()

    @classmethod
    def _runtime_rows_v2_bucket_digest(
        cls,
        leaves: Mapping[bytes, str],
    ) -> bytes:
        digest = hashlib.sha256(b"promin:runtime-rows-v2:bucket\x00")
        for identity_digest, payload_digest in sorted(leaves.items()):
            digest.update(cls._runtime_rows_v2_leaf_digest(identity_digest, payload_digest))
        return digest.digest() if leaves else cls._runtime_rows_v2_empty_bucket_digest()

    @classmethod
    def _runtime_rows_v2_node_digest(
        cls,
        depth: int,
        children: Mapping[int, bytes],
    ) -> bytes:
        if depth not in {0, 8}:
            raise DerivedCheckpointError("runtime v2 node depth is invalid")
        payload = _encode_state_storage_children(children)
        return hashlib.sha256(
            b"promin:runtime-rows-v2:node\x00" + bytes((depth,)) + payload
        ).digest()

    @classmethod
    def _runtime_rows_v2_empty_node_digest(cls, depth: int) -> bytes:
        return cls._runtime_rows_v2_node_digest(depth, {})

    @staticmethod
    def _create_runtime_rows_v2_schema(connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE binding ("
            "singleton INTEGER PRIMARY KEY CHECK(singleton = 1), "
            "manifest BLOB NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE derived_row ("
            "section TEXT NOT NULL, key TEXT NOT NULL, payload BLOB NOT NULL, "
            "payload_digest TEXT NOT NULL, identity_digest BLOB NOT NULL, "
            "bucket BLOB NOT NULL, PRIMARY KEY(section, key)) WITHOUT ROWID"
        )
        connection.execute(
            "CREATE INDEX runtime_v2_row_bucket "
            "ON derived_row(bucket, identity_digest)"
        )
        connection.execute(
            "CREATE TABLE runtime_v2_bucket ("
            "bucket BLOB PRIMARY KEY, digest BLOB NOT NULL) WITHOUT ROWID"
        )
        connection.execute(
            "CREATE TABLE runtime_v2_node ("
            "depth INTEGER NOT NULL, prefix BLOB NOT NULL, digest BLOB NOT NULL, "
            "children BLOB NOT NULL, PRIMARY KEY(depth, prefix)) WITHOUT ROWID"
        )

    @classmethod
    def _runtime_rows_v2_node(
        cls,
        connection: sqlite3.Connection,
        depth: int,
        prefix: bytes,
    ) -> tuple[bytes, dict[int, bytes]]:
        try:
            row = connection.execute(
                "SELECT digest, children FROM runtime_v2_node "
                "WHERE depth = ? AND prefix = ?",
                (depth, prefix),
            ).fetchone()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("runtime v2 node is unreadable") from exc
        if row is None:
            return cls._runtime_rows_v2_empty_node_digest(depth), {}
        digest, children_payload = row
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise DerivedCheckpointError("runtime v2 node digest is invalid")
        children = _decode_state_storage_children(children_payload)
        if cls._runtime_rows_v2_node_digest(depth, children) != digest:
            raise DerivedCheckpointError("runtime v2 node differs from its children")
        return digest, children

    @classmethod
    def _runtime_rows_v2_bucket_rows(
        cls,
        connection: sqlite3.Connection,
        buckets: Iterable[bytes],
    ) -> dict[bytes, tuple[bytes, dict[bytes, str]]]:
        selected = tuple(sorted(set(buckets)))
        if not selected or any(
            not isinstance(bucket, bytes)
            or len(bucket) != _RUNTIME_ROWS_V2_BUCKET_BYTES
            for bucket in selected
        ):
            raise DerivedCheckpointError("runtime v2 bucket request is invalid")
        values: dict[bytes, dict[bytes, str]] = {bucket: {} for bucket in selected}
        stored: dict[bytes, bytes] = {}
        try:
            for offset in range(0, len(selected), 512):
                current = selected[offset : offset + 512]
                placeholders = ",".join("?" for _unused in current)
                for bucket, identity_digest, payload_digest in connection.execute(
                    "SELECT bucket, identity_digest, payload_digest FROM derived_row "
                    f"WHERE bucket IN ({placeholders}) ORDER BY bucket, identity_digest",
                    current,
                ):
                    if (
                        bucket not in values
                        or not isinstance(identity_digest, bytes)
                        or len(identity_digest) != 32
                        or identity_digest[:_RUNTIME_ROWS_V2_BUCKET_BYTES] != bucket
                        or not isinstance(payload_digest, str)
                        or not _DIGEST.fullmatch(payload_digest)
                        or identity_digest in values[bucket]
                    ):
                        raise DerivedCheckpointError("runtime v2 row bucket is invalid")
                    values[bucket][identity_digest] = payload_digest
                for bucket, digest in connection.execute(
                    "SELECT bucket, digest FROM runtime_v2_bucket "
                    f"WHERE bucket IN ({placeholders}) ORDER BY bucket",
                    current,
                ):
                    if (
                        bucket not in values
                        or bucket in stored
                        or not isinstance(digest, bytes)
                        or len(digest) != 32
                    ):
                        raise DerivedCheckpointError("runtime v2 bucket row is invalid")
                    stored[bucket] = digest
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("runtime v2 buckets are unreadable") from exc
        result: dict[bytes, tuple[bytes, dict[bytes, str]]] = {}
        empty = cls._runtime_rows_v2_empty_bucket_digest()
        for bucket in selected:
            calculated = cls._runtime_rows_v2_bucket_digest(values[bucket])
            observed = stored.get(bucket, empty)
            if calculated != observed:
                raise DerivedCheckpointError("runtime v2 bucket differs from its rows")
            result[bucket] = (observed, values[bucket])
        return result

    @staticmethod
    def _normalize_derived_row(row: Mapping[str, Any]) -> tuple[dict[str, Any], bytes, str]:
        if not isinstance(row, Mapping):
            raise DerivedCheckpointError("derived row must be an object")
        try:
            payload = canonical_bytes(dict(row), limits=_DERIVED_STATE_LIMITS)
            normalized = parse_json_strict(payload, limits=_DERIVED_STATE_LIMITS)
        except (CanonicalError, TypeError, ValueError) as exc:
            raise DerivedCheckpointError(
                f"derived row is not bounded canonical JSON: {exc}"
            ) from exc
        if not isinstance(normalized, dict) or set(normalized) != {
            "section",
            "key",
            "value",
        }:
            raise DerivedCheckpointError("derived row fields mismatch")
        section = normalized["section"]
        key = normalized["key"]
        if (
            not isinstance(section, str)
            or not _DERIVED_ROW_ID.fullmatch(section)
            or not isinstance(key, str)
            or not _DERIVED_ROW_ID.fullmatch(key)
        ):
            raise DerivedCheckpointError("derived row identity is invalid")
        _reject_reserved_secret_fields(
            normalized["value"],
            surface="derived row checkpoint",
            error_type=DerivedCheckpointError,
        )
        return normalized, payload, hashlib.sha256(payload).hexdigest()

    def write_derived_rows(
        self,
        name: str,
        rows: Iterable[Mapping[str, Any]],
        *,
        expected_head: Mapping[str, Any],
        checkpoint_count: int,
        crash_hook: Callable[[str], Any] | None = None,
    ) -> dict[str, Any]:
        """Atomically replace a normalized disposable row checkpoint.

        The SQLite lifecycle is independent of the sparse-Merkle index.  Each
        row retains the 16 MiB record ceiling while the database may contain a
        project-sized number of rows.  The manifest binds the exact journal
        HEAD and an ordered transcript of every canonical row.
        """

        path = self._derived_rows_path(name)
        checked_head = self._validate_head_value(dict(expected_head))
        if (
            not isinstance(checkpoint_count, int)
            or isinstance(checkpoint_count, bool)
            or checkpoint_count < 1
        ):
            raise EventStoreError("derived rows checkpoint_count must be positive")
        try:
            row_iterator = iter(rows)
        except TypeError as exc:
            raise EventStoreError("derived rows must be iterable") from exc
        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            if checked_head != self._head:
                raise DerivedCheckpointError(
                    "derived rows were computed for a stale authoritative HEAD"
                )
            state_binding_digest = self._journal_state_binding_for_head_locked(
                checked_head
            )
            if state_binding_digest is None:
                raise DerivedCheckpointError(
                    "authoritative HEAD has no semantic state binding"
                )
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{path.stem}-",
                suffix=".tmp",
                dir=_native_os_path(self.derived_rows_root),
            )
            os.close(descriptor)
            temporary = Path(temporary_name)
            connection: sqlite3.Connection | None = None
            try:
                connection = sqlite3.connect(
                    _native_os_path(temporary),
                    timeout=self.lock_timeout,
                    isolation_level=None,
                )
                connection.execute(
                    f"PRAGMA busy_timeout={int(self.lock_timeout * 1000)}"
                )
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "CREATE TABLE binding ("
                    "singleton INTEGER PRIMARY KEY CHECK(singleton = 1), "
                    "manifest BLOB NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE derived_row ("
                    "section TEXT NOT NULL, key TEXT NOT NULL, "
                    "payload BLOB NOT NULL, payload_digest TEXT NOT NULL, "
                    "PRIMARY KEY(section, key)) WITHOUT ROWID"
                )
                previous_identity: tuple[str, str] | None = None
                transcript = _DERIVED_ROWS_TRANSCRIPT_GENESIS
                row_count = 0
                pending_rows: list[tuple[str, str, bytes, str]] = []
                for row in row_iterator:
                    normalized, payload, payload_digest = self._normalize_derived_row(
                        row
                    )
                    identity = (normalized["section"], normalized["key"])
                    if previous_identity is not None and identity <= previous_identity:
                        raise DerivedCheckpointError(
                            "derived rows must use unique canonical order"
                        )
                    previous_identity = identity
                    transcript = _extend_derived_rows_transcript(
                        transcript,
                        section=identity[0],
                        key=identity[1],
                        payload_digest=payload_digest,
                    )
                    pending_rows.append(
                        (identity[0], identity[1], payload, payload_digest)
                    )
                    if len(pending_rows) >= _DERIVED_ROWS_INSERT_BATCH:
                        connection.executemany(
                            "INSERT INTO derived_row(section, key, payload, payload_digest) "
                            "VALUES (?, ?, ?, ?)",
                            pending_rows,
                        )
                        pending_rows.clear()
                    row_count += 1
                if pending_rows:
                    connection.executemany(
                        "INSERT INTO derived_row(section, key, payload, payload_digest) "
                        "VALUES (?, ?, ?, ?)",
                        pending_rows,
                    )
                manifest = {
                    "record_type": "DerivedRowsCheckpoint",
                    "version": _DERIVED_ROWS_INDEX_VERSION,
                    "authoritative": False,
                    "name": name,
                    "activation_digest": self.active_activation_digest,
                    "implementation_closure_digest": self.implementation_closure_digest,
                    "head": copy.deepcopy(checked_head),
                    "batch_count": self._batch_count,
                    "event_count": self._event_count,
                    "event_semantic_digest": self._semantic_digest,
                    "authority_state_binding_digest": state_binding_digest,
                    "checkpoint_count": checkpoint_count,
                    "row_count": row_count,
                    "row_transcript_digest": transcript,
                }
                manifest["checkpoint_digest"] = digest_value(manifest)
                connection.execute(
                    "INSERT INTO binding(singleton, manifest) VALUES (1, ?)",
                    (
                        canonical_bytes(
                            manifest,
                            limits=_DERIVED_ROWS_MANIFEST_LIMITS,
                        ),
                    ),
                )
                connection.execute("COMMIT")
                connection.close()
                connection = None
                with open(_native_os_path(temporary), "rb+") as stream:
                    stream.flush()
                    os.fsync(stream.fileno())
                self._crash(crash_hook, "before_derived_rows_checkpoint")
                _replace_durable(temporary, path)
                self._crash(crash_hook, "after_derived_rows_checkpoint")
                self._derived_rows_issues[name] = None
                return copy.deepcopy(manifest)
            except sqlite3.Error as exc:
                if connection is not None:
                    try:
                        connection.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                raise DerivedCheckpointError(
                    "derived rows checkpoint write failed"
                ) from exc
            finally:
                if connection is not None:
                    connection.close()
                _unlink(temporary, missing_ok=True)
                _unlink(Path(str(temporary) + "-journal"), missing_ok=True)

    def write_runtime_rows_v2(
        self,
        rows: Iterable[Mapping[str, Any]],
        *,
        expected_head: Mapping[str, Any],
        checkpoint_count: int,
        replace: bool = False,
        crash_hook: Callable[[str], Any] | None = None,
    ) -> dict[str, Any]:
        """Incrementally persist the runtime-only v2 derived row layout.

        Generic ``write_derived_rows`` stays v1 and deliberately retains its
        complete-file replacement contract.  Runtime v2 is a private derived
        acceleration: rows use stable identities, touched 16-bit keyed-Merkle
        partitions are recomputed, and only their two bounded ancestor levels
        are published.  The journal remains the sole authority; any malformed
        v2 layout is a cache miss and callers replay from it.
        """

        path = self._derived_rows_path(_RUNTIME_ROWS_V2_NAME)
        checked_head = self._validate_head_value(dict(expected_head))
        if (
            not isinstance(checkpoint_count, int)
            or isinstance(checkpoint_count, bool)
            or checkpoint_count < 1
            or not isinstance(replace, bool)
        ):
            raise EventStoreError("runtime v2 checkpoint arguments are invalid")
        try:
            row_iterator = iter(rows)
        except TypeError as exc:
            raise EventStoreError("runtime v2 rows must be iterable") from exc

        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            if checked_head != self._head:
                raise DerivedCheckpointError(
                    "runtime v2 rows were computed for a stale authoritative HEAD"
                )
            state_binding_digest = self._journal_state_binding_for_head_locked(
                checked_head
            )
            if state_binding_digest is None:
                raise DerivedCheckpointError(
                    "runtime v2 authoritative HEAD has no semantic state binding"
                )
            connection: sqlite3.Connection | None = None
            committed = False
            try:
                connection = sqlite3.connect(
                    _native_os_path(path),
                    timeout=self.lock_timeout,
                    isolation_level=None,
                )
                connection.execute(f"PRAGMA busy_timeout={int(self.lock_timeout * 1000)}")
                connection.execute("PRAGMA journal_mode=DELETE")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                layout = self._derived_rows_layout(connection)
                bootstrap = layout in {"empty", "v1"}
                if layout == "v1":
                    # A valid v1 runtime cache is non-authoritative.  The
                    # supplied full bootstrap replaces it inside one SQLite
                    # transaction, never via a separate temporary file.
                    connection.execute("DROP TABLE derived_row")
                    connection.execute("DROP TABLE binding")
                    self._create_runtime_rows_v2_schema(connection)
                elif layout == "empty":
                    self._create_runtime_rows_v2_schema(connection)
                elif layout == "runtime-v2":
                    self._validate_runtime_rows_v2_schema(connection)
                    if replace:
                        connection.execute("DELETE FROM runtime_v2_node")
                        connection.execute("DELETE FROM runtime_v2_bucket")
                        connection.execute("DELETE FROM derived_row")
                        connection.execute("DELETE FROM binding")
                        bootstrap = True
                    else:
                        existing_manifest = self._validate_runtime_rows_v2_manifest_locked(
                            self._read_derived_rows_manifest(connection)
                        )
                        root_digest, _root_children = self._runtime_rows_v2_node(
                            connection,
                            0,
                            b"",
                        )
                        if root_digest.hex() != existing_manifest["row_merkle_digest"]:
                            raise DerivedCheckpointError(
                                "runtime v2 root differs from its manifest"
                            )
                else:  # pragma: no cover - layout validation above is exhaustive.
                    raise DerivedCheckpointError("runtime v2 layout is unresolved")

                normalized_rows: dict[tuple[str, str], tuple[bytes, str, bytes]] = {}
                for row in row_iterator:
                    normalized, payload, payload_digest = self._normalize_derived_row(row)
                    identity = (normalized["section"], normalized["key"])
                    if identity in normalized_rows:
                        raise DerivedCheckpointError(
                            "runtime v2 rows use duplicate stable identities"
                        )
                    identity_digest = self._runtime_rows_v2_identity_digest(*identity)
                    normalized_rows[identity] = (payload, payload_digest, identity_digest)
                if not normalized_rows:
                    raise DerivedCheckpointError("runtime v2 checkpoint has no rows")
                if bootstrap and ("00.runtime", "header") not in normalized_rows:
                    raise DerivedCheckpointError(
                        "runtime v2 bootstrap lacks its runtime header"
                    )

                changed: dict[tuple[str, str], tuple[bytes, str, bytes]] = {}
                inserted = 0
                if bootstrap:
                    changed = dict(normalized_rows)
                    inserted = len(changed)
                else:
                    for identity, value in normalized_rows.items():
                        try:
                            row = connection.execute(
                                "SELECT payload_digest, identity_digest FROM derived_row "
                                "WHERE section = ? AND key = ?",
                                identity,
                            ).fetchone()
                        except sqlite3.Error as exc:
                            raise DerivedCheckpointError(
                                "runtime v2 rows are unreadable"
                            ) from exc
                        if row is None:
                            changed[identity] = value
                            inserted += 1
                        else:
                            previous_digest, previous_identity = row
                            if (
                                not isinstance(previous_digest, str)
                                or not _DIGEST.fullmatch(previous_digest)
                                or previous_identity != value[2]
                            ):
                                raise DerivedCheckpointError(
                                    "runtime v2 row identity is invalid"
                                )
                            if previous_digest != value[1]:
                                changed[identity] = value

                if not bootstrap and not changed:
                    raise DerivedCheckpointError(
                        "runtime v2 incremental checkpoint has no changed rows"
                    )
                touched_buckets = tuple(
                    sorted(
                        {
                            value[2][:_RUNTIME_ROWS_V2_BUCKET_BYTES]
                            for value in changed.values()
                        }
                    )
                )
                bucket_rows = (
                    self._runtime_rows_v2_bucket_rows(connection, touched_buckets)
                    if touched_buckets
                    else {}
                )
                updated_bucket_values = {
                    bucket: dict(values)
                    for bucket, (_digest, values) in bucket_rows.items()
                }
                for _identity, (_payload, payload_digest, identity_digest) in changed.items():
                    updated_bucket_values[
                        identity_digest[:_RUNTIME_ROWS_V2_BUCKET_BYTES]
                    ][identity_digest] = payload_digest

                empty_bucket = self._runtime_rows_v2_empty_bucket_digest()
                bucket_changes: dict[bytes, tuple[bytes, bytes]] = {}
                bucket_deletes: list[bytes] = []
                bucket_upserts: list[tuple[bytes, bytes]] = []
                for bucket, values in updated_bucket_values.items():
                    old_digest = bucket_rows[bucket][0]
                    new_digest = self._runtime_rows_v2_bucket_digest(values)
                    bucket_changes[bucket] = (old_digest, new_digest)
                    if new_digest == empty_bucket:
                        if old_digest != empty_bucket:
                            bucket_deletes.append(bucket)
                    elif new_digest != old_digest:
                        bucket_upserts.append((bucket, new_digest))

                top_prefixes = tuple(sorted({bucket[:1] for bucket in touched_buckets}))
                top_changes: dict[bytes, tuple[bytes, bytes, bytes]] = {}
                node_updates: dict[tuple[int, bytes], tuple[bytes, bytes]] = {}
                for prefix in top_prefixes:
                    old_digest, children = self._runtime_rows_v2_node(connection, 8, prefix)
                    next_children = dict(children)
                    for bucket in (item for item in touched_buckets if item[:1] == prefix):
                        old_child, new_child = bucket_changes[bucket]
                        edge = bucket[1]
                        if next_children.get(edge, empty_bucket) != old_child:
                            raise DerivedCheckpointError(
                                "runtime v2 bucket differs from its parent node"
                            )
                        if new_child == empty_bucket:
                            next_children.pop(edge, None)
                        else:
                            next_children[edge] = new_child
                    new_digest = self._runtime_rows_v2_node_digest(8, next_children)
                    children_payload = _encode_state_storage_children(next_children)
                    node_updates[(8, prefix)] = (new_digest, children_payload)
                    top_changes[prefix] = (old_digest, new_digest, children_payload)

                old_root, root_children = self._runtime_rows_v2_node(connection, 0, b"")
                next_root_children = dict(root_children)
                empty_top = self._runtime_rows_v2_empty_node_digest(8)
                for prefix, (old_child, new_child, _payload) in top_changes.items():
                    edge = prefix[0]
                    if next_root_children.get(edge, empty_top) != old_child:
                        raise DerivedCheckpointError(
                            "runtime v2 top node differs from its root"
                        )
                    if new_child == empty_top:
                        next_root_children.pop(edge, None)
                    else:
                        next_root_children[edge] = new_child
                next_root = self._runtime_rows_v2_node_digest(0, next_root_children)
                node_updates[(0, b"")] = (
                    next_root,
                    _encode_state_storage_children(next_root_children),
                )
                try:
                    row_count = int(
                        connection.execute("SELECT COUNT(*) FROM derived_row").fetchone()[0]
                    ) + inserted
                except (sqlite3.Error, TypeError, IndexError) as exc:
                    raise DerivedCheckpointError("runtime v2 row count is unreadable") from exc
                manifest = {
                    "record_type": "DerivedRowsCheckpoint",
                    "version": _RUNTIME_ROWS_V2_INDEX_VERSION,
                    "authoritative": False,
                    "name": _RUNTIME_ROWS_V2_NAME,
                    "activation_digest": self.active_activation_digest,
                    "implementation_closure_digest": self.implementation_closure_digest,
                    "head": copy.deepcopy(checked_head),
                    "batch_count": self._batch_count,
                    "event_count": self._event_count,
                    "event_semantic_digest": self._semantic_digest,
                    "authority_state_binding_digest": state_binding_digest,
                    "checkpoint_count": checkpoint_count,
                    "row_count": row_count,
                    "row_merkle_digest": next_root.hex(),
                }
                manifest["checkpoint_digest"] = digest_value(manifest)

                if changed:
                    connection.executemany(
                        "INSERT INTO derived_row("
                        "section, key, payload, payload_digest, identity_digest, bucket"
                        ") VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(section, key) "
                        "DO UPDATE SET payload=excluded.payload, "
                        "payload_digest=excluded.payload_digest, "
                        "identity_digest=excluded.identity_digest, bucket=excluded.bucket",
                        (
                            (
                                section,
                                key,
                                payload,
                                payload_digest,
                                identity_digest,
                                identity_digest[:_RUNTIME_ROWS_V2_BUCKET_BYTES],
                            )
                            for (section, key), (payload, payload_digest, identity_digest) in changed.items()
                        ),
                    )
                if bucket_deletes:
                    connection.executemany(
                        "DELETE FROM runtime_v2_bucket WHERE bucket = ?",
                        ((bucket,) for bucket in bucket_deletes),
                    )
                if bucket_upserts:
                    connection.executemany(
                        "INSERT INTO runtime_v2_bucket(bucket, digest) VALUES (?, ?) "
                        "ON CONFLICT(bucket) DO UPDATE SET digest=excluded.digest",
                        bucket_upserts,
                    )
                node_deletes: list[tuple[int, bytes]] = []
                node_upserts: list[tuple[int, bytes, bytes, bytes]] = []
                for (depth, prefix), (node_digest, children_payload) in node_updates.items():
                    if node_digest == self._runtime_rows_v2_empty_node_digest(depth):
                        node_deletes.append((depth, prefix))
                    else:
                        node_upserts.append((depth, prefix, node_digest, children_payload))
                if node_deletes:
                    connection.executemany(
                        "DELETE FROM runtime_v2_node WHERE depth = ? AND prefix = ?",
                        node_deletes,
                    )
                if node_upserts:
                    connection.executemany(
                        "INSERT INTO runtime_v2_node(depth, prefix, digest, children) "
                        "VALUES (?, ?, ?, ?) ON CONFLICT(depth, prefix) DO UPDATE SET "
                        "digest=excluded.digest, children=excluded.children",
                        node_upserts,
                    )
                connection.execute("DELETE FROM binding")
                connection.execute(
                    "INSERT INTO binding(singleton, manifest) VALUES (1, ?)",
                    (canonical_bytes(manifest, limits=_DERIVED_ROWS_MANIFEST_LIMITS),),
                )
                self._crash(crash_hook, "before_runtime_rows_v2_commit")
                connection.execute("COMMIT")
                committed = True
                connection.close()
                connection = None
                with open(_native_os_path(path), "rb+") as stream:
                    stream.flush()
                    os.fsync(stream.fileno())
                self._crash(crash_hook, "after_runtime_rows_v2_commit")
                self._derived_rows_issues[_RUNTIME_ROWS_V2_NAME] = None
                return copy.deepcopy(manifest)
            except sqlite3.Error as exc:
                if connection is not None:
                    try:
                        connection.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                raise DerivedCheckpointError("runtime v2 checkpoint write failed") from exc
            finally:
                if connection is not None:
                    if not committed:
                        try:
                            connection.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                    connection.close()

    @staticmethod
    def _decode_derived_row(
        section: Any,
        key: Any,
        payload: Any,
        payload_digest: Any,
    ) -> tuple[dict[str, Any], str]:
        if (
            not isinstance(section, str)
            or not _DERIVED_ROW_ID.fullmatch(section)
            or not isinstance(key, str)
            or not _DERIVED_ROW_ID.fullmatch(key)
            or not isinstance(payload, bytes)
            or not isinstance(payload_digest, str)
            or not _DIGEST.fullmatch(payload_digest)
            or hashlib.sha256(payload).hexdigest() != payload_digest
        ):
            raise DerivedCheckpointError("derived row storage value is invalid")
        try:
            normalized = parse_json_strict(payload, limits=_DERIVED_STATE_LIMITS)
            if canonical_bytes(
                normalized,
                limits=_DERIVED_STATE_LIMITS,
            ) != payload:
                raise DerivedCheckpointError("derived row payload is not canonical")
        except CanonicalError as exc:
            raise DerivedCheckpointError("derived row payload is invalid") from exc
        if (
            not isinstance(normalized, dict)
            or set(normalized) != {"section", "key", "value"}
            or normalized["section"] != section
            or normalized["key"] != key
        ):
            raise DerivedCheckpointError("derived row payload identity mismatch")
        _reject_reserved_secret_fields(
            normalized["value"],
            surface="derived row checkpoint",
            error_type=DerivedCheckpointError,
        )
        return normalized, payload_digest

    def _scan_derived_rows_locked(
        self,
        connection: sqlite3.Connection,
        manifest: Mapping[str, Any],
    ) -> None:
        transcript = _DERIVED_ROWS_TRANSCRIPT_GENESIS
        row_count = 0
        previous_identity: tuple[str, str] | None = None
        try:
            cursor = connection.execute(
                "SELECT section, key, payload, payload_digest "
                "FROM derived_row ORDER BY section, key"
            )
            for section, key, payload, payload_digest in cursor:
                _normalized, checked_digest = self._decode_derived_row(
                    section,
                    key,
                    payload,
                    payload_digest,
                )
                identity = (section, key)
                if previous_identity is not None and identity <= previous_identity:
                    raise DerivedCheckpointError(
                        "derived row storage order is not canonical"
                    )
                previous_identity = identity
                transcript = _extend_derived_rows_transcript(
                    transcript,
                    section=section,
                    key=key,
                    payload_digest=checked_digest,
                )
                row_count += 1
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("derived rows are unreadable") from exc
        if (
            row_count != manifest["row_count"]
            or transcript != manifest["row_transcript_digest"]
        ):
            raise DerivedCheckpointError(
                "derived rows differ from their bound transcript"
            )

    def _scan_runtime_rows_v2_locked(
        self,
        connection: sqlite3.Connection,
        manifest: Mapping[str, Any],
    ) -> None:
        """Verify every v2 row and reconstruct its keyed Merkle root.

        Reads intentionally pay the complete validation cost before the
        callback observes anything.  V2 improves compaction writes, never the
        evidentiary requirement that a derived cache be independently checked.
        """

        self._validate_runtime_rows_v2_schema(connection)
        row_count = 0
        stored_buckets: dict[bytes, bytes] = {}
        try:
            for bucket, digest in connection.execute(
                "SELECT bucket, digest FROM runtime_v2_bucket ORDER BY bucket"
            ):
                if (
                    not isinstance(bucket, bytes)
                    or len(bucket) != _RUNTIME_ROWS_V2_BUCKET_BYTES
                    or bucket in stored_buckets
                    or not isinstance(digest, bytes)
                    or len(digest) != 32
                    or digest == self._runtime_rows_v2_empty_bucket_digest()
                ):
                    raise DerivedCheckpointError("runtime v2 bucket storage is invalid")
                stored_buckets[bucket] = digest
            cursor = connection.execute(
                "SELECT section, key, payload, payload_digest, identity_digest, bucket "
                "FROM derived_row ORDER BY bucket, identity_digest"
            )
            current_bucket: bytes | None = None
            bucket_hash: hashlib._Hash | None = None
            observed_buckets: dict[bytes, bytes] = {}
            for section, key, payload, payload_digest, identity_digest, bucket in cursor:
                normalized, checked_digest = self._decode_derived_row(
                    section,
                    key,
                    payload,
                    payload_digest,
                )
                del normalized
                expected_identity = self._runtime_rows_v2_identity_digest(section, key)
                if (
                    identity_digest != expected_identity
                    or not isinstance(bucket, bytes)
                    or len(bucket) != _RUNTIME_ROWS_V2_BUCKET_BYTES
                    or bucket != expected_identity[:_RUNTIME_ROWS_V2_BUCKET_BYTES]
                ):
                    raise DerivedCheckpointError("runtime v2 row identity differs from storage")
                if current_bucket != bucket:
                    if current_bucket is not None:
                        assert bucket_hash is not None
                        observed_buckets[current_bucket] = bucket_hash.digest()
                    current_bucket = bucket
                    bucket_hash = hashlib.sha256(b"promin:runtime-rows-v2:bucket\x00")
                assert bucket_hash is not None
                bucket_hash.update(
                    self._runtime_rows_v2_leaf_digest(identity_digest, checked_digest)
                )
                row_count += 1
            if current_bucket is not None:
                assert bucket_hash is not None
                observed_buckets[current_bucket] = bucket_hash.digest()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("runtime v2 rows are unreadable") from exc
        if row_count != manifest["row_count"] or observed_buckets != stored_buckets:
            raise DerivedCheckpointError("runtime v2 rows differ from their commitment")

        expected_nodes: dict[tuple[int, bytes], tuple[bytes, bytes]] = {}
        root_children: dict[int, bytes] = {}
        grouped: dict[bytes, dict[int, bytes]] = {}
        for bucket, digest in observed_buckets.items():
            grouped.setdefault(bucket[:1], {})[bucket[1]] = digest
        for prefix, children in grouped.items():
            digest = self._runtime_rows_v2_node_digest(8, children)
            expected_nodes[(8, prefix)] = (
                digest,
                _encode_state_storage_children(children),
            )
            root_children[prefix[0]] = digest
        expected_nodes[(0, b"")] = (
            self._runtime_rows_v2_node_digest(0, root_children),
            _encode_state_storage_children(root_children),
        )
        observed_nodes: dict[tuple[int, bytes], tuple[bytes, bytes]] = {}
        try:
            for depth, prefix, digest, children in connection.execute(
                "SELECT depth, prefix, digest, children FROM runtime_v2_node "
                "ORDER BY depth, prefix"
            ):
                if (
                    depth not in {0, 8}
                    or not isinstance(prefix, bytes)
                    or len(prefix) != depth // 8
                    or not isinstance(digest, bytes)
                    or len(digest) != 32
                    or (depth, prefix) in observed_nodes
                ):
                    raise DerivedCheckpointError("runtime v2 node storage is invalid")
                decoded = _decode_state_storage_children(children)
                if self._runtime_rows_v2_node_digest(depth, decoded) != digest:
                    raise DerivedCheckpointError("runtime v2 node digest is invalid")
                observed_nodes[(depth, prefix)] = (digest, children)
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("runtime v2 nodes are unreadable") from exc
        if observed_nodes != expected_nodes:
            raise DerivedCheckpointError("runtime v2 nodes differ from their rows")
        if expected_nodes[(0, b"")][0].hex() != manifest["row_merkle_digest"]:
            raise DerivedCheckpointError("runtime v2 root differs from its manifest")

    def consume_derived_rows(
        self,
        name: str,
        consume_row: Callable[[dict[str, Any]], Any],
    ) -> dict[str, Any] | None:
        """Validate one row database, then consume every row from one snapshot.

        No row reaches the callback until schema, exact journal binding, row
        count, per-row canonical bytes, and the complete ordered transcript
        have passed.  The callback must not call back into this EventStore;
        the writer lock and SQLite read transaction remain held so the second
        pass cannot observe a different file or HEAD.
        """

        path = self._derived_rows_path(name)
        if not callable(consume_row):
            raise EventStoreError("derived row consumer must be callable")
        if not _path_exists(path):
            self._derived_rows_issues[name] = "derived rows checkpoint is missing"
            return None
        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            connection: sqlite3.Connection | None = None
            try:
                connection = sqlite3.connect(
                    _native_os_path(path),
                    timeout=self.lock_timeout,
                    isolation_level=None,
                )
                connection.execute(
                    f"PRAGMA busy_timeout={int(self.lock_timeout * 1000)}"
                )
                connection.execute("PRAGMA query_only=ON")
                connection.execute("BEGIN")
                layout = self._derived_rows_layout(connection)
                if layout == "v1":
                    self._validate_derived_rows_schema(connection)
                raw_manifest = self._read_derived_rows_manifest(connection)
                if layout == "v1":
                    manifest = self._validate_derived_rows_manifest_locked(
                        name,
                        raw_manifest,
                    )
                    self._scan_derived_rows_locked(connection, manifest)
                elif layout == "runtime-v2" and name == _RUNTIME_ROWS_V2_NAME:
                    manifest = self._validate_runtime_rows_v2_manifest_locked(
                        raw_manifest
                    )
                    self._scan_runtime_rows_v2_locked(connection, manifest)
                else:
                    raise DerivedCheckpointError("derived rows layout is unsupported")
            except (
                CanonicalError,
                DerivedCheckpointError,
                JournalCorruption,
                OSError,
                sqlite3.Error,
            ) as exc:
                self._derived_rows_issues[name] = f"{type(exc).__name__}: {exc}"
                if connection is not None:
                    try:
                        connection.execute("ROLLBACK")
                    except sqlite3.Error:
                        pass
                    connection.close()
                return None

            # The validation pass and callback pass share this one SQLite read
            # transaction.  Callback failures are semantic/consumer failures,
            # not silently reclassified as a storage-cache miss.
            assert connection is not None
            try:
                cursor = connection.execute(
                    "SELECT section, key, payload, payload_digest "
                    "FROM derived_row ORDER BY section, key"
                )
                for section, key, payload, payload_digest in cursor:
                    normalized, _checked_digest = self._decode_derived_row(
                        section,
                        key,
                        payload,
                        payload_digest,
                    )
                    consume_row(copy.deepcopy(normalized))
                connection.execute("COMMIT")
            finally:
                connection.close()
            self._derived_rows_issues[name] = None
            return copy.deepcopy(manifest)

    def derived_rows_tail_status(self, name: str) -> dict[str, Any]:
        """Measure the journal tail after a normalized row checkpoint."""

        path = self._derived_rows_path(name)
        checked_batch_threshold = self.policy.derived_tail_batch_threshold
        checked_byte_threshold = self.policy.derived_tail_byte_threshold
        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            manifest: dict[str, Any] | None = None
            issue: str | None = None
            connection: sqlite3.Connection | None = None
            if _path_exists(path):
                try:
                    connection = sqlite3.connect(
                        _native_os_path(path),
                        timeout=self.lock_timeout,
                        isolation_level=None,
                    )
                    connection.execute("PRAGMA query_only=ON")
                    connection.execute("BEGIN")
                    layout = self._derived_rows_layout(connection)
                    if layout == "v1":
                        self._validate_derived_rows_schema(connection)
                    raw_manifest = self._read_derived_rows_manifest(connection)
                    if layout == "v1":
                        manifest = self._validate_derived_rows_manifest_locked(
                            name,
                            raw_manifest,
                        )
                    elif layout == "runtime-v2" and name == _RUNTIME_ROWS_V2_NAME:
                        manifest = self._validate_runtime_rows_v2_manifest_locked(
                            raw_manifest
                        )
                    else:
                        raise DerivedCheckpointError("derived rows layout is unsupported")
                    connection.execute("COMMIT")
                except (
                    CanonicalError,
                    DerivedCheckpointError,
                    JournalCorruption,
                    OSError,
                    sqlite3.Error,
                ) as exc:
                    issue = f"{type(exc).__name__}: {exc}"
                    if connection is not None:
                        try:
                            connection.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                finally:
                    if connection is not None:
                        connection.close()
            else:
                issue = "derived rows checkpoint is missing"
            checkpoint_sequence = (
                0 if manifest is None else manifest["head"]["sequence"]
            )
            checkpoint_count = (
                0 if manifest is None else manifest["checkpoint_count"]
            )
            tail_bytes = 0
            for sequence in range(
                checkpoint_sequence + 1,
                self._head["sequence"] + 1,
            ):
                try:
                    tail_bytes += os.stat(
                        _native_os_path(self._journal_path_for_sequence(sequence))
                    ).st_size
                except OSError as exc:
                    raise JournalCorruption(
                        "derived rows tail journal file is unavailable"
                    ) from exc
            tail_batches = self._head["sequence"] - checkpoint_sequence
            self._derived_rows_issues[name] = issue
            return {
                "record_type": "DerivedRowsTailStatus",
                "authoritative": False,
                "name": name,
                "head": self.head(),
                "checkpoint_head_sequence": checkpoint_sequence,
                "checkpoint_count": checkpoint_count,
                "tail_batches": tail_batches,
                "tail_bytes": tail_bytes,
                "batch_threshold": checked_batch_threshold,
                "byte_threshold": checked_byte_threshold,
                "compaction_due": manifest is None
                or tail_batches >= checked_batch_threshold
                or tail_bytes >= checked_byte_threshold,
                "checkpoint_issue": issue,
            }

    def derived_rows_issue(self, name: str) -> str | None:
        self._derived_rows_path(name)
        return self._derived_rows_issues.get(name)

    def derived_rows_storage_bytes(self, name: str) -> int:
        """Measure the current disposable row database without granting credit."""

        path = self._derived_rows_path(name)
        try:
            if _is_symlink(path) or not os.path.isfile(_native_os_path(path)):
                return 0
            return int(os.stat(_native_os_path(path), follow_symlinks=False).st_size)
        except OSError:
            return 0

    def derived_tail_status(self, name: str) -> dict[str, Any]:
        """Measure the event tail after a verified disposable checkpoint."""

        path = self._derived_state_path(name)
        checked_batch_threshold = self.policy.derived_tail_batch_threshold
        checked_byte_threshold = self.policy.derived_tail_byte_threshold
        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            checkpoint: dict[str, Any] | None = None
            issue: str | None = None
            if _path_exists(path):
                try:
                    checkpoint = self._validate_derived_state_record(
                        name,
                        self._read_canonical_object(path, limits=_DERIVED_STATE_LIMITS),
                    )
                except (CanonicalError, DerivedCheckpointError, JournalCorruption, OSError) as exc:
                    issue = f"{type(exc).__name__}: {exc}"
            else:
                issue = "derived state checkpoint is missing"
            checkpoint_sequence = 0 if checkpoint is None else checkpoint["head"]["sequence"]
            checkpoint_count = 0
            if checkpoint is not None:
                state = checkpoint.get("state")
                compaction = state.get("compaction") if isinstance(state, Mapping) else None
                value = (
                    compaction.get("checkpoint_count")
                    if isinstance(compaction, Mapping)
                    else None
                )
                if (
                    not isinstance(value, int)
                    or isinstance(value, bool)
                    or value < 1
                ):
                    raise DerivedCheckpointError(
                        "derived state checkpoint count is invalid"
                    )
                checkpoint_count = value
            tail_bytes = 0
            for sequence in range(checkpoint_sequence + 1, self._head["sequence"] + 1):
                try:
                    tail_bytes += os.stat(
                        _native_os_path(self._journal_path_for_sequence(sequence))
                    ).st_size
                except OSError as exc:
                    raise JournalCorruption(
                        "derived tail journal file is unavailable"
                    ) from exc
            tail_batches = self._head["sequence"] - checkpoint_sequence
            self._derived_state_issues[name] = issue
            return {
                "record_type": "DerivedTailStatus",
                "authoritative": False,
                "name": name,
                "head": self.head(),
                "checkpoint_head_sequence": checkpoint_sequence,
                "checkpoint_count": checkpoint_count,
                "tail_batches": tail_batches,
                "tail_bytes": tail_bytes,
                "batch_threshold": checked_batch_threshold,
                "byte_threshold": checked_byte_threshold,
                "compaction_due": checkpoint is None
                or tail_batches >= checked_batch_threshold
                or tail_bytes >= checked_byte_threshold,
                "checkpoint_issue": issue,
            }

    def write_derived_state(
        self,
        name: str,
        state: Any,
        *,
        expected_head: Mapping[str, Any] | None = None,
        crash_hook: Callable[[str], Any] | None = None,
    ) -> dict[str, Any]:
        """Persist disposable canonical runtime state bound to exact event HEAD."""

        path = self._derived_state_path(name)
        try:
            normalized_state = parse_json_strict(
                canonical_bytes(state, limits=_DERIVED_STATE_LIMITS),
                limits=_DERIVED_STATE_LIMITS,
            )
        except CanonicalError as exc:
            raise EventStoreError(f"derived state is not bounded canonical JSON: {exc}") from exc
        _reject_reserved_secret_fields(normalized_state, surface="derived state checkpoint")
        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            if expected_head is not None:
                checked_expected_head = self._validate_head_value(dict(expected_head))
                if checked_expected_head != self._head:
                    raise DerivedCheckpointError(
                        "derived state was computed for a stale authoritative HEAD"
                    )
            state_binding_digest = self._journal_state_binding_for_head_locked(
                self._head
            )
            if state_binding_digest is None:
                raise DerivedCheckpointError(
                    "authoritative HEAD has no prepared semantic state binding"
                )
            _invoke_derived_state_validator(
                self.derived_state_validator,
                name,
                normalized_state,
                state_binding_digest,
            )
            value = {
                "record_type": "DerivedStateCheckpoint",
                "version": 3,
                "authoritative": False,
                "name": name,
                "activation_digest": self.active_activation_digest,
                "implementation_closure_digest": self.implementation_closure_digest,
                "head": self.head(),
                "batch_count": self._batch_count,
                "event_count": self._event_count,
                "event_semantic_digest": self._semantic_digest,
                "state": normalized_state,
                "state_digest": digest_value(normalized_state),
                "authority_state_binding_digest": state_binding_digest,
            }
            value["checkpoint_digest"] = digest_value(value)
            self._crash(crash_hook, "before_derived_checkpoint")
            _write_atomic(path, canonical_bytes(value, limits=_DERIVED_STATE_LIMITS))
            self._crash(crash_hook, "after_derived_checkpoint")
            self._derived_state_issues[name] = None
            return copy.deepcopy(value)

    def _validate_derived_state_record(self, name: str, record: Mapping[str, Any]) -> dict[str, Any]:
        value = copy.deepcopy(dict(record))
        required = {
            "record_type", "version", "authoritative", "name", "activation_digest", "head",
            "batch_count", "event_count", "event_semantic_digest", "state", "state_digest",
            "implementation_closure_digest", "authority_state_binding_digest",
            "checkpoint_digest",
        }
        if set(value) != required or value.get("record_type") != "DerivedStateCheckpoint":
            raise DerivedCheckpointError("derived state checkpoint fields mismatch")
        supplied_digest = value.pop("checkpoint_digest")
        if not isinstance(supplied_digest, str) or digest_value(value) != supplied_digest:
            raise DerivedCheckpointError("derived state checkpoint digest mismatch")
        value["checkpoint_digest"] = supplied_digest
        if (
            value["version"] != 3
            or value["authoritative"] is not False
            or value["name"] != name
            or value["activation_digest"] != self.active_activation_digest
            or value["implementation_closure_digest"] != self.implementation_closure_digest
        ):
            raise DerivedCheckpointError("derived state checkpoint binding mismatch")
        _reject_reserved_secret_fields(
            value["state"],
            surface="derived state checkpoint",
            error_type=DerivedCheckpointError,
        )
        head = self._validate_head_value(value["head"])
        value["head"] = head
        journal_state_binding = self._journal_state_binding_for_head_locked(head)
        if (
            journal_state_binding is None
            or value["authority_state_binding_digest"] != journal_state_binding
        ):
            raise DerivedCheckpointError(
                "derived state lacks the exact journal-owned state commitment"
            )
        _invoke_derived_state_validator(
            self.derived_state_validator,
            name,
            value["state"],
            journal_state_binding,
        )
        if (
            not isinstance(value["batch_count"], int)
            or isinstance(value["batch_count"], bool)
            or value["batch_count"] != head["sequence"]
            or not isinstance(value["event_count"], int)
            or isinstance(value["event_count"], bool)
            or value["event_count"] < value["batch_count"]
            or not isinstance(value["event_semantic_digest"], str)
            or not _DIGEST.fullmatch(value["event_semantic_digest"])
            or not isinstance(value["state_digest"], str)
            or not _DIGEST.fullmatch(value["state_digest"])
            or digest_value(value["state"]) != value["state_digest"]
        ):
            raise DerivedCheckpointError("derived state checkpoint content is invalid")
        current = self._head
        if head["sequence"] > current["sequence"]:
            raise DerivedCheckpointError("derived state checkpoint is ahead of authoritative HEAD")
        if head["sequence"] == current["sequence"]:
            if head != current:
                raise DerivedCheckpointError("derived state checkpoint is bound to another HEAD")
        else:
            first_path = self._journal_path_for_sequence(head["sequence"] + 1)
            first = self._read_envelope(first_path)
            self._validate_envelope(
                first,
                expected_sequence=head["sequence"] + 1,
                expected_previous_digest=head["batch_digest"],
                validate_runtime=False,
            )
        return value

    def read_derived_state(self, name: str) -> dict[str, Any] | None:
        """Return a valid current or ancestor checkpoint; corruption is a miss."""

        path = self._derived_state_path(name)
        if not _path_exists(path):
            self._derived_state_issues[name] = "derived state checkpoint is missing"
            return None
        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            try:
                record = self._read_canonical_object(path, limits=_DERIVED_STATE_LIMITS)
                validated = self._validate_derived_state_record(name, record)
            except (CanonicalError, DerivedCheckpointError, JournalCorruption, OSError) as exc:
                self._derived_state_issues[name] = f"{type(exc).__name__}: {exc}"
                return None
            self._derived_state_issues[name] = None
            return copy.deepcopy(validated)

    def derived_state_issue(self, name: str) -> str | None:
        self._derived_state_path(name)
        return self._derived_state_issues.get(name)

    def replay_delta(
        self,
        reducer: Callable[[T, dict[str, Any]], T],
        checkpoint: Mapping[str, Any],
    ) -> ReplayResult:
        """Restore canonical state and replay only events after its verified HEAD."""

        name = checkpoint.get("name") if isinstance(checkpoint, Mapping) else None
        if not isinstance(name, str):
            raise DerivedCheckpointError("derived state checkpoint name is missing")
        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            validated = self._validate_derived_state_record(name, checkpoint)
            state = copy.deepcopy(validated["state"])
            event_count = validated["event_count"]
            batch_count = validated["batch_count"]
            semantic_digest = validated["event_semantic_digest"]
            last_head = copy.deepcopy(validated["head"])
            for envelope in self._envelopes_after_locked(
                validated["head"], validate=True
            ):
                batch = envelope["batch"]
                for event in batch["events"]:
                    state = reducer(state, copy.deepcopy(event))
                    semantic_digest = _extend_event_semantic_digest(semantic_digest, event)
                    event_count += 1
                last_head = {
                    "sequence": batch["sequence"],
                    "batch_id": batch["batch_id"],
                    "batch_digest": digest_value(batch),
                }
                batch_count += 1
            if (
                last_head != self._head
                or batch_count != self._batch_count
                or event_count != self._event_count
                or semantic_digest != self._semantic_digest
            ):
                raise DerivedCheckpointError(
                    "delta replay differs from authoritative event checkpoint"
                )
            return ReplayResult(
                state,
                copy.deepcopy(last_head),
                batch_count,
                event_count,
                semantic_digest,
            )

    def replay(
        self,
        reducer: Callable[[T, dict[str, Any]], T],
        initial_state: T,
        *,
        until_sequence: int | None = None,
    ) -> ReplayResult:
        """Replay in sequence and event time, re-running every validator."""

        if until_sequence is not None and until_sequence < 0:
            raise EventStoreError("until_sequence cannot be negative")
        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            state = copy.deepcopy(initial_state)
            event_count = 0
            batch_count = 0
            last_head = self._empty_head()
            semantic_digest = self.policy.genesis_event_semantic_digest
            for envelope in self._iter_envelopes_locked(validate=True):
                batch = envelope["batch"]
                if until_sequence is not None and batch["sequence"] > until_sequence:
                    break
                for event in batch["events"]:
                    state = reducer(state, copy.deepcopy(event))
                    semantic_digest = _extend_event_semantic_digest(
                        semantic_digest, event
                    )
                    event_count += 1
                batch_digest = digest_value(batch)
                last_head = {
                    "sequence": batch["sequence"],
                    "batch_id": batch["batch_id"],
                    "batch_digest": batch_digest,
                }
                batch_count += 1
            result = ReplayResult(
                state, last_head, batch_count, event_count, semantic_digest
            )
            if until_sequence is None and (
                result.head != self._head
                or result.batch_count != self._batch_count
                or result.event_count != self._event_count
                or result.semantic_digest != self._semantic_digest
            ):
                raise JournalCorruption(
                    "full replay differs from journal-owned prefix commitment"
                )
            return result

    def _read_envelope(self, path: Path) -> dict[str, Any]:
        try:
            raw = _read_bytes(path)
            limits = ParseLimits(max_bytes=self.policy.max_envelope_bytes)
            value = parse_json_strict(raw, limits=limits)
        except (OSError, CanonicalError) as exc:
            raise JournalCorruption(f"journal envelope is unreadable: {path.name}") from exc
        if canonical_bytes(value, limits=limits) != raw:
            raise JournalCorruption(f"journal envelope is not canonical: {path.name}")
        if not isinstance(value, dict):
            raise JournalCorruption("journal envelope must be an object")
        _reject_reserved_secret_fields(
            value,
            surface="journal envelope",
            error_type=JournalCorruption,
        )
        return value

    def _read_disk_head(self) -> dict[str, Any]:
        if not _path_exists(self.head_path):
            return self._empty_head()
        try:
            raw = _read_bytes(self.head_path)
            limits = ParseLimits(max_bytes=self.policy.max_command_bytes)
            value = parse_json_strict(raw, limits=limits)
            if canonical_bytes(value, limits=limits) != raw:
                raise CanonicalError("HEAD is not canonical")
            return self._validate_head_value(value)
        except (OSError, CanonicalError, DerivedCheckpointError) as exc:
            raise JournalCorruption("HEAD is unreadable") from exc

    @staticmethod
    def _result(command: dict[str, Any], batch_digest: str, outcome: str, batch: dict[str, Any]) -> dict[str, Any]:
        return {
            "record_type": "CommandResult",
            "command_id": command["command_id"],
            "outcome": outcome,
            "batch_digest": batch_digest,
            "reason_codes": [],
            "facts": {
                "batch_id": batch["batch_id"],
                "sequence": batch["sequence"],
                "primary_event_id": batch["events"][0]["event_id"],
            },
            "created_at": batch["created_at"],
        }

    @staticmethod
    def _as_idempotent(result: dict[str, Any]) -> dict[str, Any]:
        replay = copy.deepcopy(result)
        replay["outcome"] = "idempotent-replay"
        return replay
