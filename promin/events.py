"""Authoritative, append-only Promin event batches.

The journal stores the validated command beside its Core ``EventBatch``.  The
command is required for event-time authorization during replay; the projection
is deliberately not used as authority.
"""

from __future__ import annotations

import base64
import copy
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
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_INDEX_GENERATION = re.compile(r"^[0-9a-f]{32}$")
_EVENT_IDENTITY_INDEX_NAME = "event-identities.sqlite3"
_EVENT_IDENTITY_INDEX_VERSION = 1
_STATE_BINDING_INDEX_NAME = "state-binding.sqlite3"
_STATE_BINDING_INDEX_VERSION = 1
_STATE_BINDING_ALGORITHM = "typed-sparse-merkle-v1"
_STATE_TREE_DEPTH = 256

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


def _extend_event_semantic_digest(previous: str, event: Mapping[str, Any]) -> str:
    """Extend a deterministic event transcript without retaining prior bytes."""

    if not _DIGEST.fullmatch(previous):
        raise EventStoreError("event semantic digest is invalid")
    return digest_value({"previous_digest": previous, "event": dict(event)})


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
        self.journal = self.root / "journal"
        self.pending = self.root / "pending"
        self.head_path = self.root / "HEAD.json"
        self.checkpoint_path = self.root / "journal-checkpoint.json"
        self.authority_root = self.root / "journal-authority"
        self.authority_head_path = self.root / "journal-authority-root.json"
        self.implementation_binding_path = self.root / "implementation-closure.json"
        self.index_root = self.root / "derived-index"
        self.derived_state_root = self.root / "derived-state"
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
        self._last_commit_write_metrics = self._empty_commit_write_metrics()
        os.makedirs(_native_os_path(self.root), exist_ok=True)
        os.makedirs(_native_os_path(self.journal), exist_ok=True)
        os.makedirs(_native_os_path(self.pending), exist_ok=True)
        os.makedirs(_native_os_path(self.authority_root), exist_ok=True)
        os.makedirs(_native_os_path(self.index_root), exist_ok=True)
        os.makedirs(_native_os_path(self.derived_state_root), exist_ok=True)
        self._verify_or_create_implementation_binding()
        self._open_or_recover()

    @staticmethod
    def _empty_head() -> dict[str, Any]:
        return {"sequence": 0, "batch_id": None, "batch_digest": None}

    def head(self) -> dict[str, Any]:
        """O(1) lookup of the last durably committed batch identity."""

        return copy.deepcopy(self._head)

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
        with _WriterLock(self.lock_path, self.lock_timeout):
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

    def _recover_locked(self) -> dict[str, Any]:
        head = self._empty_head()
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
            computed_state_root, state_overlay = self._stage_state_binding_delta(
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
            self._publish_state_binding_delta(
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
            head = {"sequence": batch["sequence"], "batch_id": batch["batch_id"], "batch_digest": batch_digest}
            previous_digest = batch_digest
            previous_authority_commitment = expected_authority_commitment
            expected_sequence += 1
        try:
            disk_head = self._read_disk_head()
        except JournalCorruption:
            disk_head = None
        if disk_head != head:
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
        self._write_journal_checkpoint(
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
        # Recovery generations are disposable projections.  Keeping every
        # successful replay forever makes an otherwise small control layer grow
        # linearly with health checks and repairs.  The current generation plus
        # one previous generation are sufficient for diagnostics and rollback;
        # authoritative history remains in ``journal/``.
        self._prune_recovery_generations(
            active_index_generation=index_generation,
            active_authority_generation=authority_generation,
        )
        return self.head()

    @staticmethod
    def _prune_generation_root(
        root: Path,
        *,
        active_generation: str,
        retain: int = 2,
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

    def _load_journal_checkpoint_locked(self) -> None:
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
        authority_root = self._verify_authority_prefix_locked(head)
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
            connection.execute("PRAGMA journal_mode=TRUNCATE")
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
            connection.execute("PRAGMA journal_mode=TRUNCATE")
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
                "PRIMARY KEY(depth, prefix)) WITHOUT ROWID"
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
            connection.executemany(
                "INSERT INTO node(depth, prefix, digest) VALUES (?, ?, ?)",
                (
                    (depth, prefix, node_digest)
                    for (depth, prefix), node_digest in sorted(
                        self._genesis_state_binding_nodes.items(),
                        key=lambda item: (item[0][0], item[0][1]),
                    )
                ),
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
    def _state_node_digest(
        connection: sqlite3.Connection,
        depth: int,
        prefix: bytes,
        overlay: Mapping[tuple[int, bytes], bytes] | None = None,
    ) -> bytes:
        identity = (depth, prefix)
        if overlay is not None and identity in overlay:
            return overlay[identity]
        try:
            row = connection.execute(
                "SELECT digest FROM node WHERE depth = ? AND prefix = ?",
                (depth, prefix),
            ).fetchone()
        except sqlite3.Error as exc:
            raise DerivedCheckpointError("state binding tree node is unreadable") from exc
        if row is None:
            return _STATE_DEFAULT_DIGESTS[depth]
        if len(row) != 1 or not isinstance(row[0], bytes) or len(row[0]) != 32:
            raise DerivedCheckpointError("state binding tree node is invalid")
        return row[0]

    def _state_path_root(
        self,
        connection: sqlite3.Connection,
        key_digest: bytes,
        overlay: Mapping[tuple[int, bytes], bytes],
    ) -> bytes:
        current = self._state_node_digest(
            connection,
            _STATE_TREE_DEPTH,
            _state_prefix(key_digest, _STATE_TREE_DEPTH),
            overlay,
        )
        for child_depth in range(_STATE_TREE_DEPTH, 0, -1):
            bit_index = child_depth - 1
            sibling_prefix = bytearray(_state_prefix(key_digest, child_depth))
            sibling_prefix[bit_index // 8] ^= 1 << (7 - (bit_index % 8))
            sibling = self._state_node_digest(
                connection, child_depth, bytes(sibling_prefix), overlay
            )
            parent_depth = child_depth - 1
            if key_digest[bit_index // 8] & (1 << (7 - (bit_index % 8))):
                current = _state_internal_digest(parent_depth, sibling, current)
            else:
                current = _state_internal_digest(parent_depth, current, sibling)
        return current

    def _stage_state_binding_delta(
        self,
        generation: str,
        delta: tuple[dict[str, Any], ...],
        *,
        prior_sequence: int,
        prior_root_digest: str | None,
        prior_update_count: int,
    ) -> tuple[str, dict[tuple[int, bytes], bytes]]:
        connection = self._state_binding_connection(generation)
        overlay: dict[tuple[int, bytes], bytes] = {}
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
            for update in delta:
                key_digest = _state_leaf_key_digest(update)
                if self._state_path_root(connection, key_digest, overlay) != current_root:
                    raise DerivedCheckpointError(
                        "state binding touched-path proof differs from current root"
                    )
                leaf_digest = (
                    _state_leaf_digest(key_digest, update["value_digest"])
                    if update["operation"] == "set"
                    else _STATE_DEFAULT_DIGESTS[_STATE_TREE_DEPTH]
                )
                overlay[
                    (_STATE_TREE_DEPTH, _state_prefix(key_digest, _STATE_TREE_DEPTH))
                ] = leaf_digest
                current = leaf_digest
                for child_depth in range(_STATE_TREE_DEPTH, 0, -1):
                    bit_index = child_depth - 1
                    sibling_prefix = bytearray(
                        _state_prefix(key_digest, child_depth)
                    )
                    sibling_prefix[bit_index // 8] ^= 1 << (7 - (bit_index % 8))
                    sibling = self._state_node_digest(
                        connection, child_depth, bytes(sibling_prefix), overlay
                    )
                    parent_depth = child_depth - 1
                    if key_digest[bit_index // 8] & (1 << (7 - (bit_index % 8))):
                        current = _state_internal_digest(parent_depth, sibling, current)
                    else:
                        current = _state_internal_digest(parent_depth, current, sibling)
                    overlay[(parent_depth, _state_prefix(key_digest, parent_depth))] = current
                current_root = current
            return current_root.hex(), overlay
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
        overlay: Mapping[tuple[int, bytes], bytes],
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
            for (depth, prefix), node_digest in sorted(
                overlay.items(), key=lambda item: (item[0][0], item[0][1])
            ):
                if node_digest == _STATE_DEFAULT_DIGESTS[depth]:
                    connection.execute(
                        "DELETE FROM node WHERE depth = ? AND prefix = ?",
                        (depth, prefix),
                    )
                else:
                    connection.execute(
                        "INSERT INTO node(depth, prefix, digest) VALUES (?, ?, ?) "
                        "ON CONFLICT(depth, prefix) DO UPDATE SET digest=excluded.digest",
                        (depth, prefix, node_digest),
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
        logical_bytes = sum(2 + len(prefix) + len(node_digest) for (depth, prefix), node_digest in overlay.items())
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
            root_node = self._state_node_digest(connection, 0, b"")
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

    def commit(
        self,
        command: Mapping[str, Any],
        *,
        auxiliary_relations: Iterable[Mapping[str, Any]] = (),
        created_at: str | None = None,
        crash_hook: Callable[[str], Any] | None = None,
    ) -> dict[str, Any]:
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
        with _WriterLock(self.lock_path, self.lock_timeout):
            self._last_commit_write_metrics = self._empty_commit_write_metrics()
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
                    self._stage_state_binding_delta(
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
                    self._stage_state_binding_delta(
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
                recovered_root, state_binding_overlay = self._stage_state_binding_delta(
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
            if self._index_generation is None:
                raise DerivedCheckpointError("event index generation is unavailable")
            index_bytes = self._write_envelope_index_entries(
                envelope,
                journal_path,
                batch_digest,
                command_digest,
                result,
                self._index_generation,
            )
            state_index_bytes, state_node_writes = self._publish_state_binding_delta(
                state_generation,
                sequence=batch["sequence"],
                prior_root_digest=prior_state_binding_digest,
                prior_update_count=prior_state_binding_update_count,
                root_digest=batch["state_binding_digest"],
                delta_count=len(prepared.state_binding_delta),
                overlay=state_binding_overlay,
            )
            self._crash(crash_hook, "after_state_binding_index")
            index_bytes += state_index_bytes
            new_semantic_digest = batch["event_semantic_digest"]
            new_event_count = batch["cumulative_event_count"]
            new_state_binding_update_count = batch[
                "cumulative_state_binding_update_count"
            ]
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
            journal_checkpoint_bytes = len(canonical_bytes(journal_checkpoint))
            self._crash(crash_hook, "after_checkpoint")
            _unlink(pending_path, missing_ok=True)
            _fsync_directory(self.pending)
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
        for path in sorted(_matching_paths(self.journal, "*.json")):
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
        """Resolve one batch digest through the disposable targeted index."""

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

    def validate_state_binding_leaves(
        self,
        leaves: Iterable[Mapping[str, Any]],
        *,
        expected_head: Mapping[str, Any],
    ) -> str:
        """Prove complete restored authority/domain values against journal HEAD."""

        try:
            limits = ParseLimits(max_bytes=_DERIVED_STATE_LIMITS.max_bytes)
            normalized = parse_json_strict(
                canonical_bytes(list(leaves), limits=limits), limits=limits
            )
        except (CanonicalError, TypeError, ValueError) as exc:
            raise DerivedCheckpointError(
                f"restored state leaves are not bounded canonical JSON: {exc}"
            ) from exc
        if not isinstance(normalized, list):
            raise DerivedCheckpointError("restored state leaves must be an array")
        identities: list[tuple[str, str]] = []
        computed: list[dict[str, str]] = []
        for leaf in normalized:
            if not isinstance(leaf, dict) or set(leaf) != {"leaf_type", "value"}:
                raise DerivedCheckpointError("restored state leaf fields mismatch")
            leaf_type = leaf["leaf_type"]
            value = leaf["value"]
            if (
                leaf_type == "Activation"
                or leaf_type not in self.policy.allowed_state_binding_leaf_type_set
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
            identities.append((leaf_type, leaf_id))
            computed.append(
                {
                    "leaf_type": leaf_type,
                    "leaf_id": leaf_id,
                    "value_digest": digest_value(value),
                }
            )
        if identities != sorted(identities) or len(identities) != len(set(identities)):
            raise DerivedCheckpointError(
                "restored state leaves must use unique canonical leaf order"
            )
        activation_leaf = {
            "leaf_type": "Activation",
            "leaf_id": self.active_activation_digest,
            "value_digest": self.activation_record_digest,
        }
        computed_root = _state_binding_root_from_leaves(
            itertools.chain((activation_leaf,), computed)
        )
        checked_head = self._validate_head_value(dict(expected_head))
        with _WriterLock(self.lock_path, self.lock_timeout):
            self._refresh_from_disk_locked()
            if checked_head != self._head:
                raise DerivedCheckpointError(
                    "restored state leaves are bound to a stale journal HEAD"
                )
            journal_root = self._journal_state_binding_for_head_locked(checked_head)
            if journal_root is None or computed_root != journal_root:
                raise DerivedCheckpointError(
                    "restored state leaves do not reproduce the journal state binding"
                )
            return computed_root

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
