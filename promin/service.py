from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Iterator, Mapping, Sequence

from .authority import AuthorityEngine
from .canonical import (
    atomic_write_bytes,
    atomic_write_json,
    canonical_bytes,
    digest_value,
    format_utc_second,
    load_json_strict,
    parse_json_strict,
    parse_utc_second,
)
from .contracts import (
    ContractBundle,
    ContractError,
    compile_candidate_recipe,
    validate_candidate_consistency,
    validate_definition,
    validate_ingress,
)
from .domain import DomainState
from .events import (
    CommitReadView,
    CommitStateSnapshot,
    EventStore,
    EventStorePolicy,
    PreparedCommit,
    state_binding_leaf_id,
    state_binding_value_digest,
)
from .evidence import EvidenceStore
from .init import (
    ActivationContext,
    ActivationGuard,
    InitRequest,
    activation_read_bindings,
    activation_read_fingerprint,
    initialize_project,
    verify_before_mutation,
    verify_provider_preflight,
    _jsonschema_files,
)
from .projection import (
    Projection,
    ProjectionError,
    ProjectionLimits,
    RankedCandidateCache,
    VerifiedInventoryInput,
    compile_relation_domains,
)


ZERO_DIGEST = "0" * 64
BASE_COMMANDS = ("init", "doctor", "status", "next", "validate", "continue", "audit", "refresh", "context", "skills")


def _thaw_frozen(value: Any) -> Any:
    """Convert immutable commit views back to plain JSON-compatible values."""
    if isinstance(value, Mapping):
        return {str(key): _thaw_frozen(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_thaw_frozen(item) for item in value]
    return value
_INVENTORY_SEARCH_TEXT_MAX_BYTES = 4_096
_INVENTORY_JSONL_ROW_MAX_BYTES = 16_384


class ServiceError(RuntimeError):
    """Raised when an application workflow cannot prove its prerequisites."""


def _serialized_mutation(method: Any) -> Any:
    @wraps(method)
    def invoke(service: "ProminService", *args: Any, **kwargs: Any) -> Any:
        with service._query_runtime_lock:
            try:
                return method(service, *args, **kwargs)
            except Exception:
                service._clear_query_runtime()
                raise

    return invoke


@dataclass(frozen=True)
class _RuntimeCheckpointCursor:
    activation_digest: str
    implementation_closure_digest: str
    head_sequence: int
    head_batch_id: str | None
    head_digest: str | None
    checkpoint_count: int
    tail_batches: int
    tail_bytes: int


@dataclass(frozen=True)
class _DecisionBindings:
    parent: "_DecisionBindings | None" = None
    additions: tuple[tuple[str, Mapping[str, Any]], ...] = ()

    def resolve(self, decision_id: str) -> Mapping[str, Any] | None:
        for current_id, value in reversed(self.additions):
            if current_id == decision_id:
                return _thaw_frozen(value)
        return None if self.parent is None else self.parent.resolve(decision_id)

    def extend(
        self,
        decision_id: str,
        decision: Mapping[str, Any],
        event: Mapping[str, Any],
    ) -> "_DecisionBindings":
        if self.resolve(decision_id) is not None:
            raise ServiceError("Decision Event identity is duplicated")
        return _DecisionBindings(
            self,
            (
                (
                    decision_id,
                    MappingProxyType(
                        {
                            "decision": deepcopy(dict(decision)),
                            "event": deepcopy(dict(event)),
                        }
                    ),
                ),
            ),
        )

    def materialize(self) -> tuple[dict[str, Any], ...]:
        chain: list[_DecisionBindings] = []
        cursor: _DecisionBindings | None = self
        while cursor is not None:
            chain.append(cursor)
            cursor = cursor.parent
        return tuple(
            {
                "decision_id": decision_id,
                "binding": deepcopy(dict(binding)),
            }
            for node in reversed(chain)
            for decision_id, binding in node.additions
        )

    @classmethod
    def restore(cls, values: Any) -> "_DecisionBindings":
        if not isinstance(values, list):
            raise ServiceError("runtime checkpoint Decision bindings are invalid")
        restored = cls()
        for item in values:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"decision_id", "binding"}
                or not isinstance(item.get("decision_id"), str)
                or not isinstance(item.get("binding"), Mapping)
                or set(item["binding"]) != {"decision", "event"}
                or not isinstance(item["binding"]["decision"], Mapping)
                or not isinstance(item["binding"]["event"], Mapping)
            ):
                raise ServiceError("runtime checkpoint Decision binding is malformed")
            restored = restored.extend(
                item["decision_id"],
                item["binding"]["decision"],
                item["binding"]["event"],
            )
        return restored


@dataclass(frozen=True)
class _RelationLedger:
    parent: "_RelationLedger | None" = None
    additions: tuple[Mapping[str, Any], ...] = ()

    def extend(self, values: Iterable[Mapping[str, Any]]) -> "_RelationLedger":
        additions = tuple(
            MappingProxyType(deepcopy(dict(value))) for value in values
        )
        return self if not additions else _RelationLedger(self, additions)

    def materialize(self) -> tuple[dict[str, Any], ...]:
        chain: list[_RelationLedger] = []
        cursor: _RelationLedger | None = self
        while cursor is not None:
            chain.append(cursor)
            cursor = cursor.parent
        return tuple(
            deepcopy(dict(value))
            for node in reversed(chain)
            for value in node.additions
        )

    @classmethod
    def restore(cls, values: Any) -> "_RelationLedger":
        if not isinstance(values, list) or any(
            not isinstance(value, Mapping) for value in values
        ):
            raise ServiceError("runtime checkpoint Relation ledger is invalid")
        return cls().extend(values)


@dataclass(frozen=True)
class _RunBindings:
    parent: "_RunBindings | None" = None
    additions: tuple[tuple[str, Mapping[str, Any]], ...] = ()

    def resolve(self, run_id: str) -> dict[str, Any] | None:
        for current_id, value in reversed(self.additions):
            if current_id == run_id:
                return _thaw_frozen(value)
        return None if self.parent is None else self.parent.resolve(run_id)

    def extend(self, run: Mapping[str, Any]) -> "_RunBindings":
        run_id = run.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            raise ServiceError("Run binding lacks a canonical identity")
        if self.resolve(run_id) is not None:
            raise ServiceError("Run Event identity is duplicated")
        return _RunBindings(
            self,
            ((run_id, MappingProxyType(deepcopy(dict(run)))),),
        )

    def materialize(self) -> tuple[dict[str, Any], ...]:
        chain: list[_RunBindings] = []
        cursor: _RunBindings | None = self
        while cursor is not None:
            chain.append(cursor)
            cursor = cursor.parent
        return tuple(
            deepcopy(dict(value))
            for node in reversed(chain)
            for _run_id, value in node.additions
        )

    @classmethod
    def restore(cls, values: Any) -> "_RunBindings":
        if not isinstance(values, list) or any(
            not isinstance(value, Mapping) for value in values
        ):
            raise ServiceError("runtime checkpoint Run bindings are invalid")
        restored = cls()
        for value in values:
            restored = restored.extend(value)
        return restored


@dataclass(frozen=True)
class _ArtifactBindings:
    parent: "_ArtifactBindings | None" = None
    additions: tuple[tuple[str, Mapping[str, Any]], ...] = ()

    def extend(self, artifact: Mapping[str, Any]) -> "_ArtifactBindings":
        artifact_id = artifact.get("artifact_id")
        if not isinstance(artifact_id, str) or not artifact_id:
            raise ServiceError("Artifact binding lacks a canonical identity")
        if any(
            current_id == artifact_id
            for current_id, _value in self.additions
        ) or (self.parent is not None and self.parent.resolve(artifact_id) is not None):
            raise ServiceError("Artifact Event identity is duplicated")
        return _ArtifactBindings(
            self,
            ((artifact_id, MappingProxyType(deepcopy(dict(artifact)))),),
        )

    def resolve(self, artifact_id: str) -> dict[str, Any] | None:
        for current_id, value in reversed(self.additions):
            if current_id == artifact_id:
                return _thaw_frozen(value)
        return None if self.parent is None else self.parent.resolve(artifact_id)

    def materialize(self) -> tuple[dict[str, Any], ...]:
        chain: list[_ArtifactBindings] = []
        cursor: _ArtifactBindings | None = self
        while cursor is not None:
            chain.append(cursor)
            cursor = cursor.parent
        return tuple(
            deepcopy(dict(value))
            for node in reversed(chain)
            for _artifact_id, value in node.additions
        )

    @classmethod
    def restore(cls, values: Any) -> "_ArtifactBindings":
        if not isinstance(values, list) or any(
            not isinstance(value, Mapping) for value in values
        ):
            raise ServiceError("runtime checkpoint Artifact bindings are invalid")
        restored = cls()
        for value in values:
            restored = restored.extend(value)
        return restored


@dataclass(frozen=True)
class _RuntimeSnapshot:
    activation_digest: str
    implementation_closure_digest: str
    authoritative_byte_digest: str
    head_sequence: int
    head_digest: str | None
    state_binding_digest: str | None
    authority: AuthorityEngine
    domain: DomainState
    decisions: _DecisionBindings
    relations: _RelationLedger
    runs: _RunBindings
    artifacts: _ArtifactBindings


@dataclass
class _PreparedRuntime:
    command_id: str
    head_sequence: int
    head_digest: str | None
    authoritative_byte_digest: str
    authority: AuthorityEngine
    domain: DomainState
    decisions: _DecisionBindings
    relations: _RelationLedger
    runs: _RunBindings
    artifacts: _ArtifactBindings
    state_binding_delta: tuple[Mapping[str, Any], ...]
    runtime_overlay_metrics: dict[str, Any]


@dataclass(frozen=True)
class InventoryResult:
    candidate: dict[str, Any]
    entries: Any
    product_tree_passes: int = 1
    observed_at: str | None = None
    provider_invocations: tuple[dict[str, Any], ...] = ()
    stream_path: Path | None = None
    stream_digest: str | None = None
    stream_bytes: int | None = None
    manifest_digest: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_type": "InventoryResult",
            "candidate": self.candidate,
            "entry_count": len(self.entries),
            "product_tree_passes": self.product_tree_passes,
            "observed_at": self.observed_at,
            "creditable": bool(self.candidate.get("creditable", False)),
            "consistency_mode": self.candidate.get("consistency_mode"),
            "provider_invocations": [dict(value) for value in self.provider_invocations],
            "stream_digest": self.stream_digest,
            "stream_bytes": self.stream_bytes,
            "manifest_digest": self.manifest_digest,
        }


@dataclass(frozen=True)
class _InventoryStreamRows:
    """Lazy compatibility view over a verified immutable inventory stream."""

    path: Path
    stream_digest: str
    inventory_digest: str
    entry_count: int
    stream_bytes: int
    observed_at: str

    def __len__(self) -> int:
        return self.entry_count

    def __iter__(self) -> Iterator[dict[str, Any]]:
        for row in _iter_verified_inventory_stream(
            self.path,
            expected_stream_digest=self.stream_digest,
            expected_inventory_digest=self.inventory_digest,
            expected_entry_count=self.entry_count,
            expected_stream_bytes=self.stream_bytes,
        ):
            yield _projection_entry(row, self.observed_at)

    def __getitem__(self, index: int) -> dict[str, Any]:
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise IndexError(index)
        for offset, row in enumerate(self):
            if offset == index:
                return row
        raise IndexError(index)


def _field(value: object, *names: str) -> Any:
    for name in names:
        if isinstance(value, Mapping) and name in value:
            return value[name]
        if hasattr(value, name):
            return getattr(value, name)
    raise ServiceError(f"activation context lacks required field: {'/'.join(names)}")


def _activation(context: ActivationContext) -> dict[str, Any]:
    value = _field(context, "activation")
    if not isinstance(value, dict):
        raise ServiceError("activation context returned a non-object Activation")
    return value


def _bundle(context: ActivationContext) -> ContractBundle:
    value = _field(context, "bundle", "contracts", "contract_bundle")
    return value


def _authority_init(context: ActivationContext) -> dict[str, Any]:
    plans = _field(context, "plans", "init_records")
    if isinstance(plans, Mapping):
        for key in ("authority", "authority.json"):
            value = plans.get(key)
            if isinstance(value, dict):
                return value
    value = _field(context, "authority", "authority_init")
    if not isinstance(value, dict):
        raise ServiceError("activation context returned a non-object AuthorityInit")
    return value


def _preset(context: ActivationContext) -> dict[str, Any]:
    value = _bundle(context).preset
    if not isinstance(value, Mapping):
        raise ServiceError("activation context returned a non-object Preset")
    return dict(value)


def _project_init(context: ActivationContext) -> dict[str, Any]:
    plans = _field(context, "plans", "init_records")
    if isinstance(plans, Mapping):
        for key in ("project", "project.json"):
            value = plans.get(key)
            if isinstance(value, dict):
                return value
    value = _field(context, "project", "project_init")
    if not isinstance(value, dict):
        raise ServiceError("activation context returned a non-object ProjectInit")
    return value


def _technologies_init(context: ActivationContext) -> dict[str, Any]:
    plans = _field(context, "plans", "init_records")
    if isinstance(plans, Mapping):
        value = plans.get("technologies.json")
        if isinstance(value, dict):
            return value
    raise ServiceError("activation context returned a non-object TechnologiesInit")


def _state_root(project_root: Path) -> Path:
    return project_root / ".promin" / "state"


def _projection_path(project_root: Path) -> Path:
    return _state_root(project_root) / "projection" / "promin.sqlite3"


def _events_root(project_root: Path) -> Path:
    return _state_root(project_root) / "events"


def _evidence_root(project_root: Path) -> Path:
    return _state_root(project_root) / "evidence"


def _token_key(context: ActivationContext) -> bytes:
    secret = _field(context, "continuation_secret")
    if not isinstance(secret, bytes) or len(secret) != 32:
        raise ServiceError("Activation continuation secret is unavailable")
    return secret


def _implementation_closure_digest(context: ActivationContext) -> str:
    value = _field(context, "implementation_closure_digest")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ServiceError("Activation implementation closure is unavailable")
    return value


def _lease_parallelism_policy(context: ActivationContext) -> dict[str, Any]:
    """Compile the installed preset ceiling without creating runtime authority."""

    bundle = _bundle(context)
    activation = _activation(context)
    preset = _preset(context)
    authority_model = bundle.core.get("authority-model.json")
    policy_set = bundle.core.get("policy-set.json")
    if not isinstance(authority_model, Mapping):
        raise ServiceError("Core authority model is unavailable")
    if not isinstance(policy_set, Mapping):
        raise ServiceError("Core policy set is unavailable")
    try:
        installed_preset = load_json_strict(
            bundle.preset_path,
            root=bundle.preset_path.parent,
        )
        installed_authority_model = load_json_strict(
            bundle.core_dir / "authority-model.json",
            root=bundle.core_dir,
        )
        installed_policy_set = load_json_strict(
            bundle.core_dir / "policy-set.json",
            root=bundle.core_dir,
        )
    except Exception as exc:
        raise ServiceError("runtime parallelism source files are unavailable") from exc
    if (
        installed_preset != preset
        or installed_authority_model != authority_model
        or installed_policy_set != policy_set
    ):
        raise ServiceError("runtime parallelism inputs are stale")
    model_tier_rule = authority_model.get("model_tier_rule")
    if not isinstance(model_tier_rule, str) or not model_tier_rule.strip():
        raise ServiceError("Core model tier rule is degraded")
    state_machines = policy_set.get("state_machines")
    if not isinstance(state_machines, Mapping):
        raise ServiceError("Core lifecycle policy is degraded")
    task_transitions = state_machines.get("task")
    lease_transitions = state_machines.get("lease")
    capacity_release = state_machines.get("capacity_release")
    if (
        not isinstance(task_transitions, Mapping)
        or not isinstance(lease_transitions, Mapping)
        or not isinstance(capacity_release, Mapping)
    ):
        raise ServiceError("Core lifecycle policy is degraded")
    for transition_map in (task_transitions, lease_transitions):
        states = set(transition_map)
        if (
            not states
            or any(not isinstance(state, str) or not state for state in states)
            or any(
                not isinstance(targets, list)
                or any(not isinstance(target, str) for target in targets)
                or len(targets) != len(set(targets))
                or any(target not in states for target in targets)
                for targets in transition_map.values()
            )
        ):
            raise ServiceError("Core lifecycle transition graph is degraded")
    closed_release = capacity_release.get("closed_release")
    terminal_reconciliation = capacity_release.get("terminal_reconciliation")
    if (
        set(capacity_release)
        != {
            "closed_release",
            "terminal_reconciliation",
            "unreconciled_slot_reusable",
        }
        or not isinstance(closed_release, Mapping)
        or not isinstance(terminal_reconciliation, Mapping)
        or capacity_release.get("unreconciled_slot_reusable") is not False
        or set(closed_release) != {"state", "requires_field", "slot_reusable"}
        or closed_release.get("state") != "CLOSED"
        or closed_release.get("requires_field") != "close_ack"
        or closed_release.get("slot_reusable") is not True
        or set(terminal_reconciliation)
        != {
            "states",
            "field",
            "required_fields",
            "manager_capability",
            "generation_binding",
            "fencing_token_binding",
            "slot_reusable_after_record",
        }
        or not isinstance(terminal_reconciliation.get("states"), list)
        or any(
            not isinstance(state, str)
            for state in terminal_reconciliation.get("states", ())
        )
        or set(terminal_reconciliation["states"]) != {"EXPIRED", "REVOKED"}
        or len(terminal_reconciliation["states"]) != 2
        or terminal_reconciliation.get("field") != "capacity_reconciliation"
        or not isinstance(terminal_reconciliation.get("required_fields"), list)
        or any(
            not isinstance(field, str)
            for field in terminal_reconciliation.get("required_fields", ())
        )
        or set(terminal_reconciliation["required_fields"])
        != {
            "reconciled_by",
            "grant_id",
            "grant_claim_digest",
            "reconciled_at",
            "generation",
            "fencing_token",
        }
        or len(terminal_reconciliation["required_fields"]) != 6
        or terminal_reconciliation.get("manager_capability") != "lease.manage"
        or terminal_reconciliation.get("generation_binding")
        != "exact-lease-generation"
        or terminal_reconciliation.get("fencing_token_binding")
        != "exact-lease-fencing-token"
        or terminal_reconciliation.get("slot_reusable_after_record") is not True
    ):
        raise ServiceError("Core capacity release policy is degraded")
    if (
        activation.get("activation_digest") != _field(context, "activation_digest")
        or activation.get("core_bundle_digest") != bundle.bundle_digest
        or activation.get("preset_digest") != bundle.preset_digest
        or activation.get("implementation_closure_digest")
        != _implementation_closure_digest(context)
    ):
        raise ServiceError("runtime parallelism inputs are stale")
    profile_name = activation.get("operating_profile")
    project = _project_init(context)
    if (
        not isinstance(profile_name, str)
        or not profile_name
        or project.get("operating_profile") != profile_name
        or project.get("preset_id") != preset.get("preset_id")
    ):
        raise ServiceError("Activation operating profile is stale")
    profiles = preset.get("profiles")
    if not isinstance(profiles, Mapping):
        raise ServiceError("Activation preset profiles are degraded")
    profile = profiles.get(profile_name)
    if not isinstance(profile, Mapping):
        raise ServiceError("Activation selects an unknown preset profile")
    try:
        validate_definition(
            bundle.schema,
            "Profile",
            profile,
            validator=bundle.definition_validator("Profile"),
        )
    except Exception as exc:
        raise ServiceError("Activation preset profile is degraded") from exc
    model_tier = profile.get("model_tier")
    ceiling = profile.get("max_parallel_tasks")
    if (
        not isinstance(model_tier, str)
        or not model_tier
        or not isinstance(ceiling, int)
        or isinstance(ceiling, bool)
        or ceiling < 1
    ):
        raise ServiceError("Activation preset parallelism is degraded")
    return {
        "activation_digest": activation["activation_digest"],
        "implementation_closure_digest": _implementation_closure_digest(context),
        "core_bundle_digest": bundle.bundle_digest,
        "preset_digest": bundle.preset_digest,
        "operating_profile": profile_name,
        "profile_digest": digest_value(dict(profile)),
        "model_tier": model_tier,
        "max_parallel_tasks": ceiling,
        "model_tier_rule_digest": digest_value(
            {"model_tier_rule": model_tier_rule}
        ),
        "policy_set_digest": digest_value(dict(policy_set)),
        "state_machine_rule_digest": digest_value(
            {
                "task": task_transitions,
                "lease": lease_transitions,
            }
        ),
        "task_transitions": {
            str(state): list(targets)
            for state, targets in task_transitions.items()
        },
        "lease_transitions": {
            str(state): list(targets)
            for state, targets in lease_transitions.items()
        },
        "capacity_release_rule_digest": digest_value(
            {"capacity_release": capacity_release}
        ),
        "capacity_release": parse_json_strict(canonical_bytes(capacity_release)),
        "authority_effect": False,
    }


def _authority_runtime_policy(context: ActivationContext) -> dict[str, Any]:
    """Compile the exact live-only authority policy from the installed Core owner."""

    bundle = _bundle(context)
    authority = bundle.core.get("authority-model.json")
    if not isinstance(authority, Mapping):
        raise ServiceError("installed AuthorityModel is unavailable")
    identity = {
        "record_type": "AuthorityRuntimePolicy",
        "authority_model_digest": digest_value(authority),
        "capability_ids": [item["id"] for item in authority["capabilities"]],
        "separation_of_duties": deepcopy(authority["separation_of_duties"]),
        "separation_of_duties_capability_ids": [
            *[item["id"] for item in authority["capabilities"]],
            *authority["separation_of_duties_contract"][
                "external_capability_ids"
            ],
        ],
        "separation_of_duties_contract": deepcopy(
            authority["separation_of_duties_contract"]
        ),
        "delegation_depth_max": authority["delegation_depth_max"],
        "scope_contract": deepcopy(authority["scope_contract"]),
        "grant_contract": deepcopy(authority["grant_contract"]),
        "canonical_timestamp_contract": deepcopy(
            authority["canonical_timestamp_contract"]
        ),
    }
    policy = {**identity, "policy_digest": digest_value(identity)}
    validate_ingress(
        bundle,
        policy,
        operation="rebuild",
        definition="AuthorityRuntimePolicy",
        context={**_validation_context(context), "authority_runtime_policy": policy},
    )
    return policy


def _event_store_policy(context: ActivationContext) -> EventStorePolicy:
    """Compile and validate the one journal policy owned by installed Core."""

    bundle = _bundle(context)
    authority = bundle.core.get("authority-model.json")
    semantic = bundle.core.get("semantic-model.json")
    if not isinstance(authority, Mapping) or not isinstance(semantic, Mapping):
        raise ServiceError("installed journal policy owners are unavailable")
    event = authority["event_contract"]
    mutation = authority["command_mutation_claim_rule"]
    scope = authority["scope_contract"]
    leaf_types = [
        "Activation",
        *[item["kind"] for item in semantic["persistent_entities"]],
        "Relation",
    ]
    identity = {
        "record_type": "EventStorePolicy",
        "authority_model_digest": digest_value(authority),
        "max_command_bytes": event["command_bytes_max"],
        "max_envelope_bytes": event["envelope_bytes_max"],
        "max_state_binding_bytes": event["state_binding_bytes_max"],
        "max_state_binding_updates_per_batch": event[
            "state_binding_updates_per_batch_max"
        ],
        "max_events_per_batch": event["events_per_batch_max"],
        "max_requested_scope_items": scope["requested_scope_items_max"],
        "derived_tail_batch_threshold": event["derived_tail_batch_threshold"],
        "derived_tail_byte_threshold": event["derived_tail_byte_threshold"],
        "runtime_overlay_compaction_depth": event[
            "runtime_overlay_compaction_depth"
        ],
        "command_required_fields": deepcopy(event["command_required_fields"]),
        "command_conditional_fields": deepcopy(
            event["command_conditional_fields"]
        ),
        "command_mutation_fields": deepcopy(mutation["required_command_fields"]),
        "lease_bound_command_kinds": deepcopy(mutation["lease_bound_command_kinds"]),
        "lease_bound_task_transition_states": deepcopy(
            mutation["lease_bound_task_transition_states"]
        ),
        "command_to_primary_event": [
            [command_kind, event_kind]
            for command_kind, event_kind in event["command_to_primary_event"].items()
        ],
        "allowed_state_binding_leaf_types": leaf_types,
        "state_binding_identity_rules": deepcopy(event["state_binding_identity_rules"]),
        "state_binding_algorithm_contract": deepcopy(
            event["state_binding_algorithm_contract"]
        ),
        "state_binding_value_rules": deepcopy(event["state_binding_value_rules"]),
        "canonical_timestamp_contract": deepcopy(
            authority["canonical_timestamp_contract"]
        ),
        "genesis_previous_authority_commitment": event[
            "genesis_previous_authority_commitment"
        ],
        "genesis_event_semantic_digest": event["genesis_event_semantic_digest"],
    }
    policy_record = {**identity, "policy_digest": digest_value(identity)}
    validate_ingress(
        bundle,
        policy_record,
        operation="rebuild",
        definition="EventStorePolicy",
        context={**_validation_context(context), "event_store_policy": policy_record},
    )
    return EventStorePolicy.from_compiled(policy_record)


def _projection_limits(context: ActivationContext) -> ProjectionLimits:
    """Compile the disposable query runtime from the installed owners."""

    bundle = _bundle(context)
    authority = bundle.core["authority-model.json"]
    conformance = bundle.core["conformance.json"]
    policies = bundle.core["policy-set.json"]
    continuation = authority["continuation_access_rule"]
    workcard_scale = conformance["scale_contracts"]["workcard"]
    result_owner = policies["derived_result_contracts"]["RetrievalPage"]
    profile = _preset(context)["profiles"][_activation(context)["operating_profile"]]
    compiled_identity: dict[str, Any] = {
        "record_type": "ProjectionLimits",
        "token_version": continuation["token_version"],
        "ranking_algorithm_id": continuation["ranking_algorithm_id"],
        "traversal_algorithm_id": continuation["traversal_algorithm_id"],
        "dependency_depth_hard_max": conformance["dependency_depth_hard_max"],
        "continuation_ttl_seconds_max": continuation["ttl_seconds_max"],
        "selected_profile_id": _activation(context)["operating_profile"],
        "selected_profile_digest": digest_value(profile),
        "persistent_entity_types": [
            item["kind"]
            for item in bundle.core["semantic-model.json"]["persistent_entities"]
        ],
        "default_budget": _profile_budget(
            _preset(context), _activation(context)
        ),
        "hard_budget": deepcopy(conformance["workcard_hard_ceiling"]),
        "default_depth": profile["default_dependency_depth"],
        "depth_min": continuation["depth_min"],
        "depth_max": conformance["dependency_depth_hard_max"],
        "default_ttl_seconds": continuation["default_ttl_seconds"],
        "ttl_min_seconds": continuation["ttl_min_seconds"],
        "ttl_max_seconds": continuation["ttl_seconds_max"],
        "max_token_bytes": workcard_scale["continuation_token_bytes_max"],
        "max_continuation_state_bytes": workcard_scale[
            "continuation_state_bytes_max"
        ],
        "max_query_bytes": result_owner["query_bytes_max"],
        "min_result_bytes": continuation["min_result_bytes"],
        "max_resume_binding_fields": continuation[
            "max_resume_binding_fields"
        ],
        "max_resume_binding_key_chars": continuation[
            "max_resume_binding_key_chars"
        ],
        "max_resume_binding_value_bytes": continuation[
            "max_resume_binding_value_bytes"
        ],
        "max_resume_binding_bytes": continuation[
            "max_resume_binding_bytes"
        ],
        "required_resume_binding_fields": deepcopy(
            continuation["required_resume_binding_fields"]
        ),
    }
    compiled = {**compiled_identity, "policy_digest": digest_value(compiled_identity)}
    validate_ingress(
        bundle,
        compiled,
        operation="rebuild",
        definition="ProjectionLimits",
        context={**_validation_context(context), "projection_limits": compiled},
    )
    runtime = dict(compiled)
    runtime["persistent_entity_types"] = tuple(
        runtime["persistent_entity_types"]
    )
    runtime["required_resume_binding_fields"] = tuple(
        runtime["required_resume_binding_fields"]
    )
    return ProjectionLimits(
        **runtime,
        event_store_policy=_event_store_policy(context),
    )


def _event_store_validators(context: ActivationContext) -> dict[str, Any]:
    """Bind every journal surface to the installed compiled schema."""

    bundle = _bundle(context)
    validation_context = _validation_context(context)

    def compiled_record(
        definition: str,
        value: Mapping[str, Any],
        *,
        evaluation_time: str,
        operation: str,
    ) -> bool:
        parse_utc_second(evaluation_time)
        validate_definition(bundle.schema, definition, value)
        record_type = value.get("record_type")
        ingress_operation = {
            "commit": "command",
            "read": "replay",
        }.get(operation, operation)
        if (
            isinstance(record_type, str)
            and bundle.record_definitions.get(record_type) == definition
            and ingress_operation
            in {"command", "import", "replay", "rebuild", "export", "transient"}
        ):
            validate_ingress(
                bundle,
                dict(value),
                operation=ingress_operation,
                definition=definition,
                context=validation_context,
            )
        return True

    def command(value: Mapping[str, Any], *, evaluation_time: str) -> bool:
        if value.get("issued_at") != evaluation_time:
            raise ServiceError("journal command evaluation time is detached")
        validate_definition(bundle.schema, "CommandRequest", value)
        return True

    def authorization(value: Mapping[str, Any], *, evaluation_time: str) -> bool:
        if value.get("issued_at") != evaluation_time:
            raise ServiceError("journal authorization evaluation time is detached")
        authorization_value = value.get("authorization")
        if not isinstance(authorization_value, Mapping):
            raise ServiceError("journal command authorization is missing")
        validate_definition(
            bundle.schema,
            "RootAuthorization"
            if authorization_value.get("kind") == "root"
            else "GrantAuthorization",
            authorization_value,
        )
        return True

    def event(
        value: Mapping[str, Any],
        *,
        evaluation_time: str,
        command: Mapping[str, Any],
    ) -> bool:
        parse_utc_second(evaluation_time)
        validate_definition(bundle.schema, "Event", value)
        if value.get("activation_digest") != command.get("activation_digest"):
            raise ServiceError("journal Event Activation differs from its command")
        return True

    return {
        "compiled_record_validator": compiled_record,
        "command_validator": command,
        "authorization_validator": authorization,
        "event_validator": event,
    }


def _freeze_runtime_components(
    authority: AuthorityEngine,
    domain: DomainState,
    policy: EventStorePolicy,
) -> tuple[AuthorityEngine, DomainState, dict[str, Any]]:
    depth = getattr(policy, "runtime_overlay_compaction_depth", None)
    if not isinstance(depth, int) or isinstance(depth, bool) or depth < 1:
        raise ServiceError("EventStorePolicy lacks runtime overlay compaction depth")
    started = time.perf_counter()
    authority_result = authority.freeze(runtime_overlay_compaction_depth=depth)
    domain_result = domain.freeze(runtime_overlay_compaction_depth=depth)
    duration_ms = round((time.perf_counter() - started) * 1000, 6)
    for result, label in (
        (authority_result, "authority"),
        (domain_result, "domain"),
    ):
        if not isinstance(getattr(result, "changed_leaf_count", None), int):
            raise ServiceError(f"{label} freeze did not report changed leaves")
    return (
        authority_result.snapshot,
        domain_result.snapshot,
        {
            "runtime_overlay_compaction_depth": depth,
            "duration_ms": duration_ms,
            "changed_records": (
                authority_result.changed_leaf_count
                + domain_result.changed_leaf_count
            ),
            "compacted": bool(
                authority_result.compacted or domain_result.compacted
            ),
            "compacted_record_count": (
                authority_result.compacted_record_count
                + domain_result.compacted_record_count
            ),
            "compacted_payload_bytes": (
                authority_result.compacted_payload_bytes
                + domain_result.compacted_payload_bytes
            ),
        },
    )


def _current_state_binding_record(
    leaf_type: str,
    command: Mapping[str, Any],
    authority: AuthorityEngine,
    domain: DomainState,
) -> dict[str, Any]:
    payload = command["payload"]
    if leaf_type == "Task":
        value = domain.tasks.get(payload["task_id"])
    elif leaf_type == "Lease":
        value = domain.leases.get(payload["lease_id"])
    elif leaf_type == "Grant":
        grant_id = payload["grant_id"]
        grant = authority.grants.get(grant_id)
        if grant is None:
            raise ServiceError("Grant authority leaf is unresolved after mutation")
        value = {
            "record_type": "GrantAuthorityState",
            "grant": grant,
            "revocation": authority.revocations.get(grant_id),
        }
    else:
        value = payload
    if not isinstance(value, Mapping):
        raise ServiceError(f"{leaf_type} authority leaf is unresolved after mutation")
    return _thaw_frozen(value)


def _state_binding_delta(
    policy: EventStorePolicy,
    command: Mapping[str, Any],
    relations: Iterable[Mapping[str, Any]],
    authority: AuthorityEngine,
    domain: DomainState,
) -> tuple[Mapping[str, Any], ...]:
    command_kind = command["command_kind"]
    primary_event_kind = policy.primary_events[command_kind]
    primary_leaf_type = policy.state_binding_event_leaf_types[primary_event_kind]
    domain_commands = {
        "task.record",
        "task.transition",
        "candidate.record",
        "lease.record",
        "finding.record",
        "gate.record",
        "decision.record",
    }
    if command_kind in domain_commands:
        current_records = domain.changed_persistent_records()
        if not current_records:
            payload = command["payload"]
            identities: list[tuple[str, Any]]
            if command_kind in {"task.record", "task.transition"}:
                identities = [("Task", payload["task_id"])]
            elif command_kind == "candidate.record":
                identities = [("Candidate", payload["candidate_id"])]
            elif command_kind == "lease.record":
                identities = [("Lease", payload["lease_id"])]
            elif command_kind == "finding.record":
                identities = [("Finding", payload["finding_id"])]
            elif command_kind == "gate.record":
                identities = [("GateResult", (payload["gate_id"], payload["run_id"]))]
            elif command_kind == "decision.record":
                identities = [("Decision", payload["decision_id"])]
                if payload["decision_kind"] in {"resolve", "waive"}:
                    identities.append(("Finding", payload["target_id"]))
            else:
                raise ServiceError("domain state-binding route is unresolved")
            mappings = {
                "Task": domain.tasks,
                "Candidate": domain.candidates,
                "Lease": domain.leases,
                "Finding": domain.findings,
                "GateResult": domain.gate_results,
                "Decision": domain.decisions,
            }
            current_records = []
            for leaf_type, identity in identities:
                value = mappings[leaf_type].get(identity)
                if not isinstance(value, Mapping):
                    raise ServiceError(
                        f"{leaf_type} replay state is unresolved after mutation"
                    )
                current_records.append(
                    {"leaf_type": leaf_type, "value": _thaw_frozen(value)}
                )
    else:
        current_records = [
            {
                "leaf_type": primary_leaf_type,
                "value": _current_state_binding_record(
                    primary_leaf_type,
                    command,
                    authority,
                    domain,
                ),
            }
        ]
    updates: list[dict[str, Any]] = []
    for record in current_records:
        leaf_type = record["leaf_type"]
        value = _thaw_frozen(record["value"])
        event_kind = (
            primary_event_kind
            if leaf_type == primary_leaf_type
            else policy.primary_events["finding.record"]
        )
        updates.append(
            {
                "leaf_type": leaf_type,
                "leaf_id": state_binding_leaf_id(policy, leaf_type, value),
                "operation": "set",
                "value_digest": state_binding_value_digest(
                    policy,
                    leaf_type,
                    value,
                    event_kind=event_kind,
                ),
            }
        )
    for relation in relations:
        value = _thaw_frozen(relation)
        updates.append(
            {
                "leaf_type": "Relation",
                "leaf_id": state_binding_leaf_id(policy, "Relation", value),
                "operation": "set",
                "value_digest": state_binding_value_digest(
                    policy,
                    "Relation",
                    value,
                    event_kind="relation.recorded",
                ),
            }
        )
    updates.sort(key=lambda value: (value["leaf_type"], value["leaf_id"]))
    return tuple(dict(value) for value in updates)


def _runtime_state_binding_leaves(
    policy: EventStorePolicy,
    snapshot: _RuntimeSnapshot,
) -> tuple[dict[str, Any], ...]:
    leaves = list(snapshot.domain.persistent_records())
    grants = snapshot.authority.grants
    revocations = snapshot.authority.revocations
    leaves.extend(
        {
            "leaf_type": "Grant",
            "value": {
                "record_type": "GrantAuthorityState",
                "grant": grant,
                "revocation": revocations.get(grant_id),
            },
        }
        for grant_id, grant in grants.items()
    )
    leaves.extend(
        {"leaf_type": "Relation", "value": value}
        for value in snapshot.relations.materialize()
    )
    leaves.extend(
        {"leaf_type": "Run", "value": value}
        for value in snapshot.runs.materialize()
    )
    leaves.extend(
        {"leaf_type": "Artifact", "value": value}
        for value in snapshot.artifacts.materialize()
    )

    def identity(item: Mapping[str, Any]) -> tuple[str, str]:
        leaf_type = str(item["leaf_type"])
        value = item["value"]
        owner = value["grant"] if leaf_type == "Grant" else value
        return leaf_type, state_binding_leaf_id(policy, leaf_type, owner)

    return tuple(
        {"leaf_type": item["leaf_type"], "value": deepcopy(dict(item["value"]))}
        for item in sorted(leaves, key=identity)
    )



def _fast_implementation_stat_fingerprint(
    context: ActivationContext,
    project_root: Path,
) -> str | None:
    """Return a bounded guard for a fully byte-verified mutation context.

    The first authoritative mutation in each ``ProminService`` instance still
    performs the complete cryptographic verification.  Reuse is allowed only
    while the exact Activation-bound files and directories retain the same
    filesystem identities.  ``activation_read_bindings`` walks materialized
    content-addressed provider receipts, so additions, removals, replacements
    and in-place edits invalidate this guard without rehashing provider bytes
    for every small semantic command.

    This fingerprint is a cache guard only.  It is never an authority proof and
    a mismatch always falls back to the full fail-closed verification path.
    """

    del project_root  # The verified context owns the exact project root.
    try:
        bindings = activation_read_bindings(context)
        return activation_read_fingerprint(context, bindings)
    except Exception:
        return None



class ProminService:
    """The single validated ingress for the installed Promin runtime."""

    def __init__(self, project_root: Path | str):
        self.root = Path(project_root).resolve()
        self._read_context: ActivationContext | None = None
        self._read_context_bindings: tuple[tuple[str, Path, str], ...] | None = None
        self._read_context_fingerprint: str | None = None
        self._context_lock = threading.RLock()
        self._query_runtime_key: tuple[str, str, int, str | None, str | None] | None = None
        self._query_runtime_value: _RuntimeSnapshot | None = None
        self._prepared_runtime: _PreparedRuntime | None = None
        self._runtime_checkpoint_cursor: _RuntimeCheckpointCursor | None = None
        self._mutation_store_key: tuple[str, str] | None = None
        self._mutation_store: EventStore | None = None
        self._read_store_key: tuple[str, str] | None = None
        self._read_store: EventStore | None = None
        self._query_runtime_lock = threading.RLock()
        self._ranked_candidate_cache = RankedCandidateCache(max_entries=1_024)
        self._verified_mutation_cache: ActivationContext | None = None
        self._verified_mutation_fingerprint: str | None = None

    def _clear_query_runtime(self) -> None:
        with self._query_runtime_lock:
            self._query_runtime_key = None
            self._query_runtime_value = None
            self._prepared_runtime = None
            self._runtime_checkpoint_cursor = None
            self._mutation_store_key = None
            self._mutation_store = None
            self._read_store_key = None
            self._read_store = None
            self._verified_mutation_cache = None
            self._verified_mutation_fingerprint = None
            self._ranked_candidate_cache.clear()

    def _bind_query_runtime(
        self,
        context: ActivationContext,
        store: EventStore,
        value: _RuntimeSnapshot,
    ) -> None:
        head = store.head()
        key = (
            _activation(context)["activation_digest"],
            _implementation_closure_digest(context),
            head["sequence"],
            head["batch_id"],
            head["batch_digest"],
        )
        with self._query_runtime_lock:
            self._query_runtime_key = key
            self._query_runtime_value = value
            self._ranked_candidate_cache.clear()

    def _bind_runtime_checkpoint_cursor(
        self,
        context: ActivationContext,
        head: Mapping[str, Any],
        *,
        checkpoint_count: int,
        tail_batches: int,
        tail_bytes: int,
    ) -> _RuntimeCheckpointCursor:
        cursor = _RuntimeCheckpointCursor(
            activation_digest=_activation(context)["activation_digest"],
            implementation_closure_digest=_implementation_closure_digest(context),
            head_sequence=int(head["sequence"]),
            head_batch_id=head["batch_id"],
            head_digest=head["batch_digest"],
            checkpoint_count=checkpoint_count,
            tail_batches=tail_batches,
            tail_bytes=tail_bytes,
        )
        with self._query_runtime_lock:
            self._runtime_checkpoint_cursor = cursor
        return cursor

    def _query_runtime_state(
        self,
        context: ActivationContext,
        store: EventStore,
    ) -> _RuntimeSnapshot:
        head = store.head()
        key = (
            _activation(context)["activation_digest"],
            _implementation_closure_digest(context),
            head["sequence"],
            head["batch_id"],
            head["batch_digest"],
        )
        if self._query_runtime_key == key and self._query_runtime_value is not None:
            return self._query_runtime_value
        value = self._runtime_state(context, store)
        if store.head() != head:
            raise ServiceError("event HEAD changed while resolving query authorization state")
        self._query_runtime_key = key
        self._query_runtime_value = value
        return value

    def _context(self, *, force_full: bool = False) -> ActivationContext:
        """Return a verified Activation, reusing it only while bound files are unchanged."""

        with self._context_lock:
            if force_full:
                self._read_context = None
                self._read_context_bindings = None
                self._read_context_fingerprint = None
                return ActivationGuard(self.root).verify()
            if self._read_context is not None:
                try:
                    current = activation_read_fingerprint(
                        self._read_context,
                        self._read_context_bindings,
                    )
                except Exception:
                    self._read_context = None
                    self._read_context_bindings = None
                    self._read_context_fingerprint = None
                else:
                    if current == self._read_context_fingerprint:
                        return self._read_context
                    self._read_context = None
                    self._read_context_bindings = None
                    self._read_context_fingerprint = None
            context = ActivationGuard(self.root).verify()
            bindings = activation_read_bindings(context)
            self._read_context_fingerprint = activation_read_fingerprint(
                context,
                bindings,
            )
            self._read_context_bindings = bindings
            self._read_context = context
            return context

    def _verified_mutation_context(
        self,
        expected: ActivationContext,
    ) -> ActivationContext:
        cached = self._verified_mutation_cache
        if cached is not None and self._verified_mutation_fingerprint is not None:
            try:
                current_fingerprint = _fast_implementation_stat_fingerprint(cached, self.root)
            except Exception:
                current_fingerprint = None
            if (
                current_fingerprint == self._verified_mutation_fingerprint
                and cached.activation_digest == _activation(expected)["activation_digest"]
                and cached.implementation_closure_digest == _implementation_closure_digest(expected)
            ):
                return cached
            self._verified_mutation_cache = None
            self._verified_mutation_fingerprint = None

        verified = verify_before_mutation(self.root)
        if (
            verified.activation_digest != _activation(expected)["activation_digest"]
            or verified.implementation_closure_digest
            != _implementation_closure_digest(expected)
            or not isinstance(verified.authoritative_byte_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", verified.authoritative_byte_digest)
        ):
            raise ServiceError("mutation verification differs from the active runtime")
        verify_provider_preflight(
            _technologies_init(verified),
            self.root,
            contract_bundle=_bundle(verified),
            provider_dispatch=verified.provider_dispatch,
            receipt_root=verified.control_root / "providers",
        )
        fingerprint = _fast_implementation_stat_fingerprint(verified, self.root)
        if fingerprint is not None:
            self._verified_mutation_cache = verified
            self._verified_mutation_fingerprint = fingerprint
        else:
            self._verified_mutation_cache = None
            self._verified_mutation_fingerprint = None
        return verified

    def _load_commit_state(
        self,
        expected: ActivationContext,
        view: CommitReadView,
        envelopes: Any,
    ) -> CommitStateSnapshot:
        verified = self._verified_mutation_context(expected)
        key = (
            view.activation_digest,
            view.implementation_closure_digest,
            view.head_sequence,
            view.head_batch_id,
            view.head_digest,
        )
        cached = self._query_runtime_value
        if (
            self._query_runtime_key == key
            and cached is not None
            and cached.state_binding_digest == view.current_state_binding_digest
            and cached.authoritative_byte_digest
            == verified.authoritative_byte_digest
        ):
            return CommitStateSnapshot(
                cached,
                view.head_sequence,
                view.head_digest,
                view.current_state_binding_digest,
            )
        snapshot = self._runtime_from_envelopes(
            verified,
            envelopes(),
            head_sequence=view.head_sequence,
            head_digest=view.head_digest,
            state_binding_digest=view.current_state_binding_digest,
        )
        self._query_runtime_key = key
        self._query_runtime_value = snapshot
        return CommitStateSnapshot(
            snapshot,
            view.head_sequence,
            view.head_digest,
            view.current_state_binding_digest,
        )

    def _prepare_commit(
        self,
        expected: ActivationContext,
        view: CommitReadView,
        frozen_command: Mapping[str, Any],
        frozen_relations: Iterable[Mapping[str, Any]],
    ) -> PreparedCommit:
        snapshot = view.state
        if not isinstance(snapshot, _RuntimeSnapshot):
            raise ServiceError("commit state loader returned an unknown runtime")
        command = _thaw_frozen(frozen_command)
        relations_input = tuple(_thaw_frozen(value) for value in frozen_relations)
        authority = snapshot.authority.fork(
            decision_resolver=snapshot.decisions.resolve
        )
        domain = snapshot.domain.fork(authority=authority)
        _validate_definition_digest_equality(command)
        if command["command_kind"] == "run.record":
            _validate_run_definition(domain, command["payload"], command["issued_at"])
        run = (
            snapshot.runs.resolve(command["payload"].get("run_id", ""))
            if command["command_kind"] == "gate.record"
            else None
        )
        if command["command_kind"] == "gate.record":
            if run is None:
                raise ServiceError("GateResult Run is unresolved at the current HEAD")
            _validate_gate_run_before_authorization(
                domain,
                command["payload"],
                run,
                command["issued_at"],
            )
        issue_authorization = self._authorize_command(
            expected,
            authority,
            command,
        )
        resolved_workcard = self._resolve_mutation_workcard(expected, command, None)
        artifact = _evidence_artifact(command)
        if artifact is not None:
            _validate_artifact_implementation(expected, artifact)
        if artifact is not None and artifact.get("artifact_kind") == "diff":
            if resolved_workcard is None:
                raise ServiceError("Candidate delta requires a mutation WorkCard")
            domain.preflight_candidate_delta(
                artifact,
                task_id=resolved_workcard["task_id"],
                workcard=resolved_workcard,
                authorization=_domain_authorization(command),
            )
        self._apply_command(
            domain,
            authority,
            command,
            grant_issue_authorization=issue_authorization,
            workcard=resolved_workcard,
            parallelism_policy=_lease_parallelism_policy(expected),
            run=run,
        )
        relations = _validated_auxiliary_relations(
            _bundle(expected),
            expected,
            command,
            relations_input,
            domain=domain,
            current_relations=snapshot.relations.materialize(),
            operation="command",
        )
        policy = _event_store_policy(expected)
        delta = _state_binding_delta(
            policy,
            command,
            relations,
            authority,
            domain,
        )
        runs = snapshot.runs
        if command["command_kind"] == "run.record":
            runs = runs.extend(command["payload"])
        artifacts = snapshot.artifacts
        if command["command_kind"] == "artifact.record":
            artifacts = artifacts.extend(command["payload"])
        self._prepared_runtime = _PreparedRuntime(
            command_id=command["command_id"],
            head_sequence=view.head_sequence,
            head_digest=view.head_digest,
            authoritative_byte_digest=snapshot.authoritative_byte_digest,
            authority=authority,
            domain=domain,
            decisions=snapshot.decisions,
            relations=snapshot.relations.extend(relations),
            runs=runs,
            artifacts=artifacts,
            state_binding_delta=delta,
            runtime_overlay_metrics={},
        )
        return PreparedCommit(
            tuple(MappingProxyType(value) for value in relations),
            delta,
        )

    @staticmethod
    def _validate_derived_runtime_state(
        name: str,
        state: Any,
        *,
        expected_binding_digest: str,
    ) -> str:
        if name != "runtime":
            raise ServiceError("unknown derived runtime checkpoint")
        if not isinstance(state, Mapping) or set(state) != {
            "authority",
            "domain",
            "decisions",
            "relations",
            "runs",
            "artifacts",
            "compaction",
        }:
            raise ServiceError("derived runtime checkpoint shape is invalid")
        domain = state.get("domain")
        if (
            not isinstance(domain, Mapping)
            or domain.get("record_type") != "DomainCheckpoint"
            or domain.get("authoritative") is not False
            or domain.get("state_binding_digest") != expected_binding_digest
        ):
            raise ServiceError("derived runtime checkpoint lacks exact journal state root")
        compaction = state.get("compaction")
        if not isinstance(compaction, Mapping) or set(compaction) != {
            "checkpoint_count",
            "tail_batches_compacted",
            "tail_bytes_compacted",
            "batch_threshold",
            "byte_threshold",
        }:
            raise ServiceError("derived runtime checkpoint compaction shape is invalid")
        return expected_binding_digest

    def _event_store(
        self,
        context: ActivationContext,
        *,
        recover_publications: bool = True,
    ) -> EventStore:
        activation_digest = _activation(context)["activation_digest"]
        implementation_digest = _implementation_closure_digest(context)
        policy = _event_store_policy(context)
        validators = _event_store_validators(context)
        if not recover_publications:
            key = (activation_digest, implementation_digest)
            with self._query_runtime_lock:
                if self._read_store_key != key or self._read_store is None:
                    self._read_store = EventStore(
                        _events_root(self.root),
                        activation_digest,
                        activation_record_digest=digest_value(_activation(context)),
                        implementation_closure_digest=implementation_digest,
                        policy=policy,
                        **validators,
                        commit_state_loader=lambda view, envelopes: self._load_commit_state(
                            context, view, envelopes
                        ),
                        commit_prepare_callback=lambda view, command, relations: self._prepare_commit(
                            context, view, command, relations
                        ),
                        derived_state_validator=self._validate_derived_runtime_state,
                    )
                    self._read_store_key = key
                    return self._read_store
                store = self._read_store
            store.refresh()
            return store
        store = EventStore(
            _events_root(self.root),
            activation_digest,
            activation_record_digest=digest_value(_activation(context)),
            implementation_closure_digest=implementation_digest,
            policy=policy,
            **validators,
            commit_state_loader=lambda view, envelopes: self._load_commit_state(
                context, view, envelopes
            ),
            commit_prepare_callback=lambda view, command, relations: self._prepare_commit(
                context, view, command, relations
            ),
            derived_state_validator=self._validate_derived_runtime_state,
        )
        if recover_publications:
            _recover_evidence_publications(self.root, context, store)
        return store

    def _mutation_event_store(
        self,
        context: ActivationContext,
        bundle: ContractBundle,
    ) -> EventStore:
        key = (
            _activation(context)["activation_digest"],
            _implementation_closure_digest(context),
        )
        with self._query_runtime_lock:
            if self._mutation_store_key != key or self._mutation_store is None:
                policy = _event_store_policy(context)
                validators = _event_store_validators(context)
                self._mutation_store = EventStore(
                    _events_root(self.root),
                    key[0],
                    activation_record_digest=digest_value(_activation(context)),
                    implementation_closure_digest=key[1],
                    policy=policy,
                    **validators,
                    commit_state_loader=lambda view, envelopes: self._load_commit_state(
                        context, view, envelopes
                    ),
                    commit_prepare_callback=lambda view, command, relations: self._prepare_commit(
                        context, view, command, relations
                    ),
                    derived_state_validator=self._validate_derived_runtime_state,
                )
                self._mutation_store_key = key
            store = self._mutation_store
        _recover_evidence_publications(self.root, context, store)
        return store

    def _projection(self, context: ActivationContext) -> Projection:
        return Projection(
            _projection_path(self.root),
            _token_key(context),
            implementation_closure_digest=_implementation_closure_digest(context),
            limits=_projection_limits(context),
            relation_domains=compile_relation_domains(
                _bundle(context).core["semantic-model.json"]
            ),
            ranked_candidate_cache=self._ranked_candidate_cache,
        )

    def initialize(self, request: InitRequest) -> dict[str, Any]:
        if Path(request.project_root).resolve() != self.root:
            raise ServiceError("InitRequest project_root differs from service root")
        result = initialize_project(request)
        self._read_context = None
        self._read_context_bindings = None
        self._read_context_fingerprint = None
        self._clear_query_runtime()
        context = result.context
        activation = _activation(context)
        _lease_parallelism_policy(context)
        return {
            "record_type": "InitResult",
            "status": "created" if result.created else "idempotent",
            "activation_digest": activation["activation_digest"],
            "core_bundle_digest": activation["core_bundle_digest"],
            "preset_digest": activation["preset_digest"],
            "implementation_closure_digest": _implementation_closure_digest(context),
            "product_tree_scans": 0,
        }

    def doctor(self, *, replay: bool = True) -> dict[str, Any]:
        context = self._context(force_full=True)
        bundle = _bundle(context)
        activation = _activation(context)
        technologies = _technologies_init(context)
        validate_ingress(
            bundle,
            activation,
            operation="replay",
            definition="Activation",
            context=_validation_context(context),
        )
        observations = verify_provider_preflight(
            technologies,
            self.root,
            contract_bundle=bundle,
            provider_dispatch=context.provider_dispatch,
            receipt_root=context.control_root / "providers",
        )
        store = self._event_store(context)
        # ``EventStore`` validates the checkpoint during construction and falls
        # back to a full replay only when recovery is actually required.  A
        # routine doctor invocation must not force another full replay: doing so
        # creates a fresh disposable index/authority generation on every health
        # check and turns a read-mostly command into unbounded disk growth.  A
        # lock-stable refresh verifies the current authoritative prefix and
        # performs recovery only when the checkpoint or journal is inconsistent.
        recovery = store.refresh()
        replay_result = None
        if replay:
            replay_result = self._replay_validated(context, store)
        projection = self._projection(context)
        projection_error: str | None = None
        try:
            projection_status = projection.status()
        except ProjectionError as exc:
            projection_status = {"status": "missing", "projection_authoritative": False}
            projection_error = type(exc).__name__.casefold()
        head = store.head()
        projection_current = (
            projection_status.get("activation_digest") == activation["activation_digest"]
            and projection_status.get("head_sequence") == head["sequence"]
            and projection_status.get("head_digest") == head["batch_digest"]
        )
        provider_status = (
            "failed"
            if any(value["outcome"] == "failed" for value in observations)
            else "degraded"
            if any(value["outcome"] == "degraded" for value in observations)
            else "healthy"
        )

        def component(
            status: str,
            reasons: Sequence[str],
            observed: Any,
        ) -> dict[str, Any]:
            return {
                "status": status,
                "reason_codes": list(reasons),
                "observed_digest": (
                    None if observed is None else digest_value(observed)
                ),
            }

        components = {
            "core": component("healthy", (), bundle.bundle_digest),
            "init": component("healthy", (), activation["activation_digest"]),
            "providers": component(
                provider_status,
                () if provider_status == "healthy" else ("provider-healthcheck",),
                list(observations),
            ),
            "recovery": component(
                "healthy" if recovery == head else "failed",
                () if recovery == head else ("recovery-head-mismatch",),
                recovery,
            ),
            "replay": component(
                "healthy" if replay_result is not None else "incomplete",
                () if replay_result is not None else ("replay-not-requested",),
                replay_result,
            ),
            "projection": component(
                "healthy"
                if projection_current
                else "failed"
                if projection_error is not None and _projection_path(self.root).exists()
                else "incomplete",
                ()
                if projection_current
                else (
                    "projection-unreadable"
                    if projection_error is not None and _projection_path(self.root).exists()
                    else "projection-missing-or-stale",
                ),
                projection_status if projection_current else None,
            ),
        }
        owner = bundle.core["policy-set.json"]["derived_result_contracts"][
            "DoctorResult"
        ]
        present = {value["status"] for value in components.values()}
        status = next(value for value in owner["rollup_precedence"] if value in present)
        result = {
            "record_type": "DoctorResult",
            "status": status,
            "claim_scope": owner["claim_scope"],
            "source_scope": owner["source_scope"],
            "report_authoritative": owner["report_authoritative"],
            "pass_credit": owner["pass_credit"],
            "product_acceptance_pass": owner["product_acceptance_pass"],
            "product_public_approval": owner["product_public_approval"],
            "activation_digest": activation["activation_digest"],
            "implementation_closure_digest": _implementation_closure_digest(context),
            "head": head,
            "recovery": recovery,
            "replay": replay_result,
            "projection": projection_status,
            "provider_adapters": list(observations),
            "metrics": {
                "core_artifacts_verified": len(bundle.core),
                "init_records_verified": len(context.plans) + 1,
                "provider_healthchecks_executed": len(technologies["bindings"]),
                "event_batches": head["sequence"],
                "projection_entities": projection_status.get("entity_count"),
                "projection_relations": projection_status.get("relation_count"),
            },
            "components": components,
            "archival_diagnostics": {
                "affects_current_status": False,
                "pass_credit": False,
                "entries": [],
            },
            "operation_metrics": None,
            "product_tree_scans": owner["product_tree_scans"],
        }
        provider_receipts: dict[str, dict[str, Any]] = {}
        provider_bindings: dict[str, dict[str, Any]] = {}
        for observation in observations:
            capability_id = observation["capability_id"]
            binding = dict(context.provider_dispatch.binding(capability_id))
            adapter = context.provider_dispatch.adapter(capability_id)
            provider_receipts[capability_id] = {
                "record_type": "ProviderHealthInvocationReceipt",
                "protocol_id": adapter.protocol_id,
                "operation": "healthcheck",
                "provider_id": adapter.provider_id,
                "argv": list(binding["healthcheck"]["argv"]),
                "cwd": str(self.root),
                "stdin": "none",
                "timeout_ms": binding["healthcheck"]["timeout_ms"],
                "expected_exit": binding["healthcheck"]["expected_exit"],
                "identity_digest": adapter.identity_digest,
                "dependency_receipt_digest": adapter.dependency_receipt_digest,
                "persistence_scope": adapter.persistence_scope,
            }
            provider_bindings[capability_id] = binding
        validate_ingress(
            bundle,
            result,
            operation="replay",
            definition="DoctorResult",
            context={
                **_validation_context(context),
                "doctor_result": result,
                "doctor_provider_receipts": provider_receipts,
                "doctor_provider_bindings": provider_bindings,
            },
        )
        return result

    def status(self) -> dict[str, Any]:
        context = self._context()
        activation = _activation(context)
        provider_observations = verify_provider_preflight(
            _technologies_init(context),
            self.root,
            contract_bundle=_bundle(context),
            provider_dispatch=context.provider_dispatch,
            receipt_root=context.control_root / "providers",
        )
        store = self._event_store(context, recover_publications=False)
        projection = self._projection(context)
        try:
            pstatus = projection.status()
        except ProjectionError:
            pstatus = {"status": "missing", "projection_authoritative": False}
        if pstatus.get("activation_digest") not in (None, activation["activation_digest"]):
            raise ServiceError("projection Activation is stale")
        if pstatus.get("head_digest") not in (None, store.head()["batch_digest"]):
            raise ServiceError("projection HEAD is stale")
        domain = self._domain_state(context, store)
        if domain.candidates:
            candidate_digest = next(reversed(list(domain.candidates.values())))["candidate_digest"]
            approval = domain.approval_status(
                candidate_digest,
                current_activation_digest=activation["activation_digest"],
                current_provider_binding_digest=_provider_binding_digest(context),
                current_implementation_closure_digest=_implementation_closure_digest(context),
                evaluated_at=_utc_second_text(),
            )
        else:
            approval = {
                "candidate_digest": None,
                "product_acceptance": False,
                "public_release_approved": False,
                "current_release_eligible": False,
                "historical_release_decision_id": None,
                "human_decision_id": None,
                "release_closure_digest": None,
                "current_closure_digest": None,
                "invalidation_reasons": ["no-historical-release-decision"],
            }
        return {
            "record_type": "StatusResult",
            "status": "ready",
            "activation_digest": activation["activation_digest"],
            "implementation_closure_digest": _implementation_closure_digest(context),
            "head": store.head(),
            "projection": pstatus,
            "provider_adapters": list(provider_observations),
            "runtime_checkpoint": {
                "journal": store.checkpoint_status(),
                "derived_issue": store.derived_state_issue("runtime"),
                "authoritative": False,
            },
            "approval": approval,
            "product_acceptance_pass": False,
            "public_release_approved": False,
        }

    def validate(self, *, replay: bool = True) -> dict[str, Any]:
        context = self._context(force_full=True)
        bundle = _bundle(context)
        activation = _activation(context)
        validate_ingress(
            bundle,
            activation,
            operation="replay",
            definition="Activation",
            context=_validation_context(context),
        )
        store = self._event_store(context)
        checked = 0
        for envelope in store.iter_envelopes(validate=True):
            command = _command_from_envelope(envelope)
            validate_ingress(
                bundle,
                command,
                operation="replay",
                definition="CommandRequest",
            )
            for relation in _relations_from_envelope(envelope):
                validate_definition(bundle.schema, "Relation", relation)
            if _mutation_claim_required(bundle, command):
                self._resolve_mutation_workcard(context, command, None)
            checked += 1
        if replay:
            self._replay_validated(context, store)
        return {
            "record_type": "ValidationResult",
            "status": "pass",
            "activation_digest": activation["activation_digest"],
            "implementation_closure_digest": _implementation_closure_digest(context),
            "head": store.head(),
            "validated_event_batches": checked,
            "product_acceptance_pass": False,
            "public_release_approved": False,
        }

    @_serialized_mutation
    def commit(
        self,
        command: dict[str, Any],
        *,
        auxiliary_relations: Iterable[Mapping[str, Any]] = (),
        workcard: Mapping[str, Any] | None = None,
        evidence_payload: bytes | None = None,
    ) -> dict[str, Any]:
        operation_started = time.perf_counter()
        context = self._context()
        bundle = _bundle(context)
        activation = _activation(context)
        if command.get("activation_digest") != activation["activation_digest"]:
            raise ServiceError("command Activation is stale")
        validate_ingress(
            bundle,
            command,
            operation="command",
            definition="CommandRequest",
            context=_validation_context(context),
        )
        store = self._mutation_event_store(context, bundle)
        resolved_workcard = self._resolve_mutation_workcard(
            context,
            command,
            workcard,
        )
        # Resolve a checkpoint-bounded runtime before EventStore takes its writer
        # lock. The commit loader may then consume this exact snapshot without
        # recursively entering derived-state APIs under that lock.
        self._query_runtime_state(context, store)
        evidence_store = EvidenceStore(_evidence_root(self.root))
        artifact = _evidence_artifact(command)
        if artifact is not None:
            _validate_artifact_implementation(context, artifact)
        relations = tuple(dict(value) for value in auxiliary_relations)
        if evidence_payload is not None:
            if artifact is None:
                raise ServiceError("CAS bytes require an evidence or diff Artifact command")
            evidence_store.stage(
                artifact,
                evidence_payload,
                command_digest=digest_value(command),
            )
        elif artifact is not None:
            _require_staged_or_finalized_evidence(
                evidence_store,
                artifact,
                digest_value(command),
            )
        if resolved_workcard is not None:
            _persist_workcard(self.root, resolved_workcard)
        result = store.commit(
            command,
            auxiliary_relations=relations,
            created_at=command["issued_at"],
        )
        prepared = self._prepared_runtime
        committed_envelope = _committed_envelope(
            store, command, result["batch_digest"]
        )
        if artifact is not None:
            evidence_store.finalize(
                artifact,
                command_digest=digest_value(command),
                envelope=committed_envelope,
            )
            evidence_store.reconcile(_evidence_envelopes(evidence_store, store))
        runtime_overlay_metrics = {
            "runtime_overlay_compaction_depth": store.policy.runtime_overlay_compaction_depth,
            "duration_ms": 0.0,
            "changed_records": 0,
            "compacted": False,
            "compacted_record_count": 0,
            "compacted_payload_bytes": 0,
        }
        if result["outcome"] == "committed":
            if (
                prepared is None
                or prepared.command_id != command["command_id"]
                or prepared.head_sequence + 1 != result["facts"]["sequence"]
            ):
                raise ServiceError("durable commit lost its prepared isolated runtime")
            decisions = prepared.decisions
            batch = committed_envelope["batch"]
            if command["command_kind"] == "decision.record":
                decisions = decisions.extend(
                    command["payload"]["decision_id"],
                    command["payload"],
                    batch["events"][0],
                )
            prepared.authority.decision_resolver = decisions.resolve
            if artifact is not None and artifact.get("artifact_kind") == "diff":
                if resolved_workcard is None:
                    raise ServiceError("Candidate delta lost its mutation WorkCard")
                prepared.domain.validate_candidate_delta(
                    artifact["digest"],
                    task_id=resolved_workcard["task_id"],
                    workcard=resolved_workcard,
                    authorization=_domain_authorization(command),
                )
            frozen_authority, frozen_domain, runtime_overlay_metrics = (
                _freeze_runtime_components(
                    prepared.authority,
                    prepared.domain,
                    store.policy,
                )
            )
            frozen_authority.decision_resolver = decisions.resolve
            snapshot = _RuntimeSnapshot(
                activation_digest=activation["activation_digest"],
                implementation_closure_digest=_implementation_closure_digest(context),
                authoritative_byte_digest=prepared.authoritative_byte_digest,
                head_sequence=result["facts"]["sequence"],
                head_digest=result["batch_digest"],
                state_binding_digest=batch["state_binding_digest"],
                authority=frozen_authority,
                domain=frozen_domain,
                decisions=decisions,
                relations=prepared.relations,
                runs=prepared.runs,
                artifacts=prepared.artifacts,
            )
            self._bind_query_runtime(context, store, snapshot)
        else:
            snapshot = self._runtime_state(context, store)
            self._bind_query_runtime(context, store, snapshot)
        self._prepared_runtime = None
        try:
            projection_metrics = self._projection(context).apply_committed_batch(store)
        except ProjectionError as exc:
            projection_metrics = {
                "status": "failed-rebuild-required",
                "projection_authoritative": False,
                "error": f"{type(exc).__name__}: {exc}",
                "changed_records": 0,
                "changed_shards": 0,
                "physical_payload_bytes": 0,
                "bytes_per_changed_record": 0.0,
            }
        checkpoint_metrics = self._write_runtime_checkpoint(
            context,
            store,
            snapshot,
            committed_batch=True,
            committed_envelope=committed_envelope,
        )
        event_metrics = store.last_commit_write_metrics()
        changed_records = event_metrics["changed_records"]
        total_payload_bytes = (
            event_metrics["physical_payload_bytes"]
            + checkpoint_metrics["checkpoint_bytes"]
            + projection_metrics["physical_payload_bytes"]
        )
        result["operation_metrics"] = {
            "record_type": "OperationMetrics",
            "claim_scope": "single-command-observation-only",
            "authoritative": False,
            "duration_ms": round((time.perf_counter() - operation_started) * 1000, 6),
            "changed_records": changed_records,
            "event_write": {
                key: event_metrics[key]
                for key in (
                    "changed_records",
                    "journal_authority_bytes",
                    "temporary_staging_bytes",
                    "head_bytes",
                    "derived_index_bytes",
                    "journal_checkpoint_bytes",
                    "logical_final_bytes",
                    "physical_payload_bytes",
                )
            },
            "projection_update": projection_metrics,
            "runtime_checkpoint": checkpoint_metrics,
            "physical_payload_bytes": total_payload_bytes,
            "bytes_per_changed_record": (
                round(total_payload_bytes / changed_records, 6)
                if changed_records
                else 0.0
            ),
        }
        try:
            from .telemetry import record_observation

            record_observation(
                self.root,
                kind="runtime.overlay.freeze",
                status="compacted" if runtime_overlay_metrics.get("compacted") else "observed",
                duration_ms=runtime_overlay_metrics.get("duration_ms"),
                details={
                    "component": "runtime-overlay",
                    **runtime_overlay_metrics,
                },
            )
        except Exception:
            # Local telemetry must never affect an authoritative command.
            pass
        validate_ingress(
            bundle,
            result["operation_metrics"],
            operation="replay",
            definition="OperationMetrics",
            context={
                **_validation_context(context),
                "operation_metrics": result["operation_metrics"],
            },
        )
        return result

    def publish_evidence(
        self,
        command: dict[str, Any],
        payload: bytes,
        *,
        workcard: Mapping[str, Any],
    ) -> dict[str, Any]:
        result = self.commit(
            command,
            workcard=workcard,
            evidence_payload=payload,
        )
        artifact = _evidence_artifact(command)
        if artifact is None:
            raise ServiceError("evidence publication requires artifact.record evidence")
        record = _reconciled_evidence(self.root, self._event_store(self._context())).get_record(
            artifact["artifact_id"]
        )
        # Finalization changes the evidence-resolution view without adding a new
        # journal batch.  Discard any in-process runtime snapshot that was
        # captured before CAS reconciliation so subsequent Decisions resolve the
        # exact finalized Artifact rather than a stale non-authoritative store.
        self._query_runtime_key = None
        self._query_runtime_value = None
        return {
            "record_type": "EvidenceCommandResult",
            "status": "pass",
            "command_result": result,
            "artifact": record["artifact"],
            "commit_binding": record["commit_binding"],
            "product_acceptance_pass_credit": False,
            "public_release_approved": False,
        }

    def rebuild(
        self,
        inventory: InventoryResult | None = None,
    ) -> dict[str, Any]:
        context = self._context(force_full=True)
        store = self._event_store(context)
        self._replay_validated(context, store)
        if inventory is not None and not isinstance(inventory, InventoryResult):
            raise ServiceError("projection rebuild accepts only a verified InventoryResult")
        persisted = _load_current_inventory(self.root, context)
        selected = persisted if inventory is None else _verify_inventory_result(inventory, persisted)
        verified = None if selected is None else VerifiedInventoryInput(
            activation_digest=_activation(context)["activation_digest"],
            stream_digest=selected.stream_digest or "",
            entry_count=len(selected.entries),
            inventory_digest=selected.candidate["inventory_digest"],
            stream_path=selected.stream_path,
            stream_bytes=selected.stream_bytes,
            manifest_digest=selected.manifest_digest,
            observed_at=selected.observed_at,
            product_tree_passes=selected.product_tree_passes,
        )
        result = self._projection(context).rebuild(store, inventory=verified)
        if result.get("product_passes", 0) != 0:
            raise ServiceError("projection rebuild performed a forbidden product-tree pass")
        inventory_passes = 0 if selected is None else selected.product_tree_passes
        if result.get("inventory_passes") != inventory_passes:
            raise ServiceError("projection rebuild inventory-pass accounting differs")
        if inventory_passes not in (0, 1):
            raise ServiceError("inventory pass count is invalid")
        return result

    def search(
        self,
        query: str,
        depth: int | None = None,
        *,
        subject_id: str,
        grant_id: str,
        budget: dict[str, int] | None = None,
        ranking: str = "bm25-v1",
        now: datetime | None = None,
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        if not query or not query.strip():
            raise ServiceError("query must be non-empty")
        context = self._context()
        selected_depth = _profile_depth(
            _preset(context),
            _activation(context),
            _bundle(context).core["conformance.json"],
            depth,
        )
        store = self._event_store(context, recover_publications=False)
        projection = self._projection(context)
        projection.require_current(store)
        selected_budget = dict(budget or _profile_budget(_preset(context), _activation(context)))
        now_text = _evaluation_time(now)
        access = self._authorize_query_access(
            context,
            store,
            subject_id=subject_id,
            grant_id=grant_id,
            evaluated_at=now_text,
        )
        result = projection.search(
            query,
            depth=selected_depth,
            budget=selected_budget,
            ranking=ranking,
            resume_binding=_projection_resume_binding(context, access),
            now=now_text,
            ttl_seconds=ttl_seconds,
        )
        _validate_search_result(
            result,
            selected_budget,
            store.head(),
            _activation(context),
            now,
            max_token_bytes=projection.limits.max_token_bytes,
        )
        validate_ingress(
            _bundle(context),
            result,
            operation="replay",
            definition="RetrievalPage",
            context={
                **_validation_context(context),
                "retrieval_page": result,
            },
        )
        return result

    def continue_search(
        self,
        token: str,
        *,
        subject_id: str,
        grant_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if not token:
            raise ServiceError("continuation token must be non-empty")
        context = self._context()
        store = self._event_store(context, recover_publications=False)
        projection = self._projection(context)
        projection.require_current(store)
        now_text = _evaluation_time(now)
        head = store.head()
        access = self._authorize_query_access(
            context,
            store,
            subject_id=subject_id,
            grant_id=grant_id,
            evaluated_at=now_text,
        )
        result = projection.continue_search(
            token,
            resume_binding=_projection_resume_binding(context, access),
            now=now_text,
        )
        if result.get("record_type") != "ReadyFrontier":
            raise ServiceError(
                "public continue accepts only a ReadyFrontier continuation"
            )
        budget = _profile_budget(_preset(context), _activation(context))
        budget["top_k"] = 1
        return self._frontier_result(
            context,
            store,
            projection,
            result,
            result_type="ContinueResult",
            subject_id=subject_id,
            holder_grant_id=grant_id,
            query_grant_id=grant_id,
            query_access=access,
            budget=budget,
            evaluated_at=now_text,
        )

    def _authorize_query_access(
        self,
        context: ActivationContext,
        store: EventStore,
        *,
        subject_id: str,
        grant_id: str,
        evaluated_at: str,
        claim_digest: str | None = None,
        capability_id: str | None = None,
        requested_scope: Sequence[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any]:
        with self._query_runtime_lock:
            snapshot = self._query_runtime_state(context, store)
            authority = snapshot.authority.fork(
                decision_resolver=snapshot.decisions.resolve
            )
            grant = authority.grants.get(grant_id)
            if grant is None:
                raise ServiceError("query Grant is unresolved")
            selected_claim = grant["claim_digest"] if claim_digest is None else claim_digest
            selected_capability = "projection.read" if capability_id is None else capability_id
            if selected_capability != "projection.read":
                raise ServiceError("query continuation requires projection.read capability")
            selected_scope = (
                [dict(value) for value in grant["scope"]]
                if requested_scope is None
                else [dict(value) for value in requested_scope]
            )
            authorization = {
                "subject_id": subject_id,
                "grant_id": grant_id,
                "claim_digest": selected_claim,
                "evaluated_at": evaluated_at,
                "activation_digest": _activation(context)["activation_digest"],
            }
            receipt = authority.authorize_current_access(
                authorization,
                selected_capability,
                selected_scope,
                _activation(context)["activation_digest"],
            )
            receipt_grant = _field(receipt, "grant")
            if not isinstance(receipt_grant, Mapping) or dict(receipt_grant) != grant:
                raise ServiceError("query authorization receipt differs from the current Grant")
            revocation_epoch = _field(receipt, "revocation_state_digest")
            if not isinstance(revocation_epoch, str) or not re.fullmatch(
                r"[0-9a-f]{64}", revocation_epoch
            ):
                raise ServiceError("query authorization receipt lacks revocation state")
            return {
                "subject_id": subject_id,
                "grant_id": grant_id,
                "grant_claim_digest": selected_claim,
                "capability_id": selected_capability,
                "requested_scope": selected_scope,
                "revocation_epoch": revocation_epoch,
            }

    def next(
        self,
        *,
        subject_id: str,
        grant_id: str,
        query_grant_id: str,
        depth: int | None = None,
        now: datetime | None = None,
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        context = self._context()
        activation = _activation(context)
        if depth is not None:
            _profile_depth(
                _preset(context),
                activation,
                _bundle(context).core["conformance.json"],
                depth,
            )
        store = self._event_store(context, recover_publications=False)
        projection = self._projection(context)
        projection.require_current(store)
        now_text = _evaluation_time(now)
        access = self._authorize_query_access(
            context,
            store,
            subject_id=subject_id,
            grant_id=query_grant_id,
            evaluated_at=now_text,
        )
        budget = _profile_budget(_preset(context), activation)
        frontier = projection.ready_frontier(
            resume_binding=_projection_resume_binding(context, access),
            limit=1,
            budget=budget,
            now=now_text,
            ttl_seconds=ttl_seconds,
        )
        budget["top_k"] = 1
        return self._frontier_result(
            context,
            store,
            projection,
            frontier,
            result_type="NextResult",
            subject_id=subject_id,
            holder_grant_id=grant_id,
            query_grant_id=query_grant_id,
            query_access=access,
            budget=budget,
            evaluated_at=now_text,
        )

    def _frontier_result(
        self,
        context: ActivationContext,
        store: EventStore,
        projection: Projection,
        frontier: Mapping[str, Any],
        *,
        result_type: str,
        subject_id: str,
        holder_grant_id: str,
        query_grant_id: str,
        query_access: Mapping[str, Any],
        budget: Mapping[str, int],
        evaluated_at: str,
    ) -> dict[str, Any]:
        if result_type not in {"NextResult", "ContinueResult"}:
            raise ServiceError("frontier result type is unsupported")
        if (
            frontier.get("record_type") != "ReadyFrontier"
            or frontier.get("activation_digest")
            != _activation(context)["activation_digest"]
            or frontier.get("head_digest") != store.head()["batch_digest"]
        ):
            raise ServiceError("ReadyFrontier is stale or malformed")
        ready_tasks = frontier.get("ready_tasks")
        if not isinstance(ready_tasks, list) or len(ready_tasks) > 1:
            raise ServiceError("public ReadyFrontier page is not single-item bounded")
        continuation_record = frontier.get("continuation")
        continuation = (
            continuation_record.get("token")
            if isinstance(continuation_record, Mapping)
            else None
        )
        if (frontier.get("truncated") is True) is not isinstance(continuation, str):
            raise ServiceError("ReadyFrontier truncation binding is invalid")
        if query_access.get("grant_id") != query_grant_id:
            raise ServiceError("ReadyFrontier query Grant binding changed")
        snapshot = self._query_runtime_state(context, store)
        authority = snapshot.authority.fork(
            decision_resolver=snapshot.decisions.resolve
        )
        holder = authority.grants.get(holder_grant_id)
        if holder is None:
            raise ServiceError("WorkCard holder Grant is unresolved")
        if (
            result_type == "NextResult"
            and holder.get("capability_id") != "task.execute"
        ):
            raise ServiceError("next WorkCard holder lacks task.execute")
        activation_digest = _activation(context)["activation_digest"]
        if not ready_tasks:
            result = {
                "record_type": result_type,
                "status": "empty",
                "subject_id": subject_id,
                "activation_digest": activation_digest,
                "work_card": None,
                "continuation": None,
            }
            validate_ingress(
                _bundle(context),
                result,
                operation="replay",
                definition=result_type,
                context={
                    **_validation_context(context),
                    "next_result" if result_type == "NextResult" else "continue_result": result,
                },
            )
            return result

        selected = ready_tasks[0]
        if not isinstance(selected, Mapping):
            raise ServiceError("ReadyFrontier selection is malformed")
        workcard_projection = projection.work_card_projection(
            selected["task_id"],
            task_digest=selected["task_digest"],
            resume_binding=_projection_resume_binding(context, query_access),
            budget=budget,
        )
        validate_definition(
            _bundle(context).schema,
            "WorkCardProjection",
            workcard_projection,
        )
        task_entity = workcard_projection["task"]
        task = task_entity.get("payload") if isinstance(task_entity, Mapping) else None
        if (
            not isinstance(task, Mapping)
            or task.get("record_type") != "Task"
            or task.get("task_id") != selected["task_id"]
            or digest_value(task) != selected["task_digest"]
        ):
            raise ServiceError("WorkCardProjection selected another Task")
        if result_type == "NextResult":
            authority.authorize(
                subject_id,
                task["required_capability"],
                holder["scope"],
                holder_grant_id,
                holder["claim_digest"],
                evaluated_at,
                candidate_digest=task["candidate_digest"],
            )
        card = {
            "record_type": "WorkCard",
            "task_id": task["task_id"],
            "operation_mode": "read",
            "operation": "inspect-next-task",
            "acceptance_predicate": task["acceptance_predicate"],
            "allowed_paths": task["allowed_paths"],
            "holder_grant_id": holder_grant_id,
            "query_grant_id": query_grant_id,
            "query_grant_claim_digest": query_access["grant_claim_digest"],
            "candidate_digest": task["candidate_digest"],
            "activation_digest": activation_digest,
            "context_digest": digest_value(workcard_projection),
            "stop_conditions": ["budget-exhausted", "task-state-changed", "activation-or-head-changed"],
            "budget": dict(budget),
            "truncated": frontier["truncated"],
        }
        for optional_field in (
            "operation_profile_id",
            "recommended_model_tier",
            "orchestration_required",
        ):
            if optional_field in task:
                card[optional_field] = task[optional_field]
        if card["truncated"]:
            card["continuation_query"] = continuation
        validate_ingress(
            _bundle(context),
            card,
            operation="rebuild",
            definition="WorkCard",
            context=_validation_context(context),
        )
        result = {
            "record_type": result_type,
            "status": "ready",
            "subject_id": subject_id,
            "activation_digest": activation_digest,
            "work_card": card,
            "continuation": continuation,
        }
        validate_ingress(
            _bundle(context),
            result,
            operation="replay",
            definition=result_type,
            context={
                **_validation_context(context),
                "workcard_projection": workcard_projection,
                "next_result" if result_type == "NextResult" else "continue_result": result,
            },
        )
        return result


    def _runtime_from_envelopes(
        self,
        context: ActivationContext,
        envelopes: Iterable[Mapping[str, Any]],
        *,
        head_sequence: int,
        head_digest: str | None,
        state_binding_digest: str | None,
        allow_trailing_evidence: bool = False,
    ) -> _RuntimeSnapshot:
        envelope_values = [dict(value) for value in envelopes]
        evidence = EvidenceStore(_evidence_root(self.root))
        evidence.reconcile(
            envelope_values,
            allow_trailing_records=allow_trailing_evidence,
        )
        authority, domain = self._new_runtime(context, evidence=evidence)
        decisions = _DecisionBindings()
        relations = _RelationLedger()
        runs = _RunBindings()
        artifacts = _ArtifactBindings()
        replayed = 0
        observed_state_binding_digest: str | None = None
        for envelope in envelope_values:
            authority.decision_resolver = decisions.resolve
            decisions, relations, runs, artifacts = self._replay_envelope(
                context,
                authority,
                domain,
                envelope,
                decisions=decisions,
                relations=relations,
                runs=runs,
                artifacts=artifacts,
            )
            replayed += 1
            batch = envelope.get("batch")
            if not isinstance(batch, Mapping):
                raise ServiceError("runtime replay envelope lacks EventBatch")
            observed_state_binding_digest = batch.get("state_binding_digest")
        if replayed != head_sequence:
            raise ServiceError("runtime replay batch count differs from locked HEAD")
        if (
            replayed > 0
            and
            state_binding_digest is not None
            and observed_state_binding_digest != state_binding_digest
        ):
            raise ServiceError("runtime replay state root differs from locked HEAD")
        policy = _event_store_policy(context)
        authority, domain, _metrics = _freeze_runtime_components(
            authority, domain, policy
        )
        authority.decision_resolver = decisions.resolve
        byte_digest = context.authoritative_byte_digest
        if not isinstance(byte_digest, str):
            raise ServiceError("runtime replay lacks authoritative byte verification")
        return _RuntimeSnapshot(
            activation_digest=_activation(context)["activation_digest"],
            implementation_closure_digest=_implementation_closure_digest(context),
            authoritative_byte_digest=byte_digest,
            head_sequence=head_sequence,
            head_digest=head_digest,
            state_binding_digest=(
                state_binding_digest
                if replayed == 0
                else observed_state_binding_digest
            ),
            authority=authority,
            domain=domain,
            decisions=decisions,
            relations=relations,
            runs=runs,
            artifacts=artifacts,
        )

    def _new_runtime(
        self,
        context: ActivationContext,
        *,
        evidence: EvidenceStore | None = None,
    ) -> tuple[AuthorityEngine, DomainState]:
        activation = _activation(context)
        _lease_parallelism_policy(context)
        decisions = _DecisionBindings()
        authority = AuthorityEngine(
            _authority_init(context),
            activation["activation_digest"],
            _authority_runtime_policy(context),
            signature_verifier=context.signature_verifier,
            decision_resolver=decisions.resolve,
        )
        domain = DomainState(
            authority,
            evidence if evidence is not None else EvidenceStore(_evidence_root(self.root)),
            required_acceptance=_bundle(context).core["conformance.json"][
                "required_acceptance"
            ],
            provider_binding_digest=_provider_binding_digest(context),
            implementation_closure_digest=_implementation_closure_digest(context),
            gate_authorization_scope_contract=_bundle(context).core[
                "policy-set.json"
            ]["gate_run_definition_contract"]["authorization_scope_contract"],
        )
        return authority, domain

    def _replay_envelope(
        self,
        context: ActivationContext,
        authority: AuthorityEngine,
        domain: DomainState,
        envelope: Mapping[str, Any],
        *,
        decisions: _DecisionBindings,
        relations: _RelationLedger,
        runs: _RunBindings,
        artifacts: _ArtifactBindings,
    ) -> tuple[
        _DecisionBindings,
        _RelationLedger,
        _RunBindings,
        _ArtifactBindings,
    ]:
        bundle = _bundle(context)
        command = _command_from_envelope(envelope)
        validate_ingress(
            bundle,
            command,
            operation="replay",
            definition="CommandRequest",
            context=_validation_context(context),
        )
        _validate_definition_digest_equality(command)
        if command["command_kind"] == "run.record":
            _validate_run_definition(domain, command["payload"], command["issued_at"])
        run = (
            runs.resolve(command["payload"].get("run_id", ""))
            if command["command_kind"] == "gate.record"
            else None
        )
        if command["command_kind"] == "gate.record":
            if run is None:
                raise ServiceError("replayed GateResult Run is unresolved")
            _validate_gate_run_before_authorization(
                domain,
                command["payload"],
                run,
                command["issued_at"],
            )
        issue_authorization = self._authorize_command(
            context, authority, command, replay=True
        )
        replay_workcard = self._resolve_mutation_workcard(context, command, None)
        self._apply_command(
            domain,
            authority,
            command,
            replay=True,
            grant_issue_authorization=issue_authorization,
            workcard=replay_workcard,
            parallelism_policy=_lease_parallelism_policy(context),
            run=run,
        )
        current_relations = relations.materialize()
        added_relations = _validated_auxiliary_relations(
            bundle,
            context,
            command,
            _relations_from_envelope(envelope),
            operation="replay",
            domain=domain,
            current_relations=current_relations,
        )
        policy = _event_store_policy(context)
        expected_delta = _state_binding_delta(
            policy,
            command,
            added_relations,
            authority,
            domain,
        )
        batch = envelope.get("batch")
        actual_delta = batch.get("state_binding_delta") if isinstance(batch, Mapping) else None
        if [dict(value) for value in expected_delta] != actual_delta:
            raise ServiceError("journal state-binding delta differs from event-time state")
        artifact = _evidence_artifact(command)
        if artifact is not None and artifact.get("artifact_kind") == "diff":
            if replay_workcard is None:
                raise ServiceError("replayed Candidate delta lacks its mutation WorkCard")
            domain.validate_candidate_delta(
                artifact["digest"],
                task_id=replay_workcard["task_id"],
                workcard=replay_workcard,
                authorization=_domain_authorization(command),
            )
        if command["command_kind"] == "decision.record":
            events = batch.get("events") if isinstance(batch, Mapping) else None
            if not isinstance(events, list) or not events:
                raise ServiceError("Decision replay lacks its immutable Event")
            primary = events[0]
            if primary.get("event_kind") != "decision.recorded":
                raise ServiceError("Decision replay primary Event differs")
            decisions = decisions.extend(
                command["payload"]["decision_id"],
                command["payload"],
                primary,
            )
            authority.decision_resolver = decisions.resolve
        if command["command_kind"] == "run.record":
            runs = runs.extend(command["payload"])
        if command["command_kind"] == "artifact.record":
            artifacts = artifacts.extend(command["payload"])
        return decisions, relations.extend(added_relations), runs, artifacts

    def _runtime_state(
        self,
        context: ActivationContext,
        store: EventStore,
    ) -> _RuntimeSnapshot:
        verified = self._verified_mutation_context(context)
        head = store.head()
        checkpoint = store.read_derived_state("runtime")
        if checkpoint is not None:
            try:
                snapshot, checkpoint_count, tail_batches, tail_bytes = (
                    self._runtime_from_checkpoint(
                        verified,
                        store,
                        checkpoint,
                        expected_head=head,
                    )
                )
                binding = store.validate_state_binding_leaves(
                    _runtime_state_binding_leaves(store.policy, snapshot),
                    expected_head=head,
                )
                if binding != snapshot.state_binding_digest:
                    raise ServiceError(
                        "restored runtime state differs from its journal commitment"
                    )
                self._bind_runtime_checkpoint_cursor(
                    verified,
                    head,
                    checkpoint_count=checkpoint_count,
                    tail_batches=tail_batches,
                    tail_bytes=tail_bytes,
                )
                if store.head() != head:
                    raise ServiceError("event HEAD changed during checkpoint-tail replay")
                return snapshot
            except Exception:
                # A derived checkpoint has no authority. Any shape, binding, or
                # tail-replay failure discards it and rebuilds from the journal.
                head = store.head()
        tail_envelopes = list(store.iter_envelopes(validate=True))
        tail_bytes = sum(len(canonical_bytes(value)) for value in tail_envelopes)
        snapshot = self._runtime_from_envelopes(
            verified,
            tail_envelopes,
            head_sequence=head["sequence"],
            head_digest=head["batch_digest"],
            state_binding_digest=None,
        )
        binding = store.validate_state_binding_leaves(
            _runtime_state_binding_leaves(store.policy, snapshot),
            expected_head=head,
        )
        if snapshot.state_binding_digest not in {None, binding}:
            raise ServiceError("runtime replay differs from its journal commitment")
        if snapshot.state_binding_digest is None:
            snapshot = _RuntimeSnapshot(
                activation_digest=snapshot.activation_digest,
                implementation_closure_digest=snapshot.implementation_closure_digest,
                authoritative_byte_digest=snapshot.authoritative_byte_digest,
                head_sequence=snapshot.head_sequence,
                head_digest=snapshot.head_digest,
                state_binding_digest=binding,
                authority=snapshot.authority,
                domain=snapshot.domain,
                decisions=snapshot.decisions,
                relations=snapshot.relations,
                runs=snapshot.runs,
                artifacts=snapshot.artifacts,
            )
        self._bind_runtime_checkpoint_cursor(
            verified,
            head,
            checkpoint_count=0,
            tail_batches=len(tail_envelopes),
            tail_bytes=tail_bytes,
        )
        if store.head() != head:
            raise ServiceError("event HEAD changed during runtime replay")
        return snapshot

    def _runtime_from_checkpoint(
        self,
        context: ActivationContext,
        store: EventStore,
        checkpoint: Mapping[str, Any],
        *,
        expected_head: Mapping[str, Any],
    ) -> tuple[_RuntimeSnapshot, int, int, int]:
        checkpoint_head = checkpoint.get("head")
        state = checkpoint.get("state")
        binding = checkpoint.get("authority_state_binding_digest")
        if (
            not isinstance(checkpoint_head, Mapping)
            or not isinstance(state, Mapping)
            or not isinstance(binding, str)
        ):
            raise ServiceError("runtime checkpoint binding is incomplete")
        compaction = state.get("compaction")
        checkpoint_count = (
            compaction.get("checkpoint_count")
            if isinstance(compaction, Mapping)
            else None
        )
        if (
            not isinstance(checkpoint_count, int)
            or isinstance(checkpoint_count, bool)
            or checkpoint_count < 1
        ):
            raise ServiceError("runtime checkpoint count is invalid")
        decisions = _DecisionBindings.restore(state.get("decisions"))
        evidence = EvidenceStore(_evidence_root(self.root))
        artifact_state = state.get("artifacts")
        if (
            evidence.finalized_artifact_ids()
            or evidence.pending_artifact_ids()
            or (isinstance(artifact_state, Mapping) and bool(artifact_state))
        ):
            evidence.reconcile(store.iter_envelopes(validate=True))
        authority, domain = self._new_runtime(context, evidence=evidence)
        authority.decision_resolver = decisions.resolve
        authority.restore_checkpoint(state.get("authority"))
        domain.restore_checkpoint(
            state.get("domain"),
            expected_head_sequence=checkpoint_head["sequence"],
            expected_head_digest=checkpoint_head["batch_digest"],
            expected_state_binding_digest=binding,
            parallelism_policy=_lease_parallelism_policy(context),
        )
        relations = _RelationLedger.restore(state.get("relations"))
        runs = _RunBindings.restore(state.get("runs"))
        artifacts = _ArtifactBindings.restore(state.get("artifacts"))
        tail_batches = 0
        tail_bytes = 0
        observed_binding = binding
        for envelope in store.iter_envelopes_after(checkpoint_head, validate=True):
            authority.decision_resolver = decisions.resolve
            decisions, relations, runs, artifacts = self._replay_envelope(
                context,
                authority,
                domain,
                envelope,
                decisions=decisions,
                relations=relations,
                runs=runs,
                artifacts=artifacts,
            )
            tail_batches += 1
            tail_bytes += len(canonical_bytes(envelope))
            batch = envelope.get("batch")
            if not isinstance(batch, Mapping):
                raise ServiceError("runtime checkpoint tail lacks EventBatch")
            observed_binding = batch.get("state_binding_digest")
        if checkpoint_head["sequence"] + tail_batches != expected_head["sequence"]:
            raise ServiceError("runtime checkpoint tail count differs from current HEAD")
        authority, domain, _metrics = _freeze_runtime_components(
            authority,
            domain,
            store.policy,
        )
        authority.decision_resolver = decisions.resolve
        byte_digest = context.authoritative_byte_digest
        if not isinstance(byte_digest, str):
            raise ServiceError("runtime checkpoint lacks authoritative byte verification")
        return (
            _RuntimeSnapshot(
                activation_digest=_activation(context)["activation_digest"],
                implementation_closure_digest=_implementation_closure_digest(context),
                authoritative_byte_digest=byte_digest,
                head_sequence=expected_head["sequence"],
                head_digest=expected_head["batch_digest"],
                state_binding_digest=observed_binding,
                authority=authority,
                domain=domain,
                decisions=decisions,
                relations=relations,
                runs=runs,
                artifacts=artifacts,
            ),
            checkpoint_count,
            tail_batches,
            tail_bytes,
        )

    def _domain_state(self, context: ActivationContext, store: EventStore) -> DomainState:
        return self._query_runtime_state(context, store).domain

    def _write_runtime_checkpoint(
        self,
        context: ActivationContext,
        store: EventStore,
        snapshot: _RuntimeSnapshot,
        *,
        force: bool = False,
        committed_batch: bool = False,
        committed_envelope: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        policy = store.policy
        head = store.head()
        cursor = self._runtime_checkpoint_cursor
        tail: dict[str, Any]
        batch = (
            committed_envelope.get("batch")
            if isinstance(committed_envelope, Mapping)
            else None
        )
        cursor_matches_commit = (
            committed_batch
            and isinstance(batch, Mapping)
            and cursor is not None
            and cursor.activation_digest == _activation(context)["activation_digest"]
            and cursor.implementation_closure_digest
            == _implementation_closure_digest(context)
            and cursor.head_sequence + 1 == head["sequence"]
            and cursor.head_digest == batch.get("previous_digest")
            and batch.get("sequence") == head["sequence"]
            and batch.get("batch_id") == head["batch_id"]
            and digest_value(batch) == head["batch_digest"]
        )
        if cursor_matches_commit:
            envelope_bytes = len(canonical_bytes(committed_envelope))
            tail_batches = cursor.tail_batches + 1
            tail_bytes = cursor.tail_bytes + envelope_bytes
            tail = {
                "record_type": "DerivedTailStatus",
                "authoritative": False,
                "name": "runtime",
                "head": head,
                "checkpoint_count": cursor.checkpoint_count,
                "tail_batches": tail_batches,
                "tail_bytes": tail_bytes,
                "batch_threshold": policy.derived_tail_batch_threshold,
                "byte_threshold": policy.derived_tail_byte_threshold,
                "compaction_due": cursor.checkpoint_count == 0
                or tail_batches >= policy.derived_tail_batch_threshold
                or tail_bytes >= policy.derived_tail_byte_threshold,
            }
        else:
            # External writers, process restart, forced replay, or a missing
            # cursor fall back to the lock-stable verified journal route.
            tail = store.derived_tail_status("runtime")
        previous_count = tail.get("checkpoint_count", 0)
        if (
            not isinstance(previous_count, int)
            or isinstance(previous_count, bool)
            or previous_count < 0
        ):
            previous_count = 0
        common = {
            "authoritative": False,
            "checkpoint_count": previous_count,
            "checkpoint_bytes": 0,
            "tail_batches": tail["tail_batches"],
            "tail_bytes": tail["tail_bytes"],
            "batch_threshold": policy.derived_tail_batch_threshold,
            "byte_threshold": policy.derived_tail_byte_threshold,
        }
        if head["sequence"] == 0 or (not force and not tail["compaction_due"]):
            self._bind_runtime_checkpoint_cursor(
                context,
                head,
                checkpoint_count=previous_count,
                tail_batches=tail["tail_batches"],
                tail_bytes=tail["tail_bytes"],
            )
            return {"written": False, **common}
        if (
            snapshot.head_sequence != head["sequence"]
            or snapshot.head_digest != head["batch_digest"]
        ):
            raise ServiceError("runtime checkpoint snapshot is stale")
        envelope = (
            dict(committed_envelope)
            if cursor_matches_commit and isinstance(committed_envelope, Mapping)
            else store.envelope_at_head()
        )
        if not isinstance(envelope, Mapping):
            raise ServiceError("runtime checkpoint lacks authoritative head envelope")
        state_binding_digest = envelope["batch"]["state_binding_digest"]
        restored_binding = store.validate_state_binding_leaves(
            _runtime_state_binding_leaves(store.policy, snapshot),
            expected_head=head,
        )
        if (
            restored_binding != state_binding_digest
            or snapshot.state_binding_digest != state_binding_digest
        ):
            raise ServiceError("runtime checkpoint state differs from journal authority")
        compaction = {
            "checkpoint_count": previous_count + 1,
            "tail_batches_compacted": tail["tail_batches"],
            "tail_bytes_compacted": tail["tail_bytes"],
            "batch_threshold": policy.derived_tail_batch_threshold,
            "byte_threshold": policy.derived_tail_byte_threshold,
        }
        state = {
            "authority": snapshot.authority.checkpoint(),
            "domain": snapshot.domain.checkpoint(
                head_sequence=head["sequence"],
                head_digest=head["batch_digest"],
                state_binding_digest=state_binding_digest,
                runtime_policy=_lease_parallelism_policy(context),
            ),
            "decisions": list(snapshot.decisions.materialize()),
            "relations": list(snapshot.relations.materialize()),
            "runs": list(snapshot.runs.materialize()),
            "artifacts": list(snapshot.artifacts.materialize()),
            "compaction": compaction,
        }
        checkpoint = store.write_derived_state(
            "runtime", state, expected_head=head
        )
        self._bind_runtime_checkpoint_cursor(
            context,
            head,
            checkpoint_count=compaction["checkpoint_count"],
            tail_batches=0,
            tail_bytes=0,
        )
        return {
            "written": True,
            "authoritative": False,
            "checkpoint_count": compaction["checkpoint_count"],
            "checkpoint_bytes": len(canonical_bytes(checkpoint)),
            "tail_batches": 0,
            "tail_bytes": 0,
            "compacted_tail_batches": tail["tail_batches"],
            "compacted_tail_bytes": tail["tail_bytes"],
            "batch_threshold": policy.derived_tail_batch_threshold,
            "byte_threshold": policy.derived_tail_byte_threshold,
        }

    def _replay_validated(
        self,
        context: ActivationContext,
        store: EventStore,
    ) -> dict[str, Any]:
        head = store.head()
        verified = self._verified_mutation_context(context)
        snapshot = self._runtime_from_envelopes(
            verified,
            store.iter_envelopes(validate=True),
            head_sequence=head["sequence"],
            head_digest=head["batch_digest"],
            state_binding_digest=None,
        )
        checkpoint = self._write_runtime_checkpoint(
            verified, store, snapshot
        )
        return {
            "record_type": "ReplayResult",
            "status": "pass",
            "event_batches": head["sequence"],
            "head": head,
            "runtime_checkpoint_written": checkpoint["written"],
            "runtime_checkpoint": checkpoint,
            "runtime_checkpoint_authoritative": False,
        }

    def _authorize_command(
        self,
        context: ActivationContext,
        authority: AuthorityEngine,
        command: dict[str, Any],
        *,
        replay: bool = False,
    ) -> dict[str, Any] | None:
        _validate_definition_digest_equality(command)
        authorization = command["authorization"]
        capability = _required_capability(_bundle(context), command)
        _validate_command_intent(command)
        _validate_effect_scope(_bundle(context), command, authority.grants)
        if command["command_kind"] == "grant.issue":
            return authority.authorize_grant_issue_command(
                command, replay=replay
            )
        if authorization["kind"] == "root":
            raise ServiceError("root authorization is only valid for bootstrap grant.issue")
        authority.authorize(
            command["subject_id"],
            capability,
            command["requested_scope"],
            authorization["grant_id"],
            authorization["grant_claim_digest"],
            command["issued_at"],
            candidate_digest=command["payload"].get("candidate_digest") if isinstance(command["payload"], dict) else None,
            replay=replay,
        )
        return None

    def _resolve_mutation_workcard(
        self,
        context: ActivationContext,
        command: Mapping[str, Any],
        supplied: Mapping[str, Any] | None,
    ) -> dict[str, Any] | None:
        required = _mutation_claim_required(_bundle(context), command)
        if not required:
            if supplied is not None:
                raise ServiceError("non-lease command cannot carry a mutation WorkCard")
            return None
        digest = command.get("workcard_digest")
        if not isinstance(digest, str):
            raise ServiceError("lease-bound command lacks a WorkCard digest")
        if supplied is None:
            card = _load_workcard(self.root, digest)
        else:
            card = dict(supplied)
        validate_ingress(
            _bundle(context),
            card,
            operation="replay" if supplied is None else "command",
            definition="WorkCard",
            context=_validation_context(context),
        )
        if digest_value(card) != digest:
            raise ServiceError("mutation WorkCard does not match CommandRequest digest")
        return card

    @staticmethod
    def _apply_command(
        domain: DomainState,
        authority: AuthorityEngine,
        command: dict[str, Any],
        *,
        replay: bool = False,
        grant_issue_authorization: Mapping[str, Any] | None = None,
        workcard: Mapping[str, Any] | None = None,
        parallelism_policy: Mapping[str, Any] | None = None,
        run: Mapping[str, Any] | None = None,
    ) -> None:
        kind = command["command_kind"]
        payload = command["payload"]
        authorization = _domain_authorization(command)
        if workcard is not None:
            domain.assert_mutation_claim(command, workcard)
        if kind == "grant.issue":
            if grant_issue_authorization is None:
                raise ServiceError("grant.issue lacks its command authorization receipt")
            authority.issue_grant(
                payload,
                command["issued_at"],
                issue_authorization=grant_issue_authorization,
            )
        elif kind == "grant.revoke":
            authority.revoke_grant(payload, authorization["grant_id"], command["subject_id"])
        elif kind == "task.record":
            domain.record_task(payload, authorization)
        elif kind == "task.transition":
            domain.transition_task(
                payload,
                authorization,
                runtime_policy=parallelism_policy,
            )
        elif kind == "candidate.record":
            domain.record_candidate(payload, authorization)
        elif kind == "lease.record":
            _apply_lease(
                domain,
                authority,
                payload,
                authorization,
                command["issued_at"],
                parallelism_policy=parallelism_policy,
            )
        elif kind == "finding.record":
            domain.record_finding(payload, authorization)
        elif kind == "gate.record":
            if run is None:
                raise ServiceError("GateResult requires its immutable Run")
            domain.record_gate_result(
                payload,
                authorization,
                run_record=run,
                lease_bound_task_id=(
                    workcard["task_id"] if workcard is not None else None
                ),
            )
        elif kind == "decision.record":
            domain.record_decision(payload, authorization)
        elif kind in {"artifact.record", "run.record"}:
            # Artifact and Run facts remain immutable event-owned records. Evidence
            # publication is a separate CAS operation and cannot be inferred here.
            if kind == "run.record":
                capability = "validation.evaluate" if payload["run_kind"] == "validation" else "task.execute"
                authority.record_action(
                    command["subject_id"],
                    capability,
                    authorization=authorization,
                    candidate_digest=payload["candidate_digest"],
                )
            elif payload["artifact_kind"] in {"product", "log", "diff"}:
                candidate_digest = (
                    payload["candidate_delta"]["new_candidate_digest"]
                    if payload["artifact_kind"] == "diff"
                    else payload.get("evidence_binding", {}).get("candidate_digest")
                )
                authority.record_action(
                    command["subject_id"],
                    "task.execute",
                    authorization=authorization,
                    candidate_digest=candidate_digest,
                )
            return
        else:
            raise ServiceError(f"unsupported command kind: {kind}")


def _required_capability(bundle: ContractBundle, command: dict[str, Any]) -> str:
    authority_model = bundle.core.get("authority-model.json")
    if not isinstance(authority_model, Mapping):
        raise ServiceError("contract bundle lacks authority-model")
    rules = authority_model.get("command_capability_rules")
    if not isinstance(rules, list):
        raise ServiceError("authority-model lacks command capability rules")
    rule = next((value for value in rules if value.get("command_kind") == command["command_kind"]), None)
    if rule is None:
        raise ServiceError("command kind has no capability rule")
    if "capability_id" in rule:
        return rule["capability_id"]
    payload_value = command["payload"].get(rule["payload_field"])
    capability = rule.get("capability_by_value", {}).get(payload_value)
    if not capability:
        raise ServiceError("command payload does not resolve to one capability")
    return capability


def _mutation_claim_required(
    bundle: ContractBundle,
    command: Mapping[str, Any],
) -> bool:
    rule = bundle.core["authority-model.json"].get("command_mutation_claim_rule")
    if not isinstance(rule, Mapping):
        raise ServiceError("authority-model lacks mutation claim rule")
    kind = command.get("command_kind")
    if kind in rule.get("lease_bound_command_kinds", ()):
        return True
    if kind != "task.transition":
        return False
    payload = command.get("payload")
    return isinstance(payload, Mapping) and payload.get("to_state") in set(
        rule.get("lease_bound_task_transition_states", ())
    )


def _validate_command_intent(command: Mapping[str, Any]) -> None:
    identity = {
        key: value
        for key, value in command.items()
        if key not in {"intent_digest", "authorization"}
    }
    if command.get("intent_digest") != digest_value(identity):
        raise ServiceError("command intent digest mismatch")


def _validate_effect_scope(
    bundle: ContractBundle,
    command: Mapping[str, Any],
    grants: Mapping[str, Mapping[str, Any]],
) -> None:
    rules = {
        value["command_kind"]: value
        for value in bundle.core["authority-model.json"]["command_effect_scope_rules"]
    }
    rule = rules.get(command["command_kind"])
    if rule is None:
        raise ServiceError("command kind has no effect-scope rule")
    payload = command["payload"]
    mode = rule["mode"]
    effects: list[dict[str, str]]
    if mode == "payload-id":
        effects = [{"kind": rule["kind"], "value": payload[rule["id_field"]]}]
    elif mode == "payload-multi-id":
        effects = [
            {"kind": value["kind"], "value": payload[value["id_field"]]}
            for value in rule["targets"]
        ]
    elif mode in {
        "payload-dynamic-id",
        "payload-dynamic-id-or-referenced-grant-scope",
    }:
        target_type = payload[rule["kind_field"]]
        kind = rule["kind_map"].get(target_type)
        if kind:
            effects = [{"kind": kind, "value": payload[rule["id_field"]]}]
        elif (
            mode == "payload-dynamic-id-or-referenced-grant-scope"
            and target_type == rule["grant_target_type"]
        ):
            grant = grants.get(payload[rule["id_field"]])
            if grant is None:
                raise ServiceError(
                    "command effect references an unresolved Grant"
                )
            effects = list(grant["scope"])
        else:
            raise ServiceError("command effect target kind is unresolved")
    elif mode == "payload-scope":
        effects = list(payload[rule["scope_field"]])
    elif mode == "referenced-grant-scope":
        grant = grants.get(payload[rule["grant_id_field"]])
        if grant is None:
            raise ServiceError("command effect references an unresolved Grant")
        effects = list(grant["scope"])
    else:
        raise ServiceError("unsupported command effect-scope mode")
    requested = command["requested_scope"]
    requested_pairs = {(item["kind"], item["value"]) for item in requested}
    if ("all", "*") not in requested_pairs:
        missing = [
            (item["kind"], item["value"])
            for item in effects
            if (item["kind"], item["value"]) not in requested_pairs
        ]
        if missing:
            raise ServiceError(f"command effect target absent from requested scope: {missing}")


def _domain_authorization(command: Mapping[str, Any]) -> dict[str, Any]:
    value = command["authorization"]
    if value["kind"] != "grant":
        if command["command_kind"] == "grant.issue":
            return {
                "subject_id": command["subject_id"],
                "grant_id": "root-bootstrap",
                "claim_digest": ZERO_DIGEST,
                "evaluated_at": command["issued_at"],
                "requested_scope": command["requested_scope"],
            }
        raise ServiceError("domain mutation requires exact Grant authorization")
    return {
        "subject_id": command["subject_id"],
        "grant_id": value["grant_id"],
        "claim_digest": value["grant_claim_digest"],
        "evaluated_at": command["issued_at"],
        "requested_scope": command["requested_scope"],
    }


def _validate_definition_digest_equality(command: Mapping[str, Any]) -> None:
    if command.get("command_kind") not in {"run.record", "gate.record"}:
        return
    payload = command.get("payload")
    command_digest = command.get("definition_digest")
    payload_digest = (
        payload.get("definition_digest")
        if isinstance(payload, Mapping)
        else None
    )
    if (
        not isinstance(command_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", command_digest) is None
        or command_digest != payload_digest
    ):
        raise ServiceError(
            "CommandRequest definition_digest differs from its Run/GateResult"
        )


def _validate_run_definition(
    domain: DomainState,
    run: Mapping[str, Any],
    evaluated_at: str,
) -> dict[str, Any]:
    definition = domain.resolve_gate_definition(
        str(run.get("task_id", "")),
        str(run.get("definition_digest", "")),
    )
    for field in (
        "run_kind",
        "candidate_digest",
        "policy_digest",
        "tool_digest",
        "implementation_closure_digest",
        "provider_binding_digest",
        "input_digests",
        "activation_digest",
    ):
        if run.get(field) != definition.get(field):
            raise ServiceError(f"Run {field} differs from its GateRunDefinition")
    try:
        started_at = parse_utc_second(run.get("started_at"))
        finished_at = parse_utc_second(run.get("finished_at"))
        command_time = parse_utc_second(evaluated_at)
    except Exception as exc:
        raise ServiceError("Run chronology is invalid") from exc
    task = domain.tasks.get(run.get("task_id"))
    if (
        not isinstance(task, Mapping)
        or started_at < parse_utc_second(task.get("created_at"))
        or not started_at <= finished_at <= command_time
    ):
        raise ServiceError("Run chronology differs from its Task and command")
    return deepcopy(dict(definition))


def _validate_gate_run_before_authorization(
    domain: DomainState,
    result: Mapping[str, Any],
    run: Mapping[str, Any],
    evaluated_at: str,
) -> None:
    definition = domain.resolve_gate_definition(
        str(result.get("task_id", "")),
        str(result.get("definition_digest", "")),
    )
    try:
        DomainState._validate_gate_run(
            run,
            result,
            definition,
            parse_utc_second(evaluated_at),
        )
    except Exception as exc:
        raise ServiceError("GateResult Run differs from current authority") from exc


def _evidence_artifact(command: Mapping[str, Any]) -> dict[str, Any] | None:
    if command.get("command_kind") != "artifact.record":
        return None
    payload = command.get("payload")
    if not isinstance(payload, dict) or payload.get("artifact_kind") not in {
        "evidence",
        "diff",
    }:
        return None
    return payload


def _validate_artifact_implementation(
    context: ActivationContext,
    artifact: Mapping[str, Any],
) -> None:
    binding = artifact.get("evidence_binding")
    if artifact.get("artifact_kind") == "evidence" and not isinstance(binding, Mapping):
        raise ServiceError("evidence Artifact lacks an implementation-bound EvidenceBinding")
    if (
        isinstance(binding, Mapping)
        and binding.get("implementation_closure_digest")
        != _implementation_closure_digest(context)
    ):
        raise ServiceError("evidence Artifact implementation closure is stale")
    if isinstance(binding, Mapping):
        invocations = binding.get("provider_invocations", [])
        if not isinstance(invocations, list):
            raise ServiceError("evidence Artifact provider invocations are invalid")
        try:
            for invocation in invocations:
                context.provider_dispatch.validate_invocation_evidence(invocation)
        except Exception as exc:
            raise ServiceError(
                "evidence Artifact provider invocation differs from active bindings"
            ) from exc


def _require_staged_or_finalized_evidence(
    store: EvidenceStore,
    artifact: Mapping[str, Any],
    command_digest: str,
) -> None:
    artifact_id = artifact["artifact_id"]
    try:
        finalized = store.get_record(artifact_id)
    except Exception:
        finalized = None
    if finalized is not None:
        if (
            finalized.get("artifact") != dict(artifact)
            or finalized.get("commit_binding", {}).get("command_digest") != command_digest
        ):
            raise ServiceError("finalized evidence differs from Artifact command")
        return
    try:
        pending = store.pending_record(artifact_id)
    except Exception as exc:
            raise ServiceError("CAS Artifact bytes are neither staged nor finalized") from exc
    if pending != {"artifact": dict(artifact), "command_digest": command_digest}:
        raise ServiceError("staged evidence differs from Artifact command")


def _committed_envelope(
    store: EventStore,
    command: Mapping[str, Any],
    batch_digest: str,
) -> dict[str, Any]:
    envelope = store.read_envelope(batch_digest)
    if (
        envelope.get("command") != dict(command)
        or digest_value(envelope.get("batch")) != batch_digest
    ):
        raise ServiceError("committed command does not resolve one exact JournalEnvelope")
    return envelope


def _evidence_envelopes(evidence: EvidenceStore, store: EventStore) -> list[dict[str, Any]]:
    if evidence.pending_artifact_ids():
        return list(store.iter_envelopes(validate=True))
    return [
        store.read_envelope(binding["batch_digest"])
        for binding in evidence.finalized_commit_bindings()
    ]


def _recover_evidence_publications(
    project_root: Path,
    context: ActivationContext,
    store: EventStore,
) -> None:
    evidence = EvidenceStore(_evidence_root(project_root))
    envelopes = _evidence_envelopes(evidence, store)
    for envelope in envelopes:
        command = _command_from_envelope(envelope)
        if _evidence_artifact(command) is not None:
            validate_ingress(
                _bundle(context),
                command,
                operation="replay",
                definition="CommandRequest",
                context=_validation_context(context),
            )
    evidence.reconcile(envelopes)


def _reconciled_evidence(project_root: Path, store: EventStore) -> EvidenceStore:
    evidence = EvidenceStore(_evidence_root(project_root))
    evidence.reconcile(_evidence_envelopes(evidence, store))
    return evidence


def _holder_authorization(
    authority: AuthorityEngine,
    lease: Mapping[str, Any],
    evaluation_time: str,
) -> dict[str, Any]:
    holder = authority.grants.get(lease["holder_grant_id"])
    if holder is None:
        raise ServiceError("Lease holder Grant is unresolved")
    requested_scope = [dict(value) for value in holder["scope"]]
    pairs = {(value["kind"], value["value"]) for value in requested_scope}
    task_effect = ("task", lease["task_id"])
    if ("all", "*") not in pairs and task_effect not in pairs:
        requested_scope.append({"kind": task_effect[0], "value": task_effect[1]})
    return {
        "subject_id": lease["holder_subject_id"],
        "grant_id": lease["holder_grant_id"],
        "claim_digest": holder["claim_digest"],
        "evaluated_at": evaluation_time,
        "requested_scope": requested_scope,
    }


def _apply_lease(
    domain: DomainState,
    authority: AuthorityEngine,
    lease: dict[str, Any],
    manager_authorization: dict[str, Any],
    evaluation_time: str,
    *,
    parallelism_policy: Mapping[str, Any] | None = None,
) -> None:
    state = lease["state"]
    current = domain.leases.get(lease["lease_id"])
    holder_authorization = _holder_authorization(
        authority,
        lease,
        evaluation_time,
    )
    if (
        current is not None
        and current == lease
        and "capacity_reconciliation" not in lease
    ):
        return
    if current is None:
        domain.acquire_lease(
            lease,
            manager_authorization,
            parallelism_policy=parallelism_policy,
        )
    elif "capacity_reconciliation" in lease:
        expected = dict(current)
        expected["capacity_reconciliation"] = lease["capacity_reconciliation"]
        if expected != lease:
            raise ServiceError("Lease reconciliation changes immutable lifecycle fields")
        domain.reconcile_lease_capacity(
            lease["lease_id"],
            lease["generation"],
            lease["fencing_token"],
            lease["capacity_reconciliation"],
            manager_authorization,
            runtime_policy=parallelism_policy,
        )
    elif state == "ACTIVE":
        domain.heartbeat_lease(
            lease["lease_id"],
            lease["generation"],
            lease["fencing_token"],
            lease["heartbeat_at"],
            lease["expires_at"],
            holder_authorization,
            runtime_policy=parallelism_policy,
        )
    elif state == "CLOSING":
        domain.begin_close_lease(
            lease["lease_id"],
            lease["generation"],
            lease["fencing_token"],
            holder_authorization,
            runtime_policy=parallelism_policy,
        )
    elif state == "CLOSED":
        domain.close_lease(
            lease["lease_id"],
            lease["generation"],
            lease["fencing_token"],
            lease["close_ack"],
            manager_authorization,
            runtime_policy=parallelism_policy,
        )
    elif state == "EXPIRED":
        domain.expire_lease(
            lease["lease_id"],
            lease["generation"],
            lease["fencing_token"],
            evaluation_time,
            manager_authorization,
            runtime_policy=parallelism_policy,
        )
    elif state == "REVOKED":
        termination = lease.get("termination")
        if not isinstance(termination, Mapping):
            raise ServiceError("REVOKED Lease lacks termination provenance")
        domain.revoke_lease(
            lease["lease_id"],
            lease["generation"],
            lease["fencing_token"],
            termination["terminated_at"],
            manager_authorization,
            runtime_policy=parallelism_policy,
        )
    else:
        raise ServiceError(f"unsupported Lease state: {state}")
    if domain.leases.get(lease["lease_id"]) != lease:
        raise ServiceError("Lease event differs from the validated lifecycle result")


def _command_from_envelope(envelope: object) -> dict[str, Any]:
    if isinstance(envelope, Mapping):
        for name in ("command", "primary_event", "payload"):
            value = envelope.get(name)
            if isinstance(value, dict) and value.get("record_type") == "CommandRequest":
                return value
        events = envelope.get("events")
        if isinstance(events, Sequence):
            commands = [value for value in events if isinstance(value, dict) and value.get("record_type") == "CommandRequest"]
            if len(commands) == 1:
                return commands[0]
    for name in ("command", "primary_event", "payload"):
        value = getattr(envelope, name, None)
        if isinstance(value, dict) and value.get("record_type") == "CommandRequest":
            return value
    raise ServiceError("event envelope lacks exactly one CommandRequest")


def _relations_from_envelope(envelope: object) -> list[dict[str, Any]]:
    if not isinstance(envelope, Mapping):
        raise ServiceError("event envelope is not an object")
    batch = envelope.get("batch")
    if not isinstance(batch, Mapping) or not isinstance(batch.get("events"), list):
        raise ServiceError("event envelope lacks a bounded EventBatch")
    relations: list[dict[str, Any]] = []
    for event in batch["events"]:
        if not isinstance(event, Mapping):
            raise ServiceError("event batch contains a non-object event")
        if event.get("event_kind") == "relation.recorded":
            payload = event.get("payload")
            if not isinstance(payload, dict) or payload.get("record_type") != "Relation":
                raise ServiceError("relation event payload is malformed")
            relations.append(dict(payload))
    return relations


def _validated_auxiliary_relations(
    bundle: ContractBundle,
    context: ActivationContext,
    command: Mapping[str, Any],
    values: Iterable[Mapping[str, Any]],
    *,
    operation: str = "import",
    domain: DomainState | None = None,
    current_relations: Sequence[Mapping[str, Any]] = (),
) -> tuple[dict[str, Any], ...]:
    if isinstance(values, (str, bytes, Mapping)):
        raise ServiceError("auxiliary Relations must be an array")
    relations = [dict(value) for value in values]
    if not relations:
        return ()
    if command.get("command_kind") != "task.record":
        raise ServiceError("auxiliary Relations require one Task primary command")
    task = command.get("payload")
    if not isinstance(task, Mapping) or task.get("record_type") != "Task":
        raise ServiceError("auxiliary Relations require a Task primary payload")
    activation_digest = _activation(context)["activation_digest"]
    task_id = task["task_id"]
    seen: set[str] = set()
    ordered = sorted(relations, key=lambda value: str(value.get("relation_id", "")))
    validation_context = _validation_context(context)
    if domain is not None:
        validation_context.update(
            {
                "current_tasks": list(domain.tasks.values()),
                "current_relations": [
                    *[dict(value) for value in current_relations],
                    *ordered,
                ],
                "current_gate_results": list(domain.gate_results.values()),
                "current_findings": list(domain.findings.values()),
            }
        )
    for relation in ordered:
        validate_ingress(
            bundle,
            relation,
            operation=operation,
            definition="Relation",
            context=validation_context,
        )
        relation_id = relation.get("relation_id")
        if relation_id in seen:
            raise ServiceError("auxiliary Relation IDs must be unique")
        seen.add(relation_id)
        if relation.get("activation_digest") != activation_digest:
            raise ServiceError("auxiliary Relation Activation is stale")
        if relation.get("source_type") != "Task" or relation.get("source_id") != task_id:
            raise ServiceError("auxiliary Relation is not effect-scoped to the primary Task")
    return tuple(ordered)


def _workcard_root(project_root: Path) -> Path:
    return _state_root(project_root) / "workcards"


def _persist_workcard(project_root: Path, workcard: Mapping[str, Any]) -> str:
    digest = digest_value(workcard)
    directory = _workcard_root(project_root)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{digest}.json"
    if path.exists():
        existing = load_json_strict(path, root=directory)
        if existing != dict(workcard):
            raise ServiceError("immutable WorkCard digest identifies different content")
    else:
        atomic_write_json(path, dict(workcard), mode=0o444)
    return digest


def _load_workcard(project_root: Path, digest: str) -> dict[str, Any]:
    directory = _workcard_root(project_root)
    path = directory / f"{digest}.json"
    if not path.is_file():
        raise ServiceError("mutation WorkCard is unresolved")
    value = load_json_strict(path, root=directory)
    if not isinstance(value, dict) or value.get("record_type") != "WorkCard":
        raise ServiceError("persisted mutation WorkCard is malformed")
    if digest_value(value) != digest:
        raise ServiceError("persisted mutation WorkCard digest mismatch")
    return value


def _profile_budget(preset: dict[str, Any], activation: dict[str, Any]) -> dict[str, int]:
    profile_name = activation["operating_profile"]
    profile = preset.get("profiles", {}).get(profile_name)
    if not isinstance(profile, dict):
        raise ServiceError("Activation selects an unknown preset profile")
    return {
        "max_bytes": profile["max_context_bytes"],
        "max_entities": profile["max_entities"],
        "max_relations": profile["max_relations"],
        "max_fanout_per_entity": profile["max_fanout_per_entity"],
        "top_k": profile["top_k"],
    }


def _projection_resume_binding(
    context: ActivationContext,
    access: Mapping[str, Any],
) -> dict[str, str]:
    return {
        "activation_digest": _activation(context)["activation_digest"],
        "capability_id": access["capability_id"],
        "grant_claim_digest": access["grant_claim_digest"],
        "grant_id": access["grant_id"],
        "implementation_closure_digest": _implementation_closure_digest(context),
        "requested_scope_digest": digest_value(access["requested_scope"]),
        "revocation_epoch": access["revocation_epoch"],
        "subject_id": access["subject_id"],
    }


def _evaluation_time(value: datetime | None) -> str:
    selected = value or datetime.now(timezone.utc).replace(microsecond=0)
    try:
        return format_utc_second(selected)
    except ValueError as exc:
        raise ServiceError(
            "runtime time override must be an exact timezone-aware UTC second"
        ) from exc


def _profile_depth(
    preset: Mapping[str, Any],
    activation: Mapping[str, Any],
    conformance: Mapping[str, Any],
    requested: int | None,
) -> int:
    profile_name = activation["operating_profile"]
    profile = preset.get("profiles", {}).get(profile_name)
    if not isinstance(profile, Mapping):
        raise ServiceError("Activation selects an unknown preset profile")
    selected = profile.get("default_dependency_depth") if requested is None else requested
    hard_max = conformance.get("dependency_depth_hard_max")
    if (
        not isinstance(selected, int)
        or isinstance(selected, bool)
        or not isinstance(hard_max, int)
        or isinstance(hard_max, bool)
        or selected < 1
        or selected > hard_max
    ):
        raise ServiceError("dependency depth must be within the Core hard ceiling")
    return selected


def _validation_context(context: ActivationContext) -> dict[str, Any]:
    activation = _activation(context)
    recipe = compile_candidate_recipe(_project_init(context)["candidate_recipe"])
    return {
        "activation_digest": activation["activation_digest"],
        "operating_profile": activation["operating_profile"],
        "project_root": context.project_root,
        "authority_init": _authority_init(context),
        "candidate_recipe_digest": recipe.digest,
        "candidate_consistency_mode": recipe.consistency_mode,
        "snapshot_provider_id": recipe.snapshot_provider_id,
        "provider_binding_digest": _provider_binding_digest(context),
        "implementation_closure_digest": _implementation_closure_digest(context),
    }


def _provider_binding_digest(context: ActivationContext) -> str:
    return digest_value(list(context.provider_dispatch.binding_evidence()))


def _inventory_root(project_root: Path) -> Path:
    return _state_root(project_root) / "inventory"


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)


def _read_open_descriptor(descriptor: int, relative: str) -> bytes:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise ServiceError(f"inventory source is not a regular file: {relative}")
    chunks: list[bytes] = []
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    after = os.fstat(descriptor)
    if _stat_identity(before) != _stat_identity(after):
        raise ServiceError(f"inventory source changed during descriptor read: {relative}")
    return b"".join(chunks)


def _read_regular_nofollow(project_root: Path, relative: str) -> bytes:
    parts = tuple(relative.split("/"))
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise ServiceError("inventory source path is not canonical")
    if os.name == "nt":
        return _read_regular_nofollow_windows(project_root, parts, relative)

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    current = os.open(project_root, directory_flags)
    try:
        for component in parts[:-1]:
            following = os.open(component, directory_flags, dir_fd=current)
            os.close(current)
            current = following
        descriptor = os.open(parts[-1], os.O_RDONLY | nofollow, dir_fd=current)
        try:
            return _read_open_descriptor(descriptor, relative)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ServiceError(f"inventory no-follow read failed: {relative}: {exc}") from exc
    finally:
        try:
            os.close(current)
        except OSError:
            pass


def _read_regular_nofollow_windows(
    project_root: Path,
    parts: Sequence[str],
    relative: str,
) -> bytes:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class FileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation_low", wintypes.DWORD),
            ("creation_high", wintypes.DWORD),
            ("access_low", wintypes.DWORD),
            ("access_high", wintypes.DWORD),
            ("write_low", wintypes.DWORD),
            ("write_high", wintypes.DWORD),
            ("volume_serial", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("index_high", wintypes.DWORD),
            ("index_low", wintypes.DWORD),
        ]

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
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(FileInformation)]
    get_information.restype = wintypes.BOOL
    final_name = kernel32.GetFinalPathNameByHandleW
    final_name.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    final_name.restype = wintypes.DWORD
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    path = project_root.joinpath(*parts)
    handle = create_file(
        str(path),
        0x80000000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x00200000 | 0x02000000 | 0x08000000,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        raise ServiceError(
            f"inventory no-follow open failed: {relative}: winerror={ctypes.get_last_error()}"
        )
    transferred = False
    try:
        information = FileInformation()
        if not get_information(handle, ctypes.byref(information)):
            raise ServiceError(
                f"inventory descriptor inspection failed: {relative}: "
                f"winerror={ctypes.get_last_error()}"
            )
        if information.attributes & (0x00000400 | 0x00000010):
            raise ServiceError(f"inventory source is a reparse point or directory: {relative}")

        length = final_name(handle, None, 0, 0)
        if not length:
            raise ServiceError(
                f"inventory final-path inspection failed: {relative}: "
                f"winerror={ctypes.get_last_error()}"
            )
        buffer = ctypes.create_unicode_buffer(length + 1)
        if not final_name(handle, buffer, len(buffer), 0):
            raise ServiceError(f"inventory final-path resolution failed: {relative}")
        actual = buffer.value
        if actual.startswith("\\\\?\\UNC\\"):
            actual = "\\\\" + actual[8:]
        elif actual.startswith("\\\\?\\"):
            actual = actual[4:]
        expected = os.path.abspath(str(path))
        if os.path.normcase(os.path.normpath(actual)) != os.path.normcase(
            os.path.normpath(expected)
        ):
            raise ServiceError(f"inventory path traversed a reparse boundary: {relative}")

        descriptor = msvcrt.open_osfhandle(
            int(handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
        )
        transferred = True
        try:
            return _read_open_descriptor(descriptor, relative)
        finally:
            os.close(descriptor)
    finally:
        if not transferred:
            close_handle(handle)


def _is_link_like(value: os.stat_result) -> bool:
    attributes = getattr(value, "st_file_attributes", 0)
    return stat.S_ISLNK(value.st_mode) or bool(attributes & 0x00000400)


def _link_metadata(path: Path, relative: str) -> bytes:
    before = path.lstat()
    if not _is_link_like(before):
        raise ServiceError(f"inventory expected a symbolic link: {relative}")
    try:
        target = os.readlink(path)
    except OSError as exc:
        raise ServiceError(f"inventory link metadata read failed: {relative}: {exc}") from exc
    after = path.lstat()
    if _stat_identity(before) != _stat_identity(after):
        raise ServiceError(f"inventory link changed during metadata read: {relative}")
    return canonical_bytes({"record_type": "SymbolicLinkMetadata", "target": target})


def _bounded_search_text(payload: bytes) -> str:
    sample = payload[: _INVENTORY_SEARCH_TEXT_MAX_BYTES * 4]
    decoded = sample.decode("utf-8", errors="ignore")
    normalized = " ".join(
        "".join(character if character.isprintable() or character.isspace() else " " for character in decoded).split()
    )
    encoded = normalized.encode("utf-8")[:_INVENTORY_SEARCH_TEXT_MAX_BYTES]
    return encoded.decode("utf-8", errors="ignore")


def _raw_entry(relative: str, payload: bytes) -> dict[str, Any]:
    return {
        "path": relative,
        "digest": hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
        "search_text": _bounded_search_text(payload),
    }


def _observed_inventory(
    project_root: Path,
    requested: Sequence[str],
    recipe: Any,
) -> Iterator[dict[str, Any]]:
    collision_index: dict[str, str] = {}
    for relative_root in requested:
        base = project_root.joinpath(*relative_root.split("/"))
        try:
            base_state = base.lstat()
        except OSError as exc:
            raise ServiceError(f"inventory root is unavailable: {relative_root}: {exc}") from exc
        if _is_link_like(base_state) or not stat.S_ISDIR(base_state.st_mode):
            raise ServiceError("inventory root is missing, not a directory, or a link")
        for current, directory_names, file_names in os.walk(base, topdown=True, followlinks=False):
            current_path = Path(current)
            kept_directories: list[str] = []
            for name in sorted(directory_names):
                child = current_path / name
                relative = child.relative_to(project_root).as_posix()
                state = child.lstat()
                is_link = _is_link_like(state)
                selected = recipe.select(relative, collision_index, is_symlink=is_link)
                if is_link:
                    if selected is not None:
                        yield _raw_entry(selected, _link_metadata(child, selected))
                    continue
                if relative != ".promin" and not relative.startswith(".promin/"):
                    kept_directories.append(name)
            directory_names[:] = kept_directories
            for name in sorted(file_names):
                path = current_path / name
                relative = path.relative_to(project_root).as_posix()
                state = path.lstat()
                is_link = _is_link_like(state)
                selected = recipe.select(relative, collision_index, is_symlink=is_link)
                if selected is None:
                    continue
                payload = (
                    _link_metadata(path, selected)
                    if is_link
                    else _read_regular_nofollow(project_root, selected)
                )
                yield _raw_entry(selected, payload)


class _BoundedDigestReader:
    """Hash one provider stream while retaining only its bounded diagnostic prefix."""

    def __init__(self, source: Any, *, size_ceiling: int, capture_ceiling: int) -> None:
        self._source = source
        self._size_ceiling = size_ceiling
        self._capture_ceiling = capture_ceiling
        self._digest = hashlib.sha256()
        self._capture = bytearray()
        self.size = 0

    @property
    def digest(self) -> str:
        return self._digest.hexdigest()

    @property
    def capture(self) -> bytes:
        return bytes(self._capture)

    @property
    def capture_truncated(self) -> bool:
        return self.size > len(self._capture)

    def read(self, size: int = -1) -> bytes:
        chunk = self._source.read(size)
        if not chunk:
            return b""
        self.size += len(chunk)
        if self.size > self._size_ceiling:
            raise ServiceError("snapshot provider stream exceeds its selected Core ceiling")
        self._digest.update(chunk)
        remaining = self._capture_ceiling - len(self._capture)
        if remaining > 0:
            self._capture.extend(chunk[:remaining])
        return chunk


def _path_is_within_roots(path: str, roots: Sequence[str]) -> bool:
    return any(path == root or path.startswith(root + "/") for root in roots)


def _vcs_inventory(
    project_root: Path,
    requested: Sequence[str],
    recipe: Any,
    descriptor: Mapping[str, Any],
    context: ActivationContext,
) -> tuple[Iterator[dict[str, Any]], str, list[dict[str, Any]]]:
    required_fields = {"consistency_mode", "provider_id", "repository", "treeish"}
    if set(descriptor) != required_fields:
        raise ServiceError("immutable VCS snapshot descriptor fields are not exact")
    if (
        descriptor.get("consistency_mode") != "immutable-vcs-tree"
        or descriptor.get("consistency_mode") != recipe.consistency_mode
        or descriptor.get("provider_id") != recipe.snapshot_provider_id
    ):
        raise ServiceError("snapshot descriptor differs from the active Candidate recipe")
    repository_value = descriptor.get("repository")
    treeish = descriptor.get("treeish")
    if not isinstance(repository_value, str) or not isinstance(treeish, str):
        raise ServiceError("snapshot repository and treeish must be strings")
    if not re.fullmatch(r"[0-9A-Za-z._/@{}^~:+-]{1,256}", treeish):
        raise ServiceError("snapshot treeish is not bounded canonical syntax")
    repository = Path(repository_value).resolve(strict=True)
    if repository != project_root:
        raise ServiceError("snapshot repository must be the initialized project root")

    dispatch = context.provider_dispatch
    adapter = dispatch.adapter("filesystem-inventory")
    if adapter.provider_id != recipe.snapshot_provider_id or not adapter.reconstructable:
        raise ServiceError("snapshot provider adapter is stale or not reconstructable")
    if treeish != "HEAD":
        raise ServiceError("Core filesystem inventory protocol accepts only the exact HEAD tree")
    tree_object, tree_evidence = dispatch.invoke_tree_object(
        {"repository": str(repository)}
    )
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", tree_object):
        raise ServiceError("snapshot provider returned an invalid VCS tree identity")

    provider_invocations = [tree_evidence]
    snapshot_digest = digest_value(
        {
            "provider_invocation": tree_evidence,
            "repository_tree_object": tree_object,
            "candidate_recipe_digest": recipe.digest,
            "source_roots": list(requested),
        }
    )
    output_ceiling = dispatch.full_output_bytes_hard_max
    capture_ceiling = dispatch.diagnostic_capture_bytes_max
    plan = dispatch.prepare_invocation(
        "filesystem-inventory",
        "immutable-tree-stream",
        {"repository": str(repository), "tree_object": tree_object},
        output_size_ceiling_bytes=output_ceiling,
    )
    request_receipt = dispatch.invocation_request_receipt(plan)
    if digest_value(request_receipt) != plan.invocation_request_digest:
        raise ServiceError("snapshot provider request receipt is stale")

    def rows() -> Iterator[dict[str, Any]]:
        collision_index: dict[str, str] = {}
        with tempfile.TemporaryFile() as errors:
            started_at = _utc_second_text()
            try:
                process = subprocess.Popen(
                    list(plan.argv),
                    cwd=plan.cwd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=errors,
                    shell=False,
                    env=plan.env,
                )
            except OSError as exc:
                raise ServiceError(f"snapshot archive provider failed to start: {exc}") from exc
            assert process.stdout is not None
            stream = _BoundedDigestReader(
                process.stdout,
                size_ceiling=plan.output_size_ceiling_bytes,
                capture_ceiling=capture_ceiling,
            )
            try:
                with tarfile.open(fileobj=stream, mode="r|*") as archive:
                    for member in archive:
                        name = member.name.rstrip("/")
                        if not name:
                            continue
                        if not _path_is_within_roots(name, requested):
                            continue
                        is_link = member.issym()
                        selected = recipe.select(name, collision_index, is_symlink=is_link)
                        if member.isdir() or selected is None:
                            continue
                        if is_link:
                            payload = canonical_bytes(
                                {"record_type": "SymbolicLinkMetadata", "target": member.linkname}
                            )
                            yield _raw_entry(selected, payload)
                            continue
                        if not member.isreg():
                            raise ServiceError(
                                f"snapshot archive contains unsupported entry type: {selected}"
                            )
                        source = archive.extractfile(member)
                        if source is None:
                            raise ServiceError(f"snapshot archive member is unreadable: {selected}")
                        digest = hashlib.sha256()
                        size = 0
                        sample = bytearray()
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            digest.update(chunk)
                            size += len(chunk)
                            remaining = _INVENTORY_SEARCH_TEXT_MAX_BYTES * 4 - len(sample)
                            if remaining > 0:
                                sample.extend(chunk[:remaining])
                        if size != member.size:
                            raise ServiceError(f"snapshot archive member size changed: {selected}")
                        yield {
                            "path": selected,
                            "digest": digest.hexdigest(),
                            "size": size,
                            "search_text": _bounded_search_text(bytes(sample)),
                        }
                while stream.read(1024 * 1024):
                    pass
            except (tarfile.TarError, OSError, ServiceError) as exc:
                process.kill()
                process.wait()
                raise ServiceError(f"snapshot archive is invalid: {exc}") from exc
            finally:
                process.stdout.close()
            try:
                return_code = process.wait(timeout=300)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait()
                raise ServiceError("snapshot archive provider timed out") from exc
            if return_code != 0:
                errors.seek(0)
                detail = errors.read(4096).decode("utf-8", errors="replace").strip()
                raise ServiceError(
                    f"snapshot archive provider rejected the tree: exit={return_code}: {detail}"
                )
            completed_at = _utc_second_text()
            errors.seek(0)
            stderr_capture = errors.read(capture_ceiling + 1)
            stderr_truncated = len(stderr_capture) > capture_ceiling
            stderr_capture = stderr_capture[:capture_ceiling]
            provider_invocations.append(
                dispatch.complete_streamed_invocation_evidence(
                    plan,
                    started_at=started_at,
                    completed_at=completed_at,
                    outcome="success",
                    exit_code=return_code,
                    output_digest=stream.digest,
                    output_size_bytes=stream.size,
                    stdout_capture_digest=hashlib.sha256(stream.capture).hexdigest(),
                    stdout_capture_size_bytes=len(stream.capture),
                    stdout_capture_truncated=stream.capture_truncated,
                    stderr_capture_digest=hashlib.sha256(stderr_capture).hexdigest(),
                    stderr_capture_size_bytes=len(stderr_capture),
                    stderr_capture_truncated=stderr_truncated,
                )
            )

    return rows(), snapshot_digest, provider_invocations


def _validate_raw_inventory_row(row: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(row, Mapping) or set(row) != {"path", "digest", "size", "search_text"}:
        raise ServiceError("raw inventory row fields are not exact")
    path = row.get("path")
    digest = row.get("digest")
    size = row.get("size")
    search_text = row.get("search_text")
    if (
        not isinstance(path, str)
        or not path
        or path.startswith("/")
        or "\\" in path
        or "\x00" in path
        or any(part in {"", ".", ".."} for part in path.split("/"))
        or len(path.encode("utf-8")) > 4096
    ):
        raise ServiceError("raw inventory path is not normalized relative POSIX text")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ServiceError("raw inventory digest is not SHA-256")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ServiceError("raw inventory size is invalid")
    if (
        not isinstance(search_text, str)
        or "\x00" in search_text
        or len(search_text.encode("utf-8")) > _INVENTORY_SEARCH_TEXT_MAX_BYTES
    ):
        raise ServiceError("raw inventory search text exceeds its bound")
    return dict(row)


def _stage_inventory_stream(
    project_root: Path,
    raw_entries: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """External-sort rows and write one canonical immutable JSONL candidate stream."""

    directory = _inventory_root(project_root)
    directory.mkdir(parents=True, exist_ok=True)
    sorter_fd, sorter_name = tempfile.mkstemp(
        prefix=".inventory-sort-", suffix=".sqlite3", dir=directory
    )
    os.close(sorter_fd)
    stream_fd, stream_name = tempfile.mkstemp(
        prefix=".inventory-stream-", suffix=".tmp", dir=directory
    )
    os.close(stream_fd)
    sorter_path = Path(sorter_name)
    stream_path = Path(stream_name)
    try:
        connection = sqlite3.connect(sorter_path)
        try:
            connection.execute("PRAGMA journal_mode=OFF")
            connection.execute("PRAGMA synchronous=OFF")
            connection.execute(
                "CREATE TABLE rows(path TEXT PRIMARY KEY,digest TEXT NOT NULL,size INTEGER NOT NULL,row BLOB NOT NULL)"
            )
            for raw in raw_entries:
                row = _validate_raw_inventory_row(raw)
                encoded = canonical_bytes(row)
                if len(encoded) > _INVENTORY_JSONL_ROW_MAX_BYTES:
                    raise ServiceError("raw inventory JSONL row exceeds 16384 bytes")
                try:
                    connection.execute(
                        "INSERT INTO rows(path,digest,size,row) VALUES (?,?,?,?)",
                        (row["path"], row["digest"], row["size"], encoded),
                    )
                except sqlite3.IntegrityError as exc:
                    raise ServiceError("raw inventory contains a duplicate normalized path") from exc
            connection.commit()
            identity_digest = hashlib.sha256()
            stream_digest = hashlib.sha256()
            entry_count = 0
            stream_bytes = 0
            with stream_path.open("wb") as target:
                for path, digest, size, encoded in connection.execute(
                    "SELECT path,digest,size,row FROM rows ORDER BY path"
                ):
                    line = bytes(encoded)
                    identity_digest.update(
                        canonical_bytes({"path": path, "digest": digest, "size": size})
                    )
                    stream_digest.update(line)
                    target.write(line)
                    entry_count += 1
                    stream_bytes += len(line)
                target.flush()
                os.fsync(target.fileno())
        finally:
            connection.close()
        return {
            "path": stream_path,
            "inventory_digest": identity_digest.hexdigest(),
            "stream_digest": stream_digest.hexdigest(),
            "entry_count": entry_count,
            "stream_bytes": stream_bytes,
        }
    except Exception:
        stream_path.unlink(missing_ok=True)
        raise
    finally:
        sorter_path.unlink(missing_ok=True)


def _persist_inventory(
    project_root: Path,
    candidate: Mapping[str, Any],
    staged: Mapping[str, Any],
    activation_digest: str,
    provider_invocations: Sequence[Mapping[str, Any]],
) -> str:
    directory = _inventory_root(project_root)
    staged_path = staged.get("path")
    if not isinstance(staged_path, Path) or not staged_path.is_file():
        raise ServiceError("staged inventory stream is unavailable")
    if staged.get("inventory_digest") != candidate["inventory_digest"]:
        raise ServiceError("inventory identity digest disagrees with Candidate")
    stream_digest = staged.get("stream_digest")
    stream_bytes = staged.get("stream_bytes")
    entry_count = staged.get("entry_count")
    if (
        not isinstance(stream_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", stream_digest)
        or not isinstance(stream_bytes, int)
        or not isinstance(entry_count, int)
    ):
        raise ServiceError("staged inventory stream descriptor is malformed")
    stream_path = directory / f"{stream_digest}.jsonl"
    if stream_path.exists():
        actual = hashlib.sha256()
        actual_bytes = 0
        with stream_path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                actual.update(chunk)
                actual_bytes += len(chunk)
        if actual.hexdigest() != stream_digest or actual_bytes != stream_bytes:
            raise ServiceError("immutable inventory stream digest identifies different bytes")
        staged_path.unlink()
    else:
        staged_path.chmod(0o444)
        if os.name == "nt":
            import ctypes

            if not ctypes.windll.kernel32.MoveFileExW(
                str(staged_path), str(stream_path), 0x1 | 0x8
            ):
                raise ServiceError(
                    f"inventory stream publication failed: winerror={ctypes.get_last_error()}"
                )
        else:
            os.replace(staged_path, stream_path)
            descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    observed_at = _utc_second_text()
    metadata: dict[str, Any] = {
        "record_type": "InventoryInputManifest",
        "activation_digest": activation_digest,
        "candidate": dict(candidate),
        "inventory_digest": candidate["inventory_digest"],
        "stream_digest": stream_digest,
        "stream_bytes": stream_bytes,
        "entry_count": entry_count,
        "product_tree_passes": 1,
        "observed_at": observed_at,
        "provider_invocations": [dict(value) for value in provider_invocations],
    }
    metadata_path = directory / f"{candidate['candidate_digest']}.json"
    if metadata_path.exists():
        existing = load_json_strict(metadata_path, root=directory)
        if not isinstance(existing, dict) or set(existing) != set(metadata):
            raise ServiceError("Candidate inventory metadata is malformed")
        existing_identity = {key: value for key, value in existing.items() if key != "observed_at"}
        metadata_identity = {key: value for key, value in metadata.items() if key != "observed_at"}
        if existing_identity != metadata_identity:
            raise ServiceError("Candidate inventory metadata is immutable")
        metadata = existing
        observed_at = existing["observed_at"]
    else:
        atomic_write_json(metadata_path, metadata, mode=0o444)
    manifest_digest = digest_value(metadata)
    atomic_write_json(
        directory / "current.json",
        {
            "record_type": "CurrentInventory",
            "activation_digest": activation_digest,
            "candidate_digest": candidate["candidate_digest"],
            "stream_digest": stream_digest,
            "manifest_digest": manifest_digest,
        },
    )
    return observed_at


def _iter_verified_inventory_stream(
    path: Path,
    *,
    expected_stream_digest: str,
    expected_inventory_digest: str,
    expected_entry_count: int,
    expected_stream_bytes: int,
) -> Iterator[dict[str, Any]]:
    try:
        state = path.lstat()
    except OSError as exc:
        raise ServiceError("persisted inventory stream is unavailable") from exc
    if path.is_symlink() or not stat.S_ISREG(state.st_mode) or state.st_size != expected_stream_bytes:
        raise ServiceError("persisted inventory stream file binding is stale")
    stream_digest = hashlib.sha256()
    inventory_digest = hashlib.sha256()
    entry_count = 0
    stream_bytes = 0
    previous_path: str | None = None
    with path.open("rb") as source:
        while True:
            line = source.readline(_INVENTORY_JSONL_ROW_MAX_BYTES + 1)
            if not line:
                break
            if len(line) > _INVENTORY_JSONL_ROW_MAX_BYTES or not line.endswith(b"\n"):
                raise ServiceError("persisted inventory JSONL row exceeds its bound or lacks newline")
            value = parse_json_strict(line)
            if not isinstance(value, dict) or canonical_bytes(value) != line:
                raise ServiceError("persisted inventory JSONL row is noncanonical")
            row = _validate_raw_inventory_row(value)
            if previous_path is not None and row["path"] <= previous_path:
                raise ServiceError("persisted inventory paths are not strictly sorted and unique")
            previous_path = row["path"]
            stream_digest.update(line)
            inventory_digest.update(
                canonical_bytes(
                    {"path": row["path"], "digest": row["digest"], "size": row["size"]}
                )
            )
            entry_count += 1
            stream_bytes += len(line)
            yield row
    if (
        stream_digest.hexdigest() != expected_stream_digest
        or inventory_digest.hexdigest() != expected_inventory_digest
        or entry_count != expected_entry_count
        or stream_bytes != expected_stream_bytes
    ):
        raise ServiceError("persisted inventory rolling digest, count, or byte binding mismatch")


def _load_current_inventory(
    project_root: Path,
    context: ActivationContext,
) -> InventoryResult | None:
    directory = _inventory_root(project_root)
    pointer_path = directory / "current.json"
    if not pointer_path.exists():
        return None
    pointer = load_json_strict(pointer_path, root=directory)
    if not isinstance(pointer, dict) or set(pointer) != {
        "record_type",
        "activation_digest",
        "candidate_digest",
        "stream_digest",
        "manifest_digest",
    } or pointer["record_type"] != "CurrentInventory":
        raise ServiceError("current inventory pointer is malformed")
    metadata = load_json_strict(
        directory / f"{pointer['candidate_digest']}.json",
        root=directory,
    )
    if not isinstance(metadata, dict) or metadata.get("record_type") != "InventoryInputManifest":
        raise ServiceError("persisted inventory metadata is malformed")
    if (
        metadata.get("stream_digest") != pointer["stream_digest"]
        or metadata.get("activation_digest") != _activation(context)["activation_digest"]
        or pointer.get("activation_digest") != _activation(context)["activation_digest"]
        or metadata.get("inventory_digest") != metadata.get("candidate", {}).get("inventory_digest")
        or metadata.get("candidate", {}).get("candidate_digest") != pointer["candidate_digest"]
        or metadata.get("product_tree_passes") != 1
        or not isinstance(metadata.get("observed_at"), str)
        or not isinstance(metadata.get("provider_invocations"), list)
        or not isinstance(metadata.get("stream_bytes"), int)
        or not isinstance(metadata.get("entry_count"), int)
        or digest_value(metadata) != pointer.get("manifest_digest")
    ):
        raise ServiceError("persisted inventory bindings disagree")
    stream_path = directory / f"{pointer['stream_digest']}.jsonl"
    candidate = metadata["candidate"]
    validate_candidate_consistency(candidate)
    validate_ingress(
        _bundle(context),
        candidate,
        operation="rebuild",
        definition="Candidate",
        context=_validation_context(context),
    )
    observed_at = metadata["observed_at"]
    for _ in _iter_verified_inventory_stream(
        stream_path,
        expected_stream_digest=metadata["stream_digest"],
        expected_inventory_digest=metadata["inventory_digest"],
        expected_entry_count=metadata["entry_count"],
        expected_stream_bytes=metadata["stream_bytes"],
    ):
        pass
    entries = _InventoryStreamRows(
        path=stream_path.resolve(strict=True),
        stream_digest=metadata["stream_digest"],
        inventory_digest=metadata["inventory_digest"],
        entry_count=metadata["entry_count"],
        stream_bytes=metadata["stream_bytes"],
        observed_at=observed_at,
    )
    return InventoryResult(
        candidate=dict(candidate),
        entries=entries,
        observed_at=observed_at,
        provider_invocations=tuple(dict(value) for value in metadata["provider_invocations"]),
        stream_path=stream_path.resolve(strict=True),
        stream_digest=metadata["stream_digest"],
        stream_bytes=metadata["stream_bytes"],
        manifest_digest=pointer["manifest_digest"],
    )


def _verify_inventory_result(
    supplied: InventoryResult,
    persisted: InventoryResult | None,
) -> InventoryResult:
    if persisted is None:
        raise ServiceError("verified inventory manifest is unavailable")
    if supplied.product_tree_passes != 1:
        raise ServiceError("InventoryResult product-tree pass count is invalid")
    if (
        not isinstance(supplied.entries, _InventoryStreamRows)
        or
        supplied.candidate != persisted.candidate
        or supplied.observed_at != persisted.observed_at
        or supplied.provider_invocations != persisted.provider_invocations
        or supplied.stream_path != persisted.stream_path
        or supplied.stream_digest != persisted.stream_digest
        or supplied.stream_bytes != persisted.stream_bytes
        or supplied.manifest_digest != persisted.manifest_digest
        or supplied.entries != persisted.entries
    ):
        raise ServiceError("InventoryResult differs from the verified persisted manifest")
    return persisted


def _projection_entry(raw: Mapping[str, Any], observed_at: str) -> dict[str, Any]:
    relative = raw["path"]
    file_digest = raw["digest"]
    size = raw["size"]
    artifact_id = "artifact:file:" + hashlib.sha256(relative.encode("utf-8")).hexdigest()[:48]
    artifact = {
        "record_type": "Artifact",
        "artifact_id": artifact_id,
        "artifact_kind": "product",
        "digest": file_digest,
        "media_type": "application/octet-stream",
        "size_bytes": size,
        "retention_class": "project",
        "created_at": observed_at,
    }
    return {
        "record_type": "InventoryProjectionRow",
        "path": relative,
        "digest": file_digest,
        "size": size,
        "semantic_proxy": {
            "id": artifact_id,
            "entity_type": "Artifact",
            "payload": artifact,
        },
    }


def _validate_search_result(
    result: dict[str, Any],
    budget: Mapping[str, int],
    head: Mapping[str, Any],
    activation: Mapping[str, Any],
    now: datetime | None,
    *,
    max_token_bytes: int,
) -> None:
    if result.get("activation_digest") != activation["activation_digest"]:
        raise ServiceError("search result Activation is stale")
    if result.get("head_digest") != head["batch_digest"]:
        raise ServiceError("search result HEAD is stale")
    if len(result.get("entities", ())) > budget["max_entities"]:
        raise ServiceError("search entity budget exceeded")
    if len(result.get("relations", ())) > budget["max_relations"]:
        raise ServiceError("search relation budget exceeded")
    if len(canonical_bytes(result)) > budget["max_bytes"]:
        raise ServiceError("search byte budget exceeded")
    continuation = result.get("continuation")
    token = continuation.get("token") if isinstance(continuation, Mapping) else None
    if result.get("truncated") is True and not token:
        raise ServiceError("truncated search result lacks continuation")
    if token:
        token_bytes = len(token.encode("ascii"))
        if token_bytes > max_token_bytes:
            raise ServiceError("continuation token exceeds its Core limit")
        if token_bytes * 10 > budget["max_bytes"]:
            raise ServiceError("continuation token exceeds ten percent of the context budget")
    if result.get("refinement_required") is True:
        hints = result.get("refinement_hints")
        if not isinstance(hints, list) or not hints or len(hints) > 8:
            raise ServiceError("broad search lacks bounded refinement hints")
        if result.get("unselected_matches_traversable") is not False:
            raise ServiceError("broad search exposes unselected corpus traversal")
    if result.get("selected_closure_complete") is not (result.get("truncated") is not True):
        raise ServiceError("selected closure completion marker disagrees with pagination")
    if result.get("silent_truncation") is not False:
        raise ServiceError("search result permits silent truncation")
    expires_at = continuation.get("expiry") if isinstance(continuation, Mapping) else None
    if token and expires_at:
        instant = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        if instant <= (now or datetime.now(timezone.utc)):
            raise ServiceError("continuation is already expired")


def _time_text(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ServiceError("runtime time override must be timezone-aware UTC")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _utc_second_text() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def inventory_candidate(
    project_root: Path | str,
    source_roots: Sequence[str],
    *,
    snapshot_descriptor: Mapping[str, Any] | None = None,
) -> InventoryResult:
    root = Path(project_root).resolve()
    context = ActivationGuard(root).verify()
    activation = _activation(context)
    bundle = _bundle(context)
    project = _project_init(context)
    recipe = compile_candidate_recipe(project["candidate_recipe"])
    configured = {item["path"] for item in project["roots"]}
    requested = tuple(sorted(set(source_roots)))
    if not requested or any(value not in configured for value in requested):
        raise ServiceError("inventory roots must be an explicit subset of ProjectInit roots")
    if recipe.consistency_mode == "observational-best-effort":
        if snapshot_descriptor is not None:
            raise ServiceError("observational inventory cannot claim a snapshot descriptor")
        raw_entries = _observed_inventory(root, requested, recipe)
        snapshot_digest = None
        provider_invocations: tuple[dict[str, Any], ...] = ()
    elif recipe.consistency_mode == "immutable-vcs-tree":
        if snapshot_descriptor is None:
            raise ServiceError("immutable VCS inventory requires an explicit snapshot descriptor")
        raw_entries, snapshot_digest, provider_invocations = _vcs_inventory(
            root,
            requested,
            recipe,
            snapshot_descriptor,
            context,
        )
    else:
        raise ServiceError(
            "immutable filesystem inventory requires a provider protocol not configured by this package"
        )

    staged = _stage_inventory_stream(root, raw_entries)
    inventory_digest = staged["inventory_digest"]
    product_root_digest = digest_value(
        {
            "inventory_digest": inventory_digest,
            "candidate_recipe_digest": recipe.digest,
            "consistency_mode": recipe.consistency_mode,
            "snapshot_digest": snapshot_digest,
        }
    )
    candidate_identity = {
        "inventory_digest": inventory_digest,
        "product_root_digest": product_root_digest,
        "activation_digest": activation["activation_digest"],
        "entry_count": staged["entry_count"],
        "candidate_recipe_digest": recipe.digest,
        "consistency_mode": recipe.consistency_mode,
        "creditable": recipe.creditable,
        "snapshot_provider_id": recipe.snapshot_provider_id,
        "snapshot_digest": snapshot_digest,
    }
    candidate = {
        "record_type": "Candidate",
        "candidate_id": "candidate:" + digest_value(candidate_identity)[:24],
        "candidate_digest": digest_value(candidate_identity),
        "inventory_digest": inventory_digest,
        "product_root_digest": product_root_digest,
        "control_excluded": True,
        "candidate_recipe_digest": recipe.digest,
        "consistency_mode": recipe.consistency_mode,
        "creditable": recipe.creditable,
    }
    if recipe.creditable:
        candidate["snapshot_provider_id"] = recipe.snapshot_provider_id
        candidate["snapshot_digest"] = snapshot_digest
    try:
        validate_candidate_consistency(candidate)
        ingress_context = _validation_context(context)
        validate_ingress(
            bundle,
            candidate,
            operation="import",
            definition="Candidate",
            context=ingress_context,
        )
        observed_at = _persist_inventory(
            root,
            candidate,
            staged,
            activation["activation_digest"],
            provider_invocations,
        )
    except Exception:
        staged_path = staged.get("path")
        if isinstance(staged_path, Path):
            try:
                staged_path.chmod(0o600)
                staged_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    persisted = _load_current_inventory(root, context)
    if persisted is None or persisted.observed_at != observed_at:
        raise ServiceError("new inventory could not be verified from persisted state")
    return persisted


def load_plan(path: Path) -> dict[str, Any]:
    value = load_json_strict(path)
    if not isinstance(value, dict):
        raise ServiceError(f"plan is not a JSON object: {path}")
    return value


def doctor(project_root: Path | str, *, replay: bool = True) -> dict[str, Any]:
    return ProminService(project_root).doctor(replay=replay)


def status(project_root: Path | str) -> dict[str, Any]:
    return ProminService(project_root).status()


def validate_workspace(project_root: Path | str, *, replay: bool = True) -> dict[str, Any]:
    return ProminService(project_root).validate(replay=replay)


def commit_command(
    project_root: Path | str,
    command: dict[str, Any],
    authorization: dict[str, Any] | None = None,
    *,
    workcard: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if authorization is not None:
        if "authorization" in command and command["authorization"] != authorization:
            raise ServiceError("separate authorization conflicts with CommandRequest authorization")
        command = dict(command)
        command["authorization"] = authorization
    if command.get("record_type") != "CommandRequest":
        raise ServiceError("only strict CommandRequest ingress is accepted")
    return ProminService(project_root).commit(command, workcard=workcard)


def rebuild_projection(
    project_root: Path | str,
    inventory: InventoryResult | None = None,
) -> dict[str, Any]:
    return ProminService(project_root).rebuild(inventory)


def search(
    project_root: Path | str,
    query: str,
    depth: int | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    return ProminService(project_root).search(query, depth, **kwargs)


def next_work(
    project_root: Path | str,
    *,
    subject_id: str,
    grant_id: str,
    query_grant_id: str,
    depth: int | None = None,
) -> dict[str, Any]:
    return ProminService(project_root).next(
        subject_id=subject_id,
        grant_id=grant_id,
        query_grant_id=query_grant_id,
        depth=depth,
    )


def continue_work(
    project_root: Path | str,
    token: str,
    *,
    subject_id: str,
    grant_id: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    return ProminService(project_root).continue_search(
        token,
        subject_id=subject_id,
        grant_id=grant_id,
        now=now,
    )


def _semantic_export_material(
    service: ProminService,
    context: ActivationContext,
    store: EventStore,
    *,
    candidate_digest: str | None = None,
    source_head_digest: str | None = None,
) -> dict[str, Any]:
    """Build one immutable semantic-state export snapshot.

    Export bytes are derived from a selected *source* journal HEAD.  This
    intentionally separates snapshot construction from publication of the
    output Artifact: recording that Artifact advances the live journal and
    therefore cannot be part of the snapshot whose bytes it stores.
    """

    current_head = store.head()
    if source_head_digest is None:
        source_head_digest = current_head["batch_digest"]
    if source_head_digest is not None and not re.fullmatch(
        r"[0-9a-f]{64}", source_head_digest
    ):
        raise ServiceError("semantic export source HEAD digest is invalid")

    envelopes: list[dict[str, Any]] = []
    source_head: dict[str, Any] | None = None
    for envelope in store.iter_envelopes(validate=True):
        batch = envelope.get("batch")
        if not isinstance(batch, Mapping):
            raise ServiceError("semantic export journal envelope lacks EventBatch")
        envelopes.append(envelope)
        batch_digest = digest_value(batch)
        if batch_digest == source_head_digest:
            source_head = {
                "sequence": batch["sequence"],
                "batch_id": batch["batch_id"],
                "batch_digest": batch_digest,
                "state_binding_digest": batch["state_binding_digest"],
            }
            break

    if source_head_digest is None:
        if current_head["sequence"] != 0:
            raise ServiceError("semantic export empty HEAD differs from journal")
        source_head = {
            "sequence": 0,
            "batch_id": None,
            "batch_digest": None,
            "state_binding_digest": None,
        }
    elif source_head is None:
        raise ServiceError("semantic export source HEAD is not in the active journal")

    if source_head is None:
        raise ServiceError("semantic export source HEAD is unresolved")
    snapshot = service._runtime_from_envelopes(
        context,
        envelopes,
        head_sequence=source_head["sequence"],
        head_digest=source_head["batch_digest"],
        state_binding_digest=source_head["state_binding_digest"],
        allow_trailing_evidence=(
            source_head["batch_digest"] != current_head["batch_digest"]
        ),
    )
    authority = snapshot.authority
    domain = snapshot.domain
    records: list[dict[str, Any]] = [deepcopy(_activation(context))]
    records.extend(authority.grants.values())
    records.extend(domain.tasks.values())
    records.extend(domain.candidates.values())
    records.extend(domain.leases.values())
    records.extend(domain.findings.values())
    records.extend(domain.gate_results.values())
    records.extend(domain.decisions.values())
    for envelope in envelopes:
        command = _command_from_envelope(envelope)
        if command["command_kind"] in {
            "artifact.record",
            "run.record",
            "grant.revoke",
        }:
            records.append(command["payload"])
        records.extend(_relations_from_envelope(envelope))
    unique = {digest_value(record): dict(record) for record in records}
    ordered = [unique[key] for key in sorted(unique)]
    if candidate_digest is None and domain.candidates:
        candidate_digest = next(reversed(list(domain.candidates.values())))[
            "candidate_digest"
        ]
    if not isinstance(candidate_digest, str) or not re.fullmatch(
        r"[0-9a-f]{64}", candidate_digest
    ):
        raise ServiceError("semantic export requires an exact Candidate digest")

    head_event_id: str | None = None
    if envelopes:
        events = envelopes[-1]["batch"].get("events")
        if not isinstance(events, list) or not events:
            raise ServiceError("semantic export source HEAD lacks a primary Event")
        head_event_id = events[0]["event_id"]
    payload_record = {
        "record_type": "SemanticStatePayload",
        "candidate_digest": candidate_digest,
        "activation_digest": _activation(context)["activation_digest"],
        "head_event_id": head_event_id,
        "head_sequence": source_head["sequence"],
        "head_digest": source_head["batch_digest"],
        "records": ordered,
    }
    validate_definition(_bundle(context).schema, "SemanticStatePayload", payload_record)
    payload = canonical_bytes(payload_record)
    owner = _bundle(context).core["policy-set.json"]["semantic_export_contract"]
    return {
        "candidate_digest": candidate_digest,
        "activation_digest": _activation(context)["activation_digest"],
        "head_event_id": head_event_id,
        "head_sequence": source_head["sequence"],
        "head_digest": source_head["batch_digest"],
        "records": ordered,
        "input_digests": sorted(unique),
        "payload_record": payload_record,
        "payload_bytes": payload,
        "output_digest": hashlib.sha256(payload).hexdigest(),
        "output_size_bytes": len(payload),
        "output_media_type": owner["output_media_type"],
    }


def prepare_semantic_export(
    project_root: Path | str,
    *,
    candidate_digest: str | None = None,
    source_head_digest: str | None = None,
) -> dict[str, Any]:
    """Prepare non-authoritative bytes for a later finalized SemanticExport.

    The returned mapping is a transient Python API result.  Its ``payload_bytes``
    must be published as an immutable Artifact before :func:`semantic_export`
    can verify and return the canonical export record.
    """

    service = ProminService(project_root)
    context = service._context(force_full=True)
    context = service._verified_mutation_context(context)
    store = service._event_store(context)
    return _semantic_export_material(
        service,
        context,
        store,
        candidate_digest=candidate_digest,
        source_head_digest=source_head_digest,
    )


def semantic_export(
    project_root: Path | str,
    *,
    output_artifact_id: str,
    candidate_digest: str | None = None,
    source_head_digest: str | None = None,
) -> dict[str, Any]:
    service = ProminService(project_root)
    context = service._context(force_full=True)
    context = service._verified_mutation_context(context)
    store = service._event_store(context)
    material = _semantic_export_material(
        service,
        context,
        store,
        candidate_digest=candidate_digest,
        source_head_digest=source_head_digest,
    )
    payload = material["payload_bytes"]
    evidence = _reconciled_evidence(service.root, store)
    finalized = evidence.get_record(output_artifact_id)
    artifact = finalized["artifact"]
    object_path = evidence._object_path(artifact["digest"])
    try:
        actual_payload = object_path.read_bytes()
    except OSError as exc:
        raise ServiceError("semantic export CAS bytes are unreadable") from exc
    if actual_payload != payload:
        raise ServiceError("semantic export Artifact differs from canonical semantic state")
    owner = _bundle(context).core["policy-set.json"]["semantic_export_contract"]
    flags = owner["product_flags"]
    exported = {
        "record_type": "SemanticExport",
        "export_kind": owner["export_kind"],
        "package_or_archive": owner["package_or_archive"],
        "candidate_digest": material["candidate_digest"],
        "activation_digest": material["activation_digest"],
        "head_event_id": material["head_event_id"],
        "head_sequence": material["head_sequence"],
        "head_digest": material["head_digest"],
        "core_bundle_digest": _bundle(context).bundle_digest,
        "preset_digest": _bundle(context).preset_digest,
        "implementation_closure_digest": _implementation_closure_digest(context),
        "provider_binding_digest": _provider_binding_digest(context),
        "input_digests": material["input_digests"],
        "output_artifact_id": output_artifact_id,
        "output_artifact_record_digest": digest_value(finalized),
        "output_digest": material["output_digest"],
        "output_size_bytes": material["output_size_bytes"],
        "output_media_type": material["output_media_type"],
        "pass_credit": flags["pass_credit"],
        "product_acceptance_pass": flags["product_acceptance_pass"],
        "product_public_approval": flags["product_public_approval"],
        "public_release_approved": flags["public_release_approved"],
    }
    validate_ingress(
        _bundle(context),
        exported,
        operation="export",
        definition="SemanticExport",
        context={
            **_validation_context(context),
            "activation_context": context,
            "semantic_export": exported,
            "semantic_export_head": {
                "head_event_id": material["head_event_id"],
                "head_sequence": material["head_sequence"],
                "head_digest": material["head_digest"],
            },
            "semantic_export_records": material["records"],
            "semantic_export_artifact_record": finalized,
            "semantic_export_payload": payload,
        },
    )
    return exported


def import_fact(
    project_root: Path | str,
    *,
    fact_id: str,
    command: dict[str, Any],
    expected_record: dict[str, Any],
    provenance: dict[str, Any],
    expected_head: str,
    relations: Iterable[Mapping[str, Any]] = (),
    workcard: Mapping[str, Any] | None = None,
    evidence_payload: bytes | None = None,
) -> dict[str, Any]:
    if not fact_id or not isinstance(provenance, dict) or not provenance:
        raise ServiceError("import requires a fact ID and nonempty provenance")
    if any(value is None for value in provenance.values()):
        raise ServiceError("import provenance cannot contain null fields")
    service = ProminService(project_root)
    context = service._context(force_full=True)
    store = service._event_store(context)
    if store.head()["batch_digest"] != expected_head:
        raise ServiceError("import expected HEAD differs from current HEAD")
    if command.get("expected_head_digest") != expected_head:
        raise ServiceError("CommandRequest expected HEAD differs from import envelope")
    try:
        if command.get("command_kind") == "grant.revoke":
            validate_definition(
                _bundle(context).schema,
                "GrantRevocation",
                expected_record,
            )
        else:
            validate_ingress(
                _bundle(context),
                expected_record,
                operation="import",
                context=_validation_context(context),
            )
    except ContractError as exc:
        raise ServiceError(f"import record is not Core-valid: {exc}") from exc
    if command.get("command_kind") not in {"task.transition", "lease.record"}:
        if command.get("payload") != expected_record:
            raise ServiceError("import expected record differs from command primary payload")
    normalized_relations = _validated_auxiliary_relations(
        _bundle(context),
        context,
        command,
        relations,
    )
    relations_digest = digest_value(list(normalized_relations))
    if normalized_relations and provenance.get("relations_digest") != relations_digest:
        raise ServiceError("import provenance does not bind auxiliary Relations")
    if "relations_digest" in provenance and provenance["relations_digest"] != relations_digest:
        raise ServiceError("import provenance Relations digest is incorrect")
    result = service.commit(
        command,
        auxiliary_relations=normalized_relations,
        workcard=workcard,
        evidence_payload=evidence_payload,
    )
    rebuilt = service.rebuild()
    export_snapshot = service._runtime_state(context, store)
    export_records = [
        *export_snapshot.authority.grants.values(),
        *export_snapshot.authority.revocations.values(),
        *export_snapshot.domain.tasks.values(),
        *export_snapshot.domain.candidates.values(),
        *export_snapshot.domain.leases.values(),
        *export_snapshot.domain.findings.values(),
        *export_snapshot.domain.gate_results.values(),
        *export_snapshot.domain.decisions.values(),
    ]
    semantic_state_digest = digest_value(
        [
            {"digest": digest_value(value), "record": value}
            for value in sorted(export_records, key=digest_value)
        ]
    )
    imported = {
        "record_type": "ImportFactResult",
        "status": "pass",
        "committed": result["outcome"] in {"committed", "idempotent-replay"},
        "fact_id": fact_id,
        "accepted_fact_ids": [fact_id],
        "batch_digest": result["batch_digest"],
        "head_digest": store.head()["batch_digest"],
        "semantic_state_digest": semantic_state_digest,
        "provenance_digest": digest_value(provenance),
        "relations_digest": relations_digest,
        "relation_count": len(normalized_relations),
        "projection_digest": rebuilt["semantic_digest"],
        "product_acceptance_pass_credit": False,
        "public_release_approved": False,
    }
    artifact = _evidence_artifact(command)
    if artifact is not None:
        record = _reconciled_evidence(service.root, service._event_store(context)).get_record(
            artifact["artifact_id"]
        )
        imported["evidence_artifact_digest"] = artifact["digest"]
        imported["evidence_commit_binding"] = record["commit_binding"]
    elif evidence_payload is not None:
        raise ServiceError("evidence payload was supplied for a non-evidence command")
    return imported


def available_commands(project_root: Path | str | None = None) -> tuple[str, ...]:
    if project_root is not None:
        ActivationGuard(Path(project_root).resolve()).verify()
    return BASE_COMMANDS
