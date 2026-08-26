from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import promin.events as event_module
from promin.domain import DomainError, DomainState
from promin.events import (
    CommandConflict,
    CommitReadView,
    CommitStateSnapshot,
    EventStore as _AuthoritativeEventStore,
    EventStorePolicy,
    ImplementationClosureMismatch,
    JournalCorruption,
    PreparedCommit,
    SimulatedCrash,
    canonical_bytes,
    command_intent_identity,
    digest_value,
    state_binding_leaf_id,
    state_binding_value_digest,
)
from promin.evidence import EvidenceStore
from promin.contracts import load_contract_bundle
from promin.service import ServiceError, _apply_lease, _lease_parallelism_policy


ACTIVATION = "a" * 64
ACTIVATION_RECORD_DIGEST = "b" * 64
IMPLEMENTATION_CLOSURE = "c" * 64
ISSUED_AT = "2026-07-17T12:00:00Z"
CANDIDATE = "d" * 64
PACKAGE_ROOT = Path(__file__).parents[1]
AUTHORITY_MODEL = json.loads(
    (PACKAGE_ROOT / "core" / "authority-model.json").read_text(encoding="utf-8")
)
SEMANTIC_MODEL = json.loads(
    (PACKAGE_ROOT / "core" / "semantic-model.json").read_text(encoding="utf-8")
)


def _event_store_policy() -> EventStorePolicy:
    event = AUTHORITY_MODEL["event_contract"]
    mutation = AUTHORITY_MODEL["command_mutation_claim_rule"]
    compiled = {
        "record_type": "EventStorePolicy",
        "authority_model_digest": digest_value(AUTHORITY_MODEL),
        "max_command_bytes": event["command_bytes_max"],
        "max_envelope_bytes": event["envelope_bytes_max"],
        "max_state_binding_bytes": event["state_binding_bytes_max"],
        "max_state_binding_updates_per_batch": event[
            "state_binding_updates_per_batch_max"
        ],
        "max_events_per_batch": event["events_per_batch_max"],
        "max_requested_scope_items": AUTHORITY_MODEL["scope_contract"][
            "requested_scope_items_max"
        ],
        "derived_tail_batch_threshold": event["derived_tail_batch_threshold"],
        "derived_tail_byte_threshold": event["derived_tail_byte_threshold"],
        "runtime_overlay_compaction_depth": event[
            "runtime_overlay_compaction_depth"
        ],
        "command_required_fields": event["command_required_fields"],
        "command_conditional_fields": event["command_conditional_fields"],
        "command_mutation_fields": mutation["required_command_fields"],
        "lease_bound_command_kinds": mutation["lease_bound_command_kinds"],
        "lease_bound_task_transition_states": mutation[
            "lease_bound_task_transition_states"
        ],
        "command_to_primary_event": [
            [command_kind, event_kind]
            for command_kind, event_kind in event["command_to_primary_event"].items()
        ],
        "allowed_state_binding_leaf_types": [
            "Activation",
            *[item["kind"] for item in SEMANTIC_MODEL["persistent_entities"]],
            "Relation",
        ],
        "state_binding_identity_rules": event["state_binding_identity_rules"],
        "state_binding_algorithm_contract": event[
            "state_binding_algorithm_contract"
        ],
        "state_binding_value_rules": event["state_binding_value_rules"],
        "canonical_timestamp_contract": AUTHORITY_MODEL[
            "canonical_timestamp_contract"
        ],
        "genesis_previous_authority_commitment": event[
            "genesis_previous_authority_commitment"
        ],
        "genesis_event_semantic_digest": event["genesis_event_semantic_digest"],
    }
    compiled["policy_digest"] = digest_value(compiled)
    return EventStorePolicy.from_compiled(compiled)


EVENT_STORE_POLICY = _event_store_policy()


def _thaw(value: Any) -> Any:
    if isinstance(value, dict) or hasattr(value, "items"):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_thaw(item) for item in value]
    return value


def _load_commit_state(view: CommitReadView, envelopes) -> CommitStateSnapshot:
    state = tuple(
        event["event_id"]
        for envelope in envelopes()
        for event in envelope["batch"]["events"]
    )
    return CommitStateSnapshot(
        state,
        view.head_sequence,
        view.head_digest,
        view.current_state_binding_digest,
    )


def _prepare_commit(_view, command_value, relations) -> PreparedCommit:
    command_copy = _thaw(command_value)
    relation_copies = tuple(_thaw(value) for value in relations)
    payload = command_copy["payload"]
    leaf_type = payload["record_type"]
    event_kind = EVENT_STORE_POLICY.primary_events[command_copy["command_kind"]]
    updates = [
        {
            "leaf_type": leaf_type,
            "leaf_id": state_binding_leaf_id(
                EVENT_STORE_POLICY, leaf_type, payload
            ),
            "operation": "set",
            "value_digest": state_binding_value_digest(
                EVENT_STORE_POLICY,
                leaf_type,
                payload,
                event_kind=event_kind,
            ),
        }
    ]
    updates.extend(
        {
            "leaf_type": "Relation",
            "leaf_id": relation["relation_id"],
            "operation": "set",
            "value_digest": digest_value(relation),
        }
        for relation in relation_copies
    )
    return PreparedCommit(
        relation_copies,
        tuple(
            sorted(updates, key=lambda value: (value["leaf_type"], value["leaf_id"]))
        ),
    )


def EventStore(
    root: Path,
    active_activation_digest: str = ACTIVATION,
    *,
    activation_record_digest: str = ACTIVATION_RECORD_DIGEST,
    implementation_closure_digest: str = IMPLEMENTATION_CLOSURE,
    lock_timeout: float = 10.0,
) -> _AuthoritativeEventStore:
    return _AuthoritativeEventStore(
        root,
        active_activation_digest,
        activation_record_digest=activation_record_digest,
        implementation_closure_digest=implementation_closure_digest,
        policy=EVENT_STORE_POLICY,
        compiled_record_validator=lambda _definition, _value, **_kwargs: True,
        command_validator=lambda _value, **_kwargs: True,
        authorization_validator=lambda _value, **_kwargs: True,
        event_validator=lambda _value, **_kwargs: True,
        commit_state_loader=_load_commit_state,
        commit_prepare_callback=_prepare_commit,
        derived_state_validator=lambda _name, _state, **_kwargs: True,
        lock_timeout=lock_timeout,
    )


class _LeaseAuthority:
    def __init__(self) -> None:
        self.activation_digest = ACTIVATION
        self.capabilities = frozenset({"task.execute"})
        self.grants = {
            "grant:planner": {
                "grant_id": "grant:planner",
                "subject_id": "subject:planner",
                "capability_id": "task.plan",
                "claim_digest": "1" * 64,
                "scope": [{"kind": "all", "value": "*"}],
            },
            "grant:manager": {
                "grant_id": "grant:manager",
                "subject_id": "subject:manager",
                "capability_id": "lease.manage",
                "claim_digest": "2" * 64,
                "scope": [{"kind": "all", "value": "*"}],
            },
            "grant:worker": {
                "grant_id": "grant:worker",
                "subject_id": "subject:worker",
                "capability_id": "task.execute",
                "claim_digest": "3" * 64,
                "scope": [{"kind": "all", "value": "*"}],
            },
        }

    def authorize(
        self,
        subject_id: str,
        capability: str,
        _scope: list[dict[str, str]],
        grant_id: str,
        claim_digest: str,
        _evaluated_at: str,
        **_bindings: Any,
    ) -> dict[str, Any]:
        grant = self.grants.get(grant_id)
        if (
            grant is None
            or grant["subject_id"] != subject_id
            or grant["capability_id"] != capability
            or grant["claim_digest"] != claim_digest
        ):
            raise AssertionError("fixture authorization mismatch")
        return dict(grant)

    def resolve_grant(self, grant_id: str) -> dict[str, Any] | None:
        grant = self.grants.get(grant_id)
        return None if grant is None else dict(grant)

    def record_action(
        self,
        subject_id: str,
        capability: str,
        *,
        authorization: dict[str, Any],
        **bindings: Any,
    ) -> dict[str, Any]:
        return self.authorize(
            subject_id,
            capability,
            authorization["requested_scope"],
            authorization["grant_id"],
            authorization["claim_digest"],
            authorization["evaluated_at"],
            **bindings,
        )



def _authorization(
    authority: _LeaseAuthority,
    role: str,
    at: str = "2026-07-17T12:00:00Z",
) -> dict[str, Any]:
    grant = authority.grants[f"grant:{role}"]
    return {
        "subject_id": grant["subject_id"],
        "grant_id": grant["grant_id"],
        "claim_digest": grant["claim_digest"],
        "evaluated_at": at,
        "requested_scope": [{"kind": "all", "value": "*"}],
    }


def _parallelism_policy(ceiling: int) -> dict[str, Any]:
    policy_set = json.loads(
        (
            Path(__file__).parents[1]
            / "core"
            / "policy-set.json"
        ).read_text(encoding="utf-8")
    )
    state_machines = policy_set["state_machines"]
    capacity_release = state_machines["capacity_release"]
    return {
        "activation_digest": ACTIVATION,
        "implementation_closure_digest": IMPLEMENTATION_CLOSURE,
        "core_bundle_digest": "4" * 64,
        "preset_digest": "5" * 64,
        "operating_profile": "fixture-profile",
        "profile_digest": "6" * 64,
        "model_tier": "fixture-tier",
        "max_parallel_tasks": ceiling,
        "model_tier_rule_digest": "7" * 64,
        "policy_set_digest": digest_value(policy_set),
        "state_machine_rule_digest": digest_value(
            {
                "task": state_machines["task"],
                "lease": state_machines["lease"],
            }
        ),
        "task_transitions": state_machines["task"],
        "lease_transitions": state_machines["lease"],
        "capacity_release_rule_digest": digest_value(
            {"capacity_release": capacity_release}
        ),
        "capacity_release": capacity_release,
        "authority_effect": False,
    }


def _ready_task(
    domain: DomainState,
    authority: _LeaseAuthority,
    index: int,
    policy: dict[str, Any],
) -> None:
    if "candidate:parallel" not in domain.candidates:
        domain.record_candidate(
            {
                "record_type": "Candidate",
                "candidate_id": "candidate:parallel",
                "candidate_digest": CANDIDATE,
                "inventory_digest": "8" * 64,
                "product_root_digest": "9" * 64,
                "control_excluded": True,
                "candidate_recipe_digest": "a" * 64,
                "consistency_mode": "immutable-vcs-tree",
                "creditable": True,
                "snapshot_provider_id": "provider:test-snapshot",
                "snapshot_digest": "b" * 64,
            },
            _authorization(authority, "worker"),
        )
    task_id = f"task:parallel:{index}"
    task = {
        "record_type": "Task",
        "task_id": task_id,
        "state": "PLANNED",
        "required_capability": "task.execute",
        "acceptance_predicate": "focused fixture only",
        "allowed_paths": [f"src/{index}"],
        "activation_digest": ACTIVATION,
        "candidate_digest": CANDIDATE,
        "created_at": ISSUED_AT,
    }
    owner_digest = digest_value(
        {key: value for key, value in task.items() if key != "state"}
    )
    definition = {
        "definition_kind": "GateRunDefinition",
        "definition_id": f"definition:parallel:{index}",
        "owner_kind": "Task",
        "owner_digest": owner_digest,
        "defined_at_head_digest": None,
        "gate_id": f"gate:parallel:{index}",
        "run_kind": "validation",
        "expected_evidence_class": "validator",
        "expected_evidence_purpose": "diagnostic",
        "product_credit_required": False,
        "target_kind": "candidate",
        "target_digest": CANDIDATE,
        "target_scope": [{"kind": "candidate", "value": CANDIDATE}],
        "candidate_digest": CANDIDATE,
        "policy_digest": "c" * 64,
        "tool_digest": "d" * 64,
        "implementation_closure_digest": IMPLEMENTATION_CLOSURE,
        "provider_binding_digest": "e" * 64,
        "input_digests": [],
        "activation_digest": ACTIVATION,
    }
    task["gate_run_definitions"] = [
        {
            "definition_digest": digest_value(definition),
            "definition": definition,
        }
    ]
    domain.record_task(task, _authorization(authority, "planner"))
    domain.transition_task(
        {
            "task_id": task_id,
            "from_state": "PLANNED",
            "to_state": "READY",
            "reason": "fixture prerequisites are present",
        },
        _authorization(authority, "planner"),
        runtime_policy=policy,
    )


def _lease(index: int) -> dict[str, Any]:
    return {
        "record_type": "Lease",
        "lease_id": f"lease:parallel:{index}",
        "task_id": f"task:parallel:{index}",
        "manager_subject_id": "subject:manager",
        "manager_grant_id": "grant:manager",
        "manager_grant_claim_digest": "2" * 64,
        "holder_subject_id": "subject:worker",
        "holder_grant_id": "grant:worker",
        "holder_grant_claim_digest": "3" * 64,
        "generation": 1,
        "fencing_token": 1,
        "state": "ACTIVE",
        "acquired_at": ISSUED_AT,
        "heartbeat_at": ISSUED_AT,
        "expires_at": "2026-07-17T12:10:00Z",
        "activation_digest": ACTIVATION,
    }


def command(index: int, expected_head: str | None) -> dict[str, object]:
    value: dict[str, object] = {
        "record_type": "CommandRequest",
        "command_id": f"command:{index:04d}",
        "command_kind": "task.record",
        "subject_id": "subject:writer",
        "activation_digest": ACTIVATION,
        "idempotency_key": f"idempotency-key-{index:04d}",
        "requested_scope": [{"kind": "project", "value": "project:focused"}],
        "expected_head_digest": expected_head,
        "issued_at": ISSUED_AT,
        "payload": {
            "record_type": "Task",
            "task_id": f"task:{index:04d}",
            "state": "PLANNED",
        },
        "intent_digest": "0" * 64,
        "authorization": {
            "kind": "root",
            "subject_id": "subject:writer",
            "proof_digest": "b" * 64,
        },
    }
    value["intent_digest"] = digest_value(command_intent_identity(value))
    return value


def lease_record_command(
    lease: dict[str, Any],
    expected_head: str | None,
    *,
    phase: str,
    issued_at: str,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "record_type": "CommandRequest",
        "command_id": f"command:lease-{phase}:0001",
        "command_kind": "lease.record",
        "subject_id": "subject:manager",
        "activation_digest": ACTIVATION,
        "idempotency_key": f"lease-{phase}-key-0001",
        "requested_scope": [{"kind": "task", "value": lease["task_id"]}],
        "expected_head_digest": expected_head,
        "issued_at": issued_at,
        "payload": lease,
        "intent_digest": "0" * 64,
        "authorization": {
            "kind": "root",
            "subject_id": "subject:manager",
            "proof_digest": "b" * 64,
        },
    }
    value["intent_digest"] = digest_value(command_intent_identity(value))
    return value


def reconciliation_command(
    lease: dict[str, Any],
    expected_head: str | None,
) -> dict[str, Any]:
    return lease_record_command(
        lease,
        expected_head,
        phase="reconciliation",
        issued_at=lease["capacity_reconciliation"]["reconciled_at"],
    )


def collect_event_ids(state: list[str], event: dict[str, object]) -> list[str]:
    return [*state, str(event["event_id"])]


class EventConcurrencyCrashTests(unittest.TestCase):
    def test_installed_profile_compiles_one_activation_bound_ceiling(self) -> None:
        package_root = Path(__file__).parents[1]
        bundle = load_contract_bundle(
            package_root,
            package_root / "presets" / "semantic-standard.json",
        )
        for profile_name, profile in bundle.preset["profiles"].items():
            with self.subTest(profile=profile_name):
                activation = {
                    "activation_digest": ACTIVATION,
                    "core_bundle_digest": bundle.bundle_digest,
                    "preset_digest": bundle.preset_digest,
                    "implementation_closure_digest": IMPLEMENTATION_CLOSURE,
                    "operating_profile": profile_name,
                }
                context = SimpleNamespace(
                    activation=activation,
                    activation_digest=ACTIVATION,
                    implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                    bundle=bundle,
                    plans={
                        "project.json": {
                            "operating_profile": profile_name,
                            "preset_id": bundle.preset["preset_id"],
                        }
                    },
                )
                compiled = _lease_parallelism_policy(context)
                self.assertEqual(compiled["operating_profile"], profile_name)
                self.assertEqual(compiled["model_tier"], profile["model_tier"])
                self.assertEqual(
                    compiled["max_parallel_tasks"],
                    profile["max_parallel_tasks"],
                )
                self.assertIs(compiled["authority_effect"], False)

        unknown_activation = dict(activation, operating_profile="unknown-profile")
        unknown = SimpleNamespace(
            **{
                **vars(context),
                "activation": unknown_activation,
                "plans": {
                    "project.json": {
                        "operating_profile": "unknown-profile",
                        "preset_id": bundle.preset["preset_id"],
                    }
                },
            }
        )
        with self.assertRaisesRegex(ServiceError, "unknown preset profile"):
            _lease_parallelism_policy(unknown)

        stale = SimpleNamespace(
            **{
                **vars(context),
                "activation": dict(
                    activation,
                    core_bundle_digest="8" * 64,
                ),
            }
        )
        with self.assertRaisesRegex(ServiceError, "inputs are stale"):
            _lease_parallelism_policy(stale)

        selected_profile = bundle.preset["profiles"][activation["operating_profile"]]
        with patch.dict(selected_profile, {"max_parallel_tasks": 0}):
            with self.assertRaisesRegex(ServiceError, "inputs are stale"):
                _lease_parallelism_policy(context)

    def test_parallelism_ceiling_is_atomic_and_closing_remains_occupied(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            authority = _LeaseAuthority()
            domain = DomainState(
                authority,
                EvidenceStore(Path(temporary) / "cas"),
                implementation_closure_digest=IMPLEMENTATION_CLOSURE,
            )
            policy = _parallelism_policy(1)
            for index in (1, 2):
                _ready_task(domain, authority, index, policy)
            transition = {
                "task_id": "task:parallel:1",
                "from_state": "READY",
                "to_state": "BLOCKED",
                "reason": "policy ownership probe",
            }
            with self.assertRaisesRegex(DomainError, "policy.*shape"):
                domain.transition_task(
                    transition,
                    _authorization(authority, "planner"),
                )
            with self.assertRaisesRegex(DomainError, "policy.*shape"):
                domain.checkpoint(
                    head_sequence=0,
                    head_digest="f" * 64,
                    state_binding_digest="0" * 64,
                )
            tampered_policy = json.loads(json.dumps(policy))
            tampered_policy["task_transitions"]["READY"].remove("BLOCKED")
            with self.assertRaisesRegex(DomainError, "lifecycle policy digest is stale"):
                domain.transition_task(
                    transition,
                    _authorization(authority, "planner"),
                    runtime_policy=tampered_policy,
                )
            barrier = threading.Barrier(2)

            def acquire(index: int) -> str:
                barrier.wait(timeout=10)
                try:
                    domain.acquire_lease(
                        _lease(index),
                        _authorization(authority, "manager"),
                        parallelism_policy=policy,
                    )
                    return "acquired"
                except DomainError as exc:
                    return str(exc)

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(acquire, (1, 2)))
            self.assertEqual(outcomes.count("acquired"), 1)
            self.assertEqual(
                outcomes.count("runtime parallelism ceiling is exhausted"),
                1,
            )
            winner = 1 if outcomes[0] == "acquired" else 2
            loser = 2 if winner == 1 else 1
            domain.begin_close_lease(
                f"lease:parallel:{winner}",
                1,
                1,
                _authorization(
                    authority,
                    "worker",
                    "2026-07-17T12:01:00Z",
                ),
                runtime_policy=policy,
            )
            with self.assertRaisesRegex(DomainError, "ceiling is exhausted"):
                domain.acquire_lease(
                    _lease(loser),
                    _authorization(authority, "manager"),
                    parallelism_policy=policy,
                )
            domain.close_lease(
                f"lease:parallel:{winner}",
                1,
                1,
                {
                    "acknowledged_by": "subject:manager",
                    "grant_id": "grant:manager",
                    "grant_claim_digest": "2" * 64,
                    "acknowledged_at": "2026-07-17T12:02:00Z",
                },
                _authorization(
                    authority,
                    "manager",
                    "2026-07-17T12:02:00Z",
                ),
                runtime_policy=policy,
            )
            acquired = domain.acquire_lease(
                _lease(loser),
                _authorization(authority, "manager"),
                parallelism_policy=policy,
            )
            self.assertEqual(acquired["task_id"], f"task:parallel:{loser}")

    def test_expiry_requires_reconciliation_and_replay_rejects_oversubscription(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            authority = _LeaseAuthority()
            domain = DomainState(
                authority,
                EvidenceStore(Path(temporary) / "cas"),
                implementation_closure_digest=IMPLEMENTATION_CLOSURE,
            )
            policy = _parallelism_policy(1)
            for index in (1, 2):
                _ready_task(domain, authority, index, policy)
            manager = _authorization(authority, "manager")
            _apply_lease(
                domain,
                authority,
                _lease(1),
                manager,
                ISSUED_AT,
                parallelism_policy=policy,
            )
            with self.assertRaisesRegex(DomainError, "ceiling is exhausted"):
                _apply_lease(
                    domain,
                    authority,
                    _lease(2),
                    manager,
                    ISSUED_AT,
                    parallelism_policy=policy,
                )
            domain.expire_lease(
                "lease:parallel:1",
                1,
                1,
                "2026-07-17T12:10:00Z",
                _authorization(
                    authority,
                    "manager",
                    "2026-07-17T12:10:00Z",
                ),
                runtime_policy=policy,
            )
            with self.assertRaisesRegex(DomainError, "ceiling is exhausted"):
                _apply_lease(
                    domain,
                    authority,
                    _lease(2),
                    manager,
                    ISSUED_AT,
                    parallelism_policy=policy,
                )
            unreconciled_checkpoint = domain.checkpoint(
                head_sequence=1,
                head_digest="b" * 64,
                state_binding_digest="c" * 64,
                runtime_policy=policy,
            )
            checkpoint_domain = DomainState(
                authority,
                EvidenceStore(Path(temporary) / "unreconciled-checkpoint-cas"),
                implementation_closure_digest=IMPLEMENTATION_CLOSURE,
            )
            checkpoint_domain.restore_checkpoint(
                unreconciled_checkpoint,
                expected_head_sequence=1,
                expected_head_digest="b" * 64,
                expected_state_binding_digest="c" * 64,
                parallelism_policy=policy,
            )
            with self.assertRaisesRegex(DomainError, "ceiling is exhausted"):
                checkpoint_domain.acquire_lease(
                    _lease(2),
                    manager,
                    parallelism_policy=policy,
                )
            reconciled = dict(domain.leases["lease:parallel:1"])
            reconciled["capacity_reconciliation"] = {
                "reconciled_by": "subject:manager",
                "grant_id": "grant:manager",
                "grant_claim_digest": "2" * 64,
                "reconciled_at": "2026-07-17T12:11:00Z",
                "generation": 1,
                "fencing_token": 1,
            }
            _apply_lease(
                domain,
                authority,
                reconciled,
                _authorization(
                    authority,
                    "manager",
                    "2026-07-17T12:11:00Z",
                ),
                "2026-07-17T12:11:00Z",
                parallelism_policy=policy,
            )
            _apply_lease(
                domain,
                authority,
                reconciled,
                _authorization(
                    authority,
                    "manager",
                    "2026-07-17T12:11:00Z",
                ),
                "2026-07-17T12:11:00Z",
                parallelism_policy=policy,
            )
            _apply_lease(
                domain,
                authority,
                _lease(2),
                manager,
                ISSUED_AT,
                parallelism_policy=policy,
            )
            self.assertEqual(domain.leases["lease:parallel:2"]["state"], "ACTIVE")

            stale_policy = dict(policy, activation_digest="9" * 64)
            third_domain = DomainState(
                authority,
                EvidenceStore(Path(temporary) / "stale-cas"),
                implementation_closure_digest=IMPLEMENTATION_CLOSURE,
            )
            _ready_task(third_domain, authority, 3, policy)
            with self.assertRaisesRegex(DomainError, "Activation is stale"):
                third_domain.acquire_lease(
                    _lease(3),
                    manager,
                    parallelism_policy=stale_policy,
                )
            degraded_policy = dict(policy, max_parallel_tasks=0)
            with self.assertRaisesRegex(DomainError, "ceiling is degraded"):
                third_domain.acquire_lease(
                    _lease(3),
                    manager,
                    parallelism_policy=degraded_policy,
                )

            checkpoint_source = DomainState(
                authority,
                EvidenceStore(Path(temporary) / "checkpoint-source-cas"),
                implementation_closure_digest=IMPLEMENTATION_CLOSURE,
            )
            wider_policy = _parallelism_policy(2)
            for index in (4, 5):
                _ready_task(checkpoint_source, authority, index, wider_policy)
                checkpoint_source.acquire_lease(
                    _lease(index),
                    manager,
                    parallelism_policy=wider_policy,
                )
            checkpoint = checkpoint_source.checkpoint(
                head_sequence=2,
                head_digest="a" * 64,
                state_binding_digest="d" * 64,
                runtime_policy=wider_policy,
            )
            checkpoint_replay = DomainState(
                authority,
                EvidenceStore(Path(temporary) / "checkpoint-replay-cas"),
                implementation_closure_digest=IMPLEMENTATION_CLOSURE,
            )
            with self.assertRaisesRegex(DomainError, "exceeds.*ceiling"):
                checkpoint_replay.restore_checkpoint(
                    checkpoint,
                    expected_head_sequence=2,
                    expected_head_digest="a" * 64,
                    expected_state_binding_digest="d" * 64,
                    parallelism_policy=policy,
                )

    def test_revoked_slot_requires_fence_bound_manager_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            authority = _LeaseAuthority()
            domain = DomainState(
                authority,
                EvidenceStore(Path(temporary) / "cas"),
                implementation_closure_digest=IMPLEMENTATION_CLOSURE,
            )
            policy = _parallelism_policy(1)
            for index in (6, 7):
                _ready_task(domain, authority, index, policy)
            manager = _authorization(authority, "manager")
            domain.acquire_lease(
                _lease(6),
                manager,
                parallelism_policy=policy,
            )
            domain.revoke_lease(
                "lease:parallel:6",
                1,
                1,
                ISSUED_AT,
                manager,
                runtime_policy=policy,
            )
            with self.assertRaisesRegex(DomainError, "ceiling is exhausted"):
                domain.acquire_lease(
                    _lease(7),
                    manager,
                    parallelism_policy=policy,
                )
            reconciliation = {
                "reconciled_by": "subject:manager",
                "grant_id": "grant:manager",
                "grant_claim_digest": "2" * 64,
                "reconciled_at": "2026-07-17T12:01:00Z",
                "generation": 1,
                "fencing_token": 1,
            }
            wrong_manager = dict(
                reconciliation,
                reconciled_by="subject:planner",
                grant_id="grant:planner",
                grant_claim_digest="1" * 64,
            )
            with self.assertRaisesRegex(DomainError, "manager Grant is invalid"):
                domain.reconcile_lease_capacity(
                    "lease:parallel:6",
                    1,
                    1,
                    wrong_manager,
                    _authorization(
                        authority,
                        "planner",
                        "2026-07-17T12:01:00Z",
                    ),
                    runtime_policy=policy,
                )
            with self.assertRaisesRegex(DomainError, "values are invalid"):
                domain.reconcile_lease_capacity(
                    "lease:parallel:6",
                    1,
                    1,
                    dict(reconciliation, fencing_token=True),
                    _authorization(
                        authority,
                        "manager",
                        "2026-07-17T12:01:00Z",
                    ),
                    runtime_policy=policy,
                )
            with self.assertRaisesRegex(DomainError, "fence is stale"):
                domain.reconcile_lease_capacity(
                    "lease:parallel:6",
                    1,
                    1,
                    dict(reconciliation, fencing_token=2),
                    _authorization(
                        authority,
                        "manager",
                        "2026-07-17T12:01:00Z",
                    ),
                    runtime_policy=policy,
                )
            domain.reconcile_lease_capacity(
                "lease:parallel:6",
                1,
                1,
                reconciliation,
                _authorization(
                    authority,
                    "manager",
                    "2026-07-17T12:01:00Z",
                ),
                runtime_policy=policy,
            )
            domain.acquire_lease(
                _lease(7),
                manager,
                parallelism_policy=policy,
            )

    def test_same_task_fence_waits_for_terminal_capacity_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            authority = _LeaseAuthority()
            policy = _parallelism_policy(2)
            domain = DomainState(
                authority,
                EvidenceStore(Path(temporary) / "cas"),
                implementation_closure_digest=IMPLEMENTATION_CLOSURE,
            )
            _ready_task(domain, authority, 8, policy)
            manager = _authorization(authority, "manager")
            domain.acquire_lease(
                _lease(8),
                manager,
                parallelism_policy=policy,
            )
            domain.expire_lease(
                "lease:parallel:8",
                1,
                1,
                "2026-07-17T12:10:00Z",
                _authorization(
                    authority,
                    "manager",
                    "2026-07-17T12:10:00Z",
                ),
                runtime_policy=policy,
            )
            replacement = dict(
                _lease(8),
                lease_id="lease:parallel:8:replacement",
                generation=2,
                fencing_token=2,
                acquired_at="2026-07-17T12:11:00Z",
                heartbeat_at="2026-07-17T12:11:00Z",
                expires_at="2026-07-17T12:20:00Z",
            )
            with self.assertRaisesRegex(DomainError, "requires reconciliation"):
                domain.acquire_lease(
                    replacement,
                    _authorization(
                        authority,
                        "manager",
                        "2026-07-17T12:11:00Z",
                    ),
                    parallelism_policy=policy,
                )
            checkpoint = domain.checkpoint(
                head_sequence=1,
                head_digest="e" * 64,
                state_binding_digest="f" * 64,
                runtime_policy=policy,
            )
            corrupt = json.loads(json.dumps(checkpoint))
            corrupt["leases"].append(replacement)
            corrupt["task_lease_generations"] = [
                {"task_id": "task:parallel:8", "generation": 2}
            ]
            corrupt["task_fences"] = [
                {"task_id": "task:parallel:8", "fencing_token": 2}
            ]
            state_fields = (
                "tasks",
                "candidates",
                "leases",
                "findings",
                "gate_results",
                "gate_runs",
                "decisions",
                "candidate_ids_by_digest",
                "task_lease_generations",
                "task_fences",
                "gate_result_order",
                "decision_order",
            )
            corrupt["domain_state_digest"] = digest_value(
                {field: corrupt[field] for field in state_fields}
            )
            without_checkpoint_digest = dict(corrupt)
            without_checkpoint_digest.pop("checkpoint_digest")
            corrupt["checkpoint_digest"] = digest_value(
                without_checkpoint_digest
            )
            checkpoint_domain = DomainState(
                authority,
                EvidenceStore(Path(temporary) / "checkpoint-cas"),
                implementation_closure_digest=IMPLEMENTATION_CLOSURE,
            )
            with self.assertRaisesRegex(DomainError, "fence advanced"):
                checkpoint_domain.restore_checkpoint(
                    corrupt,
                    expected_head_sequence=1,
                    expected_head_digest="e" * 64,
                    expected_state_binding_digest="f" * 64,
                    parallelism_policy=policy,
                )
            domain.reconcile_lease_capacity(
                "lease:parallel:8",
                1,
                1,
                {
                    "reconciled_by": "subject:manager",
                    "grant_id": "grant:manager",
                    "grant_claim_digest": "2" * 64,
                    "reconciled_at": "2026-07-17T12:11:00Z",
                    "generation": 1,
                    "fencing_token": 1,
                },
                _authorization(
                    authority,
                    "manager",
                    "2026-07-17T12:11:00Z",
                ),
                runtime_policy=policy,
            )
            acquired = domain.acquire_lease(
                replacement,
                _authorization(
                    authority,
                    "manager",
                    "2026-07-17T12:11:00Z",
                ),
                parallelism_policy=policy,
            )
            self.assertEqual(acquired["generation"], 2)

    def test_existing_journal_rejects_implementation_closure_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            store = EventStore(
                root,
                ACTIVATION,
                implementation_closure_digest=IMPLEMENTATION_CLOSURE,
            )
            try:
                store.commit(command(1, None), created_at=ISSUED_AT)

                with self.assertRaisesRegex(
                    ImplementationClosureMismatch,
                    "implementation closure mismatch",
                ):
                    EventStore(
                        root,
                        ACTIVATION,
                        implementation_closure_digest="d" * 64,
                    )
            finally:
                store.close()

    def test_reconciliation_primary_event_is_crash_safe_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            store = EventStore(
                root,
                ACTIVATION,
                implementation_closure_digest=IMPLEMENTATION_CLOSURE,
            )
            recovered: _AuthoritativeEventStore | None = None
            try:
                initial = _lease(1)
                store.commit(
                    lease_record_command(
                        initial,
                        None,
                        phase="acquire",
                        issued_at=ISSUED_AT,
                    ),
                    created_at=ISSUED_AT,
                )
                expired = dict(
                    initial,
                    state="EXPIRED",
                    termination={
                        "state": "EXPIRED",
                        "terminated_by": "subject:manager",
                        "grant_id": "grant:manager",
                        "grant_claim_digest": "2" * 64,
                        "terminated_at": "2026-07-17T12:10:00Z",
                        "generation": 1,
                        "fencing_token": 1,
                    },
                )
                store.commit(
                    lease_record_command(
                        expired,
                        store.head()["batch_digest"],
                        phase="expire",
                        issued_at="2026-07-17T12:10:00Z",
                    ),
                    created_at="2026-07-17T12:10:00Z",
                )
                reconciled = dict(expired)
                reconciled["capacity_reconciliation"] = {
                    "reconciled_by": "subject:manager",
                    "grant_id": "grant:manager",
                    "grant_claim_digest": "2" * 64,
                    "reconciled_at": "2026-07-17T12:11:00Z",
                    "generation": 1,
                    "fencing_token": 1,
                }
                value = reconciliation_command(
                    reconciled,
                    store.head()["batch_digest"],
                )
                with self.assertRaises(SimulatedCrash):
                    store.commit(
                        value,
                        created_at="2026-07-17T12:11:00Z",
                        crash_hook=lambda point: point == "after_head",
                    )
                recovered = EventStore(
                    root,
                    ACTIVATION,
                    implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                )
                result = recovered.commit(
                    value,
                    created_at="2026-07-17T12:11:00Z",
                )
                self.assertEqual(result["outcome"], "idempotent-replay")
                envelopes = list(recovered.iter_envelopes(validate=True))
                self.assertEqual(len(envelopes), 3)
                self.assertEqual(envelopes[-1]["command"]["payload"], reconciled)
                self.assertEqual(
                    envelopes[-1]["batch"]["events"][0]["payload"],
                    reconciled,
                )

                authority = _LeaseAuthority()
                policy = _parallelism_policy(1)
                replayed = DomainState(
                    authority,
                    EvidenceStore(Path(temporary) / "replay-cas"),
                    implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                )
                _ready_task(replayed, authority, 1, policy)
                for envelope in envelopes:
                    replayed_command = envelope["command"]
                    issued_at = replayed_command["issued_at"]
                    _apply_lease(
                        replayed,
                        authority,
                        replayed_command["payload"],
                        _authorization(authority, "manager", issued_at),
                        issued_at,
                        parallelism_policy=policy,
                    )
                self.assertEqual(replayed.leases["lease:parallel:1"], reconciled)
                first_checkpoint = replayed.checkpoint(
                    head_sequence=recovered.head()["sequence"],
                    head_digest=recovered.head()["batch_digest"],
                    state_binding_digest="f" * 64,
                    runtime_policy=policy,
                )

                replayed_again = DomainState(
                    authority,
                    EvidenceStore(Path(temporary) / "second-replay-cas"),
                    implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                )
                _ready_task(replayed_again, authority, 1, policy)
                for envelope in envelopes:
                    replayed_command = envelope["command"]
                    issued_at = replayed_command["issued_at"]
                    _apply_lease(
                        replayed_again,
                        authority,
                        replayed_command["payload"],
                        _authorization(authority, "manager", issued_at),
                        issued_at,
                        parallelism_policy=policy,
                    )
                self.assertEqual(
                    replayed_again.checkpoint(
                        head_sequence=recovered.head()["sequence"],
                        head_digest=recovered.head()["batch_digest"],
                        state_binding_digest="f" * 64,
                        runtime_policy=policy,
                    ),
                    first_checkpoint,
                )
            finally:
                if recovered is not None:
                    recovered.close()
                store.close()

    def test_writer_timeout_configuration_is_finite_and_positive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            for invalid in (0, -1, float("inf"), float("nan"), True):
                with self.subTest(invalid=invalid), self.assertRaisesRegex(
                    event_module.EventStoreError, "finite positive"
                ):
                    EventStore(
                        root,
                        ACTIVATION,
                        implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                        lock_timeout=invalid,
                    )

    def test_process_local_writer_wait_uses_the_same_bounded_deadline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            held = event_module._local_lock(root / "writer.lock")
            held.acquire()
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(event_module.EventStoreError, "lock timeout"):
                    EventStore(
                        root,
                        ACTIVATION,
                        implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                        lock_timeout=0.05,
                    )
            finally:
                held.release()
            self.assertLess(time.monotonic() - started, 0.5)

    def test_startup_ignores_same_pid_orphan_file_and_serializes_stress(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            root.mkdir(parents=True)
            (root / "writer.lock").write_bytes(
                canonical_bytes({"pid": os.getpid(), "created_at": ISSUED_AT})
            )

            def construct(_index: int) -> int:
                return EventStore(
                    root,
                    ACTIVATION,
                    implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                    lock_timeout=2.0,
                ).head()["sequence"]

            for _round in range(8):
                with ThreadPoolExecutor(max_workers=16) as pool:
                    heads = list(pool.map(construct, range(64)))
                self.assertEqual(heads, [0] * 64)

    def test_single_writer_and_expected_head_allow_exactly_one_racer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            workers = 8
            barrier = threading.Barrier(workers)

            def attempt(index: int) -> str:
                store = EventStore(
                    root,
                    ACTIVATION,
                    implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                )
                try:
                    barrier.wait(timeout=10)
                    try:
                        return store.commit(command(index, None), created_at=ISSUED_AT)["outcome"]
                    except CommandConflict:
                        return "conflict"
                finally:
                    store.close()

            recovered: _AuthoritativeEventStore | None = None
            try:
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    outcomes = list(pool.map(attempt, range(workers)))
                self.assertEqual(outcomes.count("committed"), 1)
                self.assertEqual(outcomes.count("conflict"), workers - 1)
                recovered = EventStore(
                    root,
                    ACTIVATION,
                    implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                )
                self.assertEqual(recovered.head()["sequence"], 1)
                self.assertEqual(len(list(recovered.iter_envelopes(validate=True))), 1)
            finally:
                if recovered is not None:
                    recovered.close()

    def test_crash_points_recover_without_duplicate_primary_event(self) -> None:
        for point in (
            "after_pending",
            "after_batch",
            "after_head",
            "before_checkpoint",
            "after_checkpoint",
        ):
            with self.subTest(point=point), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "state"
                baseline: _AuthoritativeEventStore | None = None
                store: _AuthoritativeEventStore | None = None
                recovered: _AuthoritativeEventStore | None = None
                try:
                    baseline = EventStore(
                        Path(temporary) / "baseline",
                        ACTIVATION,
                        implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                    )
                    baseline.commit(command(1, None), created_at=ISSUED_AT)
                    baseline_replay = baseline.replay(collect_event_ids, [])
                    store = EventStore(
                        root,
                        ACTIVATION,
                        implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                    )
                    value = command(1, None)
                    with self.assertRaises(SimulatedCrash):
                        store.commit(
                            value,
                            created_at=ISSUED_AT,
                            crash_hook=lambda current, target=point: current == target,
                        )
                    recovered = EventStore(
                        root,
                        ACTIVATION,
                        implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                    )
                    recovery_status = recovered.checkpoint_status()
                    result = recovered.commit(value, created_at=ISSUED_AT)
                    expected = "committed" if point == "after_pending" else "idempotent-replay"
                    self.assertEqual(result["outcome"], expected)
                    envelopes = list(recovered.iter_envelopes(validate=True))
                    self.assertEqual(len(envelopes), 1)
                    primary = [
                        event
                        for event in envelopes[0]["batch"]["events"]
                        if event["event_kind"] == "task.recorded"
                    ]
                    self.assertEqual(len(primary), 1)
                    self.assertEqual(recovered.head()["sequence"], 1)
                    self.assertEqual(list(recovered.pending.glob("*.json")), [])
                    recovered_replay = recovered.replay(collect_event_ids, [])
                    self.assertEqual(recovered_replay, baseline_replay)
                    self.assertEqual(
                        recovered.checkpoint_status()["semantic_digest"],
                        recovered_replay.semantic_digest,
                    )
                    self.assertEqual(
                        recovery_status["open_mode"], "full-replay-fallback"
                    )
                    self.assertIsNotNone(recovery_status["fallback_reason"])
                finally:
                    if recovered is not None:
                        recovered.close()
                    if store is not None:
                        store.close()
                    if baseline is not None:
                        baseline.close()

    def test_missing_or_corrupt_journal_checkpoint_falls_back_to_equal_replay(self) -> None:
        for damage in ("missing", "corrupt"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "state"
                store = EventStore(
                    root,
                    ACTIVATION,
                    implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                )
                recovered: _AuthoritativeEventStore | None = None
                verified: _AuthoritativeEventStore | None = None
                try:
                    for index in range(3):
                        store.commit(
                            command(index, store.head()["batch_digest"]),
                            created_at=ISSUED_AT,
                        )
                    expected = store.replay(collect_event_ids, [])
                    if damage == "missing":
                        store.checkpoint_path.unlink()
                    else:
                        store.checkpoint_path.write_bytes(canonical_bytes({"tampered": True}))

                    recovered = EventStore(
                        root,
                        ACTIVATION,
                        implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                    )
                    status = recovered.checkpoint_status()
                    actual = recovered.replay(collect_event_ids, [])
                    self.assertEqual(status["open_mode"], "full-replay-fallback")
                    self.assertIsNotNone(status["fallback_reason"])
                    self.assertEqual(actual, expected)
                    self.assertEqual(status["semantic_digest"], actual.semantic_digest)

                    verified = EventStore(
                        root,
                        ACTIVATION,
                        implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                    )
                    self.assertEqual(
                        verified.checkpoint_status()["open_mode"], "verified-checkpoint"
                    )
                    self.assertEqual(verified.replay(collect_event_ids, []), expected)
                finally:
                    if verified is not None:
                        verified.close()
                    if recovered is not None:
                        recovered.close()
                    store.close()

    def test_derived_checkpoint_crash_and_delta_replay_match_full_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            store = EventStore(
                root,
                ACTIVATION,
                implementation_closure_digest=IMPLEMENTATION_CLOSURE,
            )
            try:
                for index in range(3):
                    store.commit(
                        command(index, store.head()["batch_digest"]),
                        created_at=ISSUED_AT,
                    )
                initial = store.replay(collect_event_ids, [])

                with self.assertRaises(SimulatedCrash):
                    store.write_derived_state(
                        "before-write",
                        initial.state,
                        crash_hook=lambda point: point == "before_derived_checkpoint",
                    )
                self.assertIsNone(store.read_derived_state("before-write"))
                self.assertIsNotNone(store.derived_state_issue("before-write"))
                self.assertEqual(store.replay(collect_event_ids, []), initial)

                with self.assertRaises(SimulatedCrash):
                    store.write_derived_state(
                        "after-write",
                        initial.state,
                        crash_hook=lambda point: point == "after_derived_checkpoint",
                    )
                durable_after_crash = store.read_derived_state("after-write")
                self.assertIsNotNone(durable_after_crash)
                self.assertIsNone(store.derived_state_issue("after-write"))

                checkpoint = store.write_derived_state("delta", initial.state)
                store.commit(command(3, store.head()["batch_digest"]), created_at=ISSUED_AT)
                delta = store.replay_delta(collect_event_ids, checkpoint)
                full = store.replay(collect_event_ids, [])
                self.assertEqual(delta, full)
            finally:
                store.close()

    def test_missing_or_corrupt_derived_checkpoint_is_non_authoritative(self) -> None:
        for damage in ("missing", "corrupt"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "state"
                store = EventStore(
                    root,
                    ACTIVATION,
                    implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                )
                try:
                    store.commit(command(1, None), created_at=ISSUED_AT)
                    expected = store.replay(collect_event_ids, [])
                    before = set(store.derived_state_root.glob("*.json"))
                    store.write_derived_state("domain", expected.state)
                    created = set(store.derived_state_root.glob("*.json")) - before
                    self.assertEqual(len(created), 1)
                    checkpoint_path = created.pop()
                    if damage == "missing":
                        checkpoint_path.unlink()
                    else:
                        checkpoint_path.write_bytes(canonical_bytes({"tampered": True}))

                    self.assertIsNone(store.read_derived_state("domain"))
                    self.assertIsNotNone(store.derived_state_issue("domain"))
                    self.assertEqual(store.replay(collect_event_ids, []), expected)
                finally:
                    store.close()

    def test_replay_is_event_time_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            store = EventStore(
                root,
                ACTIVATION,
                implementation_closure_digest=IMPLEMENTATION_CLOSURE,
            )
            first_store: _AuthoritativeEventStore | None = None
            second_store: _AuthoritativeEventStore | None = None
            try:
                for index in range(3):
                    store.commit(command(index, store.head()["batch_digest"]), created_at=ISSUED_AT)

                reducer = lambda state, event: state + [event["event_id"]]
                first_store = EventStore(
                    root,
                    ACTIVATION,
                    implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                )
                first = first_store.replay(reducer, [])
                second_store = EventStore(
                    root,
                    ACTIVATION,
                    implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                )
                second = second_store.replay(reducer, [])
                self.assertEqual(first.state, second.state)
                self.assertEqual(first.semantic_digest, second.semantic_digest)
                self.assertEqual(first.head, second.head)
                self.assertEqual(first.batch_count, 3)
                self.assertEqual(first.event_count, 3)
            finally:
                if second_store is not None:
                    second_store.close()
                if first_store is not None:
                    first_store.close()
                store.close()

    def test_canonical_journal_tamper_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "state"
            store = EventStore(
                root,
                ACTIVATION,
                implementation_closure_digest=IMPLEMENTATION_CLOSURE,
            )
            try:
                store.commit(command(1, None), created_at=ISSUED_AT)
                journal = next(store.journal.glob("*.json"))
                envelope = json.loads(journal.read_text(encoding="utf-8"))
                envelope["batch"]["command_id"] = "command:attacker"
                store.close()
                journal.write_bytes(canonical_bytes(envelope))
                with self.assertRaises(JournalCorruption):
                    EventStore(
                        root,
                        ACTIVATION,
                        implementation_closure_digest=IMPLEMENTATION_CLOSURE,
                    )
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
