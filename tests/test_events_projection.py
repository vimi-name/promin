from __future__ import annotations

import copy
import hashlib
import json
import multiprocessing
import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

import promin.events as event_module
from promin.canonical import canonical_bytes as canonical_owner_bytes
from promin.canonical import digest_value as canonical_owner_digest
from promin.events import (
    CommandConflict,
    CommitStateSnapshot,
    DerivedCheckpointError,
    EventStore,
    EventStoreError,
    EventStorePolicy,
    ImplementationClosureMismatch,
    JournalCorruption,
    SimulatedCrash,
    CommitReadView,
    PreparedCommit,
    command_intent_identity,
    digest_value,
    state_binding_leaf_id,
    state_binding_value_digest,
)
from promin.projection import (
    ContinuationError,
    Projection,
    ProjectionError,
    ProjectionLimits,
    VerifiedInventoryInput,
    compile_relation_domains,
)


ACTIVATION = "a" * 64
ACTIVATION_RECORD_DIGEST = "b" * 64
IMPLEMENTATION = "1" * 64
NOW = "2026-07-17T12:00:00Z"
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_MODEL = json.loads(
    (PACKAGE_ROOT / "core" / "authority-model.json").read_text(encoding="utf-8")
)
SEMANTIC_MODEL = json.loads(
    (PACKAGE_ROOT / "core" / "semantic-model.json").read_text(encoding="utf-8")
)
POLICY_SET = json.loads(
    (PACKAGE_ROOT / "core" / "policy-set.json").read_text(encoding="utf-8")
)
PRESET = json.loads(
    (PACKAGE_ROOT / "presets" / "semantic-standard.json").read_text(
        encoding="utf-8"
    )
)

def event_store_policy(**overrides) -> EventStorePolicy:
    event = AUTHORITY_MODEL["event_contract"]
    mutation = AUTHORITY_MODEL["command_mutation_claim_rule"]
    record = {
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
        "derived_tail_batch_threshold": event[
            "derived_tail_batch_threshold"
        ],
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
    record.update(overrides)
    record["policy_digest"] = digest_value(record)
    return EventStorePolicy.from_compiled(record)


EVENT_STORE_POLICY = event_store_policy()

def projection_limits(
    *,
    event_policy: EventStorePolicy = EVENT_STORE_POLICY,
    owner_overrides: dict | None = None,
    runtime_overrides: dict | None = None,
) -> ProjectionLimits:
    continuation = AUTHORITY_MODEL["continuation_access_rule"]
    conformance = json.loads(
        (PACKAGE_ROOT / "core" / "conformance.json").read_text(encoding="utf-8")
    )
    selected_profile_id = "extended"
    selected_profile = PRESET["profiles"][selected_profile_id]
    default_budget = {
        "max_bytes": selected_profile["max_context_bytes"],
        "max_entities": selected_profile["max_entities"],
        "max_relations": selected_profile["max_relations"],
        "max_fanout_per_entity": selected_profile["max_fanout_per_entity"],
        "top_k": selected_profile["top_k"],
    }
    owner = {
        "record_type": "ProjectionLimits",
        "token_version": continuation["token_version"],
        "ranking_algorithm_id": continuation["ranking_algorithm_id"],
        "traversal_algorithm_id": continuation["traversal_algorithm_id"],
        "dependency_depth_hard_max": conformance[
            "dependency_depth_hard_max"
        ],
        "continuation_ttl_seconds_max": continuation["ttl_seconds_max"],
        "selected_profile_id": selected_profile_id,
        "selected_profile_digest": digest_value(selected_profile),
        "persistent_entity_types": [
            item["kind"] for item in SEMANTIC_MODEL["persistent_entities"]
        ],
        "default_budget": default_budget,
        "hard_budget": conformance["workcard_hard_ceiling"],
        "default_depth": selected_profile["default_dependency_depth"],
        "depth_min": continuation["depth_min"],
        "depth_max": conformance["dependency_depth_hard_max"],
        "default_ttl_seconds": continuation["default_ttl_seconds"],
        "ttl_min_seconds": continuation["ttl_min_seconds"],
        "ttl_max_seconds": continuation["ttl_seconds_max"],
        "max_token_bytes": conformance["scale_contracts"]["workcard"][
            "continuation_token_bytes_max"
        ],
        "max_continuation_state_bytes": conformance["scale_contracts"][
            "workcard"
        ]["continuation_state_bytes_max"],
        "max_query_bytes": POLICY_SET["derived_result_contracts"][
            "RetrievalPage"
        ]["query_bytes_max"],
        "min_result_bytes": continuation["min_result_bytes"],
        "max_resume_binding_fields": continuation["max_resume_binding_fields"],
        "max_resume_binding_key_chars": continuation[
            "max_resume_binding_key_chars"
        ],
        "max_resume_binding_value_bytes": continuation[
            "max_resume_binding_value_bytes"
        ],
        "max_resume_binding_bytes": continuation["max_resume_binding_bytes"],
        "required_resume_binding_fields": continuation[
            "required_resume_binding_fields"
        ],
    }
    owner.update(owner_overrides or {})
    runtime = {
        "event_store_policy": event_policy,
    }
    runtime.update(runtime_overrides or {})
    constructor = {
        **owner,
        "persistent_entity_types": tuple(owner["persistent_entity_types"]),
        "required_resume_binding_fields": tuple(
            owner["required_resume_binding_fields"]
        ),
    }
    return ProjectionLimits(
        **constructor,
        policy_digest=digest_value(owner),
        **runtime,
    )


PROJECTION_LIMITS = projection_limits()
RESUME_BINDING = {
    "activation_digest": ACTIVATION,
    "capability_id": "projection.read",
    "grant_claim_digest": "2" * 64,
    "grant_id": "grant:projection",
    "implementation_closure_digest": IMPLEMENTATION,
    "requested_scope_digest": "3" * 64,
    "revocation_epoch": "4" * 64,
    "subject_id": "subject:projection",
}


def _thaw(value):
    if isinstance(value, dict) or hasattr(value, "items"):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_thaw(item) for item in value]
    return value


def load_event_id_state(
    view: CommitReadView,
    envelopes,
) -> CommitStateSnapshot:
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


def state_binding_delta(
    command_copy: dict,
    relation_copies: list[dict],
    *,
    primary_value: dict | None = None,
) -> tuple[dict, ...]:
    payload = command_copy["payload"]
    if command_copy["command_kind"] == "task.transition":
        payload_type = "Task"
        if primary_value is None:
            raise AssertionError(
                "Task transition state binding requires the complete post-state Task"
            )
    else:
        payload_type = payload["record_type"]
    record_type = "Grant" if payload_type == "GrantRevocation" else payload_type
    leaf_id = state_binding_leaf_id(EVENT_STORE_POLICY, record_type, payload)
    event_kind = EVENT_STORE_POLICY.primary_events[command_copy["command_kind"]]
    if primary_value is None:
        if payload_type == "Grant":
            primary_value = {
                "record_type": "GrantAuthorityState",
                "grant": payload,
                "revocation": None,
            }
        elif EVENT_STORE_POLICY.state_binding_value_rules[record_type][
            "value_definition"
        ] == payload_type:
            primary_value = payload
    primary = {
        "leaf_type": record_type,
        "leaf_id": leaf_id,
        "operation": "set",
        "value_digest": (
            state_binding_value_digest(
                EVENT_STORE_POLICY,
                record_type,
                primary_value,
                event_kind=event_kind,
            )
            if primary_value is not None
            else digest_value(payload)
        ),
    }
    updates = [primary]
    updates.extend(
        {
            "leaf_type": "Relation",
            "leaf_id": relation_value["relation_id"],
            "operation": "set",
            "value_digest": digest_value(relation_value),
        }
        for relation_value in relation_copies
    )
    return tuple(sorted(updates, key=lambda value: (value["leaf_type"], value["leaf_id"])))


def prepare_event_id_state(
    view: CommitReadView,
    command_value,
    relations,
) -> PreparedCommit:
    command_copy = _thaw(command_value)
    relation_copies = [_thaw(value) for value in relations]
    return PreparedCommit(
        tuple(relation_copies),
        state_binding_delta(command_copy, relation_copies),
    )


def validate_event_id_state(
    _name: str,
    state,
    *,
    expected_binding_digest: str,
) -> bool:
    return True


def event_store_runtime_options() -> dict:
    return {
        "policy": EVENT_STORE_POLICY,
        "compiled_record_validator": lambda _definition, _value, **_kwargs: True,
        "command_validator": lambda _value, **_kwargs: True,
        "authorization_validator": lambda _value, **_kwargs: True,
        "event_validator": lambda _value, **_kwargs: True,
        "commit_state_loader": load_event_id_state,
        "commit_prepare_callback": prepare_event_id_state,
        "derived_state_validator": validate_event_id_state,
    }


def load_grant_state(view: CommitReadView, envelopes) -> CommitStateSnapshot:
    states: dict[str, dict] = {}
    for envelope in envelopes():
        for event in envelope["batch"]["events"]:
            grant_id = event["payload"].get("grant_id")
            if event["event_kind"] == "grant.issued" and isinstance(grant_id, str):
                states[grant_id] = {
                    "record_type": "GrantAuthorityState",
                    "grant": event["payload"],
                    "revocation": None,
                }
            elif event["event_kind"] == "grant.revoked" and isinstance(grant_id, str):
                if grant_id in states:
                    states[grant_id]["revocation"] = event["payload"]
    return CommitStateSnapshot(
        tuple(
            (grant_id, canonical_owner_bytes(states[grant_id]))
            for grant_id in sorted(states)
        ),
        view.head_sequence,
        view.head_digest,
        view.current_state_binding_digest,
    )


def prepare_grant_state(view, command_value, relations) -> PreparedCommit:
    command_copy = _thaw(command_value)
    relation_copies = [_thaw(value) for value in relations]
    states = {
        grant_id: json.loads(encoded)
        for grant_id, encoded in (view.state or ())
    }
    grant_id = command_copy["payload"].get("grant_id")
    if command_copy["command_kind"] == "grant.issue":
        states[grant_id] = {
            "record_type": "GrantAuthorityState",
            "grant": command_copy["payload"],
            "revocation": None,
        }
    elif command_copy["command_kind"] == "grant.revoke":
        if grant_id not in states:
            raise EventStoreError("Grant revocation target is unresolved")
        states[grant_id]["revocation"] = command_copy["payload"]
    else:
        authorization_grant_id = command_copy["authorization"].get("grant_id")
        authority_state = states.get(authorization_grant_id)
        if authority_state is None or authority_state.get("revocation") is not None:
            raise EventStoreError(
                "stale Grant rejected at the writer linearization point"
            )
    return PreparedCommit(
        tuple(relation_copies),
        state_binding_delta(
            command_copy,
            relation_copies,
            primary_value=states.get(grant_id),
        ),
    )


def validate_grant_state(_name, state, *, expected_binding_digest):
    return True


def grant_store_runtime_options() -> dict:
    return {
        "policy": EVENT_STORE_POLICY,
        "compiled_record_validator": lambda _definition, _value, **_kwargs: True,
        "command_validator": lambda _value, **_kwargs: True,
        "authorization_validator": lambda _value, **_kwargs: True,
        "event_validator": lambda _value, **_kwargs: True,
        "commit_state_loader": load_grant_state,
        "commit_prepare_callback": prepare_grant_state,
        "derived_state_validator": validate_grant_state,
    }


def revoke_grant_worker(event_root: str, ready, release, result_queue) -> None:
    try:
        store = EventStore(
            event_root,
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **grant_store_runtime_options(),
        )
        ready.set()
        if not release.wait(20):
            raise RuntimeError("worker release timed out")
        value = command(
            "command:revoke-worker",
            "grant.revoke",
            {"record_type": "GrantRevocation", "grant_id": "grant:stale"},
            store.head()["batch_digest"],
        )
        result_queue.put(("ok", store.commit(value, created_at=NOW)))
    except BaseException as exc:
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))


def command(command_id: str, kind: str, payload: dict, expected: str | None, key: str | None = None) -> dict:
    value = {
        "record_type": "CommandRequest",
        "command_id": command_id,
        "command_kind": kind,
        "subject_id": "subject:owner",
        "activation_digest": ACTIVATION,
        "idempotency_key": key or f"idempotency:{command_id}",
        "requested_scope": [{"selector_type": "task", "selector": payload.get("task_id", "task:all")}],
        "expected_head_digest": expected,
        "issued_at": NOW,
        "payload": payload,
        "authorization": {"kind": "root", "proof": "test-bound-proof"},
    }
    if kind in {"run.record", "gate.record"}:
        value["definition_digest"] = payload["definition_digest"]
    value["intent_digest"] = digest_value(command_intent_identity(value))
    return value


def lease_bound(value: dict, task_id: str) -> dict:
    value.update(
        {
            "workcard_task_id": task_id,
            "holder_authorization": {
                "kind": "grant",
                "grant_id": "grant:holder",
                "grant_claim_digest": "d" * 64,
            },
            "lease_id": "lease:mutation",
            "lease_generation": 1,
            "fencing_token": 1,
            "workcard_digest": "e" * 64,
            "context_digest": "f" * 64,
        }
    )
    value["intent_digest"] = digest_value(command_intent_identity(value))
    return value


def task(task_id: str, title: str) -> dict:
    return {
        "record_type": "Task",
        "task_id": task_id,
        "title": title,
        "status": "ready",
        "activation_digest": ACTIVATION,
    }


def relation(relation_id: str, source: str, target: str) -> dict:
    return {
        "record_type": "Relation",
        "relation_id": relation_id,
        "kind": "DEPENDS_ON",
        "source_type": "Task",
        "source_id": source,
        "target_type": "Task",
        "target_id": target,
        "activation_digest": ACTIVATION,
        "created_at": NOW,
    }


def gate_result(gate_id: str, run_id: str) -> dict:
    return {
        "record_type": "GateResult",
        "gate_id": gate_id,
        "run_id": run_id,
        "run_digest": "a" * 64,
        "definition_digest": "9" * 64,
        "status": "blocked",
        "outcome": "blocked",
        "pass_credit": False,
        "activation_digest": ACTIVATION,
        "candidate_digest": "c" * 64,
        "policy_digest": "d" * 64,
        "tool_digest": "e" * 64,
        "evidence_artifacts": [
            {
                "artifact_id": "artifact:gate",
                "artifact_record_digest": "f" * 64,
                "run_id": run_id,
                "run_digest": "a" * 64,
            }
        ],
    }


DOMAINS = compile_relation_domains(
    {"relations": [{"kind": "DEPENDS_ON", "source": ["Task"], "target": ["Task"]}]}
)


def inventory_row(path: str = "src/render.cpp", payload: dict | None = None) -> dict:
    file_digest = hashlib.sha256(path.encode("utf-8")).hexdigest()
    artifact_id = "artifact:file:" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:48]
    artifact = payload or {
        "record_type": "Artifact",
        "artifact_id": artifact_id,
        "artifact_kind": "product",
        "digest": file_digest,
        "media_type": "application/octet-stream",
        "size_bytes": 6,
    }
    return {
        "record_type": "InventoryProjectionRow",
        "path": path,
        "digest": file_digest,
        "size": 6,
        "semantic_proxy": {
            "id": artifact_id,
            "entity_type": "Artifact",
            "payload": artifact,
        },
    }


def verified_inventory(*rows: dict) -> VerifiedInventoryInput:
    stream = hashlib.sha256()
    for row in rows:
        stream.update(
            canonical_owner_bytes(
                {"path": row["path"], "digest": row["digest"], "size": row["size"]}
            )
        )
    return VerifiedInventoryInput(
        activation_digest=ACTIVATION,
        stream_digest=stream.hexdigest(),
        entry_count=len(rows),
        entries=tuple(rows),
    )


class EventsProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.authorized_times: list[str] = []

        def authorize(_command, *, evaluation_time):
            self.authorized_times.append(evaluation_time)
            return True

        options = event_store_runtime_options()
        options["authorization_validator"] = authorize
        self.store = EventStore(
            self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **options,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def commit_tasks(self, count: int) -> list[dict]:
        results = []
        for index in range(count):
            task_id = f"task:{index:03d}"
            auxiliary = [] if index == 0 else [relation(f"rel:{index:03d}", task_id, f"task:{index - 1:03d}")]
            cmd = command(f"command:{index:03d}", "task.record", task(task_id, f"compile renderer item {index}"), self.store.head()["batch_digest"])
            results.append(self.store.commit(cmd, auxiliary_relations=auxiliary, created_at=NOW))
        return results

    def test_lease_bound_command_binds_holder_authorization(self) -> None:
        candidate_value = command(
            "command:candidate",
            "candidate.record",
            {
                "record_type": "Candidate",
                "candidate_id": "candidate:immutable",
                "candidate_digest": "b" * 64,
            },
            None,
        )
        self.assertEqual(
            self.store.commit(candidate_value, created_at=NOW)["outcome"],
            "committed",
        )
        value = lease_bound(
            command(
                "command:mutation",
                "artifact.record",
                {
                    "record_type": "Artifact",
                    "artifact_id": "artifact:mutation",
                },
                self.store.head()["batch_digest"],
            ),
            "task:mutation",
        )
        committed = self.store.commit(value, created_at=NOW)
        envelope = list(self.store.iter_envelopes())[-1]
        self.assertEqual(envelope["batch"]["command_digest"], digest_value(value))

        altered = copy.deepcopy(value)
        altered["holder_authorization"]["grant_claim_digest"] = "0" * 64
        with self.assertRaisesRegex(EventStoreError, "intent digest mismatch"):
            self.store.commit(altered, created_at=NOW)
        altered["intent_digest"] = digest_value(command_intent_identity(altered))
        with self.assertRaises(CommandConflict):
            self.store.commit(altered, created_at=NOW)

        incomplete = copy.deepcopy(value)
        del incomplete["holder_authorization"]
        incomplete["intent_digest"] = digest_value(command_intent_identity(incomplete))
        with self.assertRaisesRegex(EventStoreError, "lease-bound command fields mismatch"):
            self.store.commit(incomplete, created_at=NOW)

        non_lease = command("command:non-lease", "task.record", task("task:plain", "Plain"), None)
        non_lease["holder_authorization"] = value["holder_authorization"]
        non_lease["intent_digest"] = digest_value(command_intent_identity(non_lease))
        with self.assertRaisesRegex(EventStoreError, "non-lease command"):
            self.store.commit(non_lease, created_at=NOW)

    def test_event_identity_uses_the_single_canonical_owner(self) -> None:
        self.assertIs(event_module.canonical_bytes, canonical_owner_bytes)
        self.assertIs(event_module.digest_value, canonical_owner_digest)
        value = {"record_type": "IdentityProbe", "name": "Promin"}
        self.assertTrue(event_module.canonical_bytes(value).endswith(b"\n"))
        self.assertEqual(event_module.digest_value(value), canonical_owner_digest(value))

    def test_event_batch_has_exact_twenty_fields_and_installed_activation_digest(self) -> None:
        self.commit_tasks(1)
        batch = next(self.store.iter_envelopes())["batch"]
        self.assertEqual(
            set(batch),
            {
                "record_type", "batch_id", "sequence", "previous_digest",
                "created_at", "command_id", "idempotency_key",
                "activation_record_digest", "events", "subject_id",
                "command_intent_digest", "command_digest",
                "authorization_digest", "previous_authority_commitment",
                "authority_commitment", "cumulative_event_count",
                "event_semantic_digest", "state_binding_delta",
                "cumulative_state_binding_update_count", "state_binding_digest",
            },
        )
        self.assertEqual(len(batch), 20)
        self.assertEqual(batch["activation_record_digest"], ACTIVATION_RECORD_DIGEST)

    def test_checkpoint_leaf_identity_and_digest_have_one_event_store_owner(self) -> None:
        value = task("task:checkpoint-owner", "checkpoint identity owner")
        self.store.commit(
            command(
                "command:checkpoint-owner",
                "task.record",
                value,
                None,
            ),
            created_at=NOW,
        )
        self.assertEqual(
            self.store.validate_state_binding_leaves(
                [{"leaf_type": "Task", "value": value}],
                expected_head=self.store.head(),
            ),
            next(self.store.iter_envelopes())["batch"]["state_binding_digest"],
        )
        caller_owned = {
            "leaf_type": "Task",
            "leaf_id": value["task_id"],
            "value": value,
        }
        with self.assertRaisesRegex(DerivedCheckpointError, "fields mismatch"):
            self.store.validate_state_binding_leaves(
                [caller_owned],
                expected_head=self.store.head(),
            )

    def test_event_store_policy_is_digest_bound_and_leaf_type_closed(self) -> None:
        compiled = EVENT_STORE_POLICY.as_compiled()
        self.assertEqual(
            compiled["policy_digest"],
            digest_value({
                key: value
                for key, value in compiled.items()
                if key != "policy_digest"
            }),
        )
        forged = copy.deepcopy(compiled)
        forged["max_command_bytes"] -= 1
        with self.assertRaisesRegex(EventStoreError, "policy digest mismatch"):
            EventStorePolicy.from_compiled(forged)

        def unknown_leaf(_view, command_value, relations):
            command_copy = _thaw(command_value)
            return PreparedCommit(
                tuple(_thaw(value) for value in relations),
                ({
                    "leaf_type": "UnknownState",
                    "leaf_id": command_copy["payload"]["task_id"],
                    "operation": "set",
                    "value_digest": digest_value(command_copy["payload"]),
                },),
            )

        guarded = EventStore(
            self.root / "unknown-leaf-events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **{
                **event_store_runtime_options(),
                "commit_prepare_callback": unknown_leaf,
            },
        )
        with self.assertRaisesRegex(EventStoreError, "leaf_type is not Core-owned"):
            guarded.commit(
                command(
                    "command:unknown-leaf",
                    "task.record",
                    task("task:unknown-leaf", "must reject"),
                    None,
                ),
                created_at=NOW,
            )
        self.assertEqual(list(guarded.journal.glob("*.json")), [])

    def test_command_rejects_operational_key_fields_and_paths(self) -> None:
        secret_field = task("task:secret-field", "not persisted")
        secret_field["token_key"] = "local-runtime-material"
        with self.assertRaisesRegex(EventStoreError, "reserved operational key material field"):
            self.store.commit(
                command("command:secret-field", "task.record", secret_field, None),
                created_at=NOW,
            )

        secret_path = task("task:secret-path", "C:/project/.promin/state/secrets/continuation.key")
        with self.assertRaisesRegex(EventStoreError, "reserved operational key path"):
            self.store.commit(
                command("command:secret-path", "task.record", secret_path, None),
                created_at=NOW,
            )

    def test_journal_secret_guard_cannot_be_bypassed_by_validate_false(self) -> None:
        self.store.commit(
            command("command:journal-secret", "task.record", task("task:journal-secret", "plain"), None),
            created_at=NOW,
        )
        path = next(self.store.journal.glob("*.json"))
        envelope = json.loads(path.read_text(encoding="utf-8"))
        envelope["command"]["payload"]["token_key_material"] = "must-not-persist"
        self.store.close()
        path.write_bytes(canonical_owner_bytes(envelope))
        with self.assertRaisesRegex(JournalCorruption, "reserved operational key material field"):
            reopened = EventStore(
                self.root / "events",
                active_activation_digest=ACTIVATION,
                activation_record_digest=ACTIVATION_RECORD_DIGEST,
                implementation_closure_digest=IMPLEMENTATION,
                **event_store_runtime_options(),
            )
            list(reopened.iter_envelopes(validate=True))

    def test_journal_secret_path_guard_cannot_be_bypassed_by_validate_false(self) -> None:
        self.store.commit(
            command("command:journal-path", "task.record", task("task:journal-path", "plain"), None),
            created_at=NOW,
        )
        path = next(self.store.journal.glob("*.json"))
        envelope = json.loads(path.read_text(encoding="utf-8"))
        envelope["command"]["payload"]["path"] = ".promin/state/secrets/continuation.key"
        self.store.close()
        path.write_bytes(canonical_owner_bytes(envelope))
        with self.assertRaisesRegex(JournalCorruption, "reserved operational key path"):
            reopened = EventStore(
                self.root / "events",
                active_activation_digest=ACTIVATION,
                activation_record_digest=ACTIVATION_RECORD_DIGEST,
                implementation_closure_digest=IMPLEMENTATION,
                **event_store_runtime_options(),
            )
            list(reopened.iter_envelopes(validate=True))

    def test_derived_state_rejects_operational_key_fields_and_paths(self) -> None:
        with self.assertRaisesRegex(EventStoreError, "reserved operational key material field"):
            self.store.write_derived_state("runtime:secret-field", {"hmac_key": "must-not-persist"})
        with self.assertRaisesRegex(EventStoreError, "reserved operational key path"):
            self.store.write_derived_state(
                "runtime:secret-path",
                {"path": "C:\\project\\.promin\\state\\secrets\\continuation.key"},
            )

    def test_one_command_one_primary_event_and_unique_identities(self) -> None:
        first = command("command:one", "task.record", task("task:one", "one"), None)
        original_relation = relation("rel:one", "task:one", "task:root")
        result = self.store.commit(first, auxiliary_relations=[original_relation], created_at=NOW)
        self.assertEqual(result["outcome"], "committed")
        self.assertEqual(self.store.head()["batch_digest"], result["batch_digest"])
        retry = self.store.commit(first, auxiliary_relations=[original_relation], created_at=NOW)
        self.assertEqual(retry["outcome"], "idempotent-replay")
        altered_relation = relation("rel:one", "task:one", "task:different")
        with self.assertRaises(CommandConflict):
            self.store.commit(first, auxiliary_relations=[altered_relation], created_at=NOW)
        second_relation = relation("rel:two", "task:one", "task:other")
        ordered_command = command("command:ordered", "task.record", task("task:ordered", "ordered"), result["batch_digest"])
        ordered_result = self.store.commit(
            ordered_command,
            auxiliary_relations=[original_relation, second_relation],
            created_at=NOW,
        )
        self.assertEqual(ordered_result["outcome"], "committed")
        with self.assertRaises(CommandConflict):
            self.store.commit(
                ordered_command,
                auxiliary_relations=[second_relation, original_relation],
                created_at=NOW,
            )
        changed = copy.deepcopy(first)
        changed["payload"]["title"] = "changed"
        changed["intent_digest"] = digest_value(command_intent_identity(changed))
        with self.assertRaises(CommandConflict):
            self.store.commit(changed, created_at=NOW)
        second = command("command:two", "task.record", task("task:two", "two"), result["batch_digest"], key=first["idempotency_key"])
        with self.assertRaises(CommandConflict):
            self.store.commit(second, created_at=NOW)
        envelope = next(self.store.iter_envelopes())
        self.assertEqual(len([event for event in envelope["batch"]["events"] if event["event_kind"] == "task.recorded"]), 1)
        self.assertEqual(envelope["batch"]["events"][0]["payload"], first["payload"])

    def test_expected_head_batch_ceiling_and_event_time_replay(self) -> None:
        bad = command("command:bad", "task.record", task("task:bad", "bad"), "f" * 64)
        with self.assertRaises(CommandConflict):
            self.store.commit(bad, created_at=NOW)
        too_many = [relation(f"rel:{index}", "task:a", "task:b") for index in range(128)]
        good = command("command:good", "task.record", task("task:good", "good"), None)
        with self.assertRaisesRegex(Exception, "ceiling"):
            self.store.commit(good, auxiliary_relations=too_many, created_at=NOW)
        self.store.commit(good, created_at=NOW)
        replay = self.store.replay(lambda state, event: state + [event["event_id"]], [])
        self.assertEqual(replay.batch_count, 1)
        self.assertEqual(replay.event_count, 1)
        self.assertEqual(self.authorized_times, [NOW] * 2)

    def test_unbound_commit_writes_no_authority_event(self) -> None:
        event_root = self.root / "unbound"
        store = EventStore(
            event_root,
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            policy=EVENT_STORE_POLICY,
            compiled_record_validator=lambda _definition, _value, **_kwargs: True,
            command_validator=lambda _value, **_kwargs: True,
            authorization_validator=lambda _value, **_kwargs: True,
            event_validator=lambda _value, **_kwargs: True,
        )
        value = command(
            "command:unbound",
            "task.record",
            task("task:unbound", "must not commit"),
            None,
        )
        with self.assertRaisesRegex(EventStoreError, "prepare callback"):
            store.commit(value, created_at=NOW)
        self.assertEqual(store.head()["sequence"], 0)
        self.assertEqual(list(store.journal.glob("*.json")), [])
        self.assertEqual(list(store.pending.glob("*.json")), [])

    def test_compiled_event_and_batch_validation_is_operation_aware(self) -> None:
        calls: list[tuple[str, str]] = []

        def compiled(definition, _value, *, evaluation_time, operation):
            if definition == "EventStorePolicy":
                self.assertEqual(operation, "read")
            else:
                self.assertEqual(evaluation_time, NOW)
            calls.append((definition, operation))
            return True

        options = event_store_runtime_options()
        options["compiled_record_validator"] = compiled
        store = EventStore(
            self.root / "compiled-validation",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **options,
        )
        self.assertIn(("EventStorePolicy", "read"), calls)
        store.commit(
            command(
                "command:compiled-validation",
                "task.record",
                task("task:compiled-validation", "compiled"),
                None,
            ),
            created_at=NOW,
        )
        self.assertIn(("Event", "commit"), calls)
        self.assertIn(("EventBatch", "commit"), calls)
        calls.clear()
        store.replay(lambda state, event: state + [event["event_id"]], [])
        self.assertIn(("CommandRequest", "replay"), calls)
        self.assertIn(("Event", "replay"), calls)
        self.assertIn(("EventBatch", "replay"), calls)

    def test_loaded_state_must_match_journal_owned_binding_before_append(self) -> None:
        self.store.commit(
            command(
                "command:bound-state",
                "task.record",
                task("task:bound-state", "bound"),
                None,
            ),
            created_at=NOW,
        )
        expected_head = self.store.head()["batch_digest"]
        before_paths = sorted(self.store.journal.glob("*.json"))
        stale = EventStore(
            self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            policy=EVENT_STORE_POLICY,
            compiled_record_validator=lambda _definition, _value, **_kwargs: True,
            command_validator=lambda _value, **_kwargs: True,
            authorization_validator=lambda _value, **_kwargs: True,
            event_validator=lambda _value, **_kwargs: True,
            commit_state_loader=lambda view, _envelopes: CommitStateSnapshot(
                ("e:forged",),
                view.head_sequence,
                view.head_digest,
                "0" * 64,
            ),
            commit_prepare_callback=prepare_event_id_state,
            derived_state_validator=validate_event_id_state,
        )
        with self.assertRaisesRegex(JournalCorruption, "stale state binding"):
            stale.commit(
                command(
                    "command:after-forged-state",
                    "task.record",
                    task("task:after-forged-state", "must not commit"),
                    expected_head,
                ),
                created_at=NOW,
            )
        self.assertEqual(stale.refresh()["batch_digest"], expected_head)
        self.assertEqual(sorted(stale.journal.glob("*.json")), before_paths)

    def test_multiprocess_stale_grant_and_head_fail_before_authority_append(self) -> None:
        event_root = self.root / "multiprocess-linearization"
        store = EventStore(
            event_root,
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **grant_store_runtime_options(),
        )
        issued = command(
            "command:grant-worker",
            "grant.issue",
            {"record_type": "Grant", "grant_id": "grant:stale"},
            None,
        )
        store.commit(issued, created_at=NOW)
        stale_head = store.head()["batch_digest"]

        context = multiprocessing.get_context("spawn")
        ready = context.Event()
        release = context.Event()
        result_queue = context.Queue()
        worker = context.Process(
            target=revoke_grant_worker,
            args=(str(event_root), ready, release, result_queue),
        )
        worker.start()
        self.assertTrue(ready.wait(20))
        release.set()
        status, detail = result_queue.get(timeout=20)
        worker.join(20)
        self.assertFalse(worker.is_alive())
        self.assertEqual(worker.exitcode, 0)
        self.assertEqual(status, "ok", detail)
        current_head = store.refresh()["batch_digest"]
        self.assertNotEqual(current_head, stale_head)

        stale_grant = command(
            "command:stale-grant",
            "task.record",
            task("task:stale-grant", "must reject"),
            current_head,
        )
        stale_grant["authorization"] = {
            "kind": "grant",
            "grant_id": "grant:stale",
        }
        with self.assertRaisesRegex(EventStoreError, "stale Grant"):
            store.commit(stale_grant, created_at=NOW)

        callback_called = False

        def must_not_prepare(*_args):
            nonlocal callback_called
            callback_called = True
            raise AssertionError("stale HEAD reached prepare callback")

        guarded_store = EventStore(
            event_root,
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **{
                **grant_store_runtime_options(),
                "commit_prepare_callback": must_not_prepare,
            },
        )

        stale_expected_head = command(
            "command:stale-head",
            "task.record",
            task("task:stale-head", "must reject"),
            stale_head,
        )
        with self.assertRaisesRegex(CommandConflict, "expected HEAD"):
            guarded_store.commit(
                stale_expected_head,
                created_at=NOW,
            )
        self.assertFalse(callback_called)
        self.assertEqual(store.refresh()["sequence"], 2)

    def test_crash_recovery_after_each_durable_point(self) -> None:
        for point in (
            "after_pending",
            "after_batch",
            "after_authority_segment",
            "after_authority_root",
            "after_head",
            "after_state_binding_index",
            "before_checkpoint",
            "after_checkpoint",
        ):
            event_root = self.root / point
            store = EventStore(
                event_root,
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
                **event_store_runtime_options(),
            )
            cmd = command(f"command:{point}", "task.record", task(f"task:{point}", point), None)
            with self.assertRaises(SimulatedCrash):
                store.commit(cmd, created_at=NOW, crash_hook=lambda current, wanted=point: current == wanted)
            recovered = EventStore(
                event_root,
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
                **event_store_runtime_options(),
            )
            if point == "after_pending":
                self.assertEqual(recovered.head()["sequence"], 0)
                self.assertEqual(recovered.commit(cmd, created_at=NOW)["outcome"], "committed")
            else:
                self.assertEqual(recovered.head()["sequence"], 1)
                self.assertEqual(recovered.commit(cmd, created_at=NOW)["outcome"], "idempotent-replay")

    def test_verified_checkpoint_reopen_avoids_full_recovery_and_uses_targeted_index(self) -> None:
        results = self.commit_tasks(3)
        expected_semantic_digest = self.store.replay(lambda state, event: state, {}).semantic_digest
        with mock.patch.object(EventStore, "_recover_locked", side_effect=AssertionError("full replay used")):
            reopened = EventStore(
                self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
                **event_store_runtime_options(),
            )
            status = reopened.checkpoint_status()
            self.assertEqual(status["open_mode"], "verified-checkpoint")
            self.assertFalse(status["authoritative"])
            self.assertEqual(status["batch_count"], 3)
            self.assertEqual(status["semantic_digest"], expected_semantic_digest)
            first = reopened.read_envelope(results[0]["batch_digest"])
            self.assertEqual(first["command"]["command_id"], "command:000")
            retried = reopened.commit(
                command("command:000", "task.record", task("task:000", "compile renderer item 0"), None),
                created_at=NOW,
            )
            self.assertEqual(retried["outcome"], "idempotent-replay")

    def test_event_identity_index_is_compact_exact_and_rebuildable(self) -> None:
        event_count = self.store.max_events_per_batch
        auxiliary = [
            relation(f"rel:compact:{index:03d}", "task:compact", f"task:target:{index:03d}")
            for index in range(event_count - 1)
        ]
        self.store.commit(
            command(
                "command:compact",
                "task.record",
                task("task:compact", "compact event identity index"),
                None,
            ),
            auxiliary_relations=auxiliary,
            created_at=NOW,
        )
        write_metrics = self.store.last_commit_write_metrics()
        envelope = next(self.store.iter_envelopes(validate=True))
        event_ids = [event["event_id"] for event in envelope["batch"]["events"]]
        checkpoint = json.loads(self.store.checkpoint_path.read_text(encoding="utf-8"))
        generation_root = self.store.index_root / checkpoint["index_generation"]
        database_path = generation_root / "event-identities.sqlite3"
        state_binding_path = generation_root / "state-binding.sqlite3"

        self.assertEqual(len(event_ids), event_count)
        self.assertTrue(database_path.is_file())
        self.assertTrue(state_binding_path.is_file())
        self.assertFalse((generation_root / "event").exists())
        self.assertEqual(len(list((generation_root / "packages").glob("*.json"))), 1)
        with closing(sqlite3.connect(database_path)) as connection:
            binding = connection.execute(
                "SELECT head_sequence, event_count FROM binding WHERE singleton = 1"
            ).fetchone()
            indexed = connection.execute("SELECT COUNT(*) FROM event_identity").fetchone()
        self.assertEqual(binding, (1, event_count))
        self.assertEqual(indexed, (event_count,))
        self.assertEqual(write_metrics["state_binding_updates"], event_count)
        self.assertLessEqual(
            write_metrics["state_binding_node_writes"], event_count * 257
        )
        self.assertEqual(write_metrics["journal_checkpoint_writes"], 1)
        self.assertLess(
            write_metrics["logical_final_bytes"]
            / write_metrics["state_binding_updates"],
            65_536,
        )
        self.assertEqual(
            len(list((self.root / "events").glob("journal-checkpoint.json"))),
            1,
        )

        reopened = EventStore(
            self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **event_store_runtime_options(),
        )
        self.assertEqual(reopened.checkpoint_status()["open_mode"], "verified-checkpoint")
        middle_event_id = event_ids[len(event_ids) // 2]
        for event_id in (event_ids[0], middle_event_id, event_ids[-1]):
            entry = reopened._read_index_entry("event", event_id)
            self.assertIsNotNone(entry)
            self.assertEqual(entry["identity"], event_id)

        expected = reopened.replay(lambda state, event: state + [event["event_id"]], [])
        with closing(sqlite3.connect(database_path)) as connection:
            connection.execute(
                "DELETE FROM event_identity WHERE event_id = ?", (middle_event_id,)
            )
            connection.commit()
        recovered = EventStore(
            self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **event_store_runtime_options(),
        )
        self.assertEqual(
            recovered.checkpoint_status()["open_mode"], "full-replay-fallback"
        )
        self.assertEqual(
            recovered.replay(lambda state, event: state + [event["event_id"]], []),
            expected,
        )
        count_rebuilt_checkpoint = json.loads(
            recovered.checkpoint_path.read_text(encoding="utf-8")
        )
        count_rebuilt_database_path = (
            recovered.index_root
            / count_rebuilt_checkpoint["index_generation"]
            / "event-identities.sqlite3"
        )
        with closing(sqlite3.connect(count_rebuilt_database_path)) as connection:
            rebuilt = connection.execute("SELECT COUNT(*) FROM event_identity").fetchone()
        self.assertEqual(rebuilt, (event_count,))

        count_rebuilt_database_path.write_bytes(b"not-a-sqlite-database")
        unreadable_recovered = EventStore(
            self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **event_store_runtime_options(),
        )
        self.assertEqual(
            unreadable_recovered.checkpoint_status()["open_mode"],
            "full-replay-fallback",
        )
        self.assertEqual(
            unreadable_recovered.replay(
                lambda state, event: state + [event["event_id"]], []
            ),
            expected,
        )

    def test_corrupt_touched_state_leaf_forces_full_replay_before_append(self) -> None:
        self.store.commit(
            command(
                "command:state-leaf-initial",
                "task.record",
                task("task:state-leaf", "initial"),
                None,
            ),
            created_at=NOW,
        )
        checkpoint = json.loads(self.store.checkpoint_path.read_text(encoding="utf-8"))
        state_path = (
            self.store.index_root
            / checkpoint["index_generation"]
            / "state-binding.sqlite3"
        )
        task_leaf_key = event_module._state_leaf_key_digest(
            {"leaf_type": "Task", "leaf_id": "task:state-leaf"}
        )
        task_leaf_prefix = event_module._state_prefix(task_leaf_key, 256)
        with closing(sqlite3.connect(state_path)) as connection:
            updated = connection.execute(
                "UPDATE node SET digest = ? WHERE depth = 256 AND prefix = ?",
                (b"x" * 32, task_leaf_prefix),
            ).rowcount
            connection.commit()
        self.assertEqual(updated, 1)

        reopened = EventStore(
            self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **event_store_runtime_options(),
        )
        self.assertEqual(reopened.checkpoint_status()["open_mode"], "verified-checkpoint")
        reopened.commit(
            command(
                "command:state-leaf-update",
                "task.record",
                task("task:state-leaf", "updated"),
                reopened.head()["batch_digest"],
            ),
            created_at=NOW,
        )
        self.assertEqual(
            reopened.checkpoint_status()["open_mode"], "full-replay-fallback"
        )
        self.assertEqual(reopened.head()["sequence"], 2)

    def test_missing_or_corrupt_journal_checkpoint_falls_back_with_equal_digest(self) -> None:
        self.commit_tasks(3)
        expected = self.store.replay(lambda state, event: state + [event["event_id"]], [])
        self.store.checkpoint_path.write_bytes(b"{not-json")
        recovered = EventStore(
            self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **event_store_runtime_options(),
        )
        corrupt_status = recovered.checkpoint_status()
        self.assertEqual(corrupt_status["open_mode"], "full-replay-fallback")
        self.assertIn("DerivedCheckpointError", corrupt_status["fallback_reason"])
        replayed = recovered.replay(lambda state, event: state + [event["event_id"]], [])
        self.assertEqual(replayed.state, expected.state)
        self.assertEqual(replayed.semantic_digest, expected.semantic_digest)

        recovered.checkpoint_path.unlink()
        missing = EventStore(
            self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **event_store_runtime_options(),
        )
        missing_status = missing.checkpoint_status()
        self.assertEqual(missing_status["open_mode"], "full-replay-fallback")
        self.assertIn("missing", missing_status["fallback_reason"])
        self.assertEqual(missing_status["semantic_digest"], expected.semantic_digest)

    def test_existing_event_state_rejects_another_implementation_closure(self) -> None:
        self.commit_tasks(1)
        with self.assertRaisesRegex(
            ImplementationClosureMismatch,
            "event state implementation closure mismatch",
        ):
            EventStore(
                self.root / "events",
                active_activation_digest=ACTIVATION,
                activation_record_digest=ACTIVATION_RECORD_DIGEST,
                implementation_closure_digest="2" * 64,
                **event_store_runtime_options(),
            )

    def test_existing_event_state_rejects_a_missing_implementation_binding(self) -> None:
        self.commit_tasks(1)
        self.store.implementation_binding_path.unlink()
        with self.assertRaisesRegex(
            ImplementationClosureMismatch,
            "binding is missing for existing event state",
        ):
            EventStore(
                self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
                **event_store_runtime_options(),
            )

    def test_existing_event_state_rejects_a_corrupt_implementation_binding(self) -> None:
        self.commit_tasks(1)
        self.store.implementation_binding_path.write_bytes(b"{not-json")
        with self.assertRaisesRegex(ImplementationClosureMismatch, "binding is unreadable"):
            EventStore(
                self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
                **event_store_runtime_options(),
            )

    def test_journal_checkpoint_implementation_closure_mismatch_does_not_fallback(self) -> None:
        self.commit_tasks(1)
        checkpoint = json.loads(self.store.checkpoint_path.read_text(encoding="utf-8"))
        checkpoint["implementation_closure_digest"] = "2" * 64
        checkpoint.pop("checkpoint_digest")
        checkpoint["checkpoint_digest"] = canonical_owner_digest(checkpoint)
        self.store.checkpoint_path.write_bytes(canonical_owner_bytes(checkpoint))
        with self.assertRaisesRegex(
            ImplementationClosureMismatch,
            "journal checkpoint implementation closure mismatch",
        ):
            EventStore(
                self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
                **event_store_runtime_options(),
            )

    def test_corrupt_targeted_index_falls_back_to_authoritative_events(self) -> None:
        self.commit_tasks(1)
        reopened = EventStore(
            self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **event_store_runtime_options(),
        )
        self.assertEqual(reopened.checkpoint_status()["open_mode"], "verified-checkpoint")
        checkpoint = json.loads(reopened.checkpoint_path.read_text(encoding="utf-8"))
        index_path = next(
            (reopened.index_root / checkpoint["index_generation"] / "command").glob("*.json")
        )
        index_path.write_bytes(b"{corrupt")
        original = command("command:000", "task.record", task("task:000", "compile renderer item 0"), None)
        retried = reopened.commit(original, created_at=NOW)
        self.assertEqual(retried["outcome"], "idempotent-replay")
        self.assertEqual(reopened.checkpoint_status()["open_mode"], "full-replay-fallback")

    def test_derived_state_checkpoint_replays_only_delta_with_equal_digest(self) -> None:
        self.commit_tasks(2)
        reducer = lambda state, event: state + [event["event_id"]]
        at_checkpoint = self.store.replay(reducer, [])
        written = self.store.write_derived_state("runtime:test", at_checkpoint.state)
        self.assertEqual(written["head"]["sequence"], 2)
        self.assertFalse(written["authoritative"])

        for index in range(2, 4):
            task_id = f"task:{index:03d}"
            cmd = command(
                f"command:{index:03d}",
                "task.record",
                task(task_id, f"compile renderer item {index}"),
                self.store.head()["batch_digest"],
            )
            self.store.commit(
                cmd,
                auxiliary_relations=[relation(f"rel:{index:03d}", task_id, f"task:{index - 1:03d}")],
                created_at=NOW,
            )

        reopened = EventStore(
            self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **event_store_runtime_options(),
        )
        stale = reopened.read_derived_state("runtime:test")
        self.assertIsNotNone(stale)
        self.assertEqual(stale["head"]["sequence"], 2)
        delta_sequences = [envelope["batch"]["sequence"] for envelope in reopened.iter_envelopes_after(stale["head"])]
        self.assertEqual(delta_sequences, [3, 4])
        incremental = reopened.replay_delta(reducer, stale)
        full = reopened.replay(reducer, [])
        self.assertEqual(incremental.state, full.state)
        self.assertEqual(incremental.head, full.head)
        self.assertEqual(incremental.event_count, full.event_count)
        self.assertEqual(incremental.semantic_digest, full.semantic_digest)

        current = reopened.write_derived_state("runtime:test", full.state)
        exact = reopened.replay_delta(reducer, current)
        self.assertEqual(exact.state, full.state)
        self.assertEqual(exact.semantic_digest, full.semantic_digest)

    def test_corrupt_derived_state_is_a_non_authoritative_cache_miss(self) -> None:
        self.commit_tasks(1)
        self.store.write_derived_state("runtime:test", {"task_ids": ["task:000"]})
        state_path = next(self.store.derived_state_root.glob("*.json"))
        value = json.loads(state_path.read_text(encoding="utf-8"))
        value["state"]["task_ids"].append("task:forged")
        state_path.write_bytes(canonical_owner_bytes(value))
        self.assertIsNone(self.store.read_derived_state("runtime:test"))
        self.assertIn("digest mismatch", self.store.derived_state_issue("runtime:test"))

    def test_historical_tamper_is_rejected_by_targeted_read_and_full_recovery(self) -> None:
        self.commit_tasks(3)
        first_path = sorted((self.root / "events" / "journal").glob("*.json"))[0]
        tampered = json.loads(first_path.read_text(encoding="utf-8"))
        tampered["batch"]["events"][0]["payload"]["title"] = "forged"
        self.store.close()
        first_path.write_bytes(canonical_owner_bytes(tampered))
        with self.assertRaises(JournalCorruption):
            EventStore(
                self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
                **event_store_runtime_options(),
            )

    def test_missing_historical_journal_prefix_is_rejected_before_mutation(self) -> None:
        self.commit_tasks(3)
        self.store.close()
        sorted(self.store.journal.glob("*.json"))[0].unlink()
        with self.assertRaises(JournalCorruption):
            EventStore(
                self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
                **event_store_runtime_options(),
            )

    def test_forged_checkpoint_and_rehashed_sidecars_cannot_change_journal_state(self) -> None:
        self.commit_tasks(2)
        state = self.store.replay(
            lambda values, event: values + [event["event_id"]], []
        ).state
        self.store.write_derived_state("runtime:test", state)
        state_path = next(self.store.derived_state_root.glob("*.json"))
        checkpoint = json.loads(state_path.read_text(encoding="utf-8"))
        checkpoint["state"].append("e:forged-checkpoint-state")
        checkpoint["state_digest"] = digest_value(checkpoint["state"])
        checkpoint["authority_state_binding_digest"] = checkpoint["state_digest"]
        checkpoint.pop("checkpoint_digest")
        checkpoint["checkpoint_digest"] = digest_value(checkpoint)
        root = json.loads(self.store.authority_head_path.read_text(encoding="utf-8"))
        generation = root["generation"]
        segment_path = self.store._authority_segment_path(generation, 2)
        segment = json.loads(segment_path.read_text(encoding="utf-8"))
        segment["state_binding_digest"] = checkpoint["state_digest"]
        segment.pop("segment_digest")
        segment["segment_digest"] = digest_value(segment)
        root["state_binding_digest"] = checkpoint["state_digest"]
        root.pop("root_digest")
        root["root_digest"] = digest_value(root)
        journal_checkpoint = json.loads(
            self.store.checkpoint_path.read_text(encoding="utf-8")
        )
        journal_checkpoint["state_binding_digest"] = checkpoint["state_digest"]
        journal_checkpoint["authority_root_digest"] = root["root_digest"]
        journal_checkpoint.pop("checkpoint_digest")
        journal_checkpoint["checkpoint_digest"] = digest_value(journal_checkpoint)
        self.store.close()
        state_path.write_bytes(canonical_owner_bytes(checkpoint))
        segment_path.write_bytes(canonical_owner_bytes(segment))
        self.store.authority_head_path.write_bytes(canonical_owner_bytes(root))
        self.store.checkpoint_path.write_bytes(canonical_owner_bytes(journal_checkpoint))

        reopened = EventStore(
            self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **event_store_runtime_options(),
        )
        self.assertEqual(
            reopened.checkpoint_status()["open_mode"], "full-replay-fallback"
        )
        self.assertIsNone(reopened.read_derived_state("runtime:test"))
        self.assertTrue(reopened.checkpoint_status()["state_binding_available"])

    def test_tampered_journal_rejected(self) -> None:
        self.commit_tasks(1)
        path = next((self.root / "events" / "journal").glob("*.json"))
        value = json.loads(path.read_text(encoding="utf-8"))
        value["batch"]["events"][0]["payload"]["title"] = "tampered"
        self.store.close()
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        with self.assertRaises(JournalCorruption):
            EventStore(
                self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
                **event_store_runtime_options(),
            )

    def test_auxiliary_relation_tamper_is_rejected_by_derived_identities(self) -> None:
        value = command("command:relation-tamper", "task.record", task("task:relation-tamper", "tamper"), None)
        auxiliary = relation("rel:tamper", "task:relation-tamper", "task:root")
        self.store.commit(value, auxiliary_relations=[auxiliary], created_at=NOW)
        path = next((self.root / "events" / "journal").glob("*.json"))
        envelope = json.loads(path.read_text(encoding="utf-8"))
        envelope["batch"]["events"][1]["payload"]["target_id"] = "task:attacker"
        self.store.close()
        path.write_bytes(canonical_owner_bytes(envelope))
        with self.assertRaisesRegex(
            JournalCorruption,
            "state binding value digest differs from exact Event payload",
        ):
            EventStore(
                self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
                **event_store_runtime_options(),
            )

    def test_gate_result_is_one_primary_event_idempotent_and_tamper_evident(self) -> None:
        payload = gate_result("gate:strict", "run:gate:001")
        value = lease_bound(command("command:gate:001", "gate.record", payload, None), "task:gate")
        committed = self.store.commit(value, created_at=NOW)
        self.assertEqual(committed["outcome"], "committed")
        self.assertEqual(self.store.commit(value, created_at=NOW)["outcome"], "idempotent-replay")
        envelope = next(self.store.iter_envelopes())
        primary = [event for event in envelope["batch"]["events"] if event["event_kind"] == "gate.recorded"]
        self.assertEqual(len(primary), 1)
        self.assertEqual(primary[0]["payload"], payload)

        projection = Projection(
            self.root / "gate.sqlite",
            token_key=b"g" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        projection.rebuild(self.store)
        projected = projection.search(
            "gate:strict", depth=1, resume_binding=RESUME_BINDING
        )
        self.assertEqual(projected["entities"][0]["entity_type"], "GateResult")

        path = next((self.root / "events" / "journal").glob("*.json"))
        tampered = json.loads(path.read_text(encoding="utf-8"))
        tampered["batch"]["events"][0]["payload"]["status"] = "pass"
        self.store.close()
        path.write_text(json.dumps(tampered, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        with self.assertRaises(JournalCorruption):
            EventStore(
                self.root / "events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
                **event_store_runtime_options(),
            )

    def test_definition_digest_equality_is_required_on_commit_and_replay(self) -> None:
        payload = gate_result("gate:definition", "run:definition")
        value = lease_bound(
            command("command:definition", "gate.record", payload, None),
            "task:definition",
        )
        mismatched = copy.deepcopy(value)
        mismatched["definition_digest"] = "8" * 64
        mismatched["intent_digest"] = digest_value(
            command_intent_identity(mismatched)
        )
        with self.assertRaisesRegex(EventStoreError, "definition_digest differs"):
            self.store.commit(mismatched, created_at=NOW)

        self.store.commit(value, created_at=NOW)
        path = next((self.root / "events" / "journal").glob("*.json"))
        envelope = json.loads(path.read_text(encoding="utf-8"))
        envelope["command"]["definition_digest"] = "8" * 64
        envelope["command"]["intent_digest"] = digest_value(
            command_intent_identity(envelope["command"])
        )
        self.store.close()
        path.write_bytes(canonical_owner_bytes(envelope))
        with self.assertRaisesRegex(JournalCorruption, "definition_digest differs"):
            EventStore(
                self.root / "events",
                active_activation_digest=ACTIVATION,
                activation_record_digest=ACTIVATION_RECORD_DIGEST,
                implementation_closure_digest=IMPLEMENTATION,
                **event_store_runtime_options(),
            )

    def test_projection_rebuild_exact_id_depth_and_digest_equality(self) -> None:
        self.commit_tasks(8)
        row = inventory_row()
        inventory = verified_inventory(row)
        projection = Projection(
            self.root / "projection.sqlite",
            token_key=b"k" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        first = projection.rebuild(self.store, inventory=inventory)
        self.assertEqual(first["inventory_passes"], 1)
        self.assertEqual(first["product_passes"], 0)
        self.assertEqual(first["inventory_proxies"], 1)
        self.assertEqual(first["raw_file_proxy_ratio"], 1.0)
        self.assertEqual(first["synthetic_task_count"], 0)
        artifact = projection.search(
            row["semantic_proxy"]["id"],
            depth=1,
            resume_binding=RESUME_BINDING,
        )["entities"][0]
        self.assertEqual(artifact["entity_type"], "Artifact")
        self.assertEqual(artifact["data_class"], "untrusted-source")
        self.assertEqual(artifact["payload"]["inventory_path"], row["path"])
        self.assertEqual(artifact["payload"]["inventory_digest"], row["digest"])
        exact = projection.search(
            "task:007", depth=1, resume_binding=RESUME_BINDING
        )
        self.assertEqual(exact["entities"][0]["id"], "task:007")
        self.assertIn("task:007", {entity["id"] for entity in exact["entities"]})
        shallow = projection.search(
            "task:007", depth=1, resume_binding=RESUME_BINDING
        )
        deep = projection.search(
            "task:007", depth=6, resume_binding=RESUME_BINDING
        )
        self.assertGreater(len(deep["relations"]), len(shallow["relations"]))
        self.assertEqual(projection.semantic_digest(), first["semantic_digest"])
        with closing(sqlite3.connect(projection.db_path)) as connection:
            primary_key = [
                row[1]
                for row in connection.execute("PRAGMA table_info(semantic_rows)")
                if row[5]
            ]
            digest_column = next(
                row for row in connection.execute("PRAGMA table_info(semantic_rows)")
                if row[1] == "row_digest"
            )
            digest_types = set(
                row[0] for row in connection.execute(
                    "SELECT DISTINCT typeof(row_digest) FROM semantic_rows"
                )
            )
            explicit_indexes = list(
                connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='index' AND tbl_name='semantic_rows' AND sql IS NOT NULL"
                )
            )
        self.assertEqual(primary_key, ["shard", "key"])
        self.assertEqual(digest_column[2], "BLOB")
        self.assertEqual(digest_types, {"blob"})
        self.assertEqual(explicit_indexes, [])
        second = projection.rebuild(self.store, inventory=verified_inventory(row))
        self.assertEqual(second["semantic_digest"], first["semantic_digest"])
        self.assertEqual(second["inventory_passes"], 1)
        self.assertEqual(second["product_passes"], 0)

    def test_projection_surfaces_keep_distinct_result_envelopes(self) -> None:
        self.commit_tasks(3)
        projection = Projection(
            self.root / "projection-surfaces.sqlite",
            token_key=b"u" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        projection.rebuild(self.store)
        retrieval = projection.search(
            "task:000",
            depth=1,
            resume_binding=RESUME_BINDING,
        )
        self.assertEqual(retrieval["record_type"], "RetrievalPage")
        task_row = retrieval["entities"][0]
        work_card = projection.work_card_projection(
            task_row["id"],
            task_digest=task_row["source_digest"],
            resume_binding=RESUME_BINDING,
        )
        self.assertEqual(work_card["record_type"], "WorkCardProjection")
        self.assertNotIn("continuation", work_card)

        ready_items = [
            {
                "task_id": f"task:{index:03d}",
                "task_digest": digest_value(
                    task(f"task:{index:03d}", f"compile renderer item {index}")
                ),
                "created_at": NOW,
                "candidate_digest": "c" * 64,
                "acceptance_predicate": "all required evidence remains current",
                "dependency_task_ids": [],
                "gate_result_digests": [],
            }
            for index in range(3)
        ]
        frontier_digest = digest_value(
            {"record_type": "ReadyFrontierSelection", "ready_tasks": ready_items}
        )
        budget = dict(PROJECTION_LIMITS.default_budget)
        budget["max_entities"] = 1
        budget["top_k"] = 1
        with mock.patch.object(
            projection,
            "_eligible_ready_tasks",
            return_value=(ready_items, 3, 0, frontier_digest),
        ):
            frontier = projection.ready_frontier(
                resume_binding=RESUME_BINDING,
                budget=budget,
                now=NOW,
                ttl_seconds=60,
            )
        self.assertEqual(frontier["record_type"], "ReadyFrontier")
        self.assertTrue(frontier["truncated"])
        self.assertEqual(len(frontier["ready_tasks"]), 1)
        token = frontier["continuation"]["token"]
        self.assertLessEqual(len(token.encode("ascii")), 256)
        continued = projection.continue_search(
            token,
            resume_binding=RESUME_BINDING,
            now="2026-07-17T12:00:30Z",
        )
        self.assertEqual(continued["record_type"], "ReadyFrontier")
        self.assertEqual(len(continued["ready_tasks"]), 1)

    def test_finding_disposition_projects_the_complete_state_delta(self) -> None:
        finding = {
            "record_type": "Finding",
            "finding_id": "finding:projection",
            "status": "OPEN",
            "blocking": True,
            "activation_digest": ACTIVATION,
        }

        def prepare_disposition(_view, command_value, relations):
            command_copy = _thaw(command_value)
            relation_copies = [_thaw(value) for value in relations]
            updates = list(state_binding_delta(command_copy, relation_copies))
            if command_copy["command_kind"] == "decision.record":
                updated = copy.deepcopy(finding)
                updated["status"] = "RESOLVED"
                updated["blocking"] = False
                updated["disposition_decision_id"] = command_copy["payload"][
                    "decision_id"
                ]
                updates.append(
                    {
                        "leaf_type": "Finding",
                        "leaf_id": finding["finding_id"],
                        "operation": "set",
                        "value_digest": digest_value(updated),
                    }
                )
            return PreparedCommit(
                tuple(relation_copies),
                tuple(
                    sorted(
                        updates,
                        key=lambda value: (value["leaf_type"], value["leaf_id"]),
                    )
                ),
            )

        disposition_store = EventStore(
            self.root / "disposition-events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **{
                **event_store_runtime_options(),
                "commit_prepare_callback": prepare_disposition,
            },
        )
        disposition_store.commit(
            lease_bound(
                command("command:finding", "finding.record", finding, None),
                "task:finding-disposition",
            ),
            created_at=NOW,
        )
        finding_digest = digest_value(finding)
        decision = {
            "record_type": "Decision",
            "decision_id": "decision:projection",
            "decision_kind": "resolve",
            "target_type": "Finding",
            "target_id": finding["finding_id"],
            "target_digest": finding_digest,
            "finding_digest": finding_digest,
            "activation_digest": ACTIVATION,
        }
        disposition_store.commit(
            command(
                "command:decision",
                "decision.record",
                decision,
                disposition_store.head()["batch_digest"],
            ),
            created_at=NOW,
        )
        projection = Projection(
            self.root / "projection-disposition.sqlite",
            token_key=b"d" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        projection.rebuild(disposition_store)
        projected = projection.search(
            finding["finding_id"],
            depth=1,
            resume_binding=RESUME_BINDING,
        )["entities"][0]["payload"]
        self.assertEqual(projected["status"], "RESOLVED")
        self.assertIs(projected["blocking"], False)
        self.assertEqual(
            projected["disposition_decision_id"],
            decision["decision_id"],
        )

    def test_concurrent_projection_replacement_cannot_mix_status_rows_and_token(self) -> None:
        self.commit_tasks(4)
        projection = Projection(
            self.root / "projection-old.sqlite",
            token_key=b"r" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        projection.rebuild(self.store)
        old_status = projection.status()

        replacement_store = EventStore(
            self.root / "replacement-events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **event_store_runtime_options(),
        )
        replacement_store.commit(
            command(
                "command:replacement",
                "task.record",
                task("task:replacement", "compile renderer replacement"),
                None,
            ),
            created_at=NOW,
        )
        replacement = Projection(
            self.root / "projection-replacement.sqlite",
            token_key=b"r" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        replacement.rebuild(replacement_store)
        replacement_status = replacement.status()
        self.assertNotEqual(old_status["head_digest"], replacement_status["head_digest"])

        original_status_connection = projection._status_connection
        replacement_published = threading.Event()

        def status_then_publish_replacement(connection):
            status = original_status_connection(connection)

            def publish() -> None:
                projection.db_path = replacement.db_path
                replacement_published.set()

            worker = threading.Thread(target=publish)
            worker.start()
            worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertTrue(replacement_published.is_set())
            return status

        budget = {
            "max_bytes": 16_384,
            "max_entities": 1,
            "max_relations": 1,
            "max_fanout_per_entity": 1,
            "top_k": 2,
        }
        with mock.patch.object(
            projection,
            "_status_connection",
            side_effect=status_then_publish_replacement,
        ):
            result = projection.search(
                "compile renderer",
                depth=1,
                budget=budget,
                resume_binding=RESUME_BINDING,
                now=NOW,
                ttl_seconds=60,
            )
        self.assertTrue(result["truncated"])
        self.assertTrue(
            all(entity["id"] != "task:replacement" for entity in result["entities"])
        )
        self.assertEqual(result["head_digest"], old_status["head_digest"])
        self.assertEqual(projection.status()["head_digest"], replacement_status["head_digest"])
        with self.assertRaisesRegex(ContinuationError, "missing or substituted"):
            projection.continue_search(
                result["continuation"]["token"],
                resume_binding=RESUME_BINDING,
                now="2026-07-17T12:00:30Z",
            )

    def test_projection_authority_metadata_is_exact_and_fail_closed(self) -> None:
        mutations = {
            "true": "text",
            "unknown": "text",
            None: "sql-null",
            "missing": "missing",
        }
        for index, (value, mutation_kind) in enumerate(mutations.items()):
            with self.subTest(value=value):
                projection = Projection(
                    self.root / f"projection-authority-{index}.sqlite",
                    token_key=b"a" * 32,
                    implementation_closure_digest=IMPLEMENTATION,
                    limits=PROJECTION_LIMITS,
                    relation_domains=DOMAINS,
                )
                rebuilt = projection.rebuild(self.store)
                self.assertIs(rebuilt["projection_authoritative"], False)
                self.assertIs(projection.status()["projection_authoritative"], False)

                with closing(sqlite3.connect(projection.db_path)) as connection:
                    if mutation_kind == "text":
                        connection.execute(
                            "UPDATE metadata SET value=? WHERE key='projection_authoritative'",
                            (value,),
                        )
                    elif mutation_kind == "sql-null":
                        connection.execute(
                            "ALTER TABLE metadata RENAME TO metadata_original"
                        )
                        connection.execute(
                            "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID"
                        )
                        connection.execute(
                            "INSERT INTO metadata SELECT key,value FROM metadata_original"
                        )
                        connection.execute("DROP TABLE metadata_original")
                        connection.execute(
                            "UPDATE metadata SET value=NULL WHERE key='projection_authoritative'"
                        )
                    else:
                        connection.execute(
                            "DELETE FROM metadata WHERE key='projection_authoritative'"
                        )
                    connection.commit()

                expected = (
                    "incomplete or unknown"
                    if mutation_kind == "missing"
                    else "must be exactly 'false'"
                )
                with self.assertRaisesRegex(ProjectionError, expected):
                    projection.status()
                with self.assertRaisesRegex(ProjectionError, expected):
                    projection.semantic_digest()
                with self.assertRaisesRegex(ProjectionError, expected):
                    projection.search(
                        "task:any", resume_binding=RESUME_BINDING
                    )

    def test_projection_rejects_product_pass_credit_metadata(self) -> None:
        projection = Projection(
            self.root / "projection-product-credit.sqlite",
            token_key=b"a" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        projection.rebuild(self.store)
        with closing(sqlite3.connect(projection.db_path)) as connection:
            connection.execute(
                "UPDATE metadata SET value='1' WHERE key='product_passes'"
            )
            connection.commit()
        with self.assertRaisesRegex(ProjectionError, "binding is invalid"):
            projection.status()
        with self.assertRaisesRegex(ProjectionError, "binding is invalid"):
            projection.search("task:any", resume_binding=RESUME_BINDING)

    def test_derived_tail_threshold_and_exact_head_checkpoint_guard(self) -> None:
        options = event_store_runtime_options()
        options["policy"] = event_store_policy(
            derived_tail_batch_threshold=2,
            derived_tail_byte_threshold=10_000_000,
        )
        store = EventStore(
            self.root / "threshold-events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **options,
        )
        store.commit(
            command(
                "command:000",
                "task.record",
                task("task:000", "compile renderer item 0"),
                None,
            ),
            created_at=NOW,
        )
        checkpoint_head = store.head()
        store.write_derived_state(
            "runtime:bounded",
            {
                "task_ids": ["task:000"],
                "compaction": {"checkpoint_count": 1},
            },
            expected_head=checkpoint_head,
        )
        for index in (1, 2):
            task_id = f"task:{index:03d}"
            value = command(
                f"command:{index:03d}",
                "task.record",
                task(task_id, f"compile renderer item {index}"),
                store.head()["batch_digest"],
            )
            store.commit(
                value,
                auxiliary_relations=[
                    relation(f"rel:{index:03d}", task_id, f"task:{index - 1:03d}")
                ],
                created_at=NOW,
            )
            status = store.derived_tail_status("runtime:bounded")
            self.assertEqual(status["tail_batches"], index)
            self.assertEqual(status["compaction_due"], index == 2)
        with self.assertRaisesRegex(DerivedCheckpointError, "stale authoritative HEAD"):
            store.write_derived_state(
                "runtime:bounded",
                {
                    "task_ids": ["task:000"],
                    "compaction": {"checkpoint_count": 1},
                },
                expected_head=checkpoint_head,
            )
        metrics = store.last_commit_write_metrics()
        self.assertEqual(metrics["changed_records"], 2)
        self.assertGreater(metrics["journal_authority_bytes"], 0)
        self.assertGreater(metrics["physical_payload_bytes"], metrics["journal_authority_bytes"])

    def test_incremental_projection_matches_rebuild_and_crash_boundaries(self) -> None:
        self.commit_tasks(1)
        projection = Projection(
            self.root / "projection-incremental.sqlite",
            token_key=b"k" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        projection.rebuild(self.store)

        for index in (1, 2, 3):
            task_id = f"task:{index:03d}"
            self.store.commit(
                command(
                    f"command:{index:03d}",
                    "task.record",
                    task(task_id, f"compile renderer item {index}"),
                    self.store.head()["batch_digest"],
                ),
                auxiliary_relations=[
                    relation(f"rel:{index:03d}", task_id, f"task:{index - 1:03d}")
                ],
                created_at=NOW,
            )
            if index == 2:
                with self.assertRaisesRegex(ProjectionError, "before projection commit"):
                    projection.apply_committed_batch(
                        self.store,
                        crash_hook=lambda point: point == "before_projection_commit",
                    )
                self.assertEqual(projection.status()["head_sequence"], 2)
            if index == 3:
                with self.assertRaisesRegex(ProjectionError, "after projection commit"):
                    projection.apply_committed_batch(
                        self.store,
                        crash_hook=lambda point: point == "after_projection_commit",
                    )
                self.assertEqual(projection.status()["head_sequence"], 4)
                self.assertEqual(
                    projection.apply_committed_batch(self.store)["status"],
                    "already-current",
                )
            else:
                result = projection.apply_committed_batch(self.store)
                self.assertEqual(result["status"], "updated")
                self.assertEqual(result["changed_records"], 2)
                self.assertLessEqual(result["changed_shards"], 2)

        rebuilt = Projection(
            self.root / "projection-incremental-rebuilt.sqlite",
            token_key=b"k" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        ).rebuild(self.store)
        self.assertEqual(projection.semantic_digest(), rebuilt["semantic_digest"])
        self.assertEqual(projection.require_current(self.store)["head_sequence"], 4)

    def test_projection_streams_manifest_bound_jsonl_and_indexes_bounded_content(self) -> None:
        raw = {
            "path": "src/semantic-source.txt",
            "digest": hashlib.sha256(b"representative semantic source").hexdigest(),
            "size": len(b"representative semantic source"),
            "search_text": "representative semantic source",
        }
        encoded = canonical_owner_bytes(raw)
        stream_path = self.root / "verified-inventory.jsonl"
        stream_path.write_bytes(encoded)
        identity_digest = hashlib.sha256(
            canonical_owner_bytes(
                {"path": raw["path"], "digest": raw["digest"], "size": raw["size"]}
            )
        ).hexdigest()
        inventory = VerifiedInventoryInput(
            activation_digest=ACTIVATION,
            stream_digest=hashlib.sha256(encoded).hexdigest(),
            inventory_digest=identity_digest,
            entry_count=1,
            stream_path=stream_path,
            stream_bytes=len(encoded),
            manifest_digest="4" * 64,
            observed_at=NOW,
        )
        projection = Projection(
            self.root / "streamed-projection.sqlite",
            token_key=b"i" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        rebuilt = projection.rebuild(self.store, inventory=inventory)
        self.assertEqual(rebuilt["inventory_entries"], 1)
        self.assertEqual(rebuilt["inventory_stream_bytes"], len(encoded))
        result = projection.search(
            "semantic source", depth=1, resume_binding=RESUME_BINDING
        )
        self.assertEqual(len(result["entities"]), 1)
        self.assertEqual(result["entities"][0]["payload"]["inventory_path"], raw["path"])
        self.assertNotIn("search_text", result["entities"][0]["payload"])

    def test_exact_punctuated_id_bypasses_fts_and_token_search_remains_compatible(self) -> None:
        task_id = "task:mutation-primary"
        self.store.commit(
            command(
                "command:punctuated-id",
                "task.record",
                task(task_id, "punctuated search target"),
                None,
            ),
            created_at=NOW,
        )
        projection = Projection(
            self.root / "projection.sqlite",
            token_key=b"x" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        projection.rebuild(self.store)
        exact = projection.search(
            task_id, depth=1, resume_binding=RESUME_BINDING
        )
        self.assertEqual([entity["id"] for entity in exact["entities"]], [task_id])
        token_match = projection.search(
            "mutation-primary", depth=1, resume_binding=RESUME_BINDING
        )
        self.assertEqual(token_match["entities"][0]["id"], task_id)

    def test_task_transition_materializes_latest_state_and_refreshes_fts(self) -> None:
        task_id = "task:stateful"
        planned = {
            "record_type": "Task",
            "task_id": task_id,
            "state": "PLANNED",
            "title": "stateful projection task",
            "activation_digest": ACTIVATION,
        }
        def prepare_task_state(_view, command_value, relations):
            command_copy = _thaw(command_value)
            relation_copies = [_thaw(value) for value in relations]
            primary_value = None
            if command_copy["command_kind"] == "task.transition":
                primary_value = copy.deepcopy(planned)
                primary_value["state"] = command_copy["payload"]["to_state"]
            return PreparedCommit(
                tuple(relation_copies),
                state_binding_delta(
                    command_copy, relation_copies, primary_value=primary_value
                ),
            )

        transition_store = EventStore(
            self.root / "transition-events",
            active_activation_digest=ACTIVATION,
            activation_record_digest=ACTIVATION_RECORD_DIGEST,
            implementation_closure_digest=IMPLEMENTATION,
            **{
                **event_store_runtime_options(),
                "commit_prepare_callback": prepare_task_state,
            },
        )
        transition_store.commit(
            command("command:stateful-create", "task.record", planned, None),
            created_at=NOW,
        )
        transition = {
            "task_id": task_id,
            "from_state": "PLANNED",
            "to_state": "READY",
            "reason": "prerequisites satisfied",
        }
        transition_store.commit(
            command(
                "command:stateful-ready",
                "task.transition",
                transition,
                transition_store.head()["batch_digest"],
            ),
            created_at=NOW,
        )
        projection = Projection(
            self.root / "projection.sqlite",
            token_key=b"y" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        projection.rebuild(transition_store)
        ready = projection.search(
            "READY", depth=1, resume_binding=RESUME_BINDING
        )
        self.assertEqual(ready["entities"][0]["id"], task_id)
        self.assertEqual(ready["entities"][0]["payload"]["state"], "READY")
        self.assertNotIn(
            task_id,
            {
                entity["id"]
                for entity in projection.search(
                    "PLANNED", depth=1, resume_binding=RESUME_BINDING
                )["entities"]
            },
        )

    def test_explicit_truncation_and_bound_continuation(self) -> None:
        self.commit_tasks(20)
        projection = Projection(
            self.root / "projection.sqlite",
            token_key=b"s" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        projection.rebuild(self.store)
        budget = {
            "max_bytes": 16_384,
            "max_entities": 2,
            "max_relations": 1,
            "max_fanout_per_entity": 1,
            "top_k": 2,
        }
        page = projection.search(
            "compile renderer",
            depth=2,
            budget=budget,
            resume_binding=RESUME_BINDING,
            now=NOW,
            ttl_seconds=60,
        )
        self.assertTrue(page["truncated"])
        self.assertIsNotNone(page["continuation"])
        self.assertGreater(page["continuation"]["expiry"], NOW)
        token = page["continuation"]["token"]
        self.assertLessEqual(len(token.encode("ascii")), 256)
        continued = projection.continue_search(
            token,
            resume_binding=RESUME_BINDING,
            now="2026-07-17T12:00:30Z",
        )
        self.assertGreaterEqual(
            continued["stream_cursor"], page["next_stream_cursor"]
        )
        self.assertNotIn("seed_cursor", continued)
        self.assertNotIn("next_seed_cursor", continued)
        with projection._connect_mutable() as connection:
            legacy_payload = projection._decode_token(
                connection, token, "2026-07-17T12:00:30Z"
            )
            legacy_payload["seed_cursor"] = legacy_payload["cursor"]
            legacy_payload["next_seed_cursor"] = legacy_payload["cursor"]
            legacy_token = projection._encode_token(
                connection, legacy_payload
            )
        with self.assertRaisesRegex(ContinuationError, "incomplete"):
            projection.continue_search(
                legacy_token,
                resume_binding=RESUME_BINDING,
                now="2026-07-17T12:00:30Z",
            )
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        with self.assertRaises(ContinuationError):
            projection.continue_search(
                tampered,
                resume_binding=RESUME_BINDING,
                now="2026-07-17T12:00:30Z",
            )
        with self.assertRaises(ContinuationError):
            projection.search(
                "different query", depth=2, budget=budget, continuation_token=token,
                resume_binding=RESUME_BINDING,
                now="2026-07-17T12:00:30Z", ttl_seconds=60,
            )
        with self.assertRaises(ContinuationError):
            projection.continue_search(
                token,
                resume_binding=RESUME_BINDING,
                now="2026-07-17T12:01:00Z",
            )

    def test_projection_currentness_and_relation_domain(self) -> None:
        self.commit_tasks(1)
        projection = Projection(
            self.root / "projection.sqlite",
            token_key=b"z" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        projection.rebuild(self.store)
        projection.require_current(self.store)
        next_command = command("command:next", "task.record", task("task:next", "next"), self.store.head()["batch_digest"])
        self.store.commit(next_command, created_at=NOW)
        with self.assertRaises(ProjectionError):
            projection.require_current(self.store)

    def test_projection_rejects_unverified_inventory_and_reserved_provenance(self) -> None:
        projection = Projection(
            self.root / "projection.sqlite",
            token_key=b"p" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        row = inventory_row()
        with self.assertRaisesRegex(ProjectionError, "verified InventoryResult"):
            projection.rebuild(self.store, inventory=[row])  # type: ignore[arg-type]

        inflated = copy.deepcopy(row)
        inflated["semantic_proxies"] = [inflated.pop("semantic_proxy")]
        inflated["typed_relations"] = []
        with self.assertRaisesRegex(ProjectionError, "fields mismatch"):
            projection.rebuild(self.store, inventory=verified_inventory(inflated))

        trusted = copy.deepcopy(row)
        trusted["semantic_proxy"]["data_class"] = "trusted-authority"
        with self.assertRaisesRegex(ProjectionError, "semantic proxy fields mismatch"):
            projection.rebuild(self.store, inventory=verified_inventory(trusted))

        spoofed = copy.deepcopy(row)
        spoofed["semantic_proxy"]["payload"]["inventory_path"] = "other/path"
        with self.assertRaisesRegex(ProjectionError, "reserved provenance"):
            projection.rebuild(self.store, inventory=verified_inventory(spoofed))

        wrong_stream = VerifiedInventoryInput(
            activation_digest=ACTIVATION,
            stream_digest="f" * 64,
            entry_count=1,
            entries=(row,),
        )
        with self.assertRaisesRegex(ProjectionError, "identity digest mismatch"):
            projection.rebuild(self.store, inventory=wrong_stream)

    def test_unknown_budget_field_is_rejected(self) -> None:
        projection = Projection(
            self.root / "projection.sqlite",
            token_key=b"e" * 32,
            implementation_closure_digest=IMPLEMENTATION,
            limits=PROJECTION_LIMITS,
            relation_domains=DOMAINS,
        )
        projection.rebuild(self.store)
        invalid = {
            "max_bytes": 16_384,
            "max_entities": 6,
            "max_relations": 4,
            "max_fanout_per_entity": 2,
            "top_k": 2,
            "unknown_budget": 0,
        }
        with self.assertRaisesRegex(ProjectionError, "fields mismatch"):
            projection.search(
                "task:any", budget=invalid, resume_binding=RESUME_BINDING
            )


if __name__ == "__main__":
    unittest.main()
