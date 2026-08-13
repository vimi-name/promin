from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import promin.evidence as evidence_module
from promin.authority import (
    AuthorityEngine,
    AuthorityError,
    canonical_digest,
    grant_claim_identity,
    parse_timestamp,
    scope_is_subset,
    validate_gate_authorization_scope,
)
from promin.contracts import validate_definition
from promin.domain import DomainError, DomainState
from promin.evidence import (
    EvidenceError,
    EvidenceStore,
    _validate_evidence_attestation_trust,
    _validate_producer_attestation,
    _validate_release_evidence_attestation_graph,
    _validate_saturation_audit_producer_boundary,
    _validate_trust_configuration,
    release_evidence_invocation,
    seal_release_evidence,
    standard_distribution_status,
    validate_release_evidence_producer_configuration,
    validate_saturation_audit,
    validate_standard_release_candidate_binding,
    validate_standard_release_decision,
    validate_standard_release_evidence_manifest,
)


ACTIVATION = "a" * 64
CANDIDATE = "c" * 64
POLICY = "d" * 64
TOOL = "e" * 64
INPUT = "f" * 64
PROVIDER = "9" * 64
IMPLEMENTATION = "8" * 64


def authority_init() -> dict[str, Any]:
    subjects = [
        ("root", "human"),
        ("planner", "agent"),
        ("worker", "agent"),
        ("manager", "service"),
        ("finder", "agent"),
        ("resolver", "human"),
        ("waiver", "human"),
        ("validator", "agent"),
        ("promoter", "human"),
        ("approver", "human"),
    ]
    return {
        "record_type": "AuthorityInit",
        "trust_mode": "local-owner",
        "subjects": [
            {"subject_id": subject, "kind": kind, "display_name": subject.title()}
            for subject, kind in subjects
        ],
        "roots": [
            {
                "subject_id": "root",
                "capability_ceiling": [
                    "standard.activate",
                    "authority.manage",
                    "task.plan",
                    "task.execute",
                    "lease.manage",
                    "evidence.publish",
                    "validation.evaluate",
                    "finding.record",
                    "finding.resolve",
                    "finding.waive",
                    "candidate.promote",
                    "release.decide",
                    "export.create",
                    "migration.manage",
                    "projection.read",
                    "projection.rebuild",
                ],
                "scope": [{"kind": "all", "value": "*"}],
            }
        ],
    }


def core_schema() -> dict[str, Any]:
    return json.loads(
        (Path(__file__).parents[1] / "core" / "contracts.schema.json").read_text(
            encoding="utf-8"
        )
    )


def core_authority_model() -> dict[str, Any]:
    return json.loads(
        (Path(__file__).parents[1] / "core" / "authority-model.json").read_text(
            encoding="utf-8"
        )
    )


def authority_runtime_policy(*, delegation_depth_max: int | None = None) -> dict[str, Any]:
    model = core_authority_model()
    capability_ids = [item["id"] for item in model["capabilities"]]
    identity = {
        "record_type": "AuthorityRuntimePolicy",
        "authority_model_digest": canonical_digest(model),
        "capability_ids": capability_ids,
        "separation_of_duties": deepcopy(model["separation_of_duties"]),
        "separation_of_duties_capability_ids": [
            *capability_ids,
            *model["separation_of_duties_contract"]["external_capability_ids"],
        ],
        "separation_of_duties_contract": deepcopy(
            model["separation_of_duties_contract"]
        ),
        "delegation_depth_max": (
            model["delegation_depth_max"]
            if delegation_depth_max is None
            else delegation_depth_max
        ),
        "scope_contract": deepcopy(model["scope_contract"]),
        "grant_contract": deepcopy(model["grant_contract"]),
        "canonical_timestamp_contract": deepcopy(
            model["canonical_timestamp_contract"]
        ),
    }
    return {**identity, "policy_digest": canonical_digest(identity)}


def domain_runtime_policy() -> dict[str, Any]:
    policy_set = json.loads(
        (Path(__file__).parents[1] / "core" / "policy-set.json").read_text(
            encoding="utf-8"
        )
    )
    state_machines = policy_set["state_machines"]
    return {
        "activation_digest": ACTIVATION,
        "implementation_closure_digest": IMPLEMENTATION,
        "core_bundle_digest": "1" * 64,
        "preset_digest": "2" * 64,
        "operating_profile": "balanced-local",
        "profile_digest": "3" * 64,
        "model_tier": "strong",
        "max_parallel_tasks": 2,
        "model_tier_rule_digest": "4" * 64,
        "policy_set_digest": canonical_digest(policy_set),
        "state_machine_rule_digest": canonical_digest(
            {
                "task": state_machines["task"],
                "lease": state_machines["lease"],
            }
        ),
        "task_transitions": deepcopy(state_machines["task"]),
        "lease_transitions": deepcopy(state_machines["lease"]),
        "capacity_release_rule_digest": canonical_digest(
            {"capacity_release": state_machines["capacity_release"]}
        ),
        "capacity_release": deepcopy(state_machines["capacity_release"]),
        "authority_effect": False,
    }


def make_grant(
    init: dict[str, Any],
    grant_id: str,
    subject: str,
    capability: str,
    *,
    issuer: dict[str, Any] | None = None,
    scope: list[dict[str, str]] | None = None,
    issued_at: str = "2026-01-01T00:00:00Z",
    expires_at: str = "2028-01-01T00:00:00Z",
    nonce: str | None = None,
) -> dict[str, Any]:
    grant: dict[str, Any] = {
        "record_type": "Grant",
        "grant_id": grant_id,
        "subject_id": subject,
        "capability_id": capability,
        "scope": scope or [{"kind": "all", "value": "*"}],
        "activation_digest": ACTIVATION,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce or f"nonce-{grant_id}-00000000",
    }
    claim = canonical_digest(grant_claim_identity(grant))
    grant["claim_digest"] = claim
    if issuer is None:
        grant["trust_proofs"] = [
            {
                "kind": "local-root",
                "root_subject_id": "root",
                "authority_init_digest": canonical_digest(init),
                "signed_claim_digest": claim,
            }
        ]
    else:
        grant["trust_proofs"] = [
            {
                "kind": "issuer-grant",
                "issuer_grant_id": issuer["grant_id"],
                "issuer_signed_claim_digest": issuer["claim_digest"],
                "signed_claim_digest": claim,
            }
        ]
    return grant


def bootstrap_command(init: dict[str, Any], root_grant: dict[str, Any]) -> dict[str, Any]:
    command: dict[str, Any] = {
        "record_type": "CommandRequest",
        "command_id": "C-bootstrap",
        "command_kind": "grant.issue",
        "subject_id": "root",
        "activation_digest": ACTIVATION,
        "idempotency_key": "bootstrap-command-key-0001",
        "requested_scope": [{"kind": "all", "value": "*"}],
        "expected_head_digest": None,
        "issued_at": root_grant["issued_at"],
        "payload": root_grant,
    }
    command["intent_digest"] = canonical_digest(command)
    command["authorization"] = {
        "kind": "root",
        "subject_id": "root",
        "proofs": [
            {
                "kind": "local-root-command",
                "subject_id": "root",
                "authority_init_digest": canonical_digest(init),
                "signed_intent_digest": command["intent_digest"],
            }
        ],
    }
    return command


def delegated_grant_command(
    grant: dict[str, Any], issuer: dict[str, Any]
) -> dict[str, Any]:
    command: dict[str, Any] = {
        "record_type": "CommandRequest",
        "command_id": f"C-issue-{grant['grant_id']}",
        "command_kind": "grant.issue",
        "subject_id": issuer["subject_id"],
        "activation_digest": ACTIVATION,
        "idempotency_key": f"issue-{grant['grant_id']}-command-key",
        "requested_scope": deepcopy(grant["scope"]),
        "expected_head_digest": None,
        "issued_at": grant["issued_at"],
        "payload": deepcopy(grant),
    }
    command["intent_digest"] = canonical_digest(command)
    command["authorization"] = {
        "kind": "grant",
        "grant_id": issuer["grant_id"],
        "grant_claim_digest": issuer["claim_digest"],
    }
    return command


def persist_grant(
    engine: AuthorityEngine,
    init: dict[str, Any],
    grant: dict[str, Any],
    *,
    issuer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    command = (
        bootstrap_command(init, grant)
        if issuer is None
        else delegated_grant_command(grant, issuer)
    )
    receipt = engine.authorize_grant_issue_command(command)
    return engine.issue_grant(
        grant,
        grant["issued_at"],
        issue_authorization=receipt,
    )


def issued_engine(
    *, decision_resolver: Any = None
) -> tuple[AuthorityEngine, dict[str, dict[str, Any]]]:
    init = authority_init()
    engine = AuthorityEngine(
        init,
        ACTIVATION,
        authority_runtime_policy(),
        decision_resolver=decision_resolver,
    )
    root = make_grant(init, "g-root", "root", "authority.manage")
    persist_grant(engine, init, root)
    grants: dict[str, dict[str, Any]] = {"root": root}
    for name, subject, capability in [
        ("planner", "planner", "task.plan"),
        ("worker", "worker", "task.execute"),
        ("manager", "manager", "lease.manage"),
        ("finder", "finder", "finding.record"),
        ("resolver", "resolver", "finding.resolve"),
        ("waiver", "waiver", "finding.waive"),
        ("validator", "validator", "validation.evaluate"),
        ("promoter", "promoter", "candidate.promote"),
        ("approver", "approver", "release.decide"),
        ("reader", "worker", "projection.read"),
    ]:
        grant = make_grant(init, f"g-{name}", subject, capability, issuer=root)
        persist_grant(engine, init, grant, issuer=root)
        grants[name] = grant
    return engine, grants


def authorization(
    grant: dict[str, Any],
    *,
    at: str = "2026-02-01T00:00:00Z",
    scope: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "subject_id": grant["subject_id"],
        "grant_id": grant["grant_id"],
        "claim_digest": grant["claim_digest"],
        "evaluated_at": at,
        "requested_scope": scope or [{"kind": "all", "value": "*"}],
    }


def finalized_evidence(
    store: EvidenceStore,
    *,
    artifact_id: str,
    payload: bytes,
    media_type: str,
    retention_class: str,
    candidate_digest: str,
    policy_digest: str,
    tool_digest: str,
    input_digests: list[str],
    created_at: str,
    activation_digest: str,
    outcome: str,
    stale: bool = False,
    unresolved: bool = False,
    evidence_class: str = "validator",
    evidence_purpose: str | None = None,
    product_credit_eligible: bool = False,
    finding_digest: str | None = None,
    provider_invocations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    binding = {
        "activation_digest": activation_digest,
        "implementation_closure_digest": IMPLEMENTATION,
        "candidate_digest": candidate_digest,
        "policy_digest": policy_digest,
        "tool_digest": tool_digest,
        "input_digests": input_digests,
    }
    if finding_digest is not None:
        binding["finding_digest"] = finding_digest
    if product_credit_eligible and provider_invocations is None:
        invocation = {
            "capability_id": "control-runtime",
            "provider_id": "python-runtime",
            "invocation_kind": "python-runtime",
            "identity_kind": "file-digest",
            "identity_digest": PROVIDER,
            "adapter_id": "python-runtime-v1",
            "protocol_id": "promin.control-runtime.v1",
            "operation": "validate",
            "operation_contract_digest": canonical_digest({"request": "installed-activation", "response": "ValidationResult"}),
            "dependency_receipt_digest": PROVIDER,
            "implementation_closure_digest": IMPLEMENTATION,
            "invoked": True,
            "started_at": created_at,
            "completed_at": created_at,
            "outcome": "success",
            "exit_code": 0,
            "invocation_request_digest": INPUT,
            "input_digest": INPUT,
            "output_digest": hashlib.sha256(payload).hexdigest(),
            "output_size_bytes": len(payload),
            "output_size_ceiling_bytes": max(len(payload), 1),
            "stdout_capture_digest": hashlib.sha256(payload).hexdigest(),
            "stdout_capture_size_bytes": len(payload),
            "stdout_capture_truncated": False,
            "stderr_capture_digest": hashlib.sha256(b"").hexdigest(),
            "stderr_capture_size_bytes": 0,
            "stderr_capture_truncated": False,
            "authoritative": False,
            "pass_credit": False,
        }
        invocation["invocation_receipt_digest"] = canonical_digest(invocation)
        provider_invocations = [invocation]
    if provider_invocations is not None:
        binding["provider_invocations"] = provider_invocations
    artifact = {
        "record_type": "Artifact",
        "artifact_id": artifact_id,
        "artifact_kind": "evidence",
        "digest": hashlib.sha256(payload).hexdigest(),
        "media_type": media_type,
        "size_bytes": len(payload),
        "retention_class": retention_class,
        "created_at": created_at,
        "evidence_binding": binding,
        "outcome": outcome,
        "stale": stale,
        "unresolved": unresolved,
        "evidence_class": evidence_class,
        "evidence_purpose": (
            evidence_purpose
            if evidence_purpose is not None
            else "product"
            if evidence_class == "product-execution" and product_credit_eligible
            else "diagnostic"
            if evidence_class in {"harness-generated", "migration"}
            else "gate"
        ),
        "product_credit_eligible": product_credit_eligible,
    }
    command = {
        "record_type": "CommandRequest",
        "command_id": "c:"
        + hashlib.sha256(artifact_id.encode("utf-8")).hexdigest()[:48],
        "command_kind": "artifact.record",
        "subject_id": "validator",
        "activation_digest": activation_digest,
        "idempotency_key": "evidence-finalize-"
        + hashlib.sha256(artifact_id.encode("utf-8")).hexdigest()[:24],
        "expected_head_digest": None,
        "issued_at": created_at,
        "requested_scope": [{"kind": "artifact", "value": artifact_id}],
        "payload": artifact,
        "intent_digest": "1" * 64,
        "authorization": {
            "kind": "grant",
            "grant_id": "g:validator",
            "grant_claim_digest": "2" * 64,
        },
    }
    command_digest = canonical_digest(command)
    event = {
        "record_type": "Event",
        "event_id": "e:"
        + hashlib.sha256(command_digest.encode("ascii")).hexdigest()[:48],
        "event_kind": "artifact.recorded",
        "activation_digest": activation_digest,
        "payload": artifact,
    }
    batch = {
        "record_type": "EventBatch",
        "batch_id": "b:"
        + hashlib.sha256(command_digest.encode("ascii")).hexdigest()[:48],
        "sequence": 1,
        "previous_digest": None,
        "created_at": created_at,
        "command_id": command["command_id"],
        "idempotency_key": command["idempotency_key"],
        "activation_record_digest": activation_digest,
        "events": [event],
        "subject_id": command["subject_id"],
        "command_intent_digest": command["intent_digest"],
        "command_digest": command_digest,
        "authorization_digest": canonical_digest(command["authorization"]),
    }
    envelope = {
        "record_type": "JournalEnvelope",
        "command": command,
        "batch": batch,
    }
    store.stage(artifact, payload, command_digest=command_digest)
    store.finalize(
        artifact,
        command_digest=command_digest,
        envelope=envelope,
    )
    journal = getattr(store, "_test_evidence_journal", [])
    journal.append(envelope)
    store._test_evidence_journal = journal
    store.reconcile(journal)
    return artifact


def evidence_reference(
    store: EvidenceStore, artifact: dict[str, Any]
) -> dict[str, str]:
    return store.artifact_reference(artifact["artifact_id"])


def provider_invocation_digests(artifact: dict[str, Any]) -> list[str]:
    return [
        canonical_digest(invocation)
        for invocation in artifact["evidence_binding"].get(
            "provider_invocations", []
        )
    ]


def task_with_gate_definitions(
    task: dict[str, Any],
    *definitions: dict[str, Any],
) -> dict[str, Any]:
    value = dict(task)
    owner_digest = canonical_digest(
        {
            key: nested
            for key, nested in value.items()
            if key not in {"state", "gate_run_definitions"}
        }
    )
    bindings = []
    for spec in definitions:
        provider_invocations = spec.get("provider_invocations", [])
        target_kind = spec.get("target_kind", "candidate")
        target_digest = spec.get("target_digest", value["candidate_digest"])
        definition = {
            "definition_kind": "GateRunDefinition",
            "definition_id": f"definition:{spec['gate_id']}",
            "owner_kind": "Task",
            "owner_digest": owner_digest,
            "defined_at_head_digest": spec.get("defined_at_head_digest"),
            "gate_id": spec["gate_id"],
            "run_kind": spec.get("run_kind", "validation"),
            "expected_evidence_class": spec.get("evidence_class", "validator"),
            "expected_evidence_purpose": spec.get("evidence_purpose", "gate"),
            "product_credit_required": spec.get("product_credit_required", False),
            "target_kind": target_kind,
            "target_digest": target_digest,
            "target_scope": spec.get(
                "target_scope",
                [{"kind": "candidate", "value": value["candidate_digest"]}],
            ),
            "candidate_digest": value["candidate_digest"],
            "policy_digest": spec.get("policy_digest", POLICY),
            "tool_digest": spec.get("tool_digest", TOOL),
            "implementation_closure_digest": IMPLEMENTATION,
            "provider_binding_digest": spec.get("provider_binding_digest", PROVIDER),
            "input_digests": spec.get("input_digests", [INPUT]),
            "activation_digest": value["activation_digest"],
        }
        bindings.append(
            {
                "definition_digest": canonical_digest(definition),
                "definition": definition,
            }
        )
    value["gate_run_definitions"] = bindings
    return value


def gate_run_for(
    task: dict[str, Any],
    gate_id: str,
    run_id: str,
    *,
    status: str = "pass",
) -> dict[str, Any]:
    binding = next(
        item
        for item in task["gate_run_definitions"]
        if item["definition"]["gate_id"] == gate_id
    )
    definition = binding["definition"]
    return {
        "record_type": "Run",
        "run_id": run_id,
        "run_kind": definition["run_kind"],
        "task_id": task["task_id"],
        "candidate_digest": definition["candidate_digest"],
        "policy_digest": definition["policy_digest"],
        "tool_digest": definition["tool_digest"],
        "input_digests": deepcopy(definition["input_digests"]),
        "status": status,
        "started_at": task["created_at"],
        "finished_at": task["created_at"],
        "activation_digest": definition["activation_digest"],
        "definition_digest": binding["definition_digest"],
        "implementation_closure_digest": definition[
            "implementation_closure_digest"
        ],
        "provider_binding_digest": definition["provider_binding_digest"],
    }


def gate_result_for(
    task: dict[str, Any],
    gate_id: str,
    run_id: str,
    evidence_artifacts: list[dict[str, str]],
    *,
    status: str = "pass",
    reason: str | None = None,
    run_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    binding = next(
        item
        for item in task["gate_run_definitions"]
        if item["definition"]["gate_id"] == gate_id
    )
    definition = binding["definition"]
    run = run_record or gate_run_for(task, gate_id, run_id, status=status)
    run_digest = canonical_digest(run)
    result = {
        "record_type": "GateResult",
        "task_id": task["task_id"],
        "gate_id": gate_id,
        "run_id": run_id,
        "run_digest": run_digest,
        "definition_digest": binding["definition_digest"],
        "status": status,
        "outcome": status,
        "pass_credit": status == "pass"
        and definition["product_credit_required"],
        "activation_digest": definition["activation_digest"],
        "candidate_digest": definition["candidate_digest"],
        "policy_digest": definition["policy_digest"],
        "tool_digest": definition["tool_digest"],
        "evidence_class": definition["expected_evidence_class"],
        "evidence_artifacts": [
            {
                **reference,
                "run_id": run_id,
                "run_digest": run_digest,
            }
            for reference in evidence_artifacts
        ],
    }
    if reason is not None:
        result["reason"] = reason
    return result


def exact_decision(
    *,
    decision_id: str,
    decision_kind: str,
    grant: dict[str, Any],
    target_type: str,
    target: dict[str, Any],
    evidence_artifacts: list[dict[str, str]],
    created_at: str,
    candidate_digest: str = CANDIDATE,
    rationale: str = "exact evidence and target reviewed",
    **extra: Any,
) -> dict[str, Any]:
    decision = {
        "record_type": "Decision",
        "decision_id": decision_id,
        "decision_kind": decision_kind,
        "subject_id": grant["subject_id"],
        "grant_id": grant["grant_id"],
        "grant_claim_digest": grant["claim_digest"],
        "activation_digest": ACTIVATION,
        "candidate_digest": candidate_digest,
        "target_type": target_type,
        "target_id": next(
            target[field]
            for field in ("task_id", "candidate_id", "finding_id", "grant_id")
            if field in target
        ),
        "target_digest": canonical_digest(target),
        "rationale": rationale,
        "evidence_artifacts": evidence_artifacts,
        "created_at": created_at,
        **extra,
    }
    if decision_kind == "revoke":
        decision.pop("candidate_digest")
    return decision


def bind_revocation_decision(
    bindings: dict[str, dict[str, Any]],
    *,
    manager: dict[str, Any],
    target: dict[str, Any],
    decision_id: str,
    reason: str,
    created_at: str,
) -> None:
    decision = exact_decision(
        decision_id=decision_id,
        decision_kind="revoke",
        grant=manager,
        target_type="Grant",
        target=target,
        evidence_artifacts=[
            {
                "artifact_id": f"E-{decision_id}",
                "artifact_record_digest": "7" * 64,
            }
        ],
        rationale=reason,
        created_at=created_at,
    )
    event = {
        "record_type": "Event",
        "event_id": f"E-{decision_id}-recorded",
        "event_kind": "decision.recorded",
        "activation_digest": ACTIVATION,
        "payload": deepcopy(decision),
    }
    bindings[decision_id] = {"decision": decision, "event": event}


def finalized_delta(
    store: EvidenceStore,
    *,
    artifact_id: str,
    payload: bytes,
    base_candidate_digest: str,
    new_candidate_digest: str,
    workcard_digest: str,
    changed_paths: list[str],
    created_at: str = "2026-02-01T00:00:00Z",
    activation_digest: str = ACTIVATION,
) -> dict[str, Any]:
    artifact = {
        "record_type": "Artifact",
        "artifact_id": artifact_id,
        "artifact_kind": "diff",
        "digest": hashlib.sha256(payload).hexdigest(),
        "media_type": "application/json",
        "size_bytes": len(payload),
        "retention_class": "audit",
        "created_at": created_at,
        "candidate_delta": {
            "base_candidate_digest": base_candidate_digest,
            "new_candidate_digest": new_candidate_digest,
            "workcard_digest": workcard_digest,
            "changed_paths": changed_paths,
        },
    }
    command = {
        "record_type": "CommandRequest",
        "command_id": "c:"
        + hashlib.sha256(artifact_id.encode("utf-8")).hexdigest()[:48],
        "command_kind": "artifact.record",
        "subject_id": "validator",
        "activation_digest": activation_digest,
        "idempotency_key": "delta-finalize-"
        + hashlib.sha256(artifact_id.encode("utf-8")).hexdigest()[:24],
        "expected_head_digest": None,
        "issued_at": created_at,
        "requested_scope": [{"kind": "artifact", "value": artifact_id}],
        "payload": artifact,
        "intent_digest": "1" * 64,
        "authorization": {
            "kind": "grant",
            "grant_id": "g:validator",
            "grant_claim_digest": "2" * 64,
        },
    }
    command_digest = canonical_digest(command)
    event = {
        "record_type": "Event",
        "event_id": "e:"
        + hashlib.sha256(command_digest.encode("ascii")).hexdigest()[:48],
        "event_kind": "artifact.recorded",
        "activation_digest": activation_digest,
        "payload": artifact,
    }
    batch = {
        "record_type": "EventBatch",
        "batch_id": "b:"
        + hashlib.sha256(command_digest.encode("ascii")).hexdigest()[:48],
        "sequence": 1,
        "previous_digest": None,
        "created_at": created_at,
        "command_id": command["command_id"],
        "idempotency_key": command["idempotency_key"],
        "activation_record_digest": activation_digest,
        "events": [event],
        "subject_id": command["subject_id"],
        "command_intent_digest": command["intent_digest"],
        "command_digest": command_digest,
        "authorization_digest": canonical_digest(command["authorization"]),
    }
    envelope = {"record_type": "JournalEnvelope", "command": command, "batch": batch}
    store.stage(artifact, payload, command_digest=command_digest)
    store.finalize(artifact, command_digest=command_digest, envelope=envelope)
    journal = getattr(store, "_test_evidence_journal", [])
    journal.append(envelope)
    store._test_evidence_journal = journal
    store.reconcile(journal)
    return artifact


def test_authority_conjunctive_scope_rejects_selector_drop() -> None:
    scope_contract = authority_runtime_policy()["scope_contract"]
    allowed = [
        {"kind": "project", "value": "P"},
        {"kind": "path", "value": "src"},
    ]
    assert scope_is_subset(allowed, allowed, scope_contract)
    assert not scope_is_subset(
        [{"kind": "project", "value": "P"}], allowed, scope_contract
    )
    assert scope_is_subset(
        allowed + [{"kind": "task", "value": "T1"}], allowed, scope_contract
    )
    with pytest.raises(AuthorityError, match="unsafe"):
        scope_is_subset(
            [{"kind": "path", "value": "../secret"}],
            allowed,
            scope_contract,
        )


def test_gate_authorization_scope_allows_only_exact_target_and_operational_containment() -> None:
    scope_contract = authority_runtime_policy()["scope_contract"]
    policy_set = json.loads(
        (Path(__file__).parents[1] / "core" / "policy-set.json").read_text(
            encoding="utf-8"
        )
    )
    gate_contract = policy_set["gate_run_definition_contract"][
        "authorization_scope_contract"
    ]
    target = [{"kind": "candidate", "value": CANDIDATE}]

    # Direct domain validation may use the semantic target alone.
    validate_gate_authorization_scope(
        target,
        target,
        task_id="T1",
        scope_contract=scope_contract,
        gate_scope_contract=gate_contract,
    )

    # Lease-bound commands may add only the exact project/Task containment.
    validate_gate_authorization_scope(
        [
            {"kind": "project", "value": "P"},
            {"kind": "task", "value": "T1"},
            *target,
        ],
        target,
        task_id="T1",
        scope_contract=scope_contract,
        gate_scope_contract=gate_contract,
        lease_bound_task_id="T1",
    )

    with pytest.raises(AuthorityError, match="Task containment"):
        validate_gate_authorization_scope(
            [
                {"kind": "task", "value": "T2"},
                *target,
            ],
            target,
            task_id="T1",
            scope_contract=scope_contract,
            gate_scope_contract=gate_contract,
            lease_bound_task_id="T1",
        )

    with pytest.raises(AuthorityError, match="unrelated selector"):
        validate_gate_authorization_scope(
            [
                {"kind": "task", "value": "T1"},
                *target,
                {"kind": "candidate", "value": "d" * 64},
            ],
            target,
            task_id="T1",
            scope_contract=scope_contract,
            gate_scope_contract=gate_contract,
            lease_bound_task_id="T1",
        )

    with pytest.raises(AuthorityError, match="all scope"):
        validate_gate_authorization_scope(
            [{"kind": "all", "value": "*"}],
            target,
            task_id="T1",
            scope_contract=scope_contract,
            gate_scope_contract=gate_contract,
        )


def test_grants_bind_exact_claim_nonce_interval_ceiling_and_revocation() -> None:
    init = authority_init()
    decisions: dict[str, dict[str, Any]] = {}
    engine = AuthorityEngine(
        init,
        ACTIVATION,
        authority_runtime_policy(delegation_depth_max=2),
        decision_resolver=decisions.get,
    )
    root = make_grant(init, "g-root", "root", "authority.manage")
    command = bootstrap_command(init, root)
    validate_definition(core_schema(), "CommandRequest", command)
    root_receipt = engine.authorize_grant_issue_command(command)
    engine.issue_grant(
        root,
        "2026-01-01T00:00:00Z",
        issue_authorization=root_receipt,
    )
    with pytest.raises(AuthorityError, match="disabled"):
        engine.authorize_bootstrap_command(command)

    child = make_grant(init, "g-child", "planner", "task.plan", issuer=root)
    persist_grant(engine, init, child, issuer=root)
    validate_definition(core_schema(), "Grant", root)
    validate_definition(core_schema(), "Grant", child)
    engine.authorize(
        "planner",
        "task.plan",
        [{"kind": "task", "value": "T1"}],
        child["grant_id"],
        child["claim_digest"],
        "2026-05-01T00:00:00Z",
    )

    with pytest.raises(AuthorityError, match="exact Grant claim"):
        engine.authorize(
            "planner",
            "task.plan",
            [{"kind": "task", "value": "T1"}],
            child["grant_id"],
            "0" * 64,
            "2026-05-01T00:00:00Z",
        )

    with pytest.raises(AuthorityError, match="active"):
        engine.authorize(
            "planner",
            "task.plan",
            [{"kind": "task", "value": "T1"}],
            child["grant_id"],
            child["claim_digest"],
            "2025-12-31T23:59:59Z",
            replay=True,
        )

    reused_nonce = make_grant(
        init,
        "g-replay",
        "worker",
        "task.execute",
        issuer=root,
        nonce=child["nonce"],
        issued_at="2026-05-01T00:00:01Z",
    )
    with pytest.raises(AuthorityError, match="nonce"):
        persist_grant(engine, init, reused_nonce, issuer=root)

    overlong = make_grant(
        init,
        "g-overlong",
        "worker",
        "task.execute",
        issuer=root,
        issued_at="2026-05-01T00:00:02Z",
        expires_at="2029-01-01T00:00:00Z",
    )
    with pytest.raises(AuthorityError, match="interval"):
        persist_grant(engine, init, overlong, issuer=root)

    bind_revocation_decision(
        decisions,
        manager=root,
        target=child,
        decision_id="D-revoke-child",
        reason="subject removed",
        created_at="2026-05-31T23:59:59Z",
    )
    engine.revoke_grant(
        {
            "grant_id": "g-child",
            "decision_id": "D-revoke-child",
            "reason": "subject removed",
            "revoked_at": "2026-06-01T00:00:00Z",
        },
        "g-root",
        "root",
    )
    # Replay before the effective time remains valid; current evaluation fails closed.
    engine.authorize(
        "planner",
        "task.plan",
        [{"kind": "task", "value": "T1"}],
        child["grant_id"],
        child["claim_digest"],
        "2026-05-01T00:00:00Z",
        replay=True,
    )
    with pytest.raises(AuthorityError, match="revoked"):
        engine.authorize(
            "planner",
            "task.plan",
            [{"kind": "task", "value": "T1"}],
            child["grant_id"],
            child["claim_digest"],
            "2026-06-01T00:00:00Z",
        )
    with pytest.raises(AuthorityError, match="clock rollback"):
        engine.authorize(
            "planner",
            "task.plan",
            [{"kind": "task", "value": "T1"}],
            child["grant_id"],
            child["claim_digest"],
            "2026-05-31T23:59:59Z",
        )


def test_authority_default_deny_signature_boundary_and_sod() -> None:
    engine, grants = issued_engine()
    with pytest.raises(AuthorityError, match="unresolved"):
        engine.authorize(
            "planner",
            "task.plan",
            [{"kind": "task", "value": "T1"}],
            "missing",
            "0" * 64,
            "2026-02-01T00:00:00Z",
        )

    team_init = authority_init()
    team_init["trust_mode"] = "team-signed"
    team_init["keys"] = [
        {
            "key_id": "key-approver",
            "subject_id": "approver",
            "algorithm": "test-ed25519-boundary",
            "public_key": "test-public-key",
            "fingerprint": "9" * 64,
        }
    ]
    team_init["team_policy"] = {
        "threshold": 1,
        "key_ids": ["key-approver"],
        "signature_provider_capability": "signature",
    }
    signed = {
        "record_type": "Grant",
        "grant_id": "g-signed",
        "subject_id": "planner",
        "capability_id": "task.plan",
        "scope": [{"kind": "all", "value": "*"}],
        "activation_digest": ACTIVATION,
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2028-01-01T00:00:00Z",
        "nonce": "signed-grant-nonce-0001",
    }
    signed["claim_digest"] = canonical_digest(grant_claim_identity(signed))
    signed["trust_proofs"] = [
        {
            "kind": "signature",
            "key_id": "key-approver",
            "algorithm": "test-ed25519-boundary",
            "signed_digest": signed["claim_digest"],
            "signature": "opaque-signature",
        }
    ]
    signed_manager = {
        **deepcopy(signed),
        "grant_id": "g-team-root",
        "subject_id": "root",
        "capability_id": "authority.manage",
        "nonce": "signed-manager-nonce-0001",
    }
    signed_manager["claim_digest"] = canonical_digest(
        grant_claim_identity(signed_manager)
    )
    signed_manager["trust_proofs"] = [
        {
            "kind": "signature",
            "key_id": "key-approver",
            "algorithm": "test-ed25519-boundary",
            "signed_digest": signed_manager["claim_digest"],
            "signature": "opaque-signature",
        }
    ]
    manager_command = bootstrap_command(team_init, signed_manager)
    manager_command["authorization"] = {
        "kind": "root",
        "subject_id": "root",
        "proofs": [
            {
                "kind": "signature-command",
                "key_id": "key-approver",
                "algorithm": "test-ed25519-boundary",
                "signed_intent_digest": manager_command["intent_digest"],
                "signature": "opaque-signature",
            }
        ],
    }
    with pytest.raises(AuthorityError, match="require a verifier"):
        AuthorityEngine(
            team_init, ACTIVATION, authority_runtime_policy()
        ).authorize_grant_issue_command(manager_command)
    calls: list[tuple[str, str]] = []

    def verify_signature(proof: dict[str, Any], key: dict[str, Any]) -> bool:
        signed_digest = proof.get("signed_digest", proof.get("signed_intent_digest"))
        calls.append((signed_digest, key["fingerprint"]))
        return proof["signature"] == "opaque-signature"

    team_engine = AuthorityEngine(
        team_init,
        ACTIVATION,
        authority_runtime_policy(),
        signature_verifier=verify_signature,
    )
    manager_receipt = team_engine.authorize_grant_issue_command(manager_command)
    team_engine.issue_grant(
        signed_manager,
        signed_manager["issued_at"],
        issue_authorization=manager_receipt,
    )
    signed_receipt = team_engine.authorize_grant_issue_command(
        delegated_grant_command(signed, signed_manager)
    )
    team_engine.issue_grant(
        signed,
        signed["issued_at"],
        issue_authorization=signed_receipt,
    )
    assert (signed["claim_digest"], "9" * 64) in calls
    engine.record_action(
        "worker",
        "task.execute",
        authorization=authorization(grants["worker"]),
        candidate_digest=CANDIDATE,
    )
    with pytest.raises(AuthorityError, match="separation-of-duties"):
        engine.assert_separation_of_duties(
            "worker", "release.decide", candidate_digest=CANDIDATE
        )
    # A grant never conveys another capability, even to the same subject.
    with pytest.raises(AuthorityError, match="capability"):
        engine.authorize(
            "planner",
            "release.decide",
            [{"kind": "candidate", "value": "C1"}],
            grants["planner"]["grant_id"],
            grants["planner"]["claim_digest"],
            "2026-02-01T00:00:00Z",
        )


def test_authority_runtime_policy_is_exact_structured_and_digest_bound() -> None:
    model = core_authority_model()
    policy = authority_runtime_policy()

    def resign(value: dict[str, Any]) -> dict[str, Any]:
        value["policy_digest"] = canonical_digest(
            {key: item for key, item in value.items() if key != "policy_digest"}
        )
        return value

    assert set(policy["capability_ids"]) == {
        item["id"] for item in model["capabilities"]
    }
    AuthorityEngine(authority_init(), ACTIVATION, policy)

    malformed = deepcopy(policy)
    malformed["capability_ids"].append(malformed["capability_ids"][0])
    resign(malformed)
    with pytest.raises(AuthorityError, match="capability set"):
        AuthorityEngine(authority_init(), ACTIVATION, malformed)

    unstructured = deepcopy(policy)
    unstructured["separation_of_duties"][1][
        "forbid_same_subject_for_same_candidate"
    ] = ["task.execute"]
    resign(unstructured)
    with pytest.raises(AuthorityError, match="capabilities"):
        AuthorityEngine(authority_init(), ACTIVATION, unstructured)

    unknown_scope = deepcopy(policy)
    unknown_scope["scope_contract"]["kinds"].append("ambient")
    resign(unknown_scope)
    with pytest.raises(AuthorityError, match="scope dispatcher"):
        AuthorityEngine(authority_init(), ACTIVATION, unknown_scope)

    inverted_nonce = deepcopy(policy)
    inverted_nonce["grant_contract"]["nonce"]["min_length"] = (
        inverted_nonce["grant_contract"]["nonce"]["max_length"] + 1
    )
    resign(inverted_nonce)
    with pytest.raises(AuthorityError, match="nonce"):
        AuthorityEngine(authority_init(), ACTIVATION, inverted_nonce)

    unknown_proof = deepcopy(policy)
    unknown_proof["grant_contract"]["trust_proof_kinds"]["ambient"] = {
        "required_fields": ["kind"]
    }
    resign(unknown_proof)
    with pytest.raises(AuthorityError, match="proof dispatcher"):
        AuthorityEngine(authority_init(), ACTIVATION, unknown_proof)

    unknown_sod = deepcopy(policy)
    unknown_sod["separation_of_duties_contract"]["supported_rule_fields"][
        "forbid_ambient_authority"
    ] = {"cardinality": "unique-list", "items_min": 1}
    resign(unknown_sod)
    with pytest.raises(AuthorityError, match="dispatcher mismatch"):
        AuthorityEngine(authority_init(), ACTIVATION, unknown_sod)

    wrong_sod_capabilities = deepcopy(policy)
    wrong_sod_capabilities["separation_of_duties_capability_ids"].pop()
    resign(wrong_sod_capabilities)
    with pytest.raises(AuthorityError, match="dispatcher mismatch"):
        AuthorityEngine(authority_init(), ACTIVATION, wrong_sod_capabilities)

    detached_timestamp = deepcopy(policy)
    detached_timestamp["canonical_timestamp_contract"]["parser_api"] = (
        "detached.parse(value)"
    )
    resign(detached_timestamp)
    with pytest.raises(AuthorityError, match="timestamp dispatcher"):
        AuthorityEngine(authority_init(), ACTIVATION, detached_timestamp)

    stale_digest = deepcopy(policy)
    stale_digest["delegation_depth_max"] += 1
    with pytest.raises(AuthorityError, match="digest mismatch"):
        AuthorityEngine(authority_init(), ACTIVATION, stale_digest)


def test_grant_issue_receipt_binds_command_issuer_claim_and_current_state() -> None:
    init = authority_init()
    decisions: dict[str, dict[str, Any]] = {}
    engine = AuthorityEngine(
        init,
        ACTIVATION,
        authority_runtime_policy(),
        decision_resolver=decisions.get,
    )
    root = make_grant(init, "g-root-receipt", "root", "authority.manage")
    persist_grant(engine, init, root)
    child = make_grant(
        init,
        "g-child-receipt",
        "planner",
        "task.plan",
        issuer=root,
        scope=[{"kind": "task", "value": "T1"}],
    )

    wrong_proof = deepcopy(child)
    wrong_proof["trust_proofs"][0]["issuer_signed_claim_digest"] = "0" * 64
    with pytest.raises(AuthorityError, match="issuer proof differs"):
        engine.authorize_grant_issue_command(
            delegated_grant_command(wrong_proof, root)
        )

    wrong_subject = delegated_grant_command(child, root)
    wrong_subject["subject_id"] = "planner"
    wrong_subject["intent_digest"] = canonical_digest(
        {
            key: value
            for key, value in wrong_subject.items()
            if key not in {"intent_digest", "authorization"}
        }
    )
    with pytest.raises(AuthorityError, match="subject mismatch"):
        engine.authorize_grant_issue_command(wrong_subject)

    receipt = engine.authorize_grant_issue_command(
        delegated_grant_command(child, root)
    )
    tampered = deepcopy(receipt)
    tampered["requested_scope"] = [{"kind": "task", "value": "T2"}]
    tampered["authorization_digest"] = canonical_digest(
        {key: value for key, value in tampered.items() if key != "authorization_digest"}
    )
    with pytest.raises(AuthorityError, match="not issued by this authority transaction"):
        engine.issue_grant(
            child,
            child["issued_at"],
            issue_authorization=tampered,
        )

    bind_revocation_decision(
        decisions,
        manager=root,
        target=root,
        decision_id="D-root-rotation",
        reason="root rotation",
        created_at=child["issued_at"],
    )
    engine.revoke_grant(
        {
            "grant_id": root["grant_id"],
            "decision_id": "D-root-rotation",
            "reason": "root rotation",
            "revoked_at": child["issued_at"],
        },
        root["grant_id"],
        "root",
    )
    with pytest.raises(AuthorityError, match="binding changed"):
        engine.issue_grant(
            child,
            child["issued_at"],
            issue_authorization=receipt,
        )


def test_grant_issue_enforces_scope_aware_structured_sod() -> None:
    init = authority_init()
    engine = AuthorityEngine(init, ACTIVATION, authority_runtime_policy())
    root = make_grant(init, "g-root-sod", "root", "authority.manage")
    persist_grant(engine, init, root)
    executed_a = make_grant(
        init,
        "g-execute-a",
        "worker",
        "task.execute",
        issuer=root,
        scope=[{"kind": "candidate", "value": "candidate-A"}],
    )
    persist_grant(engine, init, executed_a, issuer=root)
    release_b = make_grant(
        init,
        "g-release-b",
        "worker",
        "release.decide",
        issuer=root,
        scope=[{"kind": "candidate", "value": "candidate-B"}],
    )
    persist_grant(engine, init, release_b, issuer=root)
    release_a = make_grant(
        init,
        "g-release-a",
        "worker",
        "release.decide",
        issuer=root,
        scope=[{"kind": "candidate", "value": "candidate-A"}],
    )
    with pytest.raises(AuthorityError, match="Grant conflict"):
        persist_grant(engine, init, release_a, issuer=root)


def test_revocation_decision_reference_requires_immutable_resolved_event() -> None:
    bindings: dict[str, dict[str, Any]] = {}
    engine, grants = issued_engine(decision_resolver=bindings.get)
    child = grants["planner"]
    with pytest.raises(AuthorityError, match="invalid Grant revocation shape"):
        engine.revoke_grant(
            {
                "grant_id": child["grant_id"],
                "reason": "missing immutable Decision",
                "revoked_at": "2026-03-01T00:00:00Z",
            },
            grants["root"]["grant_id"],
            "root",
        )
    with pytest.raises(AuthorityError, match="unresolved"):
        engine.revoke_grant(
            {
                "grant_id": child["grant_id"],
                "decision_id": "D-missing",
                "reason": "unresolved reference",
                "revoked_at": "2026-03-01T00:00:00Z",
            },
            grants["root"]["grant_id"],
            "root",
        )

    decision = {
        "record_type": "Decision",
        "decision_id": "D-revoke-planner",
        "decision_kind": "revoke",
        "subject_id": grants["root"]["subject_id"],
        "grant_id": grants["root"]["grant_id"],
        "grant_claim_digest": grants["root"]["claim_digest"],
        "activation_digest": ACTIVATION,
        "target_type": "Grant",
        "target_id": child["grant_id"],
        "target_digest": canonical_digest(child),
        "rationale": "verified authority revocation",
        "evidence_artifacts": [
            {
                "artifact_id": "E-revoke-planner-evidence",
                "artifact_record_digest": "7" * 64,
            }
        ],
        "created_at": "2026-02-28T23:59:59Z",
    }
    event = {
        "record_type": "Event",
        "event_id": "E-revoke-planner",
        "event_kind": "decision.recorded",
        "activation_digest": ACTIVATION,
        "payload": deepcopy(decision),
    }
    bindings[decision["decision_id"]] = {"decision": decision, "event": event}
    engine.revoke_grant(
        {
            "grant_id": child["grant_id"],
            "decision_id": decision["decision_id"],
            "reason": "verified authority revocation",
            "revoked_at": "2026-03-01T00:00:00Z",
        },
        grants["root"]["grant_id"],
        "root",
    )
    stored = engine.revocations[child["grant_id"]]
    assert stored["decision_binding"]["decision_digest"] == canonical_digest(decision)
    assert stored["decision_binding"]["event_digest"] == canonical_digest(event)


def test_authority_transaction_overlay_isolated_freezable_and_reusable() -> None:
    engine, grants = issued_engine()
    base_checkpoint = engine.checkpoint()
    base_result = engine.freeze(runtime_overlay_compaction_depth=2)
    base = base_result.snapshot
    assert base.is_frozen
    assert base_result.changed_leaf_count > 0
    assert base_result.compacted is False
    assert base.freeze(runtime_overlay_compaction_depth=2) is base_result

    resolver_records: dict[str, dict[str, Any]] = {}
    resolver = resolver_records.get
    transaction = base.fork(decision_resolver=resolver)
    assert not transaction.is_frozen
    assert transaction._grants._base is base._grants
    child = make_grant(
        authority_init(),
        "g-overlay-child",
        "planner",
        "task.plan",
        issuer=grants["root"],
        issued_at="2026-04-01T00:00:00Z",
        nonce="nonce-g-overlay-child-00000000",
    )
    persist_grant(
        transaction,
        authority_init(),
        child,
        issuer=grants["root"],
    )
    candidate_overlay = "b" * 64
    transaction.record_action(
        "planner",
        "task.plan",
        authorization=authorization(
            child,
            at="2026-04-15T00:00:00Z",
        ),
        candidate_digest=candidate_overlay,
    )
    transaction.record_action(
        "resolver",
        "finding.resolve",
        authorization=authorization(
            grants["resolver"],
            at="2026-04-15T00:00:00Z",
        ),
        finding_id="finding-overlay",
    )
    bind_revocation_decision(
        resolver_records,
        manager=grants["root"],
        target=child,
        decision_id="D-overlay-child",
        reason="transaction-only revocation",
        created_at="2026-04-30T23:59:59Z",
    )
    transaction.revoke_grant(
        {
            "grant_id": child["grant_id"],
            "decision_id": "D-overlay-child",
            "reason": "transaction-only revocation",
            "revoked_at": "2026-05-01T00:00:00Z",
        },
        grants["root"]["grant_id"],
        "root",
    )

    assert base.checkpoint() == base_checkpoint
    assert child["grant_id"] not in base.grants
    assert child["grant_id"] not in base.revocations
    sibling = base.fork()
    assert child["grant_id"] not in sibling.grants

    published_result = transaction.freeze(runtime_overlay_compaction_depth=2)
    published = published_result.snapshot
    assert published.is_frozen
    assert published_result.changed_leaf_count == 6
    assert published_result.compacted is False
    assert published.decision_resolver is resolver
    assert child["grant_id"] in published.grants
    assert child["grant_id"] in published.revocations
    checkpoint = published.checkpoint()
    candidate_provenance = checkpoint["candidate_actions"][0]
    assert candidate_provenance["target_kind"] == "candidate"
    assert candidate_provenance["target_id"] == candidate_overlay
    assert candidate_provenance["grant_id"] == child["grant_id"]
    assert candidate_provenance["grant_claim_digest"] == child["claim_digest"]
    finding_provenance = checkpoint["finding_actions"][0]
    assert finding_provenance["target_kind"] == "finding"
    assert finding_provenance["target_id"] == "finding-overlay"
    assert finding_provenance["grant_id"] == grants["resolver"]["grant_id"]
    restored = AuthorityEngine(
        authority_init(),
        ACTIVATION,
        authority_runtime_policy(),
        decision_resolver=resolver,
    )
    restored.restore_checkpoint(checkpoint)
    assert restored.checkpoint() == checkpoint
    substituted_provenance = deepcopy(checkpoint)
    substituted_provenance["candidate_actions"][0]["grant_claim_digest"] = "0" * 64
    substituted_identity = {
        key: deepcopy(value)
        for key, value in substituted_provenance.items()
        if key != "checkpoint_digest"
    }
    substituted_provenance["checkpoint_digest"] = canonical_digest(
        substituted_identity
    )
    with pytest.raises(AuthorityError, match="action provenance"):
        AuthorityEngine(
            authority_init(),
            ACTIVATION,
            authority_runtime_policy(),
            decision_resolver=resolver,
        ).restore_checkpoint(substituted_provenance)
    with pytest.raises(AuthorityError, match="frozen"):
        published.record_action(
            "planner",
            "task.plan",
            authorization=authorization(child, at="2026-05-01T00:00:00Z"),
            candidate_digest="c" * 64,
        )

    next_transaction = published.fork()
    candidate_next = "d" * 64
    next_transaction.record_action(
        "planner",
        "task.plan",
        authorization=authorization(
            grants["planner"],
            at="2026-06-01T00:00:00Z",
        ),
        candidate_digest=candidate_next,
    )
    assert candidate_next not in {
        row["target_id"] for row in published.checkpoint()["candidate_actions"]
    }
    compacted_result = next_transaction.freeze(
        runtime_overlay_compaction_depth=2
    )
    assert compacted_result.changed_leaf_count == 2
    assert compacted_result.compacted is True
    assert compacted_result.compacted_record_count > 0
    assert compacted_result.compacted_payload_bytes > 0
    assert compacted_result.snapshot._candidate_actions.depth == 0


def test_current_access_binds_projection_read_grant_activation_and_revocation() -> None:
    decisions: dict[str, dict[str, Any]] = {}
    engine, grants = issued_engine(decision_resolver=decisions.get)
    reader = grants["reader"]
    access = {
        "subject_id": reader["subject_id"],
        "grant_id": reader["grant_id"],
        "claim_digest": reader["claim_digest"],
        "evaluated_at": "2026-02-01T00:00:00Z",
        "activation_digest": ACTIVATION,
    }
    receipt = engine.authorize_current_access(
        access,
        "projection.read",
        [{"kind": "candidate", "value": "C1"}],
        ACTIVATION,
    )
    assert receipt["subject_id"] == "worker"
    assert receipt["grant_id"] == reader["grant_id"]
    assert receipt["claim_digest"] == reader["claim_digest"]
    assert receipt["capability_id"] == "projection.read"
    assert receipt["grant"] == reader
    before_revocation = receipt["revocation_state_digest"]

    with pytest.raises(AuthorityError, match="subject"):
        engine.authorize_current_access(
            dict(access, subject_id="planner"),
            "projection.read",
            [{"kind": "candidate", "value": "C1"}],
            ACTIVATION,
        )
    with pytest.raises(AuthorityError, match="exact Grant claim"):
        engine.authorize_current_access(
            dict(access, claim_digest="0" * 64),
            "projection.read",
            [{"kind": "candidate", "value": "C1"}],
            ACTIVATION,
        )
    with pytest.raises(AuthorityError, match="Activation"):
        engine.authorize_current_access(
            dict(access, activation_digest="b" * 64),
            "projection.read",
            [{"kind": "candidate", "value": "C1"}],
            "b" * 64,
        )
    with pytest.raises(AuthorityError, match="capability"):
        engine.authorize_current_access(
            access,
            "candidate.promote",
            [{"kind": "candidate", "value": "C1"}],
            ACTIVATION,
        )

    bind_revocation_decision(
        decisions,
        manager=grants["root"],
        target=reader,
        decision_id="D-reader-withdrawn",
        reason="read access withdrawn",
        created_at="2026-02-28T23:59:59Z",
    )
    engine.revoke_grant(
        {
            "grant_id": reader["grant_id"],
            "decision_id": "D-reader-withdrawn",
            "reason": "read access withdrawn",
            "revoked_at": "2026-03-01T00:00:00Z",
        },
        grants["root"]["grant_id"],
        "root",
    )
    assert engine.grant_revocation_state_digest(reader["grant_id"]) != before_revocation
    with pytest.raises(AuthorityError, match="revoked"):
        engine.authorize_current_access(
            dict(access, evaluated_at="2026-03-01T00:00:00Z"),
            "projection.read",
            [{"kind": "candidate", "value": "C1"}],
            ACTIVATION,
        )

    expiry_engine, expiry_grants = issued_engine()
    expired_reader = expiry_grants["reader"]
    with pytest.raises(AuthorityError, match="not active"):
        expiry_engine.authorize_current_access(
            {
                "subject_id": expired_reader["subject_id"],
                "grant_id": expired_reader["grant_id"],
                "claim_digest": expired_reader["claim_digest"],
                "evaluated_at": expired_reader["expires_at"],
                "activation_digest": ACTIVATION,
            },
            "projection.read",
            [{"kind": "candidate", "value": "C1"}],
            ACTIVATION,
        )


def _standard_candidate_binding() -> dict[str, Any]:
    identity = {
        "record_type": "StandardReleaseCandidateBinding",
        "standard_name": "promin",
        "version": "1.0.0",
        "archive_sha256": "0" * 64,
        "archive_bytes": 4096,
        "archive_member_manifest_digest": "1" * 64,
        "package_manifest_digest": "2" * 64,
        "checksums_digest": "3" * 64,
        "core_bundle_digest": "4" * 64,
        "preset_digest": "5" * 64,
        "package_tool_digest": "6" * 64,
        "validator_digest": "7" * 64,
        "test_manifest_digest": "8" * 64,
        "portable_implementation_closure_digest": "9" * 64,
        "evidence_tool_digests": {
            "tools/generate_human.py": "a" * 64,
            "tools/promin_no_degradation.py": "b" * 64,
            "tools/promin_package.py": "c" * 64,
            "tools/promin_saturation.py": "d" * 64,
            "tools/promin_saturation_audit.py": "e" * 64,
            "tools/promin_validate.py": "f" * 64,
        },
    }
    return {**identity, "candidate_binding_digest": canonical_digest(identity)}


def _fabricated_standard_evidence_manifest(
    root: Path,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    required: dict[str, tuple[str, dict[str, Any]]] = {
        "exact-package": (
            "ExactPackageVerification",
            {"valid": True, "byte_deterministic": True},
        ),
        "linux": (
            "PlatformVerificationResult",
            {"platform": "linux", "exact_candidate_verified": True},
        ),
        "windows": (
            "PlatformVerificationResult",
            {"platform": "windows", "exact_candidate_verified": True},
        ),
        "physical-scale": (
            "SaturationEvidence",
            {
                "physical_files": 100_000,
                "core_valid_relations": 198_999,
                "core_valid_relations_exact_198999": True,
                "runtime_queries": 600,
                "silent_truncations": 0,
                "selected_closure_union_completeness": 1,
                "memory_amplification_at_most_32": True,
                "broad_query_refinement_required": True,
                "high_cardinality_terms_verified": True,
                "content_search_verified": True,
                "miss_behavior_verified": True,
                "hostile_proxy_content_verified": True,
                "exact_artifact_search_verified": True,
                "mixed_query_classes_complete": True,
                "continuation_token_bytes_at_most_256": True,
                "continuation_state_bytes_at_most_16384": True,
                "continuation_token_overhead_at_most_10_percent": True,
            },
        ),
        "saturation-audit": (
            "SaturationAudit",
            {"zero_new_iterations": 3, "new_findings": 0},
        ),
        "linux-no-degradation": (
            "NoDegradationResult",
            {"platform": "linux", "no_degradation": True},
        ),
        "windows-no-degradation": (
            "NoDegradationResult",
            {"platform": "windows", "no_degradation": True},
        ),
    }
    document_rows = [
        {
            "path": path,
            "sha256": f"{index:x}" * 64,
            "size_bytes": 2048 + index,
            "page_count": 1,
            "extracted_characters": 100 + index,
            "blank_pages": [],
            "extraction_errors": [],
        }
        for index, path in enumerate(
            (
                "human/promin_appendices_en.pdf",
                "human/promin_appendices_ua.pdf",
                "human/promin_main_en.pdf",
                "human/promin_main_ua.pdf",
            ),
            start=1,
        )
    ]
    rebuild_rows = [
        {
            key: row[key]
            for key in ("path", "sha256", "size_bytes", "page_count")
        }
        for row in document_rows
    ]
    required["human-documents"] = (
        "HumanDocumentVerification",
        {
            "documents": document_rows,
            "deterministic_rebuild": True,
            "rebuild_digest": canonical_digest(rebuild_rows),
            "page_count": 4,
            "extraction_diagnostics": {
                "documents_parsed": 4,
                "total_extracted_characters": sum(
                    row["extracted_characters"] for row in document_rows
                ),
                "blank_pages": [],
                "errors": [],
            },
            "visual_review_scope": {
                "completed": True,
                "reviewer_id": "fixture-reviewer",
                "reviewed_at": "2026-07-18T11:00:00Z",
                "rendered_page_count": 4,
                "pages_reviewed": 4,
                "clipping_detected": False,
                "unreadable_text_detected": False,
            },
            "product_acceptance_pass": False,
        },
    )
    entries: list[dict[str, Any]] = []
    for index, (role, (record_type, facts)) in enumerate(required.items(), start=1):
        relative = f"evidence-{index:02d}.json"
        evidence = {
            "record_type": record_type,
            "status": "pass",
            "candidate_binding_digest": candidate["candidate_binding_digest"],
            **facts,
        }
        path = root / relative
        path.write_text(
            json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        entries.append(
            {
                "evidence_id": f"fixture-evidence-{index:02d}",
                "evidence_role": role,
                "path": relative,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size_bytes": path.stat().st_size,
                "record_type": record_type,
                "status": "pass",
                "candidate_binding_digest": candidate["candidate_binding_digest"],
                "predicates": (
                    [
                        {
                            "pointer": "/visual_review_scope/completed",
                            "equals": True,
                        },
                        {
                            "pointer": "/visual_review_scope/clipping_detected",
                            "equals": False,
                        },
                        {
                            "pointer": "/visual_review_scope/unreadable_text_detected",
                            "equals": False,
                        },
                        {"pointer": "/deterministic_rebuild", "equals": True},
                    ]
                    if role == "human-documents"
                    else [
                        {"pointer": f"/{key}", "equals": value}
                        for key, value in facts.items()
                    ]
                ),
            }
        )
    identity = {
        "record_type": "StandardReleaseEvidenceManifest",
        "standard_name": "promin",
        "version": candidate["version"],
        "candidate_binding_digest": candidate["candidate_binding_digest"],
        "entries": entries,
        "max_evidence_completed_at": "2026-07-18T11:00:00Z",
    }
    return {**identity, "evidence_manifest_digest": canonical_digest(identity)}


def _standard_trust_configuration(
    private_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "record_type": "StandardReleaseTrustConfiguration",
        "trust_root_id": "fixture-trust-root",
        "signature_provider_id": "cryptography-ed25519-v1",
        "algorithm": "Ed25519",
        "keys": [
            {
                "key_id": "fixture-decision-key",
                "subject_id": "fixture-operator",
                "capabilities": ["standard.distribute"],
                "evidence_roles": [],
                "platforms": [],
                "public_key": base64.b64encode(public_key).decode("ascii"),
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "revoked": False,
            }
        ],
    }


def _signed_standard_decision(
    private_key: Ed25519PrivateKey,
    candidate: dict[str, Any],
    manifest: dict[str, Any],
    *,
    outcome: str,
    decision_id: str,
    version: str | None = None,
    candidate_binding_digest: str | None = None,
    key_id: str = "fixture-decision-key",
    nonce: str | None = None,
    decided_at: str = "2026-07-18T12:00:00Z",
) -> dict[str, Any]:
    identity = {
        "record_type": "StandardReleaseDecision",
        "decision_id": decision_id,
        "standard_name": "promin",
        "version": version or candidate["version"],
        "candidate_binding_digest": (
            candidate_binding_digest or candidate["candidate_binding_digest"]
        ),
        "evidence_manifest_digest": manifest["evidence_manifest_digest"],
        "outcome": outcome,
        "decider_id": "fixture-operator",
        "release_capability": "standard.distribute",
        "trust_root_id": "fixture-trust-root",
        "signature_provider_id": "cryptography-ed25519-v1",
        "key_id": key_id,
        "nonce": nonce
        or base64.b64encode(b"fixture-nonce-000000000001").decode("ascii"),
        "decided_at": decided_at,
    }
    claim_digest = canonical_digest(identity)
    return {
        **identity,
        "signed_claim_digest": claim_digest,
        "signature": base64.b64encode(
            private_key.sign(bytes.fromhex(claim_digest))
        ).decode("ascii"),
    }


def test_release_evidence_attestation_binds_role_platform_payload_and_sod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer_key = Ed25519PrivateKey.generate()
    public_key = producer_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_path = tmp_path / "producer.key"
    private_path.write_bytes(
        producer_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    producer_entry = {
        "key_id": "fixture-windows-evidence-key",
        "subject_id": "fixture-windows-producer",
        "capabilities": ["evidence.produce"],
        "evidence_roles": ["windows"],
        "platforms": ["windows"],
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
        "revoked": False,
    }
    trust = {
        "record_type": "StandardReleaseTrustConfiguration",
        "trust_root_id": "fixture-evidence-trust-root",
        "signature_provider_id": "cryptography-ed25519-v1",
        "algorithm": "Ed25519",
        "keys": [producer_entry],
    }
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(
        json.dumps(trust, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    monkeypatch.setenv("PROMIN_EVIDENCE_PRIVATE_KEY", str(private_path))
    monkeypatch.setenv("PROMIN_EVIDENCE_TRUST_CONFIGURATION", str(trust_path))
    monkeypatch.setenv("PROMIN_EVIDENCE_KEY_ID", producer_entry["key_id"])

    candidate = {"candidate_binding_digest": "4" * 64}
    record = {
        "record_type": "PlatformVerificationResult",
        "candidate_binding_digest": candidate["candidate_binding_digest"],
        "platform": "windows",
        "installation": {"installed": True},
        "platform_identity": {"system": "windows"},
        "observed_environment_closure_digest": "5" * 64,
        "invocation": release_evidence_invocation(
            invocation_id="attestation:windows:fixture",
            operation="verify-platform",
            arguments={"fixture": True},
            started_at="2026-07-18T10:00:00Z",
            completed_at="2026-07-18T10:00:01Z",
            exit_code=0,
            platform_binding={"platform": "windows"},
        ),
    }
    sealed = seal_release_evidence(record)
    attestation = _validate_producer_attestation(
        sealed,
        candidate=candidate,
        expected_role="windows",
        expected_platform="windows",
    )
    _validate_evidence_attestation_trust(
        attestation,
        trust=trust,
        expected_role="windows",
        expected_platform="windows",
    )

    tampered = json.loads(json.dumps(sealed))
    tampered["installation"]["installed"] = False
    with pytest.raises(EvidenceError, match="raw-artifact manifest digest mismatch"):
        _validate_producer_attestation(
            tampered,
            candidate=candidate,
            expected_role="windows",
            expected_platform="windows",
        )
    unsigned = dict(sealed)
    unsigned.pop("producer_attestation")
    with pytest.raises(EvidenceError, match="attestation scope is invalid"):
        _validate_producer_attestation(
            unsigned,
            candidate=candidate,
            expected_role="windows",
            expected_platform="windows",
        )
    wrong_scope = {**trust, "keys": [{**producer_entry, "evidence_roles": ["linux"]}]}
    with pytest.raises(EvidenceError, match="wrongly scoped"):
        _validate_evidence_attestation_trust(
            attestation,
            trust=wrong_scope,
            expected_role="windows",
            expected_platform="windows",
        )

    decision_key = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sod_violation = {
        **trust,
        "keys": [
            producer_entry,
            {
                "key_id": "fixture-distribution-key",
                "subject_id": producer_entry["subject_id"],
                "capabilities": ["standard.distribute"],
                "evidence_roles": [],
                "platforms": [],
                "public_key": base64.b64encode(decision_key).decode("ascii"),
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "revoked": False,
            },
        ],
    }
    with pytest.raises(EvidenceError, match="separation of duties"):
        _validate_trust_configuration(sod_violation)


def _producer_private_key(path: Path, key: Ed25519PrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def _producer_trust_entry(
    key: Ed25519PrivateKey,
    *,
    key_id: str,
    subject_id: str,
    roles: list[str],
    platform_name: str = "windows",
) -> dict[str, Any]:
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "key_id": key_id,
        "subject_id": subject_id,
        "capabilities": ["evidence.produce"],
        "evidence_roles": sorted(roles),
        "platforms": [platform_name],
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "not_before": "2026-01-01T00:00:00Z",
        "not_after": "2027-01-01T00:00:00Z",
        "revoked": False,
    }


def _producer_trust(entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "record_type": "StandardReleaseTrustConfiguration",
        "trust_root_id": "fixture-saturation-trust-root",
        "signature_provider_id": "cryptography-ed25519-v1",
        "algorithm": "Ed25519",
        "keys": entries,
    }


def test_release_evidence_chronology_rejects_reverse_future_and_signing_drift() -> None:
    valid = {
        "invocation": {
            "started_at": "2026-07-22T10:00:00Z",
            "completed_at": "2026-07-22T10:00:01Z",
        },
        "producer_attestation": {"signed_at": "2026-07-22T10:00:01Z"},
    }
    assert evidence_module._validate_release_evidence_chronology(
        valid,
        verification_time="2026-07-22T10:00:02Z",
    ) == parse_timestamp("2026-07-22T10:00:01Z")
    reverse = deepcopy(valid)
    reverse["invocation"]["started_at"] = "2026-07-22T10:00:02Z"
    with pytest.raises(EvidenceError, match="chronology"):
        evidence_module._validate_release_evidence_chronology(
            reverse,
            verification_time="2026-07-22T10:00:02Z",
        )
    signing_drift = deepcopy(valid)
    signing_drift["producer_attestation"]["signed_at"] = "2026-07-22T10:00:00Z"
    with pytest.raises(EvidenceError, match="chronology"):
        evidence_module._validate_release_evidence_chronology(
            signing_drift,
            verification_time="2026-07-22T10:00:02Z",
        )
    future = deepcopy(valid)
    future["invocation"]["started_at"] = "2026-07-22T10:05:01Z"
    future["invocation"]["completed_at"] = "2026-07-22T10:05:02Z"
    future["producer_attestation"]["signed_at"] = "2026-07-22T10:05:02Z"
    with pytest.raises(EvidenceError, match="bounded verifier clock skew"):
        evidence_module._validate_release_evidence_chronology(
            future,
            verification_time="2026-07-22T10:00:01Z",
        )
    outer_completed = parse_timestamp("2026-07-22T10:00:10Z")
    evidence_module._validate_nested_completion(
        parse_timestamp("2026-07-22T10:00:09Z"),
        outer_completed,
    )
    with pytest.raises(EvidenceError, match="nested physical completion"):
        evidence_module._validate_nested_completion(
            parse_timestamp("2026-07-22T10:00:11Z"),
            outer_completed,
        )
    evidence_module._validate_human_review_chronology(
        parse_timestamp("2026-07-22T10:00:05Z"),
        parse_timestamp("2026-07-22T10:00:00Z"),
        outer_completed,
        outer_completed,
    )
    with pytest.raises(EvidenceError, match="outside its signed invocation"):
        evidence_module._validate_human_review_chronology(
            parse_timestamp("2026-07-22T10:00:11Z"),
            parse_timestamp("2026-07-22T10:00:00Z"),
            outer_completed,
            outer_completed,
        )
    assert evidence_module._derived_max_evidence_completion(
        [
            parse_timestamp("2026-07-22T10:00:01Z"),
            parse_timestamp("2026-07-22T10:00:09Z"),
            parse_timestamp("2026-07-22T10:00:12Z"),
        ]
    ) == "2026-07-22T10:00:12Z"


def test_manifest_trust_requires_exactly_seven_distinct_role_producers() -> None:
    roles = sorted(evidence_module._REQUIRED_STANDARD_EVIDENCE)
    entries = [
        _producer_trust_entry(
            Ed25519PrivateKey.generate(),
            key_id=f"fixture-{role}-key",
            subject_id=f"fixture-{role}-producer",
            roles=[role],
            platform_name=("linux" if role.startswith("linux") else "windows"),
        )
        for role in roles
    ]
    trust = _producer_trust(entries)
    validated = evidence_module._validate_trust_configuration(
        trust,
        require_complete_evidence_roles=True,
    )
    assert len(validated["keys"]) == 7

    incomplete = {**trust, "keys": trust["keys"][:-1]}
    with pytest.raises(EvidenceError, match="exactly seven"):
        evidence_module._validate_trust_configuration(
            incomplete,
            require_complete_evidence_roles=True,
        )
    overbroad = deepcopy(trust)
    overbroad["keys"][0]["evidence_roles"] = sorted(
        [overbroad["keys"][0]["evidence_roles"][0], roles[1]]
    )
    with pytest.raises(EvidenceError, match="role/platform"):
        evidence_module._validate_trust_configuration(overbroad)
    overbroad_platform = deepcopy(trust)
    linux_entry = next(
        entry
        for entry in overbroad_platform["keys"]
        if entry["evidence_roles"] == ["linux"]
    )
    linux_entry["platforms"] = ["linux", "windows"]
    with pytest.raises(EvidenceError, match="over-broad or wrong platform"):
        evidence_module._validate_trust_configuration(overbroad_platform)
    duplicate_role = deepcopy(trust)
    duplicate_role["keys"][1]["evidence_roles"] = duplicate_role["keys"][0][
        "evidence_roles"
    ]
    with pytest.raises(EvidenceError, match="multiple configured keys"):
        evidence_module._validate_trust_configuration(duplicate_role)
    duplicate_subject = deepcopy(trust)
    duplicate_subject["keys"][1]["subject_id"] = duplicate_subject["keys"][0][
        "subject_id"
    ]
    with pytest.raises(EvidenceError, match="distinct subjects"):
        evidence_module._validate_trust_configuration(duplicate_subject)


def test_matrix_manifest_requires_exact_cp314_set_and_digest_size(
    tmp_path: Path,
) -> None:
    supplemental = [
        {
            "lane_id": lane_id,
            "path": evidence_module._REQUIRED_MATRIX_LANES[lane_id]["path"],
            "sha256": "1" * 64,
            "size_bytes": 1,
            "record_type": evidence_module._REQUIRED_MATRIX_LANES[lane_id][
                "record_type"
            ],
            "status": "pass",
            "candidate_binding_digest": "2" * 64,
            "result_digest": "3" * 64,
            "evidence_role": evidence_module._REQUIRED_MATRIX_LANES[lane_id][
                "evidence_role"
            ],
            "producer_attestation_digest": "4" * 64,
        }
        for lane_id in sorted(evidence_module._REQUIRED_SUPPLEMENTAL_MATRIX_LANES)
    ]
    assert set(evidence_module._supplemental_matrix_bindings_by_id(supplemental)) == set(
        evidence_module._REQUIRED_SUPPLEMENTAL_MATRIX_LANES
    )
    with pytest.raises(EvidenceError, match="set is not exact"):
        evidence_module._supplemental_matrix_bindings_by_id(supplemental[:-1])
    extra = [*supplemental, {**supplemental[-1], "lane_id": "unexpected-cp314"}]
    with pytest.raises(EvidenceError, match="set is not exact"):
        evidence_module._supplemental_matrix_bindings_by_id(extra)

    matrix_path = tmp_path / "matrix-current" / "platform-no-degradation-matrix.json"
    matrix_path.parent.mkdir()
    matrix_path.write_text("{}\n", encoding="utf-8", newline="\n")
    binding = {
        "path": "matrix-current/platform-no-degradation-matrix.json",
        "sha256": "0" * 64,
        "size_bytes": matrix_path.stat().st_size,
        "record_type": "ProminPlatformNoDegradationMatrix",
        "matrix_digest": "5" * 64,
        "lane_count": 8,
        "matrix_authoritative": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "product_public_approval": "not_approved",
    }
    with pytest.raises(EvidenceError, match="digest/size mismatch"):
        evidence_module._validate_matrix_aggregate(
            binding,
            supplemental,
            candidate={},
            evidence_root=tmp_path,
            trust={},
            authority_records={},
            attestation_graph=[],
            verification_time=datetime(2026, 7, 22, tzinfo=timezone.utc),
        )
    with pytest.raises(EvidenceError, match="binding shape"):
        evidence_module._validate_matrix_aggregate(
            {**binding, "unexpected": True},
            supplemental,
            candidate={},
            evidence_root=tmp_path,
            trust={},
            authority_records={},
            attestation_graph=[],
            verification_time=datetime(2026, 7, 22, tzinfo=timezone.utc),
        )


def _write_producer_trust(path: Path, trust: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(trust, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _no_degradation_runtime_record(platform_name: str) -> dict[str, Any]:
    if platform_name == "windows":
        machine = "amd64"
        release = "11"
        sys_platform = "win32"
        abi_tag = "cp313-win_amd64"
        platform_tags = ["cp313-cp313-win_amd64"]
        prefix = "C:/fixture/venv"
        base_prefix = "C:/Python313"
        executable = "C:/fixture/venv/Scripts/python.exe"
        base_executable = "C:/Python313/python.exe"
        executable_sha256 = "2" * 64
        controller_sha256 = "1" * 64
    else:
        machine = "x86_64"
        release = "6.6.0-fixture"
        sys_platform = "linux"
        abi_tag = "cpython-313-x86_64-linux-gnu"
        platform_tags = ["cp313-cp313-manylinux_2_39_x86_64"]
        prefix = "/tmp/fixture/venv"
        base_prefix = "/opt/python-3.13.6"
        executable = "/tmp/fixture/venv/bin/python"
        base_executable = "/opt/python-3.13.6/bin/python3.13"
        executable_sha256 = "2" * 64
        controller_sha256 = executable_sha256
    platform_binding = {
        "system": platform_name,
        "release": release,
        "machine": machine,
        "python_implementation": "CPython",
        "python_version": "3.13.6",
        "python_executable_sha256": "sha256:" + controller_sha256,
        "sqlite_version": "3.50.4",
        "profile_key": f"{platform_name}-{machine}-cpython-3.13",
    }
    platform_binding["binding_digest"] = "sha256:" + canonical_digest(platform_binding)
    observation = {
        "python": {
            "executable": executable,
            "executable_sha256": executable_sha256,
            "base_executable": base_executable,
            "base_executable_sha256": controller_sha256,
            "implementation": "cpython",
            "version": "3.13.6",
            "abi_tag": abi_tag,
            "prefix": prefix,
            "base_prefix": base_prefix,
        },
        "platform": {
            "system": platform_name,
            "machine": machine,
            "release": release,
            "sys_platform": sys_platform,
            "tags": platform_tags,
        },
        "sqlite_version": "3.50.4",
    }
    tool_versions = {
        "python": "3.13.6",
        "python_implementation": "CPython",
        "python_executable_sha256": controller_sha256,
        "python_abi_tag": abi_tag,
        "system": platform_name,
        "machine": machine,
        "release": release,
        "sys_platform": sys_platform,
        "platform_tags": platform_tags,
        "profile_key": f"{platform_name}-{machine}-cpython-3.13",
        "jsonschema": "4.25.1",
        "sqlite": "3.50.4",
    }
    return {
        "record_type": "NoDegradationResult",
        "status": "pass",
        "candidate_binding_digest": "4" * 64,
        "platform": platform_name,
        "no_degradation": True,
        "source": "live_files_and_executable_tests",
        "root": "fixture",
        "artifact_binding": {"platform": platform_binding},
        "test_manifest": {},
        "install_mode": "offline-wheelhouse",
        "required_predicates": {},
        "validation": {"checks": {"identity_binding": {"tool_versions": tool_versions}}},
        "tests": {
            "installed_environment": {
                "installed_environment_observation": observation,
            }
        },
        "passed": True,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "product_public_approval": "not_approved",
        "scale_selection": {},
        "artifact_binding_unchanged": True,
        "standard_distribution_gate_pass": False,
        "phases": [],
        "execution_budget": {},
        "producer": {},
        "invocation": release_evidence_invocation(
            invocation_id=f"no-degradation:{platform_name}:cross-binding",
            operation="no-degradation",
            arguments={"fixture": "cross-binding"},
            started_at="2026-07-18T10:00:00Z",
            completed_at="2026-07-18T10:00:01Z",
            exit_code=0,
            platform_binding=platform_binding["binding_digest"][7:],
        ),
    }


def _refresh_no_degradation_platform_binding(record: dict[str, Any]) -> None:
    platform_binding = record["artifact_binding"]["platform"]
    platform_binding.pop("binding_digest", None)
    platform_binding["binding_digest"] = "sha256:" + canonical_digest(platform_binding)
    record["invocation"]["platform_binding_digest"] = platform_binding["binding_digest"][7:]


def test_no_degradation_runtime_cross_binding_rejects_resigned_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    windows_key = Ed25519PrivateKey.generate()
    linux_key = Ed25519PrivateKey.generate()
    windows_entry = _producer_trust_entry(
        windows_key,
        key_id="fixture-windows-no-degradation-key",
        subject_id="fixture-windows-no-degradation-producer",
        roles=["windows-no-degradation"],
        platform_name="windows",
    )
    linux_entry = _producer_trust_entry(
        linux_key,
        key_id="fixture-linux-no-degradation-key",
        subject_id="fixture-linux-no-degradation-producer",
        roles=["linux-no-degradation"],
        platform_name="linux",
    )
    trust = _producer_trust([windows_entry, linux_entry])
    windows_private_path = tmp_path / "windows-no-degradation.key"
    linux_private_path = tmp_path / "linux-no-degradation.key"
    trust_path = tmp_path / "no-degradation-trust.json"
    _producer_private_key(windows_private_path, windows_key)
    _producer_private_key(linux_private_path, linux_key)
    _write_producer_trust(trust_path, trust)

    valid_windows = _no_degradation_runtime_record("windows")
    valid_linux = _no_degradation_runtime_record("linux")
    for valid in (valid_windows, valid_linux):
        observation = valid["tests"]["installed_environment"][
            "installed_environment_observation"
        ]
        evidence_module._validate_no_degradation_runtime_cross_binding(
            valid["artifact_binding"]["platform"],
            observation,
            expected_platform=valid["platform"],
            validation_tool_versions=valid["validation"]["checks"]["identity_binding"][
                "tool_versions"
            ],
        )

    candidate = _standard_candidate_binding()
    monkeypatch.setattr(
        evidence_module,
        "_validate_exact_artifact_binding",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        evidence_module,
        "_validate_release_evidence_envelope",
        lambda *_args, **_kwargs: None,
    )

    mutations: list[tuple[str, dict[str, Any]]] = []
    outer_314 = json.loads(json.dumps(valid_windows))
    outer_314["artifact_binding"]["platform"].update(
        {"python_version": "3.14.6", "profile_key": "windows-amd64-cpython-3.14"}
    )
    mutations.append(("Python version drift", outer_314))

    implementation = json.loads(json.dumps(valid_windows))
    implementation["artifact_binding"]["platform"].update(
        {"python_implementation": "PyPy", "profile_key": "windows-amd64-pypy-3.13"}
    )
    mutations.append(("implementation drift", implementation))

    machine = json.loads(json.dumps(valid_windows))
    machine["artifact_binding"]["platform"].update(
        {"machine": "arm64", "profile_key": "windows-arm64-cpython-3.13"}
    )
    mutations.append(("platform identity drift", machine))

    release = json.loads(json.dumps(valid_windows))
    release["tests"]["installed_environment"]["installed_environment_observation"][
        "platform"
    ]["release"] = "12"
    mutations.append(("platform identity drift", release))

    sys_platform = json.loads(json.dumps(valid_windows))
    sys_platform["tests"]["installed_environment"]["installed_environment_observation"][
        "platform"
    ]["sys_platform"] = "linux"
    mutations.append(("sys.platform drift", sys_platform))

    abi = json.loads(json.dumps(valid_windows))
    abi_observation = abi["tests"]["installed_environment"][
        "installed_environment_observation"
    ]
    abi_observation["python"]["abi_tag"] = "cp314-win_amd64"
    abi_observation["platform"]["tags"] = ["cp314-cp314-win_amd64"]
    mutations.append(("ABI drift", abi))

    executable = json.loads(json.dumps(valid_linux))
    executable["artifact_binding"]["platform"]["python_executable_sha256"] = (
        "sha256:" + "9" * 64
    )
    mutations.append(("executable SHA-256 drift", executable))

    venv_escape = json.loads(json.dumps(valid_linux))
    venv_escape["tests"]["installed_environment"]["installed_environment_observation"][
        "python"
    ]["executable"] = "/opt/python-3.13.6/bin/python3.13"
    mutations.append(("outside the exact venv prefix", venv_escape))

    base_escape = json.loads(json.dumps(valid_windows))
    base_escape["tests"]["installed_environment"]["installed_environment_observation"][
        "python"
    ]["base_executable"] = "C:/unbound/python.exe"
    mutations.append(("outside the base prefix", base_escape))

    base_hash = json.loads(json.dumps(valid_windows))
    base_hash["tests"]["installed_environment"]["installed_environment_observation"][
        "python"
    ]["base_executable_sha256"] = "8" * 64
    mutations.append(("executable SHA-256 drift", base_hash))

    sqlite = json.loads(json.dumps(valid_linux))
    sqlite["tests"]["installed_environment"]["installed_environment_observation"][
        "sqlite_version"
    ] = "3.49.0"
    mutations.append(("SQLite drift", sqlite))

    validation_sqlite = json.loads(json.dumps(valid_windows))
    validation_sqlite["validation"]["checks"]["identity_binding"]["tool_versions"][
        "sqlite"
    ] = "3.49.0"
    mutations.append(("SQLite drift", validation_sqlite))

    tags = json.loads(json.dumps(valid_linux))
    tags["tests"]["installed_environment"]["installed_environment_observation"][
        "platform"
    ]["tags"] = ["cp313-cp313-manylinux_2_17_x86_64"]
    mutations.append(("ABI drift", tags))

    for expected_error, unsigned in mutations:
        unsigned["candidate_binding_digest"] = candidate["candidate_binding_digest"]
        _refresh_no_degradation_platform_binding(unsigned)
        if unsigned["platform"] == "windows":
            producer_entry = windows_entry
            producer_private_path = windows_private_path
        else:
            producer_entry = linux_entry
            producer_private_path = linux_private_path
        _set_evidence_producer(
            monkeypatch,
            private_key=producer_private_path,
            trust=trust_path,
            entry=producer_entry,
        )
        sealed = seal_release_evidence(unsigned)
        role = f"{sealed['platform']}-no-degradation"
        attestation = _validate_producer_attestation(
            sealed,
            candidate=candidate,
            expected_role=role,
            expected_platform=sealed["platform"],
        )
        _validate_evidence_attestation_trust(
            attestation,
            trust=trust,
            expected_role=role,
            expected_platform=sealed["platform"],
        )
        with pytest.raises(EvidenceError, match=expected_error):
            evidence_module.validate_no_degradation_result(
                sealed,
                candidate_binding=candidate,
                expected_platform=sealed["platform"],
            )


def _saturation_attestation_record(
    record_type: str,
    invocation_id: str,
    *,
    platform_name: str = "windows",
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "record_type": record_type,
        "candidate_binding_digest": "4" * 64,
        "artifact_binding": {"platform": {"system": platform_name}},
        "invocation": release_evidence_invocation(
            invocation_id=invocation_id,
            operation=(
                "saturation-audit"
                if record_type == "SaturationAudit"
                else "physical-saturation"
            ),
            arguments={"fixture": invocation_id},
            started_at="2026-07-18T10:00:00Z",
            completed_at="2026-07-18T10:00:01Z",
            exit_code=0,
            platform_binding={"system": platform_name},
        ),
    }
    if record_type == "SaturationAudit":
        record.update(
            {
                "families": [],
                "collection": {},
                "iterations": [],
                "requirements": {},
            }
        )
    else:
        record.update(
            {
                "physical": {},
                "inventory": {},
                "projection": {},
                "search": {},
                "resources": {},
                "performance": {},
                "contract_predicates": {},
                "current_release_regression": {},
            }
        )
    return record


def _set_evidence_producer(
    monkeypatch: pytest.MonkeyPatch,
    *,
    private_key: Path,
    trust: Path,
    entry: dict[str, Any],
) -> None:
    monkeypatch.setenv("PROMIN_EVIDENCE_PRIVATE_KEY", str(private_key))
    monkeypatch.setenv("PROMIN_EVIDENCE_TRUST_CONFIGURATION", str(trust))
    monkeypatch.setenv("PROMIN_EVIDENCE_KEY_ID", entry["key_id"])
    monkeypatch.setenv("PROMIN_EVIDENCE_PRODUCER_ID", entry["subject_id"])


def test_release_evidence_producer_preflight_checks_scope_key_and_time(
    tmp_path: Path,
) -> None:
    key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "physical.key"
    _producer_private_key(private_path, key)
    entry = _producer_trust_entry(
        key,
        key_id="fixture-physical-key",
        subject_id="fixture-physical-producer",
        roles=["physical-scale"],
    )
    trust_path = tmp_path / "trust.json"
    _write_producer_trust(trust_path, _producer_trust([entry]))

    metadata = validate_release_evidence_producer_configuration(
        role="physical-scale",
        platform_name="windows",
        private_key_path=private_path,
        trust_configuration_path=trust_path,
        key_id=entry["key_id"],
        producer_id=entry["subject_id"],
        signed_at="2026-07-18T10:00:01Z",
    )
    assert metadata["key_id"] == entry["key_id"]
    assert metadata["producer_id"] == entry["subject_id"]
    assert metadata["evidence_role"] == "physical-scale"
    assert metadata["platform"] == "windows"
    assert len(metadata["trust_configuration_sha256"]) == 64
    aware_metadata = validate_release_evidence_producer_configuration(
        role="physical-scale",
        platform_name="windows",
        private_key_path=private_path,
        trust_configuration_path=trust_path,
        key_id=entry["key_id"],
        producer_id=entry["subject_id"],
        signed_at=datetime(2026, 7, 18, 10, 0, 1, tzinfo=timezone.utc),
    )
    assert aware_metadata["key_id"] == entry["key_id"]
    with pytest.raises(EvidenceError, match="timezone-aware"):
        validate_release_evidence_producer_configuration(
            role="physical-scale",
            platform_name="windows",
            private_key_path=private_path,
            trust_configuration_path=trust_path,
            key_id=entry["key_id"],
            producer_id=entry["subject_id"],
            signed_at=datetime(2026, 7, 18, 10, 0, 1),
        )

    with pytest.raises(EvidenceError, match="wrong role, platform, validity"):
        validate_release_evidence_producer_configuration(
            role="saturation-audit",
            platform_name="windows",
            private_key_path=private_path,
            trust_configuration_path=trust_path,
            key_id=entry["key_id"],
            producer_id=entry["subject_id"],
            signed_at="2026-07-18T10:00:01Z",
        )
    with pytest.raises(EvidenceError, match="wrong role, platform, validity"):
        validate_release_evidence_producer_configuration(
            role="physical-scale",
            platform_name="windows",
            private_key_path=private_path,
            trust_configuration_path=trust_path,
            key_id=entry["key_id"],
            producer_id=entry["subject_id"],
            signed_at="2027-01-01T00:00:00Z",
        )
    wrong_private = tmp_path / "wrong.key"
    _producer_private_key(wrong_private, Ed25519PrivateKey.generate())
    with pytest.raises(EvidenceError, match="private key does not match"):
        validate_release_evidence_producer_configuration(
            role="physical-scale",
            platform_name="windows",
            private_key_path=wrong_private,
            trust_configuration_path=trust_path,
            key_id=entry["key_id"],
            producer_id=entry["subject_id"],
            signed_at="2026-07-18T10:00:01Z",
        )


def test_saturation_audit_requires_trusted_distinct_replay_safe_nested_producers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = {"candidate_binding_digest": "4" * 64}
    audit_key = Ed25519PrivateKey.generate()
    physical_key = Ed25519PrivateKey.generate()
    audit_path = tmp_path / "audit.key"
    physical_path = tmp_path / "physical.key"
    _producer_private_key(audit_path, audit_key)
    _producer_private_key(physical_path, physical_key)
    audit_entry = _producer_trust_entry(
        audit_key,
        key_id="fixture-audit-key",
        subject_id="fixture-audit-producer",
        roles=["saturation-audit"],
    )
    physical_entry = _producer_trust_entry(
        physical_key,
        key_id="fixture-physical-key",
        subject_id="fixture-physical-producer",
        roles=["physical-scale"],
    )
    trust = _producer_trust([audit_entry, physical_entry])
    trust_path = tmp_path / "trust.json"
    _write_producer_trust(trust_path, trust)

    _set_evidence_producer(
        monkeypatch,
        private_key=audit_path,
        trust=trust_path,
        entry=audit_entry,
    )
    outer_record = seal_release_evidence(
        _saturation_attestation_record("SaturationAudit", "audit:fixture")
    )
    outer_attestation = _validate_producer_attestation(
        outer_record,
        candidate=candidate,
        expected_role="saturation-audit",
        expected_platform="windows",
    )

    _set_evidence_producer(
        monkeypatch,
        private_key=physical_path,
        trust=trust_path,
        entry=physical_entry,
    )
    nested_attestations = [
        _validate_producer_attestation(
            seal_release_evidence(
                _saturation_attestation_record(
                    "SaturationEvidence",
                    f"physical:fixture:{index}",
                )
            ),
            candidate=candidate,
            expected_role="physical-scale",
            expected_platform="windows",
        )
        for index in range(3)
    ]
    _validate_saturation_audit_producer_boundary(
        outer_attestation,
        nested_attestations,
        trust_configuration=trust,
    )

    with pytest.raises(EvidenceError, match="contains replay"):
        _validate_saturation_audit_producer_boundary(
            outer_attestation,
            [nested_attestations[0], nested_attestations[0], nested_attestations[2]],
            trust_configuration=trust,
        )

    for name in (
        "PROMIN_EVIDENCE_PRIVATE_KEY",
        "PROMIN_EVIDENCE_TRUST_CONFIGURATION",
        "PROMIN_EVIDENCE_KEY_ID",
        "PROMIN_EVIDENCE_PRODUCER_ID",
    ):
        monkeypatch.delenv(name, raising=False)
    untrusted = _validate_producer_attestation(
        seal_release_evidence(
            _saturation_attestation_record("SaturationEvidence", "physical:untrusted")
        ),
        candidate=candidate,
        expected_role="physical-scale",
        expected_platform="windows",
    )
    with pytest.raises(EvidenceError, match="trust root or provider drift"):
        _validate_saturation_audit_producer_boundary(
            outer_attestation,
            [nested_attestations[0], nested_attestations[1], untrusted],
            trust_configuration=trust,
        )

    shared_entry = _producer_trust_entry(
        audit_key,
        key_id="fixture-shared-key",
        subject_id="fixture-shared-producer",
        roles=["physical-scale", "saturation-audit"],
    )
    shared_trust = _producer_trust([shared_entry])
    with pytest.raises(EvidenceError, match="role/platform"):
        _validate_trust_configuration(shared_trust)


def test_manifest_graph_rejects_multiple_keys_for_one_authority_role() -> None:
    audit_key = Ed25519PrivateKey.generate()
    nested_key = Ed25519PrivateKey.generate()
    top_level_key = Ed25519PrivateKey.generate()
    audit_entry = _producer_trust_entry(
        audit_key,
        key_id="fixture-cross-audit-key",
        subject_id="fixture-cross-audit-producer",
        roles=["saturation-audit"],
    )
    nested_entry = _producer_trust_entry(
        nested_key,
        key_id="fixture-cross-nested-key",
        subject_id="fixture-cross-nested-producer",
        roles=["physical-scale"],
    )
    top_level_entry = _producer_trust_entry(
        top_level_key,
        key_id="fixture-cross-top-level-key",
        subject_id="fixture-cross-top-level-producer",
        roles=["physical-scale"],
        platform_name="linux",
    )
    trust = _producer_trust([audit_entry, nested_entry, top_level_entry])

    with pytest.raises(EvidenceError, match="multiple configured keys"):
        _validate_trust_configuration(trust)


def test_validate_saturation_audit_direct_caller_does_not_require_graph(
    tmp_path: Path,
) -> None:
    candidate = _standard_candidate_binding()
    key = Ed25519PrivateKey.generate()
    trust = _producer_trust(
        [
            _producer_trust_entry(
                key,
                key_id="fixture-direct-audit-key",
                subject_id="fixture-direct-audit-producer",
                roles=["saturation-audit"],
            )
        ]
    )
    with pytest.raises(EvidenceError, match="violates exact SaturationAudit schema"):
        validate_saturation_audit(
            {},
            candidate_binding=candidate,
            source_path=tmp_path / "saturation-audit.json",
            evidence_root=tmp_path,
            trust_configuration=trust,
        )


def test_manifest_rejects_top_level_physical_reused_as_nested_in_any_entry_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _standard_candidate_binding()
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    role_specs = [
        ("saturation-audit", "SaturationAudit", "windows"),
        ("linux", "PlatformVerificationResult", "linux"),
        ("windows", "PlatformVerificationResult", "windows"),
        ("human-documents", "HumanDocumentVerification", "windows"),
        ("linux-no-degradation", "NoDegradationResult", "linux"),
        ("windows-no-degradation", "NoDegradationResult", "windows"),
        ("physical-scale", "SaturationEvidence", "windows"),
    ]
    keys: dict[str, Ed25519PrivateKey] = {
        role: Ed25519PrivateKey.generate() for role, _, _ in role_specs
    }
    entries_by_role = {
        role: _producer_trust_entry(
            keys[role],
            key_id=f"fixture-{role}-key",
            subject_id=f"fixture-{role}-producer",
            roles=[role],
        )
        for role, _, _ in role_specs
    }
    for role, _, platform_name in role_specs:
        entries_by_role[role]["platforms"] = [platform_name]
    trust = _producer_trust([entries_by_role[role] for role, _, _ in role_specs])
    trust_path = tmp_path / "trust.json"
    _write_producer_trust(trust_path, trust)

    def set_pointer(record: dict[str, Any], pointer: str, value: Any) -> None:
        current = record
        parts = pointer.removeprefix("/").split("/")
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = value

    sealed_by_role: dict[str, dict[str, Any]] = {}
    manifest_entries: list[dict[str, Any]] = []
    for role, record_type, platform_name in role_specs:
        private_path = tmp_path / f"{role}.key"
        _producer_private_key(private_path, keys[role])
        _set_evidence_producer(
            monkeypatch,
            private_key=private_path,
            trust=trust_path,
            entry=entries_by_role[role],
        )
        record: dict[str, Any] = {
            "record_type": record_type,
            "status": "pass",
            "candidate_binding_digest": candidate["candidate_binding_digest"],
            "invocation": release_evidence_invocation(
                invocation_id=f"manifest:{role}",
                operation=f"fixture-{role}",
                arguments={"role": role},
                started_at="2026-07-18T10:00:00Z",
                completed_at="2026-07-18T10:00:01Z",
                exit_code=0,
                platform_binding={"system": platform_name},
            ),
        }
        if record_type == "PlatformVerificationResult":
            record.update(
                {
                    "platform": platform_name,
                    "installation": {},
                    "platform_identity": {},
                    "observed_environment_closure_digest": "5" * 64,
                }
            )
        elif record_type == "NoDegradationResult":
            record.update(
                {
                    "platform": platform_name,
                    "artifact_binding": {},
                    "test_manifest": {},
                    "validation": {},
                    "tests": {},
                    "phases": {},
                    "execution_budget": {},
                }
            )
        elif record_type == "HumanDocumentVerification":
            record.update(
                {
                    "documents": [],
                    "extraction_diagnostics": {},
                    "font_bindings": {},
                    "render_environment": {"platform": platform_name},
                    "render_manifest": [],
                }
            )
        elif record_type == "SaturationAudit":
            record.update(
                {
                    "artifact_binding": {"platform": {"system": platform_name}},
                    "families": [],
                    "collection": {},
                    "iterations": [],
                    "requirements": {},
                }
            )
        else:
            record.update(
                {
                    "artifact_binding": {"platform": {"system": platform_name}},
                    "physical": {},
                    "inventory": {},
                    "projection": {},
                    "search": {},
                    "resources": {},
                    "performance": {},
                    "contract_predicates": {},
                    "current_release_regression": {},
                }
            )
        required_predicates = evidence_module._REQUIRED_STANDARD_EVIDENCE_PREDICATES[role]
        for pointer, expected in required_predicates.items():
            set_pointer(record, pointer, expected)
        sealed = seal_release_evidence(record)
        sealed_by_role[role] = sealed
        relative = f"{role}.json"
        path = evidence_root / relative
        path.write_text(
            json.dumps(sealed, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        manifest_entries.append(
            {
                "evidence_id": f"fixture-{role}",
                "evidence_role": role,
                "path": relative,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "size_bytes": path.stat().st_size,
                "record_type": record_type,
                "status": "pass",
                "candidate_binding_digest": candidate["candidate_binding_digest"],
                "predicates": [
                    {"pointer": pointer, "equals": expected}
                    for pointer, expected in required_predicates.items()
                ],
            }
        )

    physical_attestation = _validate_producer_attestation(
        sealed_by_role["physical-scale"],
        candidate=candidate,
        expected_role="physical-scale",
        expected_platform="windows",
    )

    def accept_record(evidence, **_arguments):
        return evidence

    def accept_schema(*_arguments, **_keywords):
        return None

    def accept_audit(evidence, *, attestation_graph, **_arguments):
        attestation_graph.append(dict(physical_attestation))
        return evidence

    monkeypatch.setattr(evidence_module, "_validate_release_evidence_schema", accept_schema)
    monkeypatch.setattr(evidence_module, "validate_platform_verification", accept_record)
    monkeypatch.setattr(evidence_module, "validate_saturation_evidence", accept_record)
    monkeypatch.setattr(evidence_module, "validate_saturation_audit", accept_audit)
    monkeypatch.setattr(evidence_module, "validate_human_document_verification", accept_record)
    monkeypatch.setattr(evidence_module, "validate_no_degradation_result", accept_record)
    monkeypatch.setattr(
        evidence_module,
        "_validate_matrix_aggregate",
        lambda *_arguments, **_keywords: ({}, [], []),
    )

    identity = {
        "record_type": "StandardReleaseEvidenceManifest",
        "standard_name": "promin",
        "version": candidate["version"],
        "candidate_binding_digest": candidate["candidate_binding_digest"],
        "entries": manifest_entries,
        "matrix_aggregate": {},
        "supplemental_lanes": [],
        "max_evidence_completed_at": "2026-07-18T10:00:01Z",
    }
    manifest = {
        **identity,
        "evidence_manifest_digest": canonical_digest(identity),
    }
    missing_size_identity = deepcopy(identity)
    missing_size_identity["entries"][0].pop("size_bytes")
    missing_size = {
        **missing_size_identity,
        "evidence_manifest_digest": canonical_digest(missing_size_identity),
    }
    with pytest.raises(EvidenceError, match="entry shape"):
        validate_standard_release_evidence_manifest(
            missing_size,
            candidate_binding=candidate,
            evidence_root=evidence_root,
            trust_configuration=trust,
        )
    with pytest.raises(EvidenceError, match="attestation graph contains replay"):
        validate_standard_release_evidence_manifest(
            manifest,
            candidate_binding=candidate,
            evidence_root=evidence_root,
            trust_configuration=trust,
        )


def test_standard_release_decision_is_external_exact_signed_and_never_product_credit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _standard_candidate_binding()
    validate_standard_release_candidate_binding(candidate)
    private_key = Ed25519PrivateKey.generate()
    trust = _standard_trust_configuration(private_key)
    evidence_root = tmp_path / "evidence"
    evidence_root.mkdir()
    fabricated = _fabricated_standard_evidence_manifest(evidence_root, candidate)
    with pytest.raises(EvidenceError):
        validate_standard_release_evidence_manifest(
            fabricated,
            candidate_binding=candidate,
            evidence_root=evidence_root,
            trust_configuration=trust,
            candidate_document_members=(),
        )

    manifest_identity = {
        "record_type": "StandardReleaseEvidenceManifest",
        "standard_name": "promin",
        "version": candidate["version"],
        "candidate_binding_digest": candidate["candidate_binding_digest"],
        "entries": [],
        "max_evidence_completed_at": "2026-07-18T11:00:00Z",
    }
    manifest = {
        **manifest_identity,
        "evidence_manifest_digest": canonical_digest(manifest_identity),
    }
    monkeypatch.setattr(
        "promin.evidence.validate_standard_release_evidence_manifest",
        lambda *args, **kwargs: manifest,
    )

    approved = _signed_standard_decision(
        private_key,
        candidate,
        manifest,
        outcome="approve",
        decision_id="fixture-approve",
    )
    rejected = _signed_standard_decision(
        private_key,
        candidate,
        manifest,
        outcome="reject",
        decision_id="fixture-reject",
        nonce=base64.b64encode(b"fixture-nonce-000000000002").decode("ascii"),
    )
    validated = validate_standard_release_decision(
        approved,
        candidate_binding=candidate,
        evidence_manifest=manifest,
        evidence_root=evidence_root,
        trust_configuration=trust,
        candidate_document_members=(),
    )
    assert validated["decision_digest"] == canonical_digest(approved)

    pending = standard_distribution_status(
        None,
        candidate_binding=candidate,
        evidence_manifest=manifest,
        evidence_root=evidence_root,
        trust_configuration=trust,
    )
    assert pending["distribution_status"] == "candidate"
    assert pending["current_distribution_eligible"] is False
    assert pending["historical_decision_present"] is False
    assert pending["product_acceptance_pass"] is False
    assert pending["product_public_approval"] == "not_approved"
    approved_status = standard_distribution_status(
        approved,
        candidate_binding=candidate,
        evidence_manifest=manifest,
        evidence_root=evidence_root,
        trust_configuration=trust,
    )
    assert approved_status["distribution_status"] == "signature_valid_under_supplied_root"
    assert approved_status["historical_decision_digest"] == canonical_digest(approved)
    assert approved_status["historical_decision_outcome"] == "approve"
    assert "independent-trust-root-pin-missing" in approved_status["invalidation_reasons"]
    assert approved_status["product_acceptance_pass"] is False
    assert approved_status["product_public_approval"] == "not_approved"
    supplied_trust_digest = "a" * 64
    wrong_pin = standard_distribution_status(
        approved,
        candidate_binding=candidate,
        evidence_manifest=manifest,
        evidence_root=evidence_root,
        trust_configuration=trust,
        trust_configuration_sha256=supplied_trust_digest,
        expected_trust_root_sha256="b" * 64,
    )
    assert wrong_pin["distribution_status"] == "invalidated"
    pinned = standard_distribution_status(
        approved,
        candidate_binding=candidate,
        evidence_manifest=manifest,
        evidence_root=evidence_root,
        trust_configuration=trust,
        trust_configuration_sha256=supplied_trust_digest,
        expected_trust_root_sha256=supplied_trust_digest,
    )
    assert pinned["distribution_status"] == "approved"
    assert pinned["current_distribution_eligible"] is True
    assert pinned["product_acceptance_pass"] is False
    assert pinned["product_public_approval"] == "not_approved"
    rejected_status = standard_distribution_status(
        rejected,
        candidate_binding=candidate,
        evidence_manifest=manifest,
        evidence_root=evidence_root,
        trust_configuration=trust,
    )
    assert rejected_status["distribution_status"] == "rejected"
    assert rejected_status["current_distribution_eligible"] is False
    assert rejected_status["product_acceptance_pass"] is False
    assert rejected_status["product_public_approval"] == "not_approved"

    predating = _signed_standard_decision(
        private_key,
        candidate,
        manifest,
        outcome="reject",
        decision_id="fixture-predating",
        nonce=base64.b64encode(b"fixture-nonce-000000000003").decode("ascii"),
        decided_at="2026-07-18T10:59:59Z",
    )
    with pytest.raises(EvidenceError, match="must follow"):
        validate_standard_release_decision(
            predating,
            candidate_binding=candidate,
            evidence_manifest=manifest,
            evidence_root=evidence_root,
            trust_configuration=trust,
            verification_time="2026-07-18T12:00:00Z",
        )
    simultaneous = _signed_standard_decision(
        private_key,
        candidate,
        manifest,
        outcome="reject",
        decision_id="fixture-simultaneous",
        nonce=base64.b64encode(b"fixture-nonce-000000000005").decode("ascii"),
        decided_at=manifest["max_evidence_completed_at"],
    )
    with pytest.raises(EvidenceError, match="must follow"):
        validate_standard_release_decision(
            simultaneous,
            candidate_binding=candidate,
            evidence_manifest=manifest,
            evidence_root=evidence_root,
            trust_configuration=trust,
            verification_time="2026-07-18T12:00:00Z",
        )
    future = _signed_standard_decision(
        private_key,
        candidate,
        manifest,
        outcome="reject",
        decision_id="fixture-future",
        nonce=base64.b64encode(b"fixture-nonce-000000000004").decode("ascii"),
        decided_at="2026-07-18T12:05:01Z",
    )
    with pytest.raises(EvidenceError, match="clock skew"):
        validate_standard_release_decision(
            future,
            candidate_binding=candidate,
            evidence_manifest=manifest,
            evidence_root=evidence_root,
            trust_configuration=trust,
            verification_time="2026-07-18T12:00:00Z",
        )

    wrong_key = _signed_standard_decision(
        private_key,
        candidate,
        manifest,
        outcome="reject",
        decision_id="fixture-wrong-key",
        key_id="unconfigured-key",
    )
    with pytest.raises(EvidenceError, match="not configured"):
        validate_standard_release_decision(
            wrong_key,
            candidate_binding=candidate,
            evidence_manifest=manifest,
            evidence_root=evidence_root,
            trust_configuration=trust,
            candidate_document_members=(),
        )
    wrong_version = _signed_standard_decision(
        private_key,
        candidate,
        manifest,
        outcome="reject",
        decision_id="fixture-wrong-version",
        version="1.0.1",
    )
    with pytest.raises(EvidenceError, match="identity or SemVer drift"):
        validate_standard_release_decision(
            wrong_version,
            candidate_binding=candidate,
            evidence_manifest=manifest,
            evidence_root=evidence_root,
            trust_configuration=trust,
            candidate_document_members=(),
        )
    wrong_digest = _signed_standard_decision(
        private_key,
        candidate,
        manifest,
        outcome="reject",
        decision_id="fixture-wrong-candidate",
        candidate_binding_digest="f" * 64,
    )
    with pytest.raises(EvidenceError, match="candidate binding drift"):
        validate_standard_release_decision(
            wrong_digest,
            candidate_binding=candidate,
            evidence_manifest=manifest,
            evidence_root=evidence_root,
            trust_configuration=trust,
            candidate_document_members=(),
        )
    short_nonce = _signed_standard_decision(
        private_key,
        candidate,
        manifest,
        outcome="reject",
        decision_id="fixture-short-nonce",
        nonce=base64.b64encode(b"short").decode("ascii"),
    )
    with pytest.raises(EvidenceError, match="nonce length"):
        validate_standard_release_decision(
            short_nonce,
            candidate_binding=candidate,
            evidence_manifest=manifest,
            evidence_root=evidence_root,
            trust_configuration=trust,
            candidate_document_members=(),
        )

    replayed = dict(
        approved,
        decision_id="fixture-replayed-in-another-context",
        nonce=base64.b64encode(b"fixture-nonce-000000000003").decode("ascii"),
    )
    with pytest.raises(EvidenceError, match="signed claim digest mismatch"):
        validate_standard_release_decision(
            replayed,
            candidate_binding=candidate,
            evidence_manifest=manifest,
            evidence_root=evidence_root,
            trust_configuration=trust,
            candidate_document_members=(),
        )

    other_key = Ed25519PrivateKey.generate()
    wrong_trust_key = _standard_trust_configuration(other_key)
    with pytest.raises(EvidenceError, match="signature is invalid"):
        validate_standard_release_decision(
            approved,
            candidate_binding=candidate,
            evidence_manifest=manifest,
            evidence_root=evidence_root,
            trust_configuration=wrong_trust_key,
            candidate_document_members=(),
        )

    stale_candidate = dict(candidate, archive_sha256="e" * 64)
    with pytest.raises(EvidenceError, match="candidate binding digest mismatch"):
        validate_standard_release_candidate_binding(stale_candidate)


def test_evidence_cas_core_shape_immutability_and_credit(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "cas")
    artifact = finalized_evidence(
        store,
        artifact_id="evidence:pass",
        payload=b"validated product evidence\n",
        media_type="application/json",
        retention_class="audit",
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        created_at="2026-02-01T00:00:00Z",
        activation_digest=ACTIVATION,
        outcome="pass",
        evidence_class="product-execution",
        product_credit_eligible=True,
    )
    schema = core_schema()
    validate_definition(schema, "Artifact", artifact)
    validate_definition(schema, "EvidenceBinding", artifact["evidence_binding"])
    missing_implementation = json.loads(json.dumps(artifact))
    del missing_implementation["evidence_binding"]["implementation_closure_digest"]
    with pytest.raises(EvidenceError, match="invalid evidence binding"):
        EvidenceStore._validate_artifact(missing_implementation)
    assert len(artifact["digest"]) == 64 and ":" not in artifact["digest"]
    orphan_payload = b"staged before journal crash"
    orphan = dict(
        artifact,
        artifact_id="evidence:orphan",
        digest=hashlib.sha256(orphan_payload).hexdigest(),
        size_bytes=len(orphan_payload),
    )
    orphan_command = canonical_digest(
        {"operation": "artifact.record", "artifact": orphan}
    )
    receipt = store.stage(
        orphan,
        orphan_payload,
        command_digest=orphan_command,
    )
    assert receipt["status"] == "staged"
    assert store.pending_record("evidence:orphan") == {
        "artifact": orphan,
        "command_digest": orphan_command,
    }
    assert not store.is_resolved(orphan["digest"])
    product_providers = provider_invocation_digests(artifact)
    assert not store.has_product_credit(
        orphan["artifact_id"],
        "0" * 64,
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        provider_invocation_digests=product_providers,
        activation_digest=ACTIVATION,
        implementation_closure_digest=IMPLEMENTATION,
    )
    reopened = EvidenceStore(tmp_path / "cas")
    assert reopened.pending_artifact_ids() == ("evidence:orphan",)
    assert not reopened.is_resolved(orphan["digest"])
    assert not reopened.is_resolved(artifact["digest"])
    with pytest.raises(EvidenceError, match="unresolved"):
        reopened.get_record("evidence:pass")
    reopened.reconcile(store._test_evidence_journal)
    assert reopened.is_resolved(artifact["digest"])
    assert not reopened.is_resolved(orphan["digest"])
    artifact_ref = evidence_reference(store, artifact)
    assert store.is_creditable(
        artifact_ref["artifact_id"],
        artifact_ref["artifact_record_digest"],
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        provider_invocation_digests=product_providers,
        activation_digest=ACTIVATION,
        implementation_closure_digest=IMPLEMENTATION,
        evidence_class="product-execution",
        purpose="product",
    )
    assert not store.is_creditable(
        artifact_ref["artifact_id"],
        artifact_ref["artifact_record_digest"],
        candidate_digest="b" * 64,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        provider_invocation_digests=product_providers,
        activation_digest=ACTIVATION,
        implementation_closure_digest=IMPLEMENTATION,
        evidence_class="product-execution",
        purpose="product",
    )
    assert not store.is_creditable(
        artifact_ref["artifact_id"],
        artifact_ref["artifact_record_digest"],
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        provider_invocation_digests=product_providers,
        activation_digest=ACTIVATION,
        implementation_closure_digest="7" * 64,
        evidence_class="product-execution",
        purpose="product",
    )
    with pytest.raises(EvidenceError, match="different .*evidence"):
        finalized_evidence(
            store,
            artifact_id="evidence:pass",
            payload=b"tampered",
            media_type="application/json",
            retention_class="audit",
            candidate_digest=CANDIDATE,
            policy_digest=POLICY,
            tool_digest=TOOL,
            input_digests=[INPUT],
            created_at="2026-02-01T00:00:00Z",
            activation_digest=ACTIVATION,
            outcome="pass",
        )
    with pytest.raises(EvidenceError, match="positive integer"):
        finalized_evidence(
            store,
            artifact_id="E-empty",
            payload=b"",
            media_type="application/octet-stream",
            retention_class="audit",
            candidate_digest=CANDIDATE,
            policy_digest=POLICY,
            tool_digest=TOOL,
            input_digests=[],
            created_at="2026-02-01T00:00:00Z",
            activation_digest=ACTIVATION,
            outcome="pass",
        )

    for artifact_id, outcome, stale, unresolved in [
        ("E-fail", "fail", False, False),
        ("E-blocked", "blocked", False, False),
        ("E-stale", "pass", True, False),
        ("E-unresolved", "pass", False, True),
    ]:
        rejected = finalized_evidence(
            store,
            artifact_id=artifact_id,
            payload=artifact_id.encode(),
            media_type="text/plain",
            retention_class="audit",
            candidate_digest=CANDIDATE,
            policy_digest=POLICY,
            tool_digest=TOOL,
            input_digests=[INPUT],
            created_at="2026-02-01T00:00:00Z",
            activation_digest=ACTIVATION,
            outcome=outcome,
            stale=stale,
            unresolved=unresolved,
        )
        rejected_ref = evidence_reference(store, rejected)
        assert not store.is_creditable(
            rejected_ref["artifact_id"],
            rejected_ref["artifact_record_digest"],
            candidate_digest=CANDIDATE,
            policy_digest=POLICY,
            tool_digest=TOOL,
            input_digests=[INPUT],
            provider_invocation_digests=[],
            activation_digest=ACTIVATION,
            implementation_closure_digest=IMPLEMENTATION,
            evidence_class="validator",
            purpose="gate",
        )

    harness = finalized_evidence(
        store,
        artifact_id="E-harness",
        payload=b"fixture result",
        media_type="text/plain",
        retention_class="audit",
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        created_at="2026-02-01T00:00:00Z",
        activation_digest=ACTIVATION,
        outcome="pass",
        evidence_class="harness-generated",
        product_credit_eligible=False,
    )
    harness_ref = evidence_reference(store, harness)
    assert store.is_creditable(
        harness_ref["artifact_id"],
        harness_ref["artifact_record_digest"],
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        provider_invocation_digests=[],
        activation_digest=ACTIVATION,
        implementation_closure_digest=IMPLEMENTATION,
        evidence_class="harness-generated",
        purpose="diagnostic",
    )
    with pytest.raises(EvidenceError, match="incompatible"):
        store.is_creditable(
            harness_ref["artifact_id"],
            harness_ref["artifact_record_digest"],
            candidate_digest=CANDIDATE,
            policy_digest=POLICY,
            tool_digest=TOOL,
            input_digests=[INPUT],
            provider_invocation_digests=[],
            activation_digest=ACTIVATION,
            implementation_closure_digest=IMPLEMENTATION,
            evidence_class="harness-generated",
            purpose="product",
        )


def test_credit_and_gate_bind_exact_artifact_record_class_and_definition(
    tmp_path: Path,
) -> None:
    store = EvidenceStore(tmp_path / "exact-credit-cas")
    payload = b"identical CAS payload with distinct metadata"
    product = finalized_evidence(
        store,
        artifact_id="E-same-product",
        payload=payload,
        media_type="application/json",
        retention_class="audit",
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        created_at="2026-02-01T00:00:00Z",
        activation_digest=ACTIVATION,
        outcome="pass",
        evidence_class="product-execution",
        product_credit_eligible=True,
    )
    validator = finalized_evidence(
        store,
        artifact_id="E-same-validator",
        payload=payload,
        media_type="application/json",
        retention_class="audit",
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        created_at="2026-02-01T00:00:01Z",
        activation_digest=ACTIVATION,
        outcome="pass",
        evidence_class="validator",
        evidence_purpose="diagnostic",
        product_credit_eligible=False,
    )
    assert product["digest"] == validator["digest"]
    product_ref = evidence_reference(store, product)
    validator_ref = evidence_reference(store, validator)
    providers = provider_invocation_digests(product)
    assert store.has_product_credit(
        product_ref["artifact_id"],
        product_ref["artifact_record_digest"],
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        provider_invocation_digests=providers,
        activation_digest=ACTIVATION,
        implementation_closure_digest=IMPLEMENTATION,
    )
    assert not store.has_product_credit(
        validator_ref["artifact_id"],
        validator_ref["artifact_record_digest"],
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        provider_invocation_digests=[],
        activation_digest=ACTIVATION,
        implementation_closure_digest=IMPLEMENTATION,
    )
    assert not store.has_product_credit(
        product_ref["artifact_id"],
        "0" * 64,
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        provider_invocation_digests=providers,
        activation_digest=ACTIVATION,
        implementation_closure_digest=IMPLEMENTATION,
    )
    assert store.require_creditable(
        product_ref["artifact_id"],
        product_ref["artifact_record_digest"],
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        provider_invocation_digests=providers,
        activation_digest=ACTIVATION,
        implementation_closure_digest=IMPLEMENTATION,
        evidence_class="product-execution",
        purpose="product",
        require_product_credit=True,
    ) == product
    with pytest.raises(EvidenceError, match="unbound"):
        store.require_creditable(
            validator_ref["artifact_id"],
            product_ref["artifact_record_digest"],
            candidate_digest=CANDIDATE,
            policy_digest=POLICY,
            tool_digest=TOOL,
            input_digests=[INPUT],
            provider_invocation_digests=providers,
            activation_digest=ACTIVATION,
            implementation_closure_digest=IMPLEMENTATION,
            evidence_class="product-execution",
            purpose="product",
            require_product_credit=True,
        )

    product_task = task_with_gate_definitions(
        {
            "record_type": "Task",
            "task_id": "T-evidence-product",
            "state": "PLANNED",
            "required_capability": "validation.evaluate",
            "acceptance_predicate": "exact product evidence",
            "allowed_paths": ["src"],
            "activation_digest": ACTIVATION,
            "candidate_digest": CANDIDATE,
            "created_at": "2026-02-01T00:00:00Z",
        },
        {
            "gate_id": "product-gate",
            "provider_invocations": product["evidence_binding"][
                "provider_invocations"
            ],
            "evidence_class": "product-execution",
            "evidence_purpose": "product",
            "product_credit_required": True,
        },
    )
    product_definition = product_task["gate_run_definitions"][0]["definition"]
    product_run = gate_run_for(product_task, "product-gate", "R-product")
    product_result = gate_result_for(
        product_task,
        "product-gate",
        "R-product",
        [product_ref],
        run_record=product_run,
    )
    assert store.validate_gate_evidence(
        product_result,
        gate_run_definition=product_definition,
        run_record=product_run,
    ) == [product]
    with pytest.raises(EvidenceError, match="differs"):
        store.validate_gate_evidence(
            dict(
                product_result,
                run_id="R-mixed",
                evidence_artifacts=[
                    product_result["evidence_artifacts"][0],
                    {
                        **validator_ref,
                        "run_id": product_run["run_id"],
                        "run_digest": canonical_digest(product_run),
                    },
                ],
            ),
            gate_run_definition=product_definition,
            run_record=product_run,
        )

    diagnostic_task = task_with_gate_definitions(
        {
            "record_type": "Task",
            "task_id": "T-evidence-diagnostic",
            "state": "PLANNED",
            "required_capability": "validation.evaluate",
            "acceptance_predicate": "exact diagnostic evidence",
            "allowed_paths": ["src"],
            "activation_digest": ACTIVATION,
            "candidate_digest": CANDIDATE,
            "created_at": "2026-02-01T00:00:00Z",
        },
        {
            "gate_id": "diagnostic-gate",
            "evidence_class": "validator",
            "evidence_purpose": "diagnostic",
        },
    )
    diagnostic_definition = diagnostic_task["gate_run_definitions"][0][
        "definition"
    ]
    diagnostic_run = gate_run_for(
        diagnostic_task, "diagnostic-gate", "R-diagnostic"
    )
    diagnostic_result = gate_result_for(
        diagnostic_task,
        "diagnostic-gate",
        "R-diagnostic",
        [validator_ref],
        run_record=diagnostic_run,
    )
    assert store.validate_gate_evidence(
        diagnostic_result,
        gate_run_definition=diagnostic_definition,
        run_record=diagnostic_run,
    ) == [validator]
    with pytest.raises(EvidenceError, match="pass credit differs"):
        store.validate_gate_evidence(
            dict(diagnostic_result, pass_credit=True),
            gate_run_definition=diagnostic_definition,
            run_record=diagnostic_run,
        )

    wrong_input_task = task_with_gate_definitions(
        {
            "record_type": "Task",
            "task_id": "T-evidence-wrong-input",
            "state": "PLANNED",
            "required_capability": "validation.evaluate",
            "acceptance_predicate": "wrong input rejection",
            "allowed_paths": ["src"],
            "activation_digest": ACTIVATION,
            "candidate_digest": CANDIDATE,
            "created_at": "2026-02-01T00:00:00Z",
        },
        {
            "gate_id": "diagnostic-gate",
            "input_digests": ["7" * 64],
            "evidence_class": "validator",
            "evidence_purpose": "diagnostic",
        },
    )
    wrong_inputs = wrong_input_task["gate_run_definitions"][0]["definition"]
    wrong_input_run = gate_run_for(
        wrong_input_task, "diagnostic-gate", "R-wrong-input"
    )
    with pytest.raises(EvidenceError, match="differs"):
        store.validate_gate_evidence(
            gate_result_for(
                wrong_input_task,
                "diagnostic-gate",
                "R-wrong-input",
                [validator_ref],
                run_record=wrong_input_run,
            ),
            gate_run_definition=wrong_inputs,
            run_record=wrong_input_run,
        )
    substituted_result = dict(
        diagnostic_result,
        run_id="R-substituted-policy",
        policy_digest="7" * 64,
    )
    with pytest.raises(EvidenceError, match="differs"):
        store.validate_gate_evidence(
            substituted_result,
            gate_run_definition=diagnostic_definition,
            run_record=diagnostic_run,
        )

    outcome_references: dict[str, dict[str, str]] = {}
    for status in ("fail", "blocked"):
        artifact = finalized_evidence(
            store,
            artifact_id=f"E-gate-{status}",
            payload=f"gate {status}".encode("utf-8"),
            media_type="text/plain",
            retention_class="audit",
            candidate_digest=CANDIDATE,
            policy_digest=POLICY,
            tool_digest=TOOL,
            input_digests=[INPUT],
            created_at="2026-02-01T00:00:02Z",
            activation_digest=ACTIVATION,
            outcome=status,
            evidence_class="validator",
        )
        outcome_references[status] = evidence_reference(store, artifact)
        status_task = task_with_gate_definitions(
            {
                "record_type": "Task",
                "task_id": f"T-gate-{status}",
                "state": "PLANNED",
                "required_capability": "validation.evaluate",
                "acceptance_predicate": f"exact {status} evidence",
                "allowed_paths": ["src"],
                "activation_digest": ACTIVATION,
                "candidate_digest": CANDIDATE,
                "created_at": "2026-02-01T00:00:00Z",
            },
            {"gate_id": f"gate-{status}"},
        )
        definition = status_task["gate_run_definitions"][0]["definition"]
        status_run = gate_run_for(
            status_task, f"gate-{status}", "R1", status=status
        )
        assert store.validate_gate_evidence(
            gate_result_for(
                status_task,
                f"gate-{status}",
                "R1",
                [outcome_references[status]],
                status=status,
                reason=("blocked by fixture" if status == "blocked" else None),
                run_record=status_run,
            ),
            gate_run_definition=definition,
            run_record=status_run,
        ) == [artifact]
    skipped_task = task_with_gate_definitions(
        {
            "record_type": "Task",
            "task_id": "T-gate-skipped",
            "state": "PLANNED",
            "required_capability": "validation.evaluate",
            "acceptance_predicate": "explicit skip reason",
            "allowed_paths": ["src"],
            "activation_digest": ACTIVATION,
            "candidate_digest": CANDIDATE,
            "created_at": "2026-02-01T00:00:00Z",
        },
        {"gate_id": "gate-skipped"},
    )
    skipped_definition = skipped_task["gate_run_definitions"][0]["definition"]
    skipped_run = gate_run_for(
        skipped_task, "gate-skipped", "R1", status="skipped"
    )
    assert store.validate_gate_evidence(
        gate_result_for(
            skipped_task,
            "gate-skipped",
            "R1",
            [],
            status="skipped",
            reason="not applicable to this bounded target",
            run_record=skipped_run,
        ),
        gate_run_definition=skipped_definition,
        run_record=skipped_run,
    ) == []
    blocked_task = status_task
    blocked_definition = blocked_task["gate_run_definitions"][0]["definition"]
    blocked_run = gate_run_for(
        blocked_task, "gate-blocked", "R-wrong-outcome", status="blocked"
    )
    with pytest.raises(EvidenceError, match="differs"):
        store.validate_gate_evidence(
            gate_result_for(
                blocked_task,
                "gate-blocked",
                "R-wrong-outcome",
                [outcome_references["fail"]],
                status="blocked",
                reason="fixture mismatch",
                run_record=blocked_run,
            ),
            gate_run_definition=blocked_definition,
            run_record=blocked_run,
        )


def test_task_accepts_no_filesystem_mutation_scope_and_still_validates_supplied_paths(
    tmp_path: Path,
) -> None:
    engine, grants = issued_engine()
    domain = DomainState(
        engine,
        EvidenceStore(tmp_path / "cas"),
        implementation_closure_digest=IMPLEMENTATION,
    )
    domain.record_candidate(
        {
            "record_type": "Candidate",
            "candidate_id": "C-non-filesystem-task",
            "candidate_digest": CANDIDATE,
            "inventory_digest": "1" * 64,
            "product_root_digest": "2" * 64,
            "control_excluded": True,
            "candidate_recipe_digest": "5" * 64,
            "consistency_mode": "immutable-vcs-tree",
            "creditable": True,
            "snapshot_provider_id": "test-vcs-provider",
            "snapshot_digest": "6" * 64,
        },
        authorization(grants["worker"]),
    )
    task = task_with_gate_definitions(
        {
            "record_type": "Task",
            "task_id": "T-non-filesystem",
            "state": "PLANNED",
            "required_capability": "task.execute",
            "acceptance_predicate": "the declared computation result is recorded",
            "allowed_paths": [],
            "activation_digest": ACTIVATION,
            "candidate_digest": CANDIDATE,
            "created_at": "2026-02-01T00:00:00Z",
        },
        {"gate_id": "G-non-filesystem"},
    )

    validate_definition(core_schema(), "Task", task)
    assert domain.record_task(task, authorization(grants["planner"])) == task
    assert domain.tasks[task["task_id"]]["allowed_paths"] == []

    invalid_path_task = task_with_gate_definitions(
        {
            **task,
            "task_id": "T-invalid-path",
            "allowed_paths": ["../outside"],
        },
        {"gate_id": "G-invalid-path"},
    )
    with pytest.raises(DomainError, match="changed path"):
        domain.record_task(
            invalid_path_task,
            authorization(grants["planner"]),
        )


def test_plan_proposal_accepts_tasks_without_file_or_source_bindings() -> None:
    proposal = {
        "record_type": "PlanProposal",
        "proposal_id": "proposal:compute-only",
        "project_id": "project:arbitrary-work",
        "project_mode": "greenfield",
        "goal": "Compute and communicate a deterministic result.",
        "source_plan_digest": "7" * 64,
        "created_at": "2026-02-01T00:00:00Z",
        "tasks": [
            {
                "task_id": "task:compute-only",
                "title": "Compute a result",
                "operation": "read",
                "depends_on": [],
                "acceptance_predicate": "The result matches the declared calculation.",
                "allowed_paths": [],
                "source_bindings": [],
                "authority": False,
                "pass_credit": False,
            }
        ],
        "authority": False,
        "pass_credit": False,
        "proposal_digest": "8" * 64,
    }

    validate_definition(core_schema(), "PlanProposal", proposal)


def test_task_and_lease_state_machine_fence_and_no_acceptance(tmp_path: Path) -> None:
    engine, grants = issued_engine()
    domain = DomainState(
        engine,
        EvidenceStore(tmp_path / "cas"),
        implementation_closure_digest=IMPLEMENTATION,
    )
    policy = domain_runtime_policy()
    domain.record_candidate(
        {
            "record_type": "Candidate",
            "candidate_id": "C-task-lease",
            "candidate_digest": CANDIDATE,
            "inventory_digest": "1" * 64,
            "product_root_digest": "2" * 64,
            "control_excluded": True,
            "candidate_recipe_digest": "5" * 64,
            "consistency_mode": "immutable-vcs-tree",
            "creditable": True,
            "snapshot_provider_id": "test-vcs-provider",
            "snapshot_digest": "6" * 64,
        },
        authorization(grants["worker"]),
    )
    task = task_with_gate_definitions({
        "record_type": "Task",
        "task_id": "T1",
        "state": "PLANNED",
        "required_capability": "task.execute",
        "acceptance_predicate": "candidate evidence passes policy",
        "allowed_paths": ["src"],
        "activation_digest": ACTIVATION,
        "candidate_digest": CANDIDATE,
        "created_at": "2026-02-01T00:00:00Z",
    }, {"gate_id": "G-task-diagnostic"})
    with pytest.raises(DomainError, match="begin in PLANNED"):
        domain.record_task(
            dict(task, task_id="T-terminal", state="COMPLETED"),
            authorization(grants["planner"]),
        )
    domain.record_task(task, authorization(grants["planner"]))
    with pytest.raises(DomainError, match="stale"):
        domain.transition_task(
            {
                "task_id": "T1",
                "from_state": "READY",
                "to_state": "LEASED",
                "reason": "stale actor",
            },
            authorization(grants["planner"]),
            runtime_policy=policy,
        )
    domain.transition_task(
        {
            "task_id": "T1",
            "from_state": "PLANNED",
            "to_state": "READY",
            "reason": "dependencies satisfied",
        },
        authorization(grants["planner"]),
        runtime_policy=policy,
    )
    lease = {
        "record_type": "Lease",
        "lease_id": "L1",
        "task_id": "T1",
        "manager_subject_id": "manager",
        "manager_grant_id": grants["manager"]["grant_id"],
        "manager_grant_claim_digest": grants["manager"]["claim_digest"],
        "holder_subject_id": "worker",
        "holder_grant_id": grants["worker"]["grant_id"],
        "holder_grant_claim_digest": grants["worker"]["claim_digest"],
        "generation": 1,
        "fencing_token": 1,
        "state": "ACTIVE",
        "acquired_at": "2026-02-01T00:00:00Z",
        "heartbeat_at": "2026-02-01T00:00:00Z",
        "expires_at": "2026-02-01T00:10:00Z",
        "activation_digest": ACTIVATION,
    }
    with pytest.raises(DomainError, match="begin in ACTIVE"):
        domain.acquire_lease(
            dict(lease, lease_id="L-terminal", state="CLOSED"),
            authorization(grants["manager"]),
            parallelism_policy=policy,
        )
    domain.acquire_lease(
        lease,
        authorization(grants["manager"]),
        parallelism_policy=policy,
    )
    assert domain.tasks["T1"]["state"] == "READY"
    domain.transition_task(
        {
            "task_id": "T1",
            "from_state": "READY",
            "to_state": "LEASED",
            "reason": "current Lease acquired",
        },
        authorization(grants["planner"]),
        runtime_policy=policy,
    )
    assert domain.tasks["T1"]["state"] == "LEASED"
    assert domain.assert_mutation_lease(
        task_id="T1",
        lease_id="L1",
        generation=1,
        fencing_token=1,
        holder_authorization=authorization(
            grants["worker"], at="2026-02-01T00:01:00Z"
        ),
    )["lease_id"] == "L1"
    workcard = {
        "record_type": "WorkCard",
        "task_id": "T1",
        "operation_mode": "mutate",
        "operation": "candidate.record",
        "acceptance_predicate": task["acceptance_predicate"],
        "allowed_paths": task["allowed_paths"],
        "holder_grant_id": grants["worker"]["grant_id"],
        "candidate_digest": CANDIDATE,
        "activation_digest": ACTIVATION,
        "context_digest": "7" * 64,
        "query_grant_id": grants["reader"]["grant_id"],
        "query_grant_claim_digest": grants["reader"]["claim_digest"],
        "stop_conditions": ["task-state-changed"],
        "budget": {
            "max_bytes": 4096,
            "max_entities": 8,
            "max_relations": 8,
            "max_fanout_per_entity": 4,
            "top_k": 4,
        },
        "truncated": False,
        "lease_id": "L1",
        "lease_generation": 1,
        "fencing_token": 1,
    }
    validate_definition(core_schema(), "WorkCard", workcard)
    mutation_command = {
        "command_kind": "candidate.record",
        "subject_id": "worker",
        "authorization": {
            "kind": "grant",
            "grant_id": grants["worker"]["grant_id"],
            "grant_claim_digest": grants["worker"]["claim_digest"],
        },
        "holder_authorization": {
            "kind": "grant",
            "grant_id": grants["worker"]["grant_id"],
            "grant_claim_digest": grants["worker"]["claim_digest"],
        },
        "requested_scope": [{"kind": "all", "value": "*"}],
        "issued_at": "2026-02-01T00:01:00Z",
        "activation_digest": ACTIVATION,
        "workcard_task_id": "T1",
        "lease_id": "L1",
        "lease_generation": 1,
        "fencing_token": 1,
        "workcard_digest": canonical_digest(workcard),
        "context_digest": "7" * 64,
        "payload": {"candidate_digest": CANDIDATE},
    }
    assert domain.assert_mutation_claim(mutation_command, workcard)["lease_id"] == "L1"
    with pytest.raises(DomainError, match="bound Lease holder Grant"):
        domain.assert_mutation_claim(
            dict(
                mutation_command,
                holder_authorization={
                    "kind": "grant",
                    "grant_id": grants["worker"]["grant_id"],
                    "grant_claim_digest": "0" * 64,
                },
            ),
            workcard,
        )
    domain.tasks["T1"]["state"] = "READY"
    leased_workcard = dict(workcard, operation="task.transition")
    leased_transition = dict(
        mutation_command,
        command_kind="task.transition",
        workcard_digest=canonical_digest(leased_workcard),
        payload={
            "task_id": "T1",
            "from_state": "READY",
            "to_state": "LEASED",
            "reason": "current Lease acquired",
        },
    )
    assert domain.assert_mutation_claim(leased_transition, leased_workcard)["lease_id"] == "L1"
    with pytest.raises(DomainError, match="not executable"):
        domain.assert_mutation_claim(
            dict(
                leased_transition,
                command_kind="candidate.record",
                workcard_digest=canonical_digest(workcard),
            ),
            workcard,
        )
    domain.tasks["T1"]["state"] = "LEASED"
    broadened_card = dict(workcard, allowed_paths=["src", "secrets"])
    with pytest.raises(DomainError, match="differs from its Task"):
        domain.assert_mutation_claim(
            dict(mutation_command, workcard_digest=canonical_digest(broadened_card)),
            broadened_card,
        )
    with pytest.raises(DomainError, match="fencing token binding"):
        domain.assert_mutation_claim(dict(mutation_command, fencing_token=2), workcard)
    with pytest.raises(DomainError, match="stale Lease"):
        domain.assert_mutation_lease(
            task_id="T1",
            lease_id="L1",
            generation=1,
            fencing_token=0,
            holder_authorization=authorization(
                grants["worker"], at="2026-02-01T00:01:00Z"
            ),
        )
    approval = domain.approval_status(CANDIDATE)
    assert approval["product_acceptance"] is False
    assert approval["public_release_approved"] is False
    assert approval["current_release_eligible"] is False
    assert approval["historical_release_decision_id"] is None
    assert approval["invalidation_reasons"] == ["no-historical-release-decision"]
    with pytest.raises(DomainError, match="stale Lease"):
        domain.heartbeat_lease(
            "L1",
            1,
            0,
            "2026-02-01T00:02:00Z",
            "2026-02-01T00:12:00Z",
            authorization(grants["worker"], at="2026-02-01T00:02:00Z"),
            runtime_policy=policy,
        )
    domain.heartbeat_lease(
        "L1",
        1,
        1,
        "2026-02-01T00:02:00Z",
        "2026-02-01T00:12:00Z",
        authorization(grants["worker"], at="2026-02-01T00:02:00Z"),
        runtime_policy=policy,
    )
    with pytest.raises(DomainError, match="outside its live interval"):
        domain.begin_close_lease(
            "L1",
            1,
            1,
            authorization(grants["worker"], at="2026-02-01T00:12:00Z"),
            runtime_policy=policy,
        )
    domain.begin_close_lease(
        "L1",
        1,
        1,
        authorization(grants["worker"], at="2026-02-01T00:03:00Z"),
        runtime_policy=policy,
    )
    closed = domain.close_lease(
        "L1",
        1,
        1,
        {
            "acknowledged_by": "manager",
            "grant_id": grants["manager"]["grant_id"],
            "grant_claim_digest": grants["manager"]["claim_digest"],
            "acknowledged_at": "2026-02-01T00:04:00Z",
        },
        authorization(grants["manager"], at="2026-02-01T00:04:00Z"),
        runtime_policy=policy,
    )
    assert closed["state"] == "CLOSED"
    assert closed["close_ack"]["grant_id"] != closed["holder_grant_id"]
    validate_definition(core_schema(), "Lease", closed)
    domain.transition_task(
        {
            "task_id": "T1",
            "from_state": "LEASED",
            "to_state": "READY",
            "reason": "closed Lease reconciled",
        },
        authorization(grants["planner"], at="2026-02-01T00:05:00Z"),
        runtime_policy=policy,
    )
    second = dict(
        lease,
        lease_id="L2",
        generation=2,
        fencing_token=2,
        acquired_at="2026-02-01T00:05:00Z",
        heartbeat_at="2026-02-01T00:05:00Z",
        expires_at="2026-02-01T00:06:00Z",
    )
    domain.acquire_lease(
        second,
        authorization(grants["manager"], at="2026-02-01T00:05:00Z"),
        parallelism_policy=policy,
    )
    domain.transition_task(
        {
            "task_id": "T1",
            "from_state": "READY",
            "to_state": "LEASED",
            "reason": "replacement Lease acquired",
        },
        authorization(grants["planner"], at="2026-02-01T00:05:00Z"),
        runtime_policy=policy,
    )
    expired = domain.expire_lease(
        "L2",
        2,
        2,
        "2026-02-01T00:06:00Z",
        authorization(grants["manager"], at="2026-02-01T00:06:00Z"),
        runtime_policy=policy,
    )
    assert expired["state"] == "EXPIRED"
    validate_definition(core_schema(), "Lease", expired)
    reconciliation = {
        "reconciled_by": "manager",
        "grant_id": grants["manager"]["grant_id"],
        "grant_claim_digest": grants["manager"]["claim_digest"],
        "reconciled_at": "2026-02-01T00:07:00Z",
        "generation": 2,
        "fencing_token": 2,
    }
    with pytest.raises(DomainError, match="manager Grant is invalid"):
        domain.reconcile_lease_capacity(
            "L2",
            2,
            2,
            dict(reconciliation, grant_claim_digest="0" * 64),
            authorization(grants["manager"], at="2026-02-01T00:07:00Z"),
            runtime_policy=policy,
        )
    reconciled = domain.reconcile_lease_capacity(
        "L2",
        2,
        2,
        reconciliation,
        authorization(grants["manager"], at="2026-02-01T00:07:00Z"),
        runtime_policy=policy,
    )
    assert reconciled["capacity_reconciliation"] == reconciliation
    validate_definition(core_schema(), "Lease", reconciled)
    domain.transition_task(
        {
            "task_id": "T1",
            "from_state": "LEASED",
            "to_state": "READY",
            "reason": "expired Lease capacity reconciled",
        },
        authorization(grants["planner"], at="2026-02-01T00:08:00Z"),
        runtime_policy=policy,
    )
    third = dict(
        second,
        lease_id="L3",
        generation=3,
        fencing_token=3,
        acquired_at="2026-02-01T00:08:00Z",
        heartbeat_at="2026-02-01T00:08:00Z",
        expires_at="2026-02-01T00:18:00Z",
    )
    assert domain.acquire_lease(
        third,
        authorization(grants["manager"], at="2026-02-01T00:08:00Z"),
        parallelism_policy=policy,
    )["fencing_token"] == 3
    assert domain.approval_status(CANDIDATE)["product_acceptance"] is False


def test_gate_and_decision_fail_closed_without_human_closure(tmp_path: Path) -> None:
    engine, grants = issued_engine()
    evidence = EvidenceStore(tmp_path / "cas")
    domain = DomainState(
        engine,
        evidence,
        required_acceptance=["G1", "G2", "human-release-decision"],
        provider_binding_digest=PROVIDER,
        implementation_closure_digest=IMPLEMENTATION,
    )
    candidate = {
        "record_type": "Candidate",
        "candidate_id": "C1",
        "candidate_digest": CANDIDATE,
        "inventory_digest": "1" * 64,
        "product_root_digest": "2" * 64,
        "control_excluded": True,
        "candidate_recipe_digest": "5" * 64,
        "consistency_mode": "immutable-vcs-tree",
        "creditable": True,
        "snapshot_provider_id": "test-vcs-provider",
        "snapshot_digest": "6" * 64,
    }
    domain.record_candidate(candidate, authorization(grants["worker"]))
    validate_definition(core_schema(), "Candidate", candidate)
    artifact = finalized_evidence(
        evidence,
        artifact_id="E1",
        payload=b"real validator output",
        media_type="application/json",
        retention_class="audit",
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        created_at="2026-02-01T00:01:00Z",
        activation_digest=ACTIVATION,
        outcome="pass",
        evidence_class="product-execution",
        product_credit_eligible=True,
    )
    product_invocations = artifact["evidence_binding"]["provider_invocations"]
    gate_task = task_with_gate_definitions(
        {
            "record_type": "Task",
            "task_id": "T-product-gates",
            "state": "PLANNED",
            "required_capability": "validation.evaluate",
            "acceptance_predicate": "exact product gate evidence",
            "allowed_paths": ["src"],
            "activation_digest": ACTIVATION,
            "candidate_digest": CANDIDATE,
            "created_at": "2026-02-01T00:01:00Z",
        },
        {
            "gate_id": "G1",
            "evidence_class": "product-execution",
            "evidence_purpose": "product",
            "product_credit_required": True,
            "provider_invocations": product_invocations,
        },
        {
            "gate_id": "G2",
            "evidence_class": "product-execution",
            "evidence_purpose": "product",
            "product_credit_required": True,
            "provider_invocations": product_invocations,
        },
    )
    domain.record_task(
        gate_task, authorization(grants["planner"], at="2026-02-01T00:01:00Z")
    )
    artifact_ref = evidence_reference(evidence, artifact)
    run = gate_run_for(gate_task, "G1", "R1")
    result = gate_result_for(
        gate_task, "G1", "R1", [artifact_ref], run_record=run
    )
    gate_scope = gate_task["gate_run_definitions"][0]["definition"][
        "target_scope"
    ]
    domain.record_gate_result(
        result,
        authorization(
            grants["validator"],
            at="2026-02-01T00:01:00Z",
            scope=gate_scope,
        ),
        run_record=run,
    )
    validate_definition(core_schema(), "GateResult", result)
    with pytest.raises(DomainError, match="differs from its definition"):
        invalid = dict(result, run_id="R2", pass_credit=False)
        domain.record_gate_result(
            invalid,
            authorization(
            grants["validator"],
            at="2026-02-01T00:01:00Z",
            scope=gate_scope,
        ),
            run_record=gate_run_for(gate_task, "G1", "R2"),
        )
    with pytest.raises(DomainError, match="overwrite"):
        overwrite_run = gate_run_for(gate_task, "G1", "R1", status="fail")
        domain.record_gate_result(
            gate_result_for(
                gate_task,
                "G1",
                "R1",
                [artifact_ref],
                status="fail",
                run_record=overwrite_run,
            ),
            authorization(
            grants["validator"],
            at="2026-02-01T00:01:00Z",
            scope=gate_scope,
        ),
            run_record=overwrite_run,
        )

    failed_artifact = finalized_evidence(
        evidence,
        artifact_id="E-finding",
        payload=b"observed failure",
        media_type="text/plain",
        retention_class="audit",
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        created_at="2026-02-01T00:02:00Z",
        activation_digest=ACTIVATION,
        outcome="fail",
    )
    finding = {
        "record_type": "Finding",
        "finding_id": "F1",
        "status": "OPEN",
        "severity": "P1",
        "blocking": True,
        "statement": "critical policy failure",
        "activation_digest": ACTIVATION,
        "candidate_digest": CANDIDATE,
        "evidence_artifacts": [evidence_reference(evidence, failed_artifact)],
        "created_at": "2026-02-01T00:02:00Z",
    }
    domain.record_finding(
        finding, authorization(grants["finder"], at="2026-02-01T00:02:00Z")
    )
    finding_digest = canonical_digest(finding)
    resolution_artifact = finalized_evidence(
        evidence,
        artifact_id="E-resolution-F1",
        payload=b"finding F1 corrective verification",
        media_type="application/json",
        retention_class="audit",
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        created_at="2026-02-01T00:03:00Z",
        activation_digest=ACTIVATION,
        outcome="pass",
        finding_digest=finding_digest,
    )
    resolution_task = task_with_gate_definitions(
        {
            "record_type": "Task",
            "task_id": "T-resolve-F1",
            "state": "PLANNED",
            "required_capability": "validation.evaluate",
            "acceptance_predicate": "exact Finding F1 resolution",
            "allowed_paths": ["src"],
            "activation_digest": ACTIVATION,
            "candidate_digest": CANDIDATE,
            "created_at": "2026-02-01T00:03:00Z",
        },
        {
            "gate_id": "finding-resolution-F1",
            "target_kind": "finding",
            "target_digest": finding_digest,
            "target_scope": [
                {"kind": "finding", "value": "F1"},
            ],
        },
    )
    domain.record_task(
        resolution_task,
        authorization(grants["planner"], at="2026-02-01T00:03:00Z"),
    )
    domain.record_gate_result(
        gate_result_for(
            resolution_task,
            "finding-resolution-F1",
            "R-resolution-F1",
            [evidence_reference(evidence, resolution_artifact)],
        ),
        authorization(
            grants["validator"],
            at="2026-02-01T00:03:00Z",
            scope=resolution_task["gate_run_definitions"][0]["definition"][
                "target_scope"
            ],
        ),
        run_record=gate_run_for(
            resolution_task, "finding-resolution-F1", "R-resolution-F1"
        ),
    )
    published_authority = engine.freeze(runtime_overlay_compaction_depth=2).snapshot
    published_domain = domain.freeze(runtime_overlay_compaction_depth=2).snapshot
    engine = published_authority.fork()
    domain = published_domain.fork(authority=engine)
    resolution = exact_decision(
        decision_id="D-resolve",
        decision_kind="resolve",
        grant=grants["resolver"],
        target_type="Finding",
        target=finding,
        finding_digest=finding_digest,
        rationale="corrective evidence independently validated",
        evidence_artifacts=[evidence_reference(evidence, resolution_artifact)],
        created_at="2026-02-01T00:04:00Z",
    )
    domain.record_decision(
        resolution,
        authorization(grants["resolver"], at="2026-02-01T00:04:00Z"),
    )
    validate_definition(core_schema(), "Decision", resolution)
    validate_definition(core_schema(), "Finding", domain.findings["F1"])
    assert domain.findings["F1"]["status"] == "RESOLVED"
    assert domain.findings["F1"]["blocking"] is False
    assert domain.findings["F1"]["disposition_decision_id"] == "D-resolve"
    disposition_delta = {
        item["leaf_type"]: item["value"]
        for item in domain.changed_persistent_records()
    }
    assert disposition_delta == {
        "Decision": resolution,
        "Finding": domain.findings["F1"],
    }
    with pytest.raises(DomainError, match="already been dispositioned"):
        domain.record_decision(
            dict(
                resolution,
                decision_id="D-waive-after-resolve",
                decision_kind="waive",
                subject_id="waiver",
                grant_id=grants["waiver"]["grant_id"],
                exception_policy_digest=POLICY,
                expires_at="2026-03-01T00:00:00Z",
            ),
            authorization(grants["waiver"], at="2026-02-01T00:04:00Z"),
        )

    nonblocking_p1 = dict(
        finding,
        finding_id="F2",
        blocking=False,
        statement="unresolved P1 remains release-significant",
        created_at="2026-02-01T00:04:00Z",
    )
    domain.record_finding(
        nonblocking_p1,
        authorization(grants["finder"], at="2026-02-01T00:04:00Z"),
    )
    finding_f2_digest = canonical_digest(nonblocking_p1)
    resolution_f2_artifact = finalized_evidence(
        evidence,
        artifact_id="E-resolution-F2",
        payload=b"finding F2 corrective verification",
        media_type="application/json",
        retention_class="audit",
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        created_at="2026-02-01T00:04:00Z",
        activation_digest=ACTIVATION,
        outcome="pass",
        finding_digest=finding_f2_digest,
    )
    resolution_f2_task = task_with_gate_definitions(
        {
            "record_type": "Task",
            "task_id": "T-resolve-F2",
            "state": "PLANNED",
            "required_capability": "validation.evaluate",
            "acceptance_predicate": "exact Finding F2 resolution",
            "allowed_paths": ["src"],
            "activation_digest": ACTIVATION,
            "candidate_digest": CANDIDATE,
            "created_at": "2026-02-01T00:04:00Z",
        },
        {
            "gate_id": "finding-resolution-F2",
            "target_kind": "finding",
            "target_digest": finding_f2_digest,
            "target_scope": [
                {"kind": "finding", "value": "F2"},
            ],
        },
    )
    domain.record_task(
        resolution_f2_task,
        authorization(grants["planner"], at="2026-02-01T00:04:00Z"),
    )
    domain.record_gate_result(
        gate_result_for(
            resolution_f2_task,
            "finding-resolution-F2",
            "R-resolution-F2",
            [evidence_reference(evidence, resolution_f2_artifact)],
        ),
        authorization(
            grants["validator"],
            at="2026-02-01T00:04:00Z",
            scope=resolution_f2_task["gate_run_definitions"][0]["definition"][
                "target_scope"
            ],
        ),
        run_record=gate_run_for(
            resolution_f2_task, "finding-resolution-F2", "R-resolution-F2"
        ),
    )
    promotion = exact_decision(
        decision_id="D-promote",
        decision_kind="promote",
        grant=grants["promoter"],
        target_type="Candidate",
        target=candidate,
        rationale="candidate evidence is promotion-creditable",
        evidence_artifacts=[artifact_ref],
        created_at="2026-02-01T00:05:00Z",
    )
    domain.record_decision(
        promotion,
        authorization(grants["promoter"], at="2026-02-01T00:05:00Z"),
    )

    assert domain.approval_status(CANDIDATE)["public_release_approved"] is False
    release = exact_decision(
        decision_id="D-release",
        decision_kind="release",
        grant=grants["approver"],
        target_type="Candidate",
        target=candidate,
        release_closure_digest="8" * 64,
        provider_binding_digest=PROVIDER,
        rationale="all production evidence reviewed",
        evidence_artifacts=[artifact_ref],
        created_at="2026-02-01T00:06:00Z",
    )
    with pytest.raises(DomainError, match="current Findings"):
        domain.record_decision(
            release,
            authorization(grants["approver"], at="2026-02-01T00:06:00Z"),
        )
    domain.record_decision(
        exact_decision(
            decision_id="D-resolve-F2",
            decision_kind="resolve",
            grant=grants["resolver"],
            target_type="Finding",
            target=nonblocking_p1,
            finding_digest=finding_f2_digest,
            rationale="corrective evidence independently validated",
            evidence_artifacts=[
                evidence_reference(evidence, resolution_f2_artifact)
            ],
            created_at="2026-02-01T00:07:00Z",
        ),
        authorization(grants["resolver"], at="2026-02-01T00:07:00Z"),
    )
    with pytest.raises(DomainError, match="missing required Candidate gates"):
        domain.record_decision(
            dict(release, created_at="2026-02-01T00:08:00Z"),
            authorization(grants["approver"], at="2026-02-01T00:08:00Z"),
        )
    assert domain.approval_status(CANDIDATE)["product_acceptance"] is False


def test_release_decision_is_historical_and_current_eligibility_fails_closed(
    tmp_path: Path,
) -> None:
    engine, grants = issued_engine()
    evidence = EvidenceStore(tmp_path / "release-cas")
    domain = DomainState(
        engine,
        evidence,
        required_acceptance=["G1", "G2", "human-release-decision"],
        provider_binding_digest=PROVIDER,
        implementation_closure_digest=IMPLEMENTATION,
    )
    candidate = {
        "record_type": "Candidate",
        "candidate_id": "C-release",
        "candidate_digest": CANDIDATE,
        "inventory_digest": "1" * 64,
        "product_root_digest": "2" * 64,
        "control_excluded": True,
        "candidate_recipe_digest": "5" * 64,
        "consistency_mode": "immutable-vcs-tree",
        "creditable": True,
        "snapshot_provider_id": "test-vcs-provider",
        "snapshot_digest": "6" * 64,
    }
    domain.record_candidate(candidate, authorization(grants["worker"]))
    product = finalized_evidence(
        evidence,
        artifact_id="E-release-product",
        payload=b"exact product execution",
        media_type="application/json",
        retention_class="release",
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        created_at="2026-02-01T00:01:00Z",
        activation_digest=ACTIVATION,
        outcome="pass",
        evidence_class="product-execution",
        product_credit_eligible=True,
    )
    product_ref = evidence_reference(evidence, product)
    product_invocations = product["evidence_binding"]["provider_invocations"]
    gate_task = task_with_gate_definitions(
        {
            "record_type": "Task",
            "task_id": "T-release-gates",
            "state": "PLANNED",
            "required_capability": "validation.evaluate",
            "acceptance_predicate": "exact product release gates",
            "allowed_paths": ["src"],
            "activation_digest": ACTIVATION,
            "candidate_digest": CANDIDATE,
            "created_at": "2026-02-01T00:01:00Z",
        },
        {
            "gate_id": "G1",
            "evidence_class": "product-execution",
            "evidence_purpose": "product",
            "product_credit_required": True,
            "provider_invocations": product_invocations,
        },
        {
            "gate_id": "G2",
            "evidence_class": "product-execution",
            "evidence_purpose": "product",
            "product_credit_required": True,
            "provider_invocations": product_invocations,
        },
    )
    domain.record_task(
        gate_task,
        authorization(grants["planner"], at="2026-02-01T00:01:00Z"),
    )
    for index, gate_id in enumerate(("G1", "G2"), start=1):
        run_id = f"R-release-{gate_id}"
        domain.record_gate_result(
            gate_result_for(gate_task, gate_id, run_id, [product_ref]),
            authorization(
                grants["validator"],
                at=f"2026-02-01T00:0{index}:00Z",
                scope=gate_task["gate_run_definitions"][index - 1]["definition"][
                    "target_scope"
                ],
            ),
            run_record=gate_run_for(gate_task, gate_id, run_id),
        )
    domain.record_decision(
        exact_decision(
            decision_id="D-release-promote",
            decision_kind="promote",
            grant=grants["promoter"],
            target_type="Candidate",
            target=candidate,
            rationale="exact product evidence is promotion-creditable",
            evidence_artifacts=[product_ref],
            created_at="2026-02-01T00:03:00Z",
        ),
        authorization(grants["promoter"], at="2026-02-01T00:03:00Z"),
    )
    closure = domain.release_closure_digest(
        CANDIDATE,
        provider_binding_digest=PROVIDER,
        evaluated_at="2026-02-01T00:04:00Z",
    )
    release = exact_decision(
        decision_id="D-release-current",
        decision_kind="release",
        grant=grants["approver"],
        target_type="Candidate",
        target=candidate,
        release_closure_digest=closure,
        provider_binding_digest=PROVIDER,
        rationale="exact closure reviewed by the configured human",
        evidence_artifacts=[product_ref],
        created_at="2026-02-01T00:04:00Z",
    )
    validate_definition(core_schema(), "Decision", release)
    domain.record_decision(
        release,
        authorization(grants["approver"], at="2026-02-01T00:04:00Z"),
    )
    historical_digest = canonical_digest(domain.decisions["D-release-current"])
    current = domain.approval_status(
        CANDIDATE, evaluated_at="2026-02-01T00:05:00Z"
    )
    assert current["current_release_eligible"] is True
    assert current["product_acceptance"] is False
    assert current["public_release_approved"] is False
    assert current["release_closure_digest"] == current["current_closure_digest"]
    assert current["invalidation_reasons"] == []

    provider_drift = domain.approval_status(
        CANDIDATE,
        current_provider_binding_digest="8" * 64,
        evaluated_at="2026-02-01T00:05:00Z",
    )
    assert provider_drift["current_release_eligible"] is False
    assert "provider-drift" in provider_drift["invalidation_reasons"]
    activation_drift = domain.approval_status(
        CANDIDATE,
        current_activation_digest="b" * 64,
        evaluated_at="2026-02-01T00:05:00Z",
    )
    assert activation_drift["current_release_eligible"] is False
    assert "activation-drift" in activation_drift["invalidation_reasons"]
    implementation_drift = domain.approval_status(
        CANDIDATE,
        current_implementation_closure_digest="7" * 64,
        evaluated_at="2026-02-01T00:05:00Z",
    )
    assert implementation_drift["current_release_eligible"] is False
    assert "implementation-drift" in implementation_drift["invalidation_reasons"]

    object_path = evidence._object_path(product["digest"])
    parked_path = object_path.with_name(object_path.name + ".parked")
    object_path.rename(parked_path)
    try:
        evidence_drift = domain.approval_status(
            CANDIDATE, evaluated_at="2026-02-01T00:05:00Z"
        )
        assert evidence_drift["current_release_eligible"] is False
        assert "evidence-drift" in evidence_drift["invalidation_reasons"]
    finally:
        parked_path.rename(object_path)

    failed = finalized_evidence(
        evidence,
        artifact_id="E-release-regression",
        payload=b"later release regression",
        media_type="text/plain",
        retention_class="audit",
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        created_at="2026-02-01T00:05:00Z",
        activation_digest=ACTIVATION,
        outcome="fail",
        evidence_class="product-execution",
        evidence_purpose="product",
        provider_invocations=product_invocations,
    )
    domain.record_finding(
        {
            "record_type": "Finding",
            "finding_id": "F-after-release",
            "status": "OPEN",
            "severity": "P1",
            "blocking": True,
            "statement": "later acceptance blocker",
            "activation_digest": ACTIVATION,
            "candidate_digest": CANDIDATE,
            "evidence_artifacts": [evidence_reference(evidence, failed)],
            "created_at": "2026-02-01T00:06:00Z",
        },
        authorization(grants["finder"], at="2026-02-01T00:06:00Z"),
    )
    domain.record_gate_result(
        gate_result_for(
            gate_task,
            "G2",
            "R2",
            [evidence_reference(evidence, failed)],
            status="fail",
        ),
        authorization(
            grants["validator"],
            at="2026-02-01T00:07:00Z",
            scope=gate_task["gate_run_definitions"][1]["definition"][
                "target_scope"
            ],
        ),
        run_record=gate_run_for(gate_task, "G2", "R2", status="fail"),
    )
    invalidated = domain.approval_status(
        CANDIDATE, evaluated_at="2026-02-01T00:08:00Z"
    )
    assert invalidated["current_release_eligible"] is False
    assert "later-blocking-finding" in invalidated["invalidation_reasons"]
    assert "required-gate-failed" in invalidated["invalidation_reasons"]
    assert canonical_digest(domain.decisions["D-release-current"]) == historical_digest
    policy = domain_runtime_policy()
    checkpoint = domain.checkpoint(
        head_sequence=9,
        head_digest="4" * 64,
        state_binding_digest="5" * 64,
        runtime_policy=policy,
    )
    restored = DomainState(
        engine,
        evidence,
        required_acceptance=["G1", "G2", "human-release-decision"],
        provider_binding_digest=PROVIDER,
        implementation_closure_digest=IMPLEMENTATION,
    )
    restored.restore_checkpoint(
        checkpoint,
        expected_head_sequence=9,
        expected_head_digest="4" * 64,
        expected_state_binding_digest="5" * 64,
        parallelism_policy=policy,
    )
    assert restored.approval_status(
        CANDIDATE, evaluated_at="2026-02-01T00:08:00Z"
    ) == invalidated


def test_finding_disposition_requires_exact_binding_policy_expiry_and_sod(
    tmp_path: Path,
) -> None:
    engine, grants = issued_engine()
    evidence = EvidenceStore(tmp_path / "finding-cas")
    domain = DomainState(
        engine,
        evidence,
        provider_binding_digest=PROVIDER,
        implementation_closure_digest=IMPLEMENTATION,
    )
    candidate = {
        "record_type": "Candidate",
        "candidate_id": "C-finding",
        "candidate_digest": CANDIDATE,
        "inventory_digest": "1" * 64,
        "product_root_digest": "2" * 64,
        "control_excluded": True,
        "candidate_recipe_digest": "5" * 64,
        "consistency_mode": "immutable-vcs-tree",
        "creditable": True,
        "snapshot_provider_id": "test-vcs-provider",
        "snapshot_digest": "6" * 64,
    }
    domain.record_candidate(candidate, authorization(grants["worker"]))
    observed = finalized_evidence(
        evidence,
        artifact_id="E-finding-observed",
        payload=b"finding observation",
        media_type="text/plain",
        retention_class="audit",
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        created_at="2026-02-01T00:01:00Z",
        activation_digest=ACTIVATION,
        outcome="fail",
    )
    finding = {
        "record_type": "Finding",
        "finding_id": "F-waiver",
        "status": "OPEN",
        "severity": "P1",
        "blocking": True,
        "statement": "specific exception requires independent disposition",
        "activation_digest": ACTIVATION,
        "candidate_digest": CANDIDATE,
        "evidence_artifacts": [evidence_reference(evidence, observed)],
        "created_at": "2026-02-01T00:01:00Z",
    }
    domain.record_finding(
        finding, authorization(grants["finder"], at="2026-02-01T00:01:00Z")
    )
    finding_digest = canonical_digest(finding)
    unrelated = finalized_evidence(
        evidence,
        artifact_id="E-unrelated-pass",
        payload=b"passing evidence for another fact",
        media_type="application/json",
        retention_class="audit",
        candidate_digest=CANDIDATE,
        policy_digest=POLICY,
        tool_digest=TOOL,
        input_digests=[INPUT],
        created_at="2026-02-01T00:02:00Z",
        activation_digest=ACTIVATION,
        outcome="pass",
    )
    unrelated_task = task_with_gate_definitions(
        {
            "record_type": "Task",
            "task_id": "T-unrelated-finding-gate",
            "state": "PLANNED",
            "required_capability": "validation.evaluate",
            "acceptance_predicate": "unrelated candidate validation",
            "allowed_paths": ["src"],
            "activation_digest": ACTIVATION,
            "candidate_digest": CANDIDATE,
            "created_at": "2026-02-01T00:02:00Z",
        },
        {"gate_id": "finding-unrelated"},
    )
    domain.record_task(
        unrelated_task,
        authorization(grants["planner"], at="2026-02-01T00:02:00Z"),
    )
    domain.record_gate_result(
        gate_result_for(
            unrelated_task,
            "finding-unrelated",
            "R-finding-unrelated",
            [evidence_reference(evidence, unrelated)],
        ),
        authorization(
            grants["validator"],
            at="2026-02-01T00:02:00Z",
            scope=unrelated_task["gate_run_definitions"][0]["definition"][
                "target_scope"
            ],
        ),
        run_record=gate_run_for(
            unrelated_task, "finding-unrelated", "R-finding-unrelated"
        ),
    )
    with pytest.raises(DomainError, match="exact credited gate provenance"):
        domain.record_decision(
            exact_decision(
                decision_id="D-unrelated-resolve",
                decision_kind="resolve",
                grant=grants["resolver"],
                target_type="Finding",
                target=finding,
                finding_digest=finding_digest,
                rationale="this must not use unrelated passing evidence",
                evidence_artifacts=[evidence_reference(evidence, unrelated)],
                created_at="2026-02-01T00:03:00Z",
            ),
            authorization(grants["resolver"], at="2026-02-01T00:03:00Z"),
        )

    exception_policy = "7" * 64
    bound = finalized_evidence(
        evidence,
        artifact_id="E-waiver-bound",
        payload=b"independent finding-specific exception evaluation",
        media_type="application/json",
        retention_class="audit",
        candidate_digest=CANDIDATE,
        policy_digest=exception_policy,
        tool_digest=TOOL,
        input_digests=[INPUT],
        created_at="2026-02-01T00:03:00Z",
        activation_digest=ACTIVATION,
        outcome="pass",
        finding_digest=finding_digest,
    )
    bound_task = task_with_gate_definitions(
        {
            "record_type": "Task",
            "task_id": "T-waiver-bound",
            "state": "PLANNED",
            "required_capability": "validation.evaluate",
            "acceptance_predicate": "exact Finding exception gate",
            "allowed_paths": ["src"],
            "activation_digest": ACTIVATION,
            "candidate_digest": CANDIDATE,
            "created_at": "2026-02-01T00:03:00Z",
        },
        {
            "gate_id": "finding-waiver-F",
            "target_kind": "finding",
            "target_digest": finding_digest,
            "target_scope": [
                {"kind": "finding", "value": "F-waiver"},
            ],
            "policy_digest": exception_policy,
        },
    )
    domain.record_task(
        bound_task,
        authorization(grants["planner"], at="2026-02-01T00:03:00Z"),
    )
    domain.record_gate_result(
        gate_result_for(
            bound_task,
            "finding-waiver-F",
            "R-finding-waiver",
            [evidence_reference(evidence, bound)],
        ),
        authorization(
            grants["validator"],
            at="2026-02-01T00:03:00Z",
            scope=bound_task["gate_run_definitions"][0]["definition"][
                "target_scope"
            ],
        ),
        run_record=gate_run_for(
            bound_task, "finding-waiver-F", "R-finding-waiver"
        ),
    )
    finder_waiver_grant = make_grant(
        engine.authority_init,
        "g-finder-waiver",
        "finder",
        "finding.waive",
        issuer=grants["root"],
        issued_at="2026-02-01T00:03:30Z",
        nonce="nonce-g-finder-waiver-00000000",
    )
    with pytest.raises(
        AuthorityError, match="finding separation-of-duties Grant conflict"
    ):
        persist_grant(
            engine,
            engine.authority_init,
            finder_waiver_grant,
            issuer=grants["root"],
        )
    waiver = exact_decision(
        decision_id="D-waiver",
        decision_kind="waive",
        grant=grants["waiver"],
        target_type="Finding",
        target=finding,
        finding_digest=finding_digest,
        exception_policy_digest=exception_policy,
        expires_at="2026-03-01T00:00:00Z",
        rationale="time-bounded exception approved independently",
        evidence_artifacts=[evidence_reference(evidence, bound)],
        created_at="2026-02-01T00:04:00Z",
    )
    validate_definition(core_schema(), "Decision", waiver)
    domain.record_decision(
        waiver,
        authorization(grants["waiver"], at="2026-02-01T00:04:00Z"),
    )
    assert domain.findings["F-waiver"]["status"] == "WAIVED"
    assert domain.findings["F-waiver"]["blocking"] is False
    assert domain._finding_block_state(
        domain.findings["F-waiver"], "2026-02-28T23:59:59Z"
    ) == (False, None)
    assert domain._finding_block_state(
        domain.findings["F-waiver"], "2026-03-01T00:00:00Z"
    ) == (True, "waiver-expired")


def test_candidate_delta_scope_and_domain_checkpoint(tmp_path: Path) -> None:
    engine, grants = issued_engine()
    evidence = EvidenceStore(tmp_path / "delta-cas")
    domain = DomainState(
        engine,
        evidence,
        provider_binding_digest=PROVIDER,
        implementation_closure_digest=IMPLEMENTATION,
    )
    scoped_grant = make_grant(
        engine.authority_init,
        "g-worker-src",
        "worker",
        "task.execute",
        issuer=grants["root"],
        scope=[{"kind": "path", "value": "src"}],
        nonce="nonce-g-worker-src-00000000000",
    )
    persist_grant(
        engine,
        engine.authority_init,
        scoped_grant,
        issuer=grants["root"],
    )
    new_candidate_digest = "b" * 64
    for candidate in (
        {
            "record_type": "Candidate",
            "candidate_id": "C-base",
            "candidate_digest": CANDIDATE,
            "inventory_digest": "1" * 64,
            "product_root_digest": "2" * 64,
            "control_excluded": True,
            "candidate_recipe_digest": "5" * 64,
            "consistency_mode": "immutable-vcs-tree",
            "creditable": True,
            "snapshot_provider_id": "test-vcs-provider",
            "snapshot_digest": "6" * 64,
        },
        {
            "record_type": "Candidate",
            "candidate_id": "C-new",
            "candidate_digest": new_candidate_digest,
            "inventory_digest": "3" * 64,
            "product_root_digest": "4" * 64,
            "control_excluded": True,
            "candidate_recipe_digest": "5" * 64,
            "consistency_mode": "immutable-vcs-tree",
            "creditable": True,
            "snapshot_provider_id": "test-vcs-provider",
            "snapshot_digest": "7" * 64,
        },
    ):
        domain.record_candidate(candidate, authorization(grants["worker"]))
    task = task_with_gate_definitions(
        {
            "record_type": "Task",
            "task_id": "T-delta",
            "state": "PLANNED",
            "required_capability": "task.execute",
            "acceptance_predicate": "exact Candidate delta remains in scope",
            "allowed_paths": ["src", "docs"],
            "activation_digest": ACTIVATION,
            "candidate_digest": CANDIDATE,
            "created_at": "2026-02-01T00:00:00Z",
        },
        {"gate_id": "candidate-delta-integrity"},
    )
    domain.record_task(task, authorization(grants["planner"]))
    workcard = {
        "record_type": "WorkCard",
        "task_id": "T-delta",
        "operation_mode": "mutate",
        "operation": "artifact.record",
        "acceptance_predicate": task["acceptance_predicate"],
        "allowed_paths": task["allowed_paths"],
        "holder_grant_id": scoped_grant["grant_id"],
        "candidate_digest": CANDIDATE,
        "activation_digest": ACTIVATION,
        "context_digest": "6" * 64,
        "query_grant_id": grants["reader"]["grant_id"],
        "query_grant_claim_digest": grants["reader"]["claim_digest"],
        "stop_conditions": ["scope-exhausted"],
        "budget": {
            "max_bytes": 4096,
            "max_entities": 8,
            "max_relations": 8,
            "max_fanout_per_entity": 4,
            "top_k": 4,
        },
        "truncated": False,
        "lease_id": "L-delta",
        "lease_generation": 1,
        "fencing_token": 1,
    }
    validate_definition(core_schema(), "WorkCard", workcard)
    workcard_digest = canonical_digest(workcard)
    scoped_authorization = authorization(
        scoped_grant,
        at="2026-02-01T00:01:00Z",
        scope=[
            {"kind": "candidate", "value": "C-new"},
            {"kind": "path", "value": "src"},
        ],
    )
    valid_delta = finalized_delta(
        evidence,
        artifact_id="A-delta-valid",
        payload=b'{"changed":["src/main.cpp"]}',
        base_candidate_digest=CANDIDATE,
        new_candidate_digest=new_candidate_digest,
        workcard_digest=workcard_digest,
        changed_paths=["src/main.cpp"],
    )
    validate_definition(core_schema(), "Artifact", valid_delta)
    assert domain.validate_candidate_delta(
        valid_delta["digest"],
        task_id="T-delta",
        workcard=workcard,
        authorization=scoped_authorization,
    )["artifact_id"] == "A-delta-valid"

    task_escape = finalized_delta(
        evidence,
        artifact_id="A-delta-task-escape",
        payload=b'{"changed":["build/secret.bin"]}',
        base_candidate_digest=CANDIDATE,
        new_candidate_digest=new_candidate_digest,
        workcard_digest=workcard_digest,
        changed_paths=["build/secret.bin"],
    )
    with pytest.raises(DomainError, match="Task/WorkCard allowed_paths"):
        domain.validate_candidate_delta(
            task_escape["digest"],
            task_id="T-delta",
            workcard=workcard,
            authorization=scoped_authorization,
        )
    grant_escape = finalized_delta(
        evidence,
        artifact_id="A-delta-grant-escape",
        payload=b'{"changed":["docs/audit.md"]}',
        base_candidate_digest=CANDIDATE,
        new_candidate_digest=new_candidate_digest,
        workcard_digest=workcard_digest,
        changed_paths=["docs/audit.md"],
    )
    with pytest.raises(DomainError, match="Grant path scope"):
        domain.validate_candidate_delta(
            grant_escape["digest"],
            task_id="T-delta",
            workcard=workcard,
            authorization=authorization(
                scoped_grant,
                at="2026-02-01T00:02:00Z",
                scope=[
                    {"kind": "candidate", "value": "C-new"},
                    {"kind": "path", "value": "src"},
                ],
            ),
        )

    head_digest = "5" * 64
    policy = domain_runtime_policy()
    checkpoint = domain.checkpoint(
        head_sequence=7,
        head_digest=head_digest,
        state_binding_digest="6" * 64,
        runtime_policy=policy,
    )
    restored = DomainState(
        engine,
        evidence,
        provider_binding_digest=PROVIDER,
        implementation_closure_digest=IMPLEMENTATION,
    )
    result = restored.restore_checkpoint(
        checkpoint,
        expected_head_sequence=7,
        expected_head_digest=head_digest,
        expected_state_binding_digest="6" * 64,
        parallelism_policy=policy,
    )
    assert result["status"] == "restored-nonauthoritative-cache"
    assert result["authoritative"] is False
    assert restored.persistent_records() == domain.persistent_records()
    assert restored.checkpoint(
        head_sequence=7,
        head_digest=head_digest,
        state_binding_digest="6" * 64,
        runtime_policy=policy,
    ) == checkpoint
    with pytest.raises(DomainError, match="journal binding mismatch"):
        restored.restore_checkpoint(
            checkpoint,
            expected_head_sequence=7,
            expected_head_digest="0" * 64,
            expected_state_binding_digest="6" * 64,
            parallelism_policy=policy,
        )
    tampered = json.loads(json.dumps(checkpoint))
    tampered["tasks"][0]["state"] = "COMPLETED"
    with pytest.raises(DomainError, match="checkpoint digest mismatch"):
        restored.restore_checkpoint(
            tampered,
            expected_head_sequence=7,
            expected_head_digest=head_digest,
            expected_state_binding_digest="6" * 64,
            parallelism_policy=policy,
        )


def test_domain_transaction_overlay_isolated_and_reports_compaction(
    tmp_path: Path,
) -> None:
    engine, grants = issued_engine()
    domain = DomainState(
        engine,
        EvidenceStore(tmp_path / "domain-overlay-cas"),
        implementation_closure_digest=IMPLEMENTATION,
    )
    base_candidate = {
        "record_type": "Candidate",
        "candidate_id": "C-overlay-base",
        "candidate_digest": CANDIDATE,
        "inventory_digest": "1" * 64,
        "product_root_digest": "2" * 64,
        "control_excluded": True,
        "candidate_recipe_digest": "5" * 64,
        "consistency_mode": "immutable-vcs-tree",
        "creditable": True,
        "snapshot_provider_id": "test-vcs-provider",
        "snapshot_digest": "6" * 64,
    }
    domain.record_candidate(base_candidate, authorization(grants["worker"]))
    authority_base = engine.freeze(runtime_overlay_compaction_depth=2).snapshot
    domain_base_result = domain.freeze(runtime_overlay_compaction_depth=2)
    base = domain_base_result.snapshot
    assert domain_base_result.changed_leaf_count == 0
    assert domain_base_result.compacted is False
    exposed = base.candidates["C-overlay-base"]
    exposed["creditable"] = False
    assert base.candidates["C-overlay-base"]["creditable"] is True
    with pytest.raises(DomainError, match="immutable"):
        base.record_candidate(base_candidate, authorization(grants["worker"]))

    authority_child = authority_base.fork()
    child = base.fork(authority=authority_child)
    child_candidate = dict(
        base_candidate,
        candidate_id="C-overlay-child",
        candidate_digest="b" * 64,
        inventory_digest="3" * 64,
        product_root_digest="4" * 64,
        snapshot_digest="7" * 64,
    )
    child.record_candidate(child_candidate, authorization(grants["worker"]))
    assert "C-overlay-child" not in base.candidates
    assert child.changed_persistent_records() == [
        {
            "leaf_type": "Candidate",
            "value": child_candidate,
        }
    ]
    persistent = child.persistent_records()
    assert all(item["leaf_type"] == "Candidate" for item in persistent)
    assert {
        item["value"]["candidate_id"]: item["value"] for item in persistent
    } == {
        "C-overlay-base": base_candidate,
        "C-overlay-child": child_candidate,
    }
    authority_child_result = authority_child.freeze(
        runtime_overlay_compaction_depth=2
    )
    child_result = child.freeze(runtime_overlay_compaction_depth=2)
    assert child_result.changed_leaf_count == 1
    assert child_result.compacted is False
    assert child.freeze(runtime_overlay_compaction_depth=2) is child_result

    authority_grandchild = authority_child_result.snapshot.fork()
    grandchild = child_result.snapshot.fork(authority=authority_grandchild)
    grandchild_candidate = dict(
        base_candidate,
        candidate_id="C-overlay-grandchild",
        candidate_digest="d" * 64,
        inventory_digest="8" * 64,
        product_root_digest="9" * 64,
        snapshot_digest="a" * 64,
    )
    grandchild.record_candidate(
        grandchild_candidate,
        authorization(grants["worker"]),
    )
    authority_grandchild.freeze(runtime_overlay_compaction_depth=2)
    grandchild_result = grandchild.freeze(runtime_overlay_compaction_depth=2)
    assert grandchild_result.changed_leaf_count == 1
    assert grandchild_result.compacted is True
    assert grandchild_result.compacted_record_count == 3
    assert grandchild_result.compacted_payload_bytes > 0
    assert "C-overlay-grandchild" not in child_result.snapshot.candidates
