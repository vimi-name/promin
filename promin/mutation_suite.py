from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import zipfile
from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping


ZERO = "0" * 64
ONE = "1" * 64
NOW = "2026-07-17T12:00:00Z"
IMPLEMENTATION_CLOSURE_DIGEST = "9" * 64


class MutationSuiteError(RuntimeError):
    """Raised when a declared mutation is not rejected at its production boundary."""


class ExplicitNonCredit(RuntimeError):
    """Records a production fail-closed status for mutations that do not throw."""


def _require_noncredit(condition: bool, message: str) -> None:
    if condition:
        raise ExplicitNonCredit(message)
    raise MutationSuiteError(f"mutation unexpectedly received pass credit: {message}")


def _load_tool(package_root: Path, module_name: str):
    if module_name == "promin_package" and "promin_validate" not in sys.modules:
        _load_tool(package_root, "promin_validate")
    path = package_root / "tools" / f"{module_name}.py"
    if not path.is_file() or path.is_symlink():
        raise MutationSuiteError(f"production package tool is unavailable: {module_name}")
    qualified = f"_promin_mutation_{module_name}"
    spec = importlib.util.spec_from_file_location(qualified, path)
    if spec is None or spec.loader is None:
        raise MutationSuiteError(f"cannot load production package tool: {module_name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[qualified] = module
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _task(task_id: str = "task:mutation") -> dict[str, Any]:
    from .canonical import digest_value

    task = {
        "record_type": "Task",
        "task_id": task_id,
        "state": "PLANNED",
        "required_capability": "task.execute",
        "acceptance_predicate": "mutation rejection",
        "allowed_paths": ["product/**"],
        "activation_digest": ZERO,
        "candidate_digest": ONE,
        "created_at": NOW,
    }
    definition = {
        "definition_kind": "GateRunDefinition",
        "definition_id": "definition:mutation",
        "owner_kind": "Task",
        "owner_digest": digest_value(
            {key: value for key, value in task.items() if key != "state"}
        ),
        "defined_at_head_digest": ZERO,
        "gate_id": "gate:mutation",
        "run_kind": "validation",
        "expected_evidence_class": "validator",
        "expected_evidence_purpose": "gate",
        "product_credit_required": False,
        "target_kind": "candidate",
        "target_digest": ONE,
        "target_scope": [{"kind": "candidate", "value": ONE}],
        "candidate_digest": ONE,
        "policy_digest": ZERO,
        "tool_digest": ZERO,
        "implementation_closure_digest": IMPLEMENTATION_CLOSURE_DIGEST,
        "provider_binding_digest": digest_value([]),
        "input_digests": [],
        "activation_digest": ZERO,
    }
    task["gate_run_definitions"] = [
        {
            "definition_digest": digest_value(definition),
            "definition": definition,
        }
    ]
    return task


def _gate() -> dict[str, Any]:
    return {
        "record_type": "GateResult",
        "gate_id": "gate:mutation",
        "run_id": "run:mutation",
        "run_digest": "4" * 64,
        "task_id": "task:mutation",
        "definition_digest": "5" * 64,
        "status": "fail",
        "outcome": "fail",
        "pass_credit": False,
        "activation_digest": ZERO,
        "candidate_digest": ONE,
        "policy_digest": ZERO,
        "tool_digest": ZERO,
        "evidence_artifacts": [
            {
                "artifact_id": "artifact:mutation",
                "artifact_record_digest": ONE,
                "run_id": "run:mutation",
                "run_digest": "4" * 64,
            }
        ],
        "evidence_class": "validator",
    }


def _evidence_artifact() -> dict[str, Any]:
    return {
        "record_type": "Artifact",
        "artifact_id": "artifact:mutation",
        "artifact_kind": "evidence",
        "digest": ONE,
        "media_type": "application/json",
        "size_bytes": 1,
        "retention_class": "audit",
        "created_at": NOW,
        "evidence_binding": {
            "activation_digest": ZERO,
            "candidate_digest": ONE,
            "policy_digest": "2" * 64,
            "tool_digest": "3" * 64,
            "input_digests": ["4" * 64],
            "implementation_closure_digest": IMPLEMENTATION_CLOSURE_DIGEST,
            "provider_invocations": [
                {
                    "capability_id": "control-runtime",
                    "provider_id": "provider:mutation",
                    "invocation_kind": "python-runtime",
                    "identity_kind": "file-digest",
                    "identity_digest": "5" * 64,
                    "adapter_id": "python-runtime-adapter",
                    "implementation_closure_digest": IMPLEMENTATION_CLOSURE_DIGEST,
                }
            ],
        },
        "outcome": "pass",
        "stale": False,
        "unresolved": False,
        "evidence_class": "validator",
        "evidence_purpose": "gate",
        "product_credit_eligible": False,
    }


def _finalize_evidence(store: Any, events: Any) -> dict[str, Any]:
    from .canonical import digest_value, load_json_strict
    from .events import command_intent_identity

    payload = b"evidence"
    artifact = _evidence_artifact()
    artifact["artifact_id"] = "evidence:1"
    artifact["digest"] = hashlib.sha256(payload).hexdigest()
    artifact["size_bytes"] = len(payload)
    command = {
        "record_type": "CommandRequest",
        "command_id": "command:evidence:1",
        "command_kind": "artifact.record",
        "subject_id": "worker",
        "activation_digest": ZERO,
        "idempotency_key": "evidence-mutation-0001",
        "requested_scope": [{"kind": "all", "value": "*"}],
        "expected_head_digest": None,
        "issued_at": NOW,
        "payload": artifact,
        "intent_digest": ZERO,
        "authorization": {
            "kind": "grant",
            "grant_id": "grant:evidence-publisher",
            "grant_claim_digest": "5" * 64,
        },
        "holder_authorization": {
            "kind": "grant",
            "grant_id": "grant:worker",
            "grant_claim_digest": "6" * 64,
        },
        "workcard_task_id": "task:evidence:1",
        "lease_id": "lease:evidence:1",
        "lease_generation": 1,
        "fencing_token": 1,
        "workcard_digest": "7" * 64,
        "context_digest": "8" * 64,
    }
    command["intent_digest"] = digest_value(command_intent_identity(command))
    command_digest = digest_value(command)
    store.stage(artifact, payload, command_digest=command_digest)
    events.commit(command, created_at=NOW)
    envelope_path = next(events.journal.glob("*.json"))
    envelope = load_json_strict(envelope_path, root=events.journal)
    store.finalize(
        artifact,
        command_digest=command_digest,
        envelope=envelope,
    )
    store.reconcile(events.iter_envelopes())
    return artifact


def _finalize_delta(
    store: Any,
    *,
    base_candidate_digest: str,
    new_candidate_digest: str,
    workcard_digest: str,
    changed_paths: list[str],
) -> dict[str, Any]:
    from .authority import canonical_digest

    payload = json.dumps(
        {"changed_paths": changed_paths},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    artifact = {
        "record_type": "Artifact",
        "artifact_id": "artifact:delta:escape",
        "artifact_kind": "diff",
        "digest": hashlib.sha256(payload).hexdigest(),
        "media_type": "application/json",
        "size_bytes": len(payload),
        "retention_class": "audit",
        "created_at": NOW,
        "candidate_delta": {
            "base_candidate_digest": base_candidate_digest,
            "new_candidate_digest": new_candidate_digest,
            "workcard_digest": workcard_digest,
            "changed_paths": changed_paths,
        },
    }
    command = {
        "record_type": "CommandRequest",
        "command_id": "command:delta:escape",
        "command_kind": "artifact.record",
        "subject_id": "worker",
        "activation_digest": ZERO,
        "idempotency_key": "delta-escape-mutation-0001",
        "expected_head_digest": None,
        "issued_at": NOW,
        "requested_scope": [
            {"kind": "artifact", "value": artifact["artifact_id"]}
        ],
        "payload": artifact,
        "intent_digest": ONE,
        "authorization": {
            "kind": "grant",
            "grant_id": "grant:worker",
            "grant_claim_digest": "2" * 64,
        },
    }
    command_digest = canonical_digest(command)
    event = {
        "record_type": "Event",
        "event_id": "event:delta:escape",
        "event_kind": "artifact.recorded",
        "activation_digest": ZERO,
        "payload": artifact,
    }
    batch = {
        "record_type": "EventBatch",
        "batch_id": "batch:delta:escape",
        "sequence": 1,
        "previous_digest": None,
        "created_at": NOW,
        "command_id": command["command_id"],
        "idempotency_key": command["idempotency_key"],
        "activation_record_digest": ZERO,
        "events": [event],
        "subject_id": command["subject_id"],
        "command_intent_digest": command["intent_digest"],
        "command_digest": command_digest,
        "authorization_digest": canonical_digest(command["authorization"]),
    }
    envelope = {"record_type": "JournalEnvelope", "command": command, "batch": batch}
    store.stage(artifact, payload, command_digest=command_digest)
    store.finalize(artifact, command_digest=command_digest, envelope=envelope)
    store.reconcile([envelope])
    return artifact


def _workcard(holder_grant_id: str = "grant:worker") -> dict[str, Any]:
    return {
        "record_type": "WorkCard",
        "task_id": "task:lease",
        "operation_mode": "mutate",
        "operation": "task.transition",
        "acceptance_predicate": "mutation rejection",
        "allowed_paths": ["product/**"],
        "holder_grant_id": holder_grant_id,
        "candidate_digest": ONE,
        "activation_digest": ZERO,
        "context_digest": "2" * 64,
        "stop_conditions": ["mutation rejected"],
        "budget": {
            "max_bytes": 1024,
            "max_entities": 1,
            "max_relations": 1,
            "max_fanout_per_entity": 1,
            "top_k": 1,
        },
        "truncated": False,
        "lease_id": "lease:1",
        "lease_generation": 1,
        "fencing_token": 1,
    }


def _decision() -> dict[str, Any]:
    return {
        "record_type": "Decision",
        "decision_id": "decision:mutation",
        "decision_kind": "release",
        "subject_id": "approver",
        "grant_id": "grant:approver",
        "activation_digest": ZERO,
        "candidate_digest": ONE,
        "target_type": "Candidate",
        "target_id": "candidate:mutation",
        "rationale": "mutation rejection",
        "evidence_artifacts": [
            {
                "artifact_id": "artifact:decision",
                "artifact_record_digest": ONE,
            }
        ],
        "created_at": NOW,
        "release_closure_digest": "2" * 64,
        "provider_binding_digest": "3" * 64,
    }


def _candidate(
    *,
    consistency_mode: str = "observational-best-effort",
    creditable: bool = False,
    snapshot_provider_id: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "record_type": "Candidate",
        "candidate_id": "candidate:mutation",
        "candidate_digest": ONE,
        "inventory_digest": "2" * 64,
        "product_root_digest": "3" * 64,
        "candidate_recipe_digest": "4" * 64,
        "consistency_mode": consistency_mode,
        "creditable": creditable,
        "control_excluded": True,
    }
    if snapshot_provider_id is not None:
        value["snapshot_provider_id"] = snapshot_provider_id
        value["snapshot_digest"] = "5" * 64
    return value


def _candidate_recipe(
    *,
    consistency_mode: str = "observational-best-effort",
    snapshot_provider_id: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "inventory_mode": "explicit",
        "include": ["src/**"],
        "exclude": [".promin/**", "build/**", "docs/**"],
        "symlink_policy": "reject",
        "path_identity": "nfc-posix-relative",
        "collision_policy": "reject-nfc-and-casefold-collisions",
        "product_identity_excludes_control_state": True,
        "snapshot_consistency": consistency_mode,
    }
    if snapshot_provider_id is not None:
        value["snapshot_provider_id"] = snapshot_provider_id
    return value


def _authority_init(*, team: bool = False) -> dict[str, Any]:
    subjects = (
        ("root", "human"),
        ("planner", "agent"),
        ("worker", "agent"),
        ("manager", "service"),
        ("validator", "agent"),
        ("approver", "human"),
    )
    value: dict[str, Any] = {
        "record_type": "AuthorityInit",
        "trust_mode": "team-signed" if team else "local-owner",
        "subjects": [
            {"subject_id": subject, "kind": kind, "display_name": subject.title()}
            for subject, kind in subjects
        ],
        "roots": [
            {
                "subject_id": "root",
                "capability_ceiling": [
                    "standard.activate", "authority.manage", "task.plan",
                    "task.execute", "lease.manage", "evidence.publish",
                    "validation.evaluate", "finding.record", "finding.resolve",
                    "finding.waive", "candidate.promote", "release.decide",
                    "export.create", "migration.manage", "projection.rebuild",
                ],
                "scope": [{"kind": "all", "value": "*"}],
            }
        ],
    }
    if team:
        value["keys"] = [
            {
                "key_id": "key-root",
                "subject_id": "root",
                "algorithm": "test-ed25519-boundary",
                "public_key": "test-key",
                "fingerprint": "9" * 64,
            }
        ]
        value["team_policy"] = {
            "threshold": 1,
            "key_ids": ["key-root"],
            "signature_provider_capability": "signature",
        }
    return value


def _grant(
    authority_init: Mapping[str, Any],
    grant_id: str,
    subject: str,
    capability: str,
    *,
    issuer: Mapping[str, Any] | None = None,
    scope: list[dict[str, str]] | None = None,
    expires_at: str = "2028-01-01T00:00:00Z",
    nonce: str | None = None,
) -> dict[str, Any]:
    from .authority import canonical_digest, grant_claim_identity

    value: dict[str, Any] = {
        "record_type": "Grant",
        "grant_id": grant_id,
        "subject_id": subject,
        "capability_id": capability,
        "scope": scope or [{"kind": "all", "value": "*"}],
        "activation_digest": ZERO,
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": expires_at,
        "nonce": nonce or f"nonce-{grant_id}-00000000",
    }
    value["claim_digest"] = canonical_digest(grant_claim_identity(value))
    if issuer is None:
        proof = {
            "kind": "local-root",
            "root_subject_id": "root",
            "authority_init_digest": canonical_digest(authority_init),
            "signed_claim_digest": value["claim_digest"],
        }
    else:
        proof = {
            "kind": "issuer-grant",
            "issuer_grant_id": issuer["grant_id"],
            "issuer_signed_claim_digest": issuer["claim_digest"],
            "signed_claim_digest": value["claim_digest"],
        }
    value["trust_proofs"] = [proof]
    return value


def _authority_runtime_policy() -> dict[str, Any]:
    from .canonical import digest_value

    model = json.loads(
        (Path(__file__).resolve().parents[1] / "core" / "authority-model.json").read_text(
            encoding="utf-8"
        )
    )
    capability_ids = [item["id"] for item in model["capabilities"]]
    identity = {
        "record_type": "AuthorityRuntimePolicy",
        "authority_model_digest": digest_value(model),
        "capability_ids": capability_ids,
        "separation_of_duties": deepcopy(model["separation_of_duties"]),
        "separation_of_duties_capability_ids": [
            *capability_ids,
            *model["separation_of_duties_contract"]["external_capability_ids"],
        ],
        "separation_of_duties_contract": deepcopy(
            model["separation_of_duties_contract"]
        ),
        "delegation_depth_max": model["delegation_depth_max"],
        "scope_contract": deepcopy(model["scope_contract"]),
        "grant_contract": deepcopy(model["grant_contract"]),
        "canonical_timestamp_contract": deepcopy(
            model["canonical_timestamp_contract"]
        ),
    }
    return {**identity, "policy_digest": digest_value(identity)}


def _engine_with_grants():
    from .authority import AuthorityEngine

    authority_init = _authority_init()
    engine = AuthorityEngine(authority_init, ZERO, _authority_runtime_policy())
    root = _grant(authority_init, "grant:root", "root", "authority.manage")
    _persist_grant(engine, authority_init, root)
    grants = {"root": root}
    for name, subject, capability in (
        ("planner", "planner", "task.plan"),
        ("worker", "worker", "task.execute"),
        ("manager", "manager", "lease.manage"),
        ("validator", "validator", "validation.evaluate"),
        ("approver", "approver", "release.decide"),
    ):
        grant = _grant(
            authority_init,
            f"grant:{name}",
            subject,
            capability,
            issuer=root,
        )
        _persist_grant(engine, authority_init, grant, issuer=root)
        grants[name] = grant
    return engine, grants


def _grant_issue_command(
    authority_init: Mapping[str, Any],
    grant: Mapping[str, Any],
    *,
    issuer: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    from .authority import canonical_digest

    command: dict[str, Any] = {
        "record_type": "CommandRequest",
        "command_id": (
            f"command:bootstrap:{grant['grant_id']}"
            if issuer is None
            else f"command:issue:{grant['grant_id']}"
        ),
        "command_kind": "grant.issue",
        "subject_id": grant["subject_id"] if issuer is None else issuer["subject_id"],
        "activation_digest": ZERO,
        "idempotency_key": (
            f"bootstrap-{grant['grant_id']}-key"
            if issuer is None
            else f"issue-{grant['grant_id']}-key"
        ),
        "requested_scope": deepcopy(grant["scope"]),
        "expected_head_digest": None,
        "issued_at": grant["issued_at"],
        "payload": deepcopy(dict(grant)),
    }
    command["intent_digest"] = canonical_digest(command)
    if issuer is None:
        command["authorization"] = {
            "kind": "root",
            "subject_id": grant["subject_id"],
            "proofs": [
                {
                    "kind": "local-root-command",
                    "subject_id": grant["subject_id"],
                    "authority_init_digest": canonical_digest(authority_init),
                    "signed_intent_digest": command["intent_digest"],
                }
            ],
        }
    else:
        command["authorization"] = {
            "kind": "grant",
            "grant_id": issuer["grant_id"],
            "grant_claim_digest": issuer["claim_digest"],
        }
    return command


def _persist_grant(
    engine: Any,
    authority_init: Mapping[str, Any],
    grant: Mapping[str, Any],
    *,
    issuer: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    receipt = engine.authorize_grant_issue_command(
        _grant_issue_command(authority_init, grant, issuer=issuer)
    )
    return engine.issue_grant(
        grant,
        grant["issued_at"],
        issue_authorization=receipt,
    )


def _authorization(grant: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "subject_id": grant["subject_id"],
        "grant_id": grant["grant_id"],
        "claim_digest": grant["claim_digest"],
        "evaluated_at": "2026-02-01T00:00:00Z",
        "requested_scope": [{"kind": "all", "value": "*"}],
    }


def _command(index: int, expected_head: str | None = None, *, key: str | None = None):
    from .events import command_intent_identity, digest_value

    value: dict[str, Any] = {
        "record_type": "CommandRequest",
        "command_id": f"command:mutation:{index}",
        "command_kind": "task.record",
        "subject_id": "planner",
        "activation_digest": ZERO,
        "idempotency_key": key or f"mutation-idempotency-{index:04d}",
        "requested_scope": [{"kind": "task", "value": f"task:mutation:{index}"}],
        "expected_head_digest": expected_head,
        "issued_at": NOW,
        "payload": {
            "record_type": "Task",
            "task_id": f"task:mutation:{index}",
            "state": "PLANNED",
        },
        "intent_digest": ZERO,
        "authorization": {
            "kind": "grant",
            "grant_id": "grant:planner",
            "grant_claim_digest": ONE,
        },
    }
    value["intent_digest"] = digest_value(command_intent_identity(value))
    return value


def _write_json(path: Path, value: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


def _standard_candidate_binding(fixture: "MutationFixture") -> dict[str, Any]:
    from .authority import canonical_digest

    identity = {
        "record_type": "StandardReleaseCandidateBinding",
        "standard_name": "promin",
        "version": fixture.bundle.manifest["version"],
        "archive_sha256": "1" * 64,
        "archive_bytes": 1,
        "archive_member_manifest_digest": "2" * 64,
        "package_manifest_digest": "3" * 64,
        "checksums_digest": "4" * 64,
        "core_bundle_digest": fixture.bundle.bundle_digest,
        "preset_digest": fixture.bundle.preset_digest,
        "package_tool_digest": "5" * 64,
        "validator_digest": "6" * 64,
        "test_manifest_digest": "7" * 64,
        "portable_implementation_closure_digest": "8" * 64,
        "evidence_tool_digests": {
            "tools/generate_human.py": "9" * 64,
            "tools/promin_no_degradation.py": "a" * 64,
            "tools/promin_package.py": "b" * 64,
            "tools/promin_saturation.py": "c" * 64,
            "tools/promin_saturation_audit.py": "d" * 64,
            "tools/promin_validate.py": "e" * 64,
        },
    }
    return {**identity, "candidate_binding_digest": canonical_digest(identity)}


def _standard_evidence_manifest(
    fixture: "MutationFixture",
    candidate: Mapping[str, Any],
    *,
    physical: bool = False,
) -> tuple[Path, dict[str, Any]]:
    from .authority import canonical_digest
    from .canonical import digest_file

    roles: dict[str, tuple[str, dict[str, Any]]] = {
        "linux": ("PlatformVerificationResult", {"/platform": "linux", "/exact_candidate_verified": True}),
        "windows": ("PlatformVerificationResult", {"/platform": "windows", "/exact_candidate_verified": True}),
        "physical-scale": ("SaturationEvidence", {
            "/physical_files": 100_000,
            "/core_valid_relations": 198_999,
            "/core_valid_relations_exact_198999": True,
            "/runtime_queries": 600,
            "/silent_truncations": 0,
            "/selected_closure_union_completeness": 1,
            "/memory_amplification_at_most_32": True,
            "/broad_query_refinement_required": True,
            "/high_cardinality_terms_verified": True,
            "/content_search_verified": True,
            "/miss_behavior_verified": True,
            "/hostile_proxy_content_verified": True,
            "/exact_artifact_search_verified": True,
            "/mixed_query_classes_complete": True,
            "/continuation_token_bytes_at_most_256": True,
            "/continuation_state_bytes_at_most_16384": True,
            "/continuation_token_overhead_at_most_10_percent": True,
        }),
        "saturation-audit": ("SaturationAudit", {"/zero_new_iterations": 3, "/new_findings": 0}),
        "human-documents": ("HumanDocumentVerification", {
            "/deterministic_rebuild": True,
            "/visual_review_scope/completed": True,
            "/visual_review_scope/clipping_detected": False,
            "/visual_review_scope/unreadable_text_detected": False,
        }),
        "linux-no-degradation": ("NoDegradationResult", {"/platform": "linux", "/no_degradation": True}),
        "windows-no-degradation": ("NoDegradationResult", {"/platform": "windows", "/no_degradation": True}),
    }
    evidence_root = fixture.root / "standard-evidence"
    evidence_root.mkdir()
    entries: list[dict[str, Any]] = []
    for index, (role, (record_type, required_predicates)) in enumerate(roles.items(), 1):
        relative = f"records/{index:02d}.json"
        evidence = {
            "record_type": record_type,
            "status": "pass",
            "candidate_binding_digest": candidate["candidate_binding_digest"],
        }
        if role == "human-documents":
            human_paths = [
                "human/promin_appendices_en.pdf",
                "human/promin_appendices_ua.pdf",
                "human/promin_main_en.pdf",
                "human/promin_main_ua.pdf",
            ]
            documents = [
                {
                    "path": path,
                    "sha256": format(document_index, "x") * 64,
                    "size_bytes": 1024 + document_index,
                    "page_count": 1,
                    "extracted_characters": 100,
                    "blank_pages": [],
                    "extraction_errors": [],
                }
                for document_index, path in enumerate(human_paths, 10)
            ]
            rebuild_rows = [
                {
                    "path": document["path"],
                    "sha256": document["sha256"],
                    "size_bytes": document["size_bytes"],
                    "page_count": document["page_count"],
                }
                for document in documents
            ]
            evidence.update({
                "documents": documents,
                "deterministic_rebuild": True,
                "rebuild_digest": canonical_digest(
                    sorted(rebuild_rows, key=lambda row: row["path"].encode("utf-8"))
                ),
                "page_count": 4,
                "extraction_diagnostics": {
                    "documents_parsed": 4,
                    "total_extracted_characters": 400,
                    "blank_pages": [],
                    "errors": [],
                },
                "visual_review_scope": {
                    "completed": True,
                    "reviewer_id": "reviewer:mutation",
                    "reviewed_at": NOW,
                    "rendered_page_count": 4,
                    "pages_reviewed": 4,
                    "clipping_detected": False,
                    "unreadable_text_detected": False,
                },
                "product_acceptance_pass": False,
            })
        for pointer, expected in required_predicates.items():
            current = evidence
            parts = pointer.removeprefix("/").split("/")
            for part in parts[:-1]:
                current = current.setdefault(part, {})
            current[parts[-1]] = expected
        path = evidence_root / relative
        if physical:
            _write_json(path, evidence)
            sha256 = digest_file(path)
        else:
            sha256 = str(index) * 64
        entries.append({
            "evidence_id": f"evidence:{index}",
            "evidence_role": role,
            "path": relative,
            "sha256": sha256,
            "record_type": record_type,
            "status": "pass",
            "candidate_binding_digest": candidate["candidate_binding_digest"],
            "predicates": [
                {"pointer": pointer, "equals": expected}
                for pointer, expected in required_predicates.items()
            ],
        })
    identity = {
        "record_type": "StandardReleaseEvidenceManifest",
        "standard_name": "promin",
        "version": candidate["version"],
        "candidate_binding_digest": candidate["candidate_binding_digest"],
        "entries": entries,
        "max_evidence_completed_at": NOW,
    }
    return evidence_root, {
        **identity,
        "evidence_manifest_digest": canonical_digest(identity),
    }


def _standard_trust_and_decision(
    candidate: Mapping[str, Any],
    evidence_manifest: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    from .authority import canonical_digest

    trust = {
        "record_type": "StandardReleaseTrustConfiguration",
        "trust_root_id": "trust:mutation",
        "signature_provider_id": "cryptography-ed25519-v1",
        "algorithm": "Ed25519",
        "keys": [
            {
                "key_id": "key:configured",
                "subject_id": "decider:mutation",
                "capabilities": ["standard.distribute"],
                "evidence_roles": [],
                "platforms": [],
                "public_key": base64.b64encode(b"k" * 32).decode("ascii"),
                "not_before": "2026-01-01T00:00:00Z",
                "not_after": "2027-01-01T00:00:00Z",
                "revoked": False,
            }
        ],
    }
    identity = {
        "record_type": "StandardReleaseDecision",
        "decision_id": "decision:mutation",
        "standard_name": "promin",
        "version": candidate["version"],
        "candidate_binding_digest": candidate["candidate_binding_digest"],
        "evidence_manifest_digest": evidence_manifest["evidence_manifest_digest"],
        "outcome": "approve",
        "decider_id": "decider:mutation",
        "release_capability": "standard.distribute",
        "trust_root_id": trust["trust_root_id"],
        "signature_provider_id": trust["signature_provider_id"],
        "key_id": "key:configured",
        "nonce": base64.b64encode(b"n" * 16).decode("ascii"),
        "decided_at": "2026-07-17T12:00:01Z",
    }
    return trust, {
        **identity,
        "signed_claim_digest": canonical_digest(identity),
        "signature": base64.b64encode(b"s" * 64).decode("ascii"),
    }


class MutationFixture:
    def __init__(self, root: Path, package_root: Path) -> None:
        from .contracts import load_contract_bundle
        from .projection import compile_relation_domains

        if root.exists():
            if root.is_symlink() or any(root.iterdir()):
                raise MutationSuiteError("mutation fixture root must be empty and link-free")
        else:
            root.mkdir(parents=True)
        self.root = root.resolve(strict=True)
        self.package_root = package_root.resolve(strict=True)
        self.core_dir = self.package_root / "core"
        self.preset_path = self.package_root / "presets" / "semantic-standard.json"
        self.bundle = load_contract_bundle(self.package_root, self.preset_path)
        semantic = self.bundle.core["semantic-model.json"]
        self.relation_domains = compile_relation_domains(semantic)
        self.event_policy = self._event_store_policy()
        self.projection_limits = self._projection_limits()

    def _event_store_policy(self):
        from .canonical import digest_value
        from .events import EventStorePolicy

        authority = self.bundle.core["authority-model.json"]
        semantic = self.bundle.core["semantic-model.json"]
        event = authority["event_contract"]
        mutation = authority["command_mutation_claim_rule"]
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
            "max_requested_scope_items": authority["scope_contract"][
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
                for command_kind, event_kind in event[
                    "command_to_primary_event"
                ].items()
            ],
            "allowed_state_binding_leaf_types": [
                "Activation",
                *[item["kind"] for item in semantic["persistent_entities"]],
                "Relation",
            ],
            "state_binding_identity_rules": event["state_binding_identity_rules"],
            "state_binding_algorithm_contract": event[
                "state_binding_algorithm_contract"
            ],
            "state_binding_value_rules": event["state_binding_value_rules"],
            "canonical_timestamp_contract": authority[
                "canonical_timestamp_contract"
            ],
            "genesis_previous_authority_commitment": event[
                "genesis_previous_authority_commitment"
            ],
            "genesis_event_semantic_digest": event[
                "genesis_event_semantic_digest"
            ],
        }
        return EventStorePolicy.from_compiled(
            {**identity, "policy_digest": digest_value(identity)}
        )

    def _projection_limits(self):
        from .canonical import digest_value
        from .projection import ProjectionLimits

        authority = self.bundle.core["authority-model.json"]
        conformance = self.bundle.core["conformance.json"]
        policies = self.bundle.core["policy-set.json"]
        continuation = authority["continuation_access_rule"]
        scale = conformance["scale_contracts"]["workcard"]
        profile_id = "extended"
        profile = self.bundle.preset["profiles"][profile_id]
        identity = {
            "record_type": "ProjectionLimits",
            "token_version": continuation["token_version"],
            "ranking_algorithm_id": continuation["ranking_algorithm_id"],
            "traversal_algorithm_id": continuation["traversal_algorithm_id"],
            "dependency_depth_hard_max": conformance[
                "dependency_depth_hard_max"
            ],
            "continuation_ttl_seconds_max": continuation["ttl_seconds_max"],
            "selected_profile_id": profile_id,
            "selected_profile_digest": digest_value(profile),
            "persistent_entity_types": [
                item["kind"]
                for item in self.bundle.core["semantic-model.json"][
                    "persistent_entities"
                ]
            ],
            "default_budget": {
                "max_bytes": profile["max_context_bytes"],
                "max_entities": profile["max_entities"],
                "max_relations": profile["max_relations"],
                "max_fanout_per_entity": profile["max_fanout_per_entity"],
                "top_k": profile["top_k"],
            },
            "hard_budget": conformance["workcard_hard_ceiling"],
            "default_depth": profile["default_dependency_depth"],
            "depth_min": continuation["depth_min"],
            "depth_max": conformance["dependency_depth_hard_max"],
            "default_ttl_seconds": continuation["default_ttl_seconds"],
            "ttl_min_seconds": continuation["ttl_min_seconds"],
            "ttl_max_seconds": continuation["ttl_seconds_max"],
            "max_token_bytes": scale["continuation_token_bytes_max"],
            "max_continuation_state_bytes": scale[
                "continuation_state_bytes_max"
            ],
            "max_query_bytes": policies["derived_result_contracts"][
                "RetrievalPage"
            ]["query_bytes_max"],
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
            "required_resume_binding_fields": continuation[
                "required_resume_binding_fields"
            ],
        }
        return ProjectionLimits(
            **{
                **identity,
                "persistent_entity_types": tuple(
                    identity["persistent_entity_types"]
                ),
                "required_resume_binding_fields": tuple(
                    identity["required_resume_binding_fields"]
                ),
                "policy_digest": digest_value(identity),
            },
            event_store_policy=self.event_policy,
        )

    @staticmethod
    def _thaw(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {key: MutationFixture._thaw(item) for key, item in value.items()}
        if isinstance(value, (tuple, list)):
            return [MutationFixture._thaw(item) for item in value]
        return value

    def _event_store_options(self) -> dict[str, Any]:
        from .canonical import digest_value
        from .events import (
            CommitStateSnapshot,
            PreparedCommit,
            state_binding_leaf_id,
            state_binding_value_digest,
        )

        policy = self.event_policy

        def load_state(view: Any, envelopes: Any) -> Any:
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

        def prepare(_view: Any, frozen_command: Any, frozen_relations: Any) -> Any:
            command = self._thaw(frozen_command)
            relations = [self._thaw(value) for value in frozen_relations]
            payload = command["payload"]
            event_kind = policy.primary_events[command["command_kind"]]
            leaf_type = policy.state_binding_event_leaf_types[event_kind]
            value_rule = policy.state_binding_value_rules[leaf_type]
            if payload["record_type"] == value_rule["value_definition"]:
                value_digest = state_binding_value_digest(
                    policy,
                    leaf_type,
                    payload,
                    event_kind=event_kind,
                )
            else:
                value_digest = digest_value(payload)
            delta = [
                {
                    "leaf_type": leaf_type,
                    "leaf_id": state_binding_leaf_id(policy, leaf_type, payload),
                    "operation": "set",
                    "value_digest": value_digest,
                }
            ]
            delta.extend(
                {
                    "leaf_type": "Relation",
                    "leaf_id": relation["relation_id"],
                    "operation": "set",
                    "value_digest": digest_value(relation),
                }
                for relation in relations
            )
            delta.sort(key=lambda value: (value["leaf_type"], value["leaf_id"]))
            return PreparedCommit(tuple(relations), tuple(delta))

        return {
            "activation_record_digest": ZERO,
            "implementation_closure_digest": IMPLEMENTATION_CLOSURE_DIGEST,
            "policy": policy,
            "compiled_record_validator": lambda _definition, _value, **_kwargs: True,
            "command_validator": lambda _value, **_kwargs: True,
            "authorization_validator": lambda _value, **_kwargs: True,
            "event_validator": lambda _value, **_kwargs: True,
            "commit_state_loader": load_state,
            "commit_prepare_callback": prepare,
            "derived_state_validator": lambda _name, _state, **_kwargs: True,
        }

    def event_store(self, name: str = "events"):
        from .events import EventStore

        return EventStore(
            self.root / name,
            ZERO,
            **self._event_store_options(),
        )

    def projection(self, name: str = "projection.sqlite3"):
        from .projection import Projection

        return Projection(
            self.root / name,
            b"m" * 32,
            implementation_closure_digest=IMPLEMENTATION_CLOSURE_DIGEST,
            limits=self.projection_limits,
            relation_domains=self.relation_domains,
        )

    def projection_row(
        self,
        index: int = 1,
        *,
        dangling: bool = False,
        wrong_domain: bool = False,
    ) -> dict[str, Any]:
        path = f"product/{index:04d}.txt"
        expected_id = "artifact:file:" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:48]
        return {
            "record_type": "InventoryProjectionRow",
            "path": path,
            "digest": hashlib.sha256(f"payload-{index}".encode("ascii")).hexdigest(),
            "size": len(f"payload-{index}"),
            "semantic_proxy": {
                "id": "artifact:wrong" if dangling else expected_id,
                "entity_type": "Task" if wrong_domain else "Artifact",
                "payload": {
                    "record_type": "Artifact",
                    "label": "needle",
                },
            },
        }

    @staticmethod
    def verified_inventory(*rows: Mapping[str, Any]):
        from .canonical import canonical_bytes
        from .projection import VerifiedInventoryInput

        stream = hashlib.sha256()
        for row in rows:
            stream.update(
                canonical_bytes(
                    {
                        "path": row["path"],
                        "digest": row["digest"],
                        "size": row["size"],
                    }
                )
            )
        return VerifiedInventoryInput(
            activation_digest=ZERO,
            stream_digest=stream.hexdigest(),
            entry_count=len(rows),
            entries=tuple(rows),
        )

    @staticmethod
    def relation() -> dict[str, Any]:
        return {
            "record_type": "Relation",
            "relation_id": "relation:projection",
            "kind": "READS",
            "source_type": "Task",
            "source_id": "task:projection",
            "target_type": "Artifact",
            "target_id": "artifact:projection",
            "activation_digest": ZERO,
            "created_at": NOW,
        }

    def init_request(self):
        from .canonical import digest_file
        from .init import (
            InitRequest,
            bind_implementation_closures,
            build_provider_dependency_receipt,
        )

        project = self.root / "product"
        project.mkdir()
        provider_executable = Path(
            getattr(sys, "_base_executable", sys.executable)
        ).resolve()
        # A copied CPython launcher on Windows is not a runnable provider: its
        # adjacent DLL/runtime neighbourhood is part of the host installation.
        # Keep the fixture's identity bound to that real source so receipt
        # verification can exercise the documented Windows fallback instead of
        # fabricating an executable healthcheck failure.
        if sys.platform == "win32":
            provider = provider_executable
        else:
            provider = project / provider_executable.name
            shutil.copy2(provider_executable, provider)
            provider.chmod(provider.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        license_value = {
            "expression": "Python-2.0",
            "source_uris": ["https://docs.python.org/3/license.html"],
            "review_state": "source-verified",
        }
        capabilities = list(self.bundle.preset["required_provider_capabilities"])
        bindings = [
            {
                "capability_id": capability,
                "provider_id": f"provider-{index}",
                "version": sys.version.split()[0],
                "invocation": {"kind": "python-runtime", "value": str(provider)},
                "purpose": capability,
                "required": True,
                "healthcheck": {
                    "argv": [str(provider), "--version"],
                    "timeout_ms": 10000,
                    "expected_exit": 0,
                },
                "license": license_value,
                "identity": {
                    "kind": "file-digest",
                    "digest": digest_file(provider),
                    "source": str(provider),
                },
            }
            for index, capability in enumerate(capabilities, 1)
        ]
        for binding in bindings:
            binding["dependency_receipt"] = build_provider_dependency_receipt(
                binding, project
            )
        plans = {
            "project_plan": {
                "record_type": "ProjectInit",
                "project_id": "project-1",
                "roots": [{"path": ".", "kind": "product"}],
                "candidate_recipe": {
                    "inventory_mode": "explicit",
                    "include": ["src/**"],
                    "exclude": [".promin/**"],
                    "symlink_policy": "reject",
                    "path_identity": "nfc-posix-relative",
                    "collision_policy": "reject-nfc-and-casefold-collisions",
                    "product_identity_excludes_control_state": True,
                },
                "preset_id": self.bundle.preset["preset_id"],
                "operating_profile": self.bundle.preset["default_profile"],
            },
            "standards_plan": {"record_type": "StandardsInit", "bindings": []},
            "technologies_plan": {
                "record_type": "TechnologiesInit",
                "bindings": bindings,
            },
            "licenses_plan": {
                "record_type": "LicensesPlan",
                "bindings": [
                    {"provider_id": item["provider_id"], "license": item["license"]}
                    for item in bindings
                ],
            },
            "authority_plan": {
                "record_type": "AuthorityInit",
                "trust_mode": "local-owner",
                "subjects": [
                    {"subject_id": "owner", "kind": "human", "display_name": "Owner"}
                ],
                "roots": [
                    {
                        "subject_id": "owner",
                        "capability_ceiling": [
                            "standard.activate", "task.plan", "task.execute"
                        ],
                        "scope": [{"kind": "project", "value": "project-1"}],
                    }
                ],
            },
        }
        plans["technologies_plan"] = bind_implementation_closures(
            plans["technologies_plan"], project
        )
        paths = {
            key: _write_json(self.root / "plans" / f"{key}.json", value)
            for key, value in plans.items()
        }
        return project, InitRequest(
            project_root=project,
            standard_bundle=self.package_root,
            preset_path=self.preset_path,
            **paths,
        ), paths


def _scoped_engine():
    from .authority import AuthorityEngine

    authority_init = _authority_init()
    engine = AuthorityEngine(authority_init, ZERO, _authority_runtime_policy())
    root = _grant(authority_init, "grant:root", "root", "authority.manage")
    _persist_grant(engine, authority_init, root)
    child = _grant(
        authority_init,
        "grant:scoped",
        "planner",
        "task.plan",
        issuer=root,
        scope=[
            {"kind": "project", "value": "P"},
            {"kind": "path", "value": "src"},
        ],
    )
    _persist_grant(engine, authority_init, child, issuer=root)
    return engine, child


def _runtime_policy(fixture: MutationFixture) -> dict[str, Any]:
    from .canonical import digest_value

    policy_set = fixture.bundle.core["policy-set.json"]
    authority_model = fixture.bundle.core["authority-model.json"]
    state_machines = policy_set["state_machines"]
    capacity_release = state_machines["capacity_release"]
    profile_name = fixture.bundle.preset["default_profile"]
    profile = fixture.bundle.preset["profiles"][profile_name]
    return {
        "activation_digest": ZERO,
        "implementation_closure_digest": IMPLEMENTATION_CLOSURE_DIGEST,
        "core_bundle_digest": fixture.bundle.bundle_digest,
        "preset_digest": fixture.bundle.preset_digest,
        "operating_profile": profile_name,
        "profile_digest": digest_value(profile),
        "model_tier": profile["model_tier"],
        "max_parallel_tasks": profile["max_parallel_tasks"],
        "model_tier_rule_digest": digest_value(
            {"model_tier_rule": authority_model["model_tier_rule"]}
        ),
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


def _domain_ready(fixture: MutationFixture):
    from .domain import DomainState
    from .evidence import EvidenceStore

    engine, grants = _engine_with_grants()
    policy = _runtime_policy(fixture)
    domain = DomainState(
        engine,
        EvidenceStore(fixture.root / ".promin" / "state" / "evidence"),
        implementation_closure_digest=IMPLEMENTATION_CLOSURE_DIGEST,
    )
    domain.record_candidate(
        {
            "record_type": "Candidate",
            "candidate_id": "candidate:mutation",
            "candidate_digest": ONE,
            "inventory_digest": "a" * 64,
            "product_root_digest": "b" * 64,
            "control_excluded": True,
            "candidate_recipe_digest": "c" * 64,
            "consistency_mode": "observational-best-effort",
            "creditable": False,
        },
        _authorization(grants["worker"]),
    )
    task = _task("task:lease")
    domain.record_task(task, _authorization(grants["planner"]))
    domain.transition_task(
        {
            "task_id": "task:lease",
            "from_state": "PLANNED",
            "to_state": "READY",
            "reason": "ready",
        },
        _authorization(grants["planner"]),
        runtime_policy=policy,
    )
    return domain, grants, policy


def _lease(
    grants: Mapping[str, Mapping[str, Any]],
    *,
    holder_grant: str | None = None,
    state: str = "ACTIVE",
):
    holder_id = holder_grant or grants["worker"]["grant_id"]
    holder_record = next(
        (value for value in grants.values() if value.get("grant_id") == holder_id),
        grants["worker"],
    )
    return {
        "record_type": "Lease",
        "lease_id": "lease:1",
        "task_id": "task:lease",
        "manager_subject_id": grants["manager"]["subject_id"],
        "manager_grant_id": grants["manager"]["grant_id"],
        "manager_grant_claim_digest": grants["manager"]["claim_digest"],
        "holder_subject_id": "worker",
        "holder_grant_id": holder_id,
        "holder_grant_claim_digest": holder_record["claim_digest"],
        "generation": 1,
        "fencing_token": 1,
        "state": state,
        "acquired_at": "2026-02-01T00:00:00Z",
        "heartbeat_at": "2026-02-01T00:00:00Z",
        "expires_at": "2026-02-01T00:10:00Z",
        "activation_digest": ZERO,
    }


def _tamper_journal(fixture: MutationFixture, mutation: Callable[[dict[str, Any]], None]):
    store = fixture.event_store()
    store.commit(_command(1), created_at=NOW)
    path = next(store.journal.glob("*.json"))
    value = json.loads(path.read_text(encoding="utf-8"))
    mutation(value)
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    fixture.event_store()


def _archive(fixture: MutationFixture, names: list[str], *, symlink: bool = False, expansion: bool = False):
    path = fixture.root / "invalid.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (
                (stat.S_IFLNK if symlink else stat.S_IFREG) | 0o644
            ) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, b"0" * (4 * 1024 * 1024) if expansion else b"x")
    return path


def _continuation_page(fixture: MutationFixture):
    projection = fixture.projection("continuation.sqlite3")
    rows = tuple(fixture.projection_row(index) for index in range(1, 7))
    projection.rebuild(
        fixture.event_store("continuation-events"),
        inventory=fixture.verified_inventory(*rows),
    )
    first = projection.search(
        "needle",
        depth=1,
        budget={
            "max_bytes": 16_384,
            "max_entities": 2,
            "max_relations": 1,
            "max_fanout_per_entity": 1,
            "top_k": 6,
        },
        resume_binding=_continuation_resume_binding(),
        now=NOW,
    )
    continuation = first.get("continuation")
    if not first.get("truncated") or not isinstance(continuation, Mapping):
        raise MutationSuiteError("continuation mutation fixture did not truncate")
    return projection, continuation["token"]


def _continuation_resume_binding() -> dict[str, str]:
    return {
        "activation_digest": ZERO,
        "capability_id": "projection.read",
        "grant_claim_digest": ONE,
        "grant_id": "grant:projection-read",
        "implementation_closure_digest": IMPLEMENTATION_CLOSURE_DIGEST,
        "requested_scope_digest": "2" * 64,
        "revocation_epoch": "3" * 64,
        "subject_id": "owner",
    }


def _continuation_row(projection: Any, token: str) -> tuple[str, str]:
    parts = token.split(".")
    if len(parts) != 4:
        raise MutationSuiteError("opaque continuation token is malformed")
    handle = parts[1]
    connection = sqlite3.connect(projection.db_path)
    try:
        row = connection.execute(
            "SELECT payload_json FROM continuations WHERE handle=?",
            (handle,),
        ).fetchone()
    finally:
        connection.close()
    if row is None or not isinstance(row[0], str):
        raise MutationSuiteError("opaque continuation state is unresolved")
    return handle, row[0]


def _mutate_continuation_state(
    projection: Any,
    token: str,
    mutate: Callable[[dict[str, Any]], None],
) -> str:
    handle, payload_json = _continuation_row(projection, token)
    payload = json.loads(payload_json)
    if not isinstance(payload, dict):
        raise MutationSuiteError("opaque continuation state is malformed")
    mutate(payload)
    substituted = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"
    connection = sqlite3.connect(projection.db_path)
    try:
        connection.execute(
            "UPDATE continuations SET payload_json=? WHERE handle=?",
            (substituted, handle),
        )
        connection.commit()
    finally:
        connection.close()
    return token


def _public_material_continuation(
    token: str,
    mutate: Callable[[dict[str, Any]], None],
) -> str:
    del mutate
    if not isinstance(token, str) or len(token) < 8:
        raise MutationSuiteError("continuation fixture returned a malformed token")
    replacement = "A" if token[-1] != "A" else "B"
    return token[:-1] + replacement


def _noncanonical_archive(fixture: MutationFixture) -> Path:
    path = fixture.root / "noncanonical-layout.zip"
    with zipfile.ZipFile(path, "w") as archive:
        directory = zipfile.ZipInfo("promin/", (1980, 1, 1, 0, 0, 0))
        directory.create_system = 3
        directory.external_attr = (stat.S_IFDIR | 0o755) << 16
        archive.writestr(directory, b"")
    return path


def _increase_token_budget(payload: dict[str, Any]) -> None:
    budget = payload.get("budgets", payload.get("budget"))
    if not isinstance(budget, dict):
        raise MutationSuiteError("continuation fixture lacks a budget object")
    selected = budget.get("max_entities")
    if not isinstance(selected, int) or isinstance(selected, bool):
        raise MutationSuiteError("continuation fixture lacks max_entities")
    budget["max_entities"] = selected + 1


def _schema_mutation(fixture: MutationFixture, family: str) -> None:
    from .contracts import validate_ingress

    if family in {"status-credit-contradiction", "credit-without-evidence"}:
        value = _gate()
        value["status"] = "pass"
        value["outcome"] = "pass"
        value["pass_credit"] = family == "status-credit-contradiction"
        value["evidence_artifacts"] = []
    elif family == "decision-target-confusion":
        value = _decision()
        value["target_type"] = "Finding"
    elif family == "missing-critical-field":
        value = _workcard()
        value["grant_id"] = value.pop("holder_grant_id")
    elif family == "unknown-critical-field":
        value = _evidence_artifact()
        value["degraded"] = True
    else:
        value = _task()
        if family == "activation-drift":
            validate_ingress(
                fixture.bundle,
                value,
                operation="replay",
                context={"activation_digest": ONE},
            )
            return
    validate_ingress(fixture.bundle, value, operation="import")


def _run_family(fixture: MutationFixture, family: str) -> None:
    from .authority import AuthorityEngine
    from .canonical import parse_json_strict
    from .contracts import validate_ingress, verify_core, verify_preset
    from .domain import DomainState
    from .evidence import EvidenceStore
    from .init import ActivationGuard, initialize_project
    from .service import _required_capability, _validate_effect_scope

    if family in {
        "status-credit-contradiction", "missing-critical-field",
        "unknown-critical-field", "activation-drift", "decision-target-confusion",
        "credit-without-evidence",
    }:
        _schema_mutation(fixture, family)
    elif family == "candidate-decision-cycle":
        from .evidence import validate_standard_release_candidate_binding

        candidate = _standard_candidate_binding(fixture)
        candidate["decision_digest"] = "d" * 64
        validate_standard_release_candidate_binding(candidate)
    elif family == "fabricated-evidence-digest":
        from .evidence import validate_standard_release_evidence_manifest

        candidate = _standard_candidate_binding(fixture)
        evidence_root, manifest = _standard_evidence_manifest(fixture, candidate)
        trust, _ = _standard_trust_and_decision(candidate, manifest)
        validate_standard_release_evidence_manifest(
            manifest,
            candidate_binding=candidate,
            evidence_root=evidence_root,
            trust_configuration=trust,
        )
    elif family in {
        "unsigned-standard-decision",
        "unconfigured-standard-decision-key",
        "standard-decision-version-replay",
    }:
        from unittest.mock import patch

        from .authority import canonical_digest
        from .evidence import validate_standard_release_decision

        candidate = _standard_candidate_binding(fixture)
        evidence_root, manifest = _standard_evidence_manifest(
            fixture, candidate, physical=True
        )
        trust, decision = _standard_trust_and_decision(candidate, manifest)
        if family == "unsigned-standard-decision":
            decision.pop("signature")
        elif family == "unconfigured-standard-decision-key":
            decision["key_id"] = "key:unconfigured"
        else:
            decision["version"] = "999.0.0"
        if family != "unsigned-standard-decision":
            identity = {
                key: value
                for key, value in decision.items()
                if key not in {"signed_claim_digest", "signature"}
            }
            decision["signed_claim_digest"] = canonical_digest(identity)
        prevalidated_manifest = {
            **manifest,
            "all_required_roles_resolved": True,
        }
        with patch(
            "promin.evidence.validate_standard_release_evidence_manifest",
            return_value=prevalidated_manifest,
        ):
            validate_standard_release_decision(
                decision,
                candidate_binding=candidate,
                evidence_manifest=manifest,
                evidence_root=evidence_root,
                trust_configuration=trust,
            )
    elif family in {"continuation-frontier-loss", "continuation-duplicate-emission"}:
        projection, token = _continuation_page(fixture)
        delta = 1 if family == "continuation-frontier-loss" else -1
        forged = _mutate_continuation_state(
            projection,
            token,
            lambda payload: payload.__setitem__(
                "cursor", max(0, int(payload.get("cursor", 0)) + delta)
            ),
        )
        projection.continue_search(
            forged,
            resume_binding=_continuation_resume_binding(),
            now=NOW,
        )
    elif family in {
        "continuation-public-material-mismatch",
        "workcard-budget-bypass",
    }:
        projection, token = _continuation_page(fixture)
        if family == "continuation-public-material-mismatch":
            forged = _public_material_continuation(
                token,
                lambda payload: payload.__setitem__(
                    "cursor", int(payload.get("cursor", 0)) + 1
                ),
            )
        else:
            forged = _mutate_continuation_state(
                projection,
                token,
                _increase_token_budget,
            )
        projection.continue_search(
            forged,
            resume_binding=_continuation_resume_binding(),
            now=NOW,
        )
    elif family == "continuation-token-context-inflation":
        projection, token = _continuation_page(fixture)
        _handle, payload_json = _continuation_row(projection, token)
        _require_noncredit(
            isinstance(token, str)
            and token.count(".") == 3
            and len(token.encode("ascii")) <= projection.limits.max_token_bytes
            and len(payload_json.encode("utf-8"))
            <= projection.limits.max_continuation_state_bytes,
            "continuation public material and owner state remained bounded",
        )
    elif family == "broad-query-corpus-pagination":
        projection = fixture.projection("broad-query.sqlite3")
        rows = tuple(fixture.projection_row(index) for index in range(1, 26))
        for row in rows:
            row["semantic_proxy"]["payload"]["label"] = "record"
        projection.rebuild(
            fixture.event_store("broad-query-events"),
            inventory=fixture.verified_inventory(*rows),
        )
        result = projection.search(
            "record",
            depth=1,
            budget={
                "max_bytes": 16_384,
                "max_entities": 32,
                "max_relations": 48,
                "max_fanout_per_entity": 8,
                "top_k": 12,
            },
            resume_binding=_continuation_resume_binding(),
            now=NOW,
        )
        continuation = result.get("continuation")
        _require_noncredit(
            result.get("refinement_required") is True
            and result.get("selected_seed_count") == 12
            and result.get("unselected_matches_traversable") is False
            and result.get("corpus_pagination") is not True
            and result.get("selected_closure_complete") is True
            and (continuation is None or isinstance(continuation, Mapping)),
            "broad query exposed refinement instead of corpus pagination",
        )
    elif family == "content-search-omission":
        from .service import ProminService, inventory_candidate

        project, request, _ = fixture.init_request()
        initialize_project(request)
        source = project / "src" / "semantic.txt"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(
            "semantic source sentinel for representative content retrieval",
            encoding="utf-8",
        )
        inventory = inventory_candidate(project, ["."])
        service = ProminService(project)
        service.rebuild(inventory)
        context = ActivationGuard(project).verify()
        result = service._projection(context).search(
            "semantic source sentinel",
            depth=1,
            budget={
                "max_bytes": 16_384,
                "max_entities": 8,
                "max_relations": 8,
                "max_fanout_per_entity": 4,
                "top_k": 4,
            },
            resume_binding=_continuation_resume_binding(),
            now=NOW,
        )
        matched_paths = {
            entity.get("payload", {}).get("inventory_path")
            for entity in result.get("entities", [])
            if isinstance(entity, Mapping)
            and isinstance(entity.get("payload"), Mapping)
        }
        _require_noncredit(
            "src/semantic.txt" in matched_paths,
            "representative file content remained searchable through its Artifact proxy",
        )
    elif family == "inventory-stream-materialization":
        from .service import ProminService, inventory_candidate

        project, request, _ = fixture.init_request()
        initialize_project(request)
        source = project / "src" / "raw.txt"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("manifest verified stream", encoding="utf-8")
        inventory_candidate(project, ["."])
        inventory_root = project / ".promin" / "state" / "inventory"
        pointer = json.loads((inventory_root / "current.json").read_text(encoding="utf-8"))
        stream_path = inventory_root / f"{pointer['stream_digest']}.jsonl"
        stream_path.chmod(stat.S_IREAD | stat.S_IWRITE)
        with stream_path.open("ab") as stream:
            stream.write(b"{}\n")
        ProminService(project).rebuild()
    elif family == "pdf-header-only-credit":
        validator = _load_tool(fixture.package_root, "promin_validate")
        root = fixture.root / "pdf-header-only"
        for relative in sorted(validator.HUMAN_PDFS):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"%PDF-1.7\n%%EOF\n")
        validator.verify_human_documents(root)
    elif family == "scale-environment-skip-credit":
        environment = dict(os.environ)
        environment.pop("PROMIN_SCALE_WORKSPACE", None)
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "-m",
                "scale",
                "tests/test_search_scale.py::SearchScalePhysicalTests::test_physical_100k_same_runtime_route",
            ],
            cwd=fixture.package_root,
            env=environment,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            timeout=120,
        )
        output = completed.stdout + completed.stderr
        _require_noncredit(
            completed.returncode != 0
            and "PROMIN_SCALE_WORKSPACE" in output
            and "skipped" not in output.casefold(),
            "physical scale selection failed when its explicit environment was absent",
        )
    elif family in {"inventory-provenance-override", "inventory-graph-inflation"}:
        from .service import InventoryResult, ProminService, inventory_candidate

        project, request, _ = fixture.init_request()
        initialize_project(request)
        source = project / "src" / "raw.txt"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("raw inventory fixture", encoding="utf-8")
        inventory = inventory_candidate(project, ["."])
        if not inventory.entries:
            raise MutationSuiteError("inventory mutation fixture returned no entries")
        entries = [deepcopy(item) for item in inventory.entries]
        if family == "inventory-provenance-override":
            entries[0]["provenance"] = {
                "data_class": "trusted-authority",
                "path": "attacker/override.txt",
                "digest": ZERO,
            }
        else:
            entries[0]["semantic_proxies"] = [
                {
                    "id": "task:synthetic",
                    "entity_type": "Task",
                    "data_class": "untrusted-source",
                    "payload": {
                        "record_type": "Task",
                        "task_id": "task:synthetic",
                    },
                }
            ]
            entries[0]["typed_relations"] = [
                {
                    "record_type": "Relation",
                    "relation_id": "relation:synthetic",
                    "kind": "READS",
                    "source_type": "Task",
                    "source_id": "task:synthetic",
                    "target_type": "Artifact",
                    "target_id": "artifact:synthetic",
                    "activation_digest": ZERO,
                    "created_at": NOW,
                }
            ]
        mutated = replace(inventory, entries=tuple(entries))
        if not isinstance(mutated, InventoryResult):
            raise MutationSuiteError("mutated inventory lost its production result type")
        ProminService(project).rebuild(mutated)
    elif family == "implementation-closure-drift":
        _, request, paths = fixture.init_request()
        technologies = json.loads(
            paths["technologies_plan"].read_text(encoding="utf-8")
        )
        technologies["bindings"][0]["implementation_closure"]["runtime"][
            "digest"
        ] = ZERO
        _write_json(paths["technologies_plan"], technologies)
        initialize_project(request)
    elif family == "noncanonical-archive-layout":
        verifier = _load_tool(fixture.package_root, "promin_package")
        verifier.verify_archive(_noncanonical_archive(fixture))
    elif family == "candidate-recipe-bypass":
        from .contracts import compile_candidate_recipe

        recipe = compile_candidate_recipe(_candidate_recipe())
        selected = recipe.select("build/excluded.bin", {})
        _require_noncredit(
            selected is None,
            "candidate recipe excluded path received no Candidate identity credit",
        )
    elif family == "observational-candidate-pass-credit":
        from .contracts import validate_candidate_consistency

        validate_candidate_consistency(_candidate(creditable=True))
    elif family == "snapshot-provider-substitution":
        candidate = _candidate(
            consistency_mode="immutable-vcs-tree",
            creditable=True,
            snapshot_provider_id="snapshot:attacker",
        )
        validate_ingress(
            fixture.bundle,
            candidate,
            operation="import",
            definition="Candidate",
            context={
                "candidate_recipe_digest": candidate["candidate_recipe_digest"],
                "candidate_consistency_mode": "immutable-vcs-tree",
                "snapshot_provider_id": "snapshot:trusted",
            },
        )
    elif family == "unsupported-provider-adapter":
        _, request, paths = fixture.init_request()
        technologies = json.loads(
            paths["technologies_plan"].read_text(encoding="utf-8")
        )
        technologies["bindings"][0]["invocation"]["kind"] = "unsupported-runtime"
        _write_json(paths["technologies_plan"], technologies)
        initialize_project(request)
    elif family == "stale-release-closure-credit":
        engine, _ = _engine_with_grants()
        domain = DomainState(
            engine,
            EvidenceStore(fixture.root / "release-cas"),
            provider_binding_digest="3" * 64,
        )
        historical = _decision()
        domain.decisions[historical["decision_id"]] = historical
        domain._decision_order.append(historical["decision_id"])
        status = domain.approval_status(
            ONE,
            current_activation_digest=ZERO,
            current_provider_binding_digest="3" * 64,
            evaluated_at=NOW,
        )
        _require_noncredit(
            status.get("current_release_eligible") is False
            and status.get("product_acceptance") is False
            and status.get("public_release_approved") is False
            and status.get("human_decision_id") == historical["decision_id"]
            and bool(status.get("invalidation_reasons")),
            "stale historical release closure was preserved but received no current credit",
        )
    elif family == "finding-evidence-target-mismatch":
        engine, grants = _engine_with_grants()
        domain = DomainState(engine, EvidenceStore(fixture.root / "finding-cas"))
        finding = {
            "record_type": "Finding",
            "finding_id": "finding:target",
            "status": "OPEN",
            "severity": "P1",
            "blocking": True,
            "statement": "target-specific blocking fact",
            "activation_digest": ZERO,
            "candidate_digest": ONE,
            "evidence_artifacts": [
                {
                    "artifact_id": "artifact:finding",
                    "artifact_record_digest": "4" * 64,
                }
            ],
            "created_at": NOW,
        }
        domain.findings[finding["finding_id"]] = finding
        decision = {
            "record_type": "Decision",
            "decision_id": "decision:finding:mismatch",
            "decision_kind": "resolve",
            "subject_id": "approver",
            "grant_id": grants["approver"]["grant_id"],
            "activation_digest": ZERO,
            "candidate_digest": ONE,
            "target_type": "Finding",
            "target_id": finding["finding_id"],
            "finding_digest": "5" * 64,
            "rationale": "attempt to cite evidence for another Finding",
            "evidence_artifacts": [
                {
                    "artifact_id": "artifact:decision",
                    "artifact_record_digest": "6" * 64,
                }
            ],
            "created_at": NOW,
        }
        domain.record_decision(decision, _authorization(grants["approver"]))
    elif family == "candidate-delta-scope-escape":
        from .authority import canonical_digest

        engine, grants = _engine_with_grants()
        evidence = EvidenceStore(fixture.root / "delta-cas")
        domain = DomainState(engine, evidence)
        new_candidate_digest = "b" * 64
        domain.candidates = {
            "candidate:base": {"candidate_digest": ONE},
            "candidate:new": {"candidate_digest": new_candidate_digest},
        }
        domain._candidate_ids_by_digest = {
            ONE: "candidate:base",
            new_candidate_digest: "candidate:new",
        }
        task = _task()
        task["task_id"] = "task:delta"
        task["allowed_paths"] = ["product"]
        domain.tasks[task["task_id"]] = task
        workcard = _workcard(grants["worker"]["grant_id"])
        workcard["task_id"] = task["task_id"]
        workcard["allowed_paths"] = task["allowed_paths"]
        artifact = _finalize_delta(
            evidence,
            base_candidate_digest=ONE,
            new_candidate_digest=new_candidate_digest,
            workcard_digest=canonical_digest(workcard),
            changed_paths=["outside/secret.bin"],
        )
        domain.validate_candidate_delta(
            artifact["digest"],
            task_id=task["task_id"],
            workcard=workcard,
            authorization=_authorization(grants["worker"]),
        )
    elif family in {"checkpoint-head-mismatch", "checkpoint-corruption-credit"}:
        from .canonical import canonical_bytes, digest_value

        store = fixture.event_store("checkpoint-events")
        store.commit(_command(1), created_at=NOW)
        if family == "checkpoint-corruption-credit":
            store.checkpoint_path.write_bytes(b"{corrupt")
        else:
            checkpoint = json.loads(store.checkpoint_path.read_text(encoding="utf-8"))
            checkpoint["head"]["batch_digest"] = ZERO
            checkpoint.pop("checkpoint_digest")
            checkpoint["checkpoint_digest"] = digest_value(checkpoint)
            store.checkpoint_path.write_bytes(canonical_bytes(checkpoint))
        reopened = fixture.event_store("checkpoint-events")
        status = reopened.checkpoint_status()
        _require_noncredit(
            status.get("open_mode") == "full-replay-fallback"
            and status.get("authoritative") is False
            and bool(status.get("fallback_reason")),
            "invalid checkpoint was denied authority and forced full replay",
        )
    elif family == "normal-command-full-replay":
        store = fixture.event_store("normal-checkpoint-events")
        store.commit(_command(1), created_at=NOW)
        reopened = fixture.event_store("normal-checkpoint-events")
        status = reopened.checkpoint_status()
        _require_noncredit(
            status.get("open_mode") == "verified-checkpoint"
            and status.get("fallback_reason") is None
            and status.get("authoritative") is False,
            "normal command state reopened through the verified checkpoint",
        )
    elif family == "profile-default-depth-bypass":
        from .service import _profile_depth

        profile = fixture.bundle.preset["profiles"][fixture.bundle.preset["default_profile"]]
        depth = _profile_depth(
            fixture.bundle.preset,
            {"operating_profile": fixture.bundle.preset["default_profile"]},
            fixture.bundle.core["conformance.json"],
            None,
        )
        _require_noncredit(
            depth == profile.get("default_dependency_depth")
            and fixture.bundle.core["conformance.json"].get(
                "dependency_depth_hard_max"
            )
            == 12,
            "omitted depth used the selected profile default under Core max 12",
        )
    elif family == "grant-replay":
        authority_init = _authority_init()
        engine, grants = _engine_with_grants()
        duplicate = _grant(
            authority_init, "grant:duplicate", "worker", "task.execute",
            issuer=grants["root"], nonce=grants["planner"]["nonce"],
        )
        _persist_grant(engine, authority_init, duplicate, issuer=grants["root"])
    elif family in {"scope-escalation", "command-scope-escalation"}:
        engine, grant = _scoped_engine()
        engine.authorize(
            "planner", "task.plan", [{"kind": "all", "value": "*"}],
            grant["grant_id"], grant["claim_digest"], "2026-02-01T00:00:00Z",
        )
    elif family == "expired-grant":
        engine, grants = _engine_with_grants(); grant = grants["planner"]
        engine.authorize("planner", "task.plan", [{"kind": "all", "value": "*"}], grant["grant_id"], grant["claim_digest"], "2029-01-01T00:00:00Z")
    elif family == "revoked-grant":
        engine, grants = _engine_with_grants(); grant = grants["planner"]
        engine.revoke_grant({"grant_id": grant["grant_id"], "decision_id": "decision:revoke", "reason": "test", "revoked_at": "2026-02-01T00:00:00Z"}, grants["root"]["grant_id"], "root")
        engine.authorize("planner", "task.plan", [{"kind": "all", "value": "*"}], grant["grant_id"], grant["claim_digest"], "2026-02-02T00:00:00Z")
    elif family == "stale-fence":
        domain, grants, policy = _domain_ready(fixture)
        domain.acquire_lease(
            _lease(grants),
            _authorization(grants["manager"]),
            parallelism_policy=policy,
        )
        domain.heartbeat_lease(
            "lease:1",
            1,
            0,
            "2026-02-01T00:01:00Z",
            "2026-02-01T00:11:00Z",
            _authorization(grants["worker"]),
            runtime_policy=policy,
        )
    elif family == "candidate-drift":
        from .canonical import digest_value

        store = EvidenceStore(fixture.root / ".promin" / "state" / "evidence")
        artifact = _finalize_evidence(
            store,
            fixture.event_store("candidate-drift-events"),
        )
        record = store.get_record(artifact["artifact_id"])
        binding = artifact["evidence_binding"]
        store.require_creditable(
            artifact["artifact_id"],
            digest_value(record),
            candidate_digest="5" * 64,
            policy_digest=binding["policy_digest"],
            tool_digest=binding["tool_digest"],
            input_digests=binding["input_digests"],
            provider_invocation_digests=[
                digest_value(value)
                for value in binding["provider_invocations"]
            ],
            activation_digest=binding["activation_digest"],
            implementation_closure_digest=binding[
                "implementation_closure_digest"
            ],
            evidence_class=artifact["evidence_class"],
            purpose=artifact["evidence_purpose"],
        )
    elif family == "provider-substitution":
        project, request, _ = fixture.init_request(); initialize_project(request)
        provider = project / Path(
            getattr(sys, "_base_executable", sys.executable)
        ).resolve().name
        with provider.open("ab") as stream:
            stream.write(b"provider substitution")
        ActivationGuard(project).verify()
    elif family == "event-fork":
        _tamper_journal(fixture, lambda value: value["batch"].__setitem__("previous_digest", "f"*64))
    elif family == "batch-command-mismatch":
        _tamper_journal(fixture, lambda value: value["batch"].__setitem__("command_id", "command:attacker"))
    elif family == "duplicate-idempotency-key":
        store = fixture.event_store(); key = "same-idempotency-key"
        store.commit(_command(1, key=key), created_at=NOW)
        store.commit(_command(2, store.head()["batch_digest"], key=key), created_at=NOW)
    elif family == "projection-corruption":
        projection = fixture.projection(); row = fixture.projection_row()
        projection.rebuild(fixture.event_store(), inventory=fixture.verified_inventory(row))
        projection.db_path.write_bytes(b"not sqlite"); projection.status()
    elif family == "projection-staleness":
        store = fixture.event_store(); projection = fixture.projection(); row = fixture.projection_row()
        projection.rebuild(store, inventory=fixture.verified_inventory(row))
        store.commit(_command(1), created_at=NOW); projection.require_current(store)
    elif family == "reference-break":
        row = fixture.projection_row(dangling=True)
        fixture.projection().rebuild(
            fixture.event_store(), inventory=fixture.verified_inventory(row)
        )
    elif family == "relation-domain-break":
        row = fixture.projection_row(wrong_domain=True)
        fixture.projection().rebuild(
            fixture.event_store(), inventory=fixture.verified_inventory(row)
        )
    elif family == "context-flood":
        projection = fixture.projection(); row = fixture.projection_row()
        projection.rebuild(
            fixture.event_store(), inventory=fixture.verified_inventory(row)
        )
        projection.search(
            "needle",
            budget={"max_bytes": 16385, "max_entities": 32, "max_relations": 48, "max_fanout_per_entity": 8, "top_k": 12},
            resume_binding=_continuation_resume_binding(),
        )
    elif family in {"symlink-core-input", "symlink-product-entry", "archive-expansion", "path-casefold-collision"}:
        verifier = _load_tool(fixture.package_root, "promin_package")
        if family == "symlink-core-input": path = _archive(fixture, ["promin/core/semantic-model.json"], symlink=True)
        elif family == "symlink-product-entry": path = _archive(fixture, ["promin/product/link"], symlink=True)
        elif family == "archive-expansion": path = _archive(fixture, ["promin/payload.bin"], expansion=True)
        else: path = _archive(fixture, ["promin/A.txt", "promin/a.txt"])
        verifier.verify_archive(path)
    elif family == "shadow-core-file":
        target = fixture.root / "core"; shutil.copytree(fixture.core_dir, target); (target / "shadow.json").write_text("{}", encoding="utf-8")
        verify_core(target)
    elif family in {"secret-export", "forbidden-name-reintroduction"}:
        validator = _load_tool(fixture.package_root, "promin_validate")
        root = fixture.root / "distribution"; root.mkdir()
        if family == "secret-export": (root / ".env").write_text("TOKEN=value", encoding="utf-8")
        else: (root / "bad.txt").write_text("agent" + "doc", encoding="utf-8")
        validator.scan_distribution(root)
    elif family == "preset-authority-escalation":
        value = deepcopy(fixture.bundle.preset); value["authority"] = {"grant": "all"}
        verify_preset(_write_json(fixture.root / "preset.json", value), fixture.bundle.core)
    elif family == "normalization-key-collision":
        parse_json_strict('{"é":1,"é":2}'.encode("utf-8"))
    elif family == "reinit-configuration-conflict":
        _, request, paths = fixture.init_request(); initialize_project(request)
        value = json.loads(paths["project_plan"].read_text(encoding="utf-8")); value["project_id"] = "project-conflict"
        initialize_project(replace(request, project_plan=_write_json(fixture.root / "alternate.json", value)))
    elif family == "clock-order-violation":
        fixture.event_store().commit(_command(1), created_at="2026-07-17T11:59:59Z")
    elif family == "capability-confusion":
        engine, grants = _engine_with_grants(); grant = grants["planner"]
        engine.authorize("planner", "release.decide", [{"kind": "all", "value": "*"}], grant["grant_id"], grant["claim_digest"], "2026-02-01T00:00:00Z")
    elif family == "grant-issuer-chain-break":
        authority_init = _authority_init(); engine = AuthorityEngine(authority_init, ZERO, _authority_runtime_policy())
        root = _grant(authority_init, "grant:root", "root", "authority.manage")
        _persist_grant(engine, authority_init, root)
        orphan = _grant(authority_init, "grant:orphan", "planner", "task.plan", issuer=root)
        orphan["trust_proofs"][0]["issuer_grant_id"] = "grant:missing"
        _persist_grant(engine, authority_init, orphan, issuer=root)
    elif family == "unverified-signature-acceptance":
        authority_init = _authority_init(team=True); engine = AuthorityEngine(authority_init, ZERO, _authority_runtime_policy())
        value = _grant(authority_init, "grant:signed", "root", "authority.manage")
        value["trust_proofs"] = [{"kind": "signature", "key_id": "key-root", "algorithm": "test-ed25519-boundary", "signed_digest": value["claim_digest"], "signature": "opaque"}]
        command = _grant_issue_command(authority_init, value)
        command["authorization"]["proofs"] = [{
            "kind": "signature-command",
            "key_id": "key-root",
            "algorithm": "test-ed25519-boundary",
            "signed_intent_digest": command["intent_digest"],
            "signature": "opaque",
        }]
        receipt = engine.authorize_grant_issue_command(command)
        engine.issue_grant(value, value["issued_at"], issue_authorization=receipt)
    elif family == "provider-declared-but-unavailable":
        _, request, paths = fixture.init_request(); value = json.loads(paths["technologies_plan"].read_text(encoding="utf-8"))
        value["bindings"][0]["healthcheck"]["argv"] = [str(fixture.root / "missing-provider.exe")]
        _write_json(paths["technologies_plan"], value); initialize_project(request)
    elif family == "illegal-task-transition":
        engine, grants = _engine_with_grants()
        policy = _runtime_policy(fixture)
        domain = DomainState(
            engine,
            EvidenceStore(fixture.root / ".promin" / "state" / "evidence"),
            implementation_closure_digest=IMPLEMENTATION_CLOSURE_DIGEST,
        )
        domain.record_task(_task(), _authorization(grants["planner"]))
        domain.transition_task(
            {
                "task_id": "task:mutation",
                "from_state": "PLANNED",
                "to_state": "COMPLETED",
                "reason": "skip",
            },
            _authorization(grants["planner"]),
            runtime_policy=policy,
        )
    elif family == "illegal-lease-transition":
        domain, grants, policy = _domain_ready(fixture)
        domain.acquire_lease(
            _lease(grants, state="CLOSED"),
            _authorization(grants["manager"]),
            parallelism_policy=policy,
        )
    elif family == "command-primary-event-mismatch":
        _tamper_journal(fixture, lambda value: value["batch"]["events"][0].__setitem__("payload", {"record_type": "Task", "task_id": "task:other"}))
    elif family == "duplicate-event-id":
        store = fixture.event_store(); relation = fixture.relation()
        store.commit(_command(1), auxiliary_relations=[relation, relation], created_at=NOW)
    elif family == "scope-selector-drop-broadening":
        engine, grant = _scoped_engine()
        engine.authorize("planner", "task.plan", [{"kind": "project", "value": "P"}], grant["grant_id"], grant["claim_digest"], "2026-02-01T00:00:00Z")
    elif family == "authorization-grant-claim-substitution":
        engine, grants = _engine_with_grants(); grant = grants["planner"]
        engine.authorize("planner", "task.plan", [{"kind": "all", "value": "*"}], grant["grant_id"], "f"*64, "2026-02-01T00:00:00Z")
    elif family == "command-effect-outside-requested-scope":
        command = _command(1); command["requested_scope"] = [{"kind": "task", "value": "task:other"}]
        from .events import command_intent_identity, digest_value
        command["intent_digest"] = digest_value(command_intent_identity(command)); _validate_effect_scope(fixture.bundle, command, {})
    elif family == "lease-holder-grant-mismatch":
        from .canonical import digest_value

        domain, grants, policy = _domain_ready(fixture)
        domain.acquire_lease(
            _lease(grants),
            _authorization(grants["manager"]),
            parallelism_policy=policy,
        )
        workcard = _workcard(grants["worker"]["grant_id"])
        command = {
            "record_type": "CommandRequest",
            "command_id": "command:holder-mismatch",
            "command_kind": "task.transition",
            "subject_id": "worker",
            "activation_digest": ZERO,
            "idempotency_key": "holder-mismatch-0001",
            "requested_scope": [{"kind": "task", "value": "task:lease"}],
            "expected_head_digest": None,
            "issued_at": "2026-02-01T00:00:00Z",
            "payload": {
                "task_id": "task:lease",
                "from_state": "READY",
                "to_state": "LEASED",
                "reason": "execute",
            },
            "intent_digest": ZERO,
            "authorization": {
                "kind": "grant",
                "grant_id": grants["planner"]["grant_id"],
                "grant_claim_digest": grants["planner"]["claim_digest"],
            },
            "holder_authorization": {
                "kind": "grant",
                "grant_id": grants["planner"]["grant_id"],
                "grant_claim_digest": grants["planner"]["claim_digest"],
            },
            "workcard_task_id": "task:lease",
            "lease_id": "lease:1",
            "lease_generation": 1,
            "fencing_token": 1,
            "workcard_digest": digest_value(workcard),
            "context_digest": workcard["context_digest"],
        }
        domain.assert_mutation_claim(command, workcard)
    elif family == "decision-grant-provenance-mismatch":
        engine, grants = _engine_with_grants(); domain = DomainState(engine, EvidenceStore(fixture.root / ".promin" / "state" / "evidence"))
        candidate = _candidate()
        domain.record_candidate(candidate, _authorization(grants["worker"]))
        decision = _decision(); decision["grant_id"] = "grant:wrong"
        domain.record_decision(decision, _authorization(grants["approver"]))
    elif family == "artifact-kind-capability-confusion":
        engine, grants = _engine_with_grants(); grant = grants["worker"]
        command = _command(1); command["command_kind"] = "artifact.record"; command["payload"] = {"record_type": "Artifact", "artifact_id": "artifact:1", "artifact_kind": "evidence"}
        capability = _required_capability(fixture.bundle, command)
        engine.authorize("worker", capability, [{"kind": "all", "value": "*"}], grant["grant_id"], grant["claim_digest"], "2026-02-01T00:00:00Z")
    else:
        raise MutationSuiteError(f"mutation family has no production runner: {family}")


MUTATION_FAMILIES = (
    "status-credit-contradiction", "missing-critical-field", "unknown-critical-field",
    "activation-drift", "grant-replay", "scope-escalation", "expired-grant",
    "revoked-grant", "stale-fence", "candidate-drift", "provider-substitution",
    "event-fork", "batch-command-mismatch", "duplicate-idempotency-key",
    "projection-corruption", "projection-staleness", "reference-break",
    "relation-domain-break", "context-flood", "symlink-core-input", "shadow-core-file",
    "symlink-product-entry", "secret-export", "archive-expansion",
    "preset-authority-escalation", "normalization-key-collision",
    "path-casefold-collision", "forbidden-name-reintroduction",
    "reinit-configuration-conflict", "clock-order-violation", "capability-confusion",
    "command-scope-escalation", "grant-issuer-chain-break",
    "unverified-signature-acceptance", "provider-declared-but-unavailable",
    "illegal-task-transition", "illegal-lease-transition", "decision-target-confusion",
    "credit-without-evidence", "command-primary-event-mismatch", "duplicate-event-id",
    "scope-selector-drop-broadening", "authorization-grant-claim-substitution",
    "command-effect-outside-requested-scope", "lease-holder-grant-mismatch",
    "decision-grant-provenance-mismatch", "artifact-kind-capability-confusion",
    "continuation-frontier-loss", "continuation-duplicate-emission",
    "candidate-recipe-bypass", "observational-candidate-pass-credit",
    "snapshot-provider-substitution", "unsupported-provider-adapter",
    "stale-release-closure-credit", "finding-evidence-target-mismatch",
    "candidate-delta-scope-escape", "checkpoint-head-mismatch",
    "checkpoint-corruption-credit", "normal-command-full-replay",
    "profile-default-depth-bypass",
    "continuation-public-material-mismatch", "inventory-provenance-override",
    "implementation-closure-drift", "noncanonical-archive-layout",
    "inventory-graph-inflation", "workcard-budget-bypass",
    "fabricated-evidence-digest", "unsigned-standard-decision",
    "unconfigured-standard-decision-key", "standard-decision-version-replay",
    "candidate-decision-cycle", "broad-query-corpus-pagination",
    "continuation-token-context-inflation", "inventory-stream-materialization",
    "pdf-header-only-credit", "scale-environment-skip-credit",
    "content-search-omission",
)


EXPECTED_REJECTION_TYPES: Mapping[str, tuple[str, ...]] = {
    "status-credit-contradiction": ("ContractError",),
    "missing-critical-field": ("ContractError",),
    "unknown-critical-field": ("ContractError",),
    "activation-drift": ("ContractError",),
    "grant-replay": ("AuthorityError",),
    "scope-escalation": ("AuthorityError",),
    "expired-grant": ("AuthorityError",),
    "revoked-grant": ("AuthorityError",),
    "stale-fence": ("DomainError",),
    "candidate-drift": ("EvidenceError",),
    "provider-substitution": ("InitError", "ContractError"),
    "event-fork": ("JournalCorruption",),
    "batch-command-mismatch": ("JournalCorruption",),
    "duplicate-idempotency-key": ("CommandConflict",),
    "projection-corruption": ("ProjectionError", "DatabaseError"),
    "projection-staleness": ("ProjectionError",),
    "reference-break": ("ProjectionError",),
    "relation-domain-break": ("ProjectionError",),
    "context-flood": ("ProjectionError",),
    "symlink-core-input": ("ValidationFailure",),
    "shadow-core-file": ("ContractError", "CanonicalError"),
    "symlink-product-entry": ("ValidationFailure",),
    "secret-export": ("ValidationFailure",),
    "archive-expansion": ("ValidationFailure",),
    "preset-authority-escalation": ("ContractError",),
    "normalization-key-collision": ("CanonicalError",),
    "path-casefold-collision": ("ValidationFailure",),
    "forbidden-name-reintroduction": ("ValidationFailure",),
    "reinit-configuration-conflict": ("InitError",),
    "clock-order-violation": ("CommandConflict", "EventStoreError"),
    "capability-confusion": ("AuthorityError",),
    "command-scope-escalation": ("AuthorityError",),
    "grant-issuer-chain-break": ("AuthorityError",),
    "unverified-signature-acceptance": ("AuthorityError",),
    "provider-declared-but-unavailable": ("InitError",),
    "illegal-task-transition": ("DomainError",),
    "illegal-lease-transition": ("DomainError", "ContractError"),
    "decision-target-confusion": ("ContractError",),
    "credit-without-evidence": ("ContractError",),
    "command-primary-event-mismatch": ("JournalCorruption",),
    "duplicate-event-id": ("EventStoreError", "CommandConflict"),
    "scope-selector-drop-broadening": ("AuthorityError",),
    "authorization-grant-claim-substitution": ("AuthorityError",),
    "command-effect-outside-requested-scope": ("ServiceError",),
    "lease-holder-grant-mismatch": ("DomainError", "AuthorityError"),
    "decision-grant-provenance-mismatch": ("DomainError", "AuthorityError"),
    "artifact-kind-capability-confusion": ("AuthorityError", "ServiceError"),
    "continuation-frontier-loss": ("ContinuationError",),
    "continuation-duplicate-emission": ("ContinuationError",),
    "candidate-recipe-bypass": ("ExplicitNonCredit",),
    "observational-candidate-pass-credit": ("ContractError",),
    "snapshot-provider-substitution": ("ContractError",),
    "unsupported-provider-adapter": ("ContractError", "InitError"),
    "stale-release-closure-credit": ("DomainError", "ExplicitNonCredit"),
    "finding-evidence-target-mismatch": ("DomainError",),
    "candidate-delta-scope-escape": ("DomainError",),
    "checkpoint-head-mismatch": ("ExplicitNonCredit",),
    "checkpoint-corruption-credit": ("ExplicitNonCredit",),
    "normal-command-full-replay": ("ExplicitNonCredit",),
    "profile-default-depth-bypass": ("ExplicitNonCredit",),
    "continuation-public-material-mismatch": ("ContinuationError", "ServiceError"),
    "inventory-provenance-override": ("ServiceError", "ProjectionError"),
    "implementation-closure-drift": ("InitError", "ContractError"),
    "noncanonical-archive-layout": ("ValidationFailure",),
    "inventory-graph-inflation": ("ServiceError", "ProjectionError"),
    "workcard-budget-bypass": ("ContinuationError", "ProjectionError", "ServiceError"),
    "fabricated-evidence-digest": ("EvidenceError",),
    "unsigned-standard-decision": ("EvidenceError",),
    "unconfigured-standard-decision-key": ("EvidenceError",),
    "standard-decision-version-replay": ("EvidenceError",),
    "candidate-decision-cycle": ("EvidenceError",),
    "broad-query-corpus-pagination": ("ExplicitNonCredit",),
    "continuation-token-context-inflation": ("ExplicitNonCredit", "ServiceError"),
    "inventory-stream-materialization": ("ServiceError", "ProjectionError"),
    "pdf-header-only-credit": ("ValidationFailure",),
    "scale-environment-skip-credit": ("ExplicitNonCredit",),
    "content-search-omission": ("ExplicitNonCredit",),
}


@dataclass(frozen=True)
class MutationRejection:
    family: str
    exception_type: str
    message: str


def _relax_fixture_permissions(root: Path) -> None:
    if not root.exists():
        return
    prefix = "\\\\?\\" if sys.platform == "win32" else ""
    native = Path(prefix + str(root.absolute())) if prefix else root
    for directory, directories, filenames in __import__("os").walk(native, topdown=False):
        for filename in filenames:
            try:
                (Path(directory) / filename).chmod(stat.S_IREAD | stat.S_IWRITE)
            except OSError:
                pass
        for name in directories:
            try:
                (Path(directory) / name).chmod(
                    stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC
                )
            except OSError:
                pass


def run_mutation(
    family: str,
    fixture_root: str | Path,
    package_root: str | Path,
) -> MutationRejection:
    if family not in MUTATION_FAMILIES:
        raise MutationSuiteError(f"unknown mutation family: {family}")
    if set(EXPECTED_REJECTION_TYPES) != set(MUTATION_FAMILIES):
        raise MutationSuiteError("mutation rejection type catalogue differs from Core families")
    base = Path(fixture_root).resolve()
    base.mkdir(parents=True, exist_ok=True)
    root = base / family
    fixture = MutationFixture(root, Path(package_root))
    try:
        _run_family(fixture, family)
    except Exception as exc:
        if isinstance(exc, MutationSuiteError):
            raise
        if type(exc).__name__ not in EXPECTED_REJECTION_TYPES[family]:
            raise MutationSuiteError(
                f"mutation {family} rejected through unexpected {type(exc).__name__}: {exc}"
            ) from exc
        message = str(exc).strip().encode("ascii", "backslashreplace").decode("ascii")
        if not message:
            raise MutationSuiteError(
                f"mutation {family} rejected without auditable error detail"
            ) from exc
        result = MutationRejection(family, type(exc).__name__, message)
    else:
        raise MutationSuiteError(f"mutation {family} was accepted by the production path")
    finally:
        _relax_fixture_permissions(root)
    return result
