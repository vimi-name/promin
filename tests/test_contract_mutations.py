from __future__ import annotations

import base64
import json
import hashlib
import os
import random
import shutil
import sqlite3
import stat
import sys
import tempfile
import time
import unittest
import zipfile
from unittest.mock import patch
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass, replace
from functools import partial
from pathlib import Path
from typing import Any, Callable

from promin.authority import (
    AuthorityEngine,
    AuthorityError,
    canonical_digest,
    grant_claim_identity,
)
from promin.canonical import CanonicalError, digest_bytes, digest_file, parse_json_strict
from promin.contracts import (
    ACCEPTANCE_VALIDATORS,
    POLICY_VALIDATORS,
    ContractError,
    load_contract_bundle,
    validate_ingress,
    verify_core,
    verify_preset,
)
from promin.conformance import (
    ConformanceError,
    _validate_physical_scale_result,
    integrity_requirement_catalogue,
)
from promin.domain import DomainError, DomainState
from promin.evidence import EvidenceError, EvidenceStore
from promin.events import (
    CommandConflict,
    EventStore,
    EventStoreError,
    JournalCorruption,
    command_intent_identity,
    digest_value as event_digest,
)
from promin.init import (
    ActivationGuard,
    InitError,
    InitRequest,
    bind_implementation_closures,
    build_provider_dependency_receipt,
    initialize_project,
    verify_provider_preflight,
)
from promin.projection import (
    ContinuationError,
    Projection,
    ProjectionError,
    compile_relation_domains,
)
from promin.service import ServiceError, _required_capability, _validate_effect_scope
from promin.mutation_suite import (
    ExplicitNonCredit,
    MutationFixture as ProductionMutationFixture,
    _authority_runtime_policy,
    _continuation_resume_binding,
    _runtime_policy as production_runtime_policy,
    run_mutation,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CORE = PACKAGE_ROOT / "core"
PRESET = PACKAGE_ROOT / "presets" / "semantic-standard.json"
ZERO = "0" * 64
ONE = "1" * 64
NOW = "2026-07-17T12:00:00Z"
IMPLEMENTATION_CLOSURE_DIGEST = "9" * 64
PHYSICAL_ACCEPTANCE_ID = "physical-100k-exact-bucketed-inventory"
LEGACY_PHYSICAL_ACCEPTANCE_ID = "physical-100k-one-artifact-proxy-per-file"

TOOLS = PACKAGE_ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.append(str(TOOLS))
from promin_package import verify_archive  # noqa: E402
from promin_validate import ValidationFailure, scan_distribution  # noqa: E402


@contextmanager
def _temporary_fixture(prefix: str):
    root = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield root
    finally:
        cleanup_root = (
            Path("\\\\?\\" + str(root.absolute()))
            if sys.platform == "win32"
            else root
        )
        for attempt in range(8):
            if not cleanup_root.exists():
                break
            for directory, directories, filenames in os.walk(cleanup_root, topdown=False):
                for name in filenames:
                    try:
                        (Path(directory) / name).chmod(stat.S_IREAD | stat.S_IWRITE)
                    except OSError:
                        pass
                for name in directories:
                    try:
                        (Path(directory) / name).chmod(
                            stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC
                        )
                    except OSError:
                        pass
            try:
                shutil.rmtree(cleanup_root)
            except OSError:
                if attempt == 7:
                    raise
                time.sleep(0.05 * (attempt + 1))
            else:
                break


def _task(task_id: str = "task:focused") -> dict[str, object]:
    task: dict[str, Any] = {
        "record_type": "Task",
        "task_id": task_id,
        "state": "PLANNED",
        "required_capability": "task.execute",
        "acceptance_predicate": "focused predicate",
        "allowed_paths": ["product/**"],
        "activation_digest": ZERO,
        "candidate_digest": ONE,
        "created_at": NOW,
    }
    definition = {
        "definition_kind": "GateRunDefinition",
        "definition_id": "definition:focused",
        "owner_kind": "Task",
        "owner_digest": canonical_digest(
            {key: value for key, value in task.items() if key != "state"}
        ),
        "defined_at_head_digest": ZERO,
        "gate_id": "gate:focused",
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
        "provider_binding_digest": canonical_digest([]),
        "input_digests": [],
        "activation_digest": ZERO,
    }
    task["gate_run_definitions"] = [
        {
            "definition_digest": canonical_digest(definition),
            "definition": definition,
        }
    ]
    return task


def _relation() -> dict[str, object]:
    return {
        "record_type": "Relation",
        "relation_id": "relation:focused",
        "kind": "READS",
        "source_type": "Task",
        "source_id": "task:focused",
        "target_type": "Artifact",
        "target_id": "artifact:focused",
        "activation_digest": ZERO,
        "created_at": NOW,
    }


def _workcard(bundle) -> dict[str, object]:
    profile = bundle.preset["profiles"][bundle.preset["default_profile"]]
    return {
        "record_type": "WorkCard",
        "task_id": "task:focused",
        "operation_mode": "read",
        "operation": "inspect",
        "acceptance_predicate": "focused predicate",
        "allowed_paths": ["product/**"],
        "grant_id": "grant:focused",
        "candidate_digest": ONE,
        "activation_digest": ZERO,
        "context_digest": ZERO,
        "stop_conditions": ["budget exhausted"],
        "budget": {
            "max_bytes": profile["max_context_bytes"],
            "max_entities": profile["max_entities"],
            "max_relations": profile["max_relations"],
            "max_fanout_per_entity": profile["max_fanout_per_entity"],
            "top_k": profile["top_k"],
        },
        "truncated": False,
    }


def _gate_result() -> dict[str, object]:
    return {
        "record_type": "GateResult",
        "task_id": "task:focused",
        "gate_id": "gate:focused",
        "run_id": "run:focused",
        "run_digest": "4" * 64,
        "definition_digest": "5" * 64,
        "status": "fail",
        "outcome": "fail",
        "pass_credit": False,
        "activation_digest": ZERO,
        "candidate_digest": ONE,
        "policy_digest": ZERO,
        "tool_digest": ZERO,
        "evidence_class": "validator",
        "evidence_artifacts": [
            {
                "artifact_id": "artifact:focused",
                "artifact_record_digest": "6" * 64,
                "run_id": "run:focused",
                "run_digest": "4" * 64,
            }
        ],
    }


def _decision() -> dict[str, object]:
    return {
        "record_type": "Decision",
        "decision_id": "decision:focused",
        "decision_kind": "release",
        "subject_id": "subject:owner",
        "grant_id": "grant:release",
        "activation_digest": ZERO,
        "candidate_digest": ONE,
        "target_type": "Candidate",
        "target_id": "candidate:focused",
        "rationale": "focused test",
        "evidence_digests": [ONE],
        "created_at": NOW,
        "release_closure_digest": "2" * 64,
        "provider_binding_digest": "3" * 64,
    }


def _authority_init(*, team: bool = False) -> dict[str, Any]:
    subjects = [
        ("root", "human"),
        ("planner", "agent"),
        ("worker", "agent"),
        ("manager", "service"),
        ("validator", "agent"),
        ("approver", "human"),
    ]
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
                    "projection.rebuild",
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
    value: dict[str, Any] = {
        "record_type": "Grant",
        "grant_id": grant_id,
        "subject_id": subject,
        "capability_id": capability,
        "scope": scope or [{"kind": "all", "value": "*"}],
        "activation_digest": ZERO,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce or f"nonce-{grant_id}-00000000",
    }
    value["claim_digest"] = canonical_digest(grant_claim_identity(value))
    value["trust_proofs"] = [
        {
            "kind": "local-root",
            "root_subject_id": "root",
            "authority_init_digest": canonical_digest(init),
            "signed_claim_digest": value["claim_digest"],
        }
        if issuer is None
        else {
            "kind": "issuer-grant",
            "issuer_grant_id": issuer["grant_id"],
            "issuer_signed_claim_digest": issuer["claim_digest"],
            "signed_claim_digest": value["claim_digest"],
        }
    ]
    return value


def _engine_with_grants() -> tuple[AuthorityEngine, dict[str, dict[str, Any]]]:
    init = _authority_init()
    engine = AuthorityEngine(init, ZERO, _authority_runtime_policy())
    root = _grant(init, "grant:root", "root", "authority.manage")
    _persist_grant(engine, init, root)
    grants = {"root": root}
    for name, subject, capability in (
        ("planner", "planner", "task.plan"),
        ("worker", "worker", "task.execute"),
        ("manager", "manager", "lease.manage"),
        ("validator", "validator", "validation.evaluate"),
        ("approver", "approver", "release.decide"),
    ):
        child = _grant(init, f"grant:{name}", subject, capability, issuer=root)
        _persist_grant(engine, init, child, issuer=root)
        grants[name] = child
    return engine, grants


def _grant_issue_command(
    init: dict[str, Any],
    grant: dict[str, Any],
    *,
    issuer: dict[str, Any] | None = None,
) -> dict[str, Any]:
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
        "payload": deepcopy(grant),
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
                    "authority_init_digest": canonical_digest(init),
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
    engine: AuthorityEngine,
    init: dict[str, Any],
    grant: dict[str, Any],
    *,
    issuer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    receipt = engine.authorize_grant_issue_command(
        _grant_issue_command(init, grant, issuer=issuer)
    )
    return engine.issue_grant(
        grant,
        grant["issued_at"],
        issue_authorization=receipt,
    )


def _authorization(grant: dict[str, Any], *, scope: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {
        "subject_id": grant["subject_id"],
        "grant_id": grant["grant_id"],
        "claim_digest": grant["claim_digest"],
        "evaluated_at": "2026-02-01T00:00:00Z",
        "requested_scope": scope or [{"kind": "all", "value": "*"}],
    }


def _command(index: int, expected_head: str | None = None, *, key: str | None = None) -> dict[str, Any]:
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
        "payload": {"record_type": "Task", "task_id": f"task:mutation:{index}", "state": "PLANNED"},
        "intent_digest": ZERO,
        "authorization": {"kind": "grant", "grant_id": "grant:planner", "grant_claim_digest": ONE},
    }
    value["intent_digest"] = event_digest(command_intent_identity(value))
    return value


def _write_json(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")
    return path


def _physical_scale_result_from_core(bundle) -> dict[str, Any]:
    conformance = bundle.core["conformance.json"]
    reference = conformance["reference_benchmarks"]
    scale_contracts = conformance["scale_contracts"]
    semantic = reference["semantic_corpus"]
    physical_relations = reference["physical_relation_corpus"]
    inventory_contract = scale_contracts["inventory"]
    projection_contract = scale_contracts["projection"]
    workcard_contract = scale_contracts["workcard"]
    file_count = reference["file_count"]
    runtime_queries = reference["query_count"]
    depths = list(semantic["depths"])
    quotient, remainder = divmod(runtime_queries, len(depths))
    depth_counts = {
        str(depth): quotient + (index < remainder)
        for index, depth in enumerate(depths)
    }
    profile_id, profile = next(iter(reference["performance_profiles"].items()))
    thresholds = {
        key: value for key, value in profile.items() if key.endswith("_max")
    }
    observed = {
        "p50_ms": 0,
        "p95_ms": 0,
        "p99_ms": 0,
        "peak_rss_bytes": 0,
        "database_bytes": 0,
        "projection_amplification": 0,
        "semantic_inflation": 0,
    }
    return {
        "physical": {
            "files": file_count,
            "raw_files": file_count,
            # Physical files are represented by the bound raw stream, not by
            # one semantic Artifact per file.
            "semantic_proxies": file_count
            * inventory_contract["semantic_artifacts_per_raw_file"],
            "raw_file_proxies": file_count
            * inventory_contract["physical_inventory_records_per_raw_file"],
            "physical_artifact_evidence": file_count
            * inventory_contract["physical_inventory_records_per_raw_file"],
            "raw_file_proxy_ratio": reference["raw_file_proxy_ratio"],
            "synthetic_tasks": file_count
            * inventory_contract["synthetic_tasks_per_raw_file"],
            "synthetic_task_count": file_count
            * inventory_contract["synthetic_tasks_per_raw_file"],
            "synthetic_task_ratio": reference["synthetic_task_ratio"],
            "inventory_relations": file_count
            * inventory_contract["synthetic_relations_per_raw_file"],
            # The semantic fixture Relations remain separate from the exact
            # physical relation evidence carried by the raw route.
            "relations": semantic["relation_count"],
            "physical_relation_evidence_count": physical_relations[
                "total_core_valid_relations"
            ],
            "semantic_control_records": semantic["task_count"]
            + inventory_contract["physical_bucket_count"]
            + semantic["relation_count"]
            + 5,
            "semantic_control_envelopes": semantic["task_count"]
            + inventory_contract["physical_bucket_count"]
            + 5,
            "semantic_control_record_limit": inventory_contract[
                "semantic_control_record_limit"
            ],
            "explicit_semantic_corpus": {
                "task_count": semantic["task_count"]
                + inventory_contract["physical_bucket_count"],
                "relation_count": semantic["relation_count"],
                "depths": depths,
                "harness_generated": True,
                "product_acceptance_credit": False,
                # This is intentionally only a bounded shape.  The physical
                # validator must still receive and verify the actual raw
                # stream before this shape can be considered evidence.
                "physical_bucket_control": {
                    "record_type": "PhysicalBucketControlManifest",
                    "generation": "streamed-inventory-aggregate",
                    "candidate_digest": ZERO,
                    "inventory_identity_digest": ZERO,
                    "bucket_count": inventory_contract["physical_bucket_count"],
                    "files_per_bucket": inventory_contract[
                        "physical_files_per_bucket"
                    ],
                    "file_count": file_count,
                    "aggregate_digest": ZERO,
                    "cardinality": {
                        "minimum": 1000,
                        "maximum": 1000,
                        "distinct": 1,
                    },
                    "semantic_control_record_count": inventory_contract[
                        "physical_bucket_count"
                    ],
                    "semantic_control_envelope_count": inventory_contract[
                        "physical_bucket_count"
                    ],
                    "semantic_control_record_limit": inventory_contract[
                        "semantic_control_record_limit"
                    ],
                },
            },
        },
        "inventory": {
            "passes": reference["inventory_passes"],
            "entries": file_count,
            "stream_bytes": 1,
            "candidate_digest": ZERO,
        },
        "projection": {
            "initial_inventory_passes": reference["inventory_passes"],
            "initial_product_passes": projection_contract[
                "rebuild_product_tree_passes"
            ],
            "rebuild_inventory_passes": reference["inventory_passes"],
            "rebuild_product_passes": projection_contract[
                "rebuild_product_tree_passes"
            ],
            "equal_semantic_digest": True,
            "database_bytes": observed["database_bytes"],
            "projection_amplification": observed["projection_amplification"],
            "semantic_inflation": observed["semantic_inflation"],
        },
        "search": {
            "actual_runtime_queries": runtime_queries,
            "depth_min": min(depths),
            "depth_max": max(depths),
            "depth_counts": depth_counts,
            "forced_depths": depths,
            "continuation_union_complete": True,
            "continuation_union_completeness": workcard_contract[
                "selected_closure_union_completeness"
            ],
            "silent_truncations": reference["silent_truncations_max"],
            "broad_query_refinement_required": True,
            "high_cardinality_terms_verified": True,
            "content_search_verified": True,
            "miss_behavior_verified": True,
            "hostile_proxy_content_verified": True,
            "exact_artifact_search_verified": True,
            "mixed_query_classes_complete": True,
            "continuation_state": {
                "maximum_bytes": workcard_contract[
                    "continuation_state_bytes_max"
                ]
            },
            "maximum_continuation_token_bytes": workcard_contract[
                "continuation_token_bytes_max"
            ],
            "continuation_token_overhead_at_most_10_percent": True,
            "p50_ms": observed["p50_ms"],
            "p95_ms": observed["p95_ms"],
            "p99_ms": observed["p99_ms"],
        },
        "resources": {"peak_rss_bytes": observed["peak_rss_bytes"]},
        "performance": {
            "profile_id": profile_id,
            "compatible_platforms": profile["compatible_platforms"],
            "requires_same_runner_no_degradation": profile[
                "requires_same_runner_no_degradation"
            ],
            "thresholds": thresholds,
            "observed": observed,
            "predicates": {
                "p50_within_profile": True,
                "p95_within_profile": True,
                "p99_within_profile": True,
                "peak_rss_within_profile": True,
                "database_within_profile": True,
                "projection_amplification_within_profile": True,
                "semantic_inflation_within_profile": True,
            },
            "all_within_profile": True,
        },
    }


class MutationHarness:
    def __init__(self, root: Path) -> None:
        self._production = ProductionMutationFixture(root, PACKAGE_ROOT)
        self.root = self._production.root
        self.bundle = self._production.bundle
        self.relation_domains = self._production.relation_domains

    def event_store(self, name: str = "events") -> EventStore:
        return self._production.event_store(name)

    def projection(self, name: str = "projection.sqlite3") -> Projection:
        return self._production.projection(name)

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
                "payload": {"record_type": "Artifact", "label": "needle"},
            },
        }

    @staticmethod
    def verified_inventory(*rows: dict[str, Any]):
        from promin.canonical import canonical_bytes
        from promin.projection import VerifiedInventoryInput

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

    def init_request(self) -> tuple[Path, InitRequest, dict[str, Path]]:
        project = self.root / "product"
        project.mkdir(parents=True)
        provider = Path(sys.executable).resolve()
        license_value = {
            "expression": "MIT",
            "source_uris": ["https://spdx.org/licenses/MIT.html"],
            "review_state": "source-verified",
        }
        required = [
            "control-runtime",
            "shape-validation",
            "content-identity",
            "local-serialization",
            "query-projection",
        ]
        bindings = [
            {
                "capability_id": capability,
                "provider_id": f"provider-{index}",
                "version": sys.version.split()[0],
                "invocation": {"kind": "python-runtime", "value": str(provider)},
                "purpose": capability,
                "required": True,
                "healthcheck": {"argv": [str(provider), "--version"], "timeout_ms": 10000, "expected_exit": 0},
                "license": license_value,
                "identity": {"kind": "file-digest", "digest": digest_file(provider), "source": str(provider)},
            }
            for index, capability in enumerate(required, 1)
        ]
        for binding in bindings:
            binding["dependency_receipt"] = build_provider_dependency_receipt(
                binding, project
            )
        plans: dict[str, Any] = {
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
                "preset_id": "semantic-standard",
                "operating_profile": "baseline",
            },
            "standards_plan": {"record_type": "StandardsInit", "bindings": []},
            "technologies_plan": {"record_type": "TechnologiesInit", "bindings": bindings},
            "licenses_plan": {
                "record_type": "LicensesPlan",
                "bindings": [{"provider_id": item["provider_id"], "license": item["license"]} for item in bindings],
            },
            "authority_plan": {
                "record_type": "AuthorityInit",
                "trust_mode": "local-owner",
                "subjects": [{"subject_id": "owner", "kind": "human", "display_name": "Owner"}],
                "roots": [
                    {
                        "subject_id": "owner",
                        "capability_ceiling": ["standard.activate", "task.plan", "task.execute"],
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
        request = InitRequest(
            project_root=project,
            standard_bundle=PACKAGE_ROOT,
            preset_path=PRESET,
            **paths,
        )
        return project, request, paths


def _invalid_gate() -> dict[str, Any]:
    value = _gate_result()
    value["status"] = "pass"
    value["pass_credit"] = True
    value["evidence_artifacts"] = []
    return value


def _r_status_credit(h: MutationHarness) -> None:
    value = _gate_result()
    value["status"] = "fail"
    value["pass_credit"] = True
    validate_ingress(h.bundle, value, operation="import")


def _r_missing(h: MutationHarness) -> None:
    value = _task(); del value["task_id"]
    validate_ingress(h.bundle, value, operation="import")


def _r_unknown(h: MutationHarness) -> None:
    value = _task(); value["unknown"] = True
    validate_ingress(h.bundle, value, operation="import")


def _r_activation(h: MutationHarness) -> None:
    validate_ingress(h.bundle, _task(), operation="replay", context={"activation_digest": ONE})


def _r_grant_replay(h: MutationHarness) -> None:
    engine, grants = _engine_with_grants()
    init = _authority_init()
    duplicate = _grant(init, "grant:duplicate", "worker", "task.execute", issuer=grants["root"], nonce=grants["planner"]["nonce"])
    _persist_grant(engine, init, duplicate, issuer=grants["root"])


def _scoped_engine() -> tuple[AuthorityEngine, dict[str, Any]]:
    init = _authority_init(); engine = AuthorityEngine(init, ZERO, _authority_runtime_policy())
    root = _grant(init, "grant:root", "root", "authority.manage")
    _persist_grant(engine, init, root)
    child = _grant(
        init,
        "grant:scoped",
        "planner",
        "task.plan",
        issuer=root,
        scope=[{"kind": "project", "value": "P"}, {"kind": "path", "value": "src"}],
    )
    _persist_grant(engine, init, child, issuer=root)
    return engine, child


def _r_scope_escalation(h: MutationHarness) -> None:
    engine, grant = _scoped_engine()
    engine.authorize("planner", "task.plan", [{"kind": "all", "value": "*"}], grant["grant_id"], grant["claim_digest"], "2026-02-01T00:00:00Z")


def _r_expired(h: MutationHarness) -> None:
    engine, grants = _engine_with_grants(); grant = grants["planner"]
    engine.authorize("planner", "task.plan", [{"kind": "all", "value": "*"}], grant["grant_id"], grant["claim_digest"], "2029-01-01T00:00:00Z")


def _r_revoked(h: MutationHarness) -> None:
    engine, grants = _engine_with_grants(); grant = grants["planner"]
    engine.revoke_grant({"grant_id": grant["grant_id"], "decision_id": "decision:revoke", "reason": "test", "revoked_at": "2026-02-01T00:00:00Z"}, grants["root"]["grant_id"], "root")
    engine.authorize("planner", "task.plan", [{"kind": "all", "value": "*"}], grant["grant_id"], grant["claim_digest"], "2026-02-02T00:00:00Z")


def _domain_ready(
    h: MutationHarness,
) -> tuple[DomainState, dict[str, dict[str, Any]], dict[str, Any]]:
    engine, grants = _engine_with_grants()
    policy = production_runtime_policy(h._production)
    domain = DomainState(
        engine,
        EvidenceStore(h.root / "cas"),
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
    grants: dict[str, dict[str, Any]],
    *,
    holder_grant: str | None = None,
    state: str = "ACTIVE",
) -> dict[str, Any]:
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


def _r_stale_fence(h: MutationHarness) -> None:
    domain, grants, policy = _domain_ready(h); domain.acquire_lease(_lease(grants), _authorization(grants["manager"]), parallelism_policy=policy)
    domain.heartbeat_lease("lease:1", 1, 0, "2026-02-01T00:01:00Z", "2026-02-01T00:11:00Z", _authorization(grants["worker"]))


def _r_candidate_drift(h: MutationHarness) -> None:
    store = EvidenceStore(h.root / "cas")
    payload = b"evidence"
    artifact = {
        "record_type": "Artifact",
        "artifact_id": "evidence:1",
        "artifact_kind": "evidence",
        "digest": digest_bytes(payload),
        "media_type": "text/plain",
        "size_bytes": len(payload),
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
        "evidence_class": "product-execution",
        "evidence_purpose": "product",
        "product_credit_eligible": True,
    }
    command = {
        "record_type": "CommandRequest",
        "command_id": "command:evidence:1",
        "command_kind": "artifact.record",
        "subject_id": "worker",
        "activation_digest": ZERO,
        "idempotency_key": "evidence-candidate-drift-0001",
        "requested_scope": [{"kind": "all", "value": "*"}],
        "expected_head_digest": None,
        "issued_at": NOW,
        "payload": artifact,
        "intent_digest": ZERO,
        "authorization": {
            "kind": "grant",
            "grant_id": "grant:evidence-publisher",
            "grant_claim_digest": "6" * 64,
        },
        "holder_authorization": {
            "kind": "grant",
            "grant_id": "grant:task-holder",
            "grant_claim_digest": "7" * 64,
        },
        "workcard_task_id": "task:evidence:1",
        "lease_id": "lease:evidence:1",
        "lease_generation": 1,
        "fencing_token": 1,
        "workcard_digest": "8" * 64,
        "context_digest": "9" * 64,
    }
    command["intent_digest"] = event_digest(command_intent_identity(command))
    command_digest = event_digest(command)
    store.stage(artifact, payload, command_digest=command_digest)
    events = h.event_store("evidence-events")
    events.commit(command, created_at=NOW)
    store.finalize(
        artifact,
        command_digest=command_digest,
        envelope=next(events.iter_envelopes()),
    )
    store.reconcile(events.iter_envelopes())
    artifact_reference = store.artifact_reference(artifact["artifact_id"])
    store.require_creditable(
        artifact_reference["artifact_id"],
        artifact_reference["artifact_record_digest"],
        candidate_digest="5" * 64,
        policy_digest="2" * 64,
        tool_digest="3" * 64,
        input_digests=["4" * 64],
        provider_invocation_digests=[
            canonical_digest(invocation)
            for invocation in artifact["evidence_binding"]["provider_invocations"]
        ],
        activation_digest=ZERO,
        implementation_closure_digest=IMPLEMENTATION_CLOSURE_DIGEST,
        evidence_class="product-execution",
        purpose="product",
        finding_digest=None,
        require_product_credit=True,
    )


def _r_provider_substitution(h: MutationHarness) -> None:
    project, request, _ = h.init_request(); initialize_project(request)
    technologies = project / ".promin" / "init" / "technologies.json"
    value = json.loads(technologies.read_text(encoding="utf-8")); value["bindings"][0]["identity"]["digest"] = ZERO
    _write_json(technologies, value); ActivationGuard(project).verify()


def _tamper_journal(h: MutationHarness, mutate: Callable[[dict[str, Any]], None]) -> None:
    store = h.event_store(); store.commit(_command(1), created_at=NOW)
    path = next(store.journal.glob("*.json")); value = json.loads(path.read_text(encoding="utf-8")); mutate(value)
    path.write_bytes(
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    )
    h.event_store()


def _r_event_fork(h: MutationHarness) -> None:
    _tamper_journal(h, lambda value: value["batch"].__setitem__("previous_digest", "f" * 64))


def _r_batch_mismatch(h: MutationHarness) -> None:
    _tamper_journal(h, lambda value: value["batch"].__setitem__("command_id", "command:attacker"))


def _r_duplicate_idempotency(h: MutationHarness) -> None:
    store = h.event_store(); key = "same-idempotency-key"
    store.commit(_command(1, key=key), created_at=NOW)
    store.commit(_command(2, store.head()["batch_digest"], key=key), created_at=NOW)


def _r_projection_corruption(h: MutationHarness) -> None:
    projection = h.projection(); row = h.projection_row()
    projection.rebuild(h.event_store(), inventory=h.verified_inventory(row))
    projection.db_path.write_bytes(b"not sqlite"); projection.status()


def _r_projection_stale(h: MutationHarness) -> None:
    store = h.event_store(); projection = h.projection(); row = h.projection_row()
    projection.rebuild(store, inventory=h.verified_inventory(row))
    store.commit(_command(1), created_at=NOW); projection.require_current(store)


def _r_reference_break(h: MutationHarness) -> None:
    row = h.projection_row(dangling=True)
    h.projection().rebuild(h.event_store(), inventory=h.verified_inventory(row))


def _r_relation_domain(h: MutationHarness) -> None:
    row = h.projection_row(wrong_domain=True)
    h.projection().rebuild(h.event_store(), inventory=h.verified_inventory(row))


def _r_context_flood(h: MutationHarness) -> None:
    projection = h.projection(); row = h.projection_row()
    projection.rebuild(h.event_store(), inventory=h.verified_inventory(row))
    projection.search("needle", budget={"max_bytes": 16385, "max_entities": 32, "max_relations": 48, "max_fanout_per_entity": 8, "top_k": 12})


def _special_archive(h: MutationHarness, names: list[str], *, symlink: bool = False, expansion: bool = False) -> Path:
    path = h.root / "invalid.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)); info.create_system = 3
            info.external_attr = ((stat.S_IFLNK if symlink else stat.S_IFREG) | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, b"0" * (4 * 1024 * 1024) if expansion else b"x")
    return path


def _r_symlink_core(h: MutationHarness) -> None:
    verify_archive(_special_archive(h, ["promin/core/semantic-model.json"], symlink=True))


def _r_shadow_core(h: MutationHarness) -> None:
    target = h.root / "core"; shutil.copytree(CORE, target); (target / "shadow.json").write_text("{}", encoding="utf-8")
    verify_core(target)


def _r_symlink_product(h: MutationHarness) -> None:
    verify_archive(_special_archive(h, ["promin/product/link"], symlink=True))


def _r_secret_export(h: MutationHarness) -> None:
    root = h.root / "distribution"; root.mkdir(); (root / ".env").write_text("TOKEN=value", encoding="utf-8")
    scan_distribution(root)


def _r_archive_expansion(h: MutationHarness) -> None:
    verify_archive(_special_archive(h, ["promin/payload.bin"], expansion=True))


def _r_preset_authority(h: MutationHarness) -> None:
    value = deepcopy(h.bundle.preset); value["authority"] = {"grant": "all"}
    path = _write_json(h.root / "preset.json", value); verify_preset(path, h.bundle.core)


def _r_normalization_collision(h: MutationHarness) -> None:
    parse_json_strict('{"é":1,"é":2}'.encode("utf-8"))


def _r_path_casefold(h: MutationHarness) -> None:
    verify_archive(_special_archive(h, ["promin/A.txt", "promin/a.txt"]))


def _r_forbidden_name(h: MutationHarness) -> None:
    root = h.root / "distribution"; root.mkdir(); (root / "bad.txt").write_text("agent" + "doc", encoding="utf-8")
    scan_distribution(root)


def _r_reinit_conflict(h: MutationHarness) -> None:
    _, request, paths = h.init_request(); initialize_project(request)
    value = json.loads(paths["project_plan"].read_text(encoding="utf-8")); value["project_id"] = "project-conflict"
    alternate = _write_json(h.root / "plans" / "alternate.json", value)
    initialize_project(replace(request, project_plan=alternate))


def _r_clock_order(h: MutationHarness) -> None:
    h.event_store().commit(_command(1), created_at="2026-07-17T11:59:59Z")


def _r_capability_confusion(h: MutationHarness) -> None:
    engine, grants = _engine_with_grants(); grant = grants["planner"]
    engine.authorize("planner", "release.decide", [{"kind": "all", "value": "*"}], grant["grant_id"], grant["claim_digest"], "2026-02-01T00:00:00Z")


def _r_command_scope(h: MutationHarness) -> None:
    _r_scope_escalation(h)


def _r_issuer_chain(h: MutationHarness) -> None:
    init = _authority_init(); engine = AuthorityEngine(init, ZERO, _authority_runtime_policy())
    root = _grant(init, "grant:root", "root", "authority.manage")
    _persist_grant(engine, init, root)
    missing = _grant(init, "grant:orphan", "planner", "task.plan", issuer=root)
    missing["trust_proofs"][0]["issuer_grant_id"] = "grant:missing"
    _persist_grant(engine, init, missing, issuer=root)


def _r_unverified_signature(h: MutationHarness) -> None:
    init = _authority_init(team=True); engine = AuthorityEngine(init, ZERO, _authority_runtime_policy())
    value = _grant(init, "grant:signed", "root", "authority.manage")
    value["trust_proofs"] = [{"kind": "signature", "key_id": "key-root", "algorithm": "test-ed25519-boundary", "signed_digest": value["claim_digest"], "signature": "opaque"}]
    command = _grant_issue_command(init, value)
    command["authorization"]["proofs"] = [{
        "kind": "signature-command",
        "key_id": "key-root",
        "algorithm": "test-ed25519-boundary",
        "signed_intent_digest": command["intent_digest"],
        "signature": "opaque",
    }]
    receipt = engine.authorize_grant_issue_command(command)
    engine.issue_grant(value, value["issued_at"], issue_authorization=receipt)


def _r_provider_unavailable(h: MutationHarness) -> None:
    _, request, paths = h.init_request(); value = json.loads(paths["technologies_plan"].read_text(encoding="utf-8"))
    value["bindings"][0]["healthcheck"]["argv"] = [str(h.root / "missing-provider.exe")]
    _write_json(paths["technologies_plan"], value); initialize_project(request)


def _r_illegal_task(h: MutationHarness) -> None:
    engine, grants = _engine_with_grants(); domain = DomainState(engine, EvidenceStore(h.root / "cas")); domain.record_task(_task(), _authorization(grants["planner"]))
    domain.transition_task({"task_id": "task:focused", "from_state": "PLANNED", "to_state": "COMPLETED", "reason": "skip"}, _authorization(grants["planner"]))


def _r_illegal_lease(h: MutationHarness) -> None:
    domain, grants, policy = _domain_ready(h); domain.acquire_lease(_lease(grants, state="CLOSED"), _authorization(grants["manager"]), parallelism_policy=policy)


def _r_decision_target(h: MutationHarness) -> None:
    value = _decision(); value["target_type"] = "Finding"
    validate_ingress(h.bundle, value, operation="import")


def _r_credit_without_evidence(h: MutationHarness) -> None:
    validate_ingress(h.bundle, _invalid_gate(), operation="import")


def _r_primary_mismatch(h: MutationHarness) -> None:
    _tamper_journal(h, lambda value: value["batch"]["events"][0].__setitem__("payload", {"record_type": "Task", "task_id": "task:other"}))


def _r_duplicate_event(h: MutationHarness) -> None:
    store = h.event_store(); relation = h.relation()
    store.commit(_command(1), auxiliary_relations=[relation, relation], created_at=NOW)


def _r_selector_drop(h: MutationHarness) -> None:
    engine, grant = _scoped_engine()
    engine.authorize("planner", "task.plan", [{"kind": "project", "value": "P"}], grant["grant_id"], grant["claim_digest"], "2026-02-01T00:00:00Z")


def _r_claim_substitution(h: MutationHarness) -> None:
    engine, grants = _engine_with_grants(); grant = grants["planner"]
    engine.authorize("planner", "task.plan", [{"kind": "all", "value": "*"}], grant["grant_id"], "f"*64, "2026-02-01T00:00:00Z")


def _r_effect_outside_scope(h: MutationHarness) -> None:
    command = _command(1); command["requested_scope"] = [{"kind": "task", "value": "task:other"}]
    command["intent_digest"] = event_digest(command_intent_identity(command))
    _validate_effect_scope(h.bundle, command, {})


def _r_holder_grant(h: MutationHarness) -> None:
    domain, grants, policy = _domain_ready(h); domain.acquire_lease(_lease(grants, holder_grant=grants["planner"]["grant_id"]), _authorization(grants["manager"]), parallelism_policy=policy)


def _r_decision_provenance(h: MutationHarness) -> None:
    engine, grants = _engine_with_grants(); domain = DomainState(engine, EvidenceStore(h.root / "cas"))
    candidate = {
        "record_type": "Candidate",
        "candidate_id": "candidate:1",
        "candidate_digest": ONE,
        "inventory_digest": "2" * 64,
        "product_root_digest": "3" * 64,
        "candidate_recipe_digest": "4" * 64,
        "consistency_mode": "observational-best-effort",
        "creditable": False,
        "control_excluded": True,
    }
    domain.record_candidate(candidate, _authorization(grants["worker"]))
    decision = {"record_type": "Decision", "decision_id": "decision:1", "decision_kind": "reject", "subject_id": "approver", "grant_id": "grant:wrong", "activation_digest": ZERO, "candidate_digest": ONE, "target_type": "Candidate", "target_id": "candidate:1", "rationale": "reject", "evidence_digests": ["4"*64], "created_at": NOW}
    domain.record_decision(decision, _authorization(grants["approver"]))


def _r_artifact_capability(h: MutationHarness) -> None:
    engine, grants = _engine_with_grants(); grant = grants["worker"]
    command = _command(1); command["command_kind"] = "artifact.record"; command["payload"] = {"record_type": "Artifact", "artifact_id": "artifact:1", "artifact_kind": "evidence"}
    capability = _required_capability(h.bundle, command)
    engine.authorize("worker", capability, [{"kind": "all", "value": "*"}], grant["grant_id"], grant["claim_digest"], "2026-02-01T00:00:00Z")


def _r_production_mutation(family: str, h: MutationHarness) -> None:
    result = run_mutation(family, h.root, PACKAGE_ROOT)
    if result.family != family or not result.exception_type or not result.message:
        raise AssertionError(f"{family} production mutation result is incomplete")
    raise ExplicitNonCredit(
        f"production mutation rejected: {result.exception_type}: {result.message}"
    )


MUTATION_RUNNERS: dict[str, Callable[[MutationHarness], None]] = {
    "status-credit-contradiction": _r_status_credit,
    "missing-critical-field": _r_missing,
    "unknown-critical-field": _r_unknown,
    "activation-drift": _r_activation,
    "grant-replay": _r_grant_replay,
    "scope-escalation": _r_scope_escalation,
    "expired-grant": _r_expired,
    "revoked-grant": _r_revoked,
    "stale-fence": _r_stale_fence,
    "candidate-drift": _r_candidate_drift,
    "provider-substitution": _r_provider_substitution,
    "event-fork": _r_event_fork,
    "batch-command-mismatch": _r_batch_mismatch,
    "duplicate-idempotency-key": _r_duplicate_idempotency,
    "projection-corruption": _r_projection_corruption,
    "projection-staleness": _r_projection_stale,
    "reference-break": _r_reference_break,
    "relation-domain-break": _r_relation_domain,
    "context-flood": _r_context_flood,
    "symlink-core-input": _r_symlink_core,
    "shadow-core-file": _r_shadow_core,
    "symlink-product-entry": _r_symlink_product,
    "secret-export": _r_secret_export,
    "archive-expansion": _r_archive_expansion,
    "preset-authority-escalation": _r_preset_authority,
    "normalization-key-collision": _r_normalization_collision,
    "path-casefold-collision": _r_path_casefold,
    "forbidden-name-reintroduction": _r_forbidden_name,
    "reinit-configuration-conflict": _r_reinit_conflict,
    "clock-order-violation": _r_clock_order,
    "capability-confusion": _r_capability_confusion,
    "command-scope-escalation": _r_command_scope,
    "grant-issuer-chain-break": _r_issuer_chain,
    "unverified-signature-acceptance": _r_unverified_signature,
    "provider-declared-but-unavailable": _r_provider_unavailable,
    "illegal-task-transition": _r_illegal_task,
    "illegal-lease-transition": _r_illegal_lease,
    "decision-target-confusion": _r_decision_target,
    "credit-without-evidence": _r_credit_without_evidence,
    "command-primary-event-mismatch": _r_primary_mismatch,
    "duplicate-event-id": _r_duplicate_event,
    "scope-selector-drop-broadening": _r_selector_drop,
    "authorization-grant-claim-substitution": _r_claim_substitution,
    "command-effect-outside-requested-scope": _r_effect_outside_scope,
    "lease-holder-grant-mismatch": _r_holder_grant,
    "decision-grant-provenance-mismatch": _r_decision_provenance,
    "artifact-kind-capability-confusion": _r_artifact_capability,
    "continuation-frontier-loss": partial(_r_production_mutation, "continuation-frontier-loss"),
    "continuation-duplicate-emission": partial(_r_production_mutation, "continuation-duplicate-emission"),
    "candidate-recipe-bypass": partial(_r_production_mutation, "candidate-recipe-bypass"),
    "observational-candidate-pass-credit": partial(_r_production_mutation, "observational-candidate-pass-credit"),
    "snapshot-provider-substitution": partial(_r_production_mutation, "snapshot-provider-substitution"),
    "unsupported-provider-adapter": partial(_r_production_mutation, "unsupported-provider-adapter"),
    "stale-release-closure-credit": partial(_r_production_mutation, "stale-release-closure-credit"),
    "finding-evidence-target-mismatch": partial(_r_production_mutation, "finding-evidence-target-mismatch"),
    "candidate-delta-scope-escape": partial(_r_production_mutation, "candidate-delta-scope-escape"),
    "checkpoint-head-mismatch": partial(_r_production_mutation, "checkpoint-head-mismatch"),
    "checkpoint-corruption-credit": partial(_r_production_mutation, "checkpoint-corruption-credit"),
    "normal-command-full-replay": partial(_r_production_mutation, "normal-command-full-replay"),
    "profile-default-depth-bypass": partial(_r_production_mutation, "profile-default-depth-bypass"),
    "continuation-public-material-mismatch": partial(_r_production_mutation, "continuation-public-material-mismatch"),
    "inventory-provenance-override": partial(_r_production_mutation, "inventory-provenance-override"),
    "implementation-closure-drift": partial(_r_production_mutation, "implementation-closure-drift"),
    "noncanonical-archive-layout": partial(_r_production_mutation, "noncanonical-archive-layout"),
    "inventory-graph-inflation": partial(_r_production_mutation, "inventory-graph-inflation"),
    "workcard-budget-bypass": partial(_r_production_mutation, "workcard-budget-bypass"),
    "fabricated-evidence-digest": partial(_r_production_mutation, "fabricated-evidence-digest"),
    "unsigned-standard-decision": partial(_r_production_mutation, "unsigned-standard-decision"),
    "unconfigured-standard-decision-key": partial(_r_production_mutation, "unconfigured-standard-decision-key"),
    "standard-decision-version-replay": partial(_r_production_mutation, "standard-decision-version-replay"),
    "candidate-decision-cycle": partial(_r_production_mutation, "candidate-decision-cycle"),
    "broad-query-corpus-pagination": partial(_r_production_mutation, "broad-query-corpus-pagination"),
    "continuation-token-context-inflation": partial(_r_production_mutation, "continuation-token-context-inflation"),
    "inventory-stream-materialization": partial(_r_production_mutation, "inventory-stream-materialization"),
    "pdf-header-only-credit": partial(_r_production_mutation, "pdf-header-only-credit"),
    "scale-environment-skip-credit": partial(_r_production_mutation, "scale-environment-skip-credit"),
    "content-search-omission": partial(_r_production_mutation, "content-search-omission"),
}


REQUIREMENT_SOURCE_SHA256 = "2e9fb27c1f3e76d33dbf613de3aac78e5aa8a76280c820588ba878106296b804"
INTEGRITY_REQUIREMENTS: dict[str, tuple[str, str]] = {
    "R1": ("Canonical distribution", "noncanonical-archive-layout"),
    "R2": ("Install verification semantics", "provider-declared-but-unavailable"),
    "R3": ("Continuation authorization", "continuation-public-material-mismatch"),
    "R4": ("Inventory graph minimality", "inventory-graph-inflation"),
    "R5": ("Scale acceptance", "workcard-budget-bypass"),
    "R6": ("Provider implementation closure", "implementation-closure-drift"),
    "R7": ("Snapshot-mode reduction", "snapshot-provider-substitution"),
    "R8": ("Projection provenance", "inventory-provenance-override"),
    "R9": ("Command-surface reduction", "capability-confusion"),
    "R10": ("Evidence context", "workcard-budget-bypass"),
    "R11": ("Release-state separation", "stale-release-closure-credit"),
    "R12": ("Release evidence and platform gate", "noncanonical-archive-layout"),
}
INTEGRITY_SURFACES = {
    "S1": "schema/canonicalization",
    "S2": "semantic/policy",
    "S3": "authority/trust",
    "S4": "lifecycle/events/evidence",
    "S5": "projection/search/performance",
    "S6": "package/CLI/docs/migration",
}
INTEGRITY_DEPTHS = {
    "D1": "local representation/input",
    "D2": "immediate validation/invariant",
    "D3": "authority or state transition",
    "D4": "replay/derived state",
    "D5": "agent/operator workflow and cost",
    "D6": "release/cutover/rollback",
}


@dataclass(frozen=True)
class ImpactGuard:
    repair_id: str
    repair: str
    surface_id: str
    surface: str
    depth_id: str
    depth: str
    mutation_family: str
    validator: Callable[[dict[str, Any], Any, dict[str, Any]], None]

    def execute(self, bundle: Any) -> str:
        try:
            self.validator({}, bundle, {})
        except ConformanceError as exc:
            if not str(exc):
                raise AssertionError(f"{self.repair_id} failed closed without a reason") from exc
            return "fail-closed"
        return "pass"


INTEGRITY_REQUIREMENT_VALIDATORS = integrity_requirement_catalogue()
IMPACT_GUARD_REGISTRY: dict[tuple[str, str, str], ImpactGuard] = {
    (repair_id, surface_id, depth_id): ImpactGuard(
        repair_id=repair_id,
        repair=repair,
        surface_id=surface_id,
        surface=surface,
        depth_id=depth_id,
        depth=depth,
        mutation_family=mutation_family,
        validator=INTEGRITY_REQUIREMENT_VALIDATORS[repair_id],
    )
    for repair_id, (repair, mutation_family) in INTEGRITY_REQUIREMENTS.items()
    for surface_id, surface in INTEGRITY_SURFACES.items()
    for depth_id, depth in INTEGRITY_DEPTHS.items()
}

class ContractMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)

    def _reject(self, value: object, operation: str = "import", **kwargs: object) -> None:
        with self.assertRaises(ContractError):
            validate_ingress(self.bundle, value, operation=operation, **kwargs)

    def test_mutation_catalogue_exactly_tracks_core(self) -> None:
        conformance = json.loads((CORE / "conformance.json").read_text(encoding="utf-8"))
        self.assertEqual(set(conformance["mutation_families"]), set(MUTATION_RUNNERS))
        self.assertEqual(len(conformance["mutation_families"]), len(MUTATION_RUNNERS))
        self.assertEqual(len(MUTATION_RUNNERS), 77)

    def test_core_cardinalities_and_exact_result_surfaces_are_frozen(self) -> None:
        semantic = self.bundle.core["semantic-model.json"]
        policies = self.bundle.core["policy-set.json"]
        conformance = self.bundle.core["conformance.json"]
        authority = self.bundle.core["authority-model.json"]
        definitions = self.bundle.schema["$defs"]
        inventory_contract = conformance["scale_contracts"]["inventory"]
        self.assertIn(PHYSICAL_ACCEPTANCE_ID, conformance["required_acceptance"])
        self.assertNotIn(
            LEGACY_PHYSICAL_ACCEPTANCE_ID, conformance["required_acceptance"]
        )
        conformance_text = json.dumps(conformance, sort_keys=True)
        self.assertNotIn(LEGACY_PHYSICAL_ACCEPTANCE_ID, conformance_text)
        self.assertNotIn("derived_artifact_proxies_per_raw_file", conformance_text)
        self.assertIn(PHYSICAL_ACCEPTANCE_ID, ACCEPTANCE_VALIDATORS)
        self.assertNotIn(LEGACY_PHYSICAL_ACCEPTANCE_ID, ACCEPTANCE_VALIDATORS)
        self.assertEqual(inventory_contract["semantic_artifacts_per_raw_file"], 0)
        self.assertEqual(inventory_contract["physical_inventory_records_per_raw_file"], 1)
        self.assertEqual(inventory_contract["physical_bucket_count"], 100)
        self.assertEqual(inventory_contract["physical_files_per_bucket"], 1000)
        self.assertEqual(inventory_contract["semantic_control_record_limit"], 256)
        self.assertNotIn("derived_artifact_proxies_per_raw_file", inventory_contract)
        self.assertNotIn("derived_artifact_proxies_per_raw_file", conformance)
        self.assertEqual(len(semantic["persistent_entities"]), 9)
        self.assertEqual(len(semantic["relations"]), 6)
        self.assertEqual(len(policies["policies"]), 68)
        self.assertEqual(len(conformance["required_acceptance"]), 102)
        self.assertEqual(len(conformance["mutation_families"]), 77)
        self.assertEqual(authority["event_contract"]["events_per_batch_max"], 128)
        self.assertEqual(
            authority["event_contract"]["state_binding_updates_per_batch_max"],
            128,
        )
        self.assertEqual(authority["event_contract"]["command_bytes_max"], 1_048_576)
        self.assertEqual(
            authority["event_contract"]["state_binding_bytes_max"], 1_048_576
        )
        self.assertEqual(authority["event_contract"]["envelope_bytes_max"], 2_097_152)
        self.assertEqual(
            definitions["EventBatch"]["properties"]["events"]["maxItems"],
            128,
        )
        self.assertEqual(
            definitions["EventBatch"]["properties"]["state_binding_delta"][
                "maxItems"
            ],
            128,
        )
        self.assertEqual(
            definitions["EventStorePolicy"]["properties"]["max_events_per_batch"][
                "const"
            ],
            128,
        )
        self.assertEqual(
            definitions["EventStorePolicy"]["properties"][
                "max_state_binding_updates_per_batch"
            ]["const"],
            128,
        )
        self.assertEqual(
            authority["event_contract"]["command_conditional_fields"],
            ["definition_digest"],
        )
        self.assertEqual(
            authority["command_mutation_claim_rule"]["lease_bound_command_kinds"],
            ["artifact.record", "run.record", "gate.record", "finding.record"],
        )
        self.assertNotIn(
            "candidate.record",
            authority["command_mutation_claim_rule"]["lease_bound_command_kinds"],
        )
        expected_envelope = {
            "record_type",
            "status",
            "subject_id",
            "activation_digest",
            "work_card",
            "continuation",
        }
        for name in ("NextResult", "ContinueResult"):
            self.assertEqual(set(definitions[name]["properties"]), expected_envelope)
            self.assertEqual(set(definitions[name]["required"]), expected_envelope)
        self.assertNotIn("continuation", definitions["WorkCardProjection"]["properties"])
        self.assertIn("continuation", definitions["RetrievalPage"]["properties"])
        self.assertEqual(
            policies["derived_result_contracts"]["RetrievalPage"]["query_bytes_max"],
            4096,
        )
        self.assertNotIn(
            "query_bytes_max",
            policies["derived_result_contracts"]["WorkCardProjection"],
        )
        ready_frontier = definitions["ReadyFrontier"]
        expected_ready_frontier = {
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
        self.assertEqual(
            set(ready_frontier["properties"]), expected_ready_frontier
        )
        self.assertEqual(set(ready_frontier["required"]), expected_ready_frontier)
        self.assertEqual(
            ready_frontier["x-promin-persistence"], "derived-live-only"
        )
        artifact = definitions["Artifact"]
        self.assertIn("evidence_purpose", artifact["properties"])
        evidence_rule = next(
            rule
            for rule in artifact["allOf"]
            if rule.get("title")
            == "require replay-complete immutable evidence metadata"
        )
        self.assertIn("evidence_purpose", evidence_rule["then"]["required"])
        finding = definitions["Finding"]
        self.assertIn("evidence_artifacts", finding["properties"])
        self.assertIn("evidence_artifacts", finding["required"])
        self.assertNotIn("evidence_digests", finding["properties"])
        self.assertIn("run_digest", definitions["GateResult"]["required"])
        self.assertEqual(
            set(definitions["GateEvidenceArtifactBinding"]["required"]),
            {"artifact_id", "artifact_record_digest", "run_id", "run_digest"},
        )

    def test_integrity_matrix_executes_all_432_cells(self) -> None:
        expected_keys = {
            (repair_id, surface_id, depth_id)
            for repair_id in INTEGRITY_REQUIREMENTS
            for surface_id in INTEGRITY_SURFACES
            for depth_id in INTEGRITY_DEPTHS
        }
        self.assertEqual(set(IMPACT_GUARD_REGISTRY), expected_keys)
        self.assertEqual(
            set(INTEGRITY_REQUIREMENT_VALIDATORS), set(INTEGRITY_REQUIREMENTS)
        )
        self.assertRegex(REQUIREMENT_SOURCE_SHA256, r"^[0-9a-f]{64}$")

        outcomes: dict[tuple[str, str, str], str] = {}
        for key in sorted(IMPACT_GUARD_REGISTRY):
            guard = IMPACT_GUARD_REGISTRY[key]
            with self.subTest(cell="-".join(key)):
                self.assertIs(
                    guard.validator,
                    INTEGRITY_REQUIREMENT_VALIDATORS[guard.repair_id],
                )
                self.assertIn(guard.mutation_family, MUTATION_RUNNERS)
                outcomes[key] = guard.execute(self.bundle)
                self.assertIn(outcomes[key], {"pass", "fail-closed"})

        self.assertEqual(set(outcomes), expected_keys)
        for repair_id in INTEGRITY_REQUIREMENTS:
            self.assertEqual(
                sum(key[0] == repair_id for key in outcomes),
                36,
            )
        for surface_id in INTEGRITY_SURFACES:
            self.assertEqual(
                sum(key[1] == surface_id for key in outcomes),
                72,
            )
        for depth_id in INTEGRITY_DEPTHS:
            self.assertEqual(
                sum(key[2] == depth_id for key in outcomes),
                72,
            )

    def test_direct_contract_hooks_fail_closed_without_runtime_fixture(self) -> None:
        checks = {
            POLICY_VALIDATORS["continuation_completeness"],
            POLICY_VALIDATORS["candidate_snapshot_consistency"],
            POLICY_VALIDATORS["provider_adapter_dispatch"],
            POLICY_VALIDATORS["current_release_closure"],
            POLICY_VALIDATORS["finding_disposition_evidence"],
            POLICY_VALIDATORS["candidate_delta_scope"],
            POLICY_VALIDATORS["verified_state_checkpoint"],
            POLICY_VALIDATORS["profile_default_depth"],
            POLICY_VALIDATORS["safe_export"],
            ACCEPTANCE_VALIDATORS["candidate-recipe-applied-once"],
            ACCEPTANCE_VALIDATORS["team-signed-cli-end-to-end"],
            ACCEPTANCE_VALIDATORS["safe-recursive-export"],
            ACCEPTANCE_VALIDATORS["candidate-evidence-decision-acyclic-chain"],
            ACCEPTANCE_VALIDATORS["evidence-manifest-physical-resolution"],
            ACCEPTANCE_VALIDATORS["signed-standard-decision-authority-proof"],
            ACCEPTANCE_VALIDATORS["semver-from-candidate-binding"],
            ACCEPTANCE_VALIDATORS["typed-human-document-verification"],
            ACCEPTANCE_VALIDATORS["broad-query-bounded-seed-refinement"],
            ACCEPTANCE_VALIDATORS["continuation-token-bytes-at-most-256"],
            ACCEPTANCE_VALIDATORS["inventory-stream-memory-amplification-at-most-32"],
            ACCEPTANCE_VALIDATORS["explicit-scale-marker-selection"],
        }
        for check in checks:
            with self.subTest(check=check), self.assertRaises(ConformanceError) as raised:
                check({}, self.bundle, {})
            self.assertNotIn("EvidenceStore", str(raised.exception))

    def test_bounded_incremental_commit_hook_reads_validated_nested_metrics(self) -> None:
        baseline = _physical_scale_result_from_core(self.bundle)
        validated = deepcopy(baseline)
        validated["performance"]["observed"].update(
            {
                "runtime_checkpoint_count": 4,
                "runtime_checkpoint_writes": 3,
            }
        )
        validated["contract_predicates"] = {
            "semantic_commit_count_exact": True,
        }
        candidate = {"candidate_binding_digest": "a" * 64}
        source_path = Path("physical-100k-result.json")
        evidence_root = Path("release-evidence")
        context = {
            "physical_100k_result": baseline,
            "standard_release_candidate_binding": candidate,
            "physical_100k_result_path": source_path,
            "standard_release_evidence_root": evidence_root,
        }
        check = ACCEPTANCE_VALIDATORS[
            "bounded-incremental-commit-and-compaction"
        ]

        with patch(
            "promin.evidence.validate_saturation_evidence",
            return_value=validated,
        ) as validate, patch(
            "promin.conformance._validate_physical_scale_result"
        ) as validate_physical:
            # This test isolates the incremental-commit hook.  The direct
            # physical validator has its own fail-closed test below and must
            # not treat this synthetic shape as physical evidence.
            check({}, self.bundle, context)
        validate.assert_called_once_with(
            baseline,
            candidate_binding=candidate,
            source_path=source_path,
            evidence_root=evidence_root,
        )
        validate_physical.assert_called_once()

        invalid_variants = []
        stale_predicate = deepcopy(validated)
        stale_predicate["contract_predicates"]["semantic_commit_count_exact"] = False
        invalid_variants.append(("stale semantic count predicate", stale_predicate))
        missing_predicate = deepcopy(validated)
        del missing_predicate["contract_predicates"]["semantic_commit_count_exact"]
        invalid_variants.append(("missing semantic count predicate", missing_predicate))
        excessive_writes = deepcopy(validated)
        excessive_writes["performance"]["observed"]["runtime_checkpoint_writes"] = 5
        invalid_variants.append(("checkpoint writes exceed checkpoints", excessive_writes))

        for label, invalid in invalid_variants:
            with self.subTest(case=label), patch(
                "promin.evidence.validate_saturation_evidence",
                return_value=invalid,
            ), patch(
                "promin.conformance._validate_physical_scale_result"
            ), self.assertRaises(ConformanceError):
                check({}, self.bundle, context)

    def test_release_decision_hooks_require_pinned_signed_outcome_after_evidence_validation(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from promin.authority import canonical_digest
        from promin.evidence import standard_distribution_status
        from promin.mutation_suite import (
            MutationFixture,
            _standard_candidate_binding,
            _standard_evidence_manifest,
            _standard_trust_and_decision,
        )

        with _temporary_fixture("promin-release-chain-contract-") as temporary:
            fixture = MutationFixture(temporary / "fixture", PACKAGE_ROOT)
            candidate = _standard_candidate_binding(fixture)
            evidence_root, manifest = _standard_evidence_manifest(
                fixture, candidate, physical=True
            )
            trust, template = _standard_trust_and_decision(candidate, manifest)
            private_key = Ed25519PrivateKey.generate()
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            trust["keys"][0]["public_key"] = base64.b64encode(public_key).decode("ascii")
            trust_digest = canonical_digest(trust)
            prevalidated_manifest = {
                **manifest,
                "all_required_roles_resolved": True,
            }

            with patch(
                "promin.evidence.validate_standard_release_evidence_manifest",
                return_value=prevalidated_manifest,
            ):
                for outcome in ("approve", "reject"):
                    decision = dict(template)
                    decision["decision_id"] = f"decision:{outcome}"
                    decision["outcome"] = outcome
                    decision["nonce"] = base64.b64encode(
                        (outcome.encode("ascii") + b":" + b"n" * 16)[:16]
                    ).decode("ascii")
                    identity = {
                        key: value
                        for key, value in decision.items()
                        if key not in {"signed_claim_digest", "signature"}
                    }
                    decision["signed_claim_digest"] = canonical_digest(identity)
                    decision["signature"] = base64.b64encode(
                        private_key.sign(bytes.fromhex(decision["signed_claim_digest"]))
                    ).decode("ascii")
                    decision_path = _write_json(
                        temporary / f"{outcome}-decision.json", decision
                    )
                    context = {
                        "standard_release_candidate_binding": candidate,
                        "standard_release_evidence_manifest": manifest,
                        "standard_release_evidence_root": evidence_root,
                        "standard_release_trust_configuration": trust,
                        "standard_release_decision": decision,
                        "standard_release_decision_path": decision_path,
                        "standard_trust_configuration_sha256": trust_digest,
                        "expected_trust_root_sha256": trust_digest,
                    }
                    for check_id in (
                        "candidate-evidence-decision-acyclic-chain",
                        "evidence-manifest-physical-resolution",
                        "signed-standard-decision-authority-proof",
                        "semver-from-candidate-binding",
                        "external-standard-release-decision-exact-binding",
                    ):
                        with self.subTest(outcome=outcome, check_id=check_id):
                            ACCEPTANCE_VALIDATORS[check_id]({}, self.bundle, context)
                    status = standard_distribution_status(
                        decision,
                        candidate_binding=candidate,
                        evidence_manifest=manifest,
                        evidence_root=evidence_root,
                        trust_configuration=trust,
                        trust_configuration_sha256=trust_digest,
                        expected_trust_root_sha256=trust_digest,
                    )
                    ACCEPTANCE_VALIDATORS[
                        "standard-distribution-separate-from-product-acceptance"
                    ]({}, self.bundle, {"release_status": status})
                    self.assertEqual(
                        status["current_distribution_eligible"], outcome == "approve"
                    )
                    self.assertFalse(status["product_acceptance_pass"])
                    self.assertEqual(status["product_public_approval"], "not_approved")

            human_entry = next(
                item for item in manifest["entries"]
                if item["evidence_role"] == "human-documents"
            )
            human = json.loads(
                (evidence_root / human_entry["path"]).read_text(encoding="utf-8")
            )
            with self.assertRaises(ConformanceError):
                ACCEPTANCE_VALIDATORS["typed-human-document-verification"](
                    human,
                    self.bundle,
                    {
                        "standard_release_candidate_binding": candidate,
                        "human_document_verification": human,
                    },
                )

    def test_bounded_search_state_stream_and_scale_hooks_use_physical_inputs(self) -> None:
        from promin.canonical import canonical_bytes, digest_file, digest_value

        conformance = self.bundle.core["conformance.json"]
        workcard_ceiling = conformance["workcard_hard_ceiling"]
        reference = conformance["reference_benchmarks"]
        projection_contract = conformance["scale_contracts"]["projection"]
        broad = {
            "budget": {
                "max_bytes": workcard_ceiling["max_bytes"],
                "top_k": workcard_ceiling["top_k"],
            },
            "selected_seed_count": workcard_ceiling["top_k"],
            "refinement_required": True,
            "refinement_hints": ["add an entity type", "add a path prefix"],
            "unselected_matches_traversable": False,
            "corpus_pagination": False,
            "selected_closure_complete": True,
            "continuation": None,
        }
        ACCEPTANCE_VALIDATORS["broad-query-bounded-seed-refinement"](
            broad, self.bundle, {"broad_query_result": broad}
        )
        drifted_broad_core = deepcopy(self.bundle.core)
        drifted_broad_core["conformance.json"]["workcard_hard_ceiling"][
            "top_k"
        ] -= reference["inventory_passes"]
        with self.assertRaises(ConformanceError):
            ACCEPTANCE_VALIDATORS["broad-query-bounded-seed-refinement"](
                broad,
                replace(self.bundle, core=drifted_broad_core),
                {"broad_query_result": broad},
            )
        oversized_broad = deepcopy(broad)
        oversized_broad["refinement_hints"] = [
            "x" * workcard_ceiling["max_bytes"]
        ]
        with self.assertRaises(ConformanceError):
            ACCEPTANCE_VALIDATORS["broad-query-bounded-seed-refinement"](
                oversized_broad,
                self.bundle,
                {"broad_query_result": oversized_broad},
            )

        with _temporary_fixture("promin-bounds-contract-") as temporary:
            state_path = temporary / "continuation-state.json"
            state_path.write_bytes(canonical_bytes({"cursor": 1, "inner": "x" * 1024}))
            envelope = canonical_bytes(
                {
                    "state_digest": digest_file(state_path),
                    "budgets": {"max_entities": 16},
                }
            )
            token = base64.urlsafe_b64encode(envelope).rstrip(b"=").decode("ascii")
            token += "." + base64.urlsafe_b64encode(b"m" * 32).rstrip(b"=").decode("ascii")
            workcard_path = temporary / "workcard.json"
            _write_json(
                workcard_path,
                {"budget": {"max_bytes": workcard_ceiling["max_bytes"]}},
            )
            ACCEPTANCE_VALIDATORS["continuation-token-bytes-at-most-256"](
                {},
                self.bundle,
                {
                    "continuation_token": token,
                    "continuation_state_path": state_path,
                    "continuation_workcard_path": workcard_path,
                },
            )
            continuation_context = {
                "continuation_token": token,
                "continuation_state_path": state_path,
                "continuation_workcard_path": workcard_path,
            }
            drifted_token_core = deepcopy(self.bundle.core)
            drifted_token_core["conformance.json"]["scale_contracts"][
                "workcard"
            ]["continuation_token_bytes_max"] = len(token.encode("ascii")) - 1
            with self.assertRaises(ConformanceError):
                ACCEPTANCE_VALIDATORS["continuation-token-bytes-at-most-256"](
                    {},
                    replace(self.bundle, core=drifted_token_core),
                    continuation_context,
                )
            drifted_state_core = deepcopy(self.bundle.core)
            drifted_state_core["conformance.json"]["scale_contracts"][
                "workcard"
            ]["continuation_state_bytes_max"] = state_path.stat().st_size - 1
            with self.assertRaises(ConformanceError):
                ACCEPTANCE_VALIDATORS["continuation-token-bytes-at-most-256"](
                    {},
                    replace(self.bundle, core=drifted_state_core),
                    continuation_context,
                )

            stream_path = temporary / "inventory.jsonl"
            stream = b"".join(
                canonical_bytes({"path": f"src/{index}.txt", "digest": str(index) * 64, "size": index})
                for index in (1, 2)
            )
            stream_path.write_bytes(stream)
            stream_digest = digest_file(stream_path)
            inventory_manifest = {
                "stream_digest": stream_digest,
                "stream_bytes": len(stream),
                "entry_count": 2,
            }
            manifest_path = _write_json(
                temporary / "inventory-manifest.json", inventory_manifest
            )
            inventory_result = {
                "manifest_path": manifest_path,
                "stream_path": stream_path,
                "stream_digest": stream_digest,
                "stream_bytes": len(stream),
                "entry_count": 2,
                "manifest_digest": digest_value(inventory_manifest),
                "peak_increment_bytes": len(stream) * 2,
                "memory_amplification": 2.0,
                "manifest_verified_jsonl": True,
                "atomic_publication": True,
                "inventory_passes": reference["inventory_passes"],
                "rebuild_product_passes": projection_contract[
                    "rebuild_product_tree_passes"
                ],
            }
            ACCEPTANCE_VALIDATORS[
                "inventory-stream-memory-amplification-at-most-32"
            ]({}, self.bundle, {"inventory_stream_result": inventory_result})
            drifted_amplification_core = deepcopy(self.bundle.core)
            drifted_amplification_core["conformance.json"]["scale_contracts"][
                "inventory"
            ]["memory_amplification_max"] = (
                inventory_result["memory_amplification"]
                - reference["inventory_passes"]
            )
            with self.assertRaises(ConformanceError):
                ACCEPTANCE_VALIDATORS[
                    "inventory-stream-memory-amplification-at-most-32"
                ](
                    {},
                    replace(self.bundle, core=drifted_amplification_core),
                    {"inventory_stream_result": inventory_result},
                )

            search_text = "bounded-search-text"
            owned_core = deepcopy(self.bundle.core)
            owned_core["conformance.json"]["scale_contracts"]["inventory"][
                "search_text_bytes_max"
            ] = len(search_text.encode("utf-8"))
            owned_bundle = replace(self.bundle, core=owned_core)
            search_stream_path = temporary / "inventory-search-text.jsonl"
            search_stream = canonical_bytes(
                {
                    "path": "src/search.txt",
                    "digest": ONE,
                    "size": len(search_text),
                    "search_text": search_text,
                }
            )
            search_stream_path.write_bytes(search_stream)
            search_manifest = {
                "stream_digest": digest_file(search_stream_path),
                "stream_bytes": len(search_stream),
                "entry_count": reference["inventory_passes"],
            }
            search_manifest_path = _write_json(
                temporary / "inventory-search-text-manifest.json",
                search_manifest,
            )
            search_inventory_result = {
                "manifest_path": search_manifest_path,
                "stream_path": search_stream_path,
                "stream_digest": search_manifest["stream_digest"],
                "stream_bytes": search_manifest["stream_bytes"],
                "entry_count": search_manifest["entry_count"],
                "manifest_digest": digest_value(search_manifest),
                "peak_increment_bytes": len(search_stream),
                "memory_amplification": 1.0,
                "manifest_verified_jsonl": True,
                "atomic_publication": True,
                "inventory_passes": reference["inventory_passes"],
                "rebuild_product_passes": projection_contract[
                    "rebuild_product_tree_passes"
                ],
            }
            ACCEPTANCE_VALIDATORS[
                "inventory-stream-memory-amplification-at-most-32"
            ](
                {},
                owned_bundle,
                {"inventory_stream_result": search_inventory_result},
            )

            drifted_core = deepcopy(owned_core)
            drifted_core["conformance.json"]["scale_contracts"]["inventory"][
                "search_text_bytes_max"
            ] -= reference["inventory_passes"]
            with self.assertRaises(ConformanceError):
                ACCEPTANCE_VALIDATORS[
                    "inventory-stream-memory-amplification-at-most-32"
                ](
                    {},
                    replace(self.bundle, core=drifted_core),
                    {"inventory_stream_result": search_inventory_result},
                )

        scale = {
            "focused_selector": "not scale",
            "physical_selector": "scale",
            "focused_scale_tests_collected": 0,
            "physical_scale_tests_collected": 1,
            "missing_environment_status": "fail",
            "physical_environment_status": "pass",
            "physical_skipped": 0,
        }
        ACCEPTANCE_VALIDATORS["explicit-scale-marker-selection"](
            scale, self.bundle, {"scale_selection": scale}
        )

    def test_physical_scale_cardinalities_reject_mutated_core_owners(self) -> None:
        baseline_result = _physical_scale_result_from_core(self.bundle)
        # Core-owned cardinalities are tested independently from physical raw
        # evidence.  The raw-evidence seam is patched here deliberately; the
        # unbound synthetic shape is rejected by the separate fail-closed test.
        with patch("promin.conformance._validate_physical_raw_evidence"):
            _validate_physical_scale_result(
                baseline_result,
                bundle=self.bundle,
                check_id=PHYSICAL_ACCEPTANCE_ID,
                context={"core_only_contract_probe": True},
            )

        mutated_core = deepcopy(self.bundle.core)
        conformance = mutated_core["conformance.json"]
        reference = conformance["reference_benchmarks"]
        semantic = reference["semantic_corpus"]
        physical = reference["physical_relation_corpus"]
        workcard = conformance["scale_contracts"]["workcard"]

        reference["file_count"] += len(semantic["depths"])
        reference["query_count"] += len(semantic["depths"])
        semantic["task_count"] += reference["inventory_passes"]
        semantic["relation_count"] += reference["inventory_passes"]
        physical["task_count"] += reference["inventory_passes"]
        physical["relation_count"] += len(semantic["depths"])
        physical["total_core_valid_relations"] = (
            semantic["relation_count"] + physical["relation_count"]
        )
        reference["core_valid_relation_count"] = physical[
            "total_core_valid_relations"
        ]
        semantic["depths"].append(max(semantic["depths"]) + 1)
        reference["depths_tested"] = list(semantic["depths"])
        workcard["continuation_state_bytes_max"] += reference["inventory_passes"]
        workcard["continuation_token_bytes_max"] += reference["inventory_passes"]

        mutated_bundle = replace(self.bundle, core=mutated_core)
        mutated_result = _physical_scale_result_from_core(mutated_bundle)
        with patch("promin.conformance._validate_physical_raw_evidence"):
            with self.assertRaises(ConformanceError):
                _validate_physical_scale_result(
                    mutated_result,
                    bundle=mutated_bundle,
                    check_id=PHYSICAL_ACCEPTANCE_ID,
                    context={"core_only_contract_probe": True},
                )

            with self.assertRaises(ConformanceError):
                _validate_physical_scale_result(
                    baseline_result,
                    bundle=mutated_bundle,
                    check_id=PHYSICAL_ACCEPTANCE_ID,
                    context={"core_only_contract_probe": True},
                )
            with self.assertRaises(ConformanceError):
                _validate_physical_scale_result(
                    mutated_result,
                    bundle=self.bundle,
                    check_id=PHYSICAL_ACCEPTANCE_ID,
                    context={"core_only_contract_probe": True},
                )

    def test_physical_scale_validator_rejects_unbound_synthetic_shape(self) -> None:
        synthetic = _physical_scale_result_from_core(self.bundle)
        with self.assertRaisesRegex(
            ConformanceError, "raw physical evidence context"
        ):
            _validate_physical_scale_result(
                synthetic,
                bundle=self.bundle,
                check_id=PHYSICAL_ACCEPTANCE_ID,
            )

        # A valid-looking bounded shape cannot become physical evidence by
        # carrying the removed per-file derived-artifact proxy field.
        legacy_shape = deepcopy(synthetic)
        legacy_shape["physical"]["derived_artifact_proxies_per_raw_file"] = 1
        with self.assertRaisesRegex(
            ConformanceError, "raw physical evidence context"
        ):
            _validate_physical_scale_result(
                legacy_shape,
                bundle=self.bundle,
                check_id=PHYSICAL_ACCEPTANCE_ID,
            )

    def test_profile_depth_probe_uses_the_current_core_ceiling(self) -> None:
        profile_id = self.bundle.preset["default_profile"]
        default_depth = self.bundle.preset["profiles"][profile_id][
            "default_dependency_depth"
        ]

        class DepthProbeService:
            def __init__(self) -> None:
                self.depths: list[int | None] = []

            def search(
                self,
                query: str,
                *,
                depth: int | None = None,
                subject_id: str,
                grant_id: str,
            ) -> dict[str, int]:
                self.depths.append(depth)
                return {"depth": default_depth if depth is None else depth}

        context = {
            "profile_query": "focused",
            "profile_subject_id": "subject:focused",
            "profile_grant_id": "grant:focused",
            "operating_profile": profile_id,
        }
        baseline_service = DepthProbeService()
        POLICY_VALIDATORS["profile_default_depth"](
            {},
            self.bundle,
            {**context, "profile_service": baseline_service},
        )
        self.assertEqual(
            baseline_service.depths,
            [None, self.bundle.core["conformance.json"]["dependency_depth_hard_max"]],
        )

        mutated_core = deepcopy(self.bundle.core)
        mutated_core["conformance.json"]["dependency_depth_hard_max"] += (
            mutated_core["conformance.json"]["reference_benchmarks"][
                "inventory_passes"
            ]
        )
        mutated_bundle = replace(self.bundle, core=mutated_core)
        mutated_service = DepthProbeService()
        POLICY_VALIDATORS["profile_default_depth"](
            {},
            mutated_bundle,
            {**context, "profile_service": mutated_service},
        )
        self.assertEqual(
            mutated_service.depths,
            [None, mutated_core["conformance.json"]["dependency_depth_hard_max"]],
        )

    def test_continuation_v2_contract_hook_proves_exact_page_union(self) -> None:
        with _temporary_fixture("promin-continuation-contract-") as temporary:
            harness = MutationHarness(temporary)
            projection = harness.projection("continuation-contract.sqlite3")
            rows = tuple(harness.projection_row(index) for index in range(1, 7))
            projection.rebuild(
                harness.event_store("continuation-contract-events"),
                inventory=harness.verified_inventory(*rows),
            )
            context = {
                "continuation_projection": projection,
                "continuation_query": "needle",
                "continuation_depth": 1,
                "continuation_budget": {
                    "max_bytes": self.bundle.core["conformance.json"][
                        "workcard_hard_ceiling"
                    ]["max_bytes"],
                    "max_entities": 2,
                    "max_relations": 1,
                    "max_fanout_per_entity": 1,
                    "top_k": 6,
                },
                "continuation_now": NOW,
                "continuation_resume_binding": _continuation_resume_binding(),
                "expected_entity_ids": {
                    item["semantic_proxy"]["id"] for item in rows
                },
                "expected_relation_ids": set(),
            }
            POLICY_VALIDATORS["continuation_completeness"](
                {}, self.bundle, context
            )
            ACCEPTANCE_VALIDATORS["continuation-v2-complete-page-union"](
                {}, self.bundle, context
            )

    def test_provider_and_candidate_recipe_hooks_execute_production_paths(self) -> None:
        with _temporary_fixture("promin-provider-recipe-contract-") as temporary:
            harness = MutationHarness(temporary)
            project, request, paths = harness.init_request()
            project_plan = json.loads(
                paths["project_plan"].read_text(encoding="utf-8")
            )
            project_plan["candidate_recipe"]["exclude"] = [
                ".promin/**",
                "build/**",
                "docs/**",
            ]
            _write_json(paths["project_plan"], project_plan)
            initialize_project(request)
            activation = ActivationGuard(project).verify()
            verify_provider_preflight(
                activation.plans["technologies.json"],
                project,
                contract_bundle=activation.bundle,
                provider_dispatch=activation.provider_dispatch,
                receipt_root=activation.control_root / "providers",
            )
            for relative, content in (
                ("src/included.txt", "included"),
                ("build/excluded.bin", "excluded"),
                ("docs/excluded.md", "excluded"),
            ):
                path = project / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            context = {
                "project_root": project,
                "inventory_source_roots": ["."],
                "expected_inventory_paths": {"src/included.txt"},
                "activation_context": activation,
            }
            POLICY_VALIDATORS["provider_adapter_dispatch"](
                {}, self.bundle, context
            )
            ACCEPTANCE_VALIDATORS["candidate-recipe-applied-once"](
                {}, self.bundle, context
            )

    def test_checkpoint_hook_proves_verified_and_fallback_equivalence(self) -> None:
        with _temporary_fixture("promin-checkpoint-contract-") as root:
            harness = MutationHarness(root)
            source = harness.event_store("source")
            source.commit(_command(1), created_at=NOW)
            verified_root = root / "verified"
            fallback_root = root / "fallback"
            shutil.copytree(source.root, verified_root)
            shutil.copytree(source.root, fallback_root)
            verified = harness.event_store("verified")
            (fallback_root / "journal-checkpoint.json").write_bytes(b"{corrupt")
            fallback = harness.event_store("fallback")
            context = {
                "verified_checkpoint_store": verified,
                "fallback_checkpoint_store": fallback,
            }
            POLICY_VALIDATORS["verified_state_checkpoint"](
                {}, self.bundle, context
            )
            ACCEPTANCE_VALIDATORS["verified-head-checkpoint-delta-replay"](
                {}, self.bundle, context
            )

    def test_strict_ingress_rejects_empty_unknown_null_and_stale(self) -> None:
        for operation in ("command", "import", "replay", "rebuild", "export"):
            with self.subTest(operation=operation, mutation="empty"):
                self._reject({}, operation)
            unknown = _task()
            unknown["unexpected"] = True
            with self.subTest(operation=operation, mutation="unknown"):
                self._reject(unknown, operation)
            null_critical = _task()
            null_critical["task_id"] = None
            with self.subTest(operation=operation, mutation="null"):
                self._reject(null_critical, operation)
            with self.subTest(operation=operation, mutation="stale"):
                self._reject(
                    _task(),
                    operation,
                    context={"activation_digest": ONE},
                )

    def test_mutation_fixture_recreates_removed_temp_root(self) -> None:
        with _temporary_fixture("promin-mutation-root-recovery-") as temporary:
            harness = MutationHarness(temporary)
            shutil.rmtree(temporary)

            project, request, paths = harness.init_request()

            self.assertTrue(project.is_dir())
            self.assertEqual(request.project_root, project)
            self.assertEqual(
                set(paths),
                {
                    "project_plan",
                    "standards_plan",
                    "technologies_plan",
                    "licenses_plan",
                    "authority_plan",
                },
            )

    def test_all_77_mutation_families_are_rejected_by_production_paths(self) -> None:
        seed = os.environ.get("PROMIN_MUTATION_SEED", "focused-default-seed")
        families = list(MUTATION_RUNNERS)
        random.Random(seed).shuffle(families)
        expected = (
            ContractError,
            CanonicalError,
            AuthorityError,
            DomainError,
            EvidenceError,
            InitError,
            EventStoreError,
            ProjectionError,
            ServiceError,
            ValidationFailure,
            ExplicitNonCredit,
            sqlite3.Error,
        )
        rejected: dict[str, str] = {}
        for family in families:
            with self.subTest(family=family), _temporary_fixture(
                f"promin-mutation-{family[:20]}-"
            ) as temporary:
                harness = MutationHarness(temporary)
                try:
                    MUTATION_RUNNERS[family](harness)
                except expected as exc:
                    self.assertTrue(str(exc), f"{family} rejection lacked a reason")
                    rejected[family] = f"{type(exc).__name__}: {exc}"
                else:
                    self.fail(f"{family} was unexpectedly accepted by its production path")
        self.assertEqual(len(rejected), 77)
        self.assertEqual(set(rejected), set(MUTATION_RUNNERS))

    def test_mutation_order_is_regenerated_from_execution_seed(self) -> None:
        seed = os.environ.get("PROMIN_MUTATION_SEED", "focused-default-seed")
        first = list(MUTATION_RUNNERS)
        second = list(MUTATION_RUNNERS)
        random.Random(seed).shuffle(first)
        random.Random(seed).shuffle(second)
        self.assertEqual(first, second)
        self.assertEqual(set(first), set(MUTATION_RUNNERS))


if __name__ == "__main__":
    unittest.main()
