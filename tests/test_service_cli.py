from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import base64
import hashlib
import os
from pathlib import Path
import shlex
import sqlite3
import stat
import subprocess
import sys
from typing import Any

import pytest

from promin.canonical import (
    atomic_write_json,
    canonical_bytes,
    digest_file,
    digest_value,
    load_json_strict,
    parse_json_strict,
)
from promin.contracts import ContractError, load_contract_bundle
from promin.authority import AuthorityEngine, AuthorityError
from promin.init import (
    ActivationGuard,
    InitError,
    _activation_identity,
    bind_implementation_closures,
    build_provider_dependency_receipt,
    compile_project_init,
    resolve_provider_dispatch,
)
from promin.events import CommandConflict, EventStore
from promin.projection import Projection, ProjectionError
from promin.service import (
    BASE_COMMANDS,
    InventoryResult,
    ProminService,
    ServiceError,
    _persist_workcard,
    _reconciled_evidence,
    _semantic_export_material,
    import_fact,
    inventory_candidate,
    semantic_export,
)
from promin.__main__ import _parser, main
from promin.mutation_suite import MutationFixture


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PRESET = PACKAGE_ROOT / "presets" / "semantic-morok-tower.json"


def _at(offset: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _authority_runtime_policy() -> dict[str, Any]:
    model = load_json_strict(PACKAGE_ROOT / "core" / "authority-model.json")
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


def _persist_test_grant(
    engine: AuthorityEngine,
    authority: dict[str, Any],
    activation_digest: str,
    grant: dict[str, Any],
    *,
    issuer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    authorization: dict[str, Any]
    if issuer is None:
        authorization = {
            "kind": "root",
            "subject_id": grant["subject_id"],
            "proofs": [
                {
                    "kind": "local-root-command",
                    "subject_id": grant["subject_id"],
                    "authority_init_digest": digest_value(authority),
                    "signed_intent_digest": "pending",
                }
            ],
        }
    else:
        authorization = _grant_authorization(issuer)
    command = _command(
        activation_digest=activation_digest,
        command_id=f"command:checkpoint-issue:{grant['grant_id']}",
        command_kind="grant.issue",
        payload=grant,
        expected_head=None,
        issued_at=grant["issued_at"],
        authorization=authorization,
    )
    if issuer is None:
        command["authorization"]["proofs"][0]["signed_intent_digest"] = command[
            "intent_digest"
        ]
    receipt = engine.authorize_grant_issue_command(command)
    return engine.issue_grant(
        grant,
        grant["issued_at"],
        issue_authorization=receipt,
    )


def _documented_package_counts(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for line in text.splitlines():
        cells = [cell.strip() for cell in line.split("|")[1:-1]]
        if len(cells) != 2 or not cells[1].isdigit():
            continue
        location = cells[0].strip("`")
        if location in {"package root", ".github/", "core/", "docs/", "examples/", "human/", "presets/", "profiles/", "promin/", "prompts/", "skills/", "tests/", "tools/"}:
            counts[location] = int(cells[1])
    return counts


def test_documented_v1_surface_and_package_inventory_are_exact() -> None:
    readme = (PACKAGE_ROOT / "README.md").read_text(encoding="utf-8")
    machine = (PACKAGE_ROOT / "MACHINE_README.md").read_text(encoding="utf-8")
    version = load_json_strict(PACKAGE_ROOT / "VERSION.json")
    preset = load_json_strict(PRESET)
    assert version["canonical_name"] == "promin"
    assert version["version"] == "1.0.0-alpha.3"
    assert "Version 1.0.0-alpha.3" in readme
    assert "Standard version: `1.0.0-alpha.3`" in machine

    for command in BASE_COMMANDS:
        assert f"promin {command}" in readme
    assert '["init", "doctor", "status", "next", "validate", "continue", "audit", "refresh", "context", "skills"]' in machine
    assert tuple(preset["base_user_commands"]) == BASE_COMMANDS

    expected_counts = {
        "package root": 14,
        ".github/": 1,
        "core/": 6,
        "docs/": 15,
        "examples/": 1,
        "human/": 4,
        "presets/": 1,
        "profiles/": 13,
        "promin/": 31,
        "prompts/": 2,
        "skills/": 4,
        "tests/": 34,
        "tools/": 13,
    }
    assert _documented_package_counts(readme) == expected_counts
    assert _documented_package_counts(machine) == expected_counts
    manifest = load_json_strict(PACKAGE_ROOT / "MANIFEST.json")
    assert len(manifest["files"]) == 137
    actual_counts = {key: 0 for key in expected_counts}
    actual_counts["package root"] = 2  # MANIFEST.json and SHA256SUMS.txt
    for item in manifest["files"]:
        path = item["path"]
        location = path.split("/", 1)[0] + "/" if "/" in path else "package root"
        actual_counts[location] += 1
    assert actual_counts == expected_counts
    assert sum(expected_counts.values()) == 139


def test_documented_observability_and_evidence_boundaries_are_static() -> None:
    documents = [
        (PACKAGE_ROOT / "README.md").read_text(encoding="utf-8"),
        (PACKAGE_ROOT / "MACHINE_README.md").read_text(encoding="utf-8"),
    ]
    for document in documents:
        lowered = " ".join(document.casefold().split())
        for marker in (
            "report_authoritative=false",
            "pass_credit=false",
            "token",
            "cost",
            "goal",
            "session",
            "batch",
            "workspace",
            "per-run usage",
            "base executable",
            "base prefix",
            "sqlite",
            "monotonic total deadline",
            "parent exit",
            "semantic state",
            "operational-state",
            "three consecutive full zero-new iterations",
            "audit-level compatibility",
            "non-authoritative",
        ):
            assert marker in lowered
        assert "process tree" in lowered or "process-tree" in lowered

    generator = " ".join(
        (PACKAGE_ROOT / "tools" / "generate_human.py")
        .read_text(encoding="utf-8")
        .casefold()
        .split()
    )
    for marker in (
        "canonical standard version: {manifest['version']}",
        "canonical_package_file_count",
        "report_authoritative=false",
        "per-run usage",
        "base executable",
        "sqlite",
        "monotonic total deadline",
        "process tree",
        "fresh exact five-record",
        "audit-level compatibility",
    ):
        assert marker in generator


def test_documented_init_commands_are_complete_parser_inputs() -> None:
    machine = (PACKAGE_ROOT / "MACHINE_README.md").read_text(encoding="utf-8")
    commands = [
        line
        for line in machine.splitlines()
        if line.startswith("promin --root PROJECT init ")
        and "--standard-bundle" in line
    ]
    # The machine guide also documents the two guided no-question-first forms.
    # This assertion owns only the five complete expert command variants.
    assert len(commands) == 5
    for command in commands:
        parsed = _parser().parse_args(shlex.split(command)[1:])
        assert parsed.workflow == "init"


def test_documented_release_commands_bind_required_inputs() -> None:
    readme = (PACKAGE_ROOT / "README.md").read_text(encoding="utf-8")
    machine = (PACKAGE_ROOT / "MACHINE_README.md").read_text(encoding="utf-8")
    assert (
        "build-evidence-manifest ARCHIVE CANDIDATE_BINDING EVIDENCE_ROOT "
        "EVIDENCE_PLAN TRUST_CONFIGURATION EVIDENCE_MANIFEST"
    ) in machine
    manifest_line = next(
        line
        for line in readme.splitlines()
        if " build-evidence-manifest " in line
    )
    assert "../evidence/trust-configuration.json" in manifest_line
    assert (
        "--expected-trust-root-sha256 "
        "288fbbb704a905a193088d470f1907c1798098eca903800202396c4a65e89466"
    ) in manifest_line
    no_degradation_line = next(
        line
        for line in readme.splitlines()
        if "promin_no_degradation.py" in line
    )
    assert "--install-mode offline-wheelhouse" in no_degradation_line
    assert "--wheelhouse ../wheelhouse" in no_degradation_line
    assert "--candidate-binding ../evidence/candidate-binding.json" in no_degradation_line
    no_degradation_arguments = shlex.split(no_degradation_line)
    assert no_degradation_arguments[0:4] == [
        "python",
        "tools/promin_no_degradation.py",
        ".",
        "../evidence/no-degradation.json",
    ]
    assert "../evidence/saturation-run" in readme
    assert "../evidence/saturation-audit " in readme
    assert "../evidence/saturation.json" not in readme
    assert "../evidence/saturation-audit.json" not in readme


def _grant(
    authority: dict,
    activation_digest: str,
    issued_at: str,
    *,
    grant_id: str,
    capability: str,
    issuer: dict | None = None,
) -> dict:
    grant = {
        "record_type": "Grant",
        "grant_id": grant_id,
        "subject_id": "owner",
        "capability_id": capability,
        "scope": [{"kind": "project", "value": "project-1"}],
        "activation_digest": activation_digest,
        "issued_at": issued_at,
        "expires_at": (
            datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
            + timedelta(days=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": "nonce-" + grant_id,
    }
    grant["claim_digest"] = digest_value(grant)
    if issuer is None:
        grant["trust_proofs"] = [
            {
                "kind": "local-root",
                "root_subject_id": "owner",
                "authority_init_digest": digest_value(authority),
                "signed_claim_digest": grant["claim_digest"],
            }
        ]
    else:
        grant["trust_proofs"] = [
            {
                "kind": "issuer-grant",
                "issuer_grant_id": issuer["grant_id"],
                "issuer_signed_claim_digest": issuer["claim_digest"],
                "signed_claim_digest": grant["claim_digest"],
            }
        ]
    return grant


def _command(
    *,
    activation_digest: str,
    command_id: str,
    command_kind: str,
    payload: dict,
    expected_head: str | None,
    issued_at: str,
    authorization: dict,
    effect_scope: list[dict[str, str]] | None = None,
    definition_digest: str | None = None,
) -> dict:
    task_id = payload.get("task_id")
    requested_scope = [{"kind": "project", "value": "project-1"}]
    if task_id is not None:
        requested_scope.append({"kind": "task", "value": task_id})
    for selector in effect_scope or ():
        if selector not in requested_scope:
            requested_scope.append(selector)
    command = {
        "record_type": "CommandRequest",
        "command_id": command_id,
        "command_kind": command_kind,
        "subject_id": "owner",
        "activation_digest": activation_digest,
        "idempotency_key": "idempotency:" + command_id,
        "requested_scope": requested_scope,
        "expected_head_digest": expected_head,
        "issued_at": issued_at,
        "payload": payload,
    }
    if definition_digest is not None:
        command["definition_digest"] = definition_digest
    command["intent_digest"] = digest_value(command)
    command["authorization"] = authorization
    return command


def _grant_authorization(grant: dict) -> dict:
    return {
        "kind": "grant",
        "grant_id": grant["grant_id"],
        "grant_claim_digest": grant["claim_digest"],
    }


def _semantic_records(service: ProminService) -> list[dict[str, Any]]:
    """Inspect the exact semantic snapshot before CAS publication.

    Public ``semantic_export`` deliberately requires a finalized output Artifact.
    Tests that only need to assert replay membership should not synthesize an
    unrelated evidence publication flow, so they exercise the same canonical
    material builder used by the public export boundary.
    """

    context = service._verified_mutation_context(
        service._context(force_full=True)
    )
    store = service._event_store(context)
    material = _semantic_export_material(service, context, store)
    return material["records"]


def _task_with_gate_definition(
    service: ProminService,
    task: dict[str, Any],
    *,
    defined_at_head_digest: str,
    gate_id: str,
    policy_digest: str = "4" * 64,
    tool_digest: str = "5" * 64,
    input_digests: list[str] | None = None,
) -> dict[str, Any]:
    value = deepcopy(task)
    value.pop("gate_run_definitions", None)
    owner_digest = digest_value(
        {
            key: item
            for key, item in value.items()
            if key != "state"
        }
    )
    context = service._context()
    definition = {
        "definition_kind": "GateRunDefinition",
        "definition_id": f"definition:{gate_id}",
        "owner_kind": "Task",
        "owner_digest": owner_digest,
        "defined_at_head_digest": defined_at_head_digest,
        "gate_id": gate_id,
        "run_kind": "validation",
        "expected_evidence_class": "validator",
        "expected_evidence_purpose": "gate",
        "product_credit_required": False,
        "target_kind": "candidate",
        "target_digest": value["candidate_digest"],
        "target_scope": [
            {"kind": "candidate", "value": value["candidate_digest"]}
        ],
        "candidate_digest": value["candidate_digest"],
        "policy_digest": policy_digest,
        "tool_digest": tool_digest,
        "implementation_closure_digest": context.implementation_closure_digest,
        "provider_binding_digest": digest_value(
            list(context.provider_dispatch.binding_evidence())
        ),
        "input_digests": list(input_digests or ["6" * 64]),
        "activation_digest": value["activation_digest"],
    }
    value["gate_run_definitions"] = [
        {
            "definition_digest": digest_value(definition),
            "definition": definition,
        }
    ]
    return value


def _reseal(command: dict) -> dict:
    command.pop("intent_digest", None)
    command["intent_digest"] = digest_value(
        {key: value for key, value in command.items() if key != "authorization"}
    )
    return command


def _mutation_card(
    service: ProminService,
    task: dict,
    lease: dict,
    grant: dict,
    query_grant: dict,
    operation: str,
) -> dict:
    context = service._context()
    profile = context.bundle.preset["profiles"][context.activation["operating_profile"]]
    return {
        "record_type": "WorkCard",
        "task_id": task["task_id"],
        "operation_mode": "mutate",
        "operation": operation,
        "acceptance_predicate": task["acceptance_predicate"],
        "allowed_paths": task["allowed_paths"],
        "holder_grant_id": grant["grant_id"],
        "query_grant_id": query_grant["grant_id"],
        "query_grant_claim_digest": query_grant["claim_digest"],
        "candidate_digest": task["candidate_digest"],
        "activation_digest": task["activation_digest"],
        "context_digest": "9" * 64,
        "lease_id": lease["lease_id"],
        "lease_generation": lease["generation"],
        "fencing_token": lease["fencing_token"],
        "stop_conditions": ["task-state-changed"],
        "budget": {
            "max_entities": profile["max_entities"],
            "max_relations": profile["max_relations"],
            "max_bytes": profile["max_context_bytes"],
            "max_fanout_per_entity": profile["max_fanout_per_entity"],
            "top_k": profile["top_k"],
        },
        "truncated": False,
    }


def _bind_mutation(command: dict, card: dict, holder: dict) -> dict:
    task_scope = {"kind": "task", "value": card["task_id"]}
    if task_scope not in command["requested_scope"]:
        command["requested_scope"].append(task_scope)
    command.update(
        {
            "holder_authorization": _grant_authorization(holder),
            "workcard_task_id": card["task_id"],
            "lease_id": card["lease_id"],
            "lease_generation": card["lease_generation"],
            "fencing_token": card["fencing_token"],
            "workcard_digest": digest_value(card),
            "context_digest": card["context_digest"],
        }
    )
    return _reseal(command)


def _initialized_service(
    tmp_path: Path, *, operating_profile: str = "morok-local"
) -> tuple[ProminService, dict, dict]:
    harness = MutationFixture(tmp_path, PACKAGE_ROOT)
    project, request, paths = harness.init_request()
    project_plan = load_json_strict(paths["project_plan"])
    project_plan["operating_profile"] = operating_profile
    atomic_write_json(paths["project_plan"], project_plan)
    technologies = bind_implementation_closures(
        load_json_strict(request.technologies_plan),
        project,
    )
    atomic_write_json(request.technologies_plan, technologies)
    authority = load_json_strict(request.authority_plan)
    authority["roots"][0]["capability_ceiling"] = sorted(
        set(authority["roots"][0]["capability_ceiling"])
        | {
            "authority.manage",
            "lease.manage",
            "evidence.publish",
            "validation.evaluate",
            "finding.record",
            "projection.read",
        }
    )
    atomic_write_json(request.authority_plan, authority)
    service = ProminService(project)
    result = service.initialize(request)
    context = service._context()
    return service, context.plans["authority.json"], result


def test_read_context_is_reused_only_while_activation_files_are_unchanged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _authority, _initialized = _initialized_service(tmp_path)
    service._read_context = None
    service._read_context_fingerprint = None
    original_verify = ActivationGuard.verify
    verification_count = 0

    def counted_verify(guard: ActivationGuard, **kwargs: object):
        nonlocal verification_count
        verification_count += 1
        return original_verify(guard, **kwargs)

    monkeypatch.setattr(ActivationGuard, "verify", counted_verify)
    first = service._context()
    second = service._context()
    assert second is first
    assert verification_count == 1

    project_plan_path = service.root / ".promin" / "init" / "project.json"
    project_plan = load_json_strict(project_plan_path)
    project_plan["project_id"] = "project-changed"
    atomic_write_json(project_plan_path, project_plan)
    with pytest.raises(InitError, match="Activation binding mismatch"):
        service._context()
    assert verification_count == 2


def test_projection_rebuild_forces_full_activation_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _authority, _initialized = _initialized_service(tmp_path)
    service._context()
    original_context = service._context
    full_flags: list[bool] = []

    def observed_context(*, force_full: bool = False):
        full_flags.append(force_full)
        return original_context(force_full=force_full)

    monkeypatch.setattr(service, "_context", observed_context)
    rebuilt = service.rebuild()
    assert rebuilt["product_passes"] == 0
    assert full_flags == [True]


def test_read_context_accepts_installed_preset_on_long_path(
    tmp_path: Path,
) -> None:
    long_root = tmp_path
    remaining = max(0, 115 - len(str(tmp_path / "product")))
    while remaining > 0:
        width = min(50, remaining)
        long_root /= "x" * width
        remaining = max(0, remaining - width - 1)
    long_root.mkdir(parents=True, exist_ok=True)
    service, _authority, _initialized = _initialized_service(long_root)
    context = service._context()
    assert len(str(context.bundle.preset_path)) > 260
    assert context.activation["canonical_name"] == "promin"


def _team_cli_fixture(
    tmp_path: Path,
) -> tuple[Path, dict[str, Any], list[dict[str, Any]], list[str]]:
    harness = MutationFixture(tmp_path, PACKAGE_ROOT)
    project, request, paths = harness.init_request()
    provider = project / "signature_provider.py"
    provider.write_text(
        """from __future__ import annotations
import hashlib
import sys

def verify_signature(proof, key):
    signed = proof.get("signed_digest", proof.get("signed_intent_digest", ""))
    expected = hashlib.sha256((signed + ":" + key["public_key"]).encode("utf-8")).hexdigest()
    return proof.get("signature") == expected

if __name__ == "__main__" and sys.argv[1:] != ["--health"]:
    raise SystemExit(2)
""",
        encoding="utf-8",
    )
    technologies = load_json_strict(request.technologies_plan)
    license_value = deepcopy(technologies["bindings"][0]["license"])
    signature_binding = {
        "capability_id": "signature",
        "provider_id": "provider-team-signature",
        "version": "1.0.0",
        "invocation": {
            "kind": "python-module",
            "value": f"{provider}#verify_signature",
        },
        "purpose": "Verify team Activation and authority signatures",
        "required": False,
        "healthcheck": {
            "argv": [sys.executable, str(provider), "--health"],
            "timeout_ms": 2000,
            "expected_exit": 0,
        },
        "license": license_value,
        "identity": {
            "kind": "module-file-digest",
            "digest": digest_file(provider),
            "source": str(provider),
        },
    }
    signature_binding["dependency_receipt"] = build_provider_dependency_receipt(
        signature_binding, project
    )
    technologies["bindings"].append(signature_binding)
    technologies = bind_implementation_closures(technologies, project)
    atomic_write_json(request.technologies_plan, technologies)
    licenses = load_json_strict(request.licenses_plan)
    licenses["bindings"].append(
        {"provider_id": "provider-team-signature", "license": license_value}
    )
    atomic_write_json(request.licenses_plan, licenses)
    authority = load_json_strict(request.authority_plan)
    authority["trust_mode"] = "team-signed"
    authority["roots"][0]["capability_ceiling"] = sorted(
        set(authority["roots"][0]["capability_ceiling"])
        | {"authority.manage"}
    )
    authority["keys"] = [
        {
            "key_id": "key-owner",
            "subject_id": "owner",
            "algorithm": "fixture-sha256-boundary",
            "public_key": "fixture-public-key",
            "fingerprint": "f" * 64,
        }
    ]
    authority["team_policy"] = {
        "threshold": 1,
        "key_ids": ["key-owner"],
        "signature_provider_capability": "signature",
    }
    atomic_write_json(request.authority_plan, authority)
    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    plans = {
        "project.json": compile_project_init(
            load_json_strict(request.project_plan), bundle
        ),
        "standards.json": load_json_strict(request.standards_plan),
        "technologies.json": technologies,
        "authority.json": authority,
    }
    activation_digest = digest_value(_activation_identity(bundle, plans))

    def proof_signature(signed_digest: str) -> str:
        return hashlib.sha256(
            f"{signed_digest}:fixture-public-key".encode("utf-8")
        ).hexdigest()

    proofs = [
        {
            "kind": "signature",
            "key_id": "key-owner",
            "algorithm": "fixture-sha256-boundary",
            "signed_digest": activation_digest,
            "signature": proof_signature(activation_digest),
        }
    ]
    proofs_path = tmp_path / "plans" / "activation-proofs.json"
    atomic_write_json(proofs_path, proofs)
    init_argv = [
        "--root",
        str(project),
        "init",
        "--standard-bundle",
        str(PACKAGE_ROOT),
        "--preset",
        str(PRESET),
        "--project-plan",
        str(request.project_plan),
        "--standards-plan",
        str(request.standards_plan),
        "--technologies-plan",
        str(request.technologies_plan),
        "--licenses-plan",
        str(request.licenses_plan),
        "--authority-plan",
        str(request.authority_plan),
        "--activation-proofs",
        str(proofs_path),
    ]
    return project, authority, proofs, init_argv


def _leased_service(
    tmp_path: Path, *, operating_profile: str = "morok-local"
) -> tuple[ProminService, dict[str, dict], dict, dict, str]:
    service, authority, initialized = _initialized_service(
        tmp_path, operating_profile=operating_profile
    )
    activation = initialized["activation_digest"]
    issued_at = _at()
    manager = _grant(
        authority,
        activation,
        issued_at,
        grant_id="grant:mutation-authority",
        capability="authority.manage",
    )
    bootstrap = _command(
        activation_digest=activation,
        command_id="command:mutation-bootstrap",
        command_kind="grant.issue",
        payload=manager,
        expected_head=None,
        issued_at=issued_at,
        authorization={
            "kind": "root",
            "subject_id": "owner",
            "proofs": [
                {
                    "kind": "local-root-command",
                    "subject_id": "owner",
                    "authority_init_digest": digest_value(authority),
                    "signed_intent_digest": "pending",
                }
            ],
        },
    )
    bootstrap["authorization"]["proofs"][0]["signed_intent_digest"] = bootstrap["intent_digest"]
    head = service.commit(bootstrap)["batch_digest"]
    grants = {"manager": manager}
    for name, capability in (
        ("planner", "task.plan"),
        ("holder", "task.execute"),
        ("lease_manager", "lease.manage"),
        ("publisher", "evidence.publish"),
        ("validator", "validation.evaluate"),
        ("finder", "finding.record"),
        ("reader", "projection.read"),
    ):
        grant = _grant(
            authority,
            activation,
            issued_at,
            grant_id=f"grant:mutation-{name}",
            capability=capability,
            issuer=manager,
        )
        issue = _command(
            activation_digest=activation,
            command_id=f"command:issue-{name}",
            command_kind="grant.issue",
            payload=grant,
            expected_head=head,
            issued_at=issued_at,
            authorization=_grant_authorization(manager),
        )
        head = service.commit(issue)["batch_digest"]
        grants[name] = grant
    candidate_digest = "1" * 64
    candidate = {
        "record_type": "Candidate",
        "candidate_id": "candidate:mutation-primary",
        "candidate_digest": candidate_digest,
        "inventory_digest": "2" * 64,
        "product_root_digest": "3" * 64,
        "control_excluded": True,
        "candidate_recipe_digest": digest_value(
            service._context().plans["project.json"]["candidate_recipe"]
        ),
        "consistency_mode": "observational-best-effort",
        "creditable": False,
    }
    candidate_command = _command(
        activation_digest=activation,
        command_id="command:mutation-candidate",
        command_kind="candidate.record",
        payload=candidate,
        expected_head=head,
        issued_at=issued_at,
        authorization=_grant_authorization(grants["holder"]),
        effect_scope=[{"kind": "candidate", "value": candidate["candidate_id"]}],
    )
    head = service.commit(candidate_command)["batch_digest"]
    task = {
        "record_type": "Task",
        "task_id": "task:mutation-primary",
        "state": "PLANNED",
        "required_capability": "task.execute",
        "acceptance_predicate": "all mutations bind the active Lease",
        "allowed_paths": ["src/**"],
        "activation_digest": activation,
        "candidate_digest": candidate_digest,
        "created_at": issued_at,
    }
    task = _task_with_gate_definition(
        service,
        task,
        defined_at_head_digest=head,
        gate_id="gate:mutation-distinct-grants",
    )
    task_record = _command(
        activation_digest=activation,
        command_id="command:mutation-task",
        command_kind="task.record",
        payload=task,
        expected_head=head,
        issued_at=issued_at,
        authorization=_grant_authorization(grants["planner"]),
    )
    head = service.commit(task_record)["batch_digest"]
    ready = _command(
        activation_digest=activation,
        command_id="command:task-ready",
        command_kind="task.transition",
        payload={"task_id": task["task_id"], "from_state": "PLANNED", "to_state": "READY", "reason": "ready"},
        expected_head=head,
        issued_at=issued_at,
        authorization=_grant_authorization(grants["planner"]),
    )
    head = service.commit(ready)["batch_digest"]
    lease = {
        "record_type": "Lease",
        "lease_id": "lease:mutation-primary",
        "task_id": task["task_id"],
        "manager_subject_id": "owner",
        "manager_grant_id": grants["lease_manager"]["grant_id"],
        "manager_grant_claim_digest": grants["lease_manager"]["claim_digest"],
        "holder_subject_id": "owner",
        "holder_grant_id": grants["holder"]["grant_id"],
        "holder_grant_claim_digest": grants["holder"]["claim_digest"],
        "generation": 1,
        "fencing_token": 1,
        "state": "ACTIVE",
        "acquired_at": issued_at,
        "heartbeat_at": issued_at,
        "expires_at": _at(3600),
        "activation_digest": activation,
    }
    lease_record = _command(
        activation_digest=activation,
        command_id="command:lease-active",
        command_kind="lease.record",
        payload=lease,
        expected_head=head,
        issued_at=issued_at,
        authorization=_grant_authorization(grants["lease_manager"]),
    )
    head = service.commit(lease_record)["batch_digest"]
    card = _mutation_card(
        service,
        task,
        lease,
        grants["holder"],
        grants["reader"],
        "task.transition",
    )
    leased = _bind_mutation(
        _command(
            activation_digest=activation,
            command_id="command:task-leased",
            command_kind="task.transition",
            payload={"task_id": task["task_id"], "from_state": "READY", "to_state": "LEASED", "reason": "lease active"},
            expected_head=head,
            issued_at=issued_at,
            authorization=_grant_authorization(grants["planner"]),
        ),
        card,
        grants["holder"],
    )
    head = service.commit(leased, workcard=card)["batch_digest"]
    return service, grants, task, lease, head


def test_service_bootstrap_task_relations_and_replay(tmp_path: Path) -> None:
    service, authority, initialized = _initialized_service(tmp_path)
    activation = initialized["activation_digest"]
    issued_at = _at()
    manager = _grant(
        authority,
        activation,
        issued_at,
        grant_id="grant:service-manager",
        capability="authority.manage",
    )
    root_command = _command(
        activation_digest=activation,
        command_id="command:bootstrap-planner",
        command_kind="grant.issue",
        payload=manager,
        expected_head=None,
        issued_at=issued_at,
        authorization={
            "kind": "root",
            "subject_id": "owner",
            "proofs": [
                {
                    "kind": "local-root-command",
                    "subject_id": "owner",
                    "authority_init_digest": digest_value(authority),
                    "signed_intent_digest": "pending",
                }
            ],
        },
    )
    root_command["authorization"]["proofs"][0]["signed_intent_digest"] = root_command[
        "intent_digest"
    ]
    first = service.commit(root_command)
    grant = _grant(
        authority,
        activation,
        issued_at,
        grant_id="grant:service-planner",
        capability="task.plan",
        issuer=manager,
    )
    planner_command = _command(
        activation_digest=activation,
        command_id="command:issue-planner",
        command_kind="grant.issue",
        payload=grant,
        expected_head=first["batch_digest"],
        issued_at=issued_at,
        authorization={
            "kind": "grant",
            "grant_id": manager["grant_id"],
            "grant_claim_digest": manager["claim_digest"],
        },
    )
    second = service.commit(planner_command)
    worker = _grant(
        authority,
        activation,
        issued_at,
        grant_id="grant:service-worker",
        capability="task.execute",
        issuer=manager,
    )
    worker_command = _command(
        activation_digest=activation,
        command_id="command:issue-worker",
        command_kind="grant.issue",
        payload=worker,
        expected_head=second["batch_digest"],
        issued_at=issued_at,
        authorization=_grant_authorization(manager),
    )
    third = service.commit(worker_command)
    candidate = {
        "record_type": "Candidate",
        "candidate_id": "candidate:service-primary",
        "candidate_digest": "1" * 64,
        "inventory_digest": "2" * 64,
        "product_root_digest": "3" * 64,
        "control_excluded": True,
        "candidate_recipe_digest": digest_value(
            service._context().plans["project.json"]["candidate_recipe"]
        ),
        "consistency_mode": "observational-best-effort",
        "creditable": False,
    }
    candidate_command = _command(
        activation_digest=activation,
        command_id="command:record-candidate",
        command_kind="candidate.record",
        payload=candidate,
        expected_head=third["batch_digest"],
        issued_at=issued_at,
        authorization=_grant_authorization(worker),
        effect_scope=[
            {"kind": "candidate", "value": candidate["candidate_id"]}
        ],
    )
    fourth = service.commit(candidate_command)

    prerequisite = {
        "record_type": "Task",
        "task_id": "task:prerequisite",
        "state": "PLANNED",
        "required_capability": "task.execute",
        "acceptance_predicate": "the prerequisite is explicitly represented",
        "allowed_paths": ["src/**"],
        "activation_digest": activation,
        "candidate_digest": candidate["candidate_digest"],
        "created_at": issued_at,
    }
    prerequisite = _task_with_gate_definition(
        service,
        prerequisite,
        defined_at_head_digest=fourth["batch_digest"],
        gate_id="gate:service-prerequisite",
    )
    prerequisite_command = _command(
        activation_digest=activation,
        command_id="command:record-prerequisite",
        command_kind="task.record",
        payload=prerequisite,
        expected_head=fourth["batch_digest"],
        issued_at=issued_at,
        authorization=_grant_authorization(grant),
    )
    fifth = service.commit(prerequisite_command)

    task = {
        "record_type": "Task",
        "task_id": "task:service-primary",
        "state": "PLANNED",
        "required_capability": "task.execute",
        "acceptance_predicate": "the imported dependency is explicit",
        "allowed_paths": ["src/**"],
        "activation_digest": activation,
        "candidate_digest": candidate["candidate_digest"],
        "created_at": issued_at,
    }
    task = _task_with_gate_definition(
        service,
        task,
        defined_at_head_digest=fifth["batch_digest"],
        gate_id="gate:service-primary",
    )
    task_command = _command(
        activation_digest=activation,
        command_id="command:record-task",
        command_kind="task.record",
        payload=task,
        expected_head=fifth["batch_digest"],
        issued_at=issued_at,
        authorization=_grant_authorization(grant),
    )
    relation = {
        "record_type": "Relation",
        "relation_id": "relation:task-dependency",
        "kind": "DEPENDS_ON",
        "source_type": "Task",
        "source_id": task["task_id"],
        "target_type": "Task",
        "target_id": "task:prerequisite",
        "activation_digest": activation,
        "created_at": issued_at,
    }
    committed = service.commit(task_command, auxiliary_relations=[relation])
    assert committed["outcome"] == "committed"
    assert service.commit(task_command, auxiliary_relations=[relation])["outcome"] == "idempotent-replay"

    changed = deepcopy(relation)
    changed["target_id"] = "task:different-prerequisite"
    with pytest.raises(CommandConflict):
        service.commit(task_command, auxiliary_relations=[changed])

    validation = service.validate()
    assert validation["validated_event_batches"] == 6
    assert relation in _semantic_records(service)
    assert validation["product_acceptance_pass"] is False
    assert validation["public_release_approved"] is False


def test_uninitialized_status_is_one_canonical_diagnostic_record(
    tmp_path: Path, capfdbinary: pytest.CaptureFixture[bytes]
) -> None:
    assert main(["--root", str(tmp_path / "missing"), "status"]) == 0
    captured = capfdbinary.readouterr()
    assert captured.err == b""
    assert captured.out.endswith(b"\n")
    assert not captured.out.endswith(b"\n\n")
    payload = parse_json_strict(captured.out)
    assert payload["record_type"] == "ProminStatus"
    assert payload["status"] == "not-initialized"
    assert payload["authority"] is False
    assert payload["pass_credit"] is False
    assert captured.out == canonical_bytes(payload)


def test_team_signed_cli_init_doctor_status_validate_and_internal_commit(
    tmp_path: Path,
) -> None:
    project, _authority, _proofs, init_argv = _team_cli_fixture(tmp_path)

    def invoke(argv: list[str]) -> dict[str, Any]:
        completed = subprocess.run(
            [sys.executable, "-m", "promin", *argv],
            cwd=PACKAGE_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr.decode("utf-8")
        assert completed.stderr == b""
        result = parse_json_strict(completed.stdout)
        assert isinstance(result, dict)
        return result

    initialized = invoke(init_argv)
    activation_digest = initialized["activation_digest"]
    doctor = invoke(["--root", str(project), "doctor"])
    status = invoke(["--root", str(project), "status"])
    validation = invoke(["--root", str(project), "validate"])
    # The strict expert path installs canonical Core and provider bindings only.
    # Derived documentation, context, host surfaces and projection are deliberately
    # absent until the guided refresh/repair boundary, so portability doctor must
    # report a truthful degraded state rather than a false green result.
    assert doctor["status"] == "degraded"
    assert doctor["core"]["status"] == "incomplete"
    assert doctor["core"]["components"]["projection"]["status"] == "incomplete"
    assert doctor["repair_available"] is True
    assert status["core"]["product_acceptance_pass"] is False
    assert validation["product_acceptance_pass"] is False
    signature_health = next(
        item
        for item in doctor["core"]["provider_adapters"]
        if item["capability_id"] == "signature"
    )
    assert signature_health["adapter_id"] == "python-module-signature-v1"
    assert signature_health["persistence_scope"] == "content-addressed-receipt"
    assert signature_health["reconstructable"] is True

    issued_at = _at()
    expires_at = (
        datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        + timedelta(days=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    def signed(digest: str) -> str:
        return hashlib.sha256(
            f"{digest}:fixture-public-key".encode("utf-8")
        ).hexdigest()

    grant = {
        "record_type": "Grant",
        "grant_id": "grant:team-cli-authority",
        "subject_id": "owner",
        "capability_id": "authority.manage",
        "scope": [{"kind": "project", "value": "project-1"}],
        "activation_digest": activation_digest,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": "nonce-team-cli-authority-0001",
    }
    grant["claim_digest"] = digest_value(grant)
    grant["trust_proofs"] = [
        {
            "kind": "signature",
            "key_id": "key-owner",
            "algorithm": "fixture-sha256-boundary",
            "signed_digest": grant["claim_digest"],
            "signature": signed(grant["claim_digest"]),
        }
    ]
    command = _command(
        activation_digest=activation_digest,
        command_id="command:team-cli-bootstrap",
        command_kind="grant.issue",
        payload=grant,
        expected_head=None,
        issued_at=issued_at,
        authorization={
            "kind": "root",
            "subject_id": "owner",
            "proofs": [
                {
                    "kind": "signature-command",
                    "key_id": "key-owner",
                    "algorithm": "fixture-sha256-boundary",
                    "signed_intent_digest": "0" * 64,
                    "signature": "pending",
                }
            ],
        },
    )
    command_proof = command["authorization"]["proofs"][0]
    command_proof["signed_intent_digest"] = command["intent_digest"]
    command_proof["signature"] = signed(command["intent_digest"])
    committed = ProminService(project).commit(command)
    assert committed["outcome"] == "committed"
    assert invoke(["--root", str(project), "status"])["core"]["head"][
        "batch_digest"
    ] == committed["batch_digest"]

    context = ProminService(project)._context()
    signature_adapter = context.provider_dispatch.adapter("signature")
    assert signature_adapter.adapter_id == "python-module-signature-v1"
    assert signature_adapter.reconstructable is True
    assert context.provider_dispatch.binding_evidence()[-1]["provider_id"] == (
        "provider-team-signature"
    )
    signature_source = Path(
        context.provider_dispatch.binding("signature")["identity"]["source"]
    )
    # Receipts are deliberately read-only after installation.  Clear that
    # platform attribute here so this adversarial test can mutate the exact
    # file and prove the next verification rejects it on Windows as well.
    os.chmod(signature_source, stat.S_IWRITE | stat.S_IREAD)
    signature_source.write_text(
        signature_source.read_text(encoding="utf-8") + "\n# identity drift\n",
        encoding="utf-8",
    )
    rejected = subprocess.run(
        [sys.executable, "-m", "promin", "--root", str(project), "status"],
        cwd=PACKAGE_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    # ``status`` is a diagnostic surface: provider drift must fail closed in
    # the Core state without making the status command itself unreadable.
    assert rejected.returncode == 0
    assert rejected.stderr == b""
    failure = parse_json_strict(rejected.stdout)
    assert failure["status"] == "degraded"
    assert failure["core"]["status"] == "failed"
    assert "provider receipt digest mismatch" in failure["core"]["reason"]
    assert failure["authority"] is False
    assert failure["pass_credit"] is False


def test_cli_surface_is_exactly_six_operational_commands() -> None:
    parser = _parser()
    subcommands = next(
        action.choices
        for action in parser._actions
        if isinstance(getattr(action, "choices", None), dict)
    )
    assert tuple(subcommands) == BASE_COMMANDS
    assert "commit" not in subcommands


def test_authority_checkpoint_roundtrip_is_strict_and_canonical(tmp_path: Path) -> None:
    authority = {
        "record_type": "AuthorityInit",
        "trust_mode": "local-owner",
        "subjects": [
            {"subject_id": "owner", "kind": "human", "display_name": "Owner"}
        ],
        "roots": [
            {
                "subject_id": "owner",
                "capability_ceiling": [
                    "authority.manage",
                    "finding.record",
                    "task.execute",
                    "task.plan",
                ],
                "scope": [{"kind": "project", "value": "project-1"}],
            }
        ],
    }
    activation = "a" * 64
    issued_at = _at()
    decisions: dict[str, dict[str, Any]] = {}
    runtime_policy = _authority_runtime_policy()
    engine = AuthorityEngine(
        authority,
        activation,
        runtime_policy,
        decision_resolver=decisions.get,
    )
    manager = _grant(
        authority,
        activation,
        issued_at,
        grant_id="grant:checkpoint-manager",
        capability="authority.manage",
    )
    planner = _grant(
        authority,
        activation,
        issued_at,
        grant_id="grant:checkpoint-planner",
        capability="task.plan",
        issuer=manager,
    )
    executor = _grant(
        authority,
        activation,
        issued_at,
        grant_id="grant:checkpoint-executor",
        capability="task.execute",
        issuer=manager,
    )
    finder = _grant(
        authority,
        activation,
        issued_at,
        grant_id="grant:checkpoint-finder",
        capability="finding.record",
        issuer=manager,
    )
    _persist_test_grant(engine, authority, activation, manager)
    _persist_test_grant(engine, authority, activation, planner, issuer=manager)
    _persist_test_grant(engine, authority, activation, executor, issuer=manager)
    _persist_test_grant(engine, authority, activation, finder, issuer=manager)
    engine.record_action(
        "owner",
        "task.execute",
        authorization={
            "subject_id": "owner",
            "grant_id": executor["grant_id"],
            "claim_digest": executor["claim_digest"],
            "evaluated_at": issued_at,
            "requested_scope": executor["scope"],
        },
        candidate_digest="c" * 64,
    )
    engine.record_action(
        "owner",
        "finding.record",
        authorization={
            "subject_id": "owner",
            "grant_id": finder["grant_id"],
            "claim_digest": finder["claim_digest"],
            "evaluated_at": issued_at,
            "requested_scope": finder["scope"],
        },
        finding_id="finding:checkpoint",
    )
    decision = {
        "record_type": "Decision",
        "decision_id": "decision:checkpoint-revocation",
        "decision_kind": "revoke",
        "subject_id": "owner",
        "grant_id": manager["grant_id"],
        "grant_claim_digest": manager["claim_digest"],
        "activation_digest": activation,
        "target_type": "Grant",
        "target_id": planner["grant_id"],
        "target_digest": digest_value(planner),
        "rationale": "exercise checkpoint revocation restoration",
        "evidence_artifacts": [
            {
                "artifact_id": "artifact:checkpoint-revocation",
                "artifact_record_digest": "e" * 64,
            }
        ],
        "created_at": issued_at,
    }
    event = {
        "record_type": "Event",
        "event_id": "event:checkpoint-revocation",
        "event_kind": "decision.recorded",
        "activation_digest": activation,
        "payload": decision,
    }
    decisions[decision["decision_id"]] = {"decision": decision, "event": event}
    engine.revoke_grant(
        {
            "grant_id": planner["grant_id"],
            "decision_id": decision["decision_id"],
            "reason": "exercise checkpoint revocation restoration",
            "revoked_at": issued_at,
        },
        manager["grant_id"],
        "owner",
    )
    checkpoint = engine.checkpoint()
    restored = AuthorityEngine(
        authority,
        activation,
        runtime_policy,
        decision_resolver=decisions.get,
    )
    restored.restore_checkpoint(checkpoint)
    assert restored.checkpoint() == checkpoint
    assert restored.grants == engine.grants
    assert restored.revocations == engine.revocations

    tampered = deepcopy(checkpoint)
    tampered["nonces"][0]["grant_id"] = "grant:substituted"
    tampered["checkpoint_digest"] = digest_value(
        {key: value for key, value in tampered.items() if key != "checkpoint_digest"}
    )
    with pytest.raises(AuthorityError, match="nonce map mismatch"):
        restored.restore_checkpoint(tampered)


def test_provider_dispatch_rejects_unknown_capability(tmp_path: Path) -> None:
    provider = Path(sys.executable).resolve()
    technologies = {
        "record_type": "TechnologiesInit",
        "bindings": [
            {
                "capability_id": "unknown-provider-capability",
                "provider_id": "provider-unknown",
                "version": "1.0.0",
                "invocation": {"kind": "python-runtime", "value": str(provider)},
                "purpose": "exercise unknown provider rejection",
                "required": True,
                "healthcheck": {
                    "argv": [str(provider), "--version"],
                    "timeout_ms": 1000,
                    "expected_exit": 0,
                },
                "license": {
                    "expression": "PSF-2.0",
                    "source_uris": ["https://docs.python.org/3/license.html"],
                    "review_state": "source-verified",
                },
                "identity": {
                    "kind": "file-digest",
                    "digest": digest_file(provider),
                    "source": str(provider),
                },
            }
        ],
    }
    with pytest.raises(InitError, match="unsupported provider capability"):
        resolve_provider_dispatch(technologies, tmp_path)


def test_import_grant_revocation_uses_command_bound_schema_only(tmp_path: Path) -> None:
    service, grants, task, lease, head = _leased_service(tmp_path)
    issued_at = _at()

    evidence_bytes = b"verified authority revocation evidence\n"
    context = service._context()
    artifact = {
        "record_type": "Artifact",
        "artifact_id": "artifact:synthetic-revocation",
        "artifact_kind": "evidence",
        "digest": hashlib.sha256(evidence_bytes).hexdigest(),
        "media_type": "text/plain",
        "size_bytes": len(evidence_bytes),
        "retention_class": "audit",
        "created_at": issued_at,
        "evidence_binding": {
            "activation_digest": task["activation_digest"],
            "candidate_digest": task["candidate_digest"],
            "policy_digest": "4" * 64,
            "tool_digest": "5" * 64,
            "input_digests": ["6" * 64],
            "implementation_closure_digest": context.implementation_closure_digest,
        },
        "outcome": "fail",
        "stale": False,
        "unresolved": False,
        "evidence_class": "validator",
        "evidence_purpose": "gate",
        "product_credit_eligible": False,
    }
    artifact_card = _mutation_card(
        service,
        task,
        lease,
        grants["holder"],
        grants["reader"],
        "artifact.record",
    )
    artifact_command = _bind_mutation(
        _command(
            activation_digest=task["activation_digest"],
            command_id="command:synthetic-revocation-evidence",
            command_kind="artifact.record",
            payload=artifact,
            expected_head=head,
            issued_at=issued_at,
            authorization=_grant_authorization(grants["publisher"]),
            effect_scope=[
                {"kind": "artifact", "value": artifact["artifact_id"]}
            ],
        ),
        artifact_card,
        grants["holder"],
    )
    published = service.publish_evidence(
        artifact_command,
        evidence_bytes,
        workcard=artifact_card,
    )
    head = published["command_result"]["batch_digest"]
    finalized = _reconciled_evidence(
        service.root,
        service._event_store(service._context()),
    ).get_record(artifact["artifact_id"])
    reference = {
        "artifact_id": artifact["artifact_id"],
        "artifact_record_digest": digest_value(finalized),
    }

    decision = {
        "record_type": "Decision",
        "decision_id": "decision:synthetic-revocation",
        "decision_kind": "revoke",
        "subject_id": "owner",
        "grant_id": grants["manager"]["grant_id"],
        "grant_claim_digest": grants["manager"]["claim_digest"],
        "activation_digest": task["activation_digest"],
        "target_type": "Grant",
        "target_id": grants["finder"]["grant_id"],
        "target_digest": digest_value(grants["finder"]),
        "rationale": "exercise the command-bound GrantRevocation import schema",
        "evidence_artifacts": [reference],
        "created_at": _at(1),
    }
    decision_command = _command(
        activation_digest=task["activation_digest"],
        command_id="command:record-synthetic-revocation-decision",
        command_kind="decision.record",
        payload=decision,
        expected_head=head,
        issued_at=decision["created_at"],
        authorization=_grant_authorization(grants["manager"]),
    )
    head = service.commit(decision_command)["batch_digest"]

    revocation = {
        "grant_id": grants["finder"]["grant_id"],
        "decision_id": decision["decision_id"],
        "reason": "exercise the command-bound GrantRevocation import schema",
        "revoked_at": _at(2),
    }
    command = _command(
        activation_digest=task["activation_digest"],
        command_id="command:import-grant-revocation",
        command_kind="grant.revoke",
        payload=revocation,
        expected_head=head,
        issued_at=revocation["revoked_at"],
        authorization=_grant_authorization(grants["manager"]),
    )
    substituted = {**revocation, "reason": "substituted expected record"}
    with pytest.raises(ServiceError, match="expected record differs"):
        import_fact(
            service.root,
            fact_id="migration:substituted-grant-revocation",
            command=command,
            expected_record=substituted,
            provenance={"source": "synthetic-import-boundary-test"},
            expected_head=head,
        )
    imported = import_fact(
        service.root,
        fact_id="migration:grant-revocation",
        command=command,
        expected_record=revocation,
        provenance={"source": "synthetic-import-boundary-test"},
        expected_head=head,
    )
    assert imported["status"] == "pass"
    assert revocation in _semantic_records(service)

    missing_record_type = {
        "task_id": "task:implicit-type-forbidden",
        "state": "PLANNED",
        "required_capability": "task.execute",
        "acceptance_predicate": "implicit record typing stays forbidden",
        "allowed_paths": [],
        "activation_digest": task["activation_digest"],
        "candidate_digest": task["candidate_digest"],
        "created_at": _at(3),
    }
    current_head = imported["head_digest"]
    task_command = _command(
        activation_digest=task["activation_digest"],
        command_id="command:implicit-task-type-forbidden",
        command_kind="task.record",
        payload={"record_type": "Task", **missing_record_type},
        expected_head=current_head,
        issued_at=missing_record_type["created_at"],
        authorization=_grant_authorization(grants["planner"]),
    )
    with pytest.raises(ServiceError, match="unknown or missing record_type"):
        import_fact(
            service.root,
            fact_id="migration:implicit-task-type-forbidden",
            command=task_command,
            expected_record=missing_record_type,
            provenance={"source": "synthetic-import-boundary-test"},
            expected_head=current_head,
        )


def test_projection_rebuild_keeps_latest_lease_lifecycle_state(tmp_path: Path) -> None:
    service, grants, task, lease, head = _leased_service(tmp_path)
    terminated_at = _at()
    revoked = {
        **lease,
        "state": "REVOKED",
        "termination": {
            "state": "REVOKED",
            "terminated_by": lease["manager_subject_id"],
            "grant_id": lease["manager_grant_id"],
            "grant_claim_digest": lease["manager_grant_claim_digest"],
            "terminated_at": terminated_at,
            "generation": lease["generation"],
            "fencing_token": lease["fencing_token"],
        },
    }
    command = _command(
        activation_digest=task["activation_digest"],
        command_id="command:projection-revoked-lease",
        command_kind="lease.record",
        payload=revoked,
        expected_head=head,
        issued_at=terminated_at,
        authorization=_grant_authorization(grants["lease_manager"]),
    )
    committed = service.commit(command)
    rebuilt = service.rebuild()
    result = service.search(
        lease["lease_id"],
        subject_id="owner",
        grant_id=grants["reader"]["grant_id"],
    )
    assert committed["outcome"] == "committed"
    assert rebuilt["head_digest"] == committed["batch_digest"]
    assert result["entities"][0]["payload"]["state"] == "REVOKED"


def test_next_uses_separate_query_and_holder_grants(tmp_path: Path) -> None:
    service, grants, task, _lease, head = _leased_service(tmp_path)
    recorded_at = _at()
    ready_task = {
        **task,
        "task_id": "task:next-ready",
        "state": "PLANNED",
        "created_at": recorded_at,
    }
    ready_task = _task_with_gate_definition(
        service,
        ready_task,
        defined_at_head_digest=head,
        gate_id="gate:next-ready",
    )
    recorded = _command(
        activation_digest=task["activation_digest"],
        command_id="command:next-ready-record",
        command_kind="task.record",
        payload=ready_task,
        expected_head=head,
        issued_at=recorded_at,
        authorization=_grant_authorization(grants["planner"]),
    )
    head = service.commit(recorded)["batch_digest"]
    ready = _command(
        activation_digest=task["activation_digest"],
        command_id="command:next-ready-transition",
        command_kind="task.transition",
        payload={
            "task_id": ready_task["task_id"],
            "from_state": "PLANNED",
            "to_state": "READY",
            "reason": "exercise next query authorization",
        },
        expected_head=head,
        issued_at=_at(),
        authorization=_grant_authorization(grants["planner"]),
    )
    service.commit(ready)
    service.rebuild()
    result = service.next(
        subject_id="owner",
        grant_id=grants["holder"]["grant_id"],
        query_grant_id=grants["reader"]["grant_id"],
    )
    card = result["work_card"]
    assert list(result) == [
        "record_type",
        "status",
        "subject_id",
        "activation_digest",
        "work_card",
        "continuation",
    ]
    assert result["status"] == "ready"
    assert result["continuation"] is None
    assert card["task_id"] == ready_task["task_id"]
    assert card["holder_grant_id"] == grants["holder"]["grant_id"]
    assert card["query_grant_id"] == grants["reader"]["grant_id"]
    assert card["query_grant_claim_digest"] == grants["reader"]["claim_digest"]


def test_authorized_continuation_rejects_public_derived_authenticator(
    tmp_path: Path,
) -> None:
    service, grants, task, _lease, head = _leased_service(tmp_path)
    ready_ids: list[str] = []
    for ordinal in range(2):
        ready_task = {
            **task,
            "task_id": f"task:continued-ready-{ordinal}",
            "state": "PLANNED",
            "created_at": _at(ordinal + 1),
        }
        ready_task = _task_with_gate_definition(
            service,
            ready_task,
            defined_at_head_digest=head,
            gate_id=f"gate:continued-ready-{ordinal}",
        )
        head = service.commit(
            _command(
                activation_digest=task["activation_digest"],
                command_id=f"command:continued-ready-record-{ordinal}",
                command_kind="task.record",
                payload=ready_task,
                expected_head=head,
                issued_at=ready_task["created_at"],
                authorization=_grant_authorization(grants["planner"]),
            )
        )["batch_digest"]
        head = service.commit(
            _command(
                activation_digest=task["activation_digest"],
                command_id=f"command:continued-ready-transition-{ordinal}",
                command_kind="task.transition",
                payload={
                    "task_id": ready_task["task_id"],
                    "from_state": "PLANNED",
                    "to_state": "READY",
                    "reason": "exercise ReadyFrontier continuation",
                },
                expected_head=head,
                issued_at=ready_task["created_at"],
                authorization=_grant_authorization(grants["planner"]),
            )
        )["batch_digest"]
        ready_ids.append(ready_task["task_id"])
    service.rebuild()
    issued = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=3)
    first = service.next(
        subject_id="owner",
        grant_id=grants["holder"]["grant_id"],
        query_grant_id=grants["reader"]["grant_id"],
        now=issued,
        ttl_seconds=60,
    )
    assert list(first) == [
        "record_type",
        "status",
        "subject_id",
        "activation_digest",
        "work_card",
        "continuation",
    ]
    assert first["work_card"]["task_id"] == ready_ids[0]
    assert first["work_card"]["truncated"] is True
    token = first["continuation"]
    assert isinstance(token, str)
    assert len(token.encode("ascii")) <= 256
    assert len(token.encode("ascii")) * 10 <= first["work_card"]["budget"]["max_bytes"]
    projection_path = (
        service.root / ".promin" / "state" / "projection" / "promin.sqlite3"
    )
    handle = token.split(".")[1]
    with sqlite3.connect(projection_path) as connection:
        state_row = connection.execute(
            "SELECT length(payload_json) FROM continuations WHERE handle=?",
            (handle,),
        ).fetchone()
    assert state_row is not None and state_row[0] <= 16_384
    continued = service.continue_search(
        token,
        subject_id="owner",
        grant_id=grants["reader"]["grant_id"],
        now=issued + timedelta(seconds=1),
    )
    assert list(continued) == [
        "record_type",
        "status",
        "subject_id",
        "activation_digest",
        "work_card",
        "continuation",
    ]
    assert continued["record_type"] == "ContinueResult"
    assert continued["work_card"]["task_id"] == ready_ids[1]
    assert continued["continuation"] is None

    forged_parts = token.split(".")
    signature = bytearray(
        base64.urlsafe_b64decode(
            forged_parts[-1] + "=" * (-len(forged_parts[-1]) % 4)
        )
    )
    signature[0] ^= 0x01
    forged_parts[-1] = (
        base64.urlsafe_b64encode(bytes(signature)).rstrip(b"=").decode("ascii")
    )
    forged = ".".join(forged_parts)
    with pytest.raises(ProjectionError, match="continuation signature mismatch"):
        service.continue_search(
            forged,
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=issued + timedelta(seconds=1),
        )
    with pytest.raises((AuthorityError, ServiceError)):
        service.continue_search(
            token,
            subject_id="different-subject",
            grant_id=grants["reader"]["grant_id"],
            now=issued + timedelta(seconds=1),
        )
    with pytest.raises(ProjectionError, match="expired"):
        service.continue_search(
            token,
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=issued + timedelta(seconds=60),
        )
    with sqlite3.connect(projection_path) as connection:
        connection.execute(
            "UPDATE continuations SET payload_json=payload_json || ' ' WHERE handle=?",
            (handle,),
        )
        connection.commit()
    with pytest.raises(ProjectionError, match="noncanonical or tampered"):
        service.continue_search(
            token,
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=issued + timedelta(seconds=1),
        )


def test_inventory_rebuild_uses_verified_one_proxy_rows_only(tmp_path: Path) -> None:
    service, _authority, _initialized = _initialized_service(tmp_path)
    source = service.root / "src" / "one.txt"
    source.parent.mkdir()
    source.write_text("one\n", encoding="utf-8")
    inventory = inventory_candidate(service.root, ["."])
    assert len(inventory.entries) == 1
    assert not isinstance(inventory.entries, (list, tuple))
    assert inventory.stream_path is not None and inventory.stream_path.is_file()
    assert inventory.stream_bytes == inventory.stream_path.stat().st_size
    assert inventory.stream_digest == hashlib.sha256(inventory.stream_path.read_bytes()).hexdigest()
    assert inventory.manifest_digest is not None
    row = inventory.entries[0]
    assert set(row) == {"record_type", "path", "digest", "size", "semantic_proxy"}
    assert row["semantic_proxy"]["entity_type"] == "Artifact"
    assert row["semantic_proxy"]["payload"]["record_type"] == "Artifact"
    assert "semantic_proxies" not in row
    assert "typed_relations" not in row
    rebuilt = service.rebuild(inventory)
    assert rebuilt["inventory_entries"] == 1
    assert rebuilt["inventory_proxies"] == 1
    assert rebuilt["raw_file_proxy_ratio"] == 1
    assert rebuilt["synthetic_task_count"] == 0
    assert rebuilt["synthetic_task_ratio"] == 0
    assert rebuilt["inventory_stream_bytes"] == inventory.stream_bytes
    assert rebuilt["inventory_projection_amplification"] > 0
    with pytest.raises(ServiceError, match="verified InventoryResult"):
        service.rebuild(list(inventory.entries))  # type: ignore[arg-type]
    substituted = InventoryResult(
        candidate=inventory.candidate,
        entries=(),
        observed_at=inventory.observed_at,
        provider_invocations=inventory.provider_invocations,
    )
    with pytest.raises(ServiceError, match="differs from the verified"):
        service.rebuild(substituted)


def test_inventory_content_is_searchable_without_putting_source_text_in_payload(
    tmp_path: Path,
) -> None:
    service, grants, _task, _lease, _head = _leased_service(tmp_path)
    source = service.root / "src" / "semantic-source.txt"
    source.parent.mkdir(exist_ok=True)
    source.write_text("representative semantic source boundary", encoding="utf-8")
    inventory = inventory_candidate(service.root, ["."])
    rebuilt = service.rebuild(inventory)
    assert rebuilt["product_passes"] == 0
    result = service.search(
        "semantic source",
        subject_id="owner",
        grant_id=grants["reader"]["grant_id"],
    )
    matches = [
        entity
        for entity in result["entities"]
        if entity["payload"].get("inventory_path") == "src/semantic-source.txt"
    ]
    assert len(matches) == 1
    assert "search_text" not in matches[0]["payload"]
    assert result["silent_truncation"] is False


def test_runtime_cache_advances_on_local_commit_and_invalidates_on_external_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, grants, task, _lease, head = _leased_service(tmp_path)
    service.rebuild()
    original_runtime_state = service._runtime_state
    original_ranked_candidates = Projection._ranked_candidates
    runtime_state_calls = 0
    ranked_candidate_calls = 0
    derived_state_reads = 0
    derived_tail_status_calls = 0
    event_store_initializations = 0

    def counted_runtime_state(context, store):
        nonlocal runtime_state_calls
        runtime_state_calls += 1
        return original_runtime_state(context, store)

    def counted_ranked_candidates(connection, query, top_k):
        nonlocal ranked_candidate_calls
        ranked_candidate_calls += 1
        return original_ranked_candidates(connection, query, top_k)

    original_read_derived_state = EventStore.read_derived_state
    original_derived_tail_status = EventStore.derived_tail_status
    original_event_store_init = EventStore.__init__

    def counted_read_derived_state(store, name):
        nonlocal derived_state_reads
        derived_state_reads += 1
        return original_read_derived_state(store, name)

    def counted_derived_tail_status(store, name):
        nonlocal derived_tail_status_calls
        derived_tail_status_calls += 1
        return original_derived_tail_status(store, name)

    def counted_event_store_init(store, *args, **kwargs):
        nonlocal event_store_initializations
        event_store_initializations += 1
        return original_event_store_init(store, *args, **kwargs)

    monkeypatch.setattr(service, "_runtime_state", counted_runtime_state)
    monkeypatch.setattr(
        Projection,
        "_ranked_candidates",
        staticmethod(counted_ranked_candidates),
    )
    monkeypatch.setattr(EventStore, "read_derived_state", counted_read_derived_state)
    monkeypatch.setattr(EventStore, "derived_tail_status", counted_derived_tail_status)
    monkeypatch.setattr(EventStore, "__init__", counted_event_store_init)
    query = {
        "subject_id": "owner",
        "grant_id": grants["reader"]["grant_id"],
    }
    service.search(task["task_id"], **query)
    service.search(task["task_id"], **query)
    assert runtime_state_calls == 0
    assert ranked_candidate_calls == 1
    assert event_store_initializations == 1

    next_task = {
        **task,
        "task_id": "task:query-cache-head-change",
        "state": "PLANNED",
        "created_at": _at(),
    }
    next_task = _task_with_gate_definition(
        service,
        next_task,
        defined_at_head_digest=head,
        gate_id="gate:query-cache-head-change",
    )
    before_commit_initializations = event_store_initializations
    committed = service.commit(
        _command(
            activation_digest=task["activation_digest"],
            command_id="command:query-cache-head-change",
            command_kind="task.record",
            payload=next_task,
            expected_head=head,
            issued_at=_at(),
            authorization=_grant_authorization(grants["planner"]),
        )
    )
    assert runtime_state_calls == 0
    assert committed["operation_metrics"]["changed_records"] == 1
    assert committed["operation_metrics"]["runtime_checkpoint"]["written"] is False
    assert derived_tail_status_calls == 0
    assert committed["operation_metrics"]["projection_update"]["status"] == "updated"
    assert derived_state_reads == 0
    assert event_store_initializations == before_commit_initializations
    service.rebuild()

    before_new_head_query = runtime_state_calls
    before_new_head_query_initializations = event_store_initializations
    service.search(task["task_id"], **query)
    service.search(task["task_id"], **query)
    assert runtime_state_calls == before_new_head_query
    assert ranked_candidate_calls == 2
    assert event_store_initializations == before_new_head_query_initializations

    external_task = {
        **task,
        "task_id": "task:query-cache-external-head",
        "state": "PLANNED",
        "created_at": _at(),
    }
    external_task = _task_with_gate_definition(
        service,
        external_task,
        defined_at_head_digest=committed["batch_digest"],
        gate_id="gate:query-cache-external-head",
    )
    external_committed = ProminService(service.root).commit(
        _command(
            activation_digest=task["activation_digest"],
            command_id="command:query-cache-external-head",
            command_kind="task.record",
            payload=external_task,
            expected_head=committed["batch_digest"],
            issued_at=_at(),
            authorization=_grant_authorization(grants["planner"]),
        )
    )
    before_external_head_query_initializations = event_store_initializations
    service.search(task["task_id"], **query)
    service.search(task["task_id"], **query)
    assert runtime_state_calls == before_new_head_query + 1
    assert ranked_candidate_calls == 3
    assert event_store_initializations == before_external_head_query_initializations
    assert external_committed["batch_digest"] == service._event_store(service._context()).head()[
        "batch_digest"
    ]


def test_doctor_never_promotes_tampered_projection_authority(tmp_path: Path) -> None:
    service, _authority, _initialized = _initialized_service(tmp_path)
    service.rebuild()
    projection_path = (
        service.root / ".promin" / "state" / "projection" / "promin.sqlite3"
    )
    with sqlite3.connect(projection_path) as connection:
        connection.execute(
            "UPDATE metadata SET value='true' WHERE key='projection_authoritative'"
        )
        connection.commit()

    health = service.doctor(replay=False)
    assert health["projection"] == {
        "status": "missing",
        "projection_authoritative": False,
    }
    assert health["claim_scope"] == "runtime-health-only"
    assert health["report_authoritative"] is False
    assert health["pass_credit"] is False
    assert health["product_acceptance_pass"] is False
    assert health["product_public_approval"] == "not_approved"


def test_service_resolves_distinct_transition_and_holder_grants(tmp_path: Path) -> None:
    service, grants, task, lease, head = _leased_service(tmp_path)
    assert grants["planner"]["grant_id"] != grants["holder"]["grant_id"]
    health = service.doctor()
    assert health["head"]["batch_digest"] == head
    assert health["claim_scope"] == "runtime-health-only"
    assert health["report_authoritative"] is False
    assert health["pass_credit"] is False
    assert health["product_acceptance_pass"] is False
    assert health["product_public_approval"] == "not_approved"
    assert health["metrics"]["core_artifacts_verified"] == 6
    assert health["metrics"]["init_records_verified"] == 5
    assert health["metrics"]["provider_healthchecks_executed"] == 5
    assert not any("token" in key or "cost" in key or "usage" in key for key in health["metrics"])
    assert service.status()["product_acceptance_pass"] is False
    assert lease["holder_grant_id"] == grants["holder"]["grant_id"]
    assert task["state"] == "PLANNED"

    evidence_bytes = b"validated mutation evidence\n"
    evidence_digest = hashlib.sha256(evidence_bytes).hexdigest()
    policy_digest = "4" * 64
    tool_digest = "5" * 64
    input_digests = ["6" * 64]
    provider_invocations = list(
        service._context().provider_dispatch.binding_evidence()
    )
    artifact = {
        "record_type": "Artifact",
        "artifact_id": "artifact:mutation-evidence",
        "artifact_kind": "evidence",
        "digest": evidence_digest,
        "media_type": "text/plain",
        "size_bytes": len(evidence_bytes),
        "retention_class": "audit",
        "created_at": _at(),
        "evidence_binding": {
            "activation_digest": task["activation_digest"],
            "candidate_digest": task["candidate_digest"],
            "policy_digest": policy_digest,
            "tool_digest": tool_digest,
            "input_digests": input_digests,
            "implementation_closure_digest": service._context().implementation_closure_digest,
        },
        "outcome": "fail",
        "stale": False,
        "unresolved": False,
        "evidence_class": "validator",
        "evidence_purpose": "gate",
        "product_credit_eligible": False,
    }
    artifact_card = _mutation_card(service, task, lease, grants["holder"], grants["reader"], "artifact.record")
    artifact_command = _bind_mutation(
        _command(
            activation_digest=task["activation_digest"],
            command_id="command:artifact-evidence",
            command_kind="artifact.record",
            payload=artifact,
            expected_head=head,
            issued_at=_at(),
            authorization=_grant_authorization(grants["publisher"]),
            effect_scope=[{"kind": "artifact", "value": artifact["artifact_id"]}],
        ),
        artifact_card,
        grants["holder"],
    )
    publication = service.publish_evidence(
        artifact_command,
        evidence_bytes,
        workcard=artifact_card,
    )
    head = publication["command_result"]["batch_digest"]
    assert publication["artifact"] == artifact
    assert publication["commit_binding"]["batch_digest"] == head
    finalized_artifact = _reconciled_evidence(
        service.root,
        service._event_store(service._context()),
    ).get_record(artifact["artifact_id"])
    artifact_reference = {
        "artifact_id": artifact["artifact_id"],
        "artifact_record_digest": digest_value(finalized_artifact),
    }

    finding = {
        "record_type": "Finding",
        "finding_id": "finding:mutation-evidence",
        "status": "OPEN",
        "severity": "P2",
        "blocking": False,
        "statement": "distinct command and holder Grants were exercised",
        "activation_digest": task["activation_digest"],
        "candidate_digest": task["candidate_digest"],
        "evidence_artifacts": [artifact_reference],
        "created_at": _at(),
    }
    finding_card = _mutation_card(service, task, lease, grants["holder"], grants["reader"], "finding.record")
    finding_command = _bind_mutation(
        _command(
            activation_digest=task["activation_digest"],
            command_id="command:finding-record",
            command_kind="finding.record",
            payload=finding,
            expected_head=head,
            issued_at=_at(),
            authorization=_grant_authorization(grants["finder"]),
            effect_scope=[{"kind": "finding", "value": finding["finding_id"]}],
        ),
        finding_card,
        grants["holder"],
    )
    head = service.commit(finding_command, workcard=finding_card)["batch_digest"]

    definition_binding = task["gate_run_definitions"][0]
    definition_digest = definition_binding["definition_digest"]
    run_time = _at()
    run = {
        "record_type": "Run",
        "run_id": "run:mutation-distinct-grants",
        "run_kind": "validation",
        "task_id": task["task_id"],
        "candidate_digest": task["candidate_digest"],
        "policy_digest": policy_digest,
        "tool_digest": tool_digest,
        "input_digests": input_digests,
        "status": "fail",
        "started_at": run_time,
        "finished_at": run_time,
        "activation_digest": task["activation_digest"],
        "definition_digest": definition_digest,
        "implementation_closure_digest": service._context().implementation_closure_digest,
        "provider_binding_digest": digest_value(provider_invocations),
    }
    run_card = _mutation_card(
        service,
        task,
        lease,
        grants["holder"],
        grants["reader"],
        "run.record",
    )
    run_command = _bind_mutation(
        _command(
            activation_digest=task["activation_digest"],
            command_id="command:run-record",
            command_kind="run.record",
            payload=run,
            expected_head=head,
            issued_at=run_time,
            authorization=_grant_authorization(grants["validator"]),
            effect_scope=[
                {"kind": "candidate", "value": task["candidate_digest"]}
            ],
            definition_digest=definition_digest,
        ),
        run_card,
        grants["holder"],
    )
    head = service.commit(run_command, workcard=run_card)["batch_digest"]

    gate = {
        "record_type": "GateResult",
        "gate_id": "gate:mutation-distinct-grants",
        "run_id": run["run_id"],
        "run_digest": digest_value(run),
        "task_id": task["task_id"],
        "definition_digest": definition_digest,
        "status": "fail",
        "outcome": "fail",
        "pass_credit": False,
        "activation_digest": task["activation_digest"],
        "candidate_digest": task["candidate_digest"],
        "policy_digest": policy_digest,
        "tool_digest": tool_digest,
        "evidence_artifacts": [
            {
                **artifact_reference,
                "run_id": run["run_id"],
                "run_digest": digest_value(run),
            }
        ],
        "evidence_class": "validator",
    }
    gate_card = _mutation_card(service, task, lease, grants["holder"], grants["reader"], "gate.record")
    gate_command = _bind_mutation(
        _command(
            activation_digest=task["activation_digest"],
            command_id="command:gate-record",
            command_kind="gate.record",
            payload=gate,
            expected_head=head,
            issued_at=_at(),
            authorization=_grant_authorization(grants["validator"]),
            effect_scope=[{"kind": "candidate", "value": task["candidate_digest"]}],
            definition_digest=definition_digest,
        ),
        gate_card,
        grants["holder"],
    )
    head = service.commit(gate_command, workcard=gate_card)["batch_digest"]
    final_status = service.status()
    assert final_status["product_acceptance_pass"] is False
    assert final_status["public_release_approved"] is False

    crash_bytes = b"staged before simulated process loss\n"
    crash_artifact = deepcopy(artifact)
    crash_artifact.update(
        {
            "artifact_id": "artifact:crash-recovery",
            "digest": hashlib.sha256(crash_bytes).hexdigest(),
            "size_bytes": len(crash_bytes),
            "outcome": "fail",
        }
    )
    crash_card = _mutation_card(service, task, lease, grants["holder"], grants["reader"], "artifact.record")
    crash_command = _bind_mutation(
        _command(
            activation_digest=task["activation_digest"],
            command_id="command:artifact-crash-recovery",
            command_kind="artifact.record",
            payload=crash_artifact,
            expected_head=head,
            issued_at=_at(),
            authorization=_grant_authorization(grants["publisher"]),
            effect_scope=[{"kind": "artifact", "value": crash_artifact["artifact_id"]}],
        ),
        crash_card,
        grants["holder"],
    )
    context = service._context()
    event_store = service._event_store(context)
    snapshot = service._runtime_state(context, event_store)
    authority = snapshot.authority.fork(
        decision_resolver=snapshot.decisions.resolve
    )
    domain = snapshot.domain.fork(authority=authority)
    service._authorize_command(context, authority, crash_command)
    service._apply_command(domain, authority, crash_command, workcard=crash_card)
    domain.evidence.stage(
        crash_artifact,
        crash_bytes,
        command_digest=digest_value(crash_command),
    )
    _persist_workcard(service.root, crash_card)
    event_store.commit(crash_command)
    assert domain.evidence.pending_artifact_ids() == (crash_artifact["artifact_id"],)

    restarted = ProminService(service.root)
    diagnostic = restarted.doctor()
    assert diagnostic["status"] == "incomplete"
    assert diagnostic["components"]["projection"]["status"] == "incomplete"
    restarted.rebuild()
    assert restarted.doctor()["status"] == "healthy"
    recovered = _reconciled_evidence(
        restarted.root,
        restarted._event_store(restarted._context()),
    )
    assert recovered.pending_artifact_ids() == ()
    assert recovered.get(crash_artifact["artifact_id"]) == crash_artifact
