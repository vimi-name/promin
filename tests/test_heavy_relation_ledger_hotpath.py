from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from promin.canonical import atomic_write_json, digest_value, load_json_strict
from promin.contracts import ContractError
from promin.init import bind_implementation_closures
from promin.mutation_suite import MutationFixture
from promin.service import (
    ProminService,
    _RelationLedger,
    ServiceError,
    _validated_auxiliary_relations,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
NOW = "2026-07-17T12:00:00Z"


def _initialized_context(tmp_path_factory: pytest.TempPathFactory):
    fixture = MutationFixture(tmp_path_factory.mktemp("relation-ledger"), PACKAGE_ROOT)
    project, request, _paths = fixture.init_request()
    service = ProminService(project)
    service.initialize(request)
    return service._context()


@pytest.fixture(scope="module")
def activation_context(tmp_path_factory: pytest.TempPathFactory):
    return _initialized_context(tmp_path_factory)


def _command(task_id: str) -> dict[str, Any]:
    return {
        "command_kind": "task.record",
        "payload": {"record_type": "Task", "task_id": task_id},
    }


def _relation(
    relation_id: str,
    *,
    kind: str,
    source_id: str,
    target_id: str,
    target_type: str,
    activation_digest: str,
) -> dict[str, Any]:
    return {
        "record_type": "Relation",
        "relation_id": relation_id,
        "kind": kind,
        "source_type": "Task",
        "source_id": source_id,
        "target_type": target_type,
        "target_id": target_id,
        "activation_digest": activation_digest,
        "created_at": NOW,
    }


def _task(task_id: str) -> dict[str, Any]:
    """Build a schema-valid Task for dependency graph validation."""

    task = {
        "record_type": "Task",
        "task_id": task_id,
        "state": "PLANNED",
        "required_capability": "task.execute",
        "acceptance_predicate": "exercise exact dependency validation",
        "allowed_paths": ["product/**"],
        "activation_digest": "0" * 64,
        "candidate_digest": "1" * 64,
        "created_at": NOW,
    }
    definition = {
        "definition_kind": "GateRunDefinition",
        "definition_id": f"definition:{task_id}",
        "owner_kind": "Task",
        "owner_digest": digest_value(task),
        "defined_at_head_digest": "0" * 64,
        "gate_id": f"gate:{task_id}",
        "run_kind": "validation",
        "expected_evidence_class": "validator",
        "expected_evidence_purpose": "gate",
        "product_credit_required": False,
        "target_kind": "candidate",
        "target_digest": "1" * 64,
        "target_scope": [{"kind": "candidate", "value": "1" * 64}],
        "candidate_digest": "1" * 64,
        "policy_digest": "2" * 64,
        "tool_digest": "3" * 64,
        "implementation_closure_digest": "4" * 64,
        "provider_binding_digest": digest_value([]),
        "input_digests": [],
        "activation_digest": "0" * 64,
    }
    task["gate_run_definitions"] = [
        {
            "definition_digest": digest_value(definition),
            "definition": definition,
        }
    ]
    return task


def _issued_at() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _grant(
    authority: dict[str, Any],
    activation_digest: str,
    issued_at: str,
    *,
    grant_id: str,
    capability: str,
    issuer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a locally rooted grant for the real service regression path."""

    expires_at = (
        datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        + timedelta(days=1)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    grant = {
        "record_type": "Grant",
        "grant_id": grant_id,
        "subject_id": "owner",
        "capability_id": capability,
        "scope": [{"kind": "project", "value": "project-1"}],
        "activation_digest": activation_digest,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": f"nonce:{grant_id}",
    }
    grant["claim_digest"] = digest_value(grant)
    grant["trust_proofs"] = (
        [
            {
                "kind": "local-root",
                "root_subject_id": "owner",
                "authority_init_digest": digest_value(authority),
                "signed_claim_digest": grant["claim_digest"],
            }
        ]
        if issuer is None
        else [
            {
                "kind": "issuer-grant",
                "issuer_grant_id": issuer["grant_id"],
                "issuer_signed_claim_digest": issuer["claim_digest"],
                "signed_claim_digest": grant["claim_digest"],
            }
        ]
    )
    return grant


def _grant_authorization(grant: dict[str, Any]) -> dict[str, str]:
    return {
        "kind": "grant",
        "grant_id": grant["grant_id"],
        "grant_claim_digest": grant["claim_digest"],
    }


def _service_command(
    *,
    activation_digest: str,
    command_id: str,
    command_kind: str,
    payload: dict[str, Any],
    expected_head: str | None,
    issued_at: str,
    authorization: dict[str, Any],
    effect_scope: tuple[dict[str, str], ...] = (),
) -> dict[str, Any]:
    requested_scope = [{"kind": "project", "value": "project-1"}]
    task_id = payload.get("task_id")
    if isinstance(task_id, str):
        requested_scope.append({"kind": "task", "value": task_id})
    for selector in effect_scope:
        if selector not in requested_scope:
            requested_scope.append(selector)
    command = {
        "record_type": "CommandRequest",
        "command_id": command_id,
        "command_kind": command_kind,
        "subject_id": "owner",
        "activation_digest": activation_digest,
        "idempotency_key": f"idempotency:{command_id}",
        "requested_scope": requested_scope,
        "expected_head_digest": expected_head,
        "issued_at": issued_at,
        "payload": payload,
    }
    command["intent_digest"] = digest_value(command)
    command["authorization"] = authorization
    return command


def _root_authorization(
    authority: dict[str, Any], command: dict[str, Any]
) -> dict[str, Any]:
    authorization = {
        "kind": "root",
        "subject_id": "owner",
        "proofs": [
            {
                "kind": "local-root-command",
                "subject_id": "owner",
                "authority_init_digest": digest_value(authority),
                "signed_intent_digest": command["intent_digest"],
            }
        ],
    }
    command["authorization"] = authorization
    return command


def _task_with_gate_definition(
    service: ProminService,
    task: dict[str, Any],
    *,
    defined_at_head_digest: str,
    gate_id: str,
) -> dict[str, Any]:
    """Bind a Task gate definition to the live activation and durable head."""

    value = dict(task)
    owner_digest = digest_value(
        {key: item for key, item in value.items() if key != "state"}
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
        "policy_digest": "4" * 64,
        "tool_digest": "5" * 64,
        "implementation_closure_digest": context.implementation_closure_digest,
        "provider_binding_digest": digest_value(
            list(context.provider_dispatch.binding_evidence())
        ),
        "input_digests": ["6" * 64],
        "activation_digest": value["activation_digest"],
    }
    value["gate_run_definitions"] = [
        {
            "definition_digest": digest_value(definition),
            "definition": definition,
        }
    ]
    return value


def _service_with_relation_grants(
    tmp_path: Path,
) -> tuple[ProminService, dict[str, Any], dict[str, Any], str, str]:
    """Initialize a real project with only the grants needed by this test."""

    fixture = MutationFixture(tmp_path, PACKAGE_ROOT)
    project, request, _paths = fixture.init_request()
    technologies = bind_implementation_closures(
        load_json_strict(request.technologies_plan), project
    )
    atomic_write_json(request.technologies_plan, technologies)
    authority = load_json_strict(request.authority_plan)
    authority["roots"][0]["capability_ceiling"] = sorted(
        set(authority["roots"][0]["capability_ceiling"])
        | {"authority.manage"}
    )
    atomic_write_json(request.authority_plan, authority)
    service = ProminService(project)
    initialized = service.initialize(request)
    activation = initialized["activation_digest"]
    issued_at = _issued_at()

    manager = _grant(
        authority,
        activation,
        issued_at,
        grant_id="grant:relation-manager",
        capability="authority.manage",
    )
    manager_command = _service_command(
        activation_digest=activation,
        command_id="command:grant:relation-manager",
        command_kind="grant.issue",
        payload=manager,
        expected_head=None,
        issued_at=issued_at,
        authorization={},
    )
    _root_authorization(authority, manager_command)
    manager_head = service.commit(manager_command)["batch_digest"]

    def issue_manager_grant(
        grant_id: str,
        capability: str,
        expected_head: str,
    ) -> tuple[dict[str, Any], str]:
        grant = _grant(
            authority,
            activation,
            issued_at,
            grant_id=grant_id,
            capability=capability,
            issuer=manager,
        )
        command = _service_command(
            activation_digest=activation,
            command_id=f"command:{grant_id}",
            command_kind="grant.issue",
            payload=grant,
            expected_head=expected_head,
            issued_at=issued_at,
            authorization=_grant_authorization(manager),
        )
        return grant, service.commit(command)["batch_digest"]

    planner, head = issue_manager_grant(
        "grant:relation-planner", "task.plan", manager_head
    )
    worker, head = issue_manager_grant(
        "grant:relation-worker", "task.execute", head
    )
    candidate = {
        "record_type": "Candidate",
        "candidate_id": "candidate:relation-identity",
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
    candidate_command = _service_command(
        activation_digest=activation,
        command_id="command:relation-candidate",
        command_kind="candidate.record",
        payload=candidate,
        expected_head=head,
        issued_at=issued_at,
        authorization=_grant_authorization(worker),
        effect_scope=({"kind": "candidate", "value": candidate["candidate_id"]},),
    )
    return service, candidate, planner, service.commit(candidate_command)["batch_digest"], activation


class _NoGraphDomain:
    @property
    def tasks(self) -> Any:
        raise AssertionError("non-dependency Relation must not read current Tasks")

    @property
    def gate_results(self) -> Any:
        raise AssertionError("non-dependency Relation must not read current Gates")

    @property
    def findings(self) -> Any:
        raise AssertionError("non-dependency Relation must not read current Findings")


@pytest.mark.parametrize("operation", ("command", "replay"))
@pytest.mark.parametrize("kind", ("READS", "PRODUCES"))
def test_non_dependency_relations_skip_large_ledger_materialization(
    activation_context: Any,
    operation: str,
    kind: str,
) -> None:
    """READS/PRODUCES retain ingress validation without copying old graph state."""

    activation_digest = activation_context.activation_digest
    ledger = _RelationLedger().extend(
        {"relation_id": f"relation:existing:{index:05d}"}
        for index in range(4_096)
    )
    materialize = Mock(wraps=ledger.materialize)
    relation = _relation(
        f"relation:{kind.casefold()}-new",
        kind=kind,
        source_id="task:source",
        target_id="artifact:target",
        target_type="Artifact",
        activation_digest=activation_digest,
    )

    actual = _validated_auxiliary_relations(
        activation_context.bundle,
        activation_context,
        _command("task:source"),
        [relation],
        operation=operation,
        domain=_NoGraphDomain(),
        current_relations=materialize,
        current_relation_ids=ledger.contains_relation_id,
    )

    assert actual == (relation,)
    materialize.assert_not_called()


def test_depends_on_materializes_exact_history_and_rejects_cycle(
    activation_context: Any,
) -> None:
    """Dependency ingress still receives the full current graph and fails closed."""

    activation_digest = activation_context.activation_digest
    tasks = {task_id: _task(task_id) for task_id in ("task:a", "task:b", "task:c")}
    ledger = _RelationLedger().extend(
        (
            _relation(
                "relation:a-b",
                kind="DEPENDS_ON",
                source_id="task:a",
                target_id="task:b",
                target_type="Task",
                activation_digest=activation_digest,
            ),
        )
    )
    materialize = Mock(wraps=ledger.materialize)
    domain = SimpleNamespace(tasks=tasks, gate_results={}, findings={})
    forward = _relation(
        "relation:b-c",
        kind="DEPENDS_ON",
        source_id="task:b",
        target_id="task:c",
        target_type="Task",
        activation_digest=activation_digest,
    )
    actual = _validated_auxiliary_relations(
        activation_context.bundle,
        activation_context,
        _command("task:b"),
        [forward],
        operation="command",
        domain=domain,
        current_relations=materialize,
        current_relation_ids=ledger.contains_relation_id,
    )
    assert actual == (forward,)
    materialize.assert_called_once_with()

    cycle_ledger = ledger.extend((forward,))
    cycle_materialize = Mock(wraps=cycle_ledger.materialize)
    cycle = _relation(
        "relation:c-a",
        kind="DEPENDS_ON",
        source_id="task:c",
        target_id="task:a",
        target_type="Task",
        activation_digest=activation_digest,
    )

    with pytest.raises(ContractError, match="DEPENDS_ON graph is cyclic or unresolved"):
        _validated_auxiliary_relations(
            activation_context.bundle,
            activation_context,
            _command("task:c"),
            [cycle],
            operation="replay",
            domain=domain,
            current_relations=cycle_materialize,
            current_relation_ids=cycle_ledger.contains_relation_id,
        )

    cycle_materialize.assert_called_once_with()


def test_malformed_non_dependency_relation_remains_fail_closed(
    activation_context: Any,
) -> None:
    """Laziness cannot turn a malformed auxiliary Relation into an accepted one."""

    activation_digest = activation_context.activation_digest
    ledger = _RelationLedger().extend(
        {"relation_id": f"relation:existing:{index:05d}"}
        for index in range(4_096)
    )
    materialize = Mock(wraps=ledger.materialize)
    malformed = _relation(
        "relation:malformed",
        kind="READS",
        source_id="task:source",
        target_id="artifact:target",
        target_type="Artifact",
        activation_digest=activation_digest,
    )
    malformed.pop("kind")

    with pytest.raises(ContractError):
        _validated_auxiliary_relations(
            activation_context.bundle,
            activation_context,
            _command("task:source"),
            [malformed],
            operation="command",
            domain=_NoGraphDomain(),
            current_relations=materialize,
            current_relation_ids=ledger.contains_relation_id,
        )

    materialize.assert_not_called()


def test_non_dependency_duplicate_id_is_rejected_without_graph_materialization(
    activation_context: Any,
) -> None:
    """A second committed Relation identity cannot poison a later checkpoint."""

    activation_digest = activation_context.activation_digest
    existing = _relation(
        "relation:already-committed",
        kind="READS",
        source_id="task:source",
        target_id="artifact:target",
        target_type="Artifact",
        activation_digest=activation_digest,
    )
    ledger = _RelationLedger().extend((existing,))
    materialize = Mock(wraps=ledger.materialize)

    with pytest.raises(ServiceError, match="already committed"):
        _validated_auxiliary_relations(
            activation_context.bundle,
            activation_context,
            _command("task:source"),
            [existing],
            operation="replay",
            domain=_NoGraphDomain(),
            current_relations=materialize,
            current_relation_ids=ledger.contains_relation_id,
        )

    materialize.assert_not_called()


def test_relation_identity_index_stays_exact_across_overlay_compaction() -> None:
    """Global identity checks do not regress when old overlays compact."""

    ledger = _RelationLedger()
    for index in range(130):
        ledger = ledger.extend(({"relation_id": f"relation:compact:{index:03d}"},))

    assert ledger.identity_index.depth <= 64
    for index in (0, 64, 129):
        assert ledger.contains_relation_id(f"relation:compact:{index:03d}")
    with pytest.raises(ServiceError, match="identity is duplicated"):
        ledger.extend(({"relation_id": "relation:compact:000"},))


def test_duplicate_relation_id_is_rejected_before_durable_write_and_rebuilds(
    tmp_path: Path,
) -> None:
    """A duplicate non-graph Relation cannot enter a later journal/checkpoint."""

    service, candidate, planner, head, activation = _service_with_relation_grants(
        tmp_path
    )
    issued_at = _issued_at()

    first_task = _task_with_gate_definition(
        service,
        {
            "record_type": "Task",
            "task_id": "task:relation-first",
            "state": "PLANNED",
            "required_capability": "task.execute",
            "acceptance_predicate": "first READS relation is durable",
            "allowed_paths": ["product/**"],
            "activation_digest": activation,
            "candidate_digest": candidate["candidate_digest"],
            "created_at": issued_at,
        },
        defined_at_head_digest=head,
        gate_id="gate:relation-first",
    )
    first_command = _service_command(
        activation_digest=activation,
        command_id="command:relation-first",
        command_kind="task.record",
        payload=first_task,
        expected_head=head,
        issued_at=issued_at,
        authorization=_grant_authorization(planner),
    )
    relation_id = "relation:globally-unique-reads"
    first_relation = _relation(
        relation_id,
        kind="READS",
        source_id=first_task["task_id"],
        target_id=candidate["candidate_id"],
        target_type="Candidate",
        activation_digest=activation,
    )
    accepted = service.commit(first_command, auxiliary_relations=[first_relation])
    accepted_head = accepted["batch_digest"]
    assert service._event_store(service._context()).head()["batch_digest"] == accepted_head

    second_task = _task_with_gate_definition(
        service,
        {
            "record_type": "Task",
            "task_id": "task:relation-second",
            "state": "PLANNED",
            "required_capability": "task.execute",
            "acceptance_predicate": "duplicate READS relation must fail closed",
            "allowed_paths": ["product/**"],
            "activation_digest": activation,
            "candidate_digest": candidate["candidate_digest"],
            "created_at": issued_at,
        },
        defined_at_head_digest=accepted_head,
        gate_id="gate:relation-second",
    )
    second_command = _service_command(
        activation_digest=activation,
        command_id="command:relation-second",
        command_kind="task.record",
        payload=second_task,
        expected_head=accepted_head,
        issued_at=issued_at,
        authorization=_grant_authorization(planner),
    )
    duplicate_relation = _relation(
        relation_id,
        kind="READS",
        source_id=second_task["task_id"],
        target_id=candidate["candidate_id"],
        target_type="Candidate",
        activation_digest=activation,
    )

    with pytest.raises(ServiceError, match="already committed"):
        service.commit(second_command, auxiliary_relations=[duplicate_relation])

    # The rejected command never advances the immutable EventStore head.
    assert service._event_store(service._context()).head()["batch_digest"] == accepted_head

    # A fresh process proves persisted runtime/checkpoint replay remains clean.
    reopened = ProminService(service.root)
    rebuilt = reopened.rebuild()
    assert rebuilt["product_passes"] == 0
    reopened_context = reopened._context()
    reopened_store = reopened._event_store(reopened_context)
    assert reopened_store.head()["batch_digest"] == accepted_head
    replayed = reopened._runtime_state(reopened_context, reopened_store)
    assert relation_id in {
        relation["relation_id"] for relation in replayed.relations.materialize()
    }
    assert second_task["task_id"] not in replayed.domain.tasks
