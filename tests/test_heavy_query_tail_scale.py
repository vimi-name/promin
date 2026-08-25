from __future__ import annotations

import base64
from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import inspect
import math
from pathlib import Path
import sqlite3
import time
from typing import Any, Mapping

import pytest
from jsonschema import Draft202012Validator

from promin.authority import AuthorityError
from promin.canonical import canonical_bytes, digest_value
from promin import evidence
from promin.projection import ProjectionError, VerifiedInventoryInput
from promin.service import ServiceError
from tools import promin_saturation as saturation
from tests.test_service_cli import (
    _command,
    _grant,
    _grant_authorization,
    _initialized_service,
    _task_with_gate_definition,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_COUNT = 2_048
READ_RELATION_COUNT = 127
CHAIN_DEPTH_MAX = 12
QUERY_COUNT_CONTRACT = 600
QUERY_SAMPLE_COUNT = 18
TTL_SECONDS = 600

REFERENCE_BUDGET = {
    "max_bytes": 16_384,
    "max_entities": 32,
    "max_relations": 48,
    "max_fanout_per_entity": 8,
    "top_k": 12,
}
TINY_BUDGET = {
    "max_bytes": 8_192,
    "max_entities": 1,
    "max_relations": 1,
    "max_fanout_per_entity": 1,
    "top_k": 1,
}

EXPECTED_QUERY_CLASSES = {
    "forced-continuation": 12,
    "exact-artifact": 74,
    "content-high-cardinality": 74,
    "content-probe": 74,
    "miss": 74,
    "hostile-content": 73,
    "hostile-exact": 73,
    "broad": 73,
    "exact-semantic": 73,
}
EXPECTED_QUERY_DEPTHS = {
    1: 369,
    2: 25,
    3: 1,
    4: 50,
    5: 1,
    6: 26,
    7: 1,
    8: 50,
    9: 1,
    10: 25,
    11: 1,
    12: 50,
}


def _query_instant(issued_at: str, offset_seconds: int = 60) -> datetime:
    return datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    ) + timedelta(seconds=offset_seconds)


def _verified_inventory_corpus(
    activation_digest: str,
) -> tuple[VerifiedInventoryInput, list[str]]:
    shared_phrases = " ".join(saturation._REPRESENTATIVE_PHRASES)
    rows: list[dict[str, Any]] = []
    artifact_ids: list[str] = []
    identity_stream = hashlib.sha256()
    for index in range(ARTIFACT_COUNT):
        language = ("c", "cplusplus", "csharp", "java")[index % 4]
        path = f"src/query-tail/bucket-{index // 128:02d}/record-{index:05d}-{language}.txt"
        file_digest = hashlib.sha256(f"query-tail:{index}".encode("ascii")).hexdigest()
        artifact_id = "artifact:file:" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:48]
        size = 128 + index % 97
        identity_stream.update(
            canonical_bytes({"path": path, "digest": file_digest, "size": size})
        )
        rows.append(
            {
                "record_type": "InventoryProjectionRow",
                "path": path,
                "digest": file_digest,
                "size": size,
                "semantic_proxy": {
                    "id": artifact_id,
                    "entity_type": "Artifact",
                    "payload": {
                        "record_type": "Artifact",
                        "artifact_id": artifact_id,
                        "artifact_kind": "product",
                        "digest": file_digest,
                        "media_type": "text/plain",
                        "size_bytes": size,
                        "label": (
                            "semantic source hostile exact identity record documentation "
                            f"{shared_phrases} language {language} stable-id {index:05d}"
                        ),
                    },
                },
            }
        )
        artifact_ids.append(artifact_id)
    assert len(set(artifact_ids)) == ARTIFACT_COUNT
    inventory_digest = identity_stream.hexdigest()
    return (
        VerifiedInventoryInput(
            activation_digest=activation_digest,
            stream_digest=inventory_digest,
            inventory_digest=inventory_digest,
            entry_count=ARTIFACT_COUNT,
            entries=tuple(rows),
        ),
        artifact_ids,
    )


def _query_service(
    tmp_path: Path,
) -> tuple[Any, dict[str, dict[str, Any]], dict[str, Any], str]:
    service, authority, initialized = _initialized_service(
        tmp_path,
        operating_profile="extended",
    )
    activation_digest = initialized["activation_digest"]
    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    manager = _grant(
        authority,
        activation_digest,
        issued_at,
        grant_id="grant:query-tail:authority",
        capability="authority.manage",
    )
    bootstrap = _command(
        activation_digest=activation_digest,
        command_id="command:query-tail:bootstrap-authority",
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
    bootstrap["authorization"]["proofs"][0]["signed_intent_digest"] = bootstrap[
        "intent_digest"
    ]
    head = service.commit(bootstrap)["batch_digest"]
    grants = {"manager": manager}
    for name, capability in (
        ("planner", "task.plan"),
        ("holder", "task.execute"),
        ("reader", "projection.read"),
        ("alternate_reader", "projection.read"),
    ):
        grant = _grant(
            authority,
            activation_digest,
            issued_at,
            grant_id=f"grant:query-tail:{name.replace('_', '-')}",
            capability=capability,
            issuer=manager,
        )
        head = service.commit(
            _command(
                activation_digest=activation_digest,
                command_id=f"command:query-tail:issue-{name.replace('_', '-')}",
                command_kind="grant.issue",
                payload=grant,
                expected_head=head,
                issued_at=issued_at,
                authorization=_grant_authorization(manager),
            )
        )["batch_digest"]
        grants[name] = grant

    candidate_digest = "1" * 64
    candidate = {
        "record_type": "Candidate",
        "candidate_id": "candidate:query-tail",
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
    head = service.commit(
        _command(
            activation_digest=activation_digest,
            command_id="command:query-tail:candidate",
            command_kind="candidate.record",
            payload=candidate,
            expected_head=head,
            issued_at=issued_at,
            authorization=_grant_authorization(grants["holder"]),
            effect_scope=[{"kind": "candidate", "value": candidate["candidate_id"]}],
        )
    )["batch_digest"]
    return service, grants, candidate, head


def _task_payload(
    service: Any,
    *,
    task_id: str,
    activation_digest: str,
    candidate_digest: str,
    created_at: str,
    head_digest: str,
    gate_suffix: str,
    predicate: str,
) -> dict[str, Any]:
    task = {
        "record_type": "Task",
        "task_id": task_id,
        "state": "PLANNED",
        "required_capability": "task.execute",
        "acceptance_predicate": predicate,
        "allowed_paths": ["src/query-tail/**"],
        "activation_digest": activation_digest,
        "candidate_digest": candidate_digest,
        "created_at": created_at,
    }
    return _task_with_gate_definition(
        service,
        task,
        defined_at_head_digest=head_digest,
        gate_id=f"gate:query-tail:{gate_suffix}",
    )


def _record_task(
    service: Any,
    grants: Mapping[str, Mapping[str, Any]],
    *,
    head: str,
    task: Mapping[str, Any],
    command_suffix: str,
    issued_at: str,
    relations: list[dict[str, Any]] | None = None,
) -> str:
    result = service.commit(
        _command(
            activation_digest=task["activation_digest"],
            command_id=f"command:query-tail:{command_suffix}",
            command_kind="task.record",
            payload=dict(task),
            expected_head=head,
            issued_at=issued_at,
            authorization=_grant_authorization(dict(grants["planner"])),
        ),
        auxiliary_relations=relations or (),
    )
    assert result["outcome"] == "committed"
    return result["batch_digest"]


def _build_semantic_corpus(
    service: Any,
    grants: dict[str, dict[str, Any]],
    candidate: Mapping[str, Any],
    head: str,
    artifact_ids: list[str],
) -> str:
    activation_digest = grants["manager"]["activation_digest"]
    candidate_digest = candidate["candidate_digest"]
    issued_at = grants["manager"]["issued_at"]

    store = service._event_store(service._context())
    relations_per_task = min(127, store.max_events_per_batch - 1)
    assert relations_per_task == 127
    shard_count = math.ceil(READ_RELATION_COUNT / relations_per_task)
    for shard in range(shard_count):
        task_id = (
            "task:saturation:fanout:root"
            if shard == 0
            else f"task:query-tail:relation-shard:{shard:03d}"
        )
        shard_task = _task_payload(
            service,
            task_id=task_id,
            activation_digest=activation_digest,
            candidate_digest=candidate_digest,
            created_at=issued_at,
            head_digest=head,
            gate_suffix=f"read-{shard:03d}",
            predicate=f"verify documentation dependency shard {shard:03d}",
        )
        start = shard * relations_per_task
        stop = min(start + relations_per_task, READ_RELATION_COUNT)
        relations = [
            {
                "record_type": "Relation",
                "relation_id": f"relation:query-tail:read:{index:06d}",
                "kind": "READS",
                "source_type": "Task",
                "source_id": task_id,
                "target_type": "Artifact",
                "target_id": artifact_ids[index],
                "activation_digest": activation_digest,
                "created_at": issued_at,
            }
            for index in range(start, stop)
        ]
        head = _record_task(
            service,
            grants,
            head=head,
            task=shard_task,
            command_suffix=f"read-{shard:03d}",
            issued_at=issued_at,
            relations=relations,
        )

    for depth in range(CHAIN_DEPTH_MAX + 1):
        task_id = f"task:saturation:depth:{depth:02d}"
        chain_task = _task_payload(
            service,
            task_id=task_id,
            activation_digest=activation_digest,
            candidate_digest=candidate_digest,
            created_at=issued_at,
            head_digest=head,
            gate_suffix=f"depth-{depth:02d}",
            predicate=f"verify exact dependency depth {depth}",
        )
        relations = []
        if depth:
            relations.append(
                {
                    "record_type": "Relation",
                    "relation_id": f"relation:query-tail:depth:{depth:02d}",
                    "kind": "DEPENDS_ON",
                    "source_type": "Task",
                    "source_id": task_id,
                    "target_type": "Task",
                    "target_id": f"task:saturation:depth:{depth - 1:02d}",
                    "activation_digest": activation_digest,
                    "created_at": issued_at,
                }
            )
        head = _record_task(
            service,
            grants,
            head=head,
            task=chain_task,
            command_suffix=f"depth-{depth:02d}",
            issued_at=issued_at,
            relations=relations,
        )

    needle = _task_payload(
        service,
        task_id="task:saturation:needle",
        activation_digest=activation_digest,
        candidate_digest=candidate_digest,
        created_at=issued_at,
        head_digest=head,
        gate_suffix="needle",
        predicate="exact identity must outrank hostile content",
    )
    return _record_task(
        service,
        grants,
        head=head,
        task=needle,
        command_suffix="needle",
        issued_at=issued_at,
    )


def _page_atoms(page: Mapping[str, Any]) -> set[tuple[str, str]]:
    return {
        *(("entity", entity["id"]) for entity in page["entities"]),
        *(
            (
                "relation",
                relation["relation_id"]
                if "relation_id" in relation
                else relation["id"],
            )
            for relation in page["relations"]
        ),
    }


def _continuation_state(
    projection_path: Path,
    token: str,
    *,
    token_bytes_max: int,
    state_bytes_max: int,
) -> dict[str, Any]:
    assert len(token.encode("ascii")) <= token_bytes_max
    version, handle, row_digest, _signature = token.split(".")
    assert version == "promin-v2"
    assert len(handle) == 22
    with sqlite3.connect(projection_path) as connection:
        row = connection.execute(
            "SELECT row_digest,payload_json FROM continuations WHERE handle=?",
            (handle,),
        ).fetchone()
    assert row is not None
    assert row[0] == row_digest
    payload_bytes = row[1].encode("utf-8")
    assert 0 < len(payload_bytes) <= state_bytes_max
    assert hashlib.sha256(payload_bytes).hexdigest() == row_digest
    payload = json.loads(row[1])
    assert canonical_bytes(payload) == payload_bytes
    return payload


def _drain_public_pages(
    service: Any,
    first: Mapping[str, Any],
    *,
    query: str,
    depth: int,
    budget: Mapping[str, int],
    grant: Mapping[str, Any],
    now: datetime,
    ttl_seconds: int,
    projection_path: Path,
    token_bytes_max: int,
    state_bytes_max: int,
) -> dict[str, Any]:
    current = dict(first)
    atoms: set[tuple[str, str]] = set()
    tokens: list[str] = []
    resume_binding_digests: set[str] = set()
    cursors: list[int] = []
    pages = 0
    while True:
        assert current["record_type"] == "RetrievalPage"
        assert current["query"] == query
        assert current["depth"] == depth
        assert current["ranking"] == "bm25-v1"
        assert current["budget"] == dict(budget)
        assert len(current["entities"]) <= budget["max_entities"]
        assert len(current["relations"]) <= budget["max_relations"]
        assert len(canonical_bytes(current)) <= budget["max_bytes"]
        assert current["silent_truncation"] is False
        assert current["projection_authoritative"] is False
        page_atoms = _page_atoms(current)
        assert atoms.isdisjoint(page_atoms)
        atoms.update(page_atoms)
        pages += 1

        if current["truncated"] is False:
            assert current["continuation"] is None
            assert current["selected_closure_complete"] is True
            break
        assert current["selected_closure_complete"] is False
        continuation = current["continuation"]
        assert isinstance(continuation, Mapping)
        assert "grant_claim_digest" not in continuation
        token = continuation["token"]
        assert token not in tokens
        tokens.append(token)
        cursor = continuation["cursor"]
        assert isinstance(cursor, int) and cursor > current["stream_cursor"]
        if cursors:
            assert cursor > cursors[-1]
        cursors.append(cursor)
        resume_binding_digests.add(continuation["resume_binding_digest"])
        payload = _continuation_state(
            projection_path,
            token,
            token_bytes_max=token_bytes_max,
            state_bytes_max=state_bytes_max,
        )
        assert payload["resume_binding"]["grant_claim_digest"] == grant["claim_digest"]
        assert continuation["resume_binding_digest"] == digest_value(
            payload["resume_binding"]
        )
        current = service.search(
            query,
            depth,
            budget=dict(budget),
            ranking="bm25-v1",
            continuation_token=token,
            subject_id=grant["subject_id"],
            grant_id=grant["grant_id"],
            now=now + timedelta(seconds=1),
            ttl_seconds=ttl_seconds,
        )
        assert pages <= 64
    return {
        "atoms": atoms,
        "pages": pages,
        "tokens": tokens,
        "resume_binding_digests": resume_binding_digests,
    }


def _query_plan(artifact_ids: list[str]) -> list[dict[str, Any]]:
    semantic_ids = [
        "task:saturation:depth:12",
        "task:saturation:fanout:root",
        "task:saturation:needle",
    ]
    continuation_ids = semantic_ids[:2]
    plan: list[dict[str, Any]] = []
    for index in range(QUERY_COUNT_CONTRACT):
        query_class, query = saturation._mixed_query_case(
            index,
            forced_chains=12,
            artifact_ids=artifact_ids,
            semantic_query_ids=semantic_ids,
            continuation_query_ids=continuation_ids,
        )
        plan.append(
            {
                "index": index,
                "class": query_class,
                "query": query,
                "depth": saturation._mixed_query_depth(index, query_class),
            }
        )
    return plan


def test_saturation_query_tail_declares_bounded_immutable_phase() -> None:
    source = inspect.getsource(saturation.run)
    assert "begin_immutable_query_phase" in source
    assert "_query_phase_operation_budget" in source
    assert "query_phase.close()" in source


def test_query_phase_budget_is_derived_from_plan_and_forced_depths() -> None:
    plan = [{"depth": 1}, {"depth": 2}, {"depth": 3}]
    # Initial searches: 3 planned + 1 forced. Every route is allowed the
    # contract's page limit, regardless of its traversal depth.
    assert saturation._query_phase_operation_budget(
        plan, 1, continuation_page_limit=3
    ) == 28
    with pytest.raises(saturation.SaturationError, match="positive integer"):
        saturation._query_phase_operation_budget([{"depth": 0}], 0)


@pytest.mark.parametrize("operations", [0, 12_240_612])
def test_compiled_immutable_query_phase_accepts_bounded_operations(
    operations: int,
) -> None:
    schema = json.loads(
        (PACKAGE_ROOT / "core" / "contracts.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(
        {
            "$schema": schema["$schema"],
            "$defs": schema["$defs"],
            "$ref": (
                "#/$defs/SaturationEvidence/properties/search/properties/"
                "immutable_query_phase"
            ),
        }
    )
    phase = {
        "operation_budget": 12_240_612,
        "operations": operations,
        "within_budget": operations <= 12_240_612,
        "close_elapsed_ms": 0.0,
        "product_acceptance_credit": False,
    }
    assert list(validator.iter_errors(phase)) == []


@pytest.mark.parametrize(
    ("mutation", "label"),
    [
        (lambda phase: phase.pop("operations"), "missing required field"),
        (lambda phase: phase.__setitem__("unexpected", 1), "unexpected field"),
        (lambda phase: phase.__setitem__("operations", 12_240_613), "overflow"),
        (lambda phase: phase.__setitem__("product_acceptance_credit", True), "credit"),
    ],
)
def test_compiled_immutable_query_phase_rejects_schema_mutations(
    mutation: Any,
    label: str,
) -> None:
    schema = json.loads(
        (PACKAGE_ROOT / "core" / "contracts.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(
        {
            "$schema": schema["$schema"],
            "$defs": schema["$defs"],
            "$ref": (
                "#/$defs/SaturationEvidence/properties/search/properties/"
                "immutable_query_phase"
            ),
        }
    )
    phase = {
        "operation_budget": 12_240_612,
        "operations": 12_240_612,
        "within_budget": True,
        "close_elapsed_ms": 0.0,
        "product_acceptance_credit": False,
    }
    mutation(phase)
    assert list(validator.iter_errors(phase)), label


def test_depth_one_multi_page_phase_budget_does_not_exhaust() -> None:
    # A depth-1 route can still span multiple bounded pages. The budget is
    # page-contract-derived, not depth-derived.
    assert saturation._query_phase_operation_budget(
        [{"depth": 1}], 0, continuation_page_limit=4
    ) == 9


def test_query_phase_failure_cleanup_preserves_primary_and_publishes_no_result(
    tmp_path: Path,
) -> None:
    class Phase:
        def __init__(self) -> None:
            self.closed = False
            self.lock_released = False

        def close(self) -> None:
            self.closed = True
            self.lock_released = True
            raise RuntimeError("close binding mismatch")

    phase = Phase()
    primary = RuntimeError("injected query failure")

    def operation(
        workspace: Path,
        output: Path,
        *,
        archive: Path | None = None,
        files: int = QUERY_COUNT_CONTRACT,
        queries: int = QUERY_COUNT_CONTRACT,
        reuse_product: bool = False,
        performance_profile: str = "portable-local-v1",
    ) -> dict[str, Any]:
        saturation._ACTIVE_QUERY_PHASE.set(phase)
        raise primary

    wrapped = saturation._guard_storage_run(operation)
    with pytest.raises(RuntimeError) as raised:
        wrapped(tmp_path / "workspace", tmp_path / "output")

    assert raised.value is primary
    assert phase.closed is True
    assert phase.lock_released is True
    assert any("cleanup failed" in note for note in raised.value.__notes__)
    assert not (tmp_path / "output" / "saturation-result.json").exists()


def _assert_sample_class(page: Mapping[str, Any], item: Mapping[str, Any]) -> None:
    assert page["projection_authoritative"] is False
    query_class = item["class"]
    query = item["query"]
    if query_class in {"exact-artifact", "exact-semantic", "hostile-exact"}:
        assert page["entities"][0]["id"] == query
    elif query_class == "miss":
        assert page["entities"] == []
        assert page["relations"] == []
        assert page["truncated"] is False
    elif query_class in {
        "content-high-cardinality",
        "content-probe",
        "hostile-content",
        "broad",
    }:
        assert page["entities"]
        assert page["refinement_required"] is True
        assert page["unselected_matches_traversable"] is False
    else:
        assert query_class == "forced-continuation"
        assert page["truncated"] is True
        assert page["continuation"] is not None


@pytest.mark.performance
def test_public_query_tail_scale_is_exact_bounded_and_fail_closed(tmp_path: Path) -> None:
    test_started = time.perf_counter()
    service, grants, candidate, head = _query_service(tmp_path)
    try:
        inventory, artifact_ids = _verified_inventory_corpus(
            grants["manager"]["activation_digest"]
        )
        head = _build_semantic_corpus(
            service,
            grants,
            candidate,
            head,
            artifact_ids,
        )
        # Keep this preflight below two minutes: its corpus is a verified,
        # harness-owned projection input.  Every behavior assertion below goes
        # through public ProminService.search; physical inventory remains the
        # separate exact-100k evidence route and receives no pass credit here.
        context = service._context(force_full=True)
        rebuilt = service._projection(context).rebuild(
            service._event_store(context),
            inventory=inventory,
        )
        assert rebuilt["inventory_entries"] == ARTIFACT_COUNT
        assert rebuilt["inventory_proxies"] == ARTIFACT_COUNT
        assert rebuilt["relation_count"] >= READ_RELATION_COUNT + CHAIN_DEPTH_MAX
        assert rebuilt["entity_count"] >= ARTIFACT_COUNT + 20
        assert rebuilt["product_passes"] == 0
        assert rebuilt["projection_authoritative"] is False

        projection_path = (
            service.root / ".promin" / "state" / "projection" / "promin.sqlite3"
        )
        with sqlite3.connect(projection_path) as connection:
            artifact_count = connection.execute(
                "SELECT COUNT(*) FROM entities WHERE entity_type='Artifact'"
            ).fetchone()[0]
            relation_count = connection.execute(
                "SELECT COUNT(*) FROM relations WHERE id LIKE 'relation:query-tail:%'"
            ).fetchone()[0]
        assert artifact_count == ARTIFACT_COUNT
        assert relation_count == READ_RELATION_COUNT + CHAIN_DEPTH_MAX

        conformance = json.loads(
            (PACKAGE_ROOT / "core" / "conformance.json").read_text(encoding="utf-8")
        )
        workcard_contract = conformance["scale_contracts"]["workcard"]
        token_bytes_max = workcard_contract["continuation_token_bytes_max"]
        state_bytes_max = workcard_contract["continuation_state_bytes_max"]
        assert token_bytes_max == 256
        assert state_bytes_max == 16_384

        query_now = _query_instant(grants["manager"]["issued_at"])
        query = "task:saturation:depth:12"
        global_resume_binding_digests: set[str] = set()
        untruncated_reference_atoms: set[tuple[str, str]] = set()
        depth_twelve_first: dict[str, Any] | None = None
        for depth in range(1, CHAIN_DEPTH_MAX + 1):
            expected_atoms = {
                *(
                    ("entity", f"task:saturation:depth:{12 - offset:02d}")
                    for offset in range(depth + 1)
                ),
                *(
                    ("relation", f"relation:query-tail:depth:{12 - offset:02d}")
                    for offset in range(depth)
                ),
            }
            first = service.search(
                query,
                depth,
                budget=TINY_BUDGET,
                subject_id=grants["reader"]["subject_id"],
                grant_id=grants["reader"]["grant_id"],
                now=query_now,
                ttl_seconds=TTL_SECONDS,
            )
            assert first["truncated"] is True
            assert first["depth"] == depth
            assert _page_atoms(first) <= expected_atoms
            continuation = first["continuation"]
            assert isinstance(continuation, Mapping)
            continuation_state = _continuation_state(
                projection_path=projection_path,
                token=continuation["token"],
                token_bytes_max=token_bytes_max,
                state_bytes_max=state_bytes_max,
            )
            assert continuation_state["resume_binding"]["grant_claim_digest"] == (
                grants["reader"]["claim_digest"]
            )
            assert continuation["resume_binding_digest"] == digest_value(
                continuation_state["resume_binding"]
            )
            global_resume_binding_digests.add(
                continuation["resume_binding_digest"]
            )
            if depth == CHAIN_DEPTH_MAX:
                untruncated_reference_atoms = expected_atoms
                depth_twelve_first = first
        assert len(global_resume_binding_digests) == 1
        assert depth_twelve_first is not None

        reference_first = service.search(
            query,
            CHAIN_DEPTH_MAX,
            budget=REFERENCE_BUDGET,
            subject_id=grants["reader"]["subject_id"],
            grant_id=grants["reader"]["grant_id"],
            now=query_now,
            ttl_seconds=TTL_SECONDS,
        )
        reference_trace = _drain_public_pages(
            service,
            reference_first,
            query=query,
            depth=CHAIN_DEPTH_MAX,
            budget=REFERENCE_BUDGET,
            grant=grants["reader"],
            now=query_now,
            ttl_seconds=TTL_SECONDS,
            projection_path=projection_path,
            token_bytes_max=token_bytes_max,
            state_bytes_max=state_bytes_max,
        )
        assert reference_trace["atoms"] == untruncated_reference_atoms
        assert reference_trace["pages"] <= 3

        drained = _drain_public_pages(
            service,
            depth_twelve_first,
            query=query,
            depth=CHAIN_DEPTH_MAX,
            budget=TINY_BUDGET,
            grant=grants["reader"],
            now=query_now,
            ttl_seconds=TTL_SECONDS,
            projection_path=projection_path,
            token_bytes_max=token_bytes_max,
            state_bytes_max=state_bytes_max,
        )
        assert drained["atoms"] == untruncated_reference_atoms
        assert drained["pages"] == CHAIN_DEPTH_MAX + 1
        assert drained["resume_binding_digests"] == global_resume_binding_digests

        # This is the exact production harness route that failed after the r5
        # 100k projection had already succeeded.  Keep it in the bounded test.
        harness_first = service.search(
            query,
            CHAIN_DEPTH_MAX,
            budget=TINY_BUDGET,
            subject_id=grants["reader"]["subject_id"],
            grant_id=grants["reader"]["grant_id"],
            ttl_seconds=TTL_SECONDS,
        )
        harness_trace = saturation._drain_pages(
            service,
            harness_first,
            TINY_BUDGET,
            query_grant=grants["reader"],
            ttl_seconds=TTL_SECONDS,
        )
        assert harness_trace["selected_closure_complete"] is True
        assert harness_trace["continuation_pages"] == CHAIN_DEPTH_MAX
        assert harness_trace["atoms"] == {
            f"{kind}:{atom_id}"
            for kind, atom_id in untruncated_reference_atoms
        }

        producer_trace = saturation._raw_page_trace(harness_trace)
        producer_observation = {
            "record_type": "SaturationQueryObservation",
            "index": 0,
            "query_class": "forced-continuation",
            "query": query,
            "depth": CHAIN_DEPTH_MAX,
            "elapsed_ms": 0.0,
            "first_page": dict(depth_twelve_first),
            "first_page_digest": digest_value(depth_twelve_first),
            "class_result_verified": True,
            "reference": producer_trace,
            "forced": None,
        }
        recomputed = evidence._recompute_raw_query_result(
            producer_observation,
            expected_index=0,
            top_k=1,
        )
        assert recomputed["reference"]["pages"] == CHAIN_DEPTH_MAX + 1

        forced_trace = deepcopy(producer_trace)
        forced_trace["union_matches_reference"] = True
        forced_trace["identity_digests"] = sorted(
            ["0" * 64, *producer_trace["identity_digests"][1:]]
        )
        mutated_forced_observation = dict(producer_observation)
        mutated_forced_observation["forced"] = forced_trace
        with pytest.raises(evidence.EvidenceError, match="forced continuation union"):
            evidence._recompute_raw_query_result(
                mutated_forced_observation,
                expected_index=0,
                top_k=1,
            )

        plan = _query_plan(artifact_ids)
        assert plan == _query_plan(artifact_ids)
        assert len(plan) == QUERY_COUNT_CONTRACT
        assert Counter(item["class"] for item in plan) == EXPECTED_QUERY_CLASSES
        assert Counter(item["depth"] for item in plan) == EXPECTED_QUERY_DEPTHS
        assert {item["depth"] for item in plan[:12]} == set(range(1, 13))
        sample: list[dict[str, Any]] = []
        for query_class in EXPECTED_QUERY_CLASSES:
            sample.extend(
                [item for item in plan if item["class"] == query_class][:2]
            )
        assert len(sample) == QUERY_SAMPLE_COUNT
        assert Counter(item["class"] for item in sample) == {
            query_class: 2 for query_class in EXPECTED_QUERY_CLASSES
        }

        rss_before = saturation._current_rss_bytes()
        sampled_peak_rss = rss_before
        sample_started = time.perf_counter()
        query_latencies: list[float] = []
        for item in sample:
            started = time.perf_counter()
            first = service.search(
                item["query"],
                item["depth"],
                budget=TINY_BUDGET,
                subject_id=grants["reader"]["subject_id"],
                grant_id=grants["reader"]["grant_id"],
                now=query_now,
                ttl_seconds=TTL_SECONDS,
            )
            repeated = service.search(
                item["query"],
                item["depth"],
                budget=TINY_BUDGET,
                subject_id=grants["reader"]["subject_id"],
                grant_id=grants["reader"]["grant_id"],
                now=query_now,
                ttl_seconds=TTL_SECONDS,
            )
            query_latencies.append(time.perf_counter() - started)
            assert canonical_bytes(first) == canonical_bytes(repeated)
            _assert_sample_class(first, item)
            sampled_peak_rss = max(sampled_peak_rss, saturation._current_rss_bytes())
        sample_seconds = time.perf_counter() - sample_started
        assert sample_seconds < 90.0
        assert max(query_latencies) < 15.0
        assert sampled_peak_rss - rss_before <= 256 * 1024 * 1024
        assert projection_path.stat().st_size <= 128 * 1024 * 1024

        with sqlite3.connect(projection_path) as connection:
            state_count, maximum_state_bytes, total_state_bytes = connection.execute(
                "SELECT COUNT(*),MAX(length(CAST(payload_json AS BLOB))),"
                "SUM(length(CAST(payload_json AS BLOB))) FROM continuations"
            ).fetchone()
        assert 0 < state_count <= 256
        assert 0 < maximum_state_bytes <= state_bytes_max
        assert 0 < total_state_bytes <= 2 * 1024 * 1024

        negative_now = query_now + timedelta(seconds=10)
        negative_first = service.search(
            query,
            CHAIN_DEPTH_MAX,
            budget=TINY_BUDGET,
            subject_id=grants["reader"]["subject_id"],
            grant_id=grants["reader"]["grant_id"],
            now=negative_now,
            ttl_seconds=TTL_SECONDS,
        )
        continuation = negative_first["continuation"]
        assert isinstance(continuation, Mapping)
        token = continuation["token"]

        with pytest.raises(ProjectionError, match="resume_binding binding mismatch"):
            service.search(
                query,
                CHAIN_DEPTH_MAX,
                budget=TINY_BUDGET,
                continuation_token=token,
                subject_id=grants["alternate_reader"]["subject_id"],
                grant_id=grants["alternate_reader"]["grant_id"],
                now=negative_now + timedelta(seconds=1),
                ttl_seconds=TTL_SECONDS,
            )
        with pytest.raises((AuthorityError, ServiceError)):
            service.search(
                query,
                CHAIN_DEPTH_MAX,
                budget=TINY_BUDGET,
                continuation_token=token,
                subject_id="subject:wrong",
                grant_id=grants["reader"]["grant_id"],
                now=negative_now + timedelta(seconds=1),
                ttl_seconds=TTL_SECONDS,
            )
        with pytest.raises(ProjectionError, match="ttl_seconds binding mismatch"):
            service.search(
                query,
                CHAIN_DEPTH_MAX,
                budget=TINY_BUDGET,
                continuation_token=token,
                subject_id=grants["reader"]["subject_id"],
                grant_id=grants["reader"]["grant_id"],
                now=negative_now + timedelta(seconds=1),
                ttl_seconds=TTL_SECONDS + 1,
            )
        with pytest.raises(ProjectionError, match="ranking binding mismatch"):
            service.search(
                query,
                CHAIN_DEPTH_MAX,
                budget=TINY_BUDGET,
                ranking="bm25-v2",
                continuation_token=token,
                subject_id=grants["reader"]["subject_id"],
                grant_id=grants["reader"]["grant_id"],
                now=negative_now + timedelta(seconds=1),
                ttl_seconds=TTL_SECONDS,
            )
        with pytest.raises(ProjectionError, match="depth binding mismatch"):
            service.search(
                query,
                CHAIN_DEPTH_MAX - 1,
                budget=TINY_BUDGET,
                continuation_token=token,
                subject_id=grants["reader"]["subject_id"],
                grant_id=grants["reader"]["grant_id"],
                now=negative_now + timedelta(seconds=1),
                ttl_seconds=TTL_SECONDS,
            )
        with pytest.raises(ProjectionError, match="budget binding mismatch"):
            service.search(
                query,
                CHAIN_DEPTH_MAX,
                budget={**TINY_BUDGET, "max_bytes": TINY_BUDGET["max_bytes"] - 1},
                continuation_token=token,
                subject_id=grants["reader"]["subject_id"],
                grant_id=grants["reader"]["grant_id"],
                now=negative_now + timedelta(seconds=1),
                ttl_seconds=TTL_SECONDS,
            )

        token_parts = token.split(".")
        signature = bytearray(
            base64.urlsafe_b64decode(
                token_parts[-1] + "=" * (-len(token_parts[-1]) % 4)
            )
        )
        signature[0] ^= 0x01
        token_parts[-1] = base64.urlsafe_b64encode(bytes(signature)).rstrip(
            b"="
        ).decode("ascii")
        with pytest.raises(ProjectionError, match="signature mismatch"):
            service.search(
                query,
                CHAIN_DEPTH_MAX,
                budget=TINY_BUDGET,
                continuation_token=".".join(token_parts),
                subject_id=grants["reader"]["subject_id"],
                grant_id=grants["reader"]["grant_id"],
                now=negative_now + timedelta(seconds=1),
                ttl_seconds=TTL_SECONDS,
            )
        with pytest.raises(ProjectionError, match="expired"):
            service.search(
                query,
                CHAIN_DEPTH_MAX,
                budget=TINY_BUDGET,
                continuation_token=token,
                subject_id=grants["reader"]["subject_id"],
                grant_id=grants["reader"]["grant_id"],
                now=negative_now + timedelta(seconds=TTL_SECONDS),
                ttl_seconds=TTL_SECONDS,
            )

        post_token_reader = _grant(
            service._context().plans["authority.json"],
            grants["manager"]["activation_digest"],
            grants["manager"]["issued_at"],
            grant_id="grant:query-tail:post-token-reader",
            capability="projection.read",
            issuer=grants["manager"],
        )
        new_head = service.commit(
            _command(
                activation_digest=grants["manager"]["activation_digest"],
                command_id="command:query-tail:post-token-reader",
                command_kind="grant.issue",
                payload=post_token_reader,
                expected_head=head,
                issued_at=grants["manager"]["issued_at"],
                authorization=_grant_authorization(grants["manager"]),
            )
        )["batch_digest"]
        assert new_head != continuation["head_digest"]
        with pytest.raises(
            ProjectionError,
            match="stale|missing|substituted|event HEAD",
        ):
            service.search(
                query,
                CHAIN_DEPTH_MAX,
                budget=TINY_BUDGET,
                continuation_token=token,
                subject_id=grants["reader"]["subject_id"],
                grant_id=grants["reader"]["grant_id"],
                now=negative_now + timedelta(seconds=1),
                ttl_seconds=TTL_SECONDS,
            )
        assert time.perf_counter() - test_started < 120.0
    finally:
        service.close()
