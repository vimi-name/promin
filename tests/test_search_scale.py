from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pytest

from promin.canonical import canonical_bytes
from promin.events import (
    CommitReadView,
    CommitStateSnapshot,
    EventStore,
    EventStorePolicy,
    PreparedCommit,
    command_intent_identity,
    digest_value,
    state_binding_leaf_id,
    state_binding_value_digest,
)
from promin.service import ProminService, inventory_candidate
from promin.projection import (
    ContinuationError,
    Projection,
    ProjectionError,
    ProjectionLimits,
    VerifiedInventoryInput,
    compile_relation_domains,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
TOOLS = PACKAGE_ROOT / "tools"
_SPEC = importlib.util.spec_from_file_location(
    "promin_saturation_tool", TOOLS / "promin_saturation.py"
)
assert _SPEC is not None and _SPEC.loader is not None
saturation = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(saturation)
_AUDIT_SPEC = importlib.util.spec_from_file_location(
    "promin_saturation_audit_tool", TOOLS / "promin_saturation_audit.py"
)
assert _AUDIT_SPEC is not None and _AUDIT_SPEC.loader is not None
saturation_audit = importlib.util.module_from_spec(_AUDIT_SPEC)
_AUDIT_SPEC.loader.exec_module(saturation_audit)

ACTIVATION = "a" * 64
ACTIVATION_RECORD_DIGEST = "b" * 64
IMPLEMENTATION = "1" * 64
NOW = "2026-07-17T12:00:00Z"


def _compiled_event_store_policy() -> EventStorePolicy:
    authority = json.loads(
        (PACKAGE_ROOT / "core" / "authority-model.json").read_text(encoding="utf-8")
    )
    semantic = json.loads(
        (PACKAGE_ROOT / "core" / "semantic-model.json").read_text(encoding="utf-8")
    )
    event = authority["event_contract"]
    mutation = authority["command_mutation_claim_rule"]
    record = {
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
            for command_kind, event_kind in event["command_to_primary_event"].items()
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
    record["policy_digest"] = digest_value(record)
    return EventStorePolicy.from_compiled(record)


EVENT_STORE_POLICY = _compiled_event_store_policy()
_AUTHORITY_MODEL = json.loads(
    (PACKAGE_ROOT / "core" / "authority-model.json").read_text(encoding="utf-8")
)
_SEMANTIC_MODEL = json.loads(
    (PACKAGE_ROOT / "core" / "semantic-model.json").read_text(encoding="utf-8")
)
_CONFORMANCE_MODEL = json.loads(
    (PACKAGE_ROOT / "core" / "conformance.json").read_text(encoding="utf-8")
)
_POLICY_SET = json.loads(
    (PACKAGE_ROOT / "core" / "policy-set.json").read_text(encoding="utf-8")
)
_PRESET = json.loads(
    (PACKAGE_ROOT / "presets" / "semantic-morok-tower.json").read_text(
        encoding="utf-8"
    )
)
_CONTINUATION_OWNER = _AUTHORITY_MODEL["continuation_access_rule"]
_SELECTED_PROFILE_ID = "tower-strong"
_SELECTED_PROFILE = _PRESET["profiles"][_SELECTED_PROFILE_ID]
_PROJECTION_OWNER = {
    "record_type": "ProjectionLimits",
    "token_version": _CONTINUATION_OWNER["token_version"],
    "ranking_algorithm_id": _CONTINUATION_OWNER["ranking_algorithm_id"],
    "traversal_algorithm_id": _CONTINUATION_OWNER["traversal_algorithm_id"],
    "dependency_depth_hard_max": _CONFORMANCE_MODEL[
        "dependency_depth_hard_max"
    ],
    "continuation_ttl_seconds_max": _CONTINUATION_OWNER["ttl_seconds_max"],
    "selected_profile_id": _SELECTED_PROFILE_ID,
    "selected_profile_digest": digest_value(_SELECTED_PROFILE),
    "persistent_entity_types": [
        item["kind"] for item in _SEMANTIC_MODEL["persistent_entities"]
    ],
    "default_budget": {
        "max_bytes": _SELECTED_PROFILE["max_context_bytes"],
        "max_entities": _SELECTED_PROFILE["max_entities"],
        "max_relations": _SELECTED_PROFILE["max_relations"],
        "max_fanout_per_entity": _SELECTED_PROFILE["max_fanout_per_entity"],
        "top_k": _SELECTED_PROFILE["top_k"],
    },
    "hard_budget": _CONFORMANCE_MODEL["workcard_hard_ceiling"],
    "default_depth": _SELECTED_PROFILE["default_dependency_depth"],
    "depth_min": _CONTINUATION_OWNER["depth_min"],
    "depth_max": _CONFORMANCE_MODEL["dependency_depth_hard_max"],
    "default_ttl_seconds": _CONTINUATION_OWNER["default_ttl_seconds"],
    "ttl_min_seconds": _CONTINUATION_OWNER["ttl_min_seconds"],
    "ttl_max_seconds": _CONTINUATION_OWNER["ttl_seconds_max"],
    "max_token_bytes": _CONFORMANCE_MODEL["scale_contracts"]["workcard"][
        "continuation_token_bytes_max"
    ],
    "max_continuation_state_bytes": _CONFORMANCE_MODEL["scale_contracts"][
        "workcard"
    ]["continuation_state_bytes_max"],
    "max_query_bytes": _POLICY_SET["derived_result_contracts"][
        "RetrievalPage"
    ]["query_bytes_max"],
    "min_result_bytes": _CONTINUATION_OWNER["min_result_bytes"],
    "max_resume_binding_fields": _CONTINUATION_OWNER[
        "max_resume_binding_fields"
    ],
    "max_resume_binding_key_chars": _CONTINUATION_OWNER[
        "max_resume_binding_key_chars"
    ],
    "max_resume_binding_value_bytes": _CONTINUATION_OWNER[
        "max_resume_binding_value_bytes"
    ],
    "max_resume_binding_bytes": _CONTINUATION_OWNER[
        "max_resume_binding_bytes"
    ],
    "required_resume_binding_fields": _CONTINUATION_OWNER[
        "required_resume_binding_fields"
    ],
}
PROJECTION_LIMITS = ProjectionLimits(
    **{
        **_PROJECTION_OWNER,
        "persistent_entity_types": tuple(
            _PROJECTION_OWNER["persistent_entity_types"]
        ),
        "required_resume_binding_fields": tuple(
            _PROJECTION_OWNER["required_resume_binding_fields"]
        ),
    },
    policy_digest=digest_value(_PROJECTION_OWNER),
    event_store_policy=EVENT_STORE_POLICY,
)
RESUME_BINDING = {
    "activation_digest": ACTIVATION,
    "capability_id": "projection.read",
    "grant_claim_digest": "2" * 64,
    "grant_id": "grant:search",
    "implementation_closure_digest": IMPLEMENTATION,
    "requested_scope_digest": "3" * 64,
    "revocation_epoch": "4" * 64,
    "subject_id": "subject:scale",
}


def _thaw(value):
    if isinstance(value, dict) or hasattr(value, "items"):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_thaw(item) for item in value]
    return value


def _load_scale_state(view: CommitReadView, envelopes) -> CommitStateSnapshot:
    batch_ids = tuple(envelope["batch"]["batch_id"] for envelope in envelopes())
    return CommitStateSnapshot(
        batch_ids,
        view.head_sequence,
        view.head_digest,
        view.current_state_binding_digest,
    )


def _state_leaf_update(payload: dict[str, object]) -> dict[str, object]:
    payload_type = str(payload["record_type"])
    leaf_type = "Grant" if payload_type == "GrantRevocation" else payload_type
    leaf_id = state_binding_leaf_id(EVENT_STORE_POLICY, leaf_type, payload)
    update: dict[str, object] = {
        "leaf_type": leaf_type,
        "leaf_id": leaf_id,
        "operation": "set",
    }
    value = payload
    if payload_type == "Grant":
        value = {
            "record_type": "GrantAuthorityState",
            "grant": payload,
            "revocation": None,
        }
    if value["record_type"] == EVENT_STORE_POLICY.state_binding_value_rules[
        leaf_type
    ]["value_definition"]:
        event_kind = next(
            iter(EVENT_STORE_POLICY.state_binding_value_rules[leaf_type]["event_kinds"])
        )
        update["value_digest"] = state_binding_value_digest(
            EVENT_STORE_POLICY,
            leaf_type,
            value,
            event_kind=event_kind,
        )
    else:
        update["value_digest"] = digest_value(value)
    return update


def _prepare_scale_commit(view, command_value, relations) -> PreparedCommit:
    del view
    command = _thaw(command_value)
    relation_values = [_thaw(value) for value in relations]
    updates = [_state_leaf_update(command["payload"])]
    updates.extend(_state_leaf_update(value) for value in relation_values)
    updates.sort(key=lambda value: (value["leaf_type"], value["leaf_id"]))
    return PreparedCommit(tuple(relation_values), tuple(updates))


def _inventory_rows(count: int = 4) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for index in range(count):
        path = f"product/{index:04d}.txt"
        file_digest = f"{index + 1:064x}"
        artifact_id = "artifact:file:" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:48]
        rows.append(
            {
                "record_type": "InventoryProjectionRow",
                "path": path,
                "digest": file_digest,
                "size": index + 1,
                "semantic_proxy": {
                    "id": artifact_id,
                    "entity_type": "Artifact",
                    "payload": {
                        "record_type": "Artifact",
                        "artifact_id": artifact_id,
                        "artifact_kind": "product",
                        "digest": file_digest,
                        "media_type": "application/octet-stream",
                        "size_bytes": index + 1,
                    },
                },
            }
        )
    return rows


def _verified_inventory(rows: list[dict[str, object]]) -> VerifiedInventoryInput:
    stream = hashlib.sha256()
    for row in rows:
        stream.update(canonical_bytes({"path": row["path"], "digest": row["digest"], "size": row["size"]}))
    return VerifiedInventoryInput(
        activation_digest=ACTIVATION,
        stream_digest=stream.hexdigest(),
        entry_count=len(rows),
        entries=tuple(rows),
    )


def _event_store(root: Path) -> EventStore:
    return EventStore(
        root,
        ACTIVATION,
        activation_record_digest=ACTIVATION_RECORD_DIGEST,
        implementation_closure_digest=IMPLEMENTATION,
        policy=EVENT_STORE_POLICY,
        compiled_record_validator=lambda _definition, _value, **_kwargs: True,
        command_validator=lambda _value, **_kwargs: True,
        authorization_validator=lambda _value, **_kwargs: True,
        event_validator=lambda _value, **_kwargs: True,
        commit_state_loader=_load_scale_state,
        commit_prepare_callback=_prepare_scale_commit,
        derived_state_validator=lambda _name, _state, **_kwargs: True,
    )


def _record(store: EventStore, kind: str, payload: dict[str, object], relations: list[dict[str, object]] | None = None) -> None:
    sequence = store.head()["sequence"] + 1
    command = {
        "record_type": "CommandRequest",
        "command_id": f"command:scale:{sequence:06d}",
        "command_kind": kind,
        "subject_id": "subject:scale",
        "activation_digest": ACTIVATION,
        "idempotency_key": f"idempotency:scale:{sequence:06d}",
        "requested_scope": [{"selector_type": "all", "selector": "*"}],
        "expected_head_digest": store.head()["batch_digest"],
        "issued_at": NOW,
        "payload": payload,
        "authorization": {"kind": "root", "proof": "scale-test"},
    }
    if kind == "artifact.record":
        command.update(
            {
                "workcard_task_id": "task:scale-corpus",
                "holder_authorization": {
                    "kind": "grant",
                    "grant_id": "grant:scale-holder",
                    "grant_claim_digest": "4" * 64,
                },
                "lease_id": "lease:scale-corpus",
                "lease_generation": 1,
                "fencing_token": sequence,
                "workcard_digest": "5" * 64,
                "context_digest": "6" * 64,
            }
        )
    command["intent_digest"] = digest_value(command_intent_identity(command))
    store.commit(command, auxiliary_relations=relations or (), created_at=NOW)


def _relation(relation_id: str, kind: str, source_type: str, source_id: str, target_type: str, target_id: str) -> dict[str, object]:
    return {
        "record_type": "Relation",
        "relation_id": relation_id,
        "kind": kind,
        "source_type": source_type,
        "source_id": source_id,
        "target_type": target_type,
        "target_id": target_id,
        "activation_digest": ACTIVATION,
        "created_at": NOW,
    }


def _commit_focused_graph(store: EventStore, count: int = 4) -> None:
    for index in range(count):
        task_id = f"task:focused:{index}"
        artifact_id = f"artifact:focused:{index}"
        _record(store, "task.record", {"record_type": "Task", "task_id": task_id, "label": "focused needle"})
        relations = [
            _relation(f"relation:reads:{index}", "READS", "Task", task_id, "Artifact", artifact_id),
            _relation(f"relation:produces:{index}", "PRODUCES", "Task", task_id, "Artifact", artifact_id),
        ]
        _record(
            store,
            "artifact.record",
            {"record_type": "Artifact", "artifact_id": artifact_id, "label": "focused needle"},
            relations,
        )


def _commit_fanout_graph(store: EventStore, count: int = 9, *, label_size: int = 0) -> None:
    seed_id = "task:fanout:seed"
    _record(
        store,
        "task.record",
        {"record_type": "Task", "task_id": seed_id, "label": "fanout needle" + "s" * label_size},
    )
    for index in range(count):
        artifact_id = f"artifact:fanout:{index:02d}"
        relation = _relation(
            f"relation:fanout:{index:02d}", "READS", "Task", seed_id, "Artifact", artifact_id
        )
        _record(
            store,
            "artifact.record",
            {"record_type": "Artifact", "artifact_id": artifact_id, "label": "neighbor" + "x" * label_size},
            [relation],
        )


def _commit_chain_graph(store: EventStore, length: int = 12) -> None:
    for index in range(length + 1):
        task_id = f"task:depth:{index:02d}"
        relations = [] if index == 0 else [
            _relation(
                f"relation:depth:{index - 1:02d}",
                "DEPENDS_ON",
                "Task",
                f"task:depth:{index - 1:02d}",
                "Task",
                task_id,
            )
        ]
        _record(
            store,
            "task.record",
            {"record_type": "Task", "task_id": task_id, "label": "depth chain node"},
            relations,
        )


def _commit_many_seed_graph(store: EventStore, count: int = 7) -> None:
    for index in range(count):
        task_id = f"task:seed:{index:02d}"
        _record(
            store,
            "task.record",
            {"record_type": "Task", "task_id": task_id, "label": "complete seed corpus"},
        )


def _collect_pages(
    projection: Projection,
    query: str,
    *,
    depth: int,
    budget: dict[str, int] | None = None,
) -> list[dict[str, object]]:
    page = projection.search(
        query,
        depth=depth,
        budget=budget,
        resume_binding=RESUME_BINDING,
        now=NOW,
    )
    pages = [page]
    while page["truncated"]:
        continuation = page["continuation"]
        if not isinstance(continuation, dict):
            raise AssertionError("truncated page lacks continuation")
        if (
            continuation.get("version") != PROJECTION_LIMITS.token_version
            or continuation.get("traversal")
            != PROJECTION_LIMITS.traversal_algorithm_id
        ):
            raise AssertionError("continuation does not use v2 traversal")
        if page["next_stream_cursor"] <= page["stream_cursor"]:
            raise AssertionError("continuation cursor did not advance")
        page = projection.continue_search(
            continuation["token"],
            resume_binding=RESUME_BINDING,
            now=NOW,
        )
        pages.append(page)
        if len(pages) > 512:
            raise AssertionError("continuation did not terminate")
    if page["continuation"] is not None:
        raise AssertionError("complete page has an unnecessary continuation")
    return pages


def _page_union(pages: list[dict[str, object]]) -> tuple[set[str], set[str]]:
    entity_ids = [entity["id"] for page in pages for entity in page["entities"]]
    relation_ids = [relation["relation_id"] for page in pages for relation in page["relations"]]
    if len(entity_ids) != len(set(entity_ids)):
        raise AssertionError("continuation duplicated an entity")
    if len(relation_ids) != len(set(relation_ids)):
        raise AssertionError("continuation duplicated a relation")
    return set(entity_ids), set(relation_ids)


def test_saturation_audit_executes_pytest_only_sentinel() -> None:
    sentinel = os.environ.get("PROMIN_PYTEST_SENTINEL")
    if sentinel is None:
        return
    token = os.environ.get("PROMIN_PYTEST_SENTINEL_TOKEN")
    if not token:
        raise AssertionError("PROMIN_PYTEST_SENTINEL_TOKEN is required with the sentinel path")
    Path(sentinel).write_text(token, encoding="utf-8", newline="\n")


class SearchScaleFocusedTests(unittest.TestCase):
    def test_saturation_entrypoint_precedes_tools_module_shadow(self) -> None:
        original_path = list(sys.path)
        try:
            sys.path[:] = [
                str(TOOLS),
                str(PACKAGE_ROOT),
                *[
                    value
                    for value in original_path
                    if value not in {str(TOOLS), str(PACKAGE_ROOT)}
                ],
            ]
            spec = importlib.util.spec_from_file_location(
                "promin_saturation_path_precedence_probe",
                TOOLS / "promin_saturation.py",
            )
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            if os.environ.get("PROMIN_INSTALLED_TEST_MODE") == "1":
                resolved = [Path(value).resolve() for value in sys.path if value]
                self.assertNotIn(PACKAGE_ROOT, resolved)
                self.assertEqual(Path(sys.path[-1]).resolve(), TOOLS)
            else:
                self.assertEqual(Path(sys.path[0]).resolve(), PACKAGE_ROOT)
        finally:
            sys.path[:] = original_path

    def test_saturation_audit_precedes_tools_module_shadow(self) -> None:
        original_path = list(sys.path)
        try:
            sys.path[:] = [
                str(TOOLS),
                str(PACKAGE_ROOT),
                *[
                    value
                    for value in original_path
                    if value not in {str(TOOLS), str(PACKAGE_ROOT)}
                ],
            ]
            families = saturation_audit._mutation_families(PACKAGE_ROOT)
            collection = saturation_audit._collect_mutations(PACKAGE_ROOT, families)
            self.assertEqual(Path(sys.path[0]).resolve(), PACKAGE_ROOT)
            core_families = json.loads(
                (PACKAGE_ROOT / "core" / "conformance.json").read_text(encoding="utf-8")
            )["mutation_families"]
            self.assertEqual(families, core_families)
            self.assertEqual(collection["families_discovered"], len(core_families))
        finally:
            sys.path[:] = original_path

    def test_saturation_audit_uses_full_pytest_corpus_and_requires_pytest(self) -> None:
        self.assertEqual(
            saturation_audit._pytest_command(),
            [
                saturation_audit.sys.executable,
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "-m",
                "not scale",
                "tests",
            ],
        )
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            saturation_audit.importlib.util,
            "find_spec",
            return_value=None,
        ):
            root = Path(temporary)
            with self.assertRaisesRegex(saturation_audit.AuditError, "pytest is required"):
                saturation_audit.run(
                    root / "package",
                    root / "audit",
                    root / "physical",
                    files=100_000,
                    queries=600,
                )

    def test_pytest_only_sentinel_writes_exact_iteration_token(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sentinel = Path(temporary) / "pytest-only.sentinel"
            with mock.patch.dict(
                os.environ,
                {
                    "PROMIN_PYTEST_SENTINEL": str(sentinel),
                    "PROMIN_PYTEST_SENTINEL_TOKEN": "iteration-bound-token",
                },
            ):
                test_saturation_audit_executes_pytest_only_sentinel()
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "iteration-bound-token")

    def test_production_projection_exact_id_depth_bounds_and_continuation(self) -> None:
        semantic = json.loads(
            (PACKAGE_ROOT / "core" / "semantic-model.json").read_text(encoding="utf-8")
        )
        domains = compile_relation_domains(semantic)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = _event_store(root / "state")
            _commit_focused_graph(store)
            projection = Projection(
                root / "projection.sqlite3",
                b"k" * 32,
                implementation_closure_digest=IMPLEMENTATION,
                limits=PROJECTION_LIMITS,
                relation_domains=domains,
            )
            stats = projection.rebuild(store, inventory=_verified_inventory(_inventory_rows()))
            self.assertEqual(stats["inventory_passes"], 1)
            self.assertEqual(stats["product_passes"], 0)
            self.assertEqual(stats["inventory_proxies"], 4)
            self.assertEqual(stats["raw_file_proxy_ratio"], 1.0)
            self.assertEqual(stats["synthetic_task_count"], 0)
            self.assertEqual(stats["relation_count"], 8)

            for depth in range(1, 13):
                with self.subTest(depth=depth):
                    first = projection.search(
                        "task:focused:0",
                        depth=depth,
                        resume_binding=RESUME_BINDING,
                        now=NOW,
                    )
                    second = projection.search(
                        "task:focused:0",
                        depth=depth,
                        resume_binding=RESUME_BINDING,
                        now=NOW,
                    )
                    self.assertEqual(first, second)
                    self.assertEqual(first["depth"], depth)
                    self.assertEqual(first["entities"][0]["id"], "task:focused:0")

            budget = {
                "max_bytes": 16_384,
                "max_entities": 2,
                "max_relations": 1,
                "max_fanout_per_entity": 1,
                "top_k": 1,
            }
            truncated = projection.search(
                "focused needle",
                depth=12,
                budget=budget,
                resume_binding=RESUME_BINDING,
                now=NOW,
            )
            self.assertTrue(truncated["truncated"])
            self.assertIsInstance(truncated["continuation"]["token"], str)
            self.assertEqual(
                truncated["continuation_version"], PROJECTION_LIMITS.token_version
            )
            self.assertEqual(
                truncated["continuation"]["traversal"],
                PROJECTION_LIMITS.traversal_algorithm_id,
            )
            follow = projection.continue_search(
                truncated["continuation"]["token"],
                resume_binding=RESUME_BINDING,
                now="2026-07-17T12:00:01Z",
            )
            self.assertEqual(
                follow["stream_cursor"], truncated["next_stream_cursor"]
            )
            self.assertNotIn("seed_cursor", follow)
            self.assertNotIn("next_seed_cursor", follow)
            if follow["continuation"] is not None:
                self.assertEqual(
                    follow["continuation"]["expiry"],
                    truncated["continuation"]["expiry"],
                )
            else:
                self.assertFalse(follow["truncated"])
            with self.assertRaises(ContinuationError):
                projection.continue_search(
                    truncated["continuation"]["token"] + "x",
                    resume_binding=RESUME_BINDING,
                    now="2026-07-17T12:00:01Z",
                )
            with self.assertRaises(ContinuationError):
                projection.continue_search(
                    truncated["continuation"]["token"],
                    resume_binding=RESUME_BINDING,
                    now="2026-07-17T13:00:00Z",
                )

    def test_sparse_raw_inventory_has_one_proxy_no_graph_inflation_and_bounded_storage(self) -> None:
        semantic = json.loads(
            (PACKAGE_ROOT / "core" / "semantic-model.json").read_text(encoding="utf-8")
        )
        rows = _inventory_rows(2_000)
        stream_bytes = sum(
            len(canonical_bytes({"path": row["path"], "digest": row["digest"], "size": row["size"]}))
            for row in rows
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            projection = Projection(
                root / "projection.sqlite3",
                b"r" * 32,
                implementation_closure_digest=IMPLEMENTATION,
                limits=PROJECTION_LIMITS,
                relation_domains=compile_relation_domains(semantic),
            )
            stats = projection.rebuild(
                _event_store(root / "state"),
                inventory=_verified_inventory(rows),
            )
            self.assertEqual(stats["inventory_entries"], 2_000)
            self.assertEqual(stats["inventory_proxies"], 2_000)
            self.assertEqual(stats["inventory_relations"], 0)
            self.assertEqual(stats["synthetic_task_count"], 0)
            self.assertEqual(stats["raw_file_proxy_ratio"], 1.0)
            self.assertLessEqual(stats["projection_db_bytes"] / stream_bytes, 20.0)

    def test_continuation_v2_preserves_fanout_under_entity_and_relation_ceilings(self) -> None:
        semantic = json.loads(
            (PACKAGE_ROOT / "core" / "semantic-model.json").read_text(encoding="utf-8")
        )
        domains = compile_relation_domains(semantic)
        budget = {
            "max_bytes": 16_384,
            "max_entities": 2,
            "max_relations": 1,
            "max_fanout_per_entity": 1,
            "top_k": 1,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = _event_store(root / "state")
            _commit_fanout_graph(store)
            projection = Projection(
                root / "projection.sqlite3",
                b"f" * 32,
                implementation_closure_digest=IMPLEMENTATION,
                limits=PROJECTION_LIMITS,
                relation_domains=domains,
            )
            projection.rebuild(store)
            reference = _page_union(
                _collect_pages(projection, "task:fanout:seed", depth=1)
            )
            pages = _collect_pages(
                projection,
                "task:fanout:seed",
                depth=1,
                budget=budget,
            )
            self.assertGreater(len(pages), 2)
            self.assertEqual(_page_union(pages), reference)
            self.assertEqual(len(reference[0]), 10)
            self.assertEqual(len(reference[1]), 9)
            expiry = pages[0]["continuation"]["expiry"]
            for page in pages:
                self.assertLessEqual(len(page["entities"]), budget["max_entities"])
                self.assertLessEqual(len(page["relations"]), budget["max_relations"])
                self.assertLessEqual(len(canonical_bytes(page)), budget["max_bytes"])
                if page["continuation"] is not None:
                    self.assertEqual(page["continuation"]["expiry"], expiry)

    def test_continuation_v2_byte_ceiling_resumes_without_loss(self) -> None:
        semantic = json.loads(
            (PACKAGE_ROOT / "core" / "semantic-model.json").read_text(encoding="utf-8")
        )
        domains = compile_relation_domains(semantic)
        budget = {
            "max_bytes": 4_096,
            "max_entities": 32,
            "max_relations": 48,
            "max_fanout_per_entity": 8,
            "top_k": 12,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = _event_store(root / "state")
            _commit_fanout_graph(store, 6, label_size=700)
            projection = Projection(
                root / "projection.sqlite3",
                b"b" * 32,
                implementation_closure_digest=IMPLEMENTATION,
                limits=PROJECTION_LIMITS,
                relation_domains=domains,
            )
            projection.rebuild(store)
            reference = _page_union(
                _collect_pages(projection, "task:fanout:seed", depth=1)
            )
            pages = _collect_pages(
                projection,
                "task:fanout:seed",
                depth=1,
                budget=budget,
            )
            self.assertGreater(len(pages), 1)
            self.assertEqual(_page_union(pages), reference)
            for page in pages:
                self.assertLessEqual(len(canonical_bytes(page)), budget["max_bytes"])

    def test_continuation_v2_page_union_matches_depth_one_through_twelve(self) -> None:
        semantic = json.loads(
            (PACKAGE_ROOT / "core" / "semantic-model.json").read_text(encoding="utf-8")
        )
        domains = compile_relation_domains(semantic)
        budget = {
            "max_bytes": 16_384,
            "max_entities": 2,
            "max_relations": 1,
            "max_fanout_per_entity": 1,
            "top_k": 1,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = _event_store(root / "state")
            _commit_chain_graph(store)
            projection = Projection(
                root / "projection.sqlite3",
                b"d" * 32,
                implementation_closure_digest=IMPLEMENTATION,
                limits=PROJECTION_LIMITS,
                relation_domains=domains,
            )
            projection.rebuild(store)
            for depth in range(1, 13):
                with self.subTest(depth=depth):
                    pages = _collect_pages(
                        projection,
                        "task:depth:00",
                        depth=depth,
                        budget=budget,
                    )
                    entities, relations = _page_union(pages)
                    self.assertEqual(
                        entities,
                        {f"task:depth:{index:02d}" for index in range(depth + 1)},
                    )
                    self.assertEqual(
                        relations,
                        {f"relation:depth:{index:02d}" for index in range(depth)},
                    )
                    for page in pages:
                        self.assertLessEqual(len(page["entities"]), budget["max_entities"])
                        self.assertLessEqual(len(page["relations"]), budget["max_relations"])

    def test_broad_query_requires_refinement_and_never_pages_unselected_corpus(self) -> None:
        semantic = json.loads(
            (PACKAGE_ROOT / "core" / "semantic-model.json").read_text(encoding="utf-8")
        )
        budget = {
            "max_bytes": 16_384,
            "max_entities": 2,
            "max_relations": 1,
            "max_fanout_per_entity": 1,
            "top_k": 2,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = _event_store(root / "state")
            _commit_many_seed_graph(store)
            projection = Projection(
                root / "projection.sqlite3",
                b"t" * 32,
                implementation_closure_digest=IMPLEMENTATION,
                limits=PROJECTION_LIMITS,
                relation_domains=compile_relation_domains(semantic),
            )
            projection.rebuild(store)
            pages = _collect_pages(
                projection,
                "complete seed corpus",
                depth=1,
                budget=budget,
            )
            entities, relations = _page_union(pages)
            self.assertEqual(entities, {"task:seed:00", "task:seed:01"})
            self.assertEqual(relations, set())
            self.assertTrue(pages[0]["refinement_required"])
            self.assertEqual(pages[0]["selected_seed_count"], 2)
            self.assertGreaterEqual(len(pages[0]["refinement_hints"]), 1)
            self.assertFalse(pages[0]["unselected_matches_traversable"])
            self.assertFalse(pages[0]["silent_truncation"])
            self.assertFalse(pages[-1]["truncated"])
            self.assertTrue(pages[-1]["selected_closure_complete"])

    def test_continuation_v2_is_bound_to_query_ranking_budget_and_depth(self) -> None:
        semantic = json.loads(
            (PACKAGE_ROOT / "core" / "semantic-model.json").read_text(encoding="utf-8")
        )
        domains = compile_relation_domains(semantic)
        budget = {
            "max_bytes": 16_384,
            "max_entities": 2,
            "max_relations": 1,
            "max_fanout_per_entity": 1,
            "top_k": 1,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = _event_store(root / "state")
            _commit_fanout_graph(store)
            projection = Projection(
                root / "projection.sqlite3",
                b"v" * 32,
                implementation_closure_digest=IMPLEMENTATION,
                limits=PROJECTION_LIMITS,
                relation_domains=domains,
            )
            projection.rebuild(store)
            resume_binding = dict(RESUME_BINDING)
            first = projection.search(
                "task:fanout:seed",
                depth=1,
                budget=budget,
                resume_binding=resume_binding,
                now=NOW,
                ttl_seconds=60,
            )
            token = first["continuation"]["token"]
            self.assertLessEqual(len(token.encode("ascii")), 256)
            with self.assertRaisesRegex(ContinuationError, "query binding mismatch"):
                projection.search(
                    "neighbor",
                    depth=1,
                    budget=budget,
                    resume_binding=resume_binding,
                    continuation_token=token,
                    now=NOW,
                    ttl_seconds=60,
                )
            with self.assertRaisesRegex(ContinuationError, "resume_binding binding mismatch"):
                projection.search(
                    "task:fanout:seed",
                    depth=1,
                    budget=budget,
                    resume_binding={**resume_binding, "subject_id": "subject:other"},
                    continuation_token=token,
                    now=NOW,
                    ttl_seconds=60,
                )
            with self.assertRaisesRegex(ContinuationError, "depth binding mismatch"):
                projection.search(
                    "task:fanout:seed",
                    depth=2,
                    budget=budget,
                    resume_binding=resume_binding,
                    continuation_token=token,
                    now=NOW,
                    ttl_seconds=60,
                )
            changed_budget = {**budget, "max_entities": 3}
            with self.assertRaisesRegex(ContinuationError, "budget binding mismatch"):
                projection.search(
                    "task:fanout:seed",
                    depth=1,
                    budget=changed_budget,
                    resume_binding=resume_binding,
                    continuation_token=token,
                    now=NOW,
                    ttl_seconds=60,
                )
            with self.assertRaisesRegex(ContinuationError, "ranking binding mismatch"):
                projection.search(
                    "task:fanout:seed",
                    depth=1,
                    budget=budget,
                    ranking="bm25-v2",
                    resume_binding=resume_binding,
                    continuation_token=token,
                    now=NOW,
                    ttl_seconds=60,
                )

    def test_scale_contract_rejects_reduced_physical_or_query_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(saturation.SaturationError, "100000"):
                saturation.run(root / "workspace", root / "out-a", files=99_999, queries=600)
            with self.assertRaisesRegex(saturation.SaturationError, "600"):
                saturation.run(root / "workspace", root / "out-b", files=100_000, queries=599)

    def test_saturation_initializes_and_reuses_a_dedicated_zero_scan_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "physical-saturation"
            created = saturation._initialize_saturation_workspace(workspace)
            self.assertEqual(created["status"], "created")
            self.assertEqual(created["product_tree_scans"], 0)
            self.assertEqual(created["init_record_count"], 5)
            self.assertEqual(created["project_id"], "promin-physical-saturation")
            self.assertEqual(created["snapshot_provider_id"], "git-filesystem-inventory")

            installed_project = json.loads(
                (workspace / ".promin" / "init" / "project.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                installed_project["candidate_recipe"]["snapshot_consistency"],
                "immutable-vcs-tree",
            )
            reused = saturation._initialize_saturation_workspace(workspace)
            self.assertEqual(reused["status"], "reused")
            self.assertEqual(reused["activation_digest"], created["activation_digest"])
            self.assertEqual(
                reused["implementation_closure_digest"],
                created["implementation_closure_digest"],
            )

    def test_saturation_all_scope_is_not_combined_with_task_selector(self) -> None:
        self.assertEqual(
            saturation._task_requested_scope(
                [{"kind": "all", "value": "*"}],
                "task:saturation:001",
            ),
            [{"kind": "task", "value": "task:saturation:001"}],
        )
        self.assertEqual(
            saturation._task_requested_scope(
                [{"kind": "project", "value": "project-1"}],
                "task:saturation:001",
            ),
            [
                {"kind": "project", "value": "project-1"},
                {"kind": "task", "value": "task:saturation:001"},
            ],
        )

    def test_saturation_semantic_corpus_commits_under_the_dedicated_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "physical-saturation"
            saturation._initialize_saturation_workspace(workspace)
            runtime = ProminService(workspace)
            commit_observations = []
            created = saturation._ensure_semantic_corpus(
                runtime,
                candidate_digest="a" * 64,
                commit_observations=commit_observations,
            )
            self.assertEqual(created["task_count"], 32)
            self.assertEqual(created["relation_count"], 28)
            self.assertEqual(
                created["continuation_query_ids"],
                [
                    "task:saturation:depth:12",
                    "task:saturation:fanout:root",
                ],
            )
            self.assertLessEqual(
                set(created["continuation_query_ids"]), set(created["query_ids"])
            )
            self.assertFalse(created["reused"])
            reused = saturation._ensure_semantic_corpus(
                runtime,
                candidate_digest="a" * 64,
                commit_observations=commit_observations,
            )
            self.assertTrue(reused["reused"])
            self.assertEqual(reused["query_grant"]["capability_id"], "projection.read")

    def test_physical_relation_corpus_uses_bounded_authorized_batches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "physical-saturation"
            saturation._initialize_saturation_workspace(workspace)
            runtime = ProminService(workspace)
            product = workspace / "product"
            product.mkdir()
            for index in range(100):
                (product / f"record-{index:03d}.txt").write_text(
                    f"promin fixture {index:03d}\n", encoding="utf-8"
                )
            descriptor = saturation._prepare_vcs_snapshot(
                workspace, reuse_product=False
            )
            inventory = inventory_candidate(
                workspace,
                ["product"],
                snapshot_descriptor={
                    key: descriptor[key]
                    for key in (
                        "consistency_mode",
                        "provider_id",
                        "repository",
                        "treeish",
                    )
                },
            )
            candidate_digest = inventory.candidate["candidate_digest"]
            commit_observations = []
            artifact_ids = [
                saturation._entry_query(entry) for entry in inventory.entries
            ]
            saturation._ensure_semantic_corpus(
                runtime,
                candidate_digest=candidate_digest,
                commit_observations=commit_observations,
            )
            created = saturation._ensure_physical_relation_corpus(
                runtime,
                candidate_digest=candidate_digest,
                artifact_ids=artifact_ids,
                relation_count=255,
                commit_observations=commit_observations,
            )
            self.assertEqual(created["task_count"], 3)
            self.assertEqual(created["relation_count"], 255)
            self.assertEqual(created["artifact_target_count"], 100)
            self.assertEqual(created["artifact_target_coverage"], 1.0)
            self.assertFalse(created["reused"])
            reused = saturation._ensure_physical_relation_corpus(
                runtime,
                candidate_digest=candidate_digest,
                artifact_ids=artifact_ids,
                relation_count=255,
                commit_observations=commit_observations,
            )
            self.assertTrue(reused["reused"])
            rebuilt = runtime.rebuild(inventory)
            self.assertEqual(rebuilt["inventory_proxies"], 100)
            self.assertEqual(rebuilt["inventory_relations"], 0)
            self.assertEqual(rebuilt["synthetic_task_count"], 0)
            self.assertEqual(rebuilt["relation_count"], 283)

    def test_mixed_query_plan_covers_every_required_class(self) -> None:
        continuation_query_ids = [
            "task:saturation:depth:12",
            "task:saturation:fanout:root",
        ]
        semantic_query_ids = [
            *continuation_query_ids,
            "task:saturation:needle",
        ]
        classes = {
            saturation._mixed_query_case(
                index,
                forced_chains=12,
                artifact_ids=["artifact:fixture:000"],
                semantic_query_ids=semantic_query_ids,
                continuation_query_ids=continuation_query_ids,
            )[0]
            for index in range(600)
        }
        self.assertEqual(
            classes,
            {
                "forced-continuation",
                "exact-artifact",
                "content-high-cardinality",
                "content-probe",
                "miss",
                "hostile-content",
                "hostile-exact",
                "broad",
                "exact-semantic",
            },
        )
        forced_queries = {
            saturation._mixed_query_case(
                index,
                forced_chains=12,
                artifact_ids=["artifact:fixture:000"],
                semantic_query_ids=semantic_query_ids,
                continuation_query_ids=continuation_query_ids,
            )[1]
            for index in range(12)
        }
        self.assertEqual(forced_queries, set(continuation_query_ids))
        self.assertNotIn("task:saturation:needle", forced_queries)
        query_plan = [
            (
                query_class,
                saturation._mixed_query_depth(index, query_class),
            )
            for index in range(600)
            for query_class, _query in [
                saturation._mixed_query_case(
                    index,
                    forced_chains=12,
                    artifact_ids=["artifact:fixture:000"],
                    semantic_query_ids=semantic_query_ids,
                    continuation_query_ids=continuation_query_ids,
                )
            ]
        ]
        self.assertEqual(
            {depth for _query_class, depth in query_plan}, set(range(1, 13))
        )
        self.assertTrue(
            all(
                depth == 1
                for query_class, depth in query_plan
                if query_class in saturation._PHYSICAL_QUERY_DEPTH_ONE_CLASSES
            )
        )
        ceiling = saturation._load_ceiling()
        self.assertEqual(
            saturation._mixed_query_budget(ceiling),
            {
                "max_bytes": ceiling["max_bytes"],
                "max_entities": ceiling["max_entities"],
                "max_relations": ceiling["max_relations"],
                "max_fanout_per_entity": ceiling["max_fanout_per_entity"],
                "top_k": 1,
            },
        )

    def test_continuation_metrics_exclude_preexisting_state_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / ".promin" / "state" / "continuations"
            root.mkdir(parents=True)
            (root / "preexisting.json").write_bytes(b"old\n")
            baseline = set(saturation._continuation_state_files(workspace))
            (root / "current.json").write_bytes(b"current\n")
            metrics = saturation._continuation_state_metrics(
                workspace,
                baseline_files=baseline,
            )
            self.assertEqual(metrics["files"], 1)
            self.assertEqual(metrics["maximum_bytes"], 8)
            self.assertEqual(metrics["total_bytes"], 8)
            self.assertEqual(metrics["preexisting_files_excluded"], 1)

    def test_saturation_projection_receives_the_verified_inventory_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "physical-saturation"
            saturation._initialize_saturation_workspace(workspace)
            product = workspace / "product"
            product.mkdir()
            (product / "source.txt").write_text("promin source\n", encoding="utf-8")
            descriptor = saturation._prepare_vcs_snapshot(workspace, reuse_product=False)
            inventory = inventory_candidate(
                workspace,
                ["product"],
                snapshot_descriptor={
                    key: descriptor[key]
                    for key in ("consistency_mode", "provider_id", "repository", "treeish")
                },
            )
            result = ProminService(workspace).rebuild(inventory)
            self.assertEqual(result["inventory_entries"], 1)
            self.assertEqual(result["inventory_proxies"], 1)
            self.assertEqual(result["product_passes"], 0)

    def test_workcard_bound_is_fail_closed_and_continuation_is_explicit(self) -> None:
        ceiling = saturation._load_ceiling()
        card = {
            "record_type": "WorkCardProjection",
            "entities": [{"id": "task:one"}, {"id": "artifact:one"}],
            "relations": [
                {"kind": "READS", "source_id": "task:one", "target_id": "artifact:one"}
            ],
            "evidence": [],
            "truncated": True,
            "continuation": {"version": 2, "token": "signed.continuation.token"},
            "continuation_version": PROJECTION_LIMITS.token_version,
            "refinement_required": False,
            "refinement_hints": [],
            "selected_seed_count": 1,
            "unselected_matches_traversable": False,
            "selected_closure_complete": False,
            "silent_truncation": False,
        }
        truncated, token = saturation._assert_workcard(card, ceiling)
        self.assertTrue(truncated)
        self.assertEqual(token, "signed.continuation.token")
        card["continuation"] = None
        with self.assertRaisesRegex(saturation.SaturationError, "continuation"):
            saturation._assert_workcard(card, ceiling)
        card["truncated"] = False
        card["selected_closure_complete"] = True
        card["continuation"] = {"version": 2, "token": "unexpected"}
        with self.assertRaisesRegex(saturation.SaturationError, "unnecessary"):
            saturation._assert_workcard(card, ceiling)

    def test_inventory_query_identity_comes_from_the_single_raw_artifact_proxy(self) -> None:
        row = _inventory_rows(1)[0]
        self.assertEqual(saturation._entry_query(row), row["semantic_proxy"]["id"])


@pytest.mark.scale
class SearchScalePhysicalTests(unittest.TestCase):
    def test_physical_100k_same_runtime_route(self) -> None:
        configured = os.environ.get("PROMIN_SCALE_WORKSPACE")
        if not configured:
            self.fail("PROMIN_SCALE_WORKSPACE is required for the physical scale selection")
        workspace = Path(configured).resolve()
        product = workspace / "product"
        reuse = product.is_dir() and any(product.iterdir())
        with tempfile.TemporaryDirectory() as temporary:
            result = saturation.run(
                workspace,
                Path(temporary) / "physical-saturation",
                files=100_000,
                queries=600,
                reuse_product=reuse,
            )
        self.assertEqual(result["status"], "pass")
        self.assertFalse(result["pass_credit"])
        self.assertEqual(result["physical"]["semantic_proxies"], 100_000)
        self.assertEqual(result["physical"]["raw_file_proxy_ratio"], 1.0)
        self.assertEqual(result["physical"]["synthetic_tasks"], 0)
        self.assertEqual(result["physical"]["synthetic_task_ratio"], 0.0)
        self.assertEqual(result["inventory"]["passes"], 1)
        self.assertEqual(result["projection"]["rebuild_product_passes"], 0)
        self.assertTrue(result["projection"]["equal_semantic_digest"])
        self.assertGreaterEqual(result["search"]["actual_runtime_queries"], 600)
        self.assertEqual(result["search"]["depth_min"], 1)
        self.assertEqual(result["search"]["depth_max"], 12)
        self.assertEqual(result["search"]["silent_truncations"], 0)
        self.assertLessEqual(result["projection"]["amplification"], 32.0)


if __name__ == "__main__":
    unittest.main()
