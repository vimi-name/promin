from __future__ import annotations

from pathlib import Path

import pytest

from promin.canonical import canonical_bytes, digest_value, load_json_strict
from promin.experience import resolve_plan
from promin.initial_project_work import (
    InitialProjectWorkError,
    prepare_initial_project_work,
    preview_initial_project_work,
)


def _project(root: Path, *, source: bool = True) -> dict[str, object]:
    if source:
        (root / "src").mkdir()
        (root / "src" / "main.py").write_text("print('ok')\n", encoding="utf-8")
        (root / "README.md").write_text("# Project\n", encoding="utf-8")
    plan = resolve_plan(root, language="en")
    generated = root / ".promin" / "generated"
    init = root / ".promin" / "init"
    generated.mkdir(parents=True)
    init.mkdir()
    (generated / "resolved-plan.json").write_bytes(canonical_bytes(plan))
    (init / "activation.json").write_bytes(
        canonical_bytes(
            {
                "record_type": "Activation",
                "activation_digest": digest_value({"plan_digest": plan["plan_digest"]}),
            }
        )
    )
    return plan


def _assert_false_claims(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in {
                "authority",
                "authority_granted",
                "pass_credit",
                "acceptance_pass",
                "product_acceptance_pass",
                "mutation_authorized",
                "package_defined_task",
            }:
                assert child is False
            _assert_false_claims(child)
    elif isinstance(value, list):
        for child in value:
            _assert_false_claims(child)


def test_plan_is_deterministic_and_does_not_write(tmp_path: Path) -> None:
    plan = _project(tmp_path)
    before = {path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")}
    first = prepare_initial_project_work(tmp_path, plan)
    second = prepare_initial_project_work(tmp_path, plan)
    assert first == second
    assert first["status"] == "PLANNED_NO_EXECUTION"
    assert not (tmp_path / ".promin-host").exists()
    assert {path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")} == before
    _assert_false_claims(first)


def test_preview_is_owner_generated_and_pending_initialization(tmp_path: Path) -> None:
    plan = resolve_plan(tmp_path, language="en")
    before = {path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")}

    preview = preview_initial_project_work(tmp_path, plan)

    assert preview["record_type"] == "InitialProjectWorkPreview"
    assert preview["status"] == "PLANNED_NO_EXECUTION"
    assert preview["activation_status"] == "PENDING_INITIALIZATION"
    assert preview["activation_digest"] is None
    assert preview["operations"] == [
        item["operation_id"]
        for item in plan["planned_operations"]
        if item["operation_id"] != "initialize-control-layer"
    ]
    assert preview["resource_limits"]["max_files"] == 4096
    assert not (tmp_path / ".promin").exists()
    assert {path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")} == before
    _assert_false_claims(preview)


def test_execute_records_static_inventory_and_reopens_exactly(tmp_path: Path) -> None:
    plan = _project(tmp_path)
    first = prepare_initial_project_work(tmp_path, plan, execute=True)
    second = prepare_initial_project_work(tmp_path, plan, execute=True)
    assert first == second
    assert first["status"] == "READY_PROPOSAL_ONLY"
    card = first["suggested_work_card"]
    assert card["task_shape"] == "direct-or-decomposed-dag"
    assert card["task"] is None
    assert card["model_required"] is False
    evidence = tmp_path / first["evidence_directory"]
    assert {path.name for path in evidence.iterdir()} == {
        "workflow-plan.json",
        "inventory.json",
        "semantic-map.json",
        "suggested-work-card.json",
        "result.json",
    }
    _assert_false_claims(first)


def test_resource_limit_is_explicit_and_recoverable_with_new_plan(tmp_path: Path) -> None:
    plan = _project(tmp_path)
    limited = prepare_initial_project_work(tmp_path, plan, execute=True, max_files=1)
    assert limited["status"] == "INCOMPLETE_RESOURCE_LIMIT"
    assert limited["recoverable_with_new_limits"] is True
    completed = prepare_initial_project_work(tmp_path, plan, execute=True, max_files=16)
    assert completed["status"] == "READY_PROPOSAL_ONLY"
    assert completed["workflow_digest"] != limited["workflow_digest"]


def test_file_and_byte_limits_accept_exact_boundary_then_stop(tmp_path: Path) -> None:
    plan = _project(tmp_path)
    source_bytes = sum(
        path.stat().st_size
        for path in (tmp_path / "README.md", tmp_path / "src" / "main.py")
    )

    exact = prepare_initial_project_work(
        tmp_path, plan, execute=True, max_files=2, max_bytes=source_bytes
    )
    assert exact["status"] == "READY_PROPOSAL_ONLY"
    inventory = load_json_strict(tmp_path / exact["evidence_directory"] / "inventory.json")
    assert inventory["entry_count"] == 2
    assert inventory["content_bytes_read"] == source_bytes
    assert inventory["scan_complete"] is True
    assert inventory["inventory_digest"] == digest_value(inventory["entry_samples"])

    file_limited = prepare_initial_project_work(
        tmp_path, plan, execute=True, max_files=1, max_bytes=source_bytes
    )
    assert file_limited["status"] == "INCOMPLETE_RESOURCE_LIMIT"
    assert file_limited["failure_reason"] == "max_files"

    byte_limited = prepare_initial_project_work(
        tmp_path, plan, execute=True, max_files=2, max_bytes=source_bytes - 1
    )
    assert byte_limited["status"] == "INCOMPLETE_RESOURCE_LIMIT"
    assert byte_limited["failure_reason"] == "max_bytes"


def test_depth_limit_is_reported_without_project_mutation(tmp_path: Path) -> None:
    plan = _project(tmp_path, source=False)
    directory = tmp_path
    for _ in range(65):
        directory = directory / "d"
        directory.mkdir()

    result = prepare_initial_project_work(tmp_path, plan, execute=True, max_files=1)
    assert result["status"] == "INCOMPLETE_RESOURCE_LIMIT"
    assert result["failure_reason"] == "max_depth"
    _assert_false_claims(result)


def test_plan_must_match_persisted_initialized_plan(tmp_path: Path) -> None:
    plan = _project(tmp_path)
    changed = dict(plan)
    changed["goal"] = "another goal"
    with pytest.raises(InitialProjectWorkError, match="persisted resolved plan differs"):
        prepare_initial_project_work(tmp_path, changed)


def test_evidence_is_create_only_and_mismatch_is_rejected(tmp_path: Path) -> None:
    plan = _project(tmp_path)
    planned = prepare_initial_project_work(tmp_path, plan)
    target = tmp_path / planned["evidence_directory"]
    target.mkdir(parents=True)
    (target / "unexpected.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(InitialProjectWorkError, match="existing evidence differs"):
        prepare_initial_project_work(tmp_path, plan, execute=True)


def test_replay_rejects_oversized_existing_artifact(tmp_path: Path) -> None:
    plan = _project(tmp_path)
    result = prepare_initial_project_work(tmp_path, plan, execute=True)
    artifact = tmp_path / result["evidence_directory"] / "inventory.json"
    with artifact.open("wb") as handle:
        handle.truncate(32 * 1024 * 1024)

    with pytest.raises(InitialProjectWorkError, match="existing evidence differs"):
        prepare_initial_project_work(tmp_path, plan, execute=True)


def test_greenfield_init_still_produces_a_proposal(tmp_path: Path) -> None:
    plan = _project(tmp_path, source=False)
    result = prepare_initial_project_work(tmp_path, plan, execute=True)
    assert result["status"] == "READY_PROPOSAL_ONLY"
    assert result["suggested_work_card"]["allowed_paths"]
    _assert_false_claims(result)
