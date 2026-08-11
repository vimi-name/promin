from __future__ import annotations

from copy import deepcopy

import pytest

from promin.canonical import canonical_bytes, digest_value
from promin.weak_model_execution import (
    WeakModelExecutionError,
    create_executor_receipt,
    decompose_high_level_plan,
    resume_execution_plan,
    review_executor_receipts,
    validate_execution_plan,
)


def _budget(*, max_executor_tasks: int = 24) -> dict[str, int]:
    return {
        "max_high_level_tasks": 8,
        "max_executor_tasks": max_executor_tasks,
        "max_dependencies_per_task": 4,
        "max_allowed_paths_per_task": 4,
        "max_static_tools_per_task": 4,
        "max_task_instruction_bytes": 1_024,
        "max_task_output_bytes": 2_048,
        "max_attempts_per_task": 3,
        "max_parallel_tasks": 4,
    }


def _high_level_plan() -> dict[str, object]:
    return {
        "schema": "promin.high-level-execution-plan.v1",
        "plan_id": "bounded-repair",
        "budget": _budget(),
        "tasks": [
            {
                "task_id": "apply-fix",
                "title": "Apply the bounded repair",
                "objective": "Make only the approved reversible local edit.",
                "allowed_paths": ["promin/example.py"],
                "dependencies": ["inspect-source"],
                "risk_class": "reversible-local",
                "static_tool_ids": ["syntax-check", "targeted-test"],
                "acceptance_predicate": "A reviewer can inspect the bounded result.",
            },
            {
                "task_id": "inspect-source",
                "title": "Inspect the affected source",
                "objective": "Collect only source observations for the scoped change.",
                "allowed_paths": ["promin/example.py", "tests/test_example.py"],
                "dependencies": [],
                "risk_class": "read-only",
                "static_tool_ids": ["source-scan", "syntax-check"],
                "acceptance_predicate": "The observations are bound to the declared source scope.",
            },
        ],
    }


def _task(plan: dict[str, object], task_id: str) -> dict[str, object]:
    tasks = plan["tasks"]
    assert isinstance(tasks, list)
    return next(task for task in tasks if task["task_id"] == task_id)


def _receipt(
    plan: dict[str, object], task_id: str, status: str, attempt: int = 1
) -> dict[str, object]:
    task = _task(plan, task_id)
    return create_executor_receipt(
        plan,
        task_id=task_id,
        status=status,
        attempt=attempt,
        input_digest=task["instruction_digest"],
        output_digest=digest_value({"task": task_id, "status": status, "attempt": attempt}),
        output_bytes=128,
        observation=f"Observed {status.lower()} for {task_id}.",
    )


def test_decomposition_is_deterministic_bounded_and_static_tool_first() -> None:
    first = decompose_high_level_plan(_high_level_plan())
    reordered = _high_level_plan()
    tasks = reordered["tasks"]
    assert isinstance(tasks, list)
    reordered["tasks"] = list(reversed(tasks))
    second = decompose_high_level_plan(reordered)

    assert canonical_bytes(first) == canonical_bytes(second)
    assert first["planning_model_cap_billions"] == 12
    assert first["authority_effect"] == "none"
    assert first["authority_granted"] is False
    assert first["pass_credit"] is False
    assert first["acceptance_pass"] is False
    assert [task["task_id"] for task in first["tasks"]] == [
        "inspect-source:preflight",
        "inspect-source:execute",
        "inspect-source:review",
        "apply-fix:preflight",
        "apply-fix:execute",
        "apply-fix:review",
    ]
    preflight = _task(first, "inspect-source:preflight")
    execute = _task(first, "inspect-source:execute")
    assert preflight["kind"] == "static-tool-first"
    assert preflight["tool_phase"] == "static-only"
    assert preflight["tool_ids"] == ["source-scan", "syntax-check"]
    assert execute["depends_on"] == ["inspect-source:preflight"]
    assert execute["requires_current_authorization"] is True
    assert all(
        task["instruction_bytes"] <= first["budget"]["max_task_instruction_bytes"]
        for task in first["tasks"]
    )
    assert all(task["authority_granted"] is False for task in first["tasks"])
    assert validate_execution_plan(first) == first


def test_decomposition_rejects_cycles_unsafe_scope_promotion_and_budget_escape() -> None:
    cycle = _high_level_plan()
    tasks = cycle["tasks"]
    assert isinstance(tasks, list)
    tasks[1]["dependencies"] = ["apply-fix"]
    with pytest.raises(WeakModelExecutionError, match="acyclic"):
        decompose_high_level_plan(cycle)

    unsafe_scope = _high_level_plan()
    unsafe_tasks = unsafe_scope["tasks"]
    assert isinstance(unsafe_tasks, list)
    unsafe_tasks[0]["allowed_paths"] = ["../escape.py"]
    with pytest.raises(WeakModelExecutionError, match="safe relative"):
        decompose_high_level_plan(unsafe_scope)

    promotion = _high_level_plan()
    promotion_tasks = promotion["tasks"]
    assert isinstance(promotion_tasks, list)
    promotion_tasks[0]["authority_granted"] = True
    with pytest.raises(WeakModelExecutionError, match="unsupported fields"):
        decompose_high_level_plan(promotion)

    insufficient = _high_level_plan()
    insufficient["budget"] = _budget(max_executor_tasks=5)
    with pytest.raises(WeakModelExecutionError, match="max_executor_tasks"):
        decompose_high_level_plan(insufficient)


def test_owner_only_input_creates_a_boundary_not_an_executable_mutator() -> None:
    source = _high_level_plan()
    tasks = source["tasks"]
    assert isinstance(tasks, list)
    tasks.append(
        {
            "task_id": "publish-result",
            "title": "Publish an external result",
            "objective": "Await an explicit owner decision before any external action.",
            "allowed_paths": ["docs/result.md"],
            "dependencies": ["apply-fix"],
            "risk_class": "owner-only",
            "static_tool_ids": [],
            "acceptance_predicate": "An owner separately authorizes and records the action.",
        }
    )
    plan = decompose_high_level_plan(source)

    boundary = _task(plan, "publish-result:owner-decision")
    assert boundary["kind"] == "owner-decision"
    assert boundary["status"] == "OWNER_DECISION_REQUIRED"
    assert boundary["tool_ids"] == []
    assert boundary["owner_decision_required"] is True
    assert boundary["authority_effect"] == "none"
    assert boundary["authority_granted"] is False
    assert not any(
        task["parent_task_id"] == "publish-result" and task["kind"] == "bounded-executor"
        for task in plan["tasks"]
    )
    receipts = [
        _receipt(plan, "inspect-source:preflight", "COMPLETED"),
        _receipt(plan, "inspect-source:execute", "COMPLETED"),
        _receipt(plan, "inspect-source:review", "COMPLETED"),
        _receipt(plan, "apply-fix:preflight", "COMPLETED"),
        _receipt(plan, "apply-fix:execute", "COMPLETED"),
        _receipt(plan, "apply-fix:review", "COMPLETED"),
    ]
    review = review_executor_receipts(plan, receipts)
    assert review["owner_decision_task_ids"] == ["publish-result:owner-decision"]
    with pytest.raises(WeakModelExecutionError, match="does not accept"):
        _receipt(plan, "publish-result:owner-decision", "OWNER_DECISION_REQUIRED")


def test_receipts_are_bound_reviewable_and_resume_only_bounded_work() -> None:
    plan = decompose_high_level_plan(_high_level_plan())
    receipts = [
        _receipt(plan, "inspect-source:preflight", "COMPLETED"),
        _receipt(plan, "inspect-source:execute", "COMPLETED"),
        _receipt(plan, "inspect-source:review", "COMPLETED"),
        _receipt(plan, "apply-fix:preflight", "FAILED"),
    ]

    review = review_executor_receipts(plan, receipts)
    assert review["review_status"] == "REVIEW_REQUIRED"
    assert review["ready_task_ids"] == []
    assert review["resumable_task_ids"] == ["apply-fix:preflight"]
    assert review["authority_effect"] == "none"
    assert review["authority_granted"] is False
    assert review["pass_credit"] is False
    assert review["acceptance_pass"] is False

    resume = resume_execution_plan(plan, receipts)
    assert resume["resumable_task_ids"] == ["apply-fix:preflight"]
    assert resume["owner_decision_task_ids"] == []
    assert resume["authority_granted"] is False

    wrong_digest = deepcopy(receipts[0])
    wrong_digest["input_digest"] = "0" * 64
    with pytest.raises(WeakModelExecutionError, match="input_digest"):
        review_executor_receipts(plan, [wrong_digest])


def test_resume_never_offers_more_than_the_parallel_budget() -> None:
    source = _high_level_plan()
    source["budget"] = _budget()
    source["budget"]["max_parallel_tasks"] = 1
    tasks = source["tasks"]
    assert isinstance(tasks, list)
    tasks.append(
        {
            "task_id": "parallel-read",
            "title": "Read an independent source",
            "objective": "Collect a second independent static observation.",
            "allowed_paths": ["promin/other.py"],
            "dependencies": [],
            "risk_class": "read-only",
            "static_tool_ids": ["source-scan"],
            "acceptance_predicate": "A later reviewer can inspect the second receipt.",
        }
    )
    plan = decompose_high_level_plan(source)

    review = review_executor_receipts(plan, [])
    assert review["ready_task_ids"] == ["inspect-source:preflight"]
    assert review["deferred_task_ids"] == ["parallel-read:preflight"]
