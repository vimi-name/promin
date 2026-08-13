from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from promin.canonical import canonical_bytes, digest_value
from promin.weak_model_execution import (
    TASK_STATE_TRANSITIONS,
    WeakModelExecutionError,
    create_control_record,
    create_executor_receipt,
    decompose_high_level_plan,
    resume_execution_plan,
    review_executor_receipts,
    validate_execution_plan,
)


def _budget(**changes: int) -> dict[str, int]:
    value = {
        "max_high_level_tasks": 8,
        "max_executor_tasks": 8,
        "max_dependencies_per_task": 4,
        "max_resources_per_task": 4,
        "max_task_instruction_bytes": 4096,
        "max_task_context_bytes": 8192,
        "max_task_output_bytes": 2048,
        "max_attempt_seconds": 30,
        "max_attempts_per_task": 3,
        "max_parallel_tasks": 4,
        "max_workflow_seconds": 120,
        "max_workflow_output_bytes": 8192,
    }
    value.update(changes)
    return value


def _task(
    task_id: str,
    *,
    dependencies: list[str] | None = None,
    resources: list[dict[str, str]] | None = None,
    owner: bool = False,
) -> dict[str, object]:
    return {
        "task_id": task_id,
        "title": f"Run {task_id}",
        "objective": f"Complete arbitrary objective {task_id} without narrowing its semantics.",
        "dependencies": dependencies or [],
        "task_mode": "managed",
        "resources": resources or [],
        "acceptance_predicate": f"Evidence for {task_id} is reviewable.",
        "requires_current_authorization": False,
        "requires_owner_decision": owner,
    }


def _plan() -> dict[str, object]:
    return {
        "schema": "promin.high-level-execution-plan.v1",
        "plan_id": "universal-work",
        "budget": _budget(),
        "tasks": [
            _task("deliver", dependencies=["compute", "communicate"]),
            _task("communicate", dependencies=["source"]),
            _task("source", resources=[{"resource_type": "api", "resource_id": "catalog"}]),
            _task("compute", dependencies=["source"]),
        ],
    }


def _card(plan: dict[str, object], task_id: str) -> dict[str, object]:
    tasks = plan["tasks"]
    assert isinstance(tasks, list)
    return next(item for item in tasks if item["task_id"] == task_id)


def _receipt(
    plan: dict[str, object], task_id: str, outcome: str, attempt: int = 1
) -> dict[str, object]:
    task = _card(plan, task_id)
    return create_executor_receipt(
        plan,
        task_id=task_id,
        status=outcome,
        attempt=attempt,
        input_digest=task["instruction_digest"],
        output_digest=digest_value({"task": task_id, "attempt": attempt}),
        output_bytes=16,
        elapsed_milliseconds=20,
        observation=f"Observed {outcome}.",
    )


def test_arbitrary_branched_dag_is_direct_deterministic_and_resources_are_optional() -> None:
    first = decompose_high_level_plan(_plan())
    reordered = _plan()
    reordered["tasks"] = list(reversed(reordered["tasks"]))
    second = decompose_high_level_plan(reordered)

    assert canonical_bytes(first) == canonical_bytes(second)
    assert [item["task_id"] for item in first["tasks"]] == [
        "source:execute",
        "communicate:execute",
        "compute:execute",
        "deliver:execute",
    ]
    assert _card(first, "compute:execute")["resources"] == []
    assert _card(first, "communicate:execute")["depends_on"] == ["source:execute"]
    assert _card(first, "deliver:execute")["depends_on"] == [
        "communicate:execute",
        "compute:execute",
    ]
    assert all(item["kind"] == "managed-task" for item in first["tasks"])
    assert all(item["pass_credit"] is False for item in first["tasks"])
    assert validate_execution_plan(first) == first


def test_source_validation_rejects_cycles_unknown_fields_and_declared_budget_escape() -> None:
    cyclic = _plan()
    cyclic["tasks"][2]["dependencies"] = ["deliver"]
    with pytest.raises(WeakModelExecutionError, match="acyclic"):
        decompose_high_level_plan(cyclic)

    promotion = _plan()
    promotion["tasks"][0]["pass_credit"] = True
    with pytest.raises(WeakModelExecutionError, match="unsupported fields"):
        decompose_high_level_plan(promotion)

    too_small = _plan()
    too_small["budget"] = _budget(max_executor_tasks=3)
    with pytest.raises(WeakModelExecutionError, match="max_executor_tasks"):
        decompose_high_level_plan(too_small)


def test_core_state_table_is_exact_and_failed_attempt_is_typed_blocked() -> None:
    assert TASK_STATE_TRANSITIONS == {
        "PLANNED": ("READY", "BLOCKED", "CANCELLED"),
        "READY": ("LEASED", "BLOCKED", "CANCELLED"),
        "LEASED": ("RUNNING", "READY", "BLOCKED", "CANCELLED"),
        "RUNNING": ("COMPLETED", "BLOCKED", "CANCELLED"),
        "BLOCKED": ("READY", "CANCELLED"),
        "COMPLETED": (),
        "CANCELLED": (),
    }
    plan = decompose_high_level_plan(_plan())
    failed = _receipt(plan, "source:execute", "FAILED")
    assert failed["status"] == "BLOCKED"
    assert failed["attempt_outcome"] == "FAILED"
    assert failed["block_reason"] == "executor-failed"
    review = review_executor_receipts(plan, [failed])
    assert review["resumable_task_ids"] == ["source:execute"]
    assert review["task_states"][0]["status"] == "BLOCKED"


def test_projection_transition_table_matches_normative_core_policy() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = json.loads((root / "core" / "policy-set.json").read_text("utf-8"))
    normative = {
        state: tuple(targets)
        for state, targets in policy["state_machines"]["task"].items()
    }
    assert TASK_STATE_TRANSITIONS == normative


def test_pause_resume_and_cancel_are_core_transitions() -> None:
    plan = decompose_high_level_plan(_plan())
    paused = create_control_record(
        plan,
        task_id="source:execute",
        sequence=1,
        after_attempt=0,
        action="PAUSE",
        decision=None,
        source_state="READY",
    )
    paused_review = review_executor_receipts(plan, [], controls=[paused])
    assert paused_review["task_states"][0]["status"] == "BLOCKED"
    assert paused_review["task_states"][0]["block_reason"] == "pause-requested"

    resumed = create_control_record(
        plan,
        task_id="source:execute",
        sequence=2,
        after_attempt=0,
        action="RESUME",
        decision=None,
        source_state="BLOCKED",
    )
    assert resume_execution_plan(plan, [], controls=[paused, resumed])["ready_task_ids"] == [
        "source:execute"
    ]

    cancelled = create_control_record(
        plan,
        task_id="source:execute",
        sequence=3,
        after_attempt=0,
        action="CANCEL",
        decision=None,
        source_state="READY",
    )
    review = review_executor_receipts(plan, [], controls=[paused, resumed, cancelled])
    states = {item["task_id"]: item["status"] for item in review["task_states"]}
    assert states["source:execute"] == "CANCELLED"
    assert states["communicate:execute"] == "CANCELLED"
    assert states["compute:execute"] == "CANCELLED"
    assert states["deliver:execute"] == "CANCELLED"


@pytest.mark.parametrize(
    ("decision", "expected"), [("APPROVED", "READY"), ("DECLINED", "CANCELLED")]
)
def test_owner_decision_is_resolvable_without_parallel_task_states(
    decision: str, expected: str
) -> None:
    source = _plan()
    source["tasks"] = [
        _task("publish", dependencies=["source"]),
        _task("source", owner=True),
    ]
    plan = decompose_high_level_plan(source)
    initial = review_executor_receipts(plan, [])
    assert initial["owner_decision_task_ids"] == ["source:execute"]
    assert initial["task_states"][0]["status"] == "BLOCKED"
    control = create_control_record(
        plan,
        task_id="source:execute",
        sequence=1,
        after_attempt=0,
        action="OWNER_DECISION",
        decision=decision,
        source_state="BLOCKED",
    )
    review = review_executor_receipts(plan, [], controls=[control])
    assert review["task_states"][0]["status"] == expected
    if decision == "DECLINED":
        assert review["task_states"][1]["status"] == "CANCELLED"


def test_receipts_bind_input_and_workflow_wide_parallel_ceiling_is_deterministic() -> None:
    source = _plan()
    source["budget"] = _budget(max_parallel_tasks=1)
    source["tasks"] = [_task("zeta"), _task("alpha")]
    plan = decompose_high_level_plan(source)
    review = review_executor_receipts(plan, [])
    assert review["ready_task_ids"] == ["alpha:execute"]
    assert review["deferred_task_ids"] == ["zeta:execute"]

    receipt = _receipt(plan, "alpha:execute", "COMPLETED")
    wrong = deepcopy(receipt)
    wrong["input_digest"] = "0" * 64
    with pytest.raises(WeakModelExecutionError, match="input_digest"):
        review_executor_receipts(plan, [wrong])


def test_review_preserves_actual_totals_and_stops_scheduling_at_budget() -> None:
    source = _plan()
    source["budget"] = _budget(
        max_workflow_seconds=1,
        max_workflow_output_bytes=20,
    )
    source["tasks"] = [_task("alpha"), _task("beta")]
    plan = decompose_high_level_plan(source)
    first = _receipt(plan, "alpha:execute", "COMPLETED")
    review = review_executor_receipts(plan, [first])
    assert review["workflow_elapsed_milliseconds"] == 20
    assert review["workflow_budget_elapsed_milliseconds"] == 20
    assert review["workflow_output_bytes"] == 16
    assert review["workflow_budget_output_bytes"] == 16

    blocked = _receipt(plan, "beta:execute", "FAILED")
    over_output = review_executor_receipts(plan, [first, blocked])
    assert over_output["workflow_output_bytes"] == 32
    assert over_output["workflow_budget_output_bytes"] == 20
    assert over_output["workflow_output_budget_exhausted"] is True
    assert over_output["resumable_task_ids"] == []
    assert over_output["deferred_task_ids"] == ["beta:execute"]
    assert over_output["workflow_state"] == "BLOCKED_FINAL"

    elapsed = deepcopy(blocked)
    elapsed["elapsed_milliseconds"] = 1500
    elapsed["budget_elapsed_milliseconds"] = 1500
    over_time = review_executor_receipts(plan, [elapsed])
    assert over_time["workflow_elapsed_milliseconds"] == 1500
    assert over_time["workflow_budget_elapsed_milliseconds"] == 1000
    assert over_time["workflow_time_budget_exhausted"] is True
    assert over_time["resumable_task_ids"] == []


def test_time_exhaustion_uses_actual_elapsed_not_capped_charge() -> None:
    source = _plan()
    source["budget"] = _budget(
        max_attempt_seconds=1,
        max_workflow_seconds=2,
    )
    source["tasks"] = [_task("alpha")]
    plan = decompose_high_level_plan(source)
    receipt = _receipt(plan, "alpha:execute", "FAILED")
    receipt["elapsed_milliseconds"] = 2500
    receipt["budget_elapsed_milliseconds"] = 1000
    review = review_executor_receipts(plan, [receipt])
    assert review["workflow_elapsed_milliseconds"] == 2500
    assert review["workflow_budget_elapsed_milliseconds"] == 1000
    assert review["workflow_time_budget_exhausted"] is True
    assert review["resumable_task_ids"] == []


def test_zero_output_budget_is_not_exhausted_by_zero_output() -> None:
    source = _plan()
    source["budget"] = _budget(
        max_task_output_bytes=0,
        max_workflow_output_bytes=0,
    )
    source["tasks"] = [_task("alpha")]
    plan = decompose_high_level_plan(source)
    initial = review_executor_receipts(plan, [])
    assert initial["workflow_output_budget_exhausted"] is False
    assert initial["ready_task_ids"] == ["alpha:execute"]
    receipt = create_executor_receipt(
        plan,
        task_id="alpha:execute",
        status="COMPLETED",
        attempt=1,
        input_digest=_card(plan, "alpha:execute")["instruction_digest"],
        output_digest=digest_value({"empty": True}),
        output_bytes=0,
        elapsed_milliseconds=0,
        observation="Empty output completed within the zero-byte budget.",
    )
    completed = review_executor_receipts(plan, [receipt])
    assert completed["workflow_output_bytes"] == 0
    assert completed["workflow_output_budget_exhausted"] is False
    assert completed["workflow_state"] == "COMPLETED"


def test_generic_resume_cannot_resolve_owner_decision() -> None:
    source = _plan()
    source["tasks"] = [_task("publish", owner=True)]
    plan = decompose_high_level_plan(source)
    invalid = create_control_record(
        plan,
        task_id="publish:execute",
        sequence=1,
        after_attempt=0,
        action="RESUME",
        decision=None,
        source_state="BLOCKED",
    )
    with pytest.raises(WeakModelExecutionError, match="OWNER_DECISION"):
        review_executor_receipts(plan, [], controls=[invalid])


def test_active_attempt_is_running_until_a_terminal_receipt_exists() -> None:
    source = _plan()
    source["tasks"] = [_task("alpha")]
    plan = decompose_high_level_plan(source)
    active = review_executor_receipts(
        plan, [], active_attempts={"alpha:execute": 1}
    )
    assert active["task_states"][0]["status"] == "RUNNING"
    assert active["task_states"][0]["attempts"] == 1
    assert active["ready_task_ids"] == []
    assert active["resumable_task_ids"] == []
    assert active["workflow_state"] == "ACTIVE"


@pytest.mark.parametrize(
    ("action", "outcome", "state", "reason"),
    [
        ("PAUSE", "PAUSED", "BLOCKED", "pause-requested"),
        ("CANCEL", "CANCELLED", "CANCELLED", None),
    ],
)
def test_running_control_and_matching_terminal_receipt_replay_coherently(
    action: str, outcome: str, state: str, reason: str | None
) -> None:
    source = _plan()
    source["tasks"] = [_task("alpha")]
    plan = decompose_high_level_plan(source)
    control = create_control_record(
        plan,
        task_id="alpha:execute",
        sequence=1,
        after_attempt=1,
        action=action,
        decision=None,
        source_state="RUNNING",
    )
    active = review_executor_receipts(
        plan,
        [],
        controls=[control],
        active_attempts={"alpha:execute": 1},
    )
    assert active["task_states"][0]["status"] == state
    assert active["resumable_task_ids"] == []
    expected_workflow_state = "ACTIVE" if action == "PAUSE" else "CANCELLED"
    assert active["workflow_state"] == expected_workflow_state
    receipt = _receipt(plan, "alpha:execute", outcome)
    terminal = review_executor_receipts(plan, [receipt], controls=[control])
    assert terminal["task_states"][0]["status"] == state
    assert terminal["task_states"][0]["block_reason"] == reason
