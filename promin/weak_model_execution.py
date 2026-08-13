"""Deterministic management records for arbitrary task dependency graphs.

The lifecycle view is a non-authoritative projection aligned with the Core
task-state vocabulary.  It neither mutates DomainState nor acquires a Lease.
This module also does not own an executor, operating-system isolation,
provider selection, or product credit.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import re
import unicodedata
from typing import Any

from .canonical import canonical_bytes, digest_value


class WeakModelExecutionError(ValueError):
    """Raised when a managed plan, receipt, or transition is inconsistent."""


HIGH_LEVEL_PLAN_SCHEMA = "promin.high-level-execution-plan.v1"
WEAK_MODEL_EXECUTION_PLAN_SCHEMA = "promin.weak-model-execution-plan.v1"
WEAK_MODEL_EXECUTOR_TASK_SCHEMA = "promin.weak-model-executor-task.v1"
WEAK_MODEL_EXECUTION_RECEIPT_SCHEMA = "promin.weak-model-execution-receipt.v1"
WEAK_MODEL_CONTROL_SCHEMA = "promin.weak-model-control.v1"
WEAK_MODEL_EXECUTION_REVIEW_SCHEMA = "promin.weak-model-execution-review.v1"
WEAK_MODEL_EXECUTION_RESUME_SCHEMA = "promin.weak-model-execution-resume.v1"

TASK_STATE_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "PLANNED": ("READY", "BLOCKED", "CANCELLED"),
    "READY": ("LEASED", "BLOCKED", "CANCELLED"),
    "LEASED": ("RUNNING", "READY", "BLOCKED", "CANCELLED"),
    "RUNNING": ("COMPLETED", "BLOCKED", "CANCELLED"),
    "BLOCKED": ("READY", "CANCELLED"),
    "COMPLETED": (),
    "CANCELLED": (),
}

_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_OUTCOMES = frozenset(
    {
        "COMPLETED",
        "FAILED",
        "BLOCKED",
        "PAUSED",
        "CANCELLED",
        "OWNER_DECISION_REQUIRED",
        "INTERRUPTED",
        "DEADLINE_EXCEEDED",
        "OUTPUT_BUDGET_EXCEEDED",
    }
)
_RESUMABLE_REASONS = frozenset(
    {
        "executor-failed",
        "executor-blocked",
        "executor-interrupted",
        "pause-requested",
        "deadline-exceeded",
        "output-budget-exceeded",
    }
)

_HIGH_LEVEL_PLAN_FIELDS = frozenset({"schema", "plan_id", "budget", "tasks"})
_MODERN_TASK_FIELDS = frozenset(
    {
        "task_id",
        "title",
        "objective",
        "dependencies",
        "task_mode",
        "resources",
        "acceptance_predicate",
        "requires_current_authorization",
        "requires_owner_decision",
    }
)
_LEGACY_TASK_FIELDS = frozenset(
    {
        "task_id",
        "title",
        "objective",
        "allowed_paths",
        "dependencies",
        "risk_class",
        "static_tool_ids",
        "acceptance_predicate",
    }
)
_RESOURCE_FIELDS = frozenset({"resource_type", "resource_id"})
_BUDGET_LIMITS = {
    "max_high_level_tasks": (1, 64),
    "max_executor_tasks": (1, 64),
    "max_dependencies_per_task": (0, 32),
    "max_resources_per_task": (0, 32),
    "max_task_instruction_bytes": (256, 16_384),
    "max_task_context_bytes": (0, 4_194_304),
    "max_task_output_bytes": (0, 1_048_576),
    "max_attempt_seconds": (1, 86_400),
    "max_attempts_per_task": (1, 20),
    "max_parallel_tasks": (1, 64),
    "max_workflow_seconds": (1, 2_592_000),
    "max_workflow_output_bytes": (0, 67_108_864),
}
_LEGACY_BUDGET_FIELDS = frozenset(
    {
        "max_high_level_tasks",
        "max_executor_tasks",
        "max_dependencies_per_task",
        "max_allowed_paths_per_task",
        "max_static_tools_per_task",
        "max_task_instruction_bytes",
        "max_task_output_bytes",
        "max_attempts_per_task",
        "max_parallel_tasks",
    }
)
_EXECUTION_PLAN_FIELDS = frozenset(
    {
        "schema",
        "record_type",
        "source_plan",
        "source_plan_digest",
        "budget",
        "tasks",
        "authority_effect",
        "authority_granted",
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
    }
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema",
        "record_type",
        "execution_plan_digest",
        "task_id",
        "task_digest",
        "attempt",
        "status",
        "attempt_outcome",
        "block_reason",
        "input_digest",
        "output_digest",
        "output_bytes",
        "elapsed_milliseconds",
        "budget_elapsed_milliseconds",
        "observation",
        "review_required",
        "resumable",
        "owner_decision_required",
        "authority_effect",
        "authority_granted",
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
    }
)
_CONTROL_FIELDS = frozenset(
    {
        "schema",
        "record_type",
        "execution_plan_digest",
        "task_id",
        "task_digest",
        "sequence",
        "after_attempt",
        "action",
        "decision",
        "source_state",
        "target_state",
        "block_reason",
        "authority_effect",
        "authority_granted",
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
    }
)


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise WeakModelExecutionError(f"{label} must be an object with string keys")
    return dict(value)


def _exact(value: Mapping[str, object], expected: frozenset[str], label: str) -> None:
    actual = frozenset(value)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    raise WeakModelExecutionError(
        f"{label} has unsupported fields (missing={missing}; unexpected={unexpected})"
    )


def _text(value: object, label: str, maximum_bytes: int, *, allow_empty: bool = False) -> str:
    if type(value) is not str or value != value.strip() or "\x00" in value:
        raise WeakModelExecutionError(f"{label} must be trimmed text")
    normalized = unicodedata.normalize("NFC", value)
    if not normalized and not allow_empty:
        raise WeakModelExecutionError(f"{label} must be non-empty")
    try:
        size = len(normalized.encode("utf-8", errors="strict"))
    except UnicodeError as exc:
        raise WeakModelExecutionError(f"{label} must be valid UTF-8 text") from exc
    if size > maximum_bytes:
        raise WeakModelExecutionError(f"{label} exceeds {maximum_bytes} UTF-8 bytes")
    return normalized


def _identifier(value: object, label: str) -> str:
    result = _text(value, label, 64)
    if _ID.fullmatch(result) is None:
        raise WeakModelExecutionError(f"{label} must be a lowercase hyphenated identifier")
    return result


def _digest(value: object, label: str) -> str:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise WeakModelExecutionError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise WeakModelExecutionError(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise WeakModelExecutionError(f"{label} must be a boolean")
    return value


def _collect(
    value: object,
    label: str,
    maximum_items: int,
) -> list[object]:
    if isinstance(value, (str, bytes, bytearray, Mapping)) or not isinstance(value, Iterable):
        raise WeakModelExecutionError(f"{label} must be an array")
    result: list[object] = []
    for item in value:
        if len(result) >= maximum_items:
            raise WeakModelExecutionError(f"{label} exceeds its declared budget")
        result.append(item)
    return result


def _identifiers(value: object, label: str, maximum_items: int) -> list[str]:
    result = [
        _identifier(item, f"{label}[{index}]")
        for index, item in enumerate(_collect(value, label, maximum_items))
    ]
    if len(result) != len(set(result)):
        raise WeakModelExecutionError(f"{label} must not contain duplicates")
    return sorted(result)


def _validate_budget(value: object) -> dict[str, int]:
    budget = _mapping(value, "budget")
    fields = frozenset(budget)
    if fields == frozenset(_BUDGET_LIMITS):
        return {
            name: _integer(budget[name], name, minimum, maximum)
            for name, (minimum, maximum) in _BUDGET_LIMITS.items()
        }
    if fields != _LEGACY_BUDGET_FIELDS:
        _exact(budget, frozenset(_BUDGET_LIMITS), "budget")
    legacy: dict[str, int] = {}
    legacy_limits = {
        "max_high_level_tasks": (1, 64),
        "max_executor_tasks": (1, 192),
        "max_dependencies_per_task": (0, 32),
        "max_allowed_paths_per_task": (0, 16),
        "max_static_tools_per_task": (0, 16),
        "max_task_instruction_bytes": (256, 16_384),
        "max_task_output_bytes": (0, 1_048_576),
        "max_attempts_per_task": (1, 20),
        "max_parallel_tasks": (1, 64),
    }
    for name, (minimum, maximum) in legacy_limits.items():
        legacy[name] = _integer(budget[name], name, minimum, maximum)
    task_count = legacy["max_high_level_tasks"]
    attempts = legacy["max_attempts_per_task"]
    output = legacy["max_task_output_bytes"]
    return {
        "max_high_level_tasks": task_count,
        "max_executor_tasks": min(64, legacy["max_executor_tasks"]),
        "max_dependencies_per_task": legacy["max_dependencies_per_task"],
        "max_resources_per_task": (
            legacy["max_allowed_paths_per_task"] + legacy["max_static_tools_per_task"]
        ),
        "max_task_instruction_bytes": legacy["max_task_instruction_bytes"],
        "max_task_context_bytes": min(4_194_304, legacy["max_task_instruction_bytes"] * 4),
        "max_task_output_bytes": output,
        "max_attempt_seconds": 300,
        "max_attempts_per_task": attempts,
        "max_parallel_tasks": legacy["max_parallel_tasks"],
        "max_workflow_seconds": min(2_592_000, 300 * task_count * attempts),
        "max_workflow_output_bytes": min(67_108_864, output * task_count * attempts),
    }


def _resource(value: object, label: str) -> dict[str, str]:
    item = _mapping(value, label)
    _exact(item, _RESOURCE_FIELDS, label)
    return {
        "resource_type": _identifier(item["resource_type"], f"{label}.resource_type"),
        "resource_id": _text(item["resource_id"], f"{label}.resource_id", 512),
    }


def _resources(value: object, maximum_items: int) -> list[dict[str, str]]:
    result = [
        _resource(item, f"resources[{index}]")
        for index, item in enumerate(_collect(value, "resources", maximum_items))
    ]
    keys = [(item["resource_type"], item["resource_id"]) for item in result]
    if len(keys) != len(set(keys)):
        raise WeakModelExecutionError("resources must not contain duplicates")
    return sorted(result, key=lambda item: (item["resource_type"], item["resource_id"]))


def _normalize_task(value: object, index: int, budget: Mapping[str, int]) -> dict[str, Any]:
    task = _mapping(value, f"tasks[{index}]")
    fields = frozenset(task)
    if fields == _MODERN_TASK_FIELDS:
        resources = _resources(task["resources"], budget["max_resources_per_task"])
        mode = _identifier(task["task_mode"], "task_mode")
        current = _boolean(
            task["requires_current_authorization"], "requires_current_authorization"
        )
        owner = _boolean(task["requires_owner_decision"], "requires_owner_decision")
    elif fields == _LEGACY_TASK_FIELDS:
        paths = _collect(
            task["allowed_paths"],
            "allowed_paths",
            budget["max_resources_per_task"],
        )
        remaining = budget["max_resources_per_task"] - len(paths)
        tools = _collect(task["static_tool_ids"], "static_tool_ids", remaining)
        resources = _resources(
            [
                *(
                    {"resource_type": "filesystem-path", "resource_id": path}
                    for path in paths
                ),
                *({"resource_type": "tool", "resource_id": tool} for tool in tools),
            ],
            budget["max_resources_per_task"],
        )
        risk = _text(task["risk_class"], "risk_class", 64)
        if risk not in {"read-only", "reversible-local", "owner-only"}:
            raise WeakModelExecutionError("legacy risk_class is invalid")
        mode = "managed"
        current = risk == "reversible-local"
        owner = risk == "owner-only"
    else:
        _exact(task, _MODERN_TASK_FIELDS, f"tasks[{index}]")
        raise AssertionError("unreachable")
    dependencies = _identifiers(
        task["dependencies"], "dependencies", budget["max_dependencies_per_task"]
    )
    return {
        "task_id": _identifier(task["task_id"], "task_id"),
        "title": _text(task["title"], "title", 256),
        "objective": _text(task["objective"], "objective", 8_192),
        "dependencies": dependencies,
        "task_mode": mode,
        "resources": resources,
        "acceptance_predicate": _text(
            task["acceptance_predicate"], "acceptance_predicate", 4_096
        ),
        "requires_current_authorization": current,
        "requires_owner_decision": owner,
    }


def _topological_task_ids(tasks: Sequence[Mapping[str, Any]]) -> list[str]:
    remaining = {task["task_id"]: set(task["dependencies"]) for task in tasks}
    ordered: list[str] = []
    while remaining:
        ready = sorted(key for key, dependencies in remaining.items() if not dependencies)
        if not ready:
            raise WeakModelExecutionError("high-level task dependencies must be acyclic")
        ordered.extend(ready)
        for task_id in ready:
            del remaining[task_id]
        for dependencies in remaining.values():
            dependencies.difference_update(ready)
    return ordered


def validate_high_level_plan(value: Mapping[str, object]) -> dict[str, Any]:
    """Normalize an arbitrary, bounded source DAG without narrowing its objectives."""

    plan = _mapping(value, "high-level plan")
    _exact(plan, _HIGH_LEVEL_PLAN_FIELDS, "high-level plan")
    if plan["schema"] != HIGH_LEVEL_PLAN_SCHEMA:
        raise WeakModelExecutionError("high-level plan schema is invalid")
    budget = _validate_budget(plan["budget"])
    raw_tasks = _collect(plan["tasks"], "tasks", budget["max_high_level_tasks"])
    if not raw_tasks:
        raise WeakModelExecutionError("tasks must be non-empty")
    tasks = [_normalize_task(item, index, budget) for index, item in enumerate(raw_tasks)]
    if len(tasks) > budget["max_executor_tasks"]:
        raise WeakModelExecutionError("tasks exceed max_executor_tasks")
    ids = [task["task_id"] for task in tasks]
    if len(ids) != len(set(ids)):
        raise WeakModelExecutionError("task_id values must be unique")
    id_set = set(ids)
    for task in tasks:
        unknown = sorted(set(task["dependencies"]) - id_set)
        if unknown:
            raise WeakModelExecutionError(
                f"task {task['task_id']} has unknown dependencies: {unknown}"
            )
        if task["task_id"] in task["dependencies"]:
            raise WeakModelExecutionError("a task may not depend on itself")
    tasks.sort(key=lambda item: item["task_id"])
    _topological_task_ids(tasks)
    return {
        "schema": HIGH_LEVEL_PLAN_SCHEMA,
        "plan_id": _identifier(plan["plan_id"], "plan_id"),
        "budget": budget,
        "tasks": tasks,
    }


def _instruction(task: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "phase": "managed-execution",
        "phases": ["preflight", "execute", "review"],
        "objective": task["objective"],
        "acceptance_predicate": task["acceptance_predicate"],
        "task_mode": task["task_mode"],
        "resources": list(task["resources"]),
        "limits": [
            "Honor the declared time, context, output, attempt, and workflow budgets.",
            "Report a typed blocked outcome when work cannot continue.",
            "Do not infer authority, acceptance, or pass credit.",
        ],
    }


def decompose_high_level_plan(value: Mapping[str, object]) -> dict[str, Any]:
    """Compile one managed card per source task; decomposition remains optional."""

    source = validate_high_level_plan(value)
    by_id = {task["task_id"]: task for task in source["tasks"]}
    cards: list[dict[str, Any]] = []
    for parent_id in _topological_task_ids(source["tasks"]):
        task = by_id[parent_id]
        instruction = _instruction(task)
        instruction_bytes = len(canonical_bytes(instruction))
        if instruction_bytes > source["budget"]["max_task_instruction_bytes"]:
            raise WeakModelExecutionError(
                f"task {parent_id} instruction exceeds max_task_instruction_bytes"
            )
        card_id = f"{parent_id}:execute"
        cards.append(
            {
                "schema": WEAK_MODEL_EXECUTOR_TASK_SCHEMA,
                "record_type": "WeakModelExecutorTask",
                "task_id": card_id,
                "parent_task_id": parent_id,
                "kind": "owner-decision" if task["requires_owner_decision"] else "managed-task",
                "status": "PLANNED",
                "depends_on": [f"{item}:execute" for item in task["dependencies"]],
                "title": task["title"],
                "instruction": instruction,
                "instruction_digest": digest_value(instruction),
                "instruction_bytes": instruction_bytes,
                "resources": list(task["resources"]),
                "operation_mode": task["task_mode"],
                "max_context_bytes": source["budget"]["max_task_context_bytes"],
                "max_output_bytes": source["budget"]["max_task_output_bytes"],
                "max_attempt_seconds": source["budget"]["max_attempt_seconds"],
                "max_attempts": source["budget"]["max_attempts_per_task"],
                "requires_current_authorization": task["requires_current_authorization"],
                "requires_owner_decision": task["requires_owner_decision"],
                "authority_effect": "none",
                "authority_granted": False,
                "pass_credit": False,
                "acceptance_pass": False,
                "product_acceptance_pass": False,
            }
        )
    return {
        "schema": WEAK_MODEL_EXECUTION_PLAN_SCHEMA,
        "record_type": "WeakModelExecutionPlan",
        "source_plan": source,
        "source_plan_digest": digest_value(source),
        "budget": dict(source["budget"]),
        "tasks": cards,
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }


def validate_execution_plan(value: Mapping[str, object]) -> dict[str, Any]:
    plan = _mapping(value, "execution plan")
    _exact(plan, _EXECUTION_PLAN_FIELDS, "execution plan")
    if plan["schema"] != WEAK_MODEL_EXECUTION_PLAN_SCHEMA:
        raise WeakModelExecutionError("execution plan schema is invalid")
    if plan["record_type"] != "WeakModelExecutionPlan":
        raise WeakModelExecutionError("execution plan record_type is invalid")
    _false_claims(plan, "execution plan")
    source = validate_high_level_plan(_mapping(plan["source_plan"], "source_plan"))
    if plan["source_plan_digest"] != digest_value(source):
        raise WeakModelExecutionError("execution plan source_plan_digest does not bind source_plan")
    expected = decompose_high_level_plan(source)
    try:
        if canonical_bytes(plan) != canonical_bytes(expected):
            raise WeakModelExecutionError("execution plan differs from deterministic compilation")
    except ValueError as exc:
        raise WeakModelExecutionError("execution plan must be canonical JSON") from exc
    return expected


def _false_claims(value: Mapping[str, Any], label: str) -> None:
    if value.get("authority_effect") != "none":
        raise WeakModelExecutionError(f"{label} authority_effect must be none")
    for field in (
        "authority_granted",
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
    ):
        if value.get(field) is not False:
            raise WeakModelExecutionError(f"{label} {field} must be false")


def _task(plan: Mapping[str, Any], task_id: str) -> dict[str, Any]:
    for task in plan["tasks"]:
        if task["task_id"] == task_id:
            return task
    raise WeakModelExecutionError(f"unknown executor task_id: {task_id}")


def _outcome_state(outcome: str, block_reason: str | None) -> tuple[str, str | None]:
    if outcome == "COMPLETED":
        return "COMPLETED", None
    if outcome == "CANCELLED":
        return "CANCELLED", None
    defaults = {
        "FAILED": "executor-failed",
        "BLOCKED": "executor-blocked",
        "PAUSED": "pause-requested",
        "OWNER_DECISION_REQUIRED": "owner-decision-required",
        "INTERRUPTED": "executor-interrupted",
        "DEADLINE_EXCEEDED": "deadline-exceeded",
        "OUTPUT_BUDGET_EXCEEDED": "output-budget-exceeded",
    }
    return "BLOCKED", block_reason or defaults[outcome]


def _normalize_receipt(plan: Mapping[str, Any], value: Mapping[str, object]) -> dict[str, Any]:
    receipt = _mapping(value, "executor receipt")
    _exact(receipt, _RECEIPT_FIELDS, "executor receipt")
    if receipt["schema"] != WEAK_MODEL_EXECUTION_RECEIPT_SCHEMA:
        raise WeakModelExecutionError("executor receipt schema is invalid")
    if receipt["record_type"] != "WeakModelExecutorReceipt":
        raise WeakModelExecutionError("executor receipt record_type is invalid")
    if receipt["execution_plan_digest"] != digest_value(plan):
        raise WeakModelExecutionError("executor receipt does not bind execution plan")
    task_id = _text(receipt["task_id"], "task_id", 96)
    task = _task(plan, task_id)
    if receipt["task_digest"] != digest_value(task):
        raise WeakModelExecutionError("executor receipt does not bind executor task")
    attempt = _integer(receipt["attempt"], "attempt", 1, task["max_attempts"])
    outcome = _text(receipt["attempt_outcome"], "attempt_outcome", 64)
    if outcome not in _OUTCOMES:
        raise WeakModelExecutionError("executor receipt attempt_outcome is invalid")
    raw_reason = receipt["block_reason"]
    reason = None if raw_reason is None else _text(raw_reason, "block_reason", 128)
    state, expected_reason = _outcome_state(outcome, reason)
    if receipt["status"] != state or reason != expected_reason:
        raise WeakModelExecutionError("executor receipt state or block_reason is inconsistent")
    if receipt["input_digest"] != task["instruction_digest"]:
        raise WeakModelExecutionError("executor receipt input_digest does not bind instruction")
    output_bytes = _integer(
        receipt["output_bytes"], "output_bytes", 0, task["max_output_bytes"]
    )
    elapsed = _integer(
        receipt["elapsed_milliseconds"],
        "elapsed_milliseconds",
        0,
        (1 << 63) - 1,
    )
    budget_elapsed = _integer(
        receipt["budget_elapsed_milliseconds"],
        "budget_elapsed_milliseconds",
        0,
        task["max_attempt_seconds"] * 1000,
    )
    if budget_elapsed != min(elapsed, task["max_attempt_seconds"] * 1000):
        raise WeakModelExecutionError(
            "executor receipt budget_elapsed_milliseconds is inconsistent"
        )
    resumable = state == "BLOCKED" and reason in _RESUMABLE_REASONS and attempt < task["max_attempts"]
    owner_required = reason == "owner-decision-required"
    if receipt["review_required"] is not True:
        raise WeakModelExecutionError("executor receipt review_required must be true")
    if receipt["resumable"] is not resumable:
        raise WeakModelExecutionError("executor receipt resumable is inconsistent")
    if receipt["owner_decision_required"] is not owner_required:
        raise WeakModelExecutionError("executor receipt owner_decision_required is inconsistent")
    _false_claims(receipt, "executor receipt")
    return {
        **receipt,
        "task_id": task_id,
        "attempt": attempt,
        "status": state,
        "attempt_outcome": outcome,
        "block_reason": reason,
        "input_digest": _digest(receipt["input_digest"], "input_digest"),
        "output_digest": _digest(receipt["output_digest"], "output_digest"),
        "output_bytes": output_bytes,
        "elapsed_milliseconds": elapsed,
        "budget_elapsed_milliseconds": budget_elapsed,
        "observation": _text(receipt["observation"], "observation", 512),
        "review_required": True,
        "resumable": resumable,
        "owner_decision_required": owner_required,
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }


def _validate_workflow_totals(
    plan: Mapping[str, Any], receipts: Sequence[Mapping[str, Any]]
) -> tuple[int, int, int, int, bool, bool]:
    actual_elapsed_milliseconds = sum(
        item["elapsed_milliseconds"] for item in receipts
    )
    charged_elapsed_before_workflow_cap = sum(
        item["budget_elapsed_milliseconds"] for item in receipts
    )
    output_bytes = sum(item["output_bytes"] for item in receipts)
    elapsed_limit = plan["budget"]["max_workflow_seconds"] * 1000
    output_limit = plan["budget"]["max_workflow_output_bytes"]
    return (
        actual_elapsed_milliseconds,
        min(charged_elapsed_before_workflow_cap, elapsed_limit),
        output_bytes,
        min(output_bytes, output_limit),
        actual_elapsed_milliseconds >= elapsed_limit,
        output_bytes > output_limit,
    )


def create_executor_receipt(
    execution_plan: Mapping[str, object],
    *,
    task_id: str,
    status: str,
    attempt: int,
    input_digest: str,
    output_digest: str,
    output_bytes: int,
    observation: str,
    block_reason: str | None = None,
    elapsed_milliseconds: int = 0,
) -> dict[str, Any]:
    """Create one bounded attempt observation; ``status`` is its outcome."""

    plan = validate_execution_plan(execution_plan)
    task = _task(plan, _text(task_id, "task_id", 96))
    outcome = _text(status, "status", 64)
    if outcome not in _OUTCOMES:
        raise WeakModelExecutionError("executor receipt outcome is invalid")
    state, reason = _outcome_state(outcome, block_reason)
    candidate = {
        "schema": WEAK_MODEL_EXECUTION_RECEIPT_SCHEMA,
        "record_type": "WeakModelExecutorReceipt",
        "execution_plan_digest": digest_value(plan),
        "task_id": task["task_id"],
        "task_digest": digest_value(task),
        "attempt": attempt,
        "status": state,
        "attempt_outcome": outcome,
        "block_reason": reason,
        "input_digest": input_digest,
        "output_digest": output_digest,
        "output_bytes": output_bytes,
        "elapsed_milliseconds": elapsed_milliseconds,
        "budget_elapsed_milliseconds": min(
            elapsed_milliseconds, task["max_attempt_seconds"] * 1000
        ),
        "observation": observation,
        "review_required": True,
        "resumable": state == "BLOCKED" and reason in _RESUMABLE_REASONS and attempt < task["max_attempts"],
        "owner_decision_required": reason == "owner-decision-required",
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }
    return _normalize_receipt(plan, candidate)


def validate_executor_receipt(
    execution_plan: Mapping[str, object], receipt: Mapping[str, object]
) -> dict[str, Any]:
    return _normalize_receipt(validate_execution_plan(execution_plan), receipt)


def _control_target(action: str, decision: str | None, source: str) -> tuple[str, str | None]:
    if action == "PAUSE" and source in {"READY", "RUNNING"}:
        return "BLOCKED", "pause-requested"
    if action == "RESUME" and source == "BLOCKED":
        return "READY", None
    if action == "CANCEL" and source not in {"COMPLETED", "CANCELLED"}:
        return "CANCELLED", None
    if action == "OWNER_DECISION" and source == "BLOCKED":
        if decision == "APPROVED":
            return "READY", None
        if decision == "DECLINED":
            return "CANCELLED", None
    raise WeakModelExecutionError(
        "control action is not valid from the current projected task state"
    )


def create_control_record(
    execution_plan: Mapping[str, object],
    *,
    task_id: str,
    sequence: int,
    after_attempt: int,
    action: str,
    decision: str | None,
    source_state: str,
) -> dict[str, Any]:
    plan = validate_execution_plan(execution_plan)
    task = _task(plan, _text(task_id, "task_id", 96))
    normalized_action = _text(action, "action", 32)
    normalized_decision = None if decision is None else _text(decision, "decision", 32)
    source = _text(source_state, "source_state", 32)
    target, reason = _control_target(normalized_action, normalized_decision, source)
    candidate = {
        "schema": WEAK_MODEL_CONTROL_SCHEMA,
        "record_type": "WeakModelControl",
        "execution_plan_digest": digest_value(plan),
        "task_id": task["task_id"],
        "task_digest": digest_value(task),
        "sequence": sequence,
        "after_attempt": after_attempt,
        "action": normalized_action,
        "decision": normalized_decision,
        "source_state": source,
        "target_state": target,
        "block_reason": reason,
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }
    return _normalize_control(plan, candidate)


def _normalize_control(plan: Mapping[str, Any], value: Mapping[str, object]) -> dict[str, Any]:
    control = _mapping(value, "control record")
    _exact(control, _CONTROL_FIELDS, "control record")
    if control["schema"] != WEAK_MODEL_CONTROL_SCHEMA or control["record_type"] != "WeakModelControl":
        raise WeakModelExecutionError("control record identity is invalid")
    if control["execution_plan_digest"] != digest_value(plan):
        raise WeakModelExecutionError("control record does not bind execution plan")
    task_id = _text(control["task_id"], "task_id", 96)
    task = _task(plan, task_id)
    if control["task_digest"] != digest_value(task):
        raise WeakModelExecutionError("control record does not bind executor task")
    sequence = _integer(control["sequence"], "sequence", 1, 10_000)
    after_attempt = _integer(control["after_attempt"], "after_attempt", 0, task["max_attempts"])
    action = _text(control["action"], "action", 32)
    decision = None if control["decision"] is None else _text(control["decision"], "decision", 32)
    source = _text(control["source_state"], "source_state", 32)
    target, reason = _control_target(action, decision, source)
    if control["target_state"] != target or control["block_reason"] != reason:
        raise WeakModelExecutionError("control target is inconsistent")
    if target not in TASK_STATE_TRANSITIONS.get(source, ()):
        raise WeakModelExecutionError(
            "control transition is not Core-compatible"
        )
    _false_claims(control, "control record")
    return {**control, "sequence": sequence, "after_attempt": after_attempt}


def validate_control_record(
    execution_plan: Mapping[str, object], control: Mapping[str, object]
) -> dict[str, Any]:
    return _normalize_control(validate_execution_plan(execution_plan), control)


def _initial_state(
    task: Mapping[str, Any], states: Mapping[str, Mapping[str, Any]]
) -> tuple[str, str | None]:
    dependency_states = [states[item]["status"] for item in task["depends_on"]]
    if any(state == "CANCELLED" for state in dependency_states):
        return "CANCELLED", "dependency-cancelled"
    if not all(state == "COMPLETED" for state in dependency_states):
        return "PLANNED", "dependencies-pending"
    if task["requires_owner_decision"]:
        return "BLOCKED", "owner-decision-required"
    return "READY", None


def review_executor_receipts(
    execution_plan: Mapping[str, object],
    receipts: Sequence[Mapping[str, object]] | Iterable[Mapping[str, object]],
    *,
    controls: Sequence[Mapping[str, object]] | Iterable[Mapping[str, object]] = (),
    active_attempts: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Replay attempts and controls into a non-authoritative lifecycle view."""

    plan = validate_execution_plan(execution_plan)
    receipt_limit = len(plan["tasks"]) * plan["budget"]["max_attempts_per_task"]
    normalized_receipts = [
        _normalize_receipt(plan, item)
        for item in _collect(receipts, "receipts", receipt_limit)
    ]
    control_limit = len(plan["tasks"]) * (plan["budget"]["max_attempts_per_task"] + 2)
    normalized_controls = [
        _normalize_control(plan, item)
        for item in _collect(controls, "controls", control_limit)
    ]
    normalized_controls.sort(key=lambda item: item["sequence"])
    if [item["sequence"] for item in normalized_controls] != list(
        range(1, len(normalized_controls) + 1)
    ):
        raise WeakModelExecutionError("control sequence must be contiguous")
    (
        elapsed_milliseconds,
        budget_elapsed_milliseconds,
        output_bytes,
        budget_output_bytes,
        time_budget_exhausted,
        output_budget_exhausted,
    ) = _validate_workflow_totals(plan, normalized_receipts)
    receipts_by_task: dict[str, list[dict[str, Any]]] = {item["task_id"]: [] for item in plan["tasks"]}
    for receipt in normalized_receipts:
        receipts_by_task[receipt["task_id"]].append(receipt)
    controls_by_task: dict[str, list[dict[str, Any]]] = {item["task_id"]: [] for item in plan["tasks"]}
    for control in normalized_controls:
        controls_by_task[control["task_id"]].append(control)
    active = {} if active_attempts is None else dict(active_attempts)
    if any(type(key) is not str or type(value) is not int for key, value in active.items()):
        raise WeakModelExecutionError("active_attempts must map task IDs to attempt numbers")
    if set(active) - {item["task_id"] for item in plan["tasks"]}:
        raise WeakModelExecutionError("active_attempts contains an unknown task")

    states: dict[str, dict[str, Any]] = {}
    for task in plan["tasks"]:
        task_id = task["task_id"]
        state, reason = _initial_state(task, states)
        task_receipts = sorted(receipts_by_task[task_id], key=lambda item: item["attempt"])
        if [item["attempt"] for item in task_receipts] != list(range(1, len(task_receipts) + 1)):
            raise WeakModelExecutionError(f"task {task_id} attempt sequence is not contiguous")
        task_controls = controls_by_task[task_id]
        control_index = 0

        def apply_controls(after_attempt: int) -> tuple[str, str | None, int]:
            nonlocal state, reason, control_index
            while control_index < len(task_controls) and task_controls[control_index]["after_attempt"] == after_attempt:
                control = task_controls[control_index]
                if control["source_state"] != state:
                    raise WeakModelExecutionError("control source_state differs from replayed state")
                if control["action"] == "RESUME" and reason == "owner-decision-required":
                    raise WeakModelExecutionError(
                        "owner-decision-required can only be resolved by OWNER_DECISION"
                    )
                if control["action"] == "OWNER_DECISION" and reason != "owner-decision-required":
                    raise WeakModelExecutionError("owner decision is not pending for this task")
                state = control["target_state"]
                reason = control["block_reason"]
                control_index += 1
            return state, reason, control_index

        apply_controls(0)
        for receipt in task_receipts:
            if state != "READY":
                raise WeakModelExecutionError(
                    f"task {task_id} attempt begins from {state}, not READY"
                )
            # The STARTED record projects READY -> LEASED -> RUNNING without
            # claiming DomainState mutation or a real Lease acquisition.
            state = "RUNNING"
            reason = None
            active_control_applied = False
            if (
                control_index < len(task_controls)
                and task_controls[control_index]["after_attempt"]
                == receipt["attempt"]
                and task_controls[control_index]["source_state"] == "RUNNING"
            ):
                control = task_controls[control_index]
                state = control["target_state"]
                reason = control["block_reason"]
                control_index += 1
                active_control_applied = True
            if active_control_applied:
                if (
                    receipt["status"] != state
                    or receipt["block_reason"] != reason
                ):
                    raise WeakModelExecutionError(
                        "terminal receipt does not honor the active control"
                    )
            else:
                state = receipt["status"]
                reason = receipt["block_reason"]
            apply_controls(receipt["attempt"])
        active_attempt = active.get(task_id)
        if active_attempt is not None:
            if active_attempt != len(task_receipts) + 1 or state != "READY":
                raise WeakModelExecutionError(
                    f"task {task_id} active attempt is not the next READY attempt"
                )
            if active_attempt > task["max_attempts"]:
                raise WeakModelExecutionError(
                    f"task {task_id} active attempt exceeds its attempt budget"
                )
            state = "RUNNING"
            reason = None
            apply_controls(active_attempt)
        if control_index != len(task_controls):
            raise WeakModelExecutionError("control after_attempt exceeds recorded attempts")
        states[task_id] = {
            "status": state,
            "block_reason": reason,
            "attempts": len(task_receipts) + (1 if active_attempt is not None else 0),
        }

    eligible: list[tuple[str, str]] = []
    owner_ids: list[str] = []
    task_states: list[dict[str, Any]] = []
    for task in plan["tasks"]:
        state = states[task["task_id"]]
        resumable = (
            state["status"] == "BLOCKED"
            and state["block_reason"] in _RESUMABLE_REASONS
            and state["attempts"] < task["max_attempts"]
            and task["task_id"] not in active
        )
        owner_required = state["block_reason"] == "owner-decision-required"
        if state["status"] == "READY":
            eligible.append((task["task_id"], "ready"))
        elif resumable:
            eligible.append((task["task_id"], "resumable"))
        if owner_required:
            owner_ids.append(task["task_id"])
        task_states.append(
            {
                "task_id": task["task_id"],
                "kind": task["kind"],
                "status": state["status"],
                "block_reason": state["block_reason"],
                "attempts": state["attempts"],
                "review_required": True,
                "resumable": resumable,
                "owner_decision_required": owner_required,
            }
        )
    budget_exhausted = time_budget_exhausted or output_budget_exhausted
    scheduled = (
        []
        if budget_exhausted
        else eligible[: plan["budget"]["max_parallel_tasks"]]
    )
    ready = [task_id for task_id, category in scheduled if category == "ready"]
    resumable = [task_id for task_id, category in scheduled if category == "resumable"]
    deferred = (
        [task_id for task_id, _ in eligible]
        if budget_exhausted
        else [
            task_id
            for task_id, _ in eligible[plan["budget"]["max_parallel_tasks"] :]
        ]
    )
    statuses = [item["status"] for item in task_states]
    if statuses and all(status == "COMPLETED" for status in statuses):
        workflow_state = "COMPLETED"
    elif statuses and all(
        status in {"COMPLETED", "CANCELLED"} for status in statuses
    ):
        workflow_state = "CANCELLED"
    elif (
        ready
        or resumable
        or active
        or any(status == "RUNNING" for status in statuses)
    ):
        workflow_state = "ACTIVE"
    elif owner_ids:
        workflow_state = "OWNER_DECISION_REQUIRED"
    else:
        workflow_state = "BLOCKED_FINAL"
    return {
        "schema": WEAK_MODEL_EXECUTION_REVIEW_SCHEMA,
        "record_type": "WeakModelExecutionReview",
        "execution_plan_digest": digest_value(plan),
        "receipt_set_digest": digest_value(
            {
                "receipts": normalized_receipts,
                "controls": normalized_controls,
                "active_attempts": dict(sorted(active.items())),
            }
        ),
        "workflow_elapsed_milliseconds": elapsed_milliseconds,
        "workflow_budget_elapsed_milliseconds": budget_elapsed_milliseconds,
        "workflow_output_bytes": output_bytes,
        "workflow_budget_output_bytes": budget_output_bytes,
        "workflow_time_budget_exhausted": time_budget_exhausted,
        "workflow_output_budget_exhausted": output_budget_exhausted,
        "workflow_state": workflow_state,
        "review_status": "REVIEW_REQUIRED",
        "task_states": task_states,
        "ready_task_ids": ready,
        "resumable_task_ids": resumable,
        "deferred_task_ids": deferred,
        "owner_decision_task_ids": owner_ids,
        "all_tasks_completed": all(item["status"] == "COMPLETED" for item in task_states),
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }


def resume_execution_plan(
    execution_plan: Mapping[str, object],
    receipts: Sequence[Mapping[str, object]] | Iterable[Mapping[str, object]],
    *,
    controls: Sequence[Mapping[str, object]] | Iterable[Mapping[str, object]] = (),
    active_attempts: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    plan = validate_execution_plan(execution_plan)
    review = review_executor_receipts(
        plan, receipts, controls=controls, active_attempts=active_attempts
    )
    return {
        "schema": WEAK_MODEL_EXECUTION_RESUME_SCHEMA,
        "record_type": "WeakModelExecutionResume",
        "execution_plan_digest": digest_value(plan),
        "review_digest": digest_value(review),
        "ready_task_ids": list(review["ready_task_ids"]),
        "resumable_task_ids": list(review["resumable_task_ids"]),
        "deferred_task_ids": list(review["deferred_task_ids"]),
        "owner_decision_task_ids": list(review["owner_decision_task_ids"]),
        "workflow_elapsed_milliseconds": review[
            "workflow_elapsed_milliseconds"
        ],
        "workflow_budget_elapsed_milliseconds": review[
            "workflow_budget_elapsed_milliseconds"
        ],
        "workflow_output_bytes": review["workflow_output_bytes"],
        "workflow_budget_output_bytes": review[
            "workflow_budget_output_bytes"
        ],
        "workflow_time_budget_exhausted": review[
            "workflow_time_budget_exhausted"
        ],
        "workflow_output_budget_exhausted": review[
            "workflow_output_budget_exhausted"
        ],
        "workflow_state": review["workflow_state"],
        "review_required": True,
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }


__all__ = [
    "HIGH_LEVEL_PLAN_SCHEMA",
    "TASK_STATE_TRANSITIONS",
    "WEAK_MODEL_CONTROL_SCHEMA",
    "WEAK_MODEL_EXECUTION_PLAN_SCHEMA",
    "WEAK_MODEL_EXECUTION_RECEIPT_SCHEMA",
    "WEAK_MODEL_EXECUTION_REVIEW_SCHEMA",
    "WEAK_MODEL_EXECUTION_RESUME_SCHEMA",
    "WEAK_MODEL_EXECUTOR_TASK_SCHEMA",
    "WeakModelExecutionError",
    "create_control_record",
    "create_executor_receipt",
    "decompose_high_level_plan",
    "resume_execution_plan",
    "review_executor_receipts",
    "validate_control_record",
    "validate_execution_plan",
    "validate_executor_receipt",
    "validate_high_level_plan",
]
