"""Deterministic, bounded task decomposition for constrained local hosts.

The module is deliberately declarative.  It turns a small high-level DAG into
tool-first executor cards and binds observations to those cards, but it does
not invoke a tool, choose an action, grant authority, or promote a result.  A
12B planning cap is a decomposition budget, not a statement that a particular
model, host, or agent has been authorized or has produced correct work.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import re
import unicodedata
from typing import Any

from .canonical import canonical_bytes, digest_value


class WeakModelExecutionError(ValueError):
    """Raised when a bounded execution plan or its receipts are unsafe."""


HIGH_LEVEL_PLAN_SCHEMA = "promin.high-level-execution-plan.v1"
WEAK_MODEL_EXECUTION_PLAN_SCHEMA = "promin.weak-model-execution-plan.v1"
WEAK_MODEL_EXECUTOR_TASK_SCHEMA = "promin.weak-model-executor-task.v1"
WEAK_MODEL_EXECUTION_RECEIPT_SCHEMA = "promin.weak-model-execution-receipt.v1"
WEAK_MODEL_EXECUTION_REVIEW_SCHEMA = "promin.weak-model-execution-review.v1"
WEAK_MODEL_EXECUTION_RESUME_SCHEMA = "promin.weak-model-execution-resume.v1"

PLANNING_MODEL_CAP_BILLIONS = 12

_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_RISK_CLASSES = frozenset({"read-only", "reversible-local", "owner-only"})
_RECEIPT_STATUSES = frozenset(
    {"COMPLETED", "FAILED", "BLOCKED", "OWNER_DECISION_REQUIRED"}
)

_HIGH_LEVEL_PLAN_FIELDS = frozenset({"schema", "plan_id", "budget", "tasks"})
_HIGH_LEVEL_TASK_FIELDS = frozenset(
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
_BUDGET_LIMITS = {
    "max_high_level_tasks": (1, 64),
    "max_executor_tasks": (1, 192),
    "max_dependencies_per_task": (0, 32),
    "max_allowed_paths_per_task": (1, 16),
    "max_static_tools_per_task": (1, 16),
    "max_task_instruction_bytes": (256, 8_192),
    "max_task_output_bytes": (256, 65_536),
    "max_attempts_per_task": (1, 5),
    "max_parallel_tasks": (1, 64),
}
_EXECUTION_PLAN_FIELDS = frozenset(
    {
        "schema",
        "record_type",
        "planning_model_cap_billions",
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
        "input_digest",
        "output_digest",
        "output_bytes",
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


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise WeakModelExecutionError(f"{label} must be an object with string keys")
    return dict(value)


def _exact_fields(value: Mapping[str, object], expected: frozenset[str], label: str) -> None:
    actual = frozenset(value)
    if actual == expected:
        return
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    details: list[str] = []
    if missing:
        details.append(f"missing={missing}")
    if unexpected:
        details.append(f"unexpected={unexpected}")
    raise WeakModelExecutionError(f"{label} has unsupported fields ({'; '.join(details)})")


def _text(value: object, label: str, maximum_bytes: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or "\x00" in value:
        raise WeakModelExecutionError(f"{label} must be a non-empty trimmed string")
    normalized = unicodedata.normalize("NFC", value)
    try:
        size = len(normalized.encode("utf-8", errors="strict"))
    except UnicodeError as exc:
        raise WeakModelExecutionError(f"{label} must be valid UTF-8 text") from exc
    if size > maximum_bytes:
        raise WeakModelExecutionError(f"{label} exceeds {maximum_bytes} UTF-8 bytes")
    return normalized


def _identifier(value: object, label: str) -> str:
    normalized = _text(value, label, 64)
    if _ID.fullmatch(normalized) is None:
        raise WeakModelExecutionError(f"{label} must be a lowercase hyphenated identifier")
    return normalized


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise WeakModelExecutionError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise WeakModelExecutionError(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _list(value: object, label: str) -> list[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise WeakModelExecutionError(f"{label} must be an array")
    return list(value)


def _safe_path(value: object, label: str) -> str:
    path = _text(value, label, 256)
    if "\\" in path or path.startswith("/") or ":" in path:
        raise WeakModelExecutionError(f"{label} must be a safe relative path")
    parts = path.split("/")
    if (
        not parts
        or any(part in {"", ".", ".."} for part in parts)
        or all(set(part) <= {"*", "?", "[", "]", "!"} for part in parts)
    ):
        raise WeakModelExecutionError(f"{label} must be a safe relative path")
    return path


def _unique_text_list(
    value: object,
    label: str,
    *,
    maximum_items: int,
    normalizer: Any,
    allow_empty: bool = False,
) -> list[str]:
    items = _list(value, label)
    if not items and not allow_empty:
        raise WeakModelExecutionError(f"{label} must be non-empty")
    if len(items) > maximum_items:
        raise WeakModelExecutionError(f"{label} exceeds its task budget")
    normalized = [normalizer(item, f"{label}[{index}]") for index, item in enumerate(items)]
    if len(normalized) != len(set(normalized)):
        raise WeakModelExecutionError(f"{label} must not contain duplicates")
    return sorted(normalized)


def _validate_budget(value: object) -> dict[str, int]:
    budget = _mapping(value, "budget")
    expected = frozenset(_BUDGET_LIMITS)
    _exact_fields(budget, expected, "budget")
    return {
        name: _integer(budget[name], name, minimum, maximum)
        for name, (minimum, maximum) in _BUDGET_LIMITS.items()
    }


def _topological_task_ids(tasks: Sequence[Mapping[str, Any]]) -> list[str]:
    remaining = {task["task_id"]: set(task["dependencies"]) for task in tasks}
    ordered: list[str] = []
    while remaining:
        ready = sorted(task_id for task_id, dependencies in remaining.items() if not dependencies)
        if not ready:
            raise WeakModelExecutionError("high-level task dependencies must be acyclic")
        ordered.extend(ready)
        for task_id in ready:
            del remaining[task_id]
        completed = set(ready)
        for dependencies in remaining.values():
            dependencies.difference_update(completed)
    return ordered


def validate_high_level_plan(value: Mapping[str, object]) -> dict[str, Any]:
    """Normalize a bounded, dependency-safe high-level plan without executing it."""

    plan = _mapping(value, "high-level plan")
    _exact_fields(plan, _HIGH_LEVEL_PLAN_FIELDS, "high-level plan")
    if plan["schema"] != HIGH_LEVEL_PLAN_SCHEMA:
        raise WeakModelExecutionError("high-level plan schema is invalid")
    budget = _validate_budget(plan["budget"])
    raw_tasks = _list(plan["tasks"], "tasks")
    if not raw_tasks:
        raise WeakModelExecutionError("tasks must be non-empty")
    if len(raw_tasks) > budget["max_high_level_tasks"]:
        raise WeakModelExecutionError("tasks exceed max_high_level_tasks")

    normalized_tasks: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for index, raw_task in enumerate(raw_tasks):
        task = _mapping(raw_task, f"tasks[{index}]")
        _exact_fields(task, _HIGH_LEVEL_TASK_FIELDS, "task")
        task_id = _identifier(task["task_id"], "task_id")
        if task_id in seen_ids:
            raise WeakModelExecutionError("task_id values must be unique")
        seen_ids.add(task_id)
        risk_class = _text(task["risk_class"], "risk_class", 32)
        if risk_class not in _RISK_CLASSES:
            choices = ", ".join(sorted(_RISK_CLASSES))
            raise WeakModelExecutionError(f"risk_class must be one of: {choices}")
        allowed_paths = _unique_text_list(
            task["allowed_paths"],
            "allowed_paths",
            maximum_items=budget["max_allowed_paths_per_task"],
            normalizer=_safe_path,
        )
        dependencies = _unique_text_list(
            task["dependencies"],
            "dependencies",
            maximum_items=budget["max_dependencies_per_task"],
            normalizer=_identifier,
            allow_empty=True,
        )
        static_tool_ids = _unique_text_list(
            task["static_tool_ids"],
            "static_tool_ids",
            maximum_items=budget["max_static_tools_per_task"],
            normalizer=_identifier,
            allow_empty=risk_class == "owner-only",
        )
        if risk_class != "owner-only" and not static_tool_ids:
            raise WeakModelExecutionError("non-owner-only task requires static_tool_ids")
        normalized_tasks.append(
            {
                "task_id": task_id,
                "title": _text(task["title"], "title", 256),
                "objective": _text(task["objective"], "objective", 4_096),
                "allowed_paths": allowed_paths,
                "dependencies": dependencies,
                "risk_class": risk_class,
                "static_tool_ids": static_tool_ids,
                "acceptance_predicate": _text(
                    task["acceptance_predicate"], "acceptance_predicate", 2_048
                ),
            }
        )

    by_id = {task["task_id"]: task for task in normalized_tasks}
    for task in normalized_tasks:
        unknown = sorted(set(task["dependencies"]) - set(by_id))
        if unknown:
            raise WeakModelExecutionError(f"task {task['task_id']} has unknown dependencies: {unknown}")
        if task["task_id"] in task["dependencies"]:
            raise WeakModelExecutionError("a task may not depend on itself")
    sorted_tasks = sorted(normalized_tasks, key=lambda task: task["task_id"])
    _topological_task_ids(sorted_tasks)
    return {
        "schema": HIGH_LEVEL_PLAN_SCHEMA,
        "plan_id": _identifier(plan["plan_id"], "plan_id"),
        "budget": budget,
        "tasks": sorted_tasks,
    }


def _instruction(
    task: Mapping[str, Any], *, phase: str, tool_ids: Sequence[str]
) -> dict[str, Any]:
    common = {
        "phase": phase,
        "objective": task["objective"],
        "acceptance_predicate": task["acceptance_predicate"],
        "allowed_paths": list(task["allowed_paths"]),
    }
    if phase == "static-tool-first":
        return {
            **common,
            "tool_ids": list(tool_ids),
            "limits": [
                "Run declared static tools before any executor work.",
                "Do not mutate files, invoke external actions, or infer acceptance.",
                "Record UNAVAILABLE tools as observations without credit.",
            ],
        }
    if phase == "bounded-execution":
        return {
            **common,
            "limits": [
                "Stay within allowed_paths and the declared output budget.",
                "Stop if current authorization or required evidence is unavailable.",
                "Do not claim authority, acceptance, or pass credit.",
            ],
        }
    if phase == "receipt-review":
        return {
            **common,
            "limits": [
                "Review only bound receipts and their declared digests.",
                "Do not infer tool execution from a missing receipt.",
                "Do not grant authority, acceptance, or pass credit.",
            ],
        }
    if phase == "owner-decision-boundary":
        return {
            **common,
            "limits": [
                "Stop at this owner-only boundary.",
                "An explicit owner decision is required in a separately authorized route.",
                "Do not execute, delegate, or infer approval.",
            ],
        }
    raise AssertionError(f"unsupported phase: {phase}")


def _executor_task(
    task: Mapping[str, Any],
    *,
    task_id: str,
    kind: str,
    status: str,
    depends_on: Sequence[str],
    phase: str,
    tool_ids: Sequence[str],
    operation_mode: str,
    requires_current_authorization: bool,
    owner_decision_required: bool,
    budget: Mapping[str, int],
) -> dict[str, Any]:
    instruction = _instruction(task, phase=phase, tool_ids=tool_ids)
    instruction_bytes = len(canonical_bytes(instruction))
    if instruction_bytes > budget["max_task_instruction_bytes"]:
        raise WeakModelExecutionError(
            f"task {task_id} instruction exceeds max_task_instruction_bytes"
        )
    return {
        "schema": WEAK_MODEL_EXECUTOR_TASK_SCHEMA,
        "record_type": "WeakModelExecutorTask",
        "task_id": task_id,
        "parent_task_id": task["task_id"],
        "kind": kind,
        "status": status,
        "depends_on": list(depends_on),
        "title": f"{kind}: {task['title']}",
        "instruction": instruction,
        "instruction_digest": digest_value(instruction),
        "instruction_bytes": instruction_bytes,
        "allowed_paths": list(task["allowed_paths"]),
        "tool_phase": "static-only" if kind == "static-tool-first" else phase,
        "tool_ids": list(tool_ids),
        "operation_mode": operation_mode,
        "max_output_bytes": budget["max_task_output_bytes"],
        "max_attempts": budget["max_attempts_per_task"],
        "requires_current_authorization": requires_current_authorization,
        "owner_decision_required": owner_decision_required,
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }


def decompose_high_level_plan(value: Mapping[str, object]) -> dict[str, Any]:
    """Compile a validated high-level DAG into simple, bounded task cards.

    Each non-owner task gets a static-only preflight, a bounded executor card,
    and a receipt-review card.  Owner-only work produces only a stopping
    boundary.  This function remains pure and never executes the declared
    tools.
    """

    source_plan = validate_high_level_plan(value)
    budget = source_plan["budget"]
    source_by_id = {task["task_id"]: task for task in source_plan["tasks"]}
    endpoint_by_parent: dict[str, str] = {}
    executor_tasks: list[dict[str, Any]] = []
    for parent_id in _topological_task_ids(source_plan["tasks"]):
        task = source_by_id[parent_id]
        dependency_endpoints = [endpoint_by_parent[dependency] for dependency in task["dependencies"]]
        if task["risk_class"] == "owner-only":
            boundary_id = f"{parent_id}:owner-decision"
            executor_tasks.append(
                _executor_task(
                    task,
                    task_id=boundary_id,
                    kind="owner-decision",
                    status="OWNER_DECISION_REQUIRED",
                    depends_on=dependency_endpoints,
                    phase="owner-decision-boundary",
                    tool_ids=[],
                    operation_mode="owner-only",
                    requires_current_authorization=True,
                    owner_decision_required=True,
                    budget=budget,
                )
            )
            endpoint_by_parent[parent_id] = boundary_id
            continue

        preflight_id = f"{parent_id}:preflight"
        execute_id = f"{parent_id}:execute"
        review_id = f"{parent_id}:review"
        executor_tasks.append(
            _executor_task(
                task,
                task_id=preflight_id,
                kind="static-tool-first",
                status="PENDING",
                depends_on=dependency_endpoints,
                phase="static-tool-first",
                tool_ids=task["static_tool_ids"],
                operation_mode="read-only",
                requires_current_authorization=False,
                owner_decision_required=False,
                budget=budget,
            )
        )
        executor_tasks.append(
            _executor_task(
                task,
                task_id=execute_id,
                kind="bounded-executor",
                status="PENDING",
                depends_on=[preflight_id],
                phase="bounded-execution",
                tool_ids=[],
                operation_mode=task["risk_class"],
                requires_current_authorization=True,
                owner_decision_required=False,
                budget=budget,
            )
        )
        executor_tasks.append(
            _executor_task(
                task,
                task_id=review_id,
                kind="receipt-review",
                status="PENDING",
                depends_on=[execute_id],
                phase="receipt-review",
                tool_ids=[],
                operation_mode="read-only",
                requires_current_authorization=False,
                owner_decision_required=False,
                budget=budget,
            )
        )
        endpoint_by_parent[parent_id] = review_id

    if len(executor_tasks) > budget["max_executor_tasks"]:
        raise WeakModelExecutionError("decomposition exceeds max_executor_tasks")
    return {
        "schema": WEAK_MODEL_EXECUTION_PLAN_SCHEMA,
        "record_type": "WeakModelExecutionPlan",
        "planning_model_cap_billions": PLANNING_MODEL_CAP_BILLIONS,
        "source_plan": source_plan,
        "source_plan_digest": digest_value(source_plan),
        "budget": dict(budget),
        "tasks": executor_tasks,
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }


def validate_execution_plan(value: Mapping[str, object]) -> dict[str, Any]:
    """Fail closed unless a plan exactly matches this module's decomposition."""

    plan = _mapping(value, "execution plan")
    _exact_fields(plan, _EXECUTION_PLAN_FIELDS, "execution plan")
    if plan["schema"] != WEAK_MODEL_EXECUTION_PLAN_SCHEMA:
        raise WeakModelExecutionError("execution plan schema is invalid")
    if plan["record_type"] != "WeakModelExecutionPlan":
        raise WeakModelExecutionError("execution plan record_type is invalid")
    if plan["planning_model_cap_billions"] != PLANNING_MODEL_CAP_BILLIONS:
        raise WeakModelExecutionError("execution plan planning model cap is invalid")
    if plan["authority_effect"] != "none":
        raise WeakModelExecutionError("execution plan authority_effect must be none")
    for field in (
        "authority_granted",
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
    ):
        if plan[field] is not False:
            raise WeakModelExecutionError(f"execution plan {field} must be false")
    source_plan = validate_high_level_plan(_mapping(plan["source_plan"], "source_plan"))
    if plan["source_plan_digest"] != digest_value(source_plan):
        raise WeakModelExecutionError("execution plan source_plan_digest does not bind source_plan")
    if plan["budget"] != source_plan["budget"]:
        raise WeakModelExecutionError("execution plan budget does not bind source_plan")
    if not isinstance(plan["tasks"], list):
        raise WeakModelExecutionError("execution plan tasks must be an array")
    expected = decompose_high_level_plan(source_plan)
    try:
        actual_bytes = canonical_bytes(plan)
    except ValueError as exc:
        raise WeakModelExecutionError("execution plan must be canonical JSON") from exc
    if actual_bytes != canonical_bytes(expected):
        raise WeakModelExecutionError("execution plan does not match deterministic decomposition")
    return expected


def _task_by_id(plan: Mapping[str, Any], task_id: str) -> dict[str, Any]:
    for task in plan["tasks"]:
        if task["task_id"] == task_id:
            return task
    raise WeakModelExecutionError(f"unknown executor task_id: {task_id}")


def _normalize_receipt(plan: Mapping[str, Any], value: Mapping[str, object]) -> dict[str, Any]:
    receipt = _mapping(value, "executor receipt")
    _exact_fields(receipt, _RECEIPT_FIELDS, "executor receipt")
    if receipt["schema"] != WEAK_MODEL_EXECUTION_RECEIPT_SCHEMA:
        raise WeakModelExecutionError("executor receipt schema is invalid")
    if receipt["record_type"] != "WeakModelExecutorReceipt":
        raise WeakModelExecutionError("executor receipt record_type is invalid")
    plan_digest = digest_value(plan)
    if receipt["execution_plan_digest"] != plan_digest:
        raise WeakModelExecutionError("executor receipt does not bind execution plan")
    task_id = _text(receipt["task_id"], "task_id", 96)
    task = _task_by_id(plan, task_id)
    if receipt["task_digest"] != digest_value(task):
        raise WeakModelExecutionError("executor receipt does not bind executor task")
    attempt = _integer(
        receipt["attempt"], "attempt", 1, plan["budget"]["max_attempts_per_task"]
    )
    status = _text(receipt["status"], "status", 64)
    if status not in _RECEIPT_STATUSES:
        raise WeakModelExecutionError("executor receipt status is invalid")
    if task["kind"] == "owner-decision":
        raise WeakModelExecutionError("owner-decision task does not accept executor receipts")
    input_digest = _digest(receipt["input_digest"], "input_digest")
    if input_digest != task["instruction_digest"]:
        raise WeakModelExecutionError("executor receipt input_digest does not bind instruction")
    output_digest = _digest(receipt["output_digest"], "output_digest")
    output_bytes = _integer(
        receipt["output_bytes"], "output_bytes", 0, task["max_output_bytes"]
    )
    owner_decision_required = status == "OWNER_DECISION_REQUIRED"
    resumable = status in {"FAILED", "BLOCKED"} and attempt < task["max_attempts"]
    if receipt["review_required"] is not True:
        raise WeakModelExecutionError("executor receipt review_required must be true")
    if receipt["resumable"] is not resumable:
        raise WeakModelExecutionError("executor receipt resumable is inconsistent with status")
    if receipt["owner_decision_required"] is not owner_decision_required:
        raise WeakModelExecutionError("executor receipt owner_decision_required is inconsistent")
    if receipt["authority_effect"] != "none":
        raise WeakModelExecutionError("executor receipt authority_effect must be none")
    for field in (
        "authority_granted",
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
    ):
        if receipt[field] is not False:
            raise WeakModelExecutionError(f"executor receipt {field} must be false")
    return {
        "schema": WEAK_MODEL_EXECUTION_RECEIPT_SCHEMA,
        "record_type": "WeakModelExecutorReceipt",
        "execution_plan_digest": plan_digest,
        "task_id": task_id,
        "task_digest": digest_value(task),
        "attempt": attempt,
        "status": status,
        "input_digest": input_digest,
        "output_digest": output_digest,
        "output_bytes": output_bytes,
        "observation": _text(receipt["observation"], "observation", 512),
        "review_required": True,
        "resumable": resumable,
        "owner_decision_required": owner_decision_required,
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }


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
) -> dict[str, Any]:
    """Create one non-promoting, digest-bound executor observation receipt."""

    plan = validate_execution_plan(execution_plan)
    task = _task_by_id(plan, _text(task_id, "task_id", 96))
    normalized_status = _text(status, "status", 64)
    normalized_attempt = _integer(
        attempt, "attempt", 1, plan["budget"]["max_attempts_per_task"]
    )
    candidate = {
        "schema": WEAK_MODEL_EXECUTION_RECEIPT_SCHEMA,
        "record_type": "WeakModelExecutorReceipt",
        "execution_plan_digest": digest_value(plan),
        "task_id": task["task_id"],
        "task_digest": digest_value(task),
        "attempt": normalized_attempt,
        "status": normalized_status,
        "input_digest": input_digest,
        "output_digest": output_digest,
        "output_bytes": output_bytes,
        "observation": observation,
        "review_required": True,
        "resumable": normalized_status in {"FAILED", "BLOCKED"}
        and normalized_attempt < task["max_attempts"],
        "owner_decision_required": normalized_status == "OWNER_DECISION_REQUIRED",
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
    """Validate one receipt independently before it enters a review sequence."""

    return _normalize_receipt(validate_execution_plan(execution_plan), receipt)


def review_executor_receipts(
    execution_plan: Mapping[str, object], receipts: Sequence[Mapping[str, object]]
) -> dict[str, Any]:
    """Review a chronological receipt sequence and expose only safe resumption.

    A review says that receipts are structurally bound.  It does not certify
    the observed work, grant an executor authority, or turn completion into
    acceptance.
    """

    plan = validate_execution_plan(execution_plan)
    raw_receipts = _list(receipts, "receipts")
    tasks = {task["task_id"]: task for task in plan["tasks"]}
    states: dict[str, dict[str, Any]] = {
        task_id: {
            "status": "OWNER_DECISION_REQUIRED" if task["kind"] == "owner-decision" else "PENDING",
            "attempts": 0,
        }
        for task_id, task in tasks.items()
    }
    normalized_receipts: list[dict[str, Any]] = []
    for index, raw_receipt in enumerate(raw_receipts):
        normalized = _normalize_receipt(plan, raw_receipt)
        task_id = normalized["task_id"]
        state = states[task_id]
        if state["status"] in {"COMPLETED", "OWNER_DECISION_REQUIRED"}:
            raise WeakModelExecutionError(f"receipt {index} follows a terminal task state")
        if normalized["attempt"] != state["attempts"] + 1:
            raise WeakModelExecutionError(f"receipt {index} attempt sequence is not contiguous")
        pending_dependencies = [
            dependency
            for dependency in tasks[task_id]["depends_on"]
            if states[dependency]["status"] != "COMPLETED"
        ]
        if pending_dependencies:
            raise WeakModelExecutionError(
                f"receipt {index} records a task before dependencies complete: {pending_dependencies}"
            )
        state["status"] = normalized["status"]
        state["attempts"] = normalized["attempt"]
        normalized_receipts.append(normalized)

    eligible_task_ids: list[tuple[str, str]] = []
    owner_decision_task_ids: list[str] = []
    task_states: list[dict[str, Any]] = []
    for task in plan["tasks"]:
        task_id = task["task_id"]
        state = states[task_id]
        dependencies_complete = all(
            states[dependency]["status"] == "COMPLETED" for dependency in task["depends_on"]
        )
        resumable = (
            state["status"] in {"FAILED", "BLOCKED"}
            and state["attempts"] < task["max_attempts"]
            and dependencies_complete
        )
        owner_required = (
            state["status"] == "OWNER_DECISION_REQUIRED"
            or task["kind"] == "owner-decision"
        )
        if resumable:
            eligible_task_ids.append((task_id, "resumable"))
        elif state["status"] == "PENDING" and dependencies_complete:
            eligible_task_ids.append((task_id, "ready"))
        if owner_required and dependencies_complete:
            owner_decision_task_ids.append(task_id)
        task_states.append(
            {
                "task_id": task_id,
                "kind": task["kind"],
                "status": state["status"],
                "attempts": state["attempts"],
                "review_required": True,
                "resumable": resumable,
                "owner_decision_required": owner_required,
            }
        )

    scheduled = eligible_task_ids[: plan["budget"]["max_parallel_tasks"]]
    ready_task_ids = [task_id for task_id, category in scheduled if category == "ready"]
    resumable_task_ids = [
        task_id for task_id, category in scheduled if category == "resumable"
    ]
    deferred_task_ids = [
        task_id for task_id, _category in eligible_task_ids[plan["budget"]["max_parallel_tasks"] :]
    ]

    return {
        "schema": WEAK_MODEL_EXECUTION_REVIEW_SCHEMA,
        "record_type": "WeakModelExecutionReview",
        "execution_plan_digest": digest_value(plan),
        "receipt_set_digest": digest_value(normalized_receipts),
        "review_status": "REVIEW_REQUIRED",
        "task_states": task_states,
        "ready_task_ids": ready_task_ids,
        "resumable_task_ids": resumable_task_ids,
        "deferred_task_ids": deferred_task_ids,
        "owner_decision_task_ids": owner_decision_task_ids,
        "all_tasks_completed": all(
            state["status"] == "COMPLETED" for state in states.values()
        ),
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }


def resume_execution_plan(
    execution_plan: Mapping[str, object], receipts: Sequence[Mapping[str, object]]
) -> dict[str, Any]:
    """Return the bounded next cards without restarting or promoting work."""

    plan = validate_execution_plan(execution_plan)
    review = review_executor_receipts(plan, receipts)
    return {
        "schema": WEAK_MODEL_EXECUTION_RESUME_SCHEMA,
        "record_type": "WeakModelExecutionResume",
        "execution_plan_digest": digest_value(plan),
        "review_digest": digest_value(review),
        "ready_task_ids": list(review["ready_task_ids"]),
        "resumable_task_ids": list(review["resumable_task_ids"]),
        "deferred_task_ids": list(review["deferred_task_ids"]),
        "owner_decision_task_ids": list(review["owner_decision_task_ids"]),
        "review_required": True,
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }


__all__ = [
    "HIGH_LEVEL_PLAN_SCHEMA",
    "PLANNING_MODEL_CAP_BILLIONS",
    "WEAK_MODEL_EXECUTION_PLAN_SCHEMA",
    "WEAK_MODEL_EXECUTION_RECEIPT_SCHEMA",
    "WEAK_MODEL_EXECUTION_REVIEW_SCHEMA",
    "WEAK_MODEL_EXECUTION_RESUME_SCHEMA",
    "WEAK_MODEL_EXECUTOR_TASK_SCHEMA",
    "WeakModelExecutionError",
    "create_executor_receipt",
    "decompose_high_level_plan",
    "resume_execution_plan",
    "review_executor_receipts",
    "validate_execution_plan",
    "validate_executor_receipt",
    "validate_high_level_plan",
]
