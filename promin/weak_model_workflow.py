"""Durable, deterministic execution control for arbitrary managed tasks."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from threading import Lock, RLock
from time import monotonic_ns
from typing import Any, TypeAlias
import unicodedata

from .canonical import CanonicalError, canonical_bytes, digest_bytes, digest_value, parse_json_strict
from .weak_model_execution import (
    WeakModelExecutionError,
    create_control_record,
    create_executor_receipt,
    decompose_high_level_plan,
    resume_execution_plan,
    review_executor_receipts,
    validate_control_record,
    validate_execution_plan,
    validate_executor_receipt,
)


class WeakModelWorkflowError(ValueError):
    """Raised when workflow inputs or durable records are inconsistent."""


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
_OBSERVATION_BYTES = 512
_RECEIPT_RECORD_BYTES_MAX = 4096
_CONTROL_RECORD_BYTES_MAX = 2048
# Host processes coordinate separately; this boundary serializes cooperative
# control sequencing and terminal publication inside one Python process.
_WORKFLOW_BOUNDARIES_GUARD = Lock()
_WORKFLOW_BOUNDARIES: dict[tuple[Path, str], RLock] = {}


def _workflow_boundary(root: Path, workflow_digest: str) -> RLock:
    key = (root, workflow_digest)
    with _WORKFLOW_BOUNDARIES_GUARD:
        boundary = _WORKFLOW_BOUNDARIES.get(key)
        if boundary is None:
            boundary = RLock()
            _WORKFLOW_BOUNDARIES[key] = boundary
        return boundary


@dataclass(frozen=True, slots=True)
class WeakModelWorkflowBudget:
    max_high_level_tasks: int
    max_executor_tasks: int
    max_dependencies_per_task: int
    max_resources_per_task: int
    max_task_instruction_bytes: int
    max_task_context_bytes: int
    max_task_output_bytes: int
    max_attempt_seconds: int
    max_attempts_per_task: int
    max_parallel_tasks: int
    max_workflow_seconds: int
    max_workflow_output_bytes: int


@dataclass(frozen=True, slots=True)
class WeakModelExecutorCard:
    task_id: str
    parent_task_id: str
    kind: str
    status: str
    depends_on: tuple[str, ...]
    title: str
    phase: str
    phases: tuple[str, ...]
    objective: str
    acceptance_predicate: str
    resources: tuple[tuple[str, str], ...]
    limits: tuple[str, ...]
    instruction_digest: str
    instruction_bytes: int
    operation_mode: str
    max_context_bytes: int
    max_output_bytes: int
    max_attempt_seconds: int
    max_attempts: int
    requires_current_authorization: bool
    requires_owner_decision: bool
    authority_effect: str = field(default="none", init=False)
    authority_granted: bool = field(default=False, init=False)
    pass_credit: bool = field(default=False, init=False)
    acceptance_pass: bool = field(default=False, init=False)
    product_acceptance_pass: bool = field(default=False, init=False)

    @property
    def allowed_paths(self) -> tuple[str, ...]:
        return tuple(value for kind, value in self.resources if kind == "filesystem-path")

    @property
    def tool_ids(self) -> tuple[str, ...]:
        return tuple(value for kind, value in self.resources if kind == "tool")


@dataclass(frozen=True, slots=True)
class WeakModelWorkflowPlan:
    execution_plan_json: bytes
    workflow_digest: str
    budget: WeakModelWorkflowBudget
    cards: tuple[WeakModelExecutorCard, ...]
    planning_is_diagnostic: bool = field(default=True, init=False)
    selection_policy: str = field(default="deterministic-source-dag-core-state-budget", init=False)
    authority_effect: str = field(default="none", init=False)
    authority_granted: bool = field(default=False, init=False)
    pass_credit: bool = field(default=False, init=False)
    acceptance_pass: bool = field(default=False, init=False)
    product_acceptance_pass: bool = field(default=False, init=False)

    def execution_plan_document(self) -> dict[str, Any]:
        value = parse_json_strict(self.execution_plan_json)
        if not isinstance(value, dict):
            raise WeakModelWorkflowError("prepared workflow is not a JSON object")
        return value


@dataclass(frozen=True, slots=True)
class WeakModelExecutorRequest:
    workflow_digest: str
    receipt_set_digest: str
    card: WeakModelExecutorCard
    attempt: int
    max_context_bytes: int
    max_output_bytes: int
    max_attempt_seconds: int
    deadline_utc: str
    cancellation_requested: bool
    workflow_seconds_remaining: int
    workflow_output_bytes_remaining: int
    control_check: WeakModelControlCheck
    authority_effect: str = field(default="none", init=False)
    authority_granted: bool = field(default=False, init=False)
    pass_credit: bool = field(default=False, init=False)
    acceptance_pass: bool = field(default=False, init=False)
    product_acceptance_pass: bool = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class WeakModelExecutionOutcome:
    status: str
    output: bytes
    observation: str
    block_reason: str | None = None


@dataclass(frozen=True, slots=True)
class WeakModelTaskReceipt:
    workflow_digest: str
    task_id: str
    attempt: int
    status: str
    attempt_directory: Path
    started_path: Path
    receipt_path: Path | None
    output_path: Path | None
    receipt_json: bytes
    receipt_digest: str
    output_digest: str
    output_bytes: int
    elapsed_milliseconds: int
    budget_elapsed_milliseconds: int
    authority_effect: str = field(default="none", init=False)
    authority_granted: bool = field(default=False, init=False)
    pass_credit: bool = field(default=False, init=False)
    acceptance_pass: bool = field(default=False, init=False)
    product_acceptance_pass: bool = field(default=False, init=False)

    def record_document(self) -> dict[str, Any]:
        value = parse_json_strict(self.receipt_json)
        if not isinstance(value, dict):
            raise WeakModelWorkflowError("executor receipt is not a JSON object")
        return value


@dataclass(frozen=True, slots=True)
class WeakModelTaskState:
    task_id: str
    kind: str
    status: str
    block_reason: str | None
    attempts: int
    review_required: bool
    resumable: bool
    owner_decision_required: bool


@dataclass(frozen=True, slots=True)
class WeakModelWorkflowReview:
    workflow_digest: str
    receipt_set_digest: str
    record_json: bytes
    receipts: tuple[WeakModelTaskReceipt, ...]
    task_states: tuple[WeakModelTaskState, ...]
    ready_cards: tuple[WeakModelExecutorCard, ...]
    resumable_cards: tuple[WeakModelExecutorCard, ...]
    deferred_task_ids: tuple[str, ...]
    owner_decision_task_ids: tuple[str, ...]
    all_tasks_completed: bool
    workflow_elapsed_milliseconds: int
    workflow_budget_elapsed_milliseconds: int
    workflow_output_bytes: int
    workflow_budget_output_bytes: int
    workflow_time_budget_exhausted: bool
    workflow_output_budget_exhausted: bool
    workflow_state: str
    review_required: bool = field(default=True, init=False)
    authority_effect: str = field(default="none", init=False)
    authority_granted: bool = field(default=False, init=False)
    pass_credit: bool = field(default=False, init=False)
    acceptance_pass: bool = field(default=False, init=False)
    product_acceptance_pass: bool = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class WeakModelWorkflowResume:
    workflow_digest: str
    review_digest: str
    record_json: bytes
    ready_cards: tuple[WeakModelExecutorCard, ...]
    resumable_cards: tuple[WeakModelExecutorCard, ...]
    deferred_task_ids: tuple[str, ...]
    owner_decision_task_ids: tuple[str, ...]
    workflow_elapsed_milliseconds: int
    workflow_budget_elapsed_milliseconds: int
    workflow_output_bytes: int
    workflow_budget_output_bytes: int
    workflow_time_budget_exhausted: bool
    workflow_output_budget_exhausted: bool
    workflow_state: str
    review_required: bool = field(default=True, init=False)
    authority_effect: str = field(default="none", init=False)
    authority_granted: bool = field(default=False, init=False)
    pass_credit: bool = field(default=False, init=False)
    acceptance_pass: bool = field(default=False, init=False)
    product_acceptance_pass: bool = field(default=False, init=False)


WeakModelControlCheck: TypeAlias = Callable[[], str | None]
WeakModelExecutor: TypeAlias = Callable[[WeakModelExecutorRequest], WeakModelExecutionOutcome]
WeakModelAuthorizationCheck: TypeAlias = Callable[[WeakModelExecutorRequest], bool]


def _budget(plan: Mapping[str, Any]) -> WeakModelWorkflowBudget:
    return WeakModelWorkflowBudget(**plan["budget"])


def _card(task: Mapping[str, Any]) -> WeakModelExecutorCard:
    instruction = task["instruction"]
    return WeakModelExecutorCard(
        task_id=task["task_id"],
        parent_task_id=task["parent_task_id"],
        kind=task["kind"],
        status=task["status"],
        depends_on=tuple(task["depends_on"]),
        title=task["title"],
        phase=instruction["phase"],
        phases=tuple(instruction["phases"]),
        objective=instruction["objective"],
        acceptance_predicate=instruction["acceptance_predicate"],
        resources=tuple(
            (item["resource_type"], item["resource_id"]) for item in task["resources"]
        ),
        limits=tuple(instruction["limits"]),
        instruction_digest=task["instruction_digest"],
        instruction_bytes=task["instruction_bytes"],
        operation_mode=task["operation_mode"],
        max_context_bytes=task["max_context_bytes"],
        max_output_bytes=task["max_output_bytes"],
        max_attempt_seconds=task["max_attempt_seconds"],
        max_attempts=task["max_attempts"],
        requires_current_authorization=task["requires_current_authorization"],
        requires_owner_decision=task["requires_owner_decision"],
    )


def _cards(plan: Mapping[str, Any]) -> tuple[WeakModelExecutorCard, ...]:
    return tuple(_card(item) for item in plan["tasks"])


def _validated(workflow: WeakModelWorkflowPlan) -> dict[str, Any]:
    if not isinstance(workflow, WeakModelWorkflowPlan):
        raise WeakModelWorkflowError("workflow must be a WeakModelWorkflowPlan")
    try:
        value = parse_json_strict(workflow.execution_plan_json)
        if not isinstance(value, dict):
            raise WeakModelWorkflowError("workflow plan must be an object")
        plan = validate_execution_plan(value)
    except (CanonicalError, WeakModelExecutionError) as exc:
        raise WeakModelWorkflowError("prepared workflow is invalid") from exc
    if (
        digest_value(plan) != workflow.workflow_digest
        or _budget(plan) != workflow.budget
        or _cards(plan) != workflow.cards
    ):
        raise WeakModelWorkflowError("prepared workflow binding differs")
    return plan


def prepare(source_plan: Mapping[str, object]) -> WeakModelWorkflowPlan:
    """Compile a source DAG into one deterministic managed card per task."""

    try:
        plan = decompose_high_level_plan(source_plan)
    except WeakModelExecutionError as exc:
        raise WeakModelWorkflowError(f"source plan cannot be prepared: {exc}") from exc
    return WeakModelWorkflowPlan(
        canonical_bytes(plan), digest_value(plan), _budget(plan), _cards(plan)
    )


def _root(value: str | os.PathLike[str]) -> Path:
    path = Path(value).absolute()
    if not path.is_dir():
        raise WeakModelWorkflowError("receipt directory must be an existing directory")
    return path


def _attempt_name(workflow_digest: str, task_index: int, attempt: int) -> str:
    return f"wm-{workflow_digest}-{task_index:03d}-a{attempt:02d}"


def _write_new(path: Path, payload: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise WeakModelWorkflowError(f"workflow record cannot be written: {path.name}") from exc


def _read_bounded(path: Path, maximum_bytes: int, label: str) -> bytes:
    try:
        with path.open("rb") as stream:
            payload = stream.read(maximum_bytes + 1)
    except OSError as exc:
        raise WeakModelWorkflowError(f"{label} cannot be read") from exc
    if len(payload) > maximum_bytes:
        raise WeakModelWorkflowError(f"{label} exceeds its declared read bound")
    return payload


def _started_record(plan: Mapping[str, Any], task: Mapping[str, Any], attempt: int) -> dict[str, Any]:
    return {
        "schema": "promin.weak-model-attempt-started.v1",
        "record_type": "WeakModelAttemptStarted",
        "execution_plan_digest": digest_value(plan),
        "task_id": task["task_id"],
        "task_digest": digest_value(task),
        "attempt": attempt,
        "source_state": "READY",
        "transitions": ["LEASED", "RUNNING"],
        "projection_authoritative": False,
        "authority_effect": "none",
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }


def _read_started(
    plan: Mapping[str, Any], task: Mapping[str, Any], attempt: int, path: Path
) -> dict[str, Any]:
    expected = _started_record(plan, task, attempt)
    expected_payload = canonical_bytes(expected)
    try:
        payload = _read_bounded(path, len(expected_payload), "attempt STARTED record")
        value = parse_json_strict(payload)
    except CanonicalError as exc:
        raise WeakModelWorkflowError("attempt STARTED record cannot be loaded") from exc
    if not isinstance(value, dict) or payload != expected_payload or value != expected:
        raise WeakModelWorkflowError("attempt STARTED record is invalid")
    return value


def _receipt_dto(
    workflow_digest: str,
    directory: Path,
    started_path: Path,
    receipt_path: Path | None,
    output_path: Path | None,
    record: Mapping[str, Any],
    payload: bytes,
) -> WeakModelTaskReceipt:
    return WeakModelTaskReceipt(
        workflow_digest=workflow_digest,
        task_id=record["task_id"],
        attempt=record["attempt"],
        status=record["status"],
        attempt_directory=directory,
        started_path=started_path,
        receipt_path=receipt_path,
        output_path=output_path,
        receipt_json=payload,
        receipt_digest=digest_value(record),
        output_digest=record["output_digest"],
        output_bytes=record["output_bytes"],
        elapsed_milliseconds=record["elapsed_milliseconds"],
        budget_elapsed_milliseconds=record["budget_elapsed_milliseconds"],
    )


def _load_attempts(
    plan: Mapping[str, Any], workflow_digest: str, root: Path
) -> tuple[tuple[WeakModelTaskReceipt, ...], dict[str, int]]:
    receipts: list[WeakModelTaskReceipt] = []
    active_attempts: dict[str, int] = {}
    for task_index, task in enumerate(plan["tasks"]):
        for attempt in range(1, task["max_attempts"] + 1):
            directory = root / _attempt_name(workflow_digest, task_index, attempt)
            if not directory.exists():
                continue
            if not directory.is_dir():
                raise WeakModelWorkflowError("workflow attempt is not a directory")
            started_path = directory / "started.json"
            if not started_path.is_file():
                raise WeakModelWorkflowError("workflow attempt lacks durable STARTED evidence")
            _read_started(plan, task, attempt, started_path)
            output_path = directory / "output.bin"
            receipt_path = directory / "receipt.json"
            if not output_path.exists() and not receipt_path.exists():
                if task["task_id"] in active_attempts:
                    raise WeakModelWorkflowError("task has multiple active attempts")
                active_attempts[task["task_id"]] = attempt
                continue
            if not output_path.is_file() or not receipt_path.is_file():
                raise WeakModelWorkflowError("workflow attempt terminal record is incomplete")
            try:
                output = _read_bounded(
                    output_path, task["max_output_bytes"], "executor output"
                )
                payload = _read_bounded(
                    receipt_path,
                    _RECEIPT_RECORD_BYTES_MAX,
                    "executor receipt",
                )
                value = parse_json_strict(payload)
                if not isinstance(value, dict) or canonical_bytes(value) != payload:
                    raise WeakModelWorkflowError("executor receipt is not canonical JSON")
                record = validate_executor_receipt(plan, value)
            except (CanonicalError, WeakModelExecutionError) as exc:
                raise WeakModelWorkflowError("executor receipt cannot be loaded") from exc
            if (
                record["task_id"] != task["task_id"]
                or record["attempt"] != attempt
                or record["output_bytes"] != len(output)
                or record["output_digest"] != digest_bytes(output)
            ):
                raise WeakModelWorkflowError("executor receipt does not bind its output")
            receipts.append(
                _receipt_dto(
                    workflow_digest,
                    directory,
                    started_path,
                    receipt_path,
                    output_path,
                    record,
                    payload,
                )
            )
    return tuple(receipts), active_attempts


def _control_paths(
    root: Path, workflow_digest: str, maximum_records: int
) -> list[Path]:
    prefix = f"wc-{workflow_digest}-"
    result: list[Path] = []
    for path in root.iterdir():
        if path.is_file() and path.name.startswith(prefix) and path.name.endswith(".json"):
            if len(result) >= maximum_records:
                raise WeakModelWorkflowError(
                    "control records exceed the declared workflow bound"
                )
            result.append(path)
    return sorted(result, key=lambda item: item.name)


def _load_controls(plan: Mapping[str, Any], workflow_digest: str, root: Path) -> list[dict[str, Any]]:
    maximum_records = len(plan["tasks"]) * (
        plan["budget"]["max_attempts_per_task"] + 2
    )
    result: list[dict[str, Any]] = []
    for expected_sequence, path in enumerate(
        _control_paths(root, workflow_digest, maximum_records), 1
    ):
        try:
            payload = _read_bounded(
                path, _CONTROL_RECORD_BYTES_MAX, "control record"
            )
            value = parse_json_strict(payload)
            if not isinstance(value, dict) or canonical_bytes(value) != payload:
                raise WeakModelWorkflowError("control record is not canonical JSON")
            record = validate_control_record(plan, value)
        except (CanonicalError, WeakModelExecutionError) as exc:
            raise WeakModelWorkflowError("control record cannot be loaded") from exc
        if record["sequence"] != expected_sequence:
            raise WeakModelWorkflowError("control sequence is not contiguous")
        result.append(record)
    return result


def _documents(receipts: tuple[WeakModelTaskReceipt, ...]) -> list[dict[str, Any]]:
    return [item.record_document() for item in receipts]


def _review_data(
    workflow: WeakModelWorkflowPlan, root: Path
) -> tuple[dict[str, Any], tuple[WeakModelTaskReceipt, ...], list[dict[str, Any]]]:
    plan = _validated(workflow)
    receipts, active_attempts = _load_attempts(plan, workflow.workflow_digest, root)
    controls = _load_controls(plan, workflow.workflow_digest, root)
    try:
        record = review_executor_receipts(
            plan,
            _documents(receipts),
            controls=controls,
            active_attempts=active_attempts,
        )
    except WeakModelExecutionError as exc:
        raise WeakModelWorkflowError(f"workflow history is invalid: {exc}") from exc
    return record, receipts, controls


def _review_dto(
    workflow: WeakModelWorkflowPlan,
    record: Mapping[str, Any],
    receipts: tuple[WeakModelTaskReceipt, ...],
) -> WeakModelWorkflowReview:
    by_id = {card.task_id: card for card in workflow.cards}
    return WeakModelWorkflowReview(
        workflow_digest=workflow.workflow_digest,
        receipt_set_digest=record["receipt_set_digest"],
        record_json=canonical_bytes(dict(record)),
        receipts=receipts,
        task_states=tuple(
            WeakModelTaskState(**item) for item in record["task_states"]
        ),
        ready_cards=tuple(by_id[item] for item in record["ready_task_ids"]),
        resumable_cards=tuple(
            by_id[item] for item in record["resumable_task_ids"]
        ),
        deferred_task_ids=tuple(record["deferred_task_ids"]),
        owner_decision_task_ids=tuple(record["owner_decision_task_ids"]),
        all_tasks_completed=record["all_tasks_completed"],
        workflow_elapsed_milliseconds=record["workflow_elapsed_milliseconds"],
        workflow_budget_elapsed_milliseconds=record[
            "workflow_budget_elapsed_milliseconds"
        ],
        workflow_output_bytes=record["workflow_output_bytes"],
        workflow_budget_output_bytes=record["workflow_budget_output_bytes"],
        workflow_time_budget_exhausted=record[
            "workflow_time_budget_exhausted"
        ],
        workflow_output_budget_exhausted=record[
            "workflow_output_budget_exhausted"
        ],
        workflow_state=record["workflow_state"],
    )


def review(
    workflow: WeakModelWorkflowPlan, receipt_directory: str | os.PathLike[str]
) -> WeakModelWorkflowReview:
    root = _root(receipt_directory)
    record, receipts, _ = _review_data(workflow, root)
    return _review_dto(workflow, record, receipts)


def resume(
    workflow: WeakModelWorkflowPlan, receipt_directory: str | os.PathLike[str]
) -> WeakModelWorkflowResume:
    root = _root(receipt_directory)
    plan = _validated(workflow)
    receipts, active_attempts = _load_attempts(plan, workflow.workflow_digest, root)
    controls = _load_controls(plan, workflow.workflow_digest, root)
    try:
        record = resume_execution_plan(
            plan,
            _documents(receipts),
            controls=controls,
            active_attempts=active_attempts,
        )
    except WeakModelExecutionError as exc:
        raise WeakModelWorkflowError(f"workflow cannot be resumed: {exc}") from exc
    by_id = {card.task_id: card for card in workflow.cards}
    return WeakModelWorkflowResume(
        workflow_digest=workflow.workflow_digest,
        review_digest=record["review_digest"],
        record_json=canonical_bytes(record),
        ready_cards=tuple(by_id[item] for item in record["ready_task_ids"]),
        resumable_cards=tuple(
            by_id[item] for item in record["resumable_task_ids"]
        ),
        deferred_task_ids=tuple(record["deferred_task_ids"]),
        owner_decision_task_ids=tuple(record["owner_decision_task_ids"]),
        workflow_elapsed_milliseconds=record["workflow_elapsed_milliseconds"],
        workflow_budget_elapsed_milliseconds=record[
            "workflow_budget_elapsed_milliseconds"
        ],
        workflow_output_bytes=record["workflow_output_bytes"],
        workflow_budget_output_bytes=record["workflow_budget_output_bytes"],
        workflow_time_budget_exhausted=record[
            "workflow_time_budget_exhausted"
        ],
        workflow_output_budget_exhausted=record[
            "workflow_output_budget_exhausted"
        ],
        workflow_state=record["workflow_state"],
    )


def _outcome(value: object, card: WeakModelExecutorCard) -> WeakModelExecutionOutcome:
    if not isinstance(value, WeakModelExecutionOutcome):
        raise WeakModelWorkflowError("executor must return WeakModelExecutionOutcome")
    if value.status not in _OUTCOMES:
        raise WeakModelWorkflowError("executor outcome status is invalid")
    if type(value.output) is not bytes or len(value.output) > card.max_output_bytes:
        raise WeakModelWorkflowError("executor output exceeds its task budget")
    if type(value.observation) is not str or value.observation != value.observation.strip():
        raise WeakModelWorkflowError("executor observation must be trimmed text")
    observation = unicodedata.normalize("NFC", value.observation)
    if not observation or len(observation.encode("utf-8")) > _OBSERVATION_BYTES:
        raise WeakModelWorkflowError("executor observation exceeds its task budget")
    reason = value.block_reason
    if reason is not None:
        if type(reason) is not str or reason != reason.strip() or not reason:
            raise WeakModelWorkflowError("executor block_reason must be trimmed text")
        reason = unicodedata.normalize("NFC", reason)
        if len(reason.encode("utf-8")) > 128:
            raise WeakModelWorkflowError("executor block_reason exceeds its task budget")
    return WeakModelExecutionOutcome(value.status, value.output, observation, reason)


def _cooperative_control_check(
    value: WeakModelControlCheck | None,
    persisted: WeakModelControlCheck,
) -> WeakModelControlCheck:
    if value is not None and not callable(value):
        raise WeakModelWorkflowError("control_check must be a callable")
    latched: str | None = None

    def sample() -> str | None:
        nonlocal latched
        callbacks = (persisted,) if value is None else (persisted, value)
        for callback in callbacks:
            try:
                observed = callback()
            except Exception as exc:
                raise WeakModelWorkflowError("control_check callback failed") from exc
            if observed not in {None, "PAUSE", "CANCEL"}:
                raise WeakModelWorkflowError(
                    "control_check must return None, PAUSE, or CANCEL"
                )
            if observed == "CANCEL" or observed == "PAUSE" and latched is None:
                latched = observed
        return latched

    return sample


def execute(
    workflow: WeakModelWorkflowPlan,
    receipt_directory: str | os.PathLike[str],
    *,
    task_id: str,
    executor: WeakModelExecutor,
    authorization_check: WeakModelAuthorizationCheck | None = None,
    control_check: WeakModelControlCheck | None = None,
) -> WeakModelTaskReceipt:
    """Persist STARTED, invoke one caller-owned executor, then persist outcome."""

    if not callable(executor):
        raise WeakModelWorkflowError("executor must be an explicit callable")
    plan = _validated(workflow)
    root = _root(receipt_directory)
    current = review(workflow, root)
    if current.workflow_time_budget_exhausted:
        raise WeakModelWorkflowError("workflow time budget is exhausted")
    if current.workflow_output_budget_exhausted:
        raise WeakModelWorkflowError("workflow output budget is exhausted")
    eligible = {card.task_id: card for card in current.ready_cards + current.resumable_cards}
    card = eligible.get(task_id)
    if card is None:
        raise WeakModelWorkflowError(f"executor task {task_id!r} is not ready or resumable")
    state = next(item for item in current.task_states if item.task_id == task_id)
    elapsed_used = current.workflow_elapsed_milliseconds
    output_used = current.workflow_output_bytes
    elapsed_limit = workflow.budget.max_workflow_seconds * 1000
    milliseconds_remaining = elapsed_limit - elapsed_used
    seconds_remaining = max(1, (milliseconds_remaining + 999) // 1000)
    output_remaining = workflow.budget.max_workflow_output_bytes - output_used
    attempt_seconds = min(card.max_attempt_seconds, seconds_remaining)
    attempt_output = min(card.max_output_bytes, output_remaining)
    deadline = datetime.now(timezone.utc) + timedelta(seconds=attempt_seconds)
    initial_control_count = len(
        _load_controls(plan, workflow.workflow_digest, root)
    )

    def persisted_control() -> str | None:
        controls = _load_controls(plan, workflow.workflow_digest, root)
        for item in controls[initial_control_count:]:
            if (
                item["task_id"] == task_id
                and item["after_attempt"] == state.attempts + 1
                and item["source_state"] == "RUNNING"
            ):
                return item["action"]
        return None

    sample_control = _cooperative_control_check(control_check, persisted_control)
    request = WeakModelExecutorRequest(
        workflow.workflow_digest,
        current.receipt_set_digest,
        card,
        state.attempts + 1,
        card.max_context_bytes,
        attempt_output,
        attempt_seconds,
        deadline.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        False,
        seconds_remaining,
        output_remaining,
        sample_control,
    )
    if card.requires_current_authorization:
        if not callable(authorization_check) or authorization_check(request) is not True:
            raise WeakModelWorkflowError("current authorization was not explicitly confirmed")
    task_index = next(
        index for index, item in enumerate(plan["tasks"]) if item["task_id"] == task_id
    )
    destination = root / _attempt_name(workflow.workflow_digest, task_index, request.attempt)
    try:
        destination.mkdir()
    except FileExistsError as exc:
        raise WeakModelWorkflowError("workflow attempt already exists") from exc
    except OSError as exc:
        raise WeakModelWorkflowError("workflow attempt cannot be reserved") from exc
    task = plan["tasks"][task_index]
    started_path = destination / "started.json"
    _write_new(started_path, canonical_bytes(_started_record(plan, task, request.attempt)))

    started_ns = monotonic_ns()
    outcome_error: WeakModelWorkflowError | None = None
    try:
        result = _outcome(executor(request), card)
    except Exception as exc:
        outcome_error = (
            exc
            if isinstance(exc, WeakModelWorkflowError)
            else WeakModelWorkflowError("executor callback failed")
        )
        result = WeakModelExecutionOutcome(
            "FAILED", b"", f"Executor attempt failed: {type(exc).__name__}."
        )
    elapsed_ms = max(0, (monotonic_ns() - started_ns) // 1_000_000)
    output_path = destination / "output.bin"
    receipt_path = destination / "receipt.json"
    boundary = _workflow_boundary(root, workflow.workflow_digest)
    try:
        with boundary:
            requested_control = sample_control()
            if requested_control == "CANCEL":
                result = WeakModelExecutionOutcome(
                    "CANCELLED",
                    b"",
                    "Cooperative cancellation was requested during executor work.",
                )
            elif requested_control == "PAUSE":
                result = WeakModelExecutionOutcome(
                    "PAUSED",
                    b"",
                    "Cooperative pause was requested during executor work.",
                )
            elif elapsed_ms > attempt_seconds * 1000:
                result = WeakModelExecutionOutcome(
                    "DEADLINE_EXCEEDED",
                    b"",
                    "Caller returned after the declared deadline.",
                )
            if len(result.output) > attempt_output:
                raise WeakModelWorkflowError(
                    "executor output exceeds remaining workflow budget"
                )
            record = create_executor_receipt(
                plan,
                task_id=task_id,
                status=result.status,
                attempt=request.attempt,
                input_digest=card.instruction_digest,
                output_digest=digest_bytes(result.output),
                output_bytes=len(result.output),
                elapsed_milliseconds=elapsed_ms,
                observation=result.observation,
                block_reason=result.block_reason,
            )
            _write_new(output_path, result.output)
            _write_new(receipt_path, canonical_bytes(record))
    except WeakModelExecutionError as exc:
        raise WeakModelWorkflowError("executor receipt construction failed") from exc
    if outcome_error is not None and requested_control is None:
        raise outcome_error
    persisted = review(workflow, root)
    return next(item for item in persisted.receipts if item.attempt_directory == destination)


def recover_interrupted(
    workflow: WeakModelWorkflowPlan,
    receipt_directory: str | os.PathLike[str],
    *,
    task_id: str,
    caller_confirms_stopped: bool,
) -> WeakModelTaskReceipt:
    _validated(workflow)
    root = _root(receipt_directory)
    with _workflow_boundary(root, workflow.workflow_digest):
        return _recover_interrupted_locked(
            workflow,
            root,
            task_id=task_id,
            caller_confirms_stopped=caller_confirms_stopped,
        )


def _recover_interrupted_locked(
    workflow: WeakModelWorkflowPlan,
    receipt_directory: str | os.PathLike[str],
    *,
    task_id: str,
    caller_confirms_stopped: bool,
) -> WeakModelTaskReceipt:
    """Finalize one incomplete attempt after the caller confirms it stopped."""

    if caller_confirms_stopped is not True:
        raise WeakModelWorkflowError("interrupted recovery requires stopped confirmation")
    plan = _validated(workflow)
    root = _root(receipt_directory)
    task_index = next(
        (
            index
            for index, item in enumerate(plan["tasks"])
            if item["task_id"] == task_id
        ),
        None,
    )
    if task_index is None:
        raise WeakModelWorkflowError(f"unknown task_id: {task_id}")
    task = plan["tasks"][task_index]
    attempt = 0
    destination: Path | None = None
    for candidate in range(1, task["max_attempts"] + 1):
        path = root / _attempt_name(workflow.workflow_digest, task_index, candidate)
        if not path.exists():
            continue
        if not path.is_dir():
            raise WeakModelWorkflowError("workflow attempt is not a directory")
        output_exists = (path / "output.bin").exists()
        receipt_exists = (path / "receipt.json").exists()
        started_exists = (path / "started.json").exists()
        if started_exists and output_exists and receipt_exists:
            continue
        attempt = candidate
        destination = path
        break
    if destination is None:
        raise WeakModelWorkflowError("task has no incomplete attempt to recover")

    started_path = destination / "started.json"
    output_path = destination / "output.bin"
    receipt_path = destination / "receipt.json"
    entries = list(destination.iterdir())
    if not started_path.exists():
        if entries:
            raise WeakModelWorkflowError(
                "attempt without STARTED evidence contains ambiguous files"
            )
        _write_new(
            started_path,
            canonical_bytes(_started_record(plan, task, attempt)),
        )
    else:
        _read_started(plan, task, attempt, started_path)

    if receipt_path.exists() and not output_path.exists():
        try:
            payload = _read_bounded(
                receipt_path, _RECEIPT_RECORD_BYTES_MAX, "executor receipt"
            )
            value = parse_json_strict(payload)
            if not isinstance(value, dict) or canonical_bytes(value) != payload:
                raise WeakModelWorkflowError("executor receipt is not canonical JSON")
            record = validate_executor_receipt(plan, value)
        except (CanonicalError, WeakModelExecutionError) as exc:
            raise WeakModelWorkflowError("executor receipt cannot be loaded") from exc
        if (
            record["task_id"] != task_id
            or record["attempt"] != attempt
            or record["output_bytes"] != 0
            or record["output_digest"] != digest_bytes(b"")
        ):
            raise WeakModelWorkflowError(
                "receipt-only attempt does not bind an empty recoverable output"
            )
        _write_new(output_path, b"")
        current = review(workflow, root)
        return next(
            item for item in current.receipts if item.attempt_directory == destination
        )
    if receipt_path.exists():
        raise WeakModelWorkflowError("complete terminal attempt needs no recovery")

    if output_path.exists():
        output = _read_bounded(
            output_path, task["max_output_bytes"], "executor output"
        )
    else:
        output = b""

    recovery_outcome = "INTERRUPTED"
    recovery_observation = "Caller confirmed the incomplete executor attempt has stopped."
    recovery_reason: str | None = None
    controls = _load_controls(plan, workflow.workflow_digest, root)
    for item in reversed(controls):
        if (
            item["task_id"] == task_id
            and item["after_attempt"] == attempt
            and item["source_state"] == "RUNNING"
        ):
            if item["action"] == "CANCEL":
                recovery_outcome = "CANCELLED"
                recovery_observation = "Caller confirmed the cancelled executor has stopped."
            elif item["action"] == "PAUSE":
                recovery_outcome = "PAUSED"
                recovery_observation = "Caller confirmed the paused executor has stopped."
            break
    destination = root / _attempt_name(workflow.workflow_digest, task_index, attempt)
    record = create_executor_receipt(
        plan,
        task_id=task_id,
        status=recovery_outcome,
        attempt=attempt,
        input_digest=task["instruction_digest"],
        output_digest=digest_bytes(output),
        output_bytes=len(output),
        elapsed_milliseconds=0,
        observation=recovery_observation,
        block_reason=recovery_reason,
    )
    if not output_path.exists():
        _write_new(output_path, output)
    _write_new(receipt_path, canonical_bytes(record))
    current = review(workflow, root)
    return next(
        item for item in current.receipts if item.attempt_directory == destination
    )


def _record_control(
    workflow: WeakModelWorkflowPlan,
    receipt_directory: str | os.PathLike[str],
    *,
    task_id: str,
    action: str,
    decision: str | None = None,
) -> dict[str, Any]:
    plan = _validated(workflow)
    root = _root(receipt_directory)
    with _workflow_boundary(root, workflow.workflow_digest):
        return _record_control_locked(
            workflow,
            root,
            plan,
            task_id=task_id,
            action=action,
            decision=decision,
        )


def _record_control_locked(
    workflow: WeakModelWorkflowPlan,
    root: Path,
    plan: Mapping[str, Any],
    *,
    task_id: str,
    action: str,
    decision: str | None,
) -> dict[str, Any]:
    current = review(workflow, root)
    state = next((item for item in current.task_states if item.task_id == task_id), None)
    if state is None:
        raise WeakModelWorkflowError(f"unknown task_id: {task_id}")
    if action == "RESUME" and state.block_reason == "owner-decision-required":
        raise WeakModelWorkflowError(
            "owner-decision-required must be resolved by an explicit owner decision"
        )
    if action == "OWNER_DECISION" and state.block_reason != "owner-decision-required":
        raise WeakModelWorkflowError("no owner decision is pending for this task")
    _, active_attempts = _load_attempts(plan, workflow.workflow_digest, root)
    if action == "RESUME" and task_id in active_attempts:
        raise WeakModelWorkflowError(
            "active paused attempt must record a terminal receipt before resume"
        )
    controls = _load_controls(plan, workflow.workflow_digest, root)
    try:
        record = create_control_record(
            plan,
            task_id=task_id,
            sequence=len(controls) + 1,
            after_attempt=state.attempts,
            action=action,
            decision=decision,
            source_state=state.status,
        )
    except WeakModelExecutionError as exc:
        raise WeakModelWorkflowError(f"control action is invalid: {exc}") from exc
    path = root / f"wc-{workflow.workflow_digest}-{record['sequence']:04d}.json"
    _write_new(path, canonical_bytes(record))
    return record


def pause(
    workflow: WeakModelWorkflowPlan,
    receipt_directory: str | os.PathLike[str],
    *,
    task_id: str,
) -> dict[str, Any]:
    """Cooperatively block a READY task; running callbacks must stop themselves."""

    return _record_control(workflow, receipt_directory, task_id=task_id, action="PAUSE")


def resume_task(
    workflow: WeakModelWorkflowPlan,
    receipt_directory: str | os.PathLike[str],
    *,
    task_id: str,
) -> dict[str, Any]:
    return _record_control(workflow, receipt_directory, task_id=task_id, action="RESUME")


def cancel(
    workflow: WeakModelWorkflowPlan,
    receipt_directory: str | os.PathLike[str],
    *,
    task_id: str,
) -> dict[str, Any]:
    return _record_control(workflow, receipt_directory, task_id=task_id, action="CANCEL")


def resolve_owner_decision(
    workflow: WeakModelWorkflowPlan,
    receipt_directory: str | os.PathLike[str],
    *,
    task_id: str,
    decision: str,
) -> dict[str, Any]:
    if decision not in {"APPROVED", "DECLINED"}:
        raise WeakModelWorkflowError("owner decision must be APPROVED or DECLINED")
    return _record_control(
        workflow,
        receipt_directory,
        task_id=task_id,
        action="OWNER_DECISION",
        decision=decision,
    )


__all__ = [
    "WeakModelAuthorizationCheck",
    "WeakModelControlCheck",
    "WeakModelExecutionOutcome",
    "WeakModelExecutor",
    "WeakModelExecutorCard",
    "WeakModelExecutorRequest",
    "WeakModelTaskReceipt",
    "WeakModelTaskState",
    "WeakModelWorkflowBudget",
    "WeakModelWorkflowError",
    "WeakModelWorkflowPlan",
    "WeakModelWorkflowResume",
    "WeakModelWorkflowReview",
    "cancel",
    "execute",
    "pause",
    "prepare",
    "recover_interrupted",
    "resolve_owner_decision",
    "resume",
    "resume_task",
    "review",
]
