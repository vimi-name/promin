from __future__ import annotations

from pathlib import Path
from threading import Event, Lock, Thread

import pytest

from promin.canonical import parse_json_strict
from promin.weak_model_execution import validate_high_level_plan
from promin.weak_model_workflow import (
    WeakModelExecutionOutcome,
    WeakModelWorkflowError,
    cancel,
    execute,
    pause,
    prepare,
    recover_interrupted,
    resolve_owner_decision,
    resume,
    resume_task,
    review,
)


def _budget(**changes: int) -> dict[str, int]:
    value = {
        "max_high_level_tasks": 8,
        "max_executor_tasks": 8,
        "max_dependencies_per_task": 4,
        "max_resources_per_task": 3,
        "max_task_instruction_bytes": 4096,
        "max_task_context_bytes": 8192,
        "max_task_output_bytes": 2048,
        "max_attempt_seconds": 30,
        "max_attempts_per_task": 2,
        "max_parallel_tasks": 2,
        "max_workflow_seconds": 120,
        "max_workflow_output_bytes": 4096,
    }
    value.update(changes)
    return value


def _task(task_id: str, dependencies: list[str], *, owner: bool = False) -> dict[str, object]:
    return {
        "task_id": task_id,
        "title": f"Run {task_id}",
        "objective": f"Perform arbitrary compute, API, or communication work for {task_id}.",
        "dependencies": dependencies,
        "task_mode": "managed",
        "resources": [],
        "acceptance_predicate": f"{task_id} returns reviewable evidence.",
        "requires_current_authorization": False,
        "requires_owner_decision": owner,
    }


def _plan(*, owner: bool = False, **budget_changes: int) -> dict[str, object]:
    return {
        "schema": "promin.high-level-execution-plan.v1",
        "plan_id": "branched-work",
        "budget": _budget(**budget_changes),
        "tasks": [
            _task("combine", ["api", "compute"]),
            _task("compute", ["source"]),
            _task("api", ["source"]),
            _task("source", [], owner=owner),
        ],
    }


def _complete(_request) -> WeakModelExecutionOutcome:
    return WeakModelExecutionOutcome("COMPLETED", b"evidence\n", "Evidence recorded.")


def test_prepare_preserves_source_dag_and_one_card_per_arbitrary_task() -> None:
    first = prepare(_plan())
    second = prepare(_plan())
    assert first == second
    assert first.selection_policy == "deterministic-source-dag-core-state-budget"
    assert first.execution_plan_document()["source_plan"] == validate_high_level_plan(_plan())
    assert [card.task_id for card in first.cards] == [
        "source:execute",
        "api:execute",
        "compute:execute",
        "combine:execute",
    ]
    assert all(card.resources == () for card in first.cards)
    assert all(card.pass_credit is False for card in first.cards)


def test_execute_branched_dag_and_request_has_control_budgets(tmp_path: Path) -> None:
    workflow = prepare(_plan())
    seen = []

    def source(request):
        seen.append(request)
        return _complete(request)

    execute(workflow, tmp_path, task_id="source:execute", executor=source)
    request = seen[0]
    assert request.max_context_bytes == 8192
    assert request.max_output_bytes == 2048
    assert request.max_attempt_seconds == 30
    assert request.cancellation_requested is False
    assert request.deadline_utc.endswith("Z")
    assert {card.task_id for card in resume(workflow, tmp_path).ready_cards} == {
        "api:execute",
        "compute:execute",
    }


def test_pause_resume_and_cancel_are_durable_cooperative_controls(tmp_path: Path) -> None:
    workflow = prepare(_plan())
    pause(workflow, tmp_path, task_id="source:execute")
    paused = review(workflow, tmp_path)
    assert paused.task_states[0].status == "BLOCKED"
    assert paused.task_states[0].block_reason == "pause-requested"
    resume_task(workflow, tmp_path, task_id="source:execute")
    assert [item.task_id for item in review(workflow, tmp_path).ready_cards] == [
        "source:execute"
    ]
    cancel(workflow, tmp_path, task_id="source:execute")
    assert all(item.status == "CANCELLED" for item in review(workflow, tmp_path).task_states)


@pytest.mark.parametrize(
    ("decision", "state"), [("APPROVED", "READY"), ("DECLINED", "CANCELLED")]
)
def test_owner_decision_approve_or_decline_is_durable(
    tmp_path: Path, decision: str, state: str
) -> None:
    workflow = prepare(_plan(owner=True))
    assert review(workflow, tmp_path).owner_decision_task_ids == ("source:execute",)
    resolve_owner_decision(
        workflow, tmp_path, task_id="source:execute", decision=decision
    )
    current = review(workflow, tmp_path)
    assert current.task_states[0].status == state


def test_mismatched_control_is_rejected_before_any_record_is_written(
    tmp_path: Path,
) -> None:
    owner_workflow = prepare(_plan(owner=True))
    with pytest.raises(WeakModelWorkflowError, match="explicit owner decision"):
        resume_task(owner_workflow, tmp_path, task_id="source:execute")
    assert list(tmp_path.glob("wc-*.json")) == []

    ordinary_workflow = prepare(_plan())
    execute(
        ordinary_workflow,
        tmp_path,
        task_id="source:execute",
        executor=lambda _request: WeakModelExecutionOutcome(
            "FAILED", b"", "Ordinary executor failure."
        ),
    )
    with pytest.raises(WeakModelWorkflowError, match="no owner decision"):
        resolve_owner_decision(
            ordinary_workflow,
            tmp_path,
            task_id="source:execute",
            decision="APPROVED",
        )
    assert list(tmp_path.glob("wc-*.json")) == []


def test_executor_exception_keeps_started_evidence_and_is_resumable(tmp_path: Path) -> None:
    workflow = prepare(_plan())

    def interrupted(_request):
        raise RuntimeError("lost worker")

    with pytest.raises(WeakModelWorkflowError, match="callback failed"):
        execute(workflow, tmp_path, task_id="source:execute", executor=interrupted)
    current = review(workflow, tmp_path)
    assert current.receipts[0].started_path.is_file()
    assert current.task_states[0].status == "BLOCKED"
    assert current.task_states[0].block_reason == "executor-failed"
    assert [item.task_id for item in current.resumable_cards] == ["source:execute"]


def test_started_without_terminal_is_running_until_explicit_recovery(tmp_path: Path) -> None:
    workflow = prepare(_plan())

    def stop_after_started(_request):
        attempt = next(tmp_path.glob("wm-*-a01"))
        assert (attempt / "started.json").is_file()
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        execute(workflow, tmp_path, task_id="source:execute", executor=stop_after_started)
    current = review(workflow, tmp_path)
    assert current.receipts == ()
    assert current.task_states[0].status == "RUNNING"
    assert current.task_states[0].block_reason is None
    with pytest.raises(WeakModelWorkflowError, match="stopped confirmation"):
        recover_interrupted(
            workflow,
            tmp_path,
            task_id="source:execute",
            caller_confirms_stopped=False,
        )
    recovered = recover_interrupted(
        workflow,
        tmp_path,
        task_id="source:execute",
        caller_confirms_stopped=True,
    )
    assert recovered.record_document()["attempt_outcome"] == "INTERRUPTED"
    recovered_review = review(workflow, tmp_path)
    assert recovered_review.task_states[0].status == "BLOCKED"
    assert recovered_review.task_states[0].block_reason == "executor-interrupted"


@pytest.mark.parametrize("action", ["PAUSE", "CANCEL"])
def test_threaded_active_control_is_observed_and_terminal_history_is_coherent(
    tmp_path: Path, action: str
) -> None:
    workflow = prepare(_plan())
    entered = Event()
    release = Event()
    results: list[object] = []

    def executor(request):
        entered.set()
        assert release.wait(5)
        results.append(request.control_check())
        return WeakModelExecutionOutcome(
            "COMPLETED", b"ignored", "Executor attempted to complete."
        )

    def run() -> None:
        try:
            results.append(
                execute(
                    workflow,
                    tmp_path,
                    task_id="source:execute",
                    executor=executor,
                )
            )
        except BaseException as exc:  # test captures the worker failure verbatim
            results.append(exc)

    thread = Thread(target=run)
    thread.start()
    assert entered.wait(5)
    active = review(workflow, tmp_path)
    assert active.task_states[0].status == "RUNNING"
    if action == "PAUSE":
        pause(workflow, tmp_path, task_id="source:execute")
        with pytest.raises(WeakModelWorkflowError, match="terminal receipt"):
            resume_task(workflow, tmp_path, task_id="source:execute")
    else:
        cancel(workflow, tmp_path, task_id="source:execute")
    release.set()
    thread.join(5)
    assert not thread.is_alive()
    assert action in results
    assert not any(isinstance(item, BaseException) for item in results)
    terminal = review(workflow, tmp_path)
    expected = "BLOCKED" if action == "PAUSE" else "CANCELLED"
    assert terminal.task_states[0].status == expected
    if action == "PAUSE":
        resume_task(workflow, tmp_path, task_id="source:execute")
        resumed = review(workflow, tmp_path)
        assert resumed.task_states[0].status == "READY"
        assert [item.task_id for item in resumed.ready_cards] == ["source:execute"]


@pytest.mark.parametrize(
    ("action", "status", "reason"),
    [
        ("PAUSE", "BLOCKED", "pause-requested"),
        ("CANCEL", "CANCELLED", None),
    ],
)
def test_active_control_overrides_executor_exception_terminalization(
    tmp_path: Path, action: str, status: str, reason: str | None
) -> None:
    workflow = prepare(_plan())
    entered = Event()
    release = Event()
    results: list[object] = []

    def executor(_request):
        entered.set()
        assert release.wait(5)
        raise RuntimeError("executor failed after control was requested")

    def run() -> None:
        try:
            results.append(
                execute(
                    workflow,
                    tmp_path,
                    task_id="source:execute",
                    executor=executor,
                )
            )
        except BaseException as exc:  # test captures worker failure verbatim
            results.append(exc)

    thread = Thread(target=run)
    thread.start()
    assert entered.wait(5)
    if action == "PAUSE":
        pause(workflow, tmp_path, task_id="source:execute")
    else:
        cancel(workflow, tmp_path, task_id="source:execute")
    release.set()
    thread.join(5)
    assert not thread.is_alive()
    assert not any(isinstance(item, BaseException) for item in results)

    terminal = review(workflow, tmp_path)
    assert terminal.task_states[0].status == status
    assert terminal.task_states[0].block_reason == reason
    record = terminal.receipts[0].record_document()
    assert record["attempt_outcome"] == (
        "PAUSED" if action == "PAUSE" else "CANCELLED"
    )
    assert record["output_bytes"] == 0


@pytest.mark.parametrize("action", ["PAUSE", "CANCEL"])
def test_terminal_publication_serializes_late_active_control_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    import promin.weak_model_workflow as workflow_module

    workflow = prepare(_plan())
    publication_entered = Event()
    release_publication = Event()
    control_started = Event()
    control_finished = Event()
    execute_results: list[object] = []
    control_results: list[object] = []
    original_write = workflow_module._write_new

    def gated_write(path: Path, payload: bytes) -> None:
        # This is after the final control sample and inside the shared
        # admission/publication boundary.
        if path.name == "output.bin":
            publication_entered.set()
            assert release_publication.wait(5)
        original_write(path, payload)

    monkeypatch.setattr(workflow_module, "_write_new", gated_write)

    def run_execute() -> None:
        try:
            execute_results.append(
                execute(
                    workflow,
                    tmp_path,
                    task_id="source:execute",
                    executor=_complete,
                )
            )
        except BaseException as exc:  # test captures worker failure verbatim
            execute_results.append(exc)

    def run_control() -> None:
        control_started.set()
        try:
            if action == "PAUSE":
                control_results.append(
                    pause(workflow, tmp_path, task_id="source:execute")
                )
            else:
                control_results.append(
                    cancel(workflow, tmp_path, task_id="source:execute")
                )
        except BaseException as exc:  # test captures control result verbatim
            control_results.append(exc)
        finally:
            control_finished.set()

    execute_thread = Thread(target=run_execute)
    execute_thread.start()
    assert publication_entered.wait(5)
    control_thread = Thread(target=run_control)
    control_thread.start()
    assert control_started.wait(5)
    assert not control_finished.is_set()
    release_publication.set()
    execute_thread.join(5)
    control_thread.join(5)
    assert not execute_thread.is_alive()
    assert not control_thread.is_alive()
    assert not any(isinstance(item, BaseException) for item in execute_results)
    assert len(control_results) == 1
    assert isinstance(control_results[0], WeakModelWorkflowError)

    terminal = review(workflow, tmp_path)
    assert terminal.workflow_state == "ACTIVE"
    assert terminal.task_states[0].status == "COMPLETED"
    assert terminal.receipts[0].record_document()["attempt_outcome"] == "COMPLETED"
    assert list(tmp_path.glob("wc-*.json")) == []


def test_different_task_controls_share_one_workflow_sequence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import promin.weak_model_workflow as workflow_module

    source = _plan()
    source["tasks"] = [_task("first", []), _task("second", [])]
    workflow = prepare(source)
    first_write_entered = Event()
    release_first_write = Event()
    second_started = Event()
    second_finished = Event()
    gate = Lock()
    first_write_selected = False
    results: list[object] = []
    original_write = workflow_module._write_new

    def gated_write(path: Path, payload: bytes) -> None:
        nonlocal first_write_selected
        if path.name.startswith("wc-"):
            with gate:
                is_first = not first_write_selected
                first_write_selected = True
            if is_first:
                first_write_entered.set()
                assert release_first_write.wait(5)
        original_write(path, payload)

    monkeypatch.setattr(workflow_module, "_write_new", gated_write)

    def run(task_id: str) -> None:
        if task_id == "second:execute":
            second_started.set()
        try:
            results.append(pause(workflow, tmp_path, task_id=task_id))
        except BaseException as exc:  # test captures control result verbatim
            results.append(exc)
        finally:
            if task_id == "second:execute":
                second_finished.set()

    first = Thread(target=run, args=("first:execute",))
    second = Thread(target=run, args=("second:execute",))
    first.start()
    assert first_write_entered.wait(5)
    second.start()
    assert second_started.wait(5)
    assert not second_finished.wait(0.1)
    release_first_write.set()
    first.join(5)
    second.join(5)
    assert not first.is_alive()
    assert not second.is_alive()
    assert not any(isinstance(item, BaseException) for item in results)
    assert sorted(item["sequence"] for item in results) == [1, 2]
    assert [path.name[-9:-5] for path in sorted(tmp_path.glob("wc-*.json"))] == [
        "0001",
        "0002",
    ]


def test_explicit_recovery_covers_empty_reservation_and_output_only_window(
    tmp_path: Path,
) -> None:
    workflow = prepare(_plan())
    empty = tmp_path / f"wm-{workflow.workflow_digest}-000-a01"
    empty.mkdir()
    recovered = recover_interrupted(
        workflow,
        tmp_path,
        task_id="source:execute",
        caller_confirms_stopped=True,
    )
    assert recovered.started_path.is_file()
    assert recovered.record_document()["attempt_outcome"] == "INTERRUPTED"

    second_root = tmp_path / "output-only"
    second_root.mkdir()
    second = prepare(_plan())

    def stop(_request):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        execute(second, second_root, task_id="source:execute", executor=stop)
    output = b"observed partial output"
    attempt = next(second_root.glob("wm-*-a01"))
    (attempt / "output.bin").write_bytes(output)
    preserved = recover_interrupted(
        second,
        second_root,
        task_id="source:execute",
        caller_confirms_stopped=True,
    )
    assert preserved.output_path is not None
    assert preserved.output_path.read_bytes() == output
    assert preserved.output_bytes == len(output)
    assert preserved.record_document()["attempt_outcome"] == "INTERRUPTED"


def test_explicit_recovery_recreates_only_empty_receipt_bound_output(
    tmp_path: Path,
) -> None:
    source = _plan()
    source["tasks"] = [_task("source", [])]
    empty_workflow = prepare(source)
    receipt = execute(
        empty_workflow,
        tmp_path,
        task_id="source:execute",
        executor=lambda _request: WeakModelExecutionOutcome(
            "COMPLETED", b"", "Empty output completed."
        ),
    )
    assert receipt.output_path is not None
    receipt.output_path.unlink()
    restored = recover_interrupted(
        empty_workflow,
        tmp_path,
        task_id="source:execute",
        caller_confirms_stopped=True,
    )
    assert restored.output_path is not None
    assert restored.output_path.read_bytes() == b""

    nonempty_root = tmp_path / "nonempty"
    nonempty_root.mkdir()
    nonempty_workflow = prepare(source)
    nonempty = execute(
        nonempty_workflow,
        nonempty_root,
        task_id="source:execute",
        executor=_complete,
    )
    assert nonempty.output_path is not None
    nonempty.output_path.unlink()
    with pytest.raises(WeakModelWorkflowError, match="does not bind an empty"):
        recover_interrupted(
            nonempty_workflow,
            nonempty_root,
            task_id="source:execute",
            caller_confirms_stopped=True,
        )


def test_attempt_and_workflow_output_budgets_are_enforced(tmp_path: Path) -> None:
    workflow = prepare(_plan(max_task_output_bytes=4, max_workflow_output_bytes=4))
    with pytest.raises(WeakModelWorkflowError, match="output exceeds"):
        execute(
            workflow,
            tmp_path,
            task_id="source:execute",
            executor=lambda _request: WeakModelExecutionOutcome(
                "COMPLETED", b"12345", "Too much output."
            ),
        )


def test_started_record_is_canonical_and_false_claiming(tmp_path: Path) -> None:
    workflow = prepare(_plan())
    execute(workflow, tmp_path, task_id="source:execute", executor=_complete)
    started = next(tmp_path.glob("wm-*-a01/started.json"))
    value = parse_json_strict(started.read_bytes())
    assert value["transitions"] == ["LEASED", "RUNNING"]
    assert value["projection_authoritative"] is False
    assert value["authority_granted"] is False
    assert value["pass_credit"] is False


@pytest.mark.parametrize(
    ("action", "status", "reason"),
    [
        ("PAUSE", "BLOCKED", "pause-requested"),
        ("CANCEL", "CANCELLED", None),
    ],
)
def test_active_executor_control_hook_is_latched_and_overrides_completion(
    tmp_path: Path, action: str, status: str, reason: str | None
) -> None:
    workflow = prepare(_plan())
    observations = iter([action, None])
    seen: list[str | None] = []

    def worker(request):
        seen.append(request.control_check())
        return WeakModelExecutionOutcome(
            "COMPLETED", b"ignored", "Executor attempted to complete."
        )

    receipt = execute(
        workflow,
        tmp_path,
        task_id="source:execute",
        executor=worker,
        control_check=lambda: next(observations),
    )
    record = receipt.record_document()
    assert seen == [action]
    assert record["status"] == status
    assert record["block_reason"] == reason
    assert record["output_bytes"] == 0
    assert record["attempt_outcome"] == (
        "PAUSED" if action == "PAUSE" else "CANCELLED"
    )


def test_actual_elapsed_is_preserved_while_budget_charge_blocks_more_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import promin.weak_model_workflow as workflow_module

    ticks = iter([0, 1_500_000_000])
    monkeypatch.setattr(workflow_module, "monotonic_ns", lambda: next(ticks))
    workflow = prepare(_plan(max_attempt_seconds=1, max_workflow_seconds=1))
    receipt = execute(
        workflow, tmp_path, task_id="source:execute", executor=_complete
    )
    record = receipt.record_document()
    assert record["attempt_outcome"] == "DEADLINE_EXCEEDED"
    assert record["elapsed_milliseconds"] == 1500
    assert record["budget_elapsed_milliseconds"] == 1000

    current = review(workflow, tmp_path)
    assert current.workflow_elapsed_milliseconds == 1500
    assert current.workflow_budget_elapsed_milliseconds == 1000
    assert current.workflow_time_budget_exhausted is True
    assert current.workflow_state == "BLOCKED_FINAL"
    assert current.ready_cards == ()
    assert current.resumable_cards == ()
    with pytest.raises(WeakModelWorkflowError, match="time budget is exhausted"):
        execute(workflow, tmp_path, task_id="source:execute", executor=_complete)


def test_actual_overrun_is_not_reusable_when_charge_is_below_workflow_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import promin.weak_model_workflow as workflow_module

    ticks = iter([0, 2_500_000_000])
    monkeypatch.setattr(workflow_module, "monotonic_ns", lambda: next(ticks))
    workflow = prepare(
        _plan(max_attempt_seconds=1, max_workflow_seconds=2)
    )
    execute(workflow, tmp_path, task_id="source:execute", executor=_complete)
    current = review(workflow, tmp_path)
    assert current.workflow_elapsed_milliseconds == 2500
    assert current.workflow_budget_elapsed_milliseconds == 1000
    assert current.workflow_time_budget_exhausted is True
    with pytest.raises(WeakModelWorkflowError, match="time budget is exhausted"):
        execute(workflow, tmp_path, task_id="source:execute", executor=_complete)


def test_zero_workflow_output_budget_allows_empty_execution(tmp_path: Path) -> None:
    workflow = prepare(
        _plan(max_task_output_bytes=0, max_workflow_output_bytes=0)
    )
    initial = review(workflow, tmp_path)
    assert initial.workflow_output_budget_exhausted is False
    receipt = execute(
        workflow,
        tmp_path,
        task_id="source:execute",
        executor=lambda request: WeakModelExecutionOutcome(
            "COMPLETED",
            b"",
            f"Completed with max output {request.max_output_bytes} bytes.",
        ),
    )
    assert receipt.output_bytes == 0
    current = review(workflow, tmp_path)
    assert current.workflow_output_bytes == 0
    assert current.workflow_output_budget_exhausted is False


def test_aggregate_workflow_state_is_deterministic_for_a_mixed_dag(
    tmp_path: Path,
) -> None:
    source = _plan()
    source["tasks"] = [
        _task("owner-step", [], owner=True),
        _task("independent", []),
    ]
    workflow = prepare(source)
    assert review(workflow, tmp_path).workflow_state == "ACTIVE"
    execute(workflow, tmp_path, task_id="independent:execute", executor=_complete)
    waiting = review(workflow, tmp_path)
    assert waiting.workflow_state == "OWNER_DECISION_REQUIRED"
    assert resume(workflow, tmp_path).workflow_state == "OWNER_DECISION_REQUIRED"
    resolve_owner_decision(
        workflow,
        tmp_path,
        task_id="owner-step:execute",
        decision="DECLINED",
    )
    assert review(workflow, tmp_path).workflow_state == "CANCELLED"

    completed_root = tmp_path / "completed"
    completed_root.mkdir()
    completed_source = _plan()
    completed_source["tasks"] = [_task("only", [])]
    completed = prepare(completed_source)
    execute(completed, completed_root, task_id="only:execute", executor=_complete)
    assert review(completed, completed_root).workflow_state == "COMPLETED"


@pytest.mark.parametrize("record_name", ["started.json", "receipt.json", "output.bin"])
def test_attempt_files_are_read_with_declared_bounds(
    tmp_path: Path, record_name: str
) -> None:
    workflow = prepare(_plan())
    execute(workflow, tmp_path, task_id="source:execute", executor=_complete)
    path = next(tmp_path.glob(f"wm-*-a01/{record_name}"))
    with path.open("ab") as stream:
        stream.write(b"x" * 4097)
    with pytest.raises(WeakModelWorkflowError, match="declared read bound"):
        review(workflow, tmp_path)


def test_control_enumeration_stops_at_the_declared_workflow_bound(
    tmp_path: Path,
) -> None:
    source = _plan(max_attempts_per_task=1)
    source["tasks"] = [_task("source", [])]
    workflow = prepare(source)
    for sequence in range(1, 5):
        (tmp_path / f"wc-{workflow.workflow_digest}-{sequence:04d}.json").write_bytes(b"{}")
    with pytest.raises(WeakModelWorkflowError, match="control records exceed"):
        review(workflow, tmp_path)
