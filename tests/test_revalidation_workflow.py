from __future__ import annotations

from pathlib import Path

import pytest

from promin.canonical import canonical_bytes, digest_value
from promin.recovery import (
    CleanReinitializationIntent,
    OwnerConfirmation,
    PublishedCleanReinitialization,
    TrackedExtensionRoot,
    admit_clean_state,
    admit_tracked_extensions,
)
from promin.revalidation import (
    ReadOnlyRevalidationCallback,
    RevalidationObservation,
    RevalidationPhase,
    RevalidationPlan,
    RevalidationReceipt,
    RevalidationStatus,
    reconsolidate_revalidation,
)
from promin.revalidation_workflow import (
    MAX_WORKFLOW_PRIOR_RECEIPTS,
    MAX_WORKFLOW_RECEIPT_BYTES,
    REVALIDATION_WORKFLOW_PHASE_SEQUENCE,
    RevalidationWorkflowAuthority,
    RevalidationWorkflowError,
    RevalidationWorkflowMode,
    RevalidationWorkflowPlan,
    RevalidationWorkflowReceipt,
    execute_revalidation_workflow,
    load_revalidation_workflow_receipt,
    plan_revalidation_workflow,
)
from promin.writer_identity import classify_writer_liveness


def _route(*, revision: int = 1) -> RevalidationPlan:
    return RevalidationPlan(
        plan_id="ordinary-revalidation",
        input_identity={
            "activation_identity": digest_value({"activation": revision}),
            "recovery_identity": digest_value({"recovery": revision}),
            "acceptance_pass": False,
            "pass_credit": False,
        },
        phases=(
            RevalidationPhase("inventory", 2.0),
            RevalidationPhase("documentation", 2.0),
        ),
    )


def _authority() -> RevalidationWorkflowAuthority:
    return RevalidationWorkflowAuthority(
        authority_id="owner:ordinary",
        implementation_digest=digest_value({"implementation": 1}),
        configuration_digest=digest_value({"configuration": 1}),
    )


def _inspect_plan(
    root: Path,
    *,
    name: str = "inspect.json",
    route: RevalidationPlan | None = None,
    retry_ordinal: int = 1,
    predecessor: RevalidationWorkflowReceipt | None = None,
    prior_receipts=(),
) -> RevalidationWorkflowPlan:
    return RevalidationWorkflowPlan(
        workflow_id="ordinary-cycle",
        mode=RevalidationWorkflowMode.INSPECT,
        authority=_authority(),
        receipt_root=root,
        receipt_name=name,
        retry_ordinal=retry_ordinal,
        predecessor_receipt_digest=(
            None if predecessor is None else predecessor.receipt_digest
        ),
        predecessor_receipt=predecessor,
        revalidation_plan=_route() if route is None else route,
        prior_receipts=prior_receipts,
    )


def _callback(phase_id: str) -> ReadOnlyRevalidationCallback:
    def evaluate(context) -> RevalidationObservation:
        return RevalidationObservation(
            status=RevalidationStatus.PASS,
            observed_input_digest=context.expected_input_digest,
            output_identity={
                "phase": phase_id,
                "fresh": True,
                "acceptance_pass": False,
                "pass_credit": False,
            },
            reason=None,
        )

    return ReadOnlyRevalidationCallback(phase_id, evaluate)


def _repair_inputs(root: Path):
    source = root / "extension-source"
    tracked = source / ".promin" / "docs"
    tracked.mkdir(parents=True)
    (tracked / "note.md").write_bytes(b"same portable extension\n")
    extensions = admit_tracked_extensions(
        source,
        (
            TrackedExtensionRoot(
                root=".promin/docs",
                max_files=2,
                max_total_bytes=256,
                max_file_bytes=128,
            ),
        ),
    )
    intent = CleanReinitializationIntent(
        project_identity=digest_value({"project": "ordinary"}),
        package_digest=digest_value({"package": "alpha4"}),
        profile_id="minimal",
        extension_admission_digest=extensions.admission_digest,
    )
    admission = admit_clean_state(
        intent,
        OwnerConfirmation(
            owner_id="owner:ordinary",
            confirmation_id="confirmation:ordinary-cycle",
            intent_digest=intent.intent_digest,
            confirmed_at_ns=1,
        ),
        extensions,
    )
    existing = PublishedCleanReinitialization(
        intent_digest=intent.intent_digest,
        package_digest=intent.package_digest,
        extension_admission_digest=intent.extension_admission_digest,
        activation_digest=digest_value({"activation": "fresh"}),
    )
    project = root / "project"
    project.mkdir()
    return project, admission, classify_writer_liveness(None), existing


def _repair_plan(
    receipts: Path,
    predecessor: RevalidationWorkflowReceipt,
    inputs,
    *,
    name: str = "repair.json",
    retry_ordinal: int = 1,
) -> RevalidationWorkflowPlan:
    project, admission, liveness, existing = inputs
    return RevalidationWorkflowPlan(
        workflow_id="ordinary-cycle",
        mode=RevalidationWorkflowMode.REPAIR,
        authority=_authority(),
        receipt_root=receipts,
        receipt_name=name,
        retry_ordinal=retry_ordinal,
        predecessor_receipt_digest=predecessor.receipt_digest,
        predecessor_receipt=predecessor,
        repair_project_root=project,
        repair_admission=admission,
        repair_writer_liveness=liveness,
        repair_existing=existing,
        max_attempts=2,
    )


def _execute_repair(plan: RevalidationWorkflowPlan) -> RevalidationWorkflowReceipt:
    return execute_revalidation_workflow(
        plan,
        repair_verifier=lambda _result: True,
        repair_attempt=lambda _transaction, _ordinal: plan.repair_existing,
    )


def _through_repair(root: Path):
    receipts = root / "receipts"
    receipts.mkdir(parents=True)
    inspected = execute_revalidation_workflow(_inspect_plan(receipts))
    repaired = _execute_repair(
        _repair_plan(receipts, inspected, _repair_inputs(root))
    )
    return receipts, inspected, repaired


def test_plan_only_is_deterministic_path_bound_and_writes_nothing(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first = _inspect_plan(first_root)
    second = _inspect_plan(second_root)

    first_record = plan_revalidation_workflow(first)
    assert first_record == plan_revalidation_workflow(first)
    assert first_record["plan_only"] is True
    assert first_record["filesystem_writes"] == 0
    assert first_record["transition_kind"] == "START"
    assert first_record["phase_sequence"] == list(
        REVALIDATION_WORKFLOW_PHASE_SEQUENCE
    )
    assert first.plan_digest != second.plan_digest
    assert first.workflow_semantic_identity == second.workflow_semantic_identity
    assert first.workflow_semantic_digest == second.workflow_semantic_digest
    assert str(first_root) not in str(first.workflow_semantic_identity)
    assert list(first_root.iterdir()) == []


def test_only_inspect_can_start_and_transitions_cannot_skip(tmp_path: Path) -> None:
    with pytest.raises(RevalidationWorkflowError, match="start with inspect"):
        RevalidationWorkflowPlan(
            workflow_id="ordinary-cycle",
            mode=RevalidationWorkflowMode.REVALIDATE,
            authority=_authority(),
            receipt_root=tmp_path,
            receipt_name="revalidate.json",
            revalidation_plan=_route(),
        )

    inspected = execute_revalidation_workflow(_inspect_plan(tmp_path))
    with pytest.raises(RevalidationWorkflowError, match="transition"):
        RevalidationWorkflowPlan(
            workflow_id="ordinary-cycle",
            mode=RevalidationWorkflowMode.RECONSOLIDATE,
            authority=_authority(),
            receipt_root=tmp_path,
            receipt_name="skipped.json",
            predecessor_receipt_digest=inspected.receipt_digest,
            predecessor_receipt=inspected,
            revalidation_plan=_route(),
        )
    with pytest.raises(RevalidationWorkflowError, match="ordinal one"):
        _repair_plan(
            tmp_path,
            inspected,
            _repair_inputs(tmp_path / "repair-input"),
            retry_ordinal=2,
        )


def test_full_five_phase_cycle_is_one_predecessor_chain(tmp_path: Path) -> None:
    receipts, inspected, repaired = _through_repair(tmp_path)
    route = _route()
    revalidate_plan = RevalidationWorkflowPlan(
        workflow_id="ordinary-cycle",
        mode=RevalidationWorkflowMode.REVALIDATE,
        authority=_authority(),
        receipt_root=receipts,
        receipt_name="revalidate.json",
        predecessor_receipt_digest=repaired.receipt_digest,
        predecessor_receipt=repaired,
        revalidation_plan=route,
    )
    revalidated = execute_revalidation_workflow(
        revalidate_plan,
        callbacks=tuple(_callback(item) for item in revalidate_plan.required_phase_ids),
    )
    reconsolidate_plan = RevalidationWorkflowPlan(
        workflow_id="ordinary-cycle",
        mode=RevalidationWorkflowMode.RECONSOLIDATE,
        authority=_authority(),
        receipt_root=receipts,
        receipt_name="reconsolidate.json",
        predecessor_receipt_digest=revalidated.receipt_digest,
        predecessor_receipt=revalidated,
        revalidation_plan=route,
        prior_receipts=(revalidated.result,),
    )
    reconsolidated = execute_revalidation_workflow(reconsolidate_plan)
    report_plan = RevalidationWorkflowPlan(
        workflow_id="ordinary-cycle",
        mode=RevalidationWorkflowMode.REPORT,
        authority=_authority(),
        receipt_root=receipts,
        receipt_name="report.json",
        predecessor_receipt_digest=reconsolidated.receipt_digest,
        predecessor_receipt=reconsolidated,
        report_receipt=reconsolidated.result,
    )
    reported = execute_revalidation_workflow(report_plan)

    chain = (inspected, repaired, revalidated, reconsolidated, reported)
    assert tuple(item.mode.value for item in chain) == (
        REVALIDATION_WORKFLOW_PHASE_SEQUENCE
    )
    assert [item.transition_kind for item in chain] == [
        "START",
        "ADVANCE",
        "ADVANCE",
        "ADVANCE",
        "ADVANCE",
    ]
    assert all(
        current.predecessor_receipt_digest == previous.receipt_digest
        for previous, current in zip(chain, chain[1:])
    )
    assert len({item.workflow_semantic_digest for item in chain}) == 1
    assert reported.result_kind == "RevalidationReportPreparation"
    assert reported.result["report_authoritative"] is False
    assert reported.result["pass_credit"] is False


def test_same_phase_retry_is_contiguous_and_keeps_the_route(tmp_path: Path) -> None:
    first = execute_revalidation_workflow(_inspect_plan(tmp_path))
    second = execute_revalidation_workflow(
        _inspect_plan(
            tmp_path,
            name="inspect-2.json",
            retry_ordinal=2,
            predecessor=first,
        )
    )
    assert second.transition_kind == "RETRY"
    assert second.retry_ordinal == 2

    with pytest.raises(RevalidationWorkflowError, match="not contiguous"):
        _inspect_plan(
            tmp_path,
            name="inspect-4.json",
            retry_ordinal=4,
            predecessor=second,
        )
    with pytest.raises(RevalidationWorkflowError, match="semantic subject"):
        _inspect_plan(
            tmp_path,
            name="changed.json",
            route=_route(revision=2),
            retry_ordinal=3,
            predecessor=second,
        )


def test_partial_revalidation_retries_only_the_remaining_phase(tmp_path: Path) -> None:
    receipts, _inspected, repaired = _through_repair(tmp_path)
    first_plan = RevalidationWorkflowPlan(
        workflow_id="ordinary-cycle",
        mode=RevalidationWorkflowMode.REVALIDATE,
        authority=_authority(),
        receipt_root=receipts,
        receipt_name="revalidate-1.json",
        predecessor_receipt_digest=repaired.receipt_digest,
        predecessor_receipt=repaired,
        revalidation_plan=_route(),
        max_phases=1,
    )
    first = execute_revalidation_workflow(
        first_plan,
        callbacks=tuple(_callback(item) for item in first_plan.required_phase_ids),
    )
    assert first.result["status"] == "PENDING"

    second_plan = RevalidationWorkflowPlan(
        workflow_id="ordinary-cycle",
        mode=RevalidationWorkflowMode.REVALIDATE,
        authority=_authority(),
        receipt_root=receipts,
        receipt_name="revalidate-2.json",
        retry_ordinal=2,
        predecessor_receipt_digest=first.receipt_digest,
        predecessor_receipt=first,
        revalidation_plan=_route(),
        prior_receipts=(first.result,),
    )
    assert second_plan.required_phase_ids == ("documentation",)
    second = execute_revalidation_workflow(
        second_plan,
        callbacks=(_callback("documentation"),),
    )
    assert second.transition_kind == "RETRY"
    assert second.result["status"] == "PASS"
    assert second.result["pass_credit"] is False


def test_failed_phase_must_retry_before_advance(tmp_path: Path) -> None:
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    inspected = execute_revalidation_workflow(_inspect_plan(receipts))
    inputs = _repair_inputs(tmp_path)
    failed_plan = _repair_plan(receipts, inspected, inputs)

    def unavailable(_result):
        raise RuntimeError("verifier unavailable")

    failed = execute_revalidation_workflow(
        failed_plan,
        repair_verifier=unavailable,
        repair_attempt=lambda _transaction, _ordinal: failed_plan.repair_existing,
    )
    assert failed.execution_state == "FAILURE_RECORDED"
    assert failed.result["pass_credit"] is False
    with pytest.raises(RevalidationWorkflowError, match="retried before advancing"):
        RevalidationWorkflowPlan(
            workflow_id="ordinary-cycle",
            mode=RevalidationWorkflowMode.REVALIDATE,
            authority=_authority(),
            receipt_root=receipts,
            receipt_name="invalid-advance.json",
            predecessor_receipt_digest=failed.receipt_digest,
            predecessor_receipt=failed,
            revalidation_plan=_route(),
        )

    retry_plan = _repair_plan(
        receipts,
        failed,
        inputs,
        name="repair-2.json",
        retry_ordinal=2,
    )
    retried = _execute_repair(retry_plan)
    assert retried.execution_state == "RESULT_RECORDED"
    assert retried.transition_kind == "RETRY"
    assert retried.result["published"] is True


def test_portable_repair_identity_excludes_runtime_project_roots(
    tmp_path: Path,
) -> None:
    roots = []
    for name in ("first", "second"):
        cycle = tmp_path / name
        cycle.mkdir()
        receipts = cycle / "receipts"
        receipts.mkdir()
        inspected = execute_revalidation_workflow(_inspect_plan(receipts))
        repair = _repair_plan(receipts, inspected, _repair_inputs(cycle))
        roots.append(repair)

    first, second = roots
    assert first.workflow_semantic_digest == second.workflow_semantic_digest
    assert first.semantic_subject_identity == second.semantic_subject_identity
    assert first.semantic_subject_digest == second.semantic_subject_digest
    assert first.subject_digest != second.subject_digest
    assert first.plan_digest != second.plan_digest
    assert str(first.repair_project_root) not in str(first.semantic_subject_identity)
    assert str(second.repair_project_root) not in str(second.semantic_subject_identity)


def test_collectors_and_receipt_reads_are_bounded_before_materialization(
    tmp_path: Path,
) -> None:
    receipt = reconsolidate_revalidation(_route())
    history_seen = 0

    def history():
        nonlocal history_seen
        for _ in range(MAX_WORKFLOW_PRIOR_RECEIPTS + 20):
            history_seen += 1
            yield receipt

    with pytest.raises(RevalidationWorkflowError, match="history exceeds"):
        _inspect_plan(tmp_path, prior_receipts=history())
    assert history_seen == MAX_WORKFLOW_PRIOR_RECEIPTS + 1

    receipts, _inspected, repaired = _through_repair(tmp_path / "callback-cycle")
    plan = RevalidationWorkflowPlan(
        workflow_id="ordinary-cycle",
        mode=RevalidationWorkflowMode.REVALIDATE,
        authority=_authority(),
        receipt_root=receipts,
        receipt_name="too-many-callbacks.json",
        predecessor_receipt_digest=repaired.receipt_digest,
        predecessor_receipt=repaired,
        revalidation_plan=_route(),
    )
    callback_seen = 0

    def callbacks():
        nonlocal callback_seen
        for _ in range(MAX_WORKFLOW_PRIOR_RECEIPTS + 20):
            callback_seen += 1
            yield _callback("inventory")

    with pytest.raises(RevalidationWorkflowError, match="callbacks exceeds"):
        execute_revalidation_workflow(plan, callbacks=callbacks())
    assert callback_seen == MAX_WORKFLOW_PRIOR_RECEIPTS + 1

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * (MAX_WORKFLOW_RECEIPT_BYTES + 1))
    with pytest.raises(RevalidationWorkflowError, match="cannot be read"):
        load_revalidation_workflow_receipt(oversized)


def test_receipt_is_canonical_create_only_and_round_trips(tmp_path: Path) -> None:
    plan = _inspect_plan(tmp_path)
    receipt = execute_revalidation_workflow(plan)
    path = tmp_path / "inspect.json"
    assert path.read_bytes() == canonical_bytes(receipt.to_record())
    assert load_revalidation_workflow_receipt(
        path, expected_plan_digest=plan.plan_digest
    ) == receipt
    with pytest.raises(RevalidationWorkflowError, match="already exists"):
        execute_revalidation_workflow(plan)


def test_failed_callback_records_no_acceptance_and_can_be_reconsolidated(
    tmp_path: Path,
) -> None:
    receipts, _inspected, repaired = _through_repair(tmp_path)
    plan = RevalidationWorkflowPlan(
        workflow_id="ordinary-cycle",
        mode=RevalidationWorkflowMode.REVALIDATE,
        authority=_authority(),
        receipt_root=receipts,
        receipt_name="failed-revalidation.json",
        predecessor_receipt_digest=repaired.receipt_digest,
        predecessor_receipt=repaired,
        revalidation_plan=_route(),
    )

    def failed(_context):
        raise RuntimeError("ordinary callback failure")

    result = execute_revalidation_workflow(
        plan,
        callbacks=tuple(
            ReadOnlyRevalidationCallback(item, failed)
            for item in plan.required_phase_ids
        ),
    )
    assert result.result["status"] == "FAIL"
    assert result.result["pass_credit"] is False

    reconsolidated = execute_revalidation_workflow(
        RevalidationWorkflowPlan(
            workflow_id="ordinary-cycle",
            mode=RevalidationWorkflowMode.RECONSOLIDATE,
            authority=_authority(),
            receipt_root=receipts,
            receipt_name="failure-reconsolidated.json",
            predecessor_receipt_digest=result.receipt_digest,
            predecessor_receipt=result,
            revalidation_plan=_route(),
            prior_receipts=(result.result,),
        )
    )
    assert reconsolidated.result["status"] == "FAIL"
    assert reconsolidated.result["acceptance_pass"] is False
