from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from promin.gate_admission import (
    GateAdmissionError,
    GatePhaseReceipt,
    InvalidationClass,
    ToolAvailability,
    VerificationStatus,
    classify_invalidation,
    evaluate_gate_admission,
    gate_plan_for_invalidation,
)


_INPUT = hashlib.sha256(b"alpha4-gate-input").hexdigest()


def _pass(plan: object, phase_id: str, *, elapsed: float = 0.01) -> GatePhaseReceipt:
    # Test helper intentionally derives scope/input from the plan's public
    # fields instead of duplicating a gate-plan implementation.
    return GatePhaseReceipt(
        phase_id=phase_id,
        availability=ToolAvailability.AVAILABLE,
        status=VerificationStatus.PASS,
        elapsed_seconds=elapsed,
        input_digest=plan.input_digest,  # type: ignore[attr-defined]
        scope_count=plan.scope_count,  # type: ignore[attr-defined]
    )


def test_typed_invalidation_keeps_git_head_out_of_expensive_provider_routes() -> None:
    assert classify_invalidation({"git-head"}) is InvalidationClass.BODY_ONLY
    assert classify_invalidation({"body"}) is InvalidationClass.BODY_ONLY
    assert classify_invalidation({"import-surface", "git-head"}) is InvalidationClass.IMPORT_SURFACE
    assert classify_invalidation({"cmake-topology", "body"}) is InvalidationClass.CMAKE_TOPOLOGY
    assert classify_invalidation({"tooling-only"}) is InvalidationClass.TOOLING_ONLY

    plan = gate_plan_for_invalidation(
        InvalidationClass.BODY_ONLY,
        input_digest=_INPUT,
        scope_count=4,
    )
    assert plan.phase_ids == ("cheap-source", "affected-semantic", "dependency-reuse")
    assert "single-configure" not in plan.phase_ids
    assert "provider-refresh" not in plan.phase_ids
    assert plan.as_dict()["git_head_alone_is_invalidation"] is False


def test_each_invalidation_class_has_a_bounded_cheapest_sufficient_plan() -> None:
    expected = {
        InvalidationClass.IMPORT_SURFACE: (
            "cheap-source",
            "module-graph-refresh",
            "bounded-provider-delta",
        ),
        InvalidationClass.CMAKE_TOPOLOGY: (
            "cheap-source",
            "single-configure",
            "module-graph-refresh",
            "provider-refresh",
        ),
        InvalidationClass.TOOLING_ONLY: ("tool-tests",),
    }
    for invalidation, phase_ids in expected.items():
        plan = gate_plan_for_invalidation(
            invalidation,
            input_digest=_INPUT,
            scope_count=8,
        )
        assert plan.phase_ids == phase_ids
        assert plan.host_budget_seconds == sum(phase.budget_seconds for phase in plan.phases)
        assert plan.as_dict()["pass_credit"] is False
        assert plan.as_dict()["acceptance_pass"] is False


def test_cheap_failure_blocks_every_later_expensive_gate_without_credit() -> None:
    plan = gate_plan_for_invalidation(
        InvalidationClass.CMAKE_TOPOLOGY,
        input_digest=_INPUT,
        scope_count=3,
    )
    failed = GatePhaseReceipt(
        phase_id="cheap-source",
        availability=ToolAvailability.AVAILABLE,
        status=VerificationStatus.FAIL,
        elapsed_seconds=0.01,
        input_digest=plan.input_digest,
        scope_count=plan.scope_count,
        reason="syntax invariant failed",
    )

    result = evaluate_gate_admission(plan, (failed,))
    assert result.status is VerificationStatus.FAIL
    assert result.executed_phase_ids == ("cheap-source",)
    assert result.blocked_phase_ids == (
        "single-configure",
        "module-graph-refresh",
        "provider-refresh",
    )
    assert result.admission_pass is False
    assert result.pass_credit is False
    assert result.acceptance_pass is False

    with pytest.raises(GateAdmissionError, match="non-passing"):
        evaluate_gate_admission(plan, (failed, _pass(plan, "single-configure")))


def test_unavailable_and_skipped_tools_never_obtain_pass_credit() -> None:
    plan = gate_plan_for_invalidation(
        InvalidationClass.TOOLING_ONLY,
        input_digest=_INPUT,
        scope_count=1,
    )
    unavailable = GatePhaseReceipt(
        phase_id="tool-tests",
        availability=ToolAvailability.UNAVAILABLE,
        status=VerificationStatus.UNAVAILABLE,
        elapsed_seconds=0.0,
        input_digest=plan.input_digest,
        scope_count=plan.scope_count,
        reason="clang-tidy is not installed",
    )
    unavailable_result = evaluate_gate_admission(plan, (unavailable,))
    assert unavailable_result.status is VerificationStatus.UNAVAILABLE
    assert unavailable_result.pass_credit is False

    skipped = GatePhaseReceipt(
        phase_id="tool-tests",
        availability=ToolAvailability.AVAILABLE,
        status=VerificationStatus.SKIPPED,
        elapsed_seconds=0.0,
        input_digest=plan.input_digest,
        scope_count=plan.scope_count,
        reason="user declined optional tooling",
    )
    skipped_result = evaluate_gate_admission(plan, (skipped,))
    assert skipped_result.status is VerificationStatus.SKIPPED
    assert skipped_result.pass_credit is False


def test_complete_passing_admission_is_not_product_acceptance() -> None:
    plan = gate_plan_for_invalidation(
        InvalidationClass.BODY_ONLY,
        input_digest=_INPUT,
        scope_count=2,
    )
    result = evaluate_gate_admission(
        plan,
        tuple(_pass(plan, phase_id) for phase_id in plan.phase_ids),
    )
    assert result.status is VerificationStatus.PASS
    assert result.admission_pass is True
    assert result.pass_credit is False
    assert result.acceptance_pass is False
    assert result.receipt_digest


def test_missing_or_mismatched_receipts_fail_closed_before_admission() -> None:
    plan = gate_plan_for_invalidation(
        InvalidationClass.IMPORT_SURFACE,
        input_digest=_INPUT,
        scope_count=7,
    )
    incomplete = evaluate_gate_admission(plan, (_pass(plan, "cheap-source"),))
    assert incomplete.status is VerificationStatus.UNAVAILABLE
    assert incomplete.blocked_phase_ids == ("module-graph-refresh", "bounded-provider-delta")
    assert incomplete.pass_credit is False

    wrong_digest = GatePhaseReceipt(
        phase_id="cheap-source",
        availability=ToolAvailability.AVAILABLE,
        status=VerificationStatus.PASS,
        elapsed_seconds=0.01,
        input_digest="f" * 64,
        scope_count=plan.scope_count,
    )
    with pytest.raises(GateAdmissionError, match="declared input scope"):
        evaluate_gate_admission(plan, (wrong_digest,))


def test_phase_and_host_budget_overruns_are_fail_closed() -> None:
    plan = gate_plan_for_invalidation(
        InvalidationClass.BODY_ONLY,
        input_digest=_INPUT,
        scope_count=1,
        host_budget_seconds=0.05,
    )
    result = evaluate_gate_admission(plan, (_pass(plan, "cheap-source", elapsed=0.06),))
    assert result.status is VerificationStatus.FAIL
    assert result.reason == "declared host budget exceeded"
    assert result.pass_credit is False

    normal = gate_plan_for_invalidation(
        InvalidationClass.BODY_ONLY,
        input_digest=_INPUT,
        scope_count=1,
    )
    overrun = evaluate_gate_admission(
        normal,
        (_pass(normal, "cheap-source", elapsed=normal.phases[0].budget_seconds + 0.01),),
    )
    assert overrun.status is VerificationStatus.FAIL
    assert "phase budget exceeded" in str(overrun.reason)


def test_invalid_plan_inputs_and_credit_shaped_receipts_are_rejected() -> None:
    with pytest.raises(GateAdmissionError, match="unknown"):
        classify_invalidation({"git-head", "unknown-change"})
    with pytest.raises(GateAdmissionError, match="must not be empty"):
        classify_invalidation(())
    with pytest.raises(GateAdmissionError, match="exceeds"):
        gate_plan_for_invalidation(
            InvalidationClass.TOOLING_ONLY,
            input_digest=_INPUT,
            scope_count=1,
            host_budget_seconds=61,
        )
    plan = gate_plan_for_invalidation(
        InvalidationClass.TOOLING_ONLY,
        input_digest=_INPUT,
        scope_count=1,
    )
    with pytest.raises(GateAdmissionError, match="never grant credit"):
        GatePhaseReceipt(
            phase_id="tool-tests",
            availability=ToolAvailability.AVAILABLE,
            status=VerificationStatus.PASS,
            elapsed_seconds=0.01,
            input_digest=plan.input_digest,
            scope_count=plan.scope_count,
            credit=True,
        )


def test_hand_constructed_plan_cannot_remove_or_reprice_policy_phases() -> None:
    plan = gate_plan_for_invalidation(
        InvalidationClass.CMAKE_TOPOLOGY,
        input_digest=_INPUT,
        scope_count=1,
    )
    forged = replace(
        plan,
        phases=plan.phases[:1],
        host_budget_seconds=plan.phases[0].budget_seconds,
    )
    with pytest.raises(GateAdmissionError, match="exact canonical"):
        evaluate_gate_admission(forged, (_pass(forged, "cheap-source"),))
