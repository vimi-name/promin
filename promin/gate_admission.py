"""Typed invalidation and cost-aware verification admission.

The module is deliberately planner-only in this wave.  It does not configure,
run a provider, build a target, or grant acceptance.  Its job is to make those
later execution decisions auditable: a Git revision by itself cannot broaden
work, every executed phase records its bounded input and timing, and a cheap
failure prevents admission of later expensive phases.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence

from .canonical import digest_value


class GateAdmissionError(ValueError):
    """Raised when invalidation or phase evidence is ambiguous or unsafe."""


class InvalidationClass(str, Enum):
    """The only invalidation classes admitted by the alpha.4 policy."""

    BODY_ONLY = "BODY_ONLY"
    IMPORT_SURFACE = "IMPORT_SURFACE"
    CMAKE_TOPOLOGY = "CMAKE_TOPOLOGY"
    TOOLING_ONLY = "TOOLING_ONLY"


class VerificationStatus(str, Enum):
    """Availability/result states; none of them imply product acceptance."""

    PASS = "PASS"
    UNAVAILABLE = "UNAVAILABLE"
    FAIL = "FAIL"
    SKIPPED = "SKIPPED"


class ToolAvailability(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_PHASE_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_SCHEMA = "promin.verification.gate-admission.v1"
_CHANGE_INPUTS = frozenset(
    {
        "body",
        "git-head",
        "import-surface",
        "cmake-topology",
        "tooling-only",
    }
)


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _HEX64.fullmatch(value) is None:
        raise GateAdmissionError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _positive_seconds(value: Any, field: str, *, allow_zero: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise GateAdmissionError(f"{field} must be a finite number")
    result = float(value)
    if result < 0 or (result == 0 and not allow_zero):
        comparator = "non-negative" if allow_zero else "positive"
        raise GateAdmissionError(f"{field} must be {comparator}")
    return result


@dataclass(frozen=True)
class GatePhase:
    """One ordered verification phase and its declared host budget."""

    phase_id: str
    budget_seconds: float
    expensive: bool

    def __post_init__(self) -> None:
        if not isinstance(self.phase_id, str) or _PHASE_ID.fullmatch(self.phase_id) is None:
            raise GateAdmissionError("gate phase id is invalid")
        _positive_seconds(self.budget_seconds, "gate phase budget")

    def as_dict(self) -> dict[str, Any]:
        return {
            "phase_id": self.phase_id,
            "budget_seconds": self.budget_seconds,
            "expensive": self.expensive,
        }


_PLAN_PHASES: dict[InvalidationClass, tuple[GatePhase, ...]] = {
    InvalidationClass.BODY_ONLY: (
        GatePhase("cheap-source", 5.0, False),
        GatePhase("affected-semantic", 15.0, False),
        GatePhase("dependency-reuse", 20.0, False),
    ),
    InvalidationClass.IMPORT_SURFACE: (
        GatePhase("cheap-source", 5.0, False),
        GatePhase("module-graph-refresh", 30.0, False),
        GatePhase("bounded-provider-delta", 60.0, True),
    ),
    InvalidationClass.CMAKE_TOPOLOGY: (
        GatePhase("cheap-source", 5.0, False),
        # Configure is intentionally after the cheap source invariant.  The
        # graph refresh consumes its physical reply, so this causal order is
        # the cheapest sufficient route for a topology change.
        GatePhase("single-configure", 120.0, True),
        GatePhase("module-graph-refresh", 30.0, False),
        GatePhase("provider-refresh", 90.0, True),
    ),
    InvalidationClass.TOOLING_ONLY: (
        GatePhase("tool-tests", 60.0, False),
    ),
}


def classify_invalidation(changed_inputs: Iterable[str]) -> InvalidationClass:
    """Classify explicit semantic inputs; Git HEAD alone is body-only.

    ``git-head`` intentionally contributes no configure/provider/receipt
    authority.  It can request only the bounded BODY_ONLY plan, which lets a
    later source gate decide whether any semantic work is actually required.
    """

    if isinstance(changed_inputs, str):
        raise GateAdmissionError("changed_inputs must be an iterable of tokens")
    values = frozenset(changed_inputs)
    if not values:
        raise GateAdmissionError("changed_inputs must not be empty")
    if not values <= _CHANGE_INPUTS:
        unknown = sorted(values - _CHANGE_INPUTS)
        raise GateAdmissionError(f"unknown invalidation input(s): {unknown}")
    if "cmake-topology" in values:
        return InvalidationClass.CMAKE_TOPOLOGY
    if "import-surface" in values:
        return InvalidationClass.IMPORT_SURFACE
    if values == {"tooling-only"}:
        return InvalidationClass.TOOLING_ONLY
    return InvalidationClass.BODY_ONLY


@dataclass(frozen=True)
class GateAdmissionPlan:
    """One exact bounded verification plan; it grants no pass credit itself."""

    invalidation: InvalidationClass
    input_digest: str
    scope_count: int
    host_budget_seconds: float
    phases: tuple[GatePhase, ...]
    plan_digest: str

    @property
    def phase_ids(self) -> tuple[str, ...]:
        return tuple(phase.phase_id for phase in self.phases)

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_type": "GateAdmissionPlan",
            "schema": _SCHEMA,
            "invalidation": self.invalidation.value,
            "input_digest": self.input_digest,
            "scope_count": self.scope_count,
            "host_budget_seconds": self.host_budget_seconds,
            "ordering": "cheapest-sufficient-first",
            "git_head_alone_is_invalidation": False,
            "phases": [phase.as_dict() for phase in self.phases],
            "acceptance_pass": False,
            "pass_credit": False,
            "plan_digest": self.plan_digest,
        }


def gate_plan_for_invalidation(
    invalidation: InvalidationClass | str,
    *,
    input_digest: str,
    scope_count: int,
    host_budget_seconds: float | None = None,
) -> GateAdmissionPlan:
    """Return the fixed cheapest-sufficient plan for one typed invalidation."""

    try:
        selected = (
            invalidation
            if isinstance(invalidation, InvalidationClass)
            else InvalidationClass(invalidation)
        )
    except ValueError as exc:
        raise GateAdmissionError("unknown invalidation class") from exc
    digest = _digest(input_digest, "input_digest")
    if not isinstance(scope_count, int) or isinstance(scope_count, bool) or scope_count < 0:
        raise GateAdmissionError("scope_count must be a non-negative integer")
    phases = _PLAN_PHASES[selected]
    derived_budget = sum(phase.budget_seconds for phase in phases)
    budget = derived_budget if host_budget_seconds is None else _positive_seconds(
        host_budget_seconds, "host_budget_seconds"
    )
    if budget > derived_budget:
        # A caller may constrain the declared budget further but cannot widen
        # the policy's maximum by supplying a larger host allowance.
        raise GateAdmissionError("host_budget_seconds exceeds the policy budget")
    identity = {
        "record_type": "GateAdmissionPlan",
        "schema": _SCHEMA,
        "invalidation": selected.value,
        "input_digest": digest,
        "scope_count": scope_count,
        "host_budget_seconds": budget,
        "ordering": "cheapest-sufficient-first",
        "git_head_alone_is_invalidation": False,
        "phases": [phase.as_dict() for phase in phases],
        "acceptance_pass": False,
        "pass_credit": False,
    }
    return GateAdmissionPlan(selected, digest, scope_count, budget, phases, digest_value(identity))


@dataclass(frozen=True)
class GatePhaseReceipt:
    """One phase observation with all fields required for later audit."""

    phase_id: str
    availability: ToolAvailability
    status: VerificationStatus
    elapsed_seconds: float
    input_digest: str
    scope_count: int
    credit: bool = False
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.phase_id, str) or _PHASE_ID.fullmatch(self.phase_id) is None:
            raise GateAdmissionError("gate receipt phase_id is invalid")
        if not isinstance(self.availability, ToolAvailability):
            raise GateAdmissionError("gate receipt availability is invalid")
        if not isinstance(self.status, VerificationStatus):
            raise GateAdmissionError("gate receipt status is invalid")
        _positive_seconds(self.elapsed_seconds, "gate receipt elapsed_seconds", allow_zero=True)
        _digest(self.input_digest, "gate receipt input_digest")
        if not isinstance(self.scope_count, int) or isinstance(self.scope_count, bool) or self.scope_count < 0:
            raise GateAdmissionError("gate receipt scope_count is invalid")
        if not isinstance(self.credit, bool) or self.credit:
            raise GateAdmissionError("gate admission receipts never grant credit")
        if self.status is VerificationStatus.PASS and self.availability is not ToolAvailability.AVAILABLE:
            raise GateAdmissionError("PASS requires an available tool")
        if self.status is VerificationStatus.UNAVAILABLE and self.availability is not ToolAvailability.UNAVAILABLE:
            raise GateAdmissionError("UNAVAILABLE requires an unavailable tool")
        if self.status in {VerificationStatus.FAIL, VerificationStatus.SKIPPED} and self.availability is not ToolAvailability.AVAILABLE:
            raise GateAdmissionError(f"{self.status.value} requires an available tool")
        if self.status is not VerificationStatus.PASS and (not isinstance(self.reason, str) or not self.reason.strip()):
            raise GateAdmissionError(f"{self.status.value} requires a non-empty reason")
        if self.status is VerificationStatus.PASS and self.reason is not None:
            raise GateAdmissionError("PASS must not include a failure reason")

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "phase_id": self.phase_id,
            "availability": self.availability.value,
            "status": self.status.value,
            "elapsed_seconds": self.elapsed_seconds,
            "input_digest": self.input_digest,
            "scope_count": self.scope_count,
            "credit": False,
        }
        if self.reason is not None:
            result["reason"] = self.reason
        return result


@dataclass(frozen=True)
class GateAdmissionResult:
    """Admission result, expressly distinct from acceptance or product credit."""

    status: VerificationStatus
    executed_phase_ids: tuple[str, ...]
    blocked_phase_ids: tuple[str, ...]
    elapsed_seconds: float
    receipt_digest: str
    reason: str | None
    admission_pass: bool
    pass_credit: bool = False
    acceptance_pass: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_type": "GateAdmissionResult",
            "schema": _SCHEMA,
            "status": self.status.value,
            "executed_phase_ids": list(self.executed_phase_ids),
            "blocked_phase_ids": list(self.blocked_phase_ids),
            "elapsed_seconds": self.elapsed_seconds,
            "receipt_digest": self.receipt_digest,
            "reason": self.reason,
            "admission_pass": self.admission_pass,
            "pass_credit": False,
            "acceptance_pass": False,
        }


def _result(
    plan: GateAdmissionPlan,
    *,
    status: VerificationStatus,
    receipts: Sequence[GatePhaseReceipt],
    blocked: Sequence[str],
    reason: str | None,
    admission_pass: bool,
) -> GateAdmissionResult:
    identity = {
        "plan_digest": plan.plan_digest,
        "status": status.value,
        "receipts": [item.as_dict() for item in receipts],
        "blocked_phase_ids": list(blocked),
        "reason": reason,
        "admission_pass": admission_pass,
        "pass_credit": False,
        "acceptance_pass": False,
    }
    return GateAdmissionResult(
        status,
        tuple(item.phase_id for item in receipts),
        tuple(blocked),
        sum(item.elapsed_seconds for item in receipts),
        digest_value(identity),
        reason,
        admission_pass,
    )


def _validate_plan(plan: GateAdmissionPlan) -> GateAdmissionPlan:
    """Reject hand-constructed plans that widen, reorder, or relabel policy.

    ``GateAdmissionPlan`` is a public frozen dataclass, not a capability.  Its
    fields are therefore rebound to the one canonical planner before any
    receipt is considered.  A caller cannot forge a lower-cost path merely by
    supplying a matching-looking digest or by omitting an expensive phase.
    """

    if not isinstance(plan, GateAdmissionPlan):
        raise GateAdmissionError("plan must be a GateAdmissionPlan")
    expected = gate_plan_for_invalidation(
        plan.invalidation,
        input_digest=plan.input_digest,
        scope_count=plan.scope_count,
        host_budget_seconds=plan.host_budget_seconds,
    )
    if plan != expected:
        raise GateAdmissionError("gate plan is not the exact canonical policy plan")
    return expected


def evaluate_gate_admission(
    plan: GateAdmissionPlan,
    receipts: Sequence[GatePhaseReceipt],
) -> GateAdmissionResult:
    """Evaluate an exact ordered receipt prefix against the declared plan.

    A cheap non-pass returns immediately in result terms and all later phases
    are marked blocked.  Supplying evidence after that point is rejected rather
    than silently accepting already-spent expensive work.
    """

    plan = _validate_plan(plan)
    if not isinstance(receipts, Sequence):
        raise GateAdmissionError("receipts must be an ordered sequence")
    if len(receipts) > len(plan.phases):
        raise GateAdmissionError("receipt count exceeds the declared gate plan")
    total = 0.0
    for index, receipt in enumerate(receipts):
        if not isinstance(receipt, GatePhaseReceipt):
            raise GateAdmissionError("gate receipt type is invalid")
        phase = plan.phases[index]
        if receipt.phase_id != phase.phase_id:
            raise GateAdmissionError(
                f"gate receipt order mismatch: expected {phase.phase_id}, got {receipt.phase_id}"
            )
        if receipt.input_digest != plan.input_digest or receipt.scope_count != plan.scope_count:
            raise GateAdmissionError("gate receipt does not bind the declared input scope")
        if receipt.elapsed_seconds > phase.budget_seconds:
            return _result(
                plan,
                status=VerificationStatus.FAIL,
                receipts=receipts[: index + 1],
                blocked=plan.phase_ids[index + 1 :],
                reason=f"phase budget exceeded: {phase.phase_id}",
                admission_pass=False,
            )
        total += receipt.elapsed_seconds
        if total > plan.host_budget_seconds:
            return _result(
                plan,
                status=VerificationStatus.FAIL,
                receipts=receipts[: index + 1],
                blocked=plan.phase_ids[index + 1 :],
                reason="declared host budget exceeded",
                admission_pass=False,
            )
        if receipt.status is not VerificationStatus.PASS:
            if index + 1 != len(receipts):
                raise GateAdmissionError("a non-passing gate receipt must block all later phases")
            return _result(
                plan,
                status=receipt.status,
                receipts=receipts,
                blocked=plan.phase_ids[index + 1 :],
                reason=receipt.reason,
                admission_pass=False,
            )
    if len(receipts) != len(plan.phases):
        return _result(
            plan,
            status=VerificationStatus.UNAVAILABLE,
            receipts=receipts,
            blocked=plan.phase_ids[len(receipts) :],
            reason="required gate phase receipt is missing",
            admission_pass=False,
        )
    return _result(
        plan,
        status=VerificationStatus.PASS,
        receipts=receipts,
        blocked=(),
        reason=None,
        admission_pass=True,
    )
