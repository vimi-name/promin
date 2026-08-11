"""Read-only, restart-safe orchestration for heavy recovery revalidation.

This layer composes existing authorities through explicitly declared read-only
callbacks.  It does not own a database, projection, provider, subprocess, or
filesystem mutation boundary.  Every result is diagnostic evidence only:
neither a successful phase nor a fully completed receipt grants acceptance or
pass credit.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
import json
import math
import re
import time
from typing import Any

from .canonical import CanonicalError, canonical_bytes, digest_value


REVALIDATION_SCHEMA = "promin.heavy-revalidation.v1"
REPORT_SCHEMA = "promin.heavy-revalidation-report.v1"
MAX_PHASES = 12
MAX_PHASE_SECONDS = 600.0
MAX_TOTAL_SECONDS = 1_800.0
MAX_IDENTITY_BYTES = 64 * 1024
MAX_REASON_BYTES = 512

_PHASE_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_PLAN_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CREDIT_FIELDS = frozenset(
    {
        "acceptance_pass",
        "pass_credit",
        "product_acceptance_pass",
        "release_eligible",
        "release_ready",
        "credit",
        "authoritative",
        "report_authoritative",
    }
)


class RevalidationError(ValueError):
    """Raised when a revalidation plan or restart receipt is unsafe."""


class RevalidationStatus(str, Enum):
    """Bounded phase and receipt states; none is product acceptance."""

    PENDING = "PENDING"
    PASS = "PASS"
    FAIL = "FAIL"
    STALE = "STALE"
    CHANGED = "CHANGED"
    UNAVAILABLE = "UNAVAILABLE"
    SKIPPED = "SKIPPED"


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise RevalidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_identifier(value: object, label: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise RevalidationError(f"{label} is invalid")
    return value


def _require_seconds(value: object, label: str, *, allow_zero: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RevalidationError(f"{label} must be a finite number")
    result = float(value)
    if not math.isfinite(result) or result < 0 or (not allow_zero and result == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise RevalidationError(f"{label} must be {qualifier}")
    return result


def _require_reason(value: object, *, required: bool) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise RevalidationError("non-passing revalidation state requires a trimmed reason")
    if len(value.encode("utf-8")) > MAX_REASON_BYTES:
        raise RevalidationError("revalidation reason exceeds its byte budget")
    return value


def _reject_promoting_values(value: object, label: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise RevalidationError(f"{label} contains a non-string key")
            if key in _CREDIT_FIELDS and child is not False:
                raise RevalidationError(f"{label} carries a non-false promotion field: {key}")
            _reject_promoting_values(child, label)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _reject_promoting_values(child, label)


def _canonical_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RevalidationError(f"{label} must be a mapping")
    try:
        encoded = canonical_bytes(dict(value))
        if len(encoded) > MAX_IDENTITY_BYTES:
            raise RevalidationError(f"{label} exceeds its canonical byte budget")
        normalized = json.loads(encoded.decode("utf-8"))
    except (CanonicalError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise RevalidationError(f"{label} is not canonical JSON data") from exc
    if not isinstance(normalized, dict):
        raise RevalidationError(f"{label} must normalize to an object")
    _reject_promoting_values(normalized, label)
    return normalized


@dataclass(frozen=True, slots=True)
class RevalidationPhase:
    """One ordered, bounded, read-only authority observation."""

    phase_id: str
    budget_seconds: float

    def __post_init__(self) -> None:
        _require_identifier(self.phase_id, "phase_id", _PHASE_ID)
        budget = _require_seconds(self.budget_seconds, "phase budget_seconds")
        if budget > MAX_PHASE_SECONDS:
            raise RevalidationError("phase budget_seconds exceeds the maximum")
        object.__setattr__(self, "budget_seconds", budget)

    def to_record(self) -> dict[str, object]:
        return {
            "phase_id": self.phase_id,
            "budget_seconds": self.budget_seconds,
            "read_only": True,
            "acceptance_pass": False,
            "product_acceptance_pass": False,
            "pass_credit": False,
        }


@dataclass(frozen=True, slots=True)
class RevalidationPlan:
    """Exact bounded route and input identity for one recovery revalidation."""

    plan_id: str
    input_identity: Mapping[str, Any]
    phases: Sequence[RevalidationPhase]
    total_budget_seconds: float | None = None
    input_digest: str = field(init=False)
    restart_identity: str = field(init=False)
    plan_digest: str = field(init=False)

    def __post_init__(self) -> None:
        _require_identifier(self.plan_id, "plan_id", _PLAN_ID)
        normalized_input = _canonical_mapping(self.input_identity, "plan input_identity")
        if not normalized_input:
            raise RevalidationError("plan input_identity must not be empty")
        selected = tuple(self.phases)
        if not selected or len(selected) > MAX_PHASES:
            raise RevalidationError("plan phases must be a bounded non-empty sequence")
        if not all(isinstance(phase, RevalidationPhase) for phase in selected):
            raise RevalidationError("plan phases must use RevalidationPhase")
        phase_ids = tuple(phase.phase_id for phase in selected)
        if len(set(phase_ids)) != len(phase_ids):
            raise RevalidationError("plan phase identifiers must be unique")
        derived_budget = sum(phase.budget_seconds for phase in selected)
        if derived_budget > MAX_TOTAL_SECONDS:
            raise RevalidationError("plan phase budgets exceed the total maximum")
        if self.total_budget_seconds is None:
            budget = derived_budget
        else:
            budget = _require_seconds(
                self.total_budget_seconds, "plan total_budget_seconds"
            )
            if budget > derived_budget or budget > MAX_TOTAL_SECONDS:
                raise RevalidationError("plan total_budget_seconds exceeds declared phase budgets")
        input_digest = digest_value(normalized_input)
        restart_payload = {
            "schema": REVALIDATION_SCHEMA,
            "record_type": "RevalidationRestartIdentity",
            "plan_id": self.plan_id,
            "input_digest": input_digest,
            "total_budget_seconds": budget,
            "phases": [phase.to_record() for phase in selected],
            "read_only": True,
            "acceptance_pass": False,
            "pass_credit": False,
        }
        restart_identity = digest_value(restart_payload)
        plan_payload = {
            **restart_payload,
            "record_type": "RevalidationPlan",
            "restart_identity": restart_identity,
        }
        object.__setattr__(self, "input_identity", normalized_input)
        object.__setattr__(self, "phases", selected)
        object.__setattr__(self, "total_budget_seconds", budget)
        object.__setattr__(self, "input_digest", input_digest)
        object.__setattr__(self, "restart_identity", restart_identity)
        object.__setattr__(self, "plan_digest", digest_value(plan_payload))

    @property
    def phase_ids(self) -> tuple[str, ...]:
        return tuple(phase.phase_id for phase in self.phases)

    def to_record(self) -> dict[str, object]:
        return {
            "schema": REVALIDATION_SCHEMA,
            "record_type": "RevalidationPlan",
            "plan_id": self.plan_id,
            "input_digest": self.input_digest,
            "restart_identity": self.restart_identity,
            "plan_digest": self.plan_digest,
            "total_budget_seconds": self.total_budget_seconds,
            "phases": [phase.to_record() for phase in self.phases],
            "read_only": True,
            "acceptance_pass": False,
            "pass_credit": False,
            "product_acceptance_pass": False,
        }


@dataclass(frozen=True, slots=True)
class RevalidationContext:
    """Read-only input supplied to one declared callback.

    The context intentionally exposes identities rather than a state path,
    connection, projection, or writable control object.
    """

    plan_id: str
    plan_digest: str
    restart_identity: str
    phase_id: str
    expected_input_digest: str
    previous_output_digest: str | None

    def __post_init__(self) -> None:
        _require_identifier(self.plan_id, "context plan_id", _PLAN_ID)
        _require_digest(self.plan_digest, "context plan_digest")
        _require_digest(self.restart_identity, "context restart_identity")
        _require_identifier(self.phase_id, "context phase_id", _PHASE_ID)
        _require_digest(self.expected_input_digest, "context expected_input_digest")
        if self.previous_output_digest is not None:
            _require_digest(self.previous_output_digest, "context previous_output_digest")


@dataclass(frozen=True, slots=True)
class RevalidationObservation:
    """One read-only authority result returned by a phase callback."""

    status: RevalidationStatus
    observed_input_digest: str
    output_identity: Mapping[str, Any]
    reason: str | None = None
    output_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.status, RevalidationStatus) or self.status in {
            RevalidationStatus.PENDING,
            RevalidationStatus.SKIPPED,
        }:
            raise RevalidationError("observation status must be a terminal phase status")
        _require_digest(self.observed_input_digest, "observation observed_input_digest")
        output = _canonical_mapping(self.output_identity, "observation output_identity")
        if not output:
            raise RevalidationError("observation output_identity must not be empty")
        required_reason = self.status is not RevalidationStatus.PASS
        reason = _require_reason(self.reason, required=required_reason)
        if self.status is RevalidationStatus.PASS and reason is not None:
            raise RevalidationError("passing observation must not include a reason")
        object.__setattr__(self, "output_identity", output)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "output_digest", digest_value(output))


@dataclass(frozen=True, slots=True)
class ReadOnlyRevalidationCallback:
    """Explicit declaration that a supplied authority callback is read-only."""

    phase_id: str
    evaluator: Callable[[RevalidationContext], RevalidationObservation]
    read_only: bool = True

    def __post_init__(self) -> None:
        _require_identifier(self.phase_id, "callback phase_id", _PHASE_ID)
        if not callable(self.evaluator):
            raise RevalidationError("revalidation callback evaluator must be callable")
        if self.read_only is not True:
            raise RevalidationError("revalidation callbacks must explicitly be read_only")


@dataclass(frozen=True, slots=True)
class RevalidationCheckpoint:
    """One immutable phase receipt bound to its expected and observed inputs."""

    phase_id: str
    status: RevalidationStatus
    input_digest: str
    observed_input_digest: str
    output_identity: Mapping[str, Any]
    output_digest: str
    elapsed_seconds: float
    reason: str | None = None
    read_only: bool = True
    pass_credit: bool = False
    acceptance_pass: bool = False
    product_acceptance_pass: bool = False

    def __post_init__(self) -> None:
        _require_identifier(self.phase_id, "checkpoint phase_id", _PHASE_ID)
        if not isinstance(self.status, RevalidationStatus) or self.status in {
            RevalidationStatus.PENDING,
            RevalidationStatus.SKIPPED,
        }:
            raise RevalidationError("checkpoint status must be a terminal phase status")
        expected = _require_digest(self.input_digest, "checkpoint input_digest")
        observed = _require_digest(
            self.observed_input_digest, "checkpoint observed_input_digest"
        )
        output = _canonical_mapping(self.output_identity, "checkpoint output_identity")
        output_digest = _require_digest(self.output_digest, "checkpoint output_digest")
        if output_digest != digest_value(output):
            raise RevalidationError("checkpoint output_digest does not bind output_identity")
        elapsed = _require_seconds(
            self.elapsed_seconds, "checkpoint elapsed_seconds", allow_zero=True
        )
        if elapsed > MAX_PHASE_SECONDS:
            raise RevalidationError("checkpoint elapsed_seconds exceeds the phase maximum")
        if (
            self.read_only is not True
            or self.pass_credit is not False
            or self.acceptance_pass is not False
            or self.product_acceptance_pass is not False
        ):
            raise RevalidationError("checkpoint must remain read-only and non-promoting")
        required_reason = self.status is not RevalidationStatus.PASS
        reason = _require_reason(self.reason, required=required_reason)
        if self.status is RevalidationStatus.PASS:
            if reason is not None or expected != observed:
                raise RevalidationError("passing checkpoint must bind the exact expected input")
        elif self.status is not RevalidationStatus.CHANGED and expected != observed:
            raise RevalidationError("only a CHANGED checkpoint may carry a different observed input")
        object.__setattr__(self, "output_identity", output)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "elapsed_seconds", elapsed)

    def to_record(self) -> dict[str, object]:
        return {
            "phase_id": self.phase_id,
            "status": self.status.value,
            "input_digest": self.input_digest,
            "observed_input_digest": self.observed_input_digest,
            "output_identity": dict(self.output_identity),
            "output_digest": self.output_digest,
            "elapsed_seconds": self.elapsed_seconds,
            "reason": self.reason,
            "read_only": True,
            "pass_credit": False,
            "acceptance_pass": False,
            "product_acceptance_pass": False,
        }

    @classmethod
    def from_record(cls, value: Mapping[str, object]) -> RevalidationCheckpoint:
        required = {
            "phase_id",
            "status",
            "input_digest",
            "observed_input_digest",
            "output_identity",
            "output_digest",
            "elapsed_seconds",
            "reason",
            "read_only",
            "pass_credit",
            "acceptance_pass",
            "product_acceptance_pass",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise RevalidationError("checkpoint record has an inexact field set")
        try:
            status = RevalidationStatus(value["status"])
        except (TypeError, ValueError) as exc:
            raise RevalidationError("checkpoint record status is invalid") from exc
        return cls(
            phase_id=value["phase_id"],
            status=status,
            input_digest=value["input_digest"],
            observed_input_digest=value["observed_input_digest"],
            output_identity=value["output_identity"],
            output_digest=value["output_digest"],
            elapsed_seconds=value["elapsed_seconds"],
            reason=value["reason"],
            read_only=value["read_only"],
            pass_credit=value["pass_credit"],
            acceptance_pass=value["acceptance_pass"],
            product_acceptance_pass=value["product_acceptance_pass"],
        )


@dataclass(frozen=True, slots=True)
class RevalidationReceipt:
    """Serializable recovery/revalidation state safe to inspect after restart."""

    plan_id: str
    plan_digest: str
    input_digest: str
    restart_identity: str
    phase_ids: Sequence[str]
    checkpoints: Sequence[RevalidationCheckpoint]
    status: RevalidationStatus
    next_phase_id: str | None
    reason: str | None = None
    stale_receipt_digests: Sequence[str] = ()

    def __post_init__(self) -> None:
        _require_identifier(self.plan_id, "receipt plan_id", _PLAN_ID)
        _require_digest(self.plan_digest, "receipt plan_digest")
        _require_digest(self.input_digest, "receipt input_digest")
        _require_digest(self.restart_identity, "receipt restart_identity")
        phase_ids = tuple(
            _require_identifier(item, "receipt phase_id", _PHASE_ID)
            for item in self.phase_ids
        )
        if not phase_ids or len(phase_ids) > MAX_PHASES or len(set(phase_ids)) != len(phase_ids):
            raise RevalidationError("receipt phase identifiers are invalid")
        checkpoints = tuple(self.checkpoints)
        if len(checkpoints) > len(phase_ids) or not all(
            isinstance(item, RevalidationCheckpoint) for item in checkpoints
        ):
            raise RevalidationError("receipt checkpoints are invalid")
        if tuple(item.phase_id for item in checkpoints) != phase_ids[: len(checkpoints)]:
            raise RevalidationError("receipt checkpoints must be an ordered phase prefix")
        if not isinstance(self.status, RevalidationStatus):
            raise RevalidationError("receipt status is invalid")
        if self.next_phase_id is not None:
            _require_identifier(self.next_phase_id, "receipt next_phase_id", _PHASE_ID)
            if self.next_phase_id not in phase_ids:
                raise RevalidationError("receipt next_phase_id is not declared by the plan")
        stale = tuple(_require_digest(item, "stale receipt digest") for item in self.stale_receipt_digests)
        if stale != tuple(sorted(set(stale))) or len(stale) > MAX_PHASES:
            raise RevalidationError("stale receipt digests must be sorted, unique and bounded")
        reason = _require_reason(
            self.reason,
            required=self.status not in {RevalidationStatus.PENDING, RevalidationStatus.PASS},
        )
        if self.status in {RevalidationStatus.PENDING, RevalidationStatus.PASS} and reason is not None:
            raise RevalidationError("pending or passing receipt must not carry a reason")
        if self.status is RevalidationStatus.PENDING:
            if len(checkpoints) >= len(phase_ids) or any(
                item.status is not RevalidationStatus.PASS for item in checkpoints
            ):
                raise RevalidationError("pending receipt must be a passing incomplete prefix")
            if self.next_phase_id != phase_ids[len(checkpoints)]:
                raise RevalidationError("pending receipt next_phase_id is invalid")
        if self.status is RevalidationStatus.PASS:
            if len(checkpoints) != len(phase_ids) or any(
                item.status is not RevalidationStatus.PASS for item in checkpoints
            ) or self.next_phase_id is not None:
                raise RevalidationError("passing receipt must close every declared phase")
        if self.status in {
            RevalidationStatus.FAIL,
            RevalidationStatus.UNAVAILABLE,
            RevalidationStatus.STALE,
            RevalidationStatus.CHANGED,
        }:
            nonpassing = [item for item in checkpoints if item.status is not RevalidationStatus.PASS]
            if nonpassing and (len(nonpassing) != 1 or checkpoints[-1] is not nonpassing[0]):
                raise RevalidationError("receipt may contain only one terminal non-passing checkpoint")
            if nonpassing and self.status is not nonpassing[0].status:
                raise RevalidationError("receipt status must match its terminal checkpoint")
            if self.status in {RevalidationStatus.FAIL, RevalidationStatus.UNAVAILABLE}:
                if len(nonpassing) != 1 or self.next_phase_id is not None:
                    raise RevalidationError("failed or unavailable receipt cannot advance to another phase")
            elif nonpassing:
                if self.next_phase_id is not None:
                    raise RevalidationError("terminal receipt cannot advance to another phase")
            elif self.next_phase_id != (
                phase_ids[len(checkpoints)] if len(checkpoints) < len(phase_ids) else None
            ):
                raise RevalidationError("synthetic terminal receipt next_phase_id is invalid")
        object.__setattr__(self, "phase_ids", phase_ids)
        object.__setattr__(self, "checkpoints", checkpoints)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "stale_receipt_digests", stale)

    def _payload(self) -> dict[str, object]:
        return {
            "schema": REVALIDATION_SCHEMA,
            "record_type": "RevalidationReceipt",
            "plan_id": self.plan_id,
            "plan_digest": self.plan_digest,
            "input_digest": self.input_digest,
            "restart_identity": self.restart_identity,
            "phase_ids": list(self.phase_ids),
            "checkpoints": [item.to_record() for item in self.checkpoints],
            "status": self.status.value,
            "next_phase_id": self.next_phase_id,
            "reason": self.reason,
            "stale_receipt_digests": list(self.stale_receipt_digests),
            "restart_safe": True,
            "read_only": True,
            "acceptance_pass": False,
            "product_acceptance_pass": False,
            "pass_credit": False,
        }

    @property
    def receipt_digest(self) -> str:
        return digest_value(self._payload())

    def to_record(self) -> dict[str, object]:
        return {**self._payload(), "receipt_digest": self.receipt_digest}

    as_dict = to_record

    @classmethod
    def from_record(cls, value: Mapping[str, object]) -> RevalidationReceipt:
        required = {
            "schema",
            "record_type",
            "plan_id",
            "plan_digest",
            "input_digest",
            "restart_identity",
            "phase_ids",
            "checkpoints",
            "status",
            "next_phase_id",
            "reason",
            "stale_receipt_digests",
            "restart_safe",
            "read_only",
            "acceptance_pass",
            "product_acceptance_pass",
            "pass_credit",
            "receipt_digest",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise RevalidationError("receipt record has an inexact field set")
        if (
            value["schema"] != REVALIDATION_SCHEMA
            or value["record_type"] != "RevalidationReceipt"
            or value["restart_safe"] is not True
            or value["read_only"] is not True
            or value["acceptance_pass"] is not False
            or value["product_acceptance_pass"] is not False
            or value["pass_credit"] is not False
        ):
            raise RevalidationError("receipt record has invalid read-only or credit fields")
        if not isinstance(value["phase_ids"], list) or not isinstance(value["checkpoints"], list):
            raise RevalidationError("receipt record phase data must be lists")
        if not isinstance(value["stale_receipt_digests"], list):
            raise RevalidationError("receipt record stale receipt data must be a list")
        try:
            status = RevalidationStatus(value["status"])
        except (TypeError, ValueError) as exc:
            raise RevalidationError("receipt record status is invalid") from exc
        receipt = cls(
            plan_id=value["plan_id"],
            plan_digest=value["plan_digest"],
            input_digest=value["input_digest"],
            restart_identity=value["restart_identity"],
            phase_ids=tuple(value["phase_ids"]),
            checkpoints=tuple(
                RevalidationCheckpoint.from_record(item)
                for item in value["checkpoints"]
                if isinstance(item, Mapping)
            ),
            status=status,
            next_phase_id=value["next_phase_id"],
            reason=value["reason"],
            stale_receipt_digests=tuple(value["stale_receipt_digests"]),
        )
        if len(receipt.checkpoints) != len(value["checkpoints"]):
            raise RevalidationError("receipt checkpoint record is invalid")
        if value["receipt_digest"] != receipt.receipt_digest:
            raise RevalidationError("receipt_digest does not bind the receipt record")
        return receipt


def _phase_input_digest(
    plan: RevalidationPlan,
    phase_id: str,
    previous_output_digest: str | None,
) -> str:
    return digest_value(
        {
            "schema": REVALIDATION_SCHEMA,
            "record_type": "RevalidationPhaseInput",
            "plan_digest": plan.plan_digest,
            "restart_identity": plan.restart_identity,
            "phase_id": phase_id,
            "plan_input_digest": plan.input_digest,
            "previous_output_digest": previous_output_digest,
            "read_only": True,
            "acceptance_pass": False,
            "product_acceptance_pass": False,
            "pass_credit": False,
        }
    )


def _receipt_for(
    plan: RevalidationPlan,
    checkpoints: Sequence[RevalidationCheckpoint] = (),
    *,
    synthetic_status: RevalidationStatus | None = None,
    synthetic_reason: str | None = None,
    stale_receipt_digests: Sequence[str] = (),
) -> RevalidationReceipt:
    selected = tuple(checkpoints)
    if synthetic_status is None:
        terminal = next(
            (item for item in selected if item.status is not RevalidationStatus.PASS),
            None,
        )
        if terminal is not None:
            status = terminal.status
            reason = terminal.reason
            next_phase_id = None
        elif len(selected) == len(plan.phases):
            status = RevalidationStatus.PASS
            reason = None
            next_phase_id = None
        else:
            status = RevalidationStatus.PENDING
            reason = None
            next_phase_id = plan.phase_ids[len(selected)]
    else:
        status = synthetic_status
        reason = synthetic_reason
        next_phase_id = (
            plan.phase_ids[len(selected)] if len(selected) < len(plan.phases) else None
        )
    return RevalidationReceipt(
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        input_digest=plan.input_digest,
        restart_identity=plan.restart_identity,
        phase_ids=plan.phase_ids,
        checkpoints=selected,
        status=status,
        next_phase_id=next_phase_id,
        reason=reason,
        stale_receipt_digests=tuple(stale_receipt_digests),
    )


def _coerce_receipt(value: object) -> RevalidationReceipt:
    if isinstance(value, RevalidationReceipt):
        return value
    if isinstance(value, Mapping):
        return RevalidationReceipt.from_record(value)
    raise RevalidationError("prior receipt must be a RevalidationReceipt or receipt record")


def _prior_receipts(value: object) -> tuple[RevalidationReceipt, ...]:
    if value is None:
        return ()
    if isinstance(value, (RevalidationReceipt, Mapping)):
        return (_coerce_receipt(value),)
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise RevalidationError("prior_receipts must be an iterable of receipts")
    return tuple(_coerce_receipt(item) for item in value)


def _matches_plan(receipt: RevalidationReceipt, plan: RevalidationPlan) -> bool:
    return (
        receipt.plan_id == plan.plan_id
        and receipt.plan_digest == plan.plan_digest
        and receipt.input_digest == plan.input_digest
        and receipt.restart_identity == plan.restart_identity
        and tuple(receipt.phase_ids) == plan.phase_ids
    )


def _validate_resume_receipt(receipt: RevalidationReceipt, plan: RevalidationPlan) -> None:
    if not _matches_plan(receipt, plan):
        raise RevalidationError("receipt identity does not match the requested revalidation plan")
    previous_output: str | None = None
    for index, checkpoint in enumerate(receipt.checkpoints):
        phase = plan.phases[index]
        expected_input = _phase_input_digest(plan, phase.phase_id, previous_output)
        if checkpoint.input_digest != expected_input:
            raise RevalidationError("checkpoint input identity is stale or does not match its plan")
        if (
            checkpoint.status is RevalidationStatus.PASS
            and checkpoint.elapsed_seconds > phase.budget_seconds
        ):
            raise RevalidationError("checkpoint exceeds its declared phase budget")
        if checkpoint.status is not RevalidationStatus.PASS and index + 1 != len(receipt.checkpoints):
            raise RevalidationError("terminal checkpoint cannot be followed by another checkpoint")
        previous_output = checkpoint.output_digest
    if (
        all(item.status is RevalidationStatus.PASS for item in receipt.checkpoints)
        and sum(checkpoint.elapsed_seconds for checkpoint in receipt.checkpoints)
        > plan.total_budget_seconds
    ):
        raise RevalidationError("receipt exceeds the declared total phase budget")


def _with_stale_receipts(
    receipt: RevalidationReceipt, stale_digests: Sequence[str]
) -> RevalidationReceipt:
    merged = tuple(sorted(set(receipt.stale_receipt_digests) | set(stale_digests)))
    return RevalidationReceipt(
        plan_id=receipt.plan_id,
        plan_digest=receipt.plan_digest,
        input_digest=receipt.input_digest,
        restart_identity=receipt.restart_identity,
        phase_ids=receipt.phase_ids,
        checkpoints=receipt.checkpoints,
        status=receipt.status,
        next_phase_id=receipt.next_phase_id,
        reason=receipt.reason,
        stale_receipt_digests=merged,
    )


def reconsolidate_revalidation(
    plan: RevalidationPlan,
    prior_receipts: object = (),
) -> RevalidationReceipt:
    """Reconcile restart receipts without executing an authority callback.

    Only exact plan/input/restart identities may supply checkpoints.  A receipt
    for another identity is retained as stale evidence instead of being reused.
    Divergent exact-prefix outputs fail closed as ``CHANGED``.
    """

    if not isinstance(plan, RevalidationPlan):
        raise RevalidationError("plan must be a RevalidationPlan")
    supplied = _prior_receipts(prior_receipts)
    if not supplied:
        return _receipt_for(plan)
    matching: list[RevalidationReceipt] = []
    stale: list[str] = []
    for receipt in supplied:
        if not _matches_plan(receipt, plan):
            stale.append(receipt.receipt_digest)
            continue
        _validate_resume_receipt(receipt, plan)
        matching.append(receipt)
    stale = sorted(set(stale))
    if not matching:
        return _receipt_for(
            plan,
            synthetic_status=RevalidationStatus.STALE,
            synthetic_reason="no prior receipt matches the current restart identity",
            stale_receipt_digests=stale,
        )
    # A synthetic STALE/CHANGED receipt records a prior reconciliation decision
    # without a terminal checkpoint.  Rebuilding it as a passing prefix would
    # silently turn a fail-closed result back into runnable work.
    preserved_terminal = [
        receipt
        for receipt in matching
        if receipt.status in {RevalidationStatus.STALE, RevalidationStatus.CHANGED}
    ]
    if preserved_terminal:
        return _with_stale_receipts(
            min(preserved_terminal, key=lambda receipt: receipt.receipt_digest),
            stale,
        )
    ordered = sorted(matching, key=lambda receipt: (len(receipt.checkpoints), receipt.receipt_digest))
    common = list(ordered[0].checkpoints)
    for receipt in ordered[1:]:
        limit = min(len(common), len(receipt.checkpoints))
        index = 0
        while index < limit and common[index].to_record() == receipt.checkpoints[index].to_record():
            index += 1
        if index != limit:
            return _receipt_for(
                plan,
                tuple(common[:index]),
                synthetic_status=RevalidationStatus.CHANGED,
                synthetic_reason="matching restart receipts disagree on a checkpoint identity",
                stale_receipt_digests=stale,
            )
        if len(receipt.checkpoints) > len(common):
            common = list(receipt.checkpoints)
    selected = max(
        matching,
        key=lambda receipt: (len(receipt.checkpoints), receipt.receipt_digest),
    )
    # Same checkpoints can appear in multiple externally stored receipts. Their
    # record-level status must not change the resume chain; rebuild it from the
    # longest exact prefix so the phase sequence remains authoritative.
    rebuilt = _receipt_for(plan, selected.checkpoints)
    return _with_stale_receipts(rebuilt, stale)


def _callback_map(
    callbacks: Iterable[ReadOnlyRevalidationCallback],
    required_phase_ids: Sequence[str],
) -> dict[str, ReadOnlyRevalidationCallback]:
    if isinstance(callbacks, (str, bytes)):
        raise RevalidationError("callbacks must be an iterable of read-only callbacks")
    selected = tuple(callbacks)
    if not all(isinstance(item, ReadOnlyRevalidationCallback) for item in selected):
        raise RevalidationError("callbacks must use ReadOnlyRevalidationCallback")
    by_phase = {item.phase_id: item for item in selected}
    if len(by_phase) != len(selected) or set(by_phase) != set(required_phase_ids):
        raise RevalidationError("callbacks must exactly cover the remaining declared phases")
    return by_phase


def _callback_failure_checkpoint(
    phase_id: str,
    expected_input_digest: str,
    elapsed_seconds: float,
    error: Exception,
) -> RevalidationCheckpoint:
    output = {
        "record_type": "ReadOnlyCallbackFailure",
        "exception_type": type(error).__name__,
        "read_only": True,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "pass_credit": False,
    }
    return RevalidationCheckpoint(
        phase_id=phase_id,
        status=RevalidationStatus.FAIL,
        input_digest=expected_input_digest,
        observed_input_digest=expected_input_digest,
        output_identity=output,
        output_digest=digest_value(output),
        elapsed_seconds=elapsed_seconds,
        reason="read-only callback raised an exception",
    )


def revalidate_recovery(
    plan: RevalidationPlan,
    callbacks: Iterable[ReadOnlyRevalidationCallback] = (),
    *,
    prior_receipts: object = (),
    max_phases: int | None = None,
) -> RevalidationReceipt:
    """Run the remaining bounded read-only phases for a recovery plan.

    A supplied nonmatching receipt is never silently resumed.  It yields a
    stale/changed terminal receipt.  ``max_phases`` permits a caller to stop
    after a durable in-memory checkpoint boundary and resume later with only
    the remaining callbacks.
    """

    if not isinstance(plan, RevalidationPlan):
        raise RevalidationError("plan must be a RevalidationPlan")
    baseline = reconsolidate_revalidation(plan, prior_receipts)
    if baseline.status is not RevalidationStatus.PENDING:
        return baseline
    remaining_ids = plan.phase_ids[len(baseline.checkpoints) :]
    callback_by_phase = _callback_map(callbacks, remaining_ids)
    if max_phases is None:
        phase_limit = len(remaining_ids)
    elif not isinstance(max_phases, int) or isinstance(max_phases, bool) or not 1 <= max_phases <= len(remaining_ids):
        raise RevalidationError("max_phases must be within the remaining phase count")
    else:
        phase_limit = max_phases
    checkpoints = list(baseline.checkpoints)
    previous_output = checkpoints[-1].output_digest if checkpoints else None
    elapsed_total = sum(item.elapsed_seconds for item in checkpoints)
    for phase in plan.phases[len(checkpoints) : len(checkpoints) + phase_limit]:
        expected_input = _phase_input_digest(plan, phase.phase_id, previous_output)
        context = RevalidationContext(
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            restart_identity=plan.restart_identity,
            phase_id=phase.phase_id,
            expected_input_digest=expected_input,
            previous_output_digest=previous_output,
        )
        started = time.monotonic()
        try:
            observation = callback_by_phase[phase.phase_id].evaluator(context)
            elapsed = max(0.0, time.monotonic() - started)
            if not isinstance(observation, RevalidationObservation):
                raise RevalidationError("read-only callback must return RevalidationObservation")
            status = observation.status
            reason = observation.reason
            if observation.observed_input_digest != expected_input:
                status = RevalidationStatus.CHANGED
                reason = "phase observed a changed input identity"
            if status is not RevalidationStatus.CHANGED and elapsed > phase.budget_seconds:
                status = RevalidationStatus.FAIL
                reason = "phase budget exceeded"
            if (
                status is not RevalidationStatus.CHANGED
                and elapsed_total + elapsed > plan.total_budget_seconds
            ):
                status = RevalidationStatus.FAIL
                reason = "declared total phase budget exceeded"
            checkpoint = RevalidationCheckpoint(
                phase_id=phase.phase_id,
                status=status,
                input_digest=expected_input,
                observed_input_digest=observation.observed_input_digest,
                output_identity=observation.output_identity,
                output_digest=observation.output_digest,
                elapsed_seconds=elapsed,
                reason=reason,
            )
        except Exception as exc:
            elapsed = max(0.0, time.monotonic() - started)
            checkpoint = _callback_failure_checkpoint(
                phase.phase_id, expected_input, elapsed, exc
            )
        checkpoints.append(checkpoint)
        elapsed_total += checkpoint.elapsed_seconds
        previous_output = checkpoint.output_digest
        if checkpoint.status is not RevalidationStatus.PASS:
            return _receipt_for(plan, checkpoints, stale_receipt_digests=baseline.stale_receipt_digests)
    return _receipt_for(plan, checkpoints, stale_receipt_digests=baseline.stale_receipt_digests)


def prepare_revalidation_report(
    receipt: RevalidationReceipt | Mapping[str, object],
) -> dict[str, object]:
    """Prepare a compact read-only report from an existing restart receipt.

    The function returns data only.  It does not publish a report, edit a
    projection, open SQLite, or turn any prior phase into pass credit.
    """

    selected = _coerce_receipt(receipt)
    checkpoints = [item.to_record() for item in selected.checkpoints]
    changed = [
        {
            "phase_id": item.phase_id,
            "expected_input_digest": item.input_digest,
            "observed_input_digest": item.observed_input_digest,
        }
        for item in selected.checkpoints
        if item.input_digest != item.observed_input_digest
    ]
    identity = {
        "schema": REPORT_SCHEMA,
        "record_type": "RevalidationReportPreparation",
        "receipt_digest": selected.receipt_digest,
        "plan_digest": selected.plan_digest,
        "restart_identity": selected.restart_identity,
        "status": selected.status.value,
        "next_phase_id": selected.next_phase_id,
        "reason": selected.reason,
        "phase_count": len(selected.phase_ids),
        "checkpoint_count": len(selected.checkpoints),
        "checkpoints": checkpoints,
        "changed_identities": changed,
        "stale_receipt_digests": list(selected.stale_receipt_digests),
        "report_authoritative": False,
        "read_only": True,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "pass_credit": False,
        "effects": {
            "sqlite_connections": 0,
            "projection_edits": 0,
            "filesystem_writes": 0,
            "provider_invocations": 0,
        },
    }
    return {**identity, "report_digest": digest_value(identity)}


__all__ = [
    "MAX_PHASES",
    "MAX_PHASE_SECONDS",
    "MAX_TOTAL_SECONDS",
    "REPORT_SCHEMA",
    "REVALIDATION_SCHEMA",
    "ReadOnlyRevalidationCallback",
    "RevalidationCheckpoint",
    "RevalidationContext",
    "RevalidationError",
    "RevalidationObservation",
    "RevalidationPhase",
    "RevalidationPlan",
    "RevalidationReceipt",
    "RevalidationStatus",
    "prepare_revalidation_report",
    "reconsolidate_revalidation",
    "revalidate_recovery",
]
