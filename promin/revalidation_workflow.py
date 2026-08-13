"""Simple orchestration for inspect, repair, revalidate, reconsolidate, report.

The underlying recovery and revalidation modules own their domain rules.  This
module binds an explicit plan to one canonical receipt, persists it once, and
supports a deterministic predecessor chain for retry or resume.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
import os
from pathlib import Path
import re
from typing import Any

from .canonical import CanonicalError, ParseLimits, canonical_bytes, digest_value, parse_json_strict
from .recovery import (
    CleanReinitializationAttempt,
    CleanStateAdmission,
    PublishedCleanReinitialization,
    run_bounded_clean_reinitialization,
)
from .revalidation import (
    ReadOnlyRevalidationCallback,
    RevalidationPlan,
    RevalidationReceipt,
    RevalidationStatus,
    prepare_revalidation_report,
    reconsolidate_revalidation,
    revalidate_recovery,
)
from .writer_identity import WriterLivenessReport


REVALIDATION_WORKFLOW_SCHEMA = "promin.revalidation-workflow.v1"
MAX_WORKFLOW_PRIOR_RECEIPTS = 16
MAX_WORKFLOW_RETRIES = 16
MAX_WORKFLOW_RECEIPT_BYTES = 4 * 1024 * 1024

_WORKFLOW_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_AUTHORITY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$")
_RECEIPT_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,119}\.json$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class RevalidationWorkflowError(ValueError):
    """Raised when workflow inputs, execution, or receipts are inconsistent."""


class RevalidationWorkflowMode(str, Enum):
    INSPECT = "inspect"
    REPAIR = "repair"
    REVALIDATE = "revalidate"
    RECONSOLIDATE = "reconsolidate"
    REPORT = "report"


_RESULT_KINDS = {
    RevalidationWorkflowMode.INSPECT: "RevalidationWorkflowInspection",
    RevalidationWorkflowMode.REPAIR: "CleanReinitializationRestartReport",
    RevalidationWorkflowMode.REVALIDATE: "RevalidationReceipt",
    RevalidationWorkflowMode.RECONSOLIDATE: "RevalidationReceipt",
    RevalidationWorkflowMode.REPORT: "RevalidationReportPreparation",
}

REVALIDATION_WORKFLOW_PHASE_SEQUENCE = tuple(
    mode.value
    for mode in (
        RevalidationWorkflowMode.INSPECT,
        RevalidationWorkflowMode.REPAIR,
        RevalidationWorkflowMode.REVALIDATE,
        RevalidationWorkflowMode.RECONSOLIDATE,
        RevalidationWorkflowMode.REPORT,
    )
)
_NEXT_MODE = {
    RevalidationWorkflowMode.INSPECT: RevalidationWorkflowMode.REPAIR,
    RevalidationWorkflowMode.REPAIR: RevalidationWorkflowMode.REVALIDATE,
    RevalidationWorkflowMode.REVALIDATE: RevalidationWorkflowMode.RECONSOLIDATE,
    RevalidationWorkflowMode.RECONSOLIDATE: RevalidationWorkflowMode.REPORT,
}


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise RevalidationWorkflowError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _plain_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RevalidationWorkflowError(f"{label} must be a mapping")
    try:
        if len(value) > 65_536:
            raise RevalidationWorkflowError(f"{label} exceeds its item bound")
    except TypeError as exc:
        raise RevalidationWorkflowError(f"{label} has no bounded size") from exc
    limits = ParseLimits(max_bytes=MAX_WORKFLOW_RECEIPT_BYTES, max_items=65_536)
    try:
        normalized = parse_json_strict(canonical_bytes(dict(value), limits=limits), limits=limits)
    except (CanonicalError, TypeError, ValueError, UnicodeError) as exc:
        raise RevalidationWorkflowError(f"{label} is not bounded JSON") from exc
    if not isinstance(normalized, dict):
        raise RevalidationWorkflowError(f"{label} must normalize to an object")
    for key in (
        "authority_granted",
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
        "product_credit",
        "report_authoritative",
    ):
        if key in normalized and normalized[key] is not False:
            raise RevalidationWorkflowError(f"{label} carries non-false {key}")
    return normalized


def _bounded_values(value: object, maximum: int, label: str) -> tuple[object, ...]:
    if isinstance(value, (str, bytes)):
        raise RevalidationWorkflowError(f"{label} must be an iterable")
    try:
        iterator = iter(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise RevalidationWorkflowError(f"{label} must be an iterable") from exc
    selected: list[object] = []
    for item in iterator:
        if len(selected) == maximum:
            raise RevalidationWorkflowError(f"{label} exceeds its bound")
        selected.append(item)
    return tuple(selected)


def _bounded_receipts(value: object) -> tuple[RevalidationReceipt, ...]:
    selected = _bounded_values(
        value, MAX_WORKFLOW_PRIOR_RECEIPTS, "prior receipt history"
    )
    result: list[RevalidationReceipt] = []
    for item in selected:
        if isinstance(item, RevalidationReceipt):
            result.append(item)
        elif isinstance(item, Mapping):
            result.append(RevalidationReceipt.from_record(item))
        else:
            raise RevalidationWorkflowError("prior receipt is invalid")
    return tuple(result)


def _revalidation_receipt(value: object) -> RevalidationReceipt:
    if isinstance(value, RevalidationReceipt):
        return value
    if isinstance(value, Mapping):
        return RevalidationReceipt.from_record(value)
    raise RevalidationWorkflowError("revalidation receipt is invalid")


def _published(value: PublishedCleanReinitialization) -> dict[str, object]:
    return {
        "intent_digest": value.intent_digest,
        "package_digest": value.package_digest,
        "extension_admission_digest": value.extension_admission_digest,
        "activation_digest": value.activation_digest,
        "published": True,
        "state_migration_supported": False,
        "previous_progress_imported": False,
        "product_credit": False,
    }


def _same_phase_subject_compatible(
    mode: RevalidationWorkflowMode,
    current: Mapping[str, object],
    previous: Mapping[str, object],
) -> bool:
    """Compare the stable subject of two attempts of one lifecycle phase."""

    if current.get("record_type") != previous.get("record_type"):
        return False
    if mode in {
        RevalidationWorkflowMode.INSPECT,
        RevalidationWorkflowMode.REVALIDATE,
        RevalidationWorkflowMode.RECONSOLIDATE,
    }:
        return current.get("revalidation_plan_digest") == previous.get(
            "revalidation_plan_digest"
        )
    if mode is RevalidationWorkflowMode.REPORT:
        return current.get("source_revalidation_receipt_digest") == previous.get(
            "source_revalidation_receipt_digest"
        )
    return all(
        current.get(key) == previous.get(key)
        for key in (
            "clean_state_admission_digest",
            "intent_digest",
            "writer_liveness_digest",
            "existing_result_digest",
        )
    )


@dataclass(frozen=True, slots=True)
class RevalidationWorkflowAuthority:
    authority_id: str
    implementation_digest: str
    configuration_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.authority_id, str) or _AUTHORITY_ID.fullmatch(self.authority_id) is None:
            raise RevalidationWorkflowError("workflow authority_id is invalid")
        _require_digest(self.implementation_digest, "implementation_digest")
        _require_digest(self.configuration_digest, "configuration_digest")

    def _payload(self) -> dict[str, object]:
        return {
            "record_type": "RevalidationWorkflowAuthority",
            "authority_id": self.authority_id,
            "implementation_digest": self.implementation_digest,
            "configuration_digest": self.configuration_digest,
            "acceptance_pass": False,
            "product_acceptance_pass": False,
            "pass_credit": False,
        }

    @property
    def authority_digest(self) -> str:
        return digest_value(self._payload())

    def to_record(self) -> dict[str, object]:
        return {**self._payload(), "authority_digest": self.authority_digest}


@dataclass(frozen=True, slots=True)
class RevalidationWorkflowPlan:
    workflow_id: str
    mode: RevalidationWorkflowMode
    authority: RevalidationWorkflowAuthority
    receipt_root: Path
    receipt_name: str
    retry_ordinal: int = 1
    predecessor_receipt_digest: str | None = None
    predecessor_receipt: RevalidationWorkflowReceipt | Mapping[str, object] | None = field(default=None, repr=False, compare=False)
    revalidation_plan: RevalidationPlan | None = None
    prior_receipts: Sequence[RevalidationReceipt | Mapping[str, object]] = ()
    report_receipt: RevalidationReceipt | Mapping[str, object] | None = None
    max_phases: int | None = None
    repair_project_root: Path | None = None
    repair_admission: CleanStateAdmission | None = None
    repair_writer_liveness: WriterLivenessReport | None = None
    repair_existing: PublishedCleanReinitialization | None = None
    max_attempts: int | None = None
    required_phase_ids: tuple[str, ...] = field(init=False)
    receipt_root_identity: Mapping[str, object] = field(init=False)
    repair_project_root_identity: Mapping[str, object] = field(init=False)
    subject_identity: Mapping[str, object] = field(init=False)
    subject_digest: str = field(init=False)
    semantic_subject_identity: Mapping[str, object] = field(init=False)
    semantic_subject_digest: str = field(init=False)
    workflow_semantic_identity: Mapping[str, object] = field(init=False)
    workflow_semantic_digest: str = field(init=False)
    transition_kind: str = field(init=False)
    phase_index: int = field(init=False)
    plan_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.workflow_id, str) or _WORKFLOW_ID.fullmatch(self.workflow_id) is None:
            raise RevalidationWorkflowError("workflow_id is invalid")
        if not isinstance(self.mode, RevalidationWorkflowMode):
            raise RevalidationWorkflowError("workflow mode is invalid")
        if not isinstance(self.authority, RevalidationWorkflowAuthority):
            raise RevalidationWorkflowError("workflow authority is required")
        root = Path(self.receipt_root).absolute()
        if not root.is_dir():
            raise RevalidationWorkflowError("receipt root must be an existing directory")
        if not isinstance(self.receipt_name, str) or _RECEIPT_NAME.fullmatch(self.receipt_name) is None:
            raise RevalidationWorkflowError("receipt_name must be a bounded JSON leaf")
        if type(self.retry_ordinal) is not int or not 1 <= self.retry_ordinal <= MAX_WORKFLOW_RETRIES:
            raise RevalidationWorkflowError("retry_ordinal is outside its bound")

        predecessor = None
        if self.predecessor_receipt is not None:
            predecessor = (
                self.predecessor_receipt
                if isinstance(self.predecessor_receipt, RevalidationWorkflowReceipt)
                else RevalidationWorkflowReceipt.from_record(self.predecessor_receipt)
            )

        priors = _bounded_receipts(self.prior_receipts)
        required: tuple[str, ...] = ()
        repair_identity: dict[str, object] = {}
        semantic_subject: dict[str, object]
        if self.mode in {RevalidationWorkflowMode.INSPECT, RevalidationWorkflowMode.REVALIDATE, RevalidationWorkflowMode.RECONSOLIDATE}:
            if not isinstance(self.revalidation_plan, RevalidationPlan):
                raise RevalidationWorkflowError("mode requires RevalidationPlan")
            if any(
                value is not None
                for value in (
                    self.report_receipt,
                    self.repair_project_root,
                    self.repair_admission,
                    self.repair_writer_liveness,
                    self.repair_existing,
                    self.max_attempts,
                )
            ):
                raise RevalidationWorkflowError("mode carries incompatible inputs")
            baseline = reconsolidate_revalidation(self.revalidation_plan, priors)
            if baseline.status is RevalidationStatus.PENDING:
                required = self.revalidation_plan.phase_ids[len(baseline.checkpoints):]
            if self.mode is RevalidationWorkflowMode.REVALIDATE and self.max_phases is not None:
                if type(self.max_phases) is not int or not 1 <= self.max_phases <= len(required):
                    raise RevalidationWorkflowError("max_phases is outside remaining phases")
            elif self.mode is not RevalidationWorkflowMode.REVALIDATE and self.max_phases is not None:
                raise RevalidationWorkflowError("max_phases is limited to revalidate")
            subject = {
                "revalidation_plan_digest": self.revalidation_plan.plan_digest,
                "revalidation_input_digest": self.revalidation_plan.input_digest,
                "restart_identity": self.revalidation_plan.restart_identity,
                "prior_receipt_digests": [item.receipt_digest for item in priors],
                "required_phase_ids": list(required),
                "max_phases": self.max_phases,
            }
            semantic_subject = {
                "record_type": "RevalidationRouteSubject",
                "revalidation_plan_id": self.revalidation_plan.plan_id,
                "revalidation_plan_digest": self.revalidation_plan.plan_digest,
                "revalidation_input_digest": self.revalidation_plan.input_digest,
                "restart_identity": self.revalidation_plan.restart_identity,
                "phase_ids": list(self.revalidation_plan.phase_ids),
                "total_budget_seconds": self.revalidation_plan.total_budget_seconds,
                "max_phases": self.max_phases,
            }
        elif self.mode is RevalidationWorkflowMode.REPORT:
            report = _revalidation_receipt(self.report_receipt)
            if (
                self.revalidation_plan is not None
                or priors
                or self.repair_project_root is not None
                or self.repair_admission is not None
                or self.repair_writer_liveness is not None
                or self.repair_existing is not None
                or self.max_attempts is not None
                or self.max_phases is not None
            ):
                raise RevalidationWorkflowError("report mode carries incompatible inputs")
            object.__setattr__(self, "report_receipt", report)
            subject = {"source_revalidation_receipt_digest": report.receipt_digest}
            semantic_subject = {
                "record_type": "RevalidationReportSubject",
                "source_revalidation_receipt_digest": report.receipt_digest,
                "revalidation_plan_digest": report.plan_digest,
            }
        else:
            if (
                self.revalidation_plan is not None
                or priors
                or self.report_receipt is not None
                or self.max_phases is not None
            ):
                raise RevalidationWorkflowError("repair mode carries incompatible inputs")
            if not isinstance(self.repair_admission, CleanStateAdmission) or not isinstance(self.repair_writer_liveness, WriterLivenessReport):
                raise RevalidationWorkflowError("repair mode requires recovery inputs")
            if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= MAX_WORKFLOW_RETRIES:
                raise RevalidationWorkflowError("repair max_attempts is outside its bound")
            project = Path(self.repair_project_root).absolute() if self.repair_project_root is not None else None
            if project is None or not project.is_dir():
                raise RevalidationWorkflowError("repair project root is unavailable")
            object.__setattr__(self, "repair_project_root", project)
            if self.repair_existing is not None and not isinstance(
                self.repair_existing, PublishedCleanReinitialization
            ):
                raise RevalidationWorkflowError("repair existing result is invalid")
            existing = (
                None if self.repair_existing is None else _published(self.repair_existing)
            )
            repair_identity = {"path": str(project)}
            subject = {
                "repair_project_root": str(project),
                "clean_state_admission_digest": digest_value(self.repair_admission.to_record()),
                "intent_digest": self.repair_admission.intent.intent_digest,
                "writer_liveness_digest": digest_value(self.repair_writer_liveness.to_record()),
                "existing_result_digest": None if existing is None else digest_value(existing),
                "max_attempts": self.max_attempts,
            }
            semantic_subject = {
                "record_type": "CleanReinitializationSubject",
                "clean_state_admission_digest": digest_value(
                    self.repair_admission.to_record()
                ),
                "intent_digest": self.repair_admission.intent.intent_digest,
                "package_digest": self.repair_admission.intent.package_digest,
                "extension_admission_digest": (
                    self.repair_admission.intent.extension_admission_digest
                ),
                "writer_liveness_digest": digest_value(
                    self.repair_writer_liveness.to_record()
                ),
                "existing_result_digest": (
                    None if existing is None else digest_value(existing)
                ),
                "max_attempts": self.max_attempts,
            }

        normalized = _plain_mapping(subject, "workflow subject")
        semantic = _plain_mapping(semantic_subject, "workflow semantic subject")
        subject_digest = digest_value(normalized)
        semantic_subject_digest = digest_value(semantic)

        if predecessor is None:
            if self.mode is not RevalidationWorkflowMode.INSPECT:
                raise RevalidationWorkflowError("workflow must start with inspect")
            if self.retry_ordinal != 1 or self.predecessor_receipt_digest is not None:
                raise RevalidationWorkflowError(
                    "initial inspect cannot have a predecessor or retry ordinal"
                )
            transition_kind = "START"
            workflow_semantic_identity = _plain_mapping(
                {
                    "schema": REVALIDATION_WORKFLOW_SCHEMA,
                    "record_type": "RevalidationWorkflowSemanticIdentity",
                    "workflow_id": self.workflow_id,
                    "authority_id": self.authority.authority_id,
                    "authority_digest": self.authority.authority_digest,
                    "implementation_digest": self.authority.implementation_digest,
                    "configuration_digest": self.authority.configuration_digest,
                    "initial_subject_identity": semantic,
                    "phase_sequence": list(REVALIDATION_WORKFLOW_PHASE_SEQUENCE),
                    "acceptance_pass": False,
                    "product_acceptance_pass": False,
                    "pass_credit": False,
                },
                "workflow semantic identity",
            )
        else:
            if self.predecessor_receipt_digest is None:
                raise RevalidationWorkflowError("workflow continuation requires predecessor digest")
            if predecessor.receipt_digest != self.predecessor_receipt_digest:
                raise RevalidationWorkflowError("predecessor receipt digest differs")
            if predecessor.workflow_id != self.workflow_id:
                raise RevalidationWorkflowError("predecessor belongs to another workflow")
            if predecessor.authority_digest != self.authority.authority_digest:
                raise RevalidationWorkflowError("predecessor belongs to another authority")
            workflow_semantic_identity = _plain_mapping(
                predecessor.workflow_semantic_identity,
                "predecessor workflow semantic identity",
            )
            if self.mode is predecessor.mode:
                if self.retry_ordinal != predecessor.retry_ordinal + 1:
                    raise RevalidationWorkflowError(
                        "same-phase retry ordinal is not contiguous"
                    )
                if not _same_phase_subject_compatible(
                    self.mode,
                    semantic,
                    predecessor.semantic_subject_identity,
                ):
                    raise RevalidationWorkflowError(
                        "same-phase retry changed its semantic subject"
                    )
                transition_kind = "RETRY"
            else:
                expected = _NEXT_MODE.get(predecessor.mode)
                if expected is not self.mode:
                    raise RevalidationWorkflowError("workflow phase transition is invalid")
                if self.retry_ordinal != 1:
                    raise RevalidationWorkflowError(
                        "a new workflow phase must start at retry ordinal one"
                    )
                if predecessor.execution_state != "RESULT_RECORDED":
                    raise RevalidationWorkflowError(
                        "failed workflow phase must be retried before advancing"
                    )
                if (
                    predecessor.mode is RevalidationWorkflowMode.REPAIR
                    and predecessor.result.get("published") is not True
                ):
                    raise RevalidationWorkflowError(
                        "repair must publish a result before revalidation"
                    )
                transition_kind = "ADVANCE"

        workflow_semantic_digest = digest_value(workflow_semantic_identity)
        if (
            predecessor is not None
            and predecessor.workflow_semantic_digest != workflow_semantic_digest
        ):
            raise RevalidationWorkflowError("predecessor workflow identity differs")

        initial_subject = workflow_semantic_identity.get("initial_subject_identity")
        if not isinstance(initial_subject, Mapping):
            raise RevalidationWorkflowError("workflow initial subject identity is invalid")
        if self.mode in {
            RevalidationWorkflowMode.INSPECT,
            RevalidationWorkflowMode.REVALIDATE,
            RevalidationWorkflowMode.RECONSOLIDATE,
        } and semantic.get("revalidation_plan_digest") != initial_subject.get(
            "revalidation_plan_digest"
        ):
            raise RevalidationWorkflowError(
                "revalidation route differs from the inspected workflow subject"
            )
        if self.mode is RevalidationWorkflowMode.REPORT and semantic.get(
            "revalidation_plan_digest"
        ) != initial_subject.get("revalidation_plan_digest"):
            raise RevalidationWorkflowError(
                "report receipt differs from the inspected workflow subject"
            )

        if (
            predecessor is not None
            and predecessor.result_kind == "RevalidationReceipt"
            and predecessor.execution_state == "RESULT_RECORDED"
            and self.mode
            in {
                RevalidationWorkflowMode.REVALIDATE,
                RevalidationWorkflowMode.RECONSOLIDATE,
            }
        ):
            resumed = RevalidationReceipt.from_record(predecessor.result)
            if resumed.receipt_digest not in {item.receipt_digest for item in priors}:
                raise RevalidationWorkflowError(
                    "continuation prior receipts do not include the predecessor result"
                )
        if (
            predecessor is not None
            and self.mode is RevalidationWorkflowMode.REPORT
            and predecessor.mode is RevalidationWorkflowMode.RECONSOLIDATE
            and dict(predecessor.result) != self.report_receipt.to_record()  # type: ignore[union-attr]
        ):
            raise RevalidationWorkflowError(
                "report input is not the reconsolidated predecessor result"
            )

        object.__setattr__(self, "receipt_root", root)
        object.__setattr__(self, "receipt_root_identity", {"path": str(root)})
        object.__setattr__(self, "repair_project_root_identity", repair_identity)
        object.__setattr__(self, "prior_receipts", priors)
        object.__setattr__(self, "predecessor_receipt", predecessor)
        object.__setattr__(self, "required_phase_ids", required)
        object.__setattr__(self, "subject_identity", normalized)
        object.__setattr__(self, "subject_digest", subject_digest)
        object.__setattr__(self, "semantic_subject_identity", semantic)
        object.__setattr__(self, "semantic_subject_digest", semantic_subject_digest)
        object.__setattr__(
            self, "workflow_semantic_identity", workflow_semantic_identity
        )
        object.__setattr__(self, "workflow_semantic_digest", workflow_semantic_digest)
        object.__setattr__(self, "transition_kind", transition_kind)
        object.__setattr__(
            self,
            "phase_index",
            REVALIDATION_WORKFLOW_PHASE_SEQUENCE.index(self.mode.value),
        )
        object.__setattr__(self, "plan_digest", digest_value(self._payload()))

    @property
    def receipt_path(self) -> Path:
        return self.receipt_root / self.receipt_name

    @property
    def read_only_operation(self) -> bool:
        return self.mode is not RevalidationWorkflowMode.REPAIR

    def _payload(self) -> dict[str, object]:
        return {
            "schema": REVALIDATION_WORKFLOW_SCHEMA,
            "record_type": "RevalidationWorkflowPlan",
            "workflow_id": self.workflow_id,
            "mode": self.mode.value,
            "authority": self.authority.to_record(),
            "authority_digest": self.authority.authority_digest,
            "workflow_semantic_identity": dict(self.workflow_semantic_identity),
            "workflow_semantic_digest": self.workflow_semantic_digest,
            "phase_sequence": list(REVALIDATION_WORKFLOW_PHASE_SEQUENCE),
            "phase_index": self.phase_index,
            "transition_kind": self.transition_kind,
            "receipt_root_identity": dict(self.receipt_root_identity),
            "receipt_name": self.receipt_name,
            "retry_ordinal": self.retry_ordinal,
            "predecessor_receipt_digest": self.predecessor_receipt_digest,
            "subject_identity": dict(self.subject_identity),
            "subject_digest": self.subject_digest,
            "semantic_subject_identity": dict(self.semantic_subject_identity),
            "semantic_subject_digest": self.semantic_subject_digest,
            "required_phase_ids": list(self.required_phase_ids),
            "read_only_operation": self.read_only_operation,
            "plan_only": True,
            "execution_performed": False,
            "filesystem_writes": 0,
            "hidden_tool_invocations": 0,
            "acceptance_pass": False,
            "product_acceptance_pass": False,
            "pass_credit": False,
        }

    def to_record(self) -> dict[str, object]:
        return {**self._payload(), "plan_digest": self.plan_digest}


@dataclass(frozen=True, slots=True)
class RevalidationWorkflowReceipt:
    workflow_id: str
    mode: RevalidationWorkflowMode
    plan_digest: str
    authority_digest: str
    workflow_semantic_identity: Mapping[str, object]
    workflow_semantic_digest: str
    semantic_subject_identity: Mapping[str, object]
    semantic_subject_digest: str
    phase_index: int
    transition_kind: str
    subject_digest: str
    retry_ordinal: int
    predecessor_receipt_digest: str | None
    execution_state: str
    result_kind: str
    result: Mapping[str, object]
    result_digest: str
    read_only_operation: bool

    def __post_init__(self) -> None:
        if not isinstance(self.workflow_id, str) or _WORKFLOW_ID.fullmatch(self.workflow_id) is None:
            raise RevalidationWorkflowError("workflow receipt id is invalid")
        if not isinstance(self.mode, RevalidationWorkflowMode):
            raise RevalidationWorkflowError("workflow receipt mode is invalid")
        _require_digest(self.plan_digest, "plan_digest")
        _require_digest(self.authority_digest, "authority_digest")
        workflow_identity = _plain_mapping(
            self.workflow_semantic_identity, "workflow semantic identity"
        )
        if (
            set(workflow_identity)
            != {
                "schema",
                "record_type",
                "workflow_id",
                "authority_id",
                "authority_digest",
                "implementation_digest",
                "configuration_digest",
                "initial_subject_identity",
                "phase_sequence",
                "acceptance_pass",
                "product_acceptance_pass",
                "pass_credit",
            }
            or workflow_identity["schema"] != REVALIDATION_WORKFLOW_SCHEMA
            or workflow_identity["record_type"]
            != "RevalidationWorkflowSemanticIdentity"
            or workflow_identity["workflow_id"] != self.workflow_id
            or workflow_identity["authority_digest"] != self.authority_digest
            or workflow_identity["phase_sequence"]
            != list(REVALIDATION_WORKFLOW_PHASE_SEQUENCE)
        ):
            raise RevalidationWorkflowError("workflow semantic identity is invalid")
        try:
            semantic_authority = RevalidationWorkflowAuthority(
                authority_id=workflow_identity["authority_id"],
                implementation_digest=workflow_identity["implementation_digest"],
                configuration_digest=workflow_identity["configuration_digest"],
            )
        except (TypeError, RevalidationWorkflowError) as exc:
            raise RevalidationWorkflowError(
                "workflow semantic authority is invalid"
            ) from exc
        if semantic_authority.authority_digest != self.authority_digest:
            raise RevalidationWorkflowError("workflow semantic authority differs")
        if not isinstance(workflow_identity["initial_subject_identity"], Mapping):
            raise RevalidationWorkflowError("workflow initial subject identity is invalid")
        _require_digest(self.workflow_semantic_digest, "workflow_semantic_digest")
        if digest_value(workflow_identity) != self.workflow_semantic_digest:
            raise RevalidationWorkflowError("workflow semantic digest differs")
        semantic_subject = _plain_mapping(
            self.semantic_subject_identity, "workflow semantic subject"
        )
        _require_digest(self.semantic_subject_digest, "semantic_subject_digest")
        if digest_value(semantic_subject) != self.semantic_subject_digest:
            raise RevalidationWorkflowError("semantic subject digest differs")
        if (
            type(self.phase_index) is not int
            or self.phase_index
            != REVALIDATION_WORKFLOW_PHASE_SEQUENCE.index(self.mode.value)
        ):
            raise RevalidationWorkflowError("workflow receipt phase index is invalid")
        if self.transition_kind not in {"START", "ADVANCE", "RETRY"}:
            raise RevalidationWorkflowError("workflow receipt transition is invalid")
        _require_digest(self.subject_digest, "subject_digest")
        if type(self.retry_ordinal) is not int or not 1 <= self.retry_ordinal <= MAX_WORKFLOW_RETRIES:
            raise RevalidationWorkflowError("workflow receipt ordinal is invalid")
        if self.predecessor_receipt_digest is not None:
            _require_digest(self.predecessor_receipt_digest, "predecessor_receipt_digest")
        if self.transition_kind == "START" and (
            self.mode is not RevalidationWorkflowMode.INSPECT
            or self.retry_ordinal != 1
            or self.predecessor_receipt_digest is not None
        ):
            raise RevalidationWorkflowError("workflow start receipt is invalid")
        if self.transition_kind == "ADVANCE" and (
            self.retry_ordinal != 1 or self.predecessor_receipt_digest is None
        ):
            raise RevalidationWorkflowError("workflow advance receipt is invalid")
        if self.transition_kind == "RETRY" and (
            self.retry_ordinal < 2 or self.predecessor_receipt_digest is None
        ):
            raise RevalidationWorkflowError("workflow retry receipt is invalid")
        if self.execution_state not in {"RESULT_RECORDED", "FAILURE_RECORDED"}:
            raise RevalidationWorkflowError("workflow receipt state is invalid")
        result = _plain_mapping(self.result, "workflow result")
        if digest_value(result) != self.result_digest:
            raise RevalidationWorkflowError("workflow result digest differs")
        expected = "RevalidationWorkflowFailure" if self.execution_state == "FAILURE_RECORDED" else _RESULT_KINDS[self.mode]
        if self.result_kind != expected or result.get("record_type") != expected:
            raise RevalidationWorkflowError("workflow result kind differs")
        if type(self.read_only_operation) is not bool or self.read_only_operation != (
            self.mode is not RevalidationWorkflowMode.REPAIR
        ):
            raise RevalidationWorkflowError("workflow read-only classification differs")
        object.__setattr__(self, "workflow_semantic_identity", workflow_identity)
        object.__setattr__(self, "semantic_subject_identity", semantic_subject)
        object.__setattr__(self, "result", result)

    def _payload(self) -> dict[str, object]:
        return {
            "schema": REVALIDATION_WORKFLOW_SCHEMA,
            "record_type": "RevalidationWorkflowReceipt",
            "workflow_id": self.workflow_id,
            "mode": self.mode.value,
            "plan_digest": self.plan_digest,
            "authority_digest": self.authority_digest,
            "workflow_semantic_identity": dict(self.workflow_semantic_identity),
            "workflow_semantic_digest": self.workflow_semantic_digest,
            "semantic_subject_identity": dict(self.semantic_subject_identity),
            "semantic_subject_digest": self.semantic_subject_digest,
            "phase_sequence": list(REVALIDATION_WORKFLOW_PHASE_SEQUENCE),
            "phase_index": self.phase_index,
            "transition_kind": self.transition_kind,
            "subject_digest": self.subject_digest,
            "retry_ordinal": self.retry_ordinal,
            "predecessor_receipt_digest": self.predecessor_receipt_digest,
            "execution_state": self.execution_state,
            "result_kind": self.result_kind,
            "result": dict(self.result),
            "result_digest": self.result_digest,
            "read_only_operation": self.read_only_operation,
            "receipt_create_only": True,
            "workflow_receipt_writes": 1,
            "callback_invocation_policy": "explicit-caller-supplied-only",
            "hidden_tool_invocations": 0,
            "acceptance_pass": False,
            "product_acceptance_pass": False,
            "pass_credit": False,
        }

    @property
    def receipt_digest(self) -> str:
        return digest_value(self._payload())

    def to_record(self) -> dict[str, object]:
        return {**self._payload(), "receipt_digest": self.receipt_digest}

    @classmethod
    def from_record(cls, value: Mapping[str, object]) -> RevalidationWorkflowReceipt:
        required = {
            "schema", "record_type", "workflow_id", "mode", "plan_digest",
            "authority_digest", "workflow_semantic_identity",
            "workflow_semantic_digest", "semantic_subject_identity",
            "semantic_subject_digest", "phase_sequence", "phase_index",
            "transition_kind", "subject_digest", "retry_ordinal",
            "predecessor_receipt_digest", "execution_state", "result_kind",
            "result", "result_digest", "read_only_operation", "receipt_create_only",
            "workflow_receipt_writes", "callback_invocation_policy",
            "hidden_tool_invocations", "acceptance_pass",
            "product_acceptance_pass", "pass_credit", "receipt_digest",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise RevalidationWorkflowError("workflow receipt fields are invalid")
        if (
            value["schema"] != REVALIDATION_WORKFLOW_SCHEMA
            or value["record_type"] != "RevalidationWorkflowReceipt"
            or value["phase_sequence"] != list(REVALIDATION_WORKFLOW_PHASE_SEQUENCE)
            or value["receipt_create_only"] is not True
            or value["workflow_receipt_writes"] != 1
            or value["hidden_tool_invocations"] != 0
            or value["acceptance_pass"] is not False
            or value["product_acceptance_pass"] is not False
            or value["pass_credit"] is not False
        ):
            raise RevalidationWorkflowError("workflow receipt invariants are invalid")
        try:
            mode = RevalidationWorkflowMode(value["mode"])
        except (TypeError, ValueError) as exc:
            raise RevalidationWorkflowError("workflow receipt mode is invalid") from exc
        receipt = cls(
            workflow_id=value["workflow_id"], mode=mode, plan_digest=value["plan_digest"],
            authority_digest=value["authority_digest"],
            workflow_semantic_identity=value["workflow_semantic_identity"],
            workflow_semantic_digest=value["workflow_semantic_digest"],
            semantic_subject_identity=value["semantic_subject_identity"],
            semantic_subject_digest=value["semantic_subject_digest"],
            phase_index=value["phase_index"], transition_kind=value["transition_kind"],
            subject_digest=value["subject_digest"],
            retry_ordinal=value["retry_ordinal"], predecessor_receipt_digest=value["predecessor_receipt_digest"],
            execution_state=value["execution_state"], result_kind=value["result_kind"],
            result=value["result"], result_digest=value["result_digest"],
            read_only_operation=value["read_only_operation"],
        )  # type: ignore[arg-type]
        if value["receipt_digest"] != receipt.receipt_digest:
            raise RevalidationWorkflowError("workflow receipt digest differs")
        return receipt


def plan_revalidation_workflow(plan: RevalidationWorkflowPlan) -> dict[str, object]:
    """Return the deterministic no-write representation of a workflow plan."""

    if not isinstance(plan, RevalidationWorkflowPlan):
        raise RevalidationWorkflowError("workflow plan is required")
    if plan.receipt_path.exists():
        raise RevalidationWorkflowError(f"workflow receipt already exists: {plan.receipt_path}")
    return plan.to_record()


def _inspection(plan: RevalidationWorkflowPlan) -> dict[str, object]:
    assert plan.revalidation_plan is not None
    baseline = reconsolidate_revalidation(plan.revalidation_plan, plan.prior_receipts)
    identity = {
        "schema": REVALIDATION_WORKFLOW_SCHEMA,
        "record_type": "RevalidationWorkflowInspection",
        "revalidation_plan": plan.revalidation_plan.to_record(),
        "reconciliation": baseline.to_record(),
        "prior_receipt_digests": [item.receipt_digest for item in plan.prior_receipts],
        "required_phase_ids": list(plan.required_phase_ids),
        "read_only": True,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "pass_credit": False,
        "effects": {"filesystem_writes": 0, "provider_invocations": 0},
    }
    return {**identity, "inspection_digest": digest_value(identity)}


def _operation(
    plan: RevalidationWorkflowPlan,
    callbacks: tuple[ReadOnlyRevalidationCallback, ...],
    verifier: Callable[[PublishedCleanReinitialization], bool] | None,
    attempt: CleanReinitializationAttempt | None,
) -> tuple[str, dict[str, object]]:
    if plan.mode is RevalidationWorkflowMode.INSPECT:
        return _RESULT_KINDS[plan.mode], _inspection(plan)
    if plan.mode is RevalidationWorkflowMode.REVALIDATE:
        assert plan.revalidation_plan is not None
        result = revalidate_recovery(plan.revalidation_plan, callbacks, prior_receipts=plan.prior_receipts, max_phases=plan.max_phases)
        return _RESULT_KINDS[plan.mode], result.to_record()
    if plan.mode is RevalidationWorkflowMode.RECONSOLIDATE:
        assert plan.revalidation_plan is not None
        result = reconsolidate_revalidation(plan.revalidation_plan, plan.prior_receipts)
        return _RESULT_KINDS[plan.mode], result.to_record()
    if plan.mode is RevalidationWorkflowMode.REPORT:
        assert isinstance(plan.report_receipt, RevalidationReceipt)
        return _RESULT_KINDS[plan.mode], prepare_revalidation_report(plan.report_receipt)
    if verifier is None or attempt is None:
        raise RevalidationWorkflowError("repair requires explicit verifier and attempt callbacks")
    assert plan.repair_project_root is not None
    assert plan.repair_admission is not None
    assert plan.repair_writer_liveness is not None
    assert plan.max_attempts is not None
    result = run_bounded_clean_reinitialization(
        plan.repair_project_root,
        plan.repair_admission,
        plan.repair_writer_liveness,
        max_attempts=plan.max_attempts,
        existing=plan.repair_existing,
        verifier=verifier,
        attempt=attempt,
    )
    return _RESULT_KINDS[plan.mode], result.to_record()


def _failure(error: BaseException) -> dict[str, object]:
    identity = {
        "schema": REVALIDATION_WORKFLOW_SCHEMA,
        "record_type": "RevalidationWorkflowFailure",
        "exception_type": type(error).__name__[:128] or "Exception",
        "reason": "explicit workflow operation raised an exception",
        "authoritative": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "pass_credit": False,
    }
    return {**identity, "failure_digest": digest_value(identity)}


def execute_revalidation_workflow(
    plan: RevalidationWorkflowPlan,
    *,
    callbacks: Iterable[ReadOnlyRevalidationCallback] = (),
    repair_verifier: Callable[[PublishedCleanReinitialization], bool] | None = None,
    repair_attempt: CleanReinitializationAttempt | None = None,
) -> RevalidationWorkflowReceipt:
    """Execute one workflow and create one canonical result receipt."""

    plan_revalidation_workflow(plan)
    selected = _bounded_values(
        callbacks, MAX_WORKFLOW_PRIOR_RECEIPTS, "callbacks"
    )
    if plan.mode is RevalidationWorkflowMode.REVALIDATE:
        if not all(isinstance(item, ReadOnlyRevalidationCallback) for item in selected):
            raise RevalidationWorkflowError("callbacks must be revalidation callbacks")
        if {item.phase_id for item in selected} != set(plan.required_phase_ids):
            raise RevalidationWorkflowError("callbacks must cover remaining phases")
    elif selected:
        raise RevalidationWorkflowError("callbacks are limited to revalidate mode")

    try:
        result_kind, result = _operation(plan, selected, repair_verifier, repair_attempt)
        execution_state = "RESULT_RECORDED"
    except Exception as exc:
        result_kind, result = "RevalidationWorkflowFailure", _failure(exc)
        execution_state = "FAILURE_RECORDED"
    normalized = _plain_mapping(result, "workflow result")
    receipt = RevalidationWorkflowReceipt(
        workflow_id=plan.workflow_id,
        mode=plan.mode,
        plan_digest=plan.plan_digest,
        authority_digest=plan.authority.authority_digest,
        workflow_semantic_identity=plan.workflow_semantic_identity,
        workflow_semantic_digest=plan.workflow_semantic_digest,
        semantic_subject_identity=plan.semantic_subject_identity,
        semantic_subject_digest=plan.semantic_subject_digest,
        phase_index=plan.phase_index,
        transition_kind=plan.transition_kind,
        subject_digest=plan.subject_digest,
        retry_ordinal=plan.retry_ordinal,
        predecessor_receipt_digest=plan.predecessor_receipt_digest,
        execution_state=execution_state,
        result_kind=result_kind,
        result=normalized,
        result_digest=digest_value(normalized),
        read_only_operation=plan.read_only_operation,
    )
    payload = canonical_bytes(receipt.to_record(), limits=ParseLimits(max_bytes=MAX_WORKFLOW_RECEIPT_BYTES, max_items=65_536))
    try:
        descriptor = os.open(plan.receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as exc:
        raise RevalidationWorkflowError(f"workflow receipt already exists: {plan.receipt_path}") from exc
    except OSError as exc:
        raise RevalidationWorkflowError("workflow receipt cannot be written") from exc
    return receipt


def load_revalidation_workflow_receipt(
    path: str | os.PathLike[str], *, expected_plan_digest: str | None = None
) -> RevalidationWorkflowReceipt:
    """Load a canonical workflow receipt for review or retry."""

    if expected_plan_digest is not None:
        _require_digest(expected_plan_digest, "expected_plan_digest")
    try:
        limits = ParseLimits(max_bytes=MAX_WORKFLOW_RECEIPT_BYTES, max_items=65_536)
        with Path(path).open("rb") as handle:
            payload = handle.read(MAX_WORKFLOW_RECEIPT_BYTES + 1)
        value = parse_json_strict(payload, limits=limits)
        if not isinstance(value, dict) or canonical_bytes(value, limits=limits) != payload:
            raise RevalidationWorkflowError("workflow receipt is not canonical JSON")
        receipt = RevalidationWorkflowReceipt.from_record(value)
    except (OSError, CanonicalError, RevalidationWorkflowError) as exc:
        raise RevalidationWorkflowError("workflow receipt cannot be read") from exc
    if expected_plan_digest is not None and receipt.plan_digest != expected_plan_digest:
        raise RevalidationWorkflowError("workflow receipt belongs to another plan")
    return receipt


__all__ = [
    "MAX_WORKFLOW_PRIOR_RECEIPTS",
    "MAX_WORKFLOW_RECEIPT_BYTES",
    "MAX_WORKFLOW_RETRIES",
    "REVALIDATION_WORKFLOW_SCHEMA",
    "REVALIDATION_WORKFLOW_PHASE_SEQUENCE",
    "RevalidationWorkflowAuthority",
    "RevalidationWorkflowError",
    "RevalidationWorkflowMode",
    "RevalidationWorkflowPlan",
    "RevalidationWorkflowReceipt",
    "execute_revalidation_workflow",
    "load_revalidation_workflow_receipt",
    "plan_revalidation_workflow",
]
