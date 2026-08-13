"""Stateful Promin domain invariants for lifecycle and acceptance records."""

from __future__ import annotations

from copy import deepcopy
from collections.abc import Iterator, MutableMapping
from dataclasses import dataclass
from functools import wraps
import posixpath
import threading
from typing import Any, Iterable, Mapping
import unicodedata

from .authority import (
    AuthorityEngine,
    AuthorityError,
    GATE_AUTHORIZATION_SCOPE_CONTRACT,
    canonical_digest,
    derived_checkpoint_digest,
    parse_timestamp,
    validate_gate_authorization_scope,
)
from .canonical import canonical_bytes
from .evidence import EvidenceError, EvidenceStore


class DomainError(ValueError):
    """Raised when a record violates its current-state domain invariant."""


@dataclass(frozen=True)
class DomainFreezeResult:
    """Truthful publication and optional overlay-compaction measurements."""

    snapshot: "DomainState"
    changed_leaf_count: int
    compacted: bool
    compacted_record_count: int
    compacted_payload_bytes: int


class _OverlayMap(MutableMapping[Any, Any]):
    """O(changed-key) transaction overlay over an immutable published view."""

    def __init__(self, base: Mapping[Any, Any]) -> None:
        self._base = base
        self._writes: dict[Any, Any] = {}
        self._deletes: set[Any] = set()

    def __getitem__(self, key: Any) -> Any:
        if key in self._writes:
            return self._writes[key]
        if key in self._deletes:
            raise KeyError(key)
        return self._base[key]

    def __setitem__(self, key: Any, value: Any) -> None:
        self._writes[key] = value
        self._deletes.discard(key)

    def __delitem__(self, key: Any) -> None:
        if key not in self:
            raise KeyError(key)
        self._writes.pop(key, None)
        self._deletes.add(key)

    def __iter__(self) -> Iterator[Any]:
        yielded: set[Any] = set()
        for key in self._writes:
            if key not in self._deletes:
                yielded.add(key)
                yield key
        for key in self._base:
            if key not in yielded and key not in self._deletes:
                yield key

    def __len__(self) -> int:
        return sum(1 for _ in self)


class _ReadOnlyMap(Mapping[Any, Any]):
    """O(1) immutable publication wrapper that never exposes stored values."""

    def __init__(self, base: Mapping[Any, Any]) -> None:
        self._base = base

    def __getitem__(self, key: Any) -> Any:
        return deepcopy(self._base[key])

    def __iter__(self) -> Iterator[Any]:
        return iter(self._base)

    def __len__(self) -> int:
        return len(self._base)


def _materialize_overlay(mapping: Mapping[Any, Any]) -> dict[Any, Any]:
    """Flatten one bounded overlay chain in one base pass plus changed leaves."""

    source: Mapping[Any, Any] = mapping
    layers: list[_OverlayMap] = []
    while True:
        if isinstance(source, _ReadOnlyMap):
            source = source._base
            continue
        if isinstance(source, _OverlayMap):
            layers.append(source)
            source = source._base
            continue
        break
    materialized = {key: deepcopy(source[key]) for key in source}
    for layer in reversed(layers):
        for key in layer._deletes:
            materialized.pop(key, None)
        for key, value in layer._writes.items():
            materialized[key] = deepcopy(value)
    return materialized


class _AppendLog:
    """Persistent append-only chronology used by an isolated domain fork."""

    def __init__(self, base: Iterable[Any]) -> None:
        self._base = base
        self._appended: list[Any] = []

    def append(self, value: Any) -> None:
        self._appended.append(value)

    def __iter__(self) -> Iterator[Any]:
        yield from self._base
        yield from self._appended

    def __len__(self) -> int:
        return sum(1 for _ in self._base) + len(self._appended)


_TASK_FIELDS = frozenset(
    {
        "record_type",
        "task_id",
        "state",
        "required_capability",
        "acceptance_predicate",
        "allowed_paths",
        "activation_digest",
        "candidate_digest",
        "created_at",
        "gate_run_definitions",
    }
)
_TASK_OPTIONAL_FIELDS = frozenset(
    {
        "operation_profile_id",
        "recommended_model_tier",
        "orchestration_required",
    }
)
_LEASE_FIELDS = frozenset(
    {
        "record_type",
        "lease_id",
        "task_id",
        "manager_subject_id",
        "manager_grant_id",
        "manager_grant_claim_digest",
        "holder_subject_id",
        "holder_grant_id",
        "holder_grant_claim_digest",
        "generation",
        "fencing_token",
        "state",
        "acquired_at",
        "heartbeat_at",
        "expires_at",
        "activation_digest",
    }
)
_CAPACITY_RECONCILIATION_FIELDS = frozenset(
    {
        "reconciled_by",
        "grant_id",
        "grant_claim_digest",
        "reconciled_at",
        "generation",
        "fencing_token",
    }
)
_LEASE_CLOSE_ACK_FIELDS = frozenset(
    {"acknowledged_by", "grant_id", "grant_claim_digest", "acknowledged_at"}
)
_LEASE_TERMINATION_FIELDS = frozenset(
    {
        "state",
        "terminated_by",
        "grant_id",
        "grant_claim_digest",
        "terminated_at",
        "generation",
        "fencing_token",
    }
)
_ARTIFACT_REFERENCE_FIELDS = frozenset({"artifact_id", "artifact_record_digest"})
_GATE_ARTIFACT_REFERENCE_FIELDS = frozenset(
    {"artifact_id", "artifact_record_digest", "run_id", "run_digest"}
)
_GATE_DEFINITION_FIELDS = frozenset(
    {
        "definition_kind",
        "definition_id",
        "owner_kind",
        "owner_digest",
        "defined_at_head_digest",
        "gate_id",
        "run_kind",
        "expected_evidence_class",
        "expected_evidence_purpose",
        "product_credit_required",
        "target_kind",
        "target_digest",
        "target_scope",
        "candidate_digest",
        "policy_digest",
        "tool_digest",
        "implementation_closure_digest",
        "provider_binding_digest",
        "input_digests",
        "activation_digest",
    }
)
_GATE_BINDING_FIELDS = frozenset({"definition_digest", "definition"})
_FINDING_FIELDS = frozenset(
    {
        "record_type",
        "finding_id",
        "status",
        "severity",
        "blocking",
        "statement",
        "activation_digest",
        "candidate_digest",
        "evidence_artifacts",
        "created_at",
    }
)
_GATE_FIELDS = frozenset(
    {
        "record_type",
        "task_id",
        "gate_id",
        "run_id",
        "run_digest",
        "definition_digest",
        "status",
        "outcome",
        "pass_credit",
        "activation_digest",
        "candidate_digest",
        "policy_digest",
        "tool_digest",
        "evidence_class",
        "evidence_artifacts",
    }
)
_RUN_FIELDS = frozenset(
    {
        "record_type",
        "run_id",
        "run_kind",
        "task_id",
        "candidate_digest",
        "policy_digest",
        "tool_digest",
        "input_digests",
        "status",
        "started_at",
        "finished_at",
        "activation_digest",
        "definition_digest",
        "implementation_closure_digest",
        "provider_binding_digest",
    }
)
_DECISION_COMMON_FIELDS = frozenset(
    {
        "record_type",
        "decision_id",
        "decision_kind",
        "subject_id",
        "grant_id",
        "grant_claim_digest",
        "activation_digest",
        "target_type",
        "target_id",
        "target_digest",
        "rationale",
        "evidence_artifacts",
        "created_at",
    }
)
_DECISION_BASE_FIELDS = frozenset({*_DECISION_COMMON_FIELDS, "candidate_digest"})
_DECISION_RELEASE_FIELDS = frozenset(
    {*_DECISION_BASE_FIELDS, "release_closure_digest", "provider_binding_digest"}
)
_DECISION_FINDING_FIELDS = frozenset(
    {*_DECISION_BASE_FIELDS, "finding_digest"}
)
_DECISION_WAIVER_FIELDS = frozenset(
    {
        *_DECISION_FINDING_FIELDS,
        "exception_policy_digest",
        "expires_at",
    }
)
_DECISION_REVOKE_FIELDS = _DECISION_COMMON_FIELDS
_CANDIDATE_BASE_FIELDS = frozenset(
    {
        "record_type",
        "candidate_id",
        "candidate_digest",
        "inventory_digest",
        "product_root_digest",
        "control_excluded",
        "candidate_recipe_digest",
        "consistency_mode",
        "creditable",
    }
)
_CANDIDATE_SNAPSHOT_FIELDS = frozenset(
    {*_CANDIDATE_BASE_FIELDS, "snapshot_provider_id", "snapshot_digest"}
)


def _valid_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise DomainError("invalid changed path")
    normalized_unicode = unicodedata.normalize("NFC", value)
    if normalized_unicode != value or "\\" in value or "\x00" in value:
        raise DomainError("changed path is not canonical POSIX NFC")
    normalized = posixpath.normpath(value)
    if (
        value.startswith("/")
        or normalized in {"", ".", ".."}
        or normalized.startswith("../")
        or normalized != value.rstrip("/")
    ):
        raise DomainError("changed path escapes the product root")
    return normalized


def _path_within(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _serialized_lease_transition(method: Any) -> Any:
    @wraps(method)
    def invoke(state: "DomainState", *args: Any, **kwargs: Any) -> Any:
        with state._lease_transition_lock:
            return method(state, *args, **kwargs)

    return invoke


class DomainState:
    """In-memory authoritative projection used while applying event commands.

    The event store remains the durable authority.  Replaying accepted events
    reconstructs this object and re-runs the same transition checks.
    """

    def __init__(
        self,
        authority: AuthorityEngine,
        evidence: EvidenceStore,
        *,
        required_acceptance: Iterable[str] = (),
        provider_binding_digest: str | None = None,
        implementation_closure_digest: str | None = None,
        gate_authorization_scope_contract: Mapping[str, Any] | None = None,
    ) -> None:
        self.authority = authority
        self.evidence = evidence
        required = tuple(required_acceptance)
        if (
            any(not isinstance(value, str) or not value for value in required)
            or len(set(required)) != len(required)
        ):
            raise DomainError("required acceptance IDs must be unique non-empty strings")
        if provider_binding_digest is not None and not _valid_digest(
            provider_binding_digest
        ):
            raise DomainError("provider binding digest must be a SHA-256 digest")
        if implementation_closure_digest is not None and not _valid_digest(
            implementation_closure_digest
        ):
            raise DomainError("implementation closure digest must be a SHA-256 digest")
        self.required_acceptance = frozenset(required)
        self.provider_binding_digest = provider_binding_digest
        self.implementation_closure_digest = implementation_closure_digest
        gate_scope_contract = (
            GATE_AUTHORIZATION_SCOPE_CONTRACT
            if gate_authorization_scope_contract is None
            else dict(gate_authorization_scope_contract)
        )
        if gate_scope_contract != GATE_AUTHORIZATION_SCOPE_CONTRACT:
            raise DomainError("gate authorization scope contract differs from Core policy")
        self.gate_authorization_scope_contract = deepcopy(gate_scope_contract)
        self.tasks: dict[str, dict[str, Any]] = {}
        self.candidates: dict[str, dict[str, Any]] = {}
        self.leases: dict[str, dict[str, Any]] = {}
        self.findings: dict[str, dict[str, Any]] = {}
        self.gate_results: dict[tuple[str, str], dict[str, Any]] = {}
        self.decisions: dict[str, dict[str, Any]] = {}
        self._candidate_ids_by_digest: dict[str, str] = {}
        self._task_lease_generation: dict[str, int] = {}
        self._task_fence: dict[str, int] = {}
        self._gate_runs: dict[str, dict[str, Any]] = {}
        self._gate_result_order: list[tuple[str, str]] = []
        self._decision_order: list[str] = []
        self._lease_transition_lock = threading.RLock()
        self._frozen = False
        self._overlay_depth = 0
        self._freeze_compaction_depth: int | None = None
        self._freeze_result: DomainFreezeResult | None = None
        self._frozen_changed_records: tuple[dict[str, Any], ...] = ()

    def _assert_writable(self) -> None:
        if self._frozen:
            raise DomainError("published DomainState is immutable; fork it first")

    def freeze(
        self, *, runtime_overlay_compaction_depth: int
    ) -> DomainFreezeResult:
        """Publish this state and compact only at the verified overlay threshold."""

        if (
            not isinstance(runtime_overlay_compaction_depth, int)
            or isinstance(runtime_overlay_compaction_depth, bool)
            or runtime_overlay_compaction_depth < 1
        ):
            raise DomainError("runtime overlay compaction depth is invalid")
        if self._freeze_result is not None:
            if self._freeze_compaction_depth != runtime_overlay_compaction_depth:
                raise DomainError("published DomainState compaction policy changed")
            return self._freeze_result
        if not self.authority.is_frozen:
            raise DomainError("DomainState publication requires frozen authority")

        changed_records = self.changed_persistent_records()
        compacted = self._overlay_depth >= runtime_overlay_compaction_depth
        compacted_record_count = 0
        compacted_payload_bytes = 0
        record_fields = (
            "tasks",
            "candidates",
            "leases",
            "findings",
            "gate_results",
            "decisions",
        )
        index_fields = (
            "_candidate_ids_by_digest",
            "_task_lease_generation",
            "_task_fence",
            "_gate_runs",
        )
        if compacted:
            for field in (*record_fields, *index_fields):
                mapping = getattr(self, field)
                materialized = _materialize_overlay(mapping)
                setattr(self, field, materialized)
                if field in record_fields:
                    compacted_record_count += len(materialized)
                    compacted_payload_bytes += sum(
                        len(canonical_bytes(record))
                        for record in materialized.values()
                    )
            self._gate_result_order = tuple(self._gate_result_order)
            self._decision_order = tuple(self._decision_order)
            self._overlay_depth = 0

        for field in (
            *record_fields,
            *index_fields,
        ):
            mapping = getattr(self, field)
            if not isinstance(mapping, _ReadOnlyMap):
                setattr(self, field, _ReadOnlyMap(mapping))
        self._frozen = True
        self._freeze_compaction_depth = runtime_overlay_compaction_depth
        self._frozen_changed_records = tuple(deepcopy(changed_records))
        result = DomainFreezeResult(
            snapshot=self,
            changed_leaf_count=len(changed_records),
            compacted=compacted,
            compacted_record_count=compacted_record_count,
            compacted_payload_bytes=compacted_payload_bytes,
        )
        self._freeze_result = result
        return result

    def fork(self, *, authority: AuthorityEngine) -> "DomainState":
        """Create an O(1) writable overlay bound to an isolated authority fork."""

        if not self._frozen:
            raise DomainError("DomainState must be frozen before it can be forked")
        if authority is self.authority:
            raise DomainError("DomainState fork requires an isolated AuthorityEngine")
        if not self.authority.is_frozen or authority.is_frozen:
            raise DomainError("DomainState fork requires a writable authority fork")
        if authority.activation_digest != self.authority.activation_digest:
            raise DomainError("DomainState fork Authority Activation mismatch")
        forked = object.__new__(DomainState)
        forked.authority = authority
        forked.evidence = self.evidence
        forked.required_acceptance = self.required_acceptance
        forked.provider_binding_digest = self.provider_binding_digest
        forked.implementation_closure_digest = self.implementation_closure_digest
        forked.gate_authorization_scope_contract = (
            self.gate_authorization_scope_contract
        )
        forked.tasks = _OverlayMap(self.tasks)
        forked.candidates = _OverlayMap(self.candidates)
        forked.leases = _OverlayMap(self.leases)
        forked.findings = _OverlayMap(self.findings)
        forked.gate_results = _OverlayMap(self.gate_results)
        forked.decisions = _OverlayMap(self.decisions)
        forked._candidate_ids_by_digest = _OverlayMap(
            self._candidate_ids_by_digest
        )
        forked._task_lease_generation = _OverlayMap(self._task_lease_generation)
        forked._task_fence = _OverlayMap(self._task_fence)
        forked._gate_runs = _OverlayMap(self._gate_runs)
        forked._gate_result_order = _AppendLog(self._gate_result_order)
        forked._decision_order = _AppendLog(self._decision_order)
        forked._lease_transition_lock = threading.RLock()
        forked._frozen = False
        forked._overlay_depth = self._overlay_depth + 1
        forked._freeze_compaction_depth = None
        forked._freeze_result = None
        forked._frozen_changed_records = ()
        return forked

    def _persistent_mappings(
        self,
    ) -> tuple[tuple[str, Mapping[Any, Mapping[str, Any]]], ...]:
        return (
            ("Task", self.tasks),
            ("Candidate", self.candidates),
            ("Lease", self.leases),
            ("Finding", self.findings),
            ("GateResult", self.gate_results),
            ("Decision", self.decisions),
        )

    def persistent_records(self) -> list[dict[str, Any]]:
        """Expose complete Domain values while EventStore owns Merkle identity."""

        return [
            {"leaf_type": leaf_type, "value": self._copy(mapping[key])}
            for leaf_type, mapping in self._persistent_mappings()
            for key in sorted(mapping)
        ]

    def changed_persistent_records(self) -> list[dict[str, Any]]:
        """Expose only transaction-local post-state values, never Merkle claims."""

        if self._frozen:
            return deepcopy(list(self._frozen_changed_records))
        changed: list[dict[str, Any]] = []
        for leaf_type, mapping in self._persistent_mappings():
            source = mapping._base if isinstance(mapping, _ReadOnlyMap) else mapping
            writes = source._writes if isinstance(source, _OverlayMap) else {}
            changed.extend(
                {"leaf_type": leaf_type, "value": self._copy(writes[key])}
                for key in sorted(writes)
            )
        return changed

    @staticmethod
    def _copy(record: Mapping[str, Any]) -> dict[str, Any]:
        return deepcopy(dict(record))

    @staticmethod
    def _require_fields(
        record: Mapping[str, Any], fields: frozenset[str], record_type: str
    ) -> None:
        if set(record) != fields or record.get("record_type") != record_type:
            raise DomainError(f"{record_type} does not match the Core shape")

    @staticmethod
    def _require_decision_fields(decision: Mapping[str, Any]) -> None:
        kind = decision.get("decision_kind")
        fields = (
            _DECISION_RELEASE_FIELDS
            if kind == "release"
            else _DECISION_REVOKE_FIELDS
            if kind == "revoke"
            else _DECISION_WAIVER_FIELDS
            if kind == "waive"
            else _DECISION_FINDING_FIELDS
            if kind == "resolve"
            else _DECISION_BASE_FIELDS
        )
        DomainState._require_fields(decision, fields, "Decision")
        for field in (
            "grant_claim_digest",
            "target_digest",
            "release_closure_digest",
            "provider_binding_digest",
            "finding_digest",
            "exception_policy_digest",
            "candidate_digest",
        ):
            if field in decision and not _valid_digest(decision[field]):
                raise DomainError(f"Decision {field} must be a SHA-256 digest")

    @staticmethod
    def _require_gate_fields(result: Mapping[str, Any]) -> None:
        status = result.get("status")
        fields = set(result)
        required = _GATE_FIELDS | (
            {"reason"} if status in {"blocked", "skipped"} else set()
        )
        allowed = _GATE_FIELDS | ({"reason"} if status != "pass" else set())
        if (
            not required <= fields
            or not fields <= allowed
            or result.get("record_type") != "GateResult"
        ):
            raise DomainError("GateResult does not match the Core shape")

    @staticmethod
    def _validate_gate_run(
        run: Mapping[str, Any],
        result: Mapping[str, Any],
        definition: Mapping[str, Any],
        evaluation_time: Any | None,
    ) -> dict[str, Any]:
        if not isinstance(run, Mapping) or set(run) != _RUN_FIELDS:
            raise DomainError("GateResult Run does not match the Core shape")
        value = deepcopy(dict(run))
        if (
            value.get("record_type") != "Run"
            or not isinstance(value.get("run_id"), str)
            or not value["run_id"]
            or not isinstance(value.get("task_id"), str)
            or not value["task_id"]
            or value.get("run_kind") not in {"execution", "validation"}
            or value.get("status") not in {"pass", "fail", "blocked", "skipped", "error"}
        ):
            raise DomainError("GateResult Run identity or status is invalid")
        digest_fields = (
            "candidate_digest",
            "policy_digest",
            "tool_digest",
            "activation_digest",
            "definition_digest",
            "implementation_closure_digest",
            "provider_binding_digest",
        )
        inputs = value.get("input_digests")
        if (
            any(not _valid_digest(value.get(field)) for field in digest_fields)
            or not isinstance(inputs, list)
            or len(inputs) > 128
            or len(inputs) != len(set(inputs))
            or any(not _valid_digest(item) for item in inputs)
        ):
            raise DomainError("GateResult Run digest binding is invalid")
        started_at = parse_timestamp(value["started_at"])
        finished_at = parse_timestamp(value["finished_at"])
        if not started_at <= finished_at or (
            evaluation_time is not None and finished_at > evaluation_time
        ):
            raise DomainError("GateResult Run chronology is invalid")
        expected_status = "fail" if value["status"] == "error" else value["status"]
        if expected_status != result["status"]:
            raise DomainError("GateResult status differs from its Run")
        if (
            value["run_id"] != result["run_id"]
            or result.get("run_digest") != canonical_digest(value)
            or value["task_id"] != result["task_id"]
            or value["definition_digest"] != result["definition_digest"]
            or value["run_kind"] != definition["run_kind"]
            or any(
                value[field] != definition[field]
                for field in (
                    "candidate_digest",
                    "policy_digest",
                    "tool_digest",
                    "implementation_closure_digest",
                    "provider_binding_digest",
                    "input_digests",
                    "activation_digest",
                )
            )
        ):
            raise DomainError("GateResult Run differs from its definition")
        return value

    @staticmethod
    def _task_owner_digest(task: Mapping[str, Any]) -> str:
        return canonical_digest(
            {
                key: deepcopy(value)
                for key, value in task.items()
                if key not in {"state", "gate_run_definitions"}
            }
        )

    @staticmethod
    def _open_finding_digests(finding: Mapping[str, Any]) -> frozenset[str]:
        value = deepcopy(dict(finding))
        if value.get("status") == "OPEN":
            return frozenset({canonical_digest(value)})
        value["status"] = "OPEN"
        value.pop("disposition_decision_id", None)
        return frozenset(
            canonical_digest({**value, "blocking": blocking})
            for blocking in (False, True)
        )

    def _validate_task_gate_definitions(
        self,
        task: Mapping[str, Any],
        *,
        finding_records: Mapping[str, Mapping[str, Any]] | None = None,
        allow_historical_findings: bool = False,
    ) -> None:
        raw = task.get("gate_run_definitions")
        if not isinstance(raw, list) or not raw or len(raw) > 64:
            raise DomainError("Task requires a bounded GateRunDefinition set")
        owner_digest = self._task_owner_digest(task)
        definition_ids: set[str] = set()
        definition_digests: set[str] = set()
        gate_ids: set[str] = set()
        for binding in raw:
            if not isinstance(binding, Mapping) or set(binding) != _GATE_BINDING_FIELDS:
                raise DomainError("Task GateRunDefinition binding shape is invalid")
            definition = binding.get("definition")
            if (
                not isinstance(definition, Mapping)
                or set(definition) != _GATE_DEFINITION_FIELDS
                or definition.get("definition_kind") != "GateRunDefinition"
                or definition.get("owner_kind") != "Task"
                or definition.get("owner_digest") != owner_digest
                or binding.get("definition_digest") != canonical_digest(definition)
            ):
                raise DomainError("Task GateRunDefinition provenance is invalid")
            definition_id = definition.get("definition_id")
            definition_digest = binding["definition_digest"]
            if (
                not isinstance(definition_id, str)
                or not definition_id
                or definition_id in definition_ids
                or definition_digest in definition_digests
            ):
                raise DomainError("Task GateRunDefinition identity is duplicated")
            definition_ids.add(definition_id)
            definition_digests.add(definition_digest)
            gate_id = definition.get("gate_id")
            if not isinstance(gate_id, str) or not gate_id or gate_id in gate_ids:
                raise DomainError("Task GateRunDefinition gate identity is duplicated")
            gate_ids.add(gate_id)
            defined_head = definition.get("defined_at_head_digest")
            digest_fields = (
                "candidate_digest",
                "policy_digest",
                "tool_digest",
                "implementation_closure_digest",
                "provider_binding_digest",
                "activation_digest",
            )
            inputs = definition.get("input_digests")
            scope = definition.get("target_scope")
            if (
                any(not _valid_digest(definition.get(field)) for field in digest_fields)
                or (defined_head is not None and not _valid_digest(defined_head))
                or definition["candidate_digest"] != task.get("candidate_digest")
                or definition["activation_digest"] != task.get("activation_digest")
                or self.implementation_closure_digest is None
                or definition["implementation_closure_digest"]
                != self.implementation_closure_digest
                or not isinstance(inputs, list)
                or len(inputs) > 128
                or len(inputs) != len(set(inputs))
                or any(not _valid_digest(value) for value in inputs)
                or not isinstance(scope, list)
                or not scope
                or len(scope) > 32
                or len({canonical_digest(item) for item in scope}) != len(scope)
                or any(
                    not isinstance(item, Mapping)
                    or set(item) != {"kind", "value"}
                    or item.get("kind")
                    not in {"project", "path", "task", "candidate", "artifact", "finding", "all"}
                    or not isinstance(item.get("value"), str)
                    or not item["value"]
                    for item in scope
                )
            ):
                raise DomainError("Task GateRunDefinition binding is degraded")
            evidence_class = definition.get("expected_evidence_class")
            evidence_purpose = definition.get("expected_evidence_purpose")
            product_required = definition.get("product_credit_required")
            compatible_pairs = {
                ("validator", "diagnostic"),
                ("validator", "gate"),
                ("product-execution", "gate"),
                ("product-execution", "product"),
            }
            if (
                evidence_class
                not in {"product-execution", "validator", "harness-generated", "migration"}
                or evidence_purpose not in {"product", "gate", "diagnostic"}
                or (evidence_class, evidence_purpose) not in compatible_pairs
                or not isinstance(product_required, bool)
                or definition.get("target_kind") not in {"candidate", "finding"}
                or not _valid_digest(definition.get("target_digest"))
                or (
                    definition.get("target_kind") == "candidate"
                    and definition.get("target_digest")
                    != definition.get("candidate_digest")
                )
                or (
                    product_required
                    and (
                        evidence_class != "product-execution"
                        or evidence_purpose != "product"
                    )
                )
                or definition.get("run_kind") not in {"execution", "validation"}
            ):
                raise DomainError("Task GateRunDefinition evidence expectation is invalid")
            finding_selectors = [
                item["value"]
                for item in scope
                if item["kind"] == "finding"
            ]
            if definition["target_kind"] == "candidate":
                if finding_selectors:
                    raise DomainError("Candidate GateRunDefinition carries a Finding target")
                continue
            if len(finding_selectors) != 1:
                raise DomainError("Finding GateRunDefinition target scope is not exact")
            if finding_records is None:
                continue
            finding = finding_records.get(finding_selectors[0])
            if finding is None:
                raise DomainError("Finding GateRunDefinition target is unresolved")
            target = self._copy(finding)
            if target.get("status") != "OPEN" and not allow_historical_findings:
                raise DomainError("Finding GateRunDefinition target is not OPEN")
            if (
                target.get("candidate_digest") != task.get("candidate_digest")
                or definition["target_digest"] not in self._open_finding_digests(target)
            ):
                raise DomainError("Finding GateRunDefinition target digest is stale")

    def _resolve_gate_definition(
        self, task_id: str, definition_digest: str
    ) -> dict[str, Any]:
        task = self.tasks.get(task_id)
        if task is None:
            raise DomainError("GateResult Task owner is unresolved")
        matches = [
            binding["definition"]
            for binding in task["gate_run_definitions"]
            if binding["definition_digest"] == definition_digest
            and canonical_digest(binding["definition"]) == definition_digest
        ]
        if len(matches) != 1:
            raise DomainError("GateResult definition does not resolve exactly once")
        return self._copy(matches[0])

    def resolve_gate_definition(
        self, task_id: str, definition_digest: str
    ) -> dict[str, Any]:
        """Resolve one immutable Task-owned definition without exposing storage."""

        return self._resolve_gate_definition(task_id, definition_digest)

    @staticmethod
    def _assert_authorization_time(
        record_time: str, authorization: Mapping[str, Any], label: str
    ) -> None:
        if parse_timestamp(record_time) != parse_timestamp(
            authorization.get("evaluated_at")
        ):
            raise DomainError(f"{label} time is not command-bound")

    def _artifact_records(
        self,
        references: Any,
        *,
        allow_empty: bool = False,
    ) -> list[tuple[dict[str, str], dict[str, Any], dict[str, Any]]]:
        if (
            not isinstance(references, list)
            or (not allow_empty and not references)
            or len(references) > 64
            or any(
                not isinstance(reference, Mapping)
                or set(reference) != _ARTIFACT_REFERENCE_FIELDS
                for reference in references
            )
        ):
            raise DomainError("evidence Artifact references are not exact and bounded")
        normalized = [dict(reference) for reference in references]
        identities = [
            (reference.get("artifact_id"), reference.get("artifact_record_digest"))
            for reference in normalized
        ]
        if (
            len(identities) != len(set(identities))
            or len({identity[0] for identity in identities}) != len(identities)
        ):
            raise DomainError("evidence Artifact references are duplicated")
        resolved: list[tuple[dict[str, str], dict[str, Any], dict[str, Any]]] = []
        for reference in normalized:
            artifact_id = reference["artifact_id"]
            record_digest = reference["artifact_record_digest"]
            if (
                not isinstance(artifact_id, str)
                or not artifact_id
                or not _valid_digest(record_digest)
            ):
                raise DomainError("evidence Artifact reference identity is invalid")
            try:
                record = self.evidence.get_record(artifact_id)
            except EvidenceError as exc:
                raise DomainError("evidence Artifact record is unresolved") from exc
            artifact = record.get("artifact")
            if (
                canonical_digest(record) != record_digest
                or not isinstance(artifact, Mapping)
                or artifact.get("artifact_id") != artifact_id
            ):
                raise DomainError("evidence Artifact record digest mismatch")
            resolved.append(
                (self._copy(reference), self._copy(record), self._copy(artifact))
            )
        return resolved

    def _artifact_is_current(
        self, reference: Mapping[str, str]
    ) -> bool:
        if self.implementation_closure_digest is None:
            return False
        return self.evidence.has_current_implementation_binding(
            reference["artifact_id"],
            reference["artifact_record_digest"],
            activation_digest=self.authority.activation_digest,
            implementation_closure_digest=self.implementation_closure_digest,
        )

    @staticmethod
    def _reject_harness_product_mix(
        artifacts: Iterable[Mapping[str, Any]],
    ) -> None:
        classes = {artifact.get("evidence_class") for artifact in artifacts}
        if {"harness-generated", "product-execution"} <= classes:
            raise DomainError(
                "harness-generated and product-execution evidence cannot be mixed"
            )

    @staticmethod
    def _require_task_fields(task: Mapping[str, Any]) -> None:
        actual = set(task)
        if (
            not _TASK_FIELDS <= actual
            or not actual <= set(_TASK_FIELDS) | set(_TASK_OPTIONAL_FIELDS)
            or task.get("record_type") != "Task"
        ):
            raise DomainError("Task does not match the Core shape")
        tier = task.get("recommended_model_tier")
        if tier is not None and tier not in {
            "tool-only", "micro", "standard", "strong", "critical-review"
        }:
            raise DomainError("Task recommended model tier is invalid")
        operation_profile = task.get("operation_profile_id")
        if operation_profile is not None and (
            not isinstance(operation_profile, str) or not operation_profile
        ):
            raise DomainError("Task operation profile is invalid")
        if "orchestration_required" in task and task["orchestration_required"] is not True:
            raise DomainError("Task orchestration flag cannot be disabled in alpha")

    @staticmethod
    def _require_candidate_fields(candidate: Mapping[str, Any]) -> None:
        immutable = candidate.get("consistency_mode") == "immutable-vcs-tree"
        required = _CANDIDATE_SNAPSHOT_FIELDS if immutable else _CANDIDATE_BASE_FIELDS
        optional = {"baseline_kind", "specification_digest"}
        actual = set(candidate)
        if (
            not required <= actual
            or not actual <= set(required) | optional
            or candidate.get("record_type") != "Candidate"
        ):
            raise DomainError("Candidate does not match the Core shape")
        for field in (
            "candidate_digest",
            "inventory_digest",
            "product_root_digest",
            "candidate_recipe_digest",
        ):
            if not _valid_digest(candidate[field]):
                raise DomainError(f"Candidate {field} must be a SHA-256 digest")
        baseline_kind = candidate.get("baseline_kind")
        if baseline_kind is not None:
            if baseline_kind not in {"specification", "product", "hybrid"}:
                raise DomainError("Candidate baseline_kind is invalid")
            has_specification = "specification_digest" in candidate
            if baseline_kind in {"specification", "hybrid"}:
                if not has_specification or not _valid_digest(
                    candidate.get("specification_digest")
                ):
                    raise DomainError(
                        "specification or hybrid Candidate lacks a specification digest"
                    )
            elif has_specification:
                raise DomainError(
                    "product Candidate cannot carry a specification digest"
                )
        elif "specification_digest" in candidate:
            raise DomainError(
                "Candidate specification digest requires an explicit baseline kind"
            )
        if immutable:
            if (
                candidate["creditable"] is not True
                or not isinstance(candidate["snapshot_provider_id"], str)
                or not candidate["snapshot_provider_id"]
                or not _valid_digest(candidate["snapshot_digest"])
            ):
                raise DomainError("immutable Candidate lacks snapshot provider proof")
        elif (
            candidate.get("consistency_mode") != "observational-best-effort"
            or candidate.get("creditable") is not False
        ):
            raise DomainError("observational Candidate cannot receive release credit")

    @staticmethod
    def _requested_scope(
        authorization: Mapping[str, Any], effect: Mapping[str, str]
    ) -> list[Mapping[str, Any]]:
        required = {
            "subject_id",
            "grant_id",
            "claim_digest",
            "evaluated_at",
            "requested_scope",
        }
        if set(authorization) != required:
            raise DomainError("authorization must bind subject, Grant claim, time, and scope")
        requested = authorization["requested_scope"]
        if not isinstance(requested, list) or not requested:
            raise DomainError("authorization requested scope is empty")
        effect_pair = (effect["kind"], effect["value"])
        pairs = {(item.get("kind"), item.get("value")) for item in requested}
        if ("all", "*") not in pairs and effect_pair not in pairs:
            raise DomainError("authorization scope omits the command effect target")
        return requested

    def _authorize(
        self,
        authorization: Mapping[str, Any],
        capability: str,
        effect: Mapping[str, str],
        *,
        candidate_digest: str | None = None,
        finding_id: str | None = None,
    ) -> dict[str, Any]:
        requested = self._requested_scope(authorization, effect)
        try:
            return self.authority.authorize(
                authorization["subject_id"],
                capability,
                requested,
                authorization["grant_id"],
                authorization["claim_digest"],
                authorization["evaluated_at"],
                candidate_digest=candidate_digest,
                finding_id=finding_id,
            )
        except AuthorityError as exc:
            raise DomainError(str(exc)) from exc

    def _assert_activation(self, record: Mapping[str, Any]) -> None:
        if record.get("activation_digest") != self.authority.activation_digest:
            raise DomainError("record Activation mismatch")

    def _task_definitions_satisfied(self, task_id: str) -> bool:
        task = self.tasks[task_id]
        latest: dict[str, Mapping[str, Any]] = {}
        for key in self._gate_result_order:
            result = self.gate_results[key]
            if result["task_id"] == task_id:
                latest[result["definition_digest"]] = result
        for binding in task["gate_run_definitions"]:
            result = latest.get(binding["definition_digest"])
            if result is None or result["status"] != "pass":
                return False
            requires_credit = binding["definition"]["product_credit_required"]
            if result["pass_credit"] is not requires_credit:
                return False
            if not self._gate_evidence_current(result):
                return False
        return True

    def record_task(
        self, task: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._assert_writable()
        self._require_task_fields(task)
        self._assert_activation(task)
        task_id = task["task_id"]
        if task_id in self.tasks:
            if canonical_digest(self.tasks[task_id]) == canonical_digest(task):
                return self._copy(self.tasks[task_id])
            raise DomainError("Task ID already identifies another Task")
        if task["state"] != "PLANNED":
            raise DomainError("new Task must begin in PLANNED")
        if task["required_capability"] not in self.authority.capabilities:
            raise DomainError("Task requires an unknown capability")
        if task["candidate_digest"] not in self._candidate_ids_by_digest:
            raise DomainError("Task Candidate is unresolved")
        if not isinstance(task["acceptance_predicate"], str) or not task["acceptance_predicate"]:
            raise DomainError("Task acceptance predicate is required")
        paths = task["allowed_paths"]
        if (
            not isinstance(paths, list)
            or len(paths) != len(set(paths))
            or len(paths) > 64
        ):
            raise DomainError("Task allowed paths must be unique and bounded")
        [_relative_path(path) for path in paths]
        self._validate_task_gate_definitions(task, finding_records=self.findings)
        self._assert_authorization_time(task["created_at"], authorization, "Task")
        self._authorize(
            authorization,
            "task.plan",
            {"kind": "task", "value": task_id},
            candidate_digest=task["candidate_digest"],
        )
        self.tasks[task_id] = self._copy(task)
        return self._copy(task)

    def transition_task(
        self,
        transition: Mapping[str, Any],
        authorization: Mapping[str, Any],
        *,
        runtime_policy: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._assert_writable()
        if set(transition) != {"task_id", "from_state", "to_state", "reason"}:
            raise DomainError("invalid TaskTransition shape")
        task = self.tasks.get(transition["task_id"])
        if task is None:
            raise DomainError("TaskTransition references an unresolved Task")
        if task["state"] != transition["from_state"]:
            raise DomainError("TaskTransition from_state is stale")
        task_transitions = self._runtime_policy(runtime_policy)[1]
        allowed = task_transitions.get(task["state"])
        if allowed is None or transition["to_state"] not in allowed:
            raise DomainError("illegal Task state transition")
        if not isinstance(transition["reason"], str) or not transition["reason"]:
            raise DomainError("TaskTransition reason is required")
        self._authorize(
            authorization,
            "task.plan",
            {"kind": "task", "value": task["task_id"]},
            candidate_digest=task["candidate_digest"],
        )
        if transition["to_state"] == "LEASED" and not self._active_lease_for_task(task["task_id"]):
            raise DomainError("Task cannot enter LEASED without the current active Lease")
        if transition["to_state"] == "COMPLETED":
            lease = self._active_lease_for_task(task["task_id"])
            if lease is None or lease["state"] not in {"ACTIVE", "CLOSING"}:
                raise DomainError("Task completion requires its current Lease")
            if not self._task_definitions_satisfied(task["task_id"]):
                raise DomainError("Task completion requires every precommitted gate")
        updated = self._copy(task)
        updated["state"] = transition["to_state"]
        self.tasks[updated["task_id"]] = updated
        return self._copy(updated)

    def record_candidate(
        self, candidate: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._assert_writable()
        self._require_candidate_fields(candidate)
        if candidate["control_excluded"] is not True:
            raise DomainError("Candidate product identity must exclude control state")
        candidate_id = candidate["candidate_id"]
        if candidate_id in self.candidates or candidate["candidate_digest"] in self._candidate_ids_by_digest:
            existing_id = self._candidate_ids_by_digest.get(candidate["candidate_digest"], candidate_id)
            existing = self.candidates.get(existing_id)
            if existing is not None and canonical_digest(existing) == canonical_digest(candidate):
                return self._copy(existing)
            raise DomainError("Candidate identity already resolves to different content")
        self._authorize(
            authorization,
            "task.execute",
            {"kind": "candidate", "value": candidate_id},
            candidate_digest=candidate["candidate_digest"],
        )
        self.authority.record_action(
            authorization["subject_id"],
            "task.execute",
            authorization=authorization,
            candidate_digest=candidate["candidate_digest"],
        )
        stored = self._copy(candidate)
        self.candidates[candidate_id] = stored
        self._candidate_ids_by_digest[candidate["candidate_digest"]] = candidate_id
        return self._copy(stored)

    def validate_candidate_delta(
        self,
        artifact_digest: str,
        *,
        task_id: str,
        workcard: Mapping[str, Any],
        authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Bind actual product changes to the Task, WorkCard, and exact Grant scope."""
        try:
            artifacts = [
                artifact
                for artifact in self.evidence.resolved_artifacts(artifact_digest)
                if artifact.get("artifact_kind") == "diff"
            ]
        except EvidenceError as exc:
            raise DomainError("Candidate delta Artifact is unresolved") from exc
        if len(artifacts) != 1:
            raise DomainError("Candidate delta must resolve one immutable diff Artifact")
        artifact = self.preflight_candidate_delta(
            artifacts[0],
            task_id=task_id,
            workcard=workcard,
            authorization=authorization,
        )
        delta = artifact["candidate_delta"]
        try:
            authoritative = self.evidence.require_candidate_delta(
                artifact_digest,
                base_candidate_digest=delta["base_candidate_digest"],
                new_candidate_digest=delta["new_candidate_digest"],
                workcard_digest=delta["workcard_digest"],
            )
        except EvidenceError as exc:
            raise DomainError("Candidate delta binding is not authoritative") from exc
        if authoritative != artifact:
            raise DomainError("Candidate delta authoritative bytes differ from preflight")
        return authoritative

    def preflight_candidate_delta(
        self,
        artifact: Mapping[str, Any],
        *,
        task_id: str,
        workcard: Mapping[str, Any],
        authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Validate a staged diff before its authoritative journal commit."""

        if artifact.get("artifact_kind") != "diff" or not isinstance(
            artifact.get("candidate_delta"), Mapping
        ):
            raise DomainError("Candidate delta requires one diff Artifact")
        task = self.tasks.get(task_id)
        if task is None:
            raise DomainError("Candidate delta Task is unresolved")
        required_card = {
            "record_type",
            "task_id",
            "operation_mode",
            "allowed_paths",
            "holder_grant_id",
            "candidate_digest",
            "activation_digest",
        }
        if (
            not required_card <= set(workcard)
            or workcard.get("record_type") != "WorkCard"
            or workcard.get("operation_mode") != "mutate"
        ):
            raise DomainError("Candidate delta requires one mutate WorkCard")
        if (
            workcard["task_id"] != task_id
            or workcard["candidate_digest"] != task["candidate_digest"]
            or workcard["activation_digest"] != task["activation_digest"]
            or workcard["allowed_paths"] != task["allowed_paths"]
        ):
            raise DomainError("Candidate delta WorkCard differs from its Task")
        value = self._copy(artifact)
        delta = value["candidate_delta"]
        if delta["base_candidate_digest"] != task["candidate_digest"]:
            raise DomainError("Candidate delta base differs from Task Candidate")
        if delta["new_candidate_digest"] not in self._candidate_ids_by_digest:
            raise DomainError("Candidate delta new Candidate is unresolved")
        workcard_digest = canonical_digest(workcard)
        if delta["workcard_digest"] != workcard_digest:
            raise DomainError("Candidate delta WorkCard digest mismatch")
        changed_paths = [_relative_path(value) for value in delta["changed_paths"]]
        allowed_paths = [_relative_path(value) for value in task["allowed_paths"]]
        if not allowed_paths or any(
            not any(_path_within(path, root) for root in allowed_paths)
            for path in changed_paths
        ):
            raise DomainError("Candidate delta changed_paths exceed Task/WorkCard allowed_paths")
        new_candidate_id = self._candidate_ids_by_digest[delta["new_candidate_digest"]]
        grant = self._authorize(
            authorization,
            "task.execute",
            {"kind": "candidate", "value": new_candidate_id},
            candidate_digest=delta["new_candidate_digest"],
        )
        grant_scope = grant["scope"]
        if not any(
            selector.get("kind") == "all" and selector.get("value") == "*"
            for selector in grant_scope
        ):
            grant_paths = [
                _relative_path(selector["value"])
                for selector in grant_scope
                if selector.get("kind") == "path"
            ]
            if not grant_paths or any(
                not any(_path_within(path, root) for root in grant_paths)
                for path in changed_paths
            ):
                raise DomainError("Candidate delta changed_paths exceed Grant path scope")
        return value

    def _active_lease_for_task(self, task_id: str) -> dict[str, Any] | None:
        active = [
            lease
            for lease in self.leases.values()
            if lease["task_id"] == task_id and lease["state"] in {"ACTIVE", "CLOSING"}
        ]
        if len(active) > 1:
            raise DomainError("multiple active Leases for one Task")
        return active[0] if active else None

    @staticmethod
    def _validate_lease_times(lease: Mapping[str, Any]) -> None:
        acquired = parse_timestamp(lease["acquired_at"])
        heartbeat = parse_timestamp(lease["heartbeat_at"])
        expires = parse_timestamp(lease["expires_at"])
        if not acquired <= heartbeat < expires:
            raise DomainError("Lease timestamp order violation")

    def _grant_matches(
        self,
        *,
        grant_id: Any,
        subject_id: Any,
        claim_digest: Any,
        capability_id: str,
    ) -> Mapping[str, Any] | None:
        grant = self.authority.resolve_grant(grant_id)
        if (
            grant is None
            or grant.get("subject_id") != subject_id
            or grant.get("claim_digest") != claim_digest
            or grant.get("capability_id") != capability_id
        ):
            return None
        return grant

    def _validate_capacity_reconciliation(
        self,
        lease: Mapping[str, Any],
        reconciliation: Mapping[str, Any],
        capacity_policy: Mapping[str, Any],
    ) -> dict[str, Any]:
        terminal = capacity_policy["terminal_reconciliation"]
        if lease.get("state") not in set(terminal["states"]):
            raise DomainError("capacity reconciliation requires a terminal Lease")
        if (
            not isinstance(reconciliation, Mapping)
            or set(reconciliation) != _CAPACITY_RECONCILIATION_FIELDS
        ):
            raise DomainError("Lease capacity reconciliation shape is invalid")
        if (
            not isinstance(reconciliation["reconciled_by"], str)
            or not reconciliation["reconciled_by"]
            or not isinstance(reconciliation["grant_id"], str)
            or not reconciliation["grant_id"]
            or not _valid_digest(reconciliation["grant_claim_digest"])
            or not isinstance(reconciliation["generation"], int)
            or isinstance(reconciliation["generation"], bool)
            or reconciliation["generation"] < 1
            or not isinstance(reconciliation["fencing_token"], int)
            or isinstance(reconciliation["fencing_token"], bool)
            or reconciliation["fencing_token"] < 1
        ):
            raise DomainError("Lease capacity reconciliation values are invalid")
        if (
            reconciliation["generation"] != lease["generation"]
            or reconciliation["fencing_token"] != lease["fencing_token"]
        ):
            raise DomainError("Lease capacity reconciliation fence is stale")
        reconciled_at = parse_timestamp(reconciliation["reconciled_at"])
        termination = lease.get("termination")
        if not isinstance(termination, Mapping):
            raise DomainError("Lease capacity reconciliation lacks termination provenance")
        lower_bound = parse_timestamp(termination["terminated_at"])
        if reconciled_at < lower_bound:
            raise DomainError("Lease capacity reconciliation predates termination")
        manager = self._grant_matches(
            grant_id=reconciliation["grant_id"],
            subject_id=reconciliation["reconciled_by"],
            claim_digest=reconciliation["grant_claim_digest"],
            capability_id=terminal["manager_capability"],
        )
        if (
            manager is None
            or manager.get("grant_id") == lease["holder_grant_id"]
        ):
            raise DomainError("Lease capacity reconciliation manager Grant is invalid")
        return manager

    @staticmethod
    def _lease_occupies_capacity(
        lease: Mapping[str, Any],
        capacity_policy: Mapping[str, Any],
    ) -> bool:
        state = lease.get("state")
        closed = capacity_policy["closed_release"]
        terminal = capacity_policy["terminal_reconciliation"]
        if state == closed["state"]:
            return not (
                closed["slot_reusable"] is True
                and closed["requires_field"] in lease
            )
        if state in set(terminal["states"]):
            return not (
                terminal["slot_reusable_after_record"] is True
                and terminal["field"] in lease
            )
        return True

    @classmethod
    def _validate_capacity_fence_progression(
        cls,
        leases: Iterable[Mapping[str, Any]],
        capacity_policy: Mapping[str, Any],
    ) -> None:
        by_task: dict[str, list[Mapping[str, Any]]] = {}
        for lease in leases:
            by_task.setdefault(lease["task_id"], []).append(lease)
        for task_leases in by_task.values():
            occupied = [
                lease
                for lease in task_leases
                if cls._lease_occupies_capacity(lease, capacity_policy)
            ]
            latest_generation = max(lease["generation"] for lease in task_leases)
            if len(occupied) > 1 or any(
                lease["generation"] != latest_generation for lease in occupied
            ):
                raise DomainError(
                    "Task Lease fence advanced before capacity reconciliation"
                )

    def _runtime_policy(
        self,
        policy: Mapping[str, Any] | None,
    ) -> tuple[
        int,
        dict[str, frozenset[str]],
        dict[str, frozenset[str]],
        dict[str, Any],
    ]:
        fields = {
            "activation_digest",
            "implementation_closure_digest",
            "core_bundle_digest",
            "preset_digest",
            "operating_profile",
            "profile_digest",
            "model_tier",
            "max_parallel_tasks",
            "model_tier_rule_digest",
            "policy_set_digest",
            "state_machine_rule_digest",
            "task_transitions",
            "lease_transitions",
            "capacity_release_rule_digest",
            "capacity_release",
            "authority_effect",
        }
        if not isinstance(policy, Mapping) or set(policy) != fields:
            raise DomainError("runtime policy shape is invalid")
        if policy["activation_digest"] != self.authority.activation_digest:
            raise DomainError("runtime parallelism ceiling Activation is stale")
        if (
            self.implementation_closure_digest is None
            or policy["implementation_closure_digest"]
            != self.implementation_closure_digest
        ):
            raise DomainError("runtime parallelism ceiling implementation closure is stale")
        for field in (
            "core_bundle_digest",
            "preset_digest",
            "profile_digest",
            "model_tier_rule_digest",
            "policy_set_digest",
            "state_machine_rule_digest",
            "capacity_release_rule_digest",
        ):
            if not _valid_digest(policy[field]):
                raise DomainError("runtime parallelism ceiling digest is invalid")
        if (
            not isinstance(policy["operating_profile"], str)
            or not policy["operating_profile"]
            or not isinstance(policy["model_tier"], str)
            or not policy["model_tier"]
            or policy["authority_effect"] is not False
        ):
            raise DomainError("runtime parallelism ceiling profile is degraded")
        ceiling = policy["max_parallel_tasks"]
        if not isinstance(ceiling, int) or isinstance(ceiling, bool) or ceiling < 1:
            raise DomainError("runtime parallelism ceiling is degraded")
        compiled: list[dict[str, frozenset[str]]] = []
        for field in ("task_transitions", "lease_transitions"):
            source = policy[field]
            if not isinstance(source, Mapping) or not source:
                raise DomainError("runtime lifecycle policy is degraded")
            states = set(source)
            if any(not isinstance(state, str) or not state for state in states):
                raise DomainError("runtime lifecycle state is invalid")
            transitions: dict[str, frozenset[str]] = {}
            for state, targets in source.items():
                if (
                    not isinstance(targets, list)
                    or any(not isinstance(target, str) for target in targets)
                    or len(targets) != len(set(targets))
                    or any(target not in states for target in targets)
                ):
                    raise DomainError("runtime lifecycle transition graph is invalid")
                transitions[state] = frozenset(targets)
            compiled.append(transitions)
        if canonical_digest(
            {
                "task": policy["task_transitions"],
                "lease": policy["lease_transitions"],
            }
        ) != policy["state_machine_rule_digest"]:
            raise DomainError("runtime lifecycle policy digest is stale")
        capacity = policy["capacity_release"]
        if not isinstance(capacity, Mapping) or set(capacity) != {
            "closed_release",
            "terminal_reconciliation",
            "unreconciled_slot_reusable",
        }:
            raise DomainError("runtime capacity release policy is invalid")
        closed = capacity["closed_release"]
        terminal = capacity["terminal_reconciliation"]
        lease_states = set(compiled[1])
        if (
            not isinstance(closed, Mapping)
            or set(closed) != {"state", "requires_field", "slot_reusable"}
            or closed.get("state") not in lease_states
            or closed.get("requires_field") != "close_ack"
            or closed.get("slot_reusable") is not True
            or not isinstance(terminal, Mapping)
            or set(terminal)
            != {
                "states",
                "field",
                "required_fields",
                "manager_capability",
                "generation_binding",
                "fencing_token_binding",
                "slot_reusable_after_record",
            }
            or not isinstance(terminal.get("states"), list)
            or not terminal["states"]
            or any(not isinstance(state, str) for state in terminal["states"])
            or len(terminal["states"]) != len(set(terminal["states"]))
            or not set(terminal["states"]) <= lease_states
            or terminal.get("field") != "capacity_reconciliation"
            or not isinstance(terminal.get("required_fields"), list)
            or any(
                not isinstance(field, str)
                for field in terminal.get("required_fields", ())
            )
            or len(terminal.get("required_fields", ()))
            != len(set(terminal.get("required_fields", ())))
            or set(terminal.get("required_fields", ()))
            != _CAPACITY_RECONCILIATION_FIELDS
            or terminal.get("manager_capability") != "lease.manage"
            or terminal.get("generation_binding") != "exact-lease-generation"
            or terminal.get("fencing_token_binding")
            != "exact-lease-fencing-token"
            or terminal.get("slot_reusable_after_record") is not True
            or capacity.get("unreconciled_slot_reusable") is not False
            or canonical_digest({"capacity_release": capacity})
            != policy["capacity_release_rule_digest"]
        ):
            raise DomainError("runtime capacity release policy is degraded")
        return ceiling, compiled[0], compiled[1], self._copy(capacity)

    def _parallelism_ceiling(self, policy: Mapping[str, Any]) -> int:
        return self._runtime_policy(policy)[0]

    @_serialized_lease_transition
    def acquire_lease(
        self,
        lease: Mapping[str, Any],
        manager_authorization: Mapping[str, Any],
        *,
        parallelism_policy: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._assert_writable()
        self._require_fields(lease, _LEASE_FIELDS, "Lease")
        self._assert_activation(lease)
        ceiling, _task, _lease, capacity_policy = self._runtime_policy(
            parallelism_policy
        )
        if lease["lease_id"] in self.leases:
            if canonical_digest(self.leases[lease["lease_id"]]) == canonical_digest(lease):
                return self._copy(self.leases[lease["lease_id"]])
            raise DomainError("Lease ID already identifies another Lease")
        task = self.tasks.get(lease["task_id"])
        if task is None or task["state"] != "READY":
            raise DomainError("Lease acquisition requires a READY Task")
        if self._active_lease_for_task(task["task_id"]) is not None:
            raise DomainError("Task already has an active Lease")
        if lease["state"] != "ACTIVE":
            raise DomainError("new Lease must begin in ACTIVE")
        self._validate_lease_times(lease)
        occupied = sum(
            self._lease_occupies_capacity(current, capacity_policy)
            for current in self.leases.values()
        )
        if occupied >= ceiling:
            raise DomainError("runtime parallelism ceiling is exhausted")
        if any(
            current["task_id"] == task["task_id"]
            and self._lease_occupies_capacity(current, capacity_policy)
            for current in self.leases.values()
        ):
            raise DomainError("Task Lease capacity requires reconciliation")
        expected_generation = self._task_lease_generation.get(task["task_id"], 0) + 1
        expected_fence = self._task_fence.get(task["task_id"], 0) + 1
        if lease["generation"] != expected_generation or lease["fencing_token"] != expected_fence:
            raise DomainError("Lease generation or fencing token is not the next value")
        effect = {"kind": "task", "value": task["task_id"]}
        self._authorize(
            manager_authorization,
            "lease.manage",
            effect,
            candidate_digest=task["candidate_digest"],
        )
        if (
            lease["manager_subject_id"] != manager_authorization.get("subject_id")
            or lease["manager_grant_id"] != manager_authorization.get("grant_id")
            or lease["manager_grant_claim_digest"]
            != manager_authorization.get("claim_digest")
            or parse_timestamp(lease["acquired_at"])
            != parse_timestamp(manager_authorization.get("evaluated_at"))
        ):
            raise DomainError("Lease manager provenance is not command-bound")
        holder = self.authority.resolve_grant(lease["holder_grant_id"])
        if (
            holder is None
            or holder.get("subject_id") != lease["holder_subject_id"]
            or holder.get("claim_digest") != lease["holder_grant_claim_digest"]
            or holder.get("capability_id") != "task.execute"
        ):
            raise DomainError("Lease holder Grant is unresolved")
        try:
            holder_requested = [effect]
            if not any(
                item.get("kind") == "all" and item.get("value") == "*"
                for item in holder["scope"]
            ):
                holder_requested = [self._copy(item) for item in holder["scope"]]
                if effect not in holder_requested:
                    holder_requested.append(effect)
            self.authority.authorize(
                lease["holder_subject_id"],
                "task.execute",
                holder_requested,
                lease["holder_grant_id"],
                lease["holder_grant_claim_digest"],
                lease["acquired_at"],
                candidate_digest=task["candidate_digest"],
            )
        except AuthorityError as exc:
            raise DomainError("Lease holder lacks a current task.execute Grant") from exc
        if holder["grant_id"] == manager_authorization["grant_id"]:
            raise DomainError("Lease manager and holder Grants must be distinct")
        stored = self._copy(lease)
        self.leases[lease["lease_id"]] = stored
        self._task_lease_generation[task["task_id"]] = lease["generation"]
        self._task_fence[task["task_id"]] = lease["fencing_token"]
        return self._copy(stored)

    def _current_lease(
        self, lease_id: str, generation: int, fencing_token: int
    ) -> dict[str, Any]:
        lease = self.leases.get(lease_id)
        if lease is None:
            raise DomainError("Lease is unresolved")
        if lease["generation"] != generation or lease["fencing_token"] != fencing_token:
            raise DomainError("stale Lease generation or fencing token")
        if (
            self._task_lease_generation.get(lease["task_id"]) != generation
            or self._task_fence.get(lease["task_id"]) != fencing_token
        ):
            raise DomainError("Lease is not the current Task fence")
        return lease

    @_serialized_lease_transition
    def assert_mutation_lease(
        self,
        *,
        task_id: str,
        lease_id: str,
        generation: int,
        fencing_token: int,
        holder_authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Bind a product mutation to the current live holder fence."""

        lease = self._current_lease(lease_id, generation, fencing_token)
        if lease["task_id"] != task_id or lease["state"] != "ACTIVE":
            raise DomainError("mutation does not bind the current ACTIVE Task Lease")
        evaluated = parse_timestamp(holder_authorization.get("evaluated_at"))
        if evaluated < parse_timestamp(lease["acquired_at"]) or evaluated >= parse_timestamp(
            lease["expires_at"]
        ):
            raise DomainError("mutation Lease is not active at command time")
        if (
            holder_authorization.get("subject_id") != lease["holder_subject_id"]
            or holder_authorization.get("grant_id") != lease["holder_grant_id"]
            or holder_authorization.get("claim_digest")
            != lease["holder_grant_claim_digest"]
        ):
            raise DomainError("mutation does not use the bound Lease holder Grant")
        self._authorize(
            holder_authorization,
            "task.execute",
            {"kind": "task", "value": task_id},
            candidate_digest=self.tasks[task_id]["candidate_digest"],
        )
        self.authority.record_action(
            holder_authorization["subject_id"],
            "task.execute",
            authorization=holder_authorization,
            candidate_digest=self.tasks[task_id]["candidate_digest"],
        )
        return self._copy(lease)

    def assert_mutation_claim(
        self, command: Mapping[str, Any], workcard: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Validate a lease-bound command against its exact bounded WorkCard."""

        required_command = {
            "subject_id",
            "authorization",
            "holder_authorization",
            "requested_scope",
            "issued_at",
            "activation_digest",
            "workcard_task_id",
            "lease_id",
            "lease_generation",
            "fencing_token",
            "workcard_digest",
            "context_digest",
            "payload",
        }
        if not required_command <= set(command):
            raise DomainError("mutation command lacks its WorkCard/Lease binding")
        authorization = command["authorization"]
        if not isinstance(authorization, Mapping) or set(authorization) != {
            "kind",
            "grant_id",
            "grant_claim_digest",
        } or authorization.get("kind") != "grant":
            raise DomainError("mutation requires one exact Grant authorization")
        holder_authorization = command["holder_authorization"]
        if not isinstance(holder_authorization, Mapping) or set(holder_authorization) != {
            "kind",
            "grant_id",
            "grant_claim_digest",
        } or holder_authorization.get("kind") != "grant":
            raise DomainError("mutation requires one exact holder Grant authorization")
        required_card = {
            "record_type",
            "task_id",
            "operation_mode",
            "holder_grant_id",
            "candidate_digest",
            "activation_digest",
            "context_digest",
            "lease_id",
            "lease_generation",
            "fencing_token",
        }
        if not required_card <= set(workcard) or workcard.get("record_type") != "WorkCard":
            raise DomainError("mutation WorkCard is incomplete")
        if workcard.get("operation_mode") != "mutate":
            raise DomainError("product mutation requires a mutate WorkCard")
        if canonical_digest(workcard) != command["workcard_digest"]:
            raise DomainError("mutation WorkCard digest mismatch")
        equalities = (
            (command["workcard_task_id"], workcard["task_id"], "Task"),
            (command["lease_id"], workcard["lease_id"], "Lease"),
            (
                command["lease_generation"],
                workcard["lease_generation"],
                "Lease generation",
            ),
            (command["fencing_token"], workcard["fencing_token"], "fencing token"),
            (command["context_digest"], workcard["context_digest"], "context"),
            (
                command["activation_digest"],
                workcard["activation_digest"],
                "Activation",
            ),
            (
                holder_authorization["grant_id"],
                workcard["holder_grant_id"],
                "holder Grant",
            ),
        )
        for command_value, card_value, label in equalities:
            if command_value != card_value:
                raise DomainError(f"mutation {label} binding mismatch")
        task = self.tasks.get(workcard["task_id"])
        payload = command["payload"]
        ready_to_leased = (
            task is not None
            and task["state"] == "READY"
            and command.get("command_kind") == "task.transition"
            and isinstance(payload, Mapping)
            and payload.get("task_id") == task["task_id"]
            and payload.get("from_state") == "READY"
            and payload.get("to_state") == "LEASED"
        )
        if task is None or (
            task["state"] not in {"LEASED", "RUNNING"} and not ready_to_leased
        ):
            raise DomainError("mutation WorkCard Task is not executable")
        if workcard.get("operation") != command.get("command_kind"):
            raise DomainError("mutation WorkCard operation differs from command")
        if (
            task["candidate_digest"] != workcard["candidate_digest"]
            or task["activation_digest"] != workcard["activation_digest"]
            or task["acceptance_predicate"] != workcard.get("acceptance_predicate")
            or task["allowed_paths"] != workcard.get("allowed_paths")
        ):
            raise DomainError("mutation WorkCard differs from its Task")
        candidate = None
        if isinstance(payload, Mapping):
            candidate = payload.get("candidate_digest")
            binding = payload.get("evidence_binding")
            if candidate is None and isinstance(binding, Mapping):
                candidate = binding.get("candidate_digest")
        if candidate is not None and candidate != workcard["candidate_digest"]:
            raise DomainError("mutation payload Candidate differs from WorkCard")
        holder_evaluation = {
            "subject_id": command["subject_id"],
            "grant_id": holder_authorization["grant_id"],
            "claim_digest": holder_authorization["grant_claim_digest"],
            "evaluated_at": command["issued_at"],
            "requested_scope": command["requested_scope"],
        }
        return self.assert_mutation_lease(
            task_id=command["workcard_task_id"],
            lease_id=command["lease_id"],
            generation=command["lease_generation"],
            fencing_token=command["fencing_token"],
            holder_authorization=holder_evaluation,
        )

    @_serialized_lease_transition
    def heartbeat_lease(
        self,
        lease_id: str,
        generation: int,
        fencing_token: int,
        heartbeat_at: str,
        expires_at: str,
        holder_authorization: Mapping[str, Any],
        *,
        runtime_policy: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._assert_writable()
        self._runtime_policy(runtime_policy)
        lease = self._current_lease(lease_id, generation, fencing_token)
        if lease["state"] != "ACTIVE":
            raise DomainError("only ACTIVE Lease may heartbeat")
        old_heartbeat = parse_timestamp(lease["heartbeat_at"])
        old_expiry = parse_timestamp(lease["expires_at"])
        heartbeat = parse_timestamp(heartbeat_at)
        expiry = parse_timestamp(expires_at)
        if not old_heartbeat < heartbeat < expiry or heartbeat >= old_expiry:
            raise DomainError("Lease heartbeat is stale or arrives after expiry")
        effect = {"kind": "task", "value": lease["task_id"]}
        self._authorize(
            holder_authorization,
            "task.execute",
            effect,
            candidate_digest=self.tasks[lease["task_id"]]["candidate_digest"],
        )
        if (
            holder_authorization["subject_id"] != lease["holder_subject_id"]
            or holder_authorization["grant_id"] != lease["holder_grant_id"]
            or holder_authorization["claim_digest"]
            != lease["holder_grant_claim_digest"]
        ):
            raise DomainError("Lease heartbeat must use its bound holder Grant")
        self._assert_authorization_time(
            heartbeat_at, holder_authorization, "Lease heartbeat"
        )
        updated = self._copy(lease)
        updated["heartbeat_at"] = heartbeat_at
        updated["expires_at"] = expires_at
        self.leases[lease_id] = updated
        return self._copy(updated)

    @_serialized_lease_transition
    def begin_close_lease(
        self,
        lease_id: str,
        generation: int,
        fencing_token: int,
        holder_authorization: Mapping[str, Any],
        *,
        runtime_policy: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._assert_writable()
        lease = self._current_lease(lease_id, generation, fencing_token)
        lease_transitions = self._runtime_policy(runtime_policy)[2]
        if "CLOSING" not in lease_transitions.get(lease["state"], frozenset()):
            raise DomainError("Lease cannot enter CLOSING from current state")
        evaluated_at = parse_timestamp(holder_authorization.get("evaluated_at"))
        if not parse_timestamp(lease["heartbeat_at"]) <= evaluated_at < parse_timestamp(
            lease["expires_at"]
        ):
            raise DomainError("Lease close request is outside its live interval")
        effect = {"kind": "task", "value": lease["task_id"]}
        self._authorize(
            holder_authorization,
            "task.execute",
            effect,
            candidate_digest=self.tasks[lease["task_id"]]["candidate_digest"],
        )
        if (
            holder_authorization["subject_id"] != lease["holder_subject_id"]
            or holder_authorization["grant_id"] != lease["holder_grant_id"]
            or holder_authorization["claim_digest"]
            != lease["holder_grant_claim_digest"]
        ):
            raise DomainError("Lease close request must use its bound holder Grant")
        updated = self._copy(lease)
        updated["state"] = "CLOSING"
        self.leases[lease_id] = updated
        return self._copy(updated)

    @_serialized_lease_transition
    def close_lease(
        self,
        lease_id: str,
        generation: int,
        fencing_token: int,
        close_ack: Mapping[str, Any],
        manager_authorization: Mapping[str, Any],
        *,
        runtime_policy: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._assert_writable()
        lease = self._current_lease(lease_id, generation, fencing_token)
        lease_transitions = self._runtime_policy(runtime_policy)[2]
        if "CLOSED" not in lease_transitions.get(lease["state"], frozenset()):
            raise DomainError("Lease cannot enter CLOSED from current state")
        if set(close_ack) != _LEASE_CLOSE_ACK_FIELDS:
            raise DomainError("invalid Lease close acknowledgement")
        acknowledged = parse_timestamp(close_ack["acknowledged_at"])
        if not parse_timestamp(lease["heartbeat_at"]) <= acknowledged <= parse_timestamp(
            lease["expires_at"]
        ):
            raise DomainError("Lease close acknowledgement is outside its interval")
        effect = {"kind": "task", "value": lease["task_id"]}
        self._authorize(
            manager_authorization,
            "lease.manage",
            effect,
            candidate_digest=self.tasks[lease["task_id"]]["candidate_digest"],
        )
        if (
            close_ack["acknowledged_by"] != manager_authorization["subject_id"]
            or close_ack["grant_id"] != manager_authorization["grant_id"]
            or close_ack["grant_claim_digest"]
            != manager_authorization["claim_digest"]
            or close_ack["grant_id"] == lease["holder_grant_id"]
        ):
            raise DomainError("Lease close acknowledgement requires its separate manager Grant")
        self._assert_authorization_time(
            close_ack["acknowledged_at"],
            manager_authorization,
            "Lease close acknowledgement",
        )
        updated = self._copy(lease)
        updated["state"] = "CLOSED"
        updated["close_ack"] = self._copy(close_ack)
        self.leases[lease_id] = updated
        return self._copy(updated)

    @_serialized_lease_transition
    def expire_lease(
        self,
        lease_id: str,
        generation: int,
        fencing_token: int,
        evaluation_time: str,
        manager_authorization: Mapping[str, Any],
        *,
        runtime_policy: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._assert_writable()
        lease = self._current_lease(lease_id, generation, fencing_token)
        now = parse_timestamp(evaluation_time)
        lease_transitions = self._runtime_policy(runtime_policy)[2]
        if "EXPIRED" not in lease_transitions.get(lease["state"], frozenset()):
            raise DomainError("Lease cannot expire from current state")
        if now < parse_timestamp(lease["expires_at"]):
            raise DomainError("Lease has not reached expiry")
        self._authorize(
            manager_authorization,
            "lease.manage",
            {"kind": "task", "value": lease["task_id"]},
            candidate_digest=self.tasks[lease["task_id"]]["candidate_digest"],
        )
        self._assert_authorization_time(
            evaluation_time, manager_authorization, "Lease expiry"
        )
        updated = self._copy(lease)
        updated["state"] = "EXPIRED"
        updated["termination"] = {
            "state": "EXPIRED",
            "terminated_by": manager_authorization["subject_id"],
            "grant_id": manager_authorization["grant_id"],
            "grant_claim_digest": manager_authorization["claim_digest"],
            "terminated_at": evaluation_time,
            "generation": generation,
            "fencing_token": fencing_token,
        }
        self.leases[lease_id] = updated
        return self._copy(updated)

    @_serialized_lease_transition
    def revoke_lease(
        self,
        lease_id: str,
        generation: int,
        fencing_token: int,
        revoked_at: str,
        manager_authorization: Mapping[str, Any],
        *,
        runtime_policy: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._assert_writable()
        lease = self._current_lease(lease_id, generation, fencing_token)
        lease_transitions = self._runtime_policy(runtime_policy)[2]
        if "REVOKED" not in lease_transitions.get(lease["state"], frozenset()):
            raise DomainError("Lease cannot enter REVOKED from current state")
        self._authorize(
            manager_authorization,
            "lease.manage",
            {"kind": "task", "value": lease["task_id"]},
            candidate_digest=self.tasks[lease["task_id"]]["candidate_digest"],
        )
        revoked = parse_timestamp(revoked_at)
        if not parse_timestamp(lease["heartbeat_at"]) <= revoked:
            raise DomainError("Lease revocation predates its current heartbeat")
        self._assert_authorization_time(
            revoked_at, manager_authorization, "Lease revocation"
        )
        updated = self._copy(lease)
        updated["state"] = "REVOKED"
        updated["termination"] = {
            "state": "REVOKED",
            "terminated_by": manager_authorization["subject_id"],
            "grant_id": manager_authorization["grant_id"],
            "grant_claim_digest": manager_authorization["claim_digest"],
            "terminated_at": revoked_at,
            "generation": generation,
            "fencing_token": fencing_token,
        }
        self.leases[lease_id] = updated
        return self._copy(updated)

    @_serialized_lease_transition
    def reconcile_lease_capacity(
        self,
        lease_id: str,
        generation: int,
        fencing_token: int,
        reconciliation: Mapping[str, Any],
        manager_authorization: Mapping[str, Any],
        *,
        runtime_policy: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._assert_writable()
        lease = self._current_lease(lease_id, generation, fencing_token)
        capacity_policy = self._runtime_policy(runtime_policy)[3]
        terminal = capacity_policy["terminal_reconciliation"]
        capability = terminal["manager_capability"]
        field = terminal["field"]
        existing = lease.get(field)
        if existing is not None:
            if canonical_digest(existing) != canonical_digest(reconciliation):
                raise DomainError("Lease capacity reconciliation is immutable")
        self._validate_capacity_reconciliation(
            lease,
            reconciliation,
            capacity_policy,
        )
        if parse_timestamp(reconciliation["reconciled_at"]) != parse_timestamp(
            manager_authorization.get("evaluated_at")
        ):
            raise DomainError("Lease capacity reconciliation time is not command-bound")
        self._authorize(
            manager_authorization,
            capability,
            {"kind": "task", "value": lease["task_id"]},
            candidate_digest=self.tasks[lease["task_id"]]["candidate_digest"],
        )
        if (
            reconciliation["reconciled_by"]
            != manager_authorization.get("subject_id")
            or reconciliation["grant_id"]
            != manager_authorization.get("grant_id")
            or reconciliation["grant_claim_digest"]
            != manager_authorization.get("claim_digest")
        ):
            raise DomainError("Lease capacity reconciliation uses another manager Grant")
        if existing is not None:
            return self._copy(lease)
        updated = self._copy(lease)
        updated[field] = self._copy(reconciliation)
        self.leases[lease_id] = updated
        return self._copy(updated)

    def record_finding(
        self, finding: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._assert_writable()
        self._require_fields(finding, _FINDING_FIELDS, "Finding")
        self._assert_activation(finding)
        finding_id = finding["finding_id"]
        if finding_id in self.findings:
            if canonical_digest(self.findings[finding_id]) == canonical_digest(finding):
                return self._copy(self.findings[finding_id])
            raise DomainError("Finding ID already identifies another Finding")
        if finding["status"] != "OPEN":
            raise DomainError("new Finding must begin in OPEN")
        if finding["severity"] not in {"P0", "P1", "P2", "P3"}:
            raise DomainError("invalid Finding severity")
        if finding["candidate_digest"] not in self._candidate_ids_by_digest:
            raise DomainError("Finding Candidate is unresolved")
        if not isinstance(finding["blocking"], bool) or not finding["statement"]:
            raise DomainError("invalid Finding blocking state or statement")
        evidence = self._artifact_records(finding["evidence_artifacts"])
        self._reject_harness_product_mix(
            artifact for _reference, _record, artifact in evidence
        )
        finding_time = parse_timestamp(finding["created_at"])
        for reference, _record, artifact in evidence:
            binding = artifact.get("evidence_binding")
            if (
                artifact.get("artifact_kind") != "evidence"
                or artifact.get("outcome") not in {"fail", "blocked", "error"}
                or artifact.get("stale") is not False
                or artifact.get("unresolved") is not False
                or not isinstance(binding, Mapping)
                or binding.get("activation_digest") != finding["activation_digest"]
                or binding.get("candidate_digest") != finding["candidate_digest"]
                or parse_timestamp(artifact.get("created_at")) > finding_time
                or not self._artifact_is_current(reference)
            ):
                raise DomainError("Finding evidence is stale, degraded, or unbound")
        self._assert_authorization_time(
            finding["created_at"], authorization, "Finding"
        )
        self._authorize(
            authorization,
            "finding.record",
            {"kind": "finding", "value": finding_id},
            candidate_digest=finding["candidate_digest"],
            finding_id=finding_id,
        )
        self.authority.record_action(
            authorization["subject_id"],
            "finding.record",
            authorization=authorization,
            candidate_digest=finding["candidate_digest"],
            finding_id=finding_id,
        )
        stored = self._copy(finding)
        self.findings[finding_id] = stored
        return self._copy(stored)

    def validate_gate_authorization_scope(
        self,
        requested_scope: Iterable[Mapping[str, Any]],
        definition: Mapping[str, Any],
        *,
        task_id: str,
        lease_bound_task_id: str | None = None,
    ) -> tuple[tuple[str, str], ...]:
        """Enforce semantic target scope plus bounded WorkCard containment."""

        try:
            return validate_gate_authorization_scope(
                requested_scope,
                definition["target_scope"],
                task_id=task_id,
                scope_contract=self.authority.runtime_policy["scope_contract"],
                gate_scope_contract=self.gate_authorization_scope_contract,
                lease_bound_task_id=lease_bound_task_id,
            )
        except (AuthorityError, KeyError, TypeError) as exc:
            raise DomainError(str(exc)) from exc

    def record_gate_result(
        self,
        result: Mapping[str, Any],
        authorization: Mapping[str, Any],
        *,
        run_record: Mapping[str, Any],
        lease_bound_task_id: str | None = None,
    ) -> dict[str, Any]:
        self._assert_writable()
        self._require_gate_fields(result)
        self._assert_activation(result)
        if result["candidate_digest"] not in self._candidate_ids_by_digest:
            raise DomainError("GateResult Candidate is unresolved")
        definition = self._resolve_gate_definition(
            result["task_id"], result["definition_digest"]
        )
        evaluation_time = parse_timestamp(authorization.get("evaluated_at"))
        run = self._validate_gate_run(
            run_record,
            result,
            definition,
            evaluation_time,
        )
        if parse_timestamp(run["started_at"]) < parse_timestamp(
            self.tasks[result["task_id"]]["created_at"]
        ):
            raise DomainError("GateResult predates its Task definition")
        for field in (
            "gate_id",
            "candidate_digest",
            "policy_digest",
            "tool_digest",
            "activation_digest",
        ):
            if result[field] != definition[field]:
                raise DomainError(f"GateResult {field} differs from its definition")
        if result["evidence_class"] != definition["expected_evidence_class"]:
            raise DomainError("GateResult evidence class differs from its definition")
        references = result["evidence_artifacts"]
        if not isinstance(references, list) or any(
            not isinstance(reference, Mapping)
            or set(reference) != _GATE_ARTIFACT_REFERENCE_FIELDS
            or reference.get("run_id") != run["run_id"]
            or reference.get("run_digest") != result["run_digest"]
            for reference in references
        ):
            raise DomainError("GateResult Artifact bindings differ from its Run")
        key = (result["gate_id"], result["run_id"])
        if key in self.gate_results:
            if canonical_digest(self.gate_results[key]) == canonical_digest(result):
                return self._copy(self.gate_results[key])
            raise DomainError("GateResult cannot overwrite an existing gate run")
        status = result["status"]
        if status not in {"pass", "fail", "blocked", "skipped"}:
            raise DomainError("invalid GateResult status")
        if result["outcome"] != status:
            raise DomainError("GateResult outcome differs from normalized status")
        required_credit = status == "pass" and definition["product_credit_required"]
        if result["pass_credit"] is not required_credit:
            raise DomainError("GateResult pass credit differs from its definition")
        finding_ids = [
            item["value"]
            for item in definition["target_scope"]
            if item["kind"] == "finding"
        ]
        if definition["target_kind"] == "finding":
            if len(finding_ids) != 1 or finding_ids[0] not in self.findings:
                raise DomainError("GateResult Finding target is unresolved")
            if canonical_digest(self.findings[finding_ids[0]]) != definition[
                "target_digest"
            ]:
                raise DomainError("GateResult Finding target digest is stale")
        elif finding_ids:
            raise DomainError("Candidate GateRunDefinition carries a Finding target")
        effect = (
            {"kind": "finding", "value": finding_ids[0]}
            if definition["target_kind"] == "finding"
            else {"kind": "candidate", "value": result["candidate_digest"]}
        )
        self._authorize(
            authorization,
            "validation.evaluate",
            effect,
            candidate_digest=result["candidate_digest"],
            finding_id=finding_ids[0] if finding_ids else None,
        )
        self.validate_gate_authorization_scope(
            authorization.get("requested_scope", ()),
            definition,
            task_id=result["task_id"],
            lease_bound_task_id=lease_bound_task_id,
        )
        if (
            self.implementation_closure_digest is None
            or definition["implementation_closure_digest"]
            != self.implementation_closure_digest
        ):
            raise DomainError("GateResult implementation closure is unresolved")
        if (
            self.provider_binding_digest is None
            or definition["provider_binding_digest"]
            != self.provider_binding_digest
        ):
            raise DomainError("GateResult provider binding is unresolved")
        try:
            artifacts = self.evidence.validate_gate_evidence(
                result,
                gate_run_definition=definition,
                run_record=run,
            )
        except EvidenceError as exc:
            raise DomainError("GateResult evidence violates its definition") from exc
        if any(
            parse_timestamp(artifact.get("created_at")) > evaluation_time
            for artifact in artifacts
        ):
            raise DomainError("GateResult predates its evidence")
        prior_run = self._gate_runs.get(run["run_id"])
        if prior_run is not None and canonical_digest(prior_run) != result["run_digest"]:
            raise DomainError("GateResult Run ID resolves to another Run")
        self.authority.record_action(
            authorization["subject_id"],
            "validation.evaluate",
            authorization=authorization,
            candidate_digest=result["candidate_digest"],
        )
        stored = self._copy(result)
        self._gate_runs[run["run_id"]] = self._copy(run)
        self.gate_results[key] = stored
        self._gate_result_order.append(key)
        return self._copy(stored)

    @staticmethod
    def _decision_capability(kind: str) -> str:
        capabilities = {
            "accept": "validation.evaluate",
            "reject": "validation.evaluate",
            "resolve": "finding.resolve",
            "waive": "finding.waive",
            "promote": "candidate.promote",
            "release": "release.decide",
            "revoke": "authority.manage",
        }
        try:
            return capabilities[kind]
        except KeyError as exc:
            raise DomainError("unknown Decision kind") from exc

    def _target_exists(self, target_type: str, target_id: str) -> bool:
        if target_type == "Task":
            return target_id in self.tasks
        if target_type == "Candidate":
            return target_id in self.candidates
        if target_type == "Finding":
            return target_id in self.findings
        if target_type == "Grant":
            return self.authority.resolve_grant(target_id) is not None
        return False

    def _target_record(self, target_type: str, target_id: str) -> dict[str, Any]:
        if target_type == "Task":
            return self._copy(self.tasks[target_id])
        if target_type == "Candidate":
            return self._copy(self.candidates[target_id])
        if target_type == "Finding":
            return self._copy(self.findings[target_id])
        if target_type == "Grant":
            grant = self.authority.resolve_grant(target_id)
            if grant is not None:
                return grant
        raise DomainError("Decision target type is unknown")

    def _decision_evidence_creditable(
        self, decision: Mapping[str, Any], *, purpose: str
    ) -> bool:
        latest: dict[str, Mapping[str, Any]] = {}
        for key in self._gate_result_order:
            result = self.gate_results[key]
            if result["candidate_digest"] == decision["candidate_digest"]:
                latest[result["definition_digest"]] = result
        relevant = [
            result
            for result in latest.values()
            if result["status"] == "pass"
            and self._gate_evidence_current(result)
            and (purpose != "product" or result["pass_credit"])
        ]
        credited = {
            (reference["artifact_id"], reference["artifact_record_digest"])
            for result in relevant
            for reference in result["evidence_artifacts"]
        }
        references = decision["evidence_artifacts"]
        identities = {
            (reference.get("artifact_id"), reference.get("artifact_record_digest"))
            for reference in references
            if isinstance(reference, Mapping)
        }
        if (
            not references
            or len(identities) != len(references)
            or not identities <= credited
        ):
            return False
        try:
            artifacts = self._artifact_records(references)
        except DomainError:
            return False
        if not all(self._artifact_is_current(reference) for reference, _, _ in artifacts):
            return False
        if decision["decision_kind"] in {"resolve", "waive"}:
            expected_policy = (
                decision["exception_policy_digest"]
                if decision["decision_kind"] == "waive"
                else None
            )
            if not all(
                artifact.get("artifact_kind") == "evidence"
                and artifact.get("outcome") == "pass"
                and artifact.get("stale") is False
                and artifact.get("unresolved") is False
                and artifact.get("evidence_binding", {}).get("finding_digest")
                == decision["finding_digest"]
                and (
                    expected_policy is None
                    or artifact.get("evidence_binding", {}).get("policy_digest")
                    == expected_policy
                )
                for _reference, _record, artifact in artifacts
            ):
                return False
        return True

    def _latest_required_gates(
        self, candidate_digest: str
    ) -> tuple[set[str], dict[str, Mapping[str, Any]]]:
        required = set(self.required_acceptance - {"human-release-decision"})
        latest: dict[str, Mapping[str, Any]] = {}
        for key in self._gate_result_order:
            result = self.gate_results[key]
            if result["candidate_digest"] == candidate_digest and result["gate_id"] in required:
                latest[result["gate_id"]] = result
        return required, latest

    def _gate_evidence_current(self, result: Mapping[str, Any]) -> bool:
        if result["status"] != "pass":
            return False
        try:
            definition = self._resolve_gate_definition(
                result["task_id"], result["definition_digest"]
            )
            if (
                self.implementation_closure_digest is None
                or definition["implementation_closure_digest"]
                != self.implementation_closure_digest
            ):
                return False
            if (
                self.provider_binding_digest is None
                or definition["provider_binding_digest"]
                != self.provider_binding_digest
            ):
                return False
            run = self._gate_runs.get(result["run_id"])
            if (
                run is None
                or canonical_digest(run) != result.get("run_digest")
            ):
                return False
            self.evidence.validate_gate_evidence(
                result,
                gate_run_definition=definition,
                run_record=run,
            )
        except (DomainError, EvidenceError):
            return False
        return True

    def _finding_block_state(
        self, finding: Mapping[str, Any], evaluated_at: str | None
    ) -> tuple[bool, str | None]:
        if finding["status"] == "OPEN":
            return (
                finding["blocking"] or finding["severity"] in {"P0", "P1"},
                "later-blocking-finding",
            )
        decision = self.decisions.get(finding.get("disposition_decision_id"))
        expected_kind = "resolve" if finding["status"] == "RESOLVED" else "waive"
        if decision is None or decision.get("decision_kind") != expected_kind:
            return True, "finding-disposition-unresolved"
        if not self._decision_evidence_creditable(decision, purpose="gate"):
            return True, "finding-disposition-evidence-drift"
        if finding["status"] == "RESOLVED":
            return False, None
        if evaluated_at is None:
            return True, "evaluation-time-unresolved"
        if parse_timestamp(evaluated_at) >= parse_timestamp(decision["expires_at"]):
            return True, "waiver-expired"
        return False, None

    def _release_closure_identity(
        self,
        candidate_digest: str,
        *,
        activation_digest: str,
        provider_binding_digest: str,
        implementation_closure_digest: str,
        evaluated_at: str | None,
    ) -> dict[str, Any]:
        required, latest = self._latest_required_gates(candidate_digest)
        gate_records = [self._copy(latest[gate_id]) for gate_id in sorted(latest)]
        evidence_state: list[dict[str, Any]] = []
        for result in gate_records:
            for reference in result["evidence_artifacts"]:
                try:
                    record = self.evidence.get_record(reference["artifact_id"])
                    resolved = canonical_digest(record) == reference[
                        "artifact_record_digest"
                    ]
                except EvidenceError:
                    record = None
                    resolved = False
                evidence_state.append(
                    {
                        "reference": self._copy(reference),
                        "finalized_record": self._copy(record)
                        if record is not None
                        else None,
                        "resolved": resolved,
                    }
                )
        candidate_findings = [
            finding
            for finding in self.findings.values()
            if finding["candidate_digest"] == candidate_digest
        ]
        blockers = []
        for finding in candidate_findings:
            blocked, reason = self._finding_block_state(finding, evaluated_at)
            if blocked:
                blockers.append(
                    {
                        "finding": self._copy(finding),
                        "reason": reason,
                    }
                )
        candidate_id = self._candidate_ids_by_digest.get(candidate_digest)
        dispositions = [
            self._copy(self.decisions[finding["disposition_decision_id"]])
            for finding in candidate_findings
            if finding.get("disposition_decision_id") in self.decisions
        ]
        promotions = [
            self._copy(self.decisions[decision_id])
            for decision_id in self._decision_order
            if self.decisions[decision_id]["decision_kind"] == "promote"
            and self.decisions[decision_id]["candidate_digest"] == candidate_digest
        ]
        return {
            "record_type": "ReleaseClosureIdentity",
            "candidate": self._copy(self.candidates[candidate_id])
            if candidate_id is not None
            else None,
            "activation_digest": activation_digest,
            "provider_binding_digest": provider_binding_digest,
            "implementation_closure_digest": implementation_closure_digest,
            "required_gate_ids": sorted(required),
            "latest_gate_results": gate_records,
            "gate_evidence_state": evidence_state,
            "findings": [
                self._copy(finding)
                for finding in sorted(
                    candidate_findings, key=lambda value: value["finding_id"]
                )
            ],
            "finding_dispositions": sorted(
                dispositions, key=lambda value: value["decision_id"]
            ),
            "promotion_decisions": promotions,
            "blockers": sorted(
                blockers, key=lambda value: value["finding"]["finding_id"]
            ),
        }

    def release_closure_digest(
        self,
        candidate_digest: str,
        *,
        activation_digest: str | None = None,
        provider_binding_digest: str | None = None,
        implementation_closure_digest: str | None = None,
        evaluated_at: str | None = None,
    ) -> str:
        activation = activation_digest or self.authority.activation_digest
        provider = provider_binding_digest or self.provider_binding_digest
        implementation = (
            implementation_closure_digest or self.implementation_closure_digest
        )
        if (
            not _valid_digest(activation)
            or not _valid_digest(provider)
            or not _valid_digest(implementation)
        ):
            raise DomainError(
                "release closure requires Activation, provider, and implementation digests"
            )
        if evaluated_at is not None:
            parse_timestamp(evaluated_at)
        return canonical_digest(
            self._release_closure_identity(
                candidate_digest,
                activation_digest=activation,
                provider_binding_digest=provider,
                implementation_closure_digest=implementation,
                evaluated_at=evaluated_at,
            )
        )

    def record_decision(
        self, decision: Mapping[str, Any], authorization: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._assert_writable()
        self._require_decision_fields(decision)
        self._assert_activation(decision)
        decision_id = decision["decision_id"]
        if decision_id in self.decisions:
            if canonical_digest(self.decisions[decision_id]) == canonical_digest(decision):
                return self._copy(self.decisions[decision_id])
            raise DomainError("Decision ID already identifies another Decision")
        kind = decision["decision_kind"]
        target_type = decision["target_type"]
        if kind in {"resolve", "waive"} and target_type != "Finding":
            raise DomainError("Finding disposition Decision has the wrong target type")
        if kind in {"promote", "release"} and target_type != "Candidate":
            raise DomainError("promotion/release Decision has the wrong target type")
        if kind in {"accept", "reject"} and target_type not in {"Task", "Candidate"}:
            raise DomainError("accept/reject Decision has the wrong target type")
        if kind == "revoke" and target_type != "Grant":
            raise DomainError("Grant revocation Decision has the wrong target type")
        if not self._target_exists(target_type, decision["target_id"]):
            raise DomainError("Decision target is unresolved")
        target = self._target_record(target_type, decision["target_id"])
        if kind in {"resolve", "waive"} and target["status"] != "OPEN":
            raise DomainError("Finding has already been dispositioned")
        if decision["target_digest"] != canonical_digest(target):
            raise DomainError("Decision does not bind the exact current target")
        if kind != "revoke" and target.get("candidate_digest") != decision["candidate_digest"]:
            raise DomainError("Decision Candidate binding differs from its target")
        if kind in {"resolve", "waive"}:
            finding_digest = canonical_digest(self.findings[decision["target_id"]])
            if decision["finding_digest"] != finding_digest:
                raise DomainError("Decision does not bind the exact OPEN Finding")
        if (
            decision["subject_id"] != authorization.get("subject_id")
            or decision["grant_id"] != authorization.get("grant_id")
            or decision["grant_claim_digest"] != authorization.get("claim_digest")
        ):
            raise DomainError("Decision provenance differs from authorization")
        created_at = parse_timestamp(decision["created_at"])
        if kind == "waive" and parse_timestamp(decision["expires_at"]) <= created_at:
            raise DomainError("Finding waiver must expire after the Decision time")
        if not decision["rationale"] or not decision["evidence_artifacts"]:
            raise DomainError("Decision requires rationale and evidence")
        evidence_records = self._artifact_records(decision["evidence_artifacts"])
        self._reject_harness_product_mix(
            artifact for _reference, _record, artifact in evidence_records
        )
        if any(
            parse_timestamp(artifact.get("created_at")) > created_at
            for _reference, _record, artifact in evidence_records
        ):
            raise DomainError("Decision predates its evidence")
        self._assert_authorization_time(
            decision["created_at"], authorization, "Decision"
        )
        capability = self._decision_capability(kind)
        effect_kind = target_type.lower()
        candidate_digest = decision.get("candidate_digest")
        finding_id = decision["target_id"] if target_type == "Finding" else None
        if kind == "revoke":
            requested = authorization.get("requested_scope")
            if not isinstance(requested, list) or not requested:
                raise DomainError("Grant revocation Decision scope is unresolved")
            requested_pairs = {
                (item.get("kind"), item.get("value"))
                for item in requested
                if isinstance(item, Mapping)
            }
            if ("all", "*") not in requested_pairs and any(
                (item["kind"], item["value"]) not in requested_pairs
                for item in target["scope"]
            ):
                raise DomainError("Grant revocation Decision scope omits its target")
            try:
                self.authority.authorize(
                    authorization["subject_id"],
                    capability,
                    requested,
                    authorization["grant_id"],
                    authorization["claim_digest"],
                    authorization["evaluated_at"],
                )
            except AuthorityError as exc:
                raise DomainError(str(exc)) from exc
        else:
            self._authorize(
                authorization,
                capability,
                {"kind": effect_kind, "value": decision["target_id"]},
                candidate_digest=candidate_digest,
                finding_id=finding_id,
            )
        purpose = "product" if kind in {"accept", "promote", "release"} else "gate"
        if kind not in {"reject", "revoke"} and not self._decision_evidence_creditable(decision, purpose=purpose):
            raise DomainError("Decision evidence lacks exact credited gate provenance")
        if kind in {"reject", "revoke"} and any(
            artifact.get("artifact_kind") != "evidence"
            or artifact.get("stale") is not False
            or artifact.get("unresolved") is not False
            or artifact.get("evidence_binding", {}).get("activation_digest")
            != decision["activation_digest"]
            or not self._artifact_is_current(reference)
            for reference, _record, artifact in evidence_records
        ):
            raise DomainError("Decision evidence is stale, degraded, or unbound")
        if kind == "release":
            if target.get("creditable") is not True:
                raise DomainError("release requires a provider-proven immutable Candidate")
            subject = next(
                (
                    item
                    for item in self.authority.authority_init["subjects"]
                    if item["subject_id"] == decision["subject_id"]
                ),
                None,
            )
            if subject is None or subject["kind"] != "human":
                raise DomainError("public release requires a recorded human Decision")
            if not any(
                item["decision_kind"] == "promote"
                and item["target_id"] == decision["target_id"]
                and item["candidate_digest"] == candidate_digest
                for item in self.decisions.values()
            ):
                raise DomainError("release requires a prior Candidate promotion Decision")
            if any(
                finding["candidate_digest"] == candidate_digest
                and self._finding_block_state(finding, decision["created_at"])[0]
                for finding in self.findings.values()
            ):
                raise DomainError("release is blocked by current Findings or expired waivers")
            required_gates, latest_gates = self._latest_required_gates(candidate_digest)
            if not required_gates:
                raise DomainError("release required acceptance set is unavailable")
            if required_gates - set(latest_gates):
                raise DomainError("release is missing required Candidate gates")
            if any(
                latest_gates[gate_id]["status"] != "pass"
                or not latest_gates[gate_id]["pass_credit"]
                for gate_id in required_gates
            ):
                raise DomainError("release requires every required Candidate gate to pass")
            if any(
                not self._gate_evidence_current(latest_gates[gate_id])
                for gate_id in required_gates
            ):
                raise DomainError("release required gate evidence is stale or unresolved")
            if (
                self.provider_binding_digest is None
                or decision["provider_binding_digest"] != self.provider_binding_digest
            ):
                raise DomainError("release Decision provider binding differs from runtime")
            if self.implementation_closure_digest is None:
                raise DomainError("release Decision implementation closure is unresolved")
            expected_closure = self.release_closure_digest(
                candidate_digest,
                activation_digest=decision["activation_digest"],
                provider_binding_digest=decision["provider_binding_digest"],
                implementation_closure_digest=self.implementation_closure_digest,
                evaluated_at=decision["created_at"],
            )
            if decision["release_closure_digest"] != expected_closure:
                raise DomainError("release Decision closure digest is stale")
        if kind != "revoke":
            self.authority.record_action(
                decision["subject_id"],
                capability,
                authorization=authorization,
                candidate_digest=candidate_digest,
                finding_id=finding_id,
            )
        stored = self._copy(decision)
        self.decisions[decision_id] = stored
        self._decision_order.append(decision_id)
        if kind in {"resolve", "waive"}:
            finding = self._copy(self.findings[decision["target_id"]])
            finding["status"] = "RESOLVED" if kind == "resolve" else "WAIVED"
            finding["blocking"] = False
            finding["disposition_decision_id"] = decision_id
            self.findings[decision["target_id"]] = finding
        return self._copy(stored)

    def _checkpoint_state(self) -> dict[str, Any]:
        return {
            "tasks": [self._copy(self.tasks[key]) for key in sorted(self.tasks)],
            "candidates": [
                self._copy(self.candidates[key]) for key in sorted(self.candidates)
            ],
            "leases": [self._copy(self.leases[key]) for key in sorted(self.leases)],
            "findings": [
                self._copy(self.findings[key]) for key in sorted(self.findings)
            ],
            "gate_results": [
                self._copy(self.gate_results[key]) for key in sorted(self.gate_results)
            ],
            "gate_runs": [
                self._copy(self._gate_runs[key]) for key in sorted(self._gate_runs)
            ],
            "decisions": [
                self._copy(self.decisions[key]) for key in sorted(self.decisions)
            ],
            "candidate_ids_by_digest": [
                {"candidate_digest": digest, "candidate_id": candidate_id}
                for digest, candidate_id in sorted(self._candidate_ids_by_digest.items())
            ],
            "task_lease_generations": [
                {"task_id": task_id, "generation": generation}
                for task_id, generation in sorted(self._task_lease_generation.items())
            ],
            "task_fences": [
                {"task_id": task_id, "fencing_token": token}
                for task_id, token in sorted(self._task_fence.items())
            ],
            "gate_result_order": [
                {"gate_id": gate_id, "run_id": run_id}
                for gate_id, run_id in self._gate_result_order
            ],
            "decision_order": list(self._decision_order),
        }

    def checkpoint(
        self,
        *,
        head_sequence: int,
        head_digest: str,
        state_binding_digest: str,
        runtime_policy: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Serialize a strict derived checkpoint; the event HEAD remains authority."""

        if (
            not isinstance(head_sequence, int)
            or isinstance(head_sequence, bool)
            or head_sequence < 0
            or not _valid_digest(head_digest)
            or not _valid_digest(state_binding_digest)
        ):
            raise DomainError("Domain checkpoint requires exact journal bindings")
        (
            ceiling,
            task_transitions,
            lease_transitions,
            capacity_policy,
        ) = self._runtime_policy(runtime_policy)
        if any(task["state"] not in task_transitions for task in self.tasks.values()):
            raise DomainError("Domain checkpoint Task state is outside policy")
        if any(lease["state"] not in lease_transitions for lease in self.leases.values()):
            raise DomainError("Domain checkpoint Lease state is outside policy")
        self._validate_capacity_fence_progression(
            self.leases.values(),
            capacity_policy,
        )
        occupied = sum(
            self._lease_occupies_capacity(lease, capacity_policy)
            for lease in self.leases.values()
        )
        if occupied > ceiling:
            raise DomainError("Domain checkpoint exceeds the runtime parallelism ceiling")
        state = self._checkpoint_state()
        checkpoint: dict[str, Any] = {
            "record_type": "DomainCheckpoint",
            "authoritative": False,
            "activation_digest": self.authority.activation_digest,
            "provider_binding_digest": self.provider_binding_digest,
            "implementation_closure_digest": self.implementation_closure_digest,
            "required_acceptance": sorted(self.required_acceptance),
            "head_sequence": head_sequence,
            "head_digest": head_digest,
            "state_binding_digest": state_binding_digest,
            **state,
            "domain_state_digest": derived_checkpoint_digest(state),
        }
        checkpoint["checkpoint_digest"] = derived_checkpoint_digest(checkpoint)
        return checkpoint

    def restore_checkpoint(
        self,
        checkpoint: Mapping[str, Any],
        *,
        expected_head_sequence: int,
        expected_head_digest: str,
        expected_state_binding_digest: str,
        parallelism_policy: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Strictly restore a checkpoint after the caller verifies its event HEAD."""

        self._assert_writable()

        fields = {
            "record_type",
            "authoritative",
            "activation_digest",
            "provider_binding_digest",
            "implementation_closure_digest",
            "required_acceptance",
            "head_sequence",
            "head_digest",
            "state_binding_digest",
            "tasks",
            "candidates",
            "leases",
            "findings",
            "gate_results",
            "gate_runs",
            "decisions",
            "candidate_ids_by_digest",
            "task_lease_generations",
            "task_fences",
            "gate_result_order",
            "decision_order",
            "domain_state_digest",
            "checkpoint_digest",
        }
        value = self._copy(checkpoint)
        if (
            set(value) != fields
            or value.get("record_type") != "DomainCheckpoint"
            or value.get("authoritative") is not False
        ):
            raise DomainError("invalid Domain checkpoint shape")
        if (
            not isinstance(expected_head_sequence, int)
            or isinstance(expected_head_sequence, bool)
            or expected_head_sequence < 0
            or value["head_sequence"] != expected_head_sequence
            or not _valid_digest(expected_head_digest)
            or value["head_digest"] != expected_head_digest
            or not _valid_digest(expected_state_binding_digest)
            or value["state_binding_digest"] != expected_state_binding_digest
        ):
            raise DomainError("Domain checkpoint journal binding mismatch")
        if value["activation_digest"] != self.authority.activation_digest:
            raise DomainError("Domain checkpoint Activation mismatch")
        if value["provider_binding_digest"] != self.provider_binding_digest:
            raise DomainError("Domain checkpoint provider binding mismatch")
        if (
            value["implementation_closure_digest"]
            != self.implementation_closure_digest
        ):
            raise DomainError("Domain checkpoint implementation closure mismatch")
        if value["required_acceptance"] != sorted(self.required_acceptance):
            raise DomainError("Domain checkpoint acceptance set mismatch")
        expected_checkpoint_digest = value.pop("checkpoint_digest")
        if (
            not _valid_digest(expected_checkpoint_digest)
            or derived_checkpoint_digest(value) != expected_checkpoint_digest
        ):
            raise DomainError("Domain checkpoint digest mismatch")
        value["checkpoint_digest"] = expected_checkpoint_digest
        list_fields = {
            "tasks",
            "candidates",
            "leases",
            "findings",
            "gate_results",
            "gate_runs",
            "decisions",
            "candidate_ids_by_digest",
            "task_lease_generations",
            "task_fences",
            "gate_result_order",
            "decision_order",
        }
        if any(not isinstance(value[field], list) for field in list_fields):
            raise DomainError("Domain checkpoint state arrays are invalid")
        (
            ceiling,
            task_transitions,
            lease_transitions,
            capacity_policy,
        ) = self._runtime_policy(parallelism_policy)
        state = {field: value[field] for field in list_fields}
        if (
            not _valid_digest(value["domain_state_digest"])
            or derived_checkpoint_digest(state) != value["domain_state_digest"]
        ):
            raise DomainError("Domain checkpoint state digest mismatch")

        tasks: dict[str, dict[str, Any]] = {}
        for task in value["tasks"]:
            self._require_task_fields(task)
            self._assert_activation(task)
            paths = task["allowed_paths"]
            if (
                task["task_id"] in tasks
                or task["state"] not in task_transitions
                or task["required_capability"] not in self.authority.capabilities
                or not isinstance(task["acceptance_predicate"], str)
                or not task["acceptance_predicate"]
                or not isinstance(paths, list)
                or len(paths) > 64
                or len(paths) != len(set(paths))
                or not _valid_digest(task["candidate_digest"])
            ):
                raise DomainError("invalid checkpoint Task identity or state")
            [_relative_path(path) for path in paths]
            self._validate_task_gate_definitions(task)
            parse_timestamp(task["created_at"])
            tasks[task["task_id"]] = self._copy(task)
        candidates: dict[str, dict[str, Any]] = {}
        candidate_ids_by_digest: dict[str, str] = {}
        for candidate in value["candidates"]:
            self._require_candidate_fields(candidate)
            if candidate["control_excluded"] is not True:
                raise DomainError("checkpoint Candidate includes control state")
            if (
                candidate["candidate_id"] in candidates
                or candidate["candidate_digest"] in candidate_ids_by_digest
            ):
                raise DomainError("duplicate checkpoint Candidate identity")
            candidates[candidate["candidate_id"]] = self._copy(candidate)
            candidate_ids_by_digest[candidate["candidate_digest"]] = candidate[
                "candidate_id"
            ]
        expected_candidate_index = [
            {"candidate_digest": digest, "candidate_id": candidate_id}
            for digest, candidate_id in sorted(candidate_ids_by_digest.items())
        ]
        if value["candidate_ids_by_digest"] != expected_candidate_index:
            raise DomainError("Domain checkpoint Candidate index mismatch")
        if value["tasks"] != [tasks[key] for key in sorted(tasks)]:
            raise DomainError("Domain checkpoint Tasks are not canonically ordered")
        if value["candidates"] != [candidates[key] for key in sorted(candidates)]:
            raise DomainError("Domain checkpoint Candidates are not canonically ordered")
        if any(
            task["candidate_digest"] not in candidate_ids_by_digest
            for task in tasks.values()
        ):
            raise DomainError("Domain checkpoint Task Candidate is unresolved")

        leases: dict[str, dict[str, Any]] = {}
        derived_generations: dict[str, int] = {}
        derived_fences: dict[str, int] = {}
        for lease in value["leases"]:
            allowed_fields = _LEASE_FIELDS | (
                {"close_ack"} if lease.get("state") == "CLOSED" else set()
            ) | (
                {"capacity_reconciliation"}
                if "capacity_reconciliation" in lease
                else set()
            ) | (
                {"termination"}
                if lease.get("state") in {"EXPIRED", "REVOKED"}
                else set()
            )
            if set(lease) != allowed_fields or lease.get("record_type") != "Lease":
                raise DomainError("Lease does not match the checkpoint shape")
            self._assert_activation(lease)
            self._validate_lease_times(lease)
            if (
                lease["lease_id"] in leases
                or lease["task_id"] not in tasks
                or lease["state"] not in lease_transitions
                or not isinstance(lease["generation"], int)
                or isinstance(lease["generation"], bool)
                or lease["generation"] < 1
                or not isinstance(lease["fencing_token"], int)
                or isinstance(lease["fencing_token"], bool)
                or lease["fencing_token"] < 1
            ):
                raise DomainError("invalid checkpoint Lease identity or Task")
            holder = self._grant_matches(
                grant_id=lease["holder_grant_id"],
                subject_id=lease["holder_subject_id"],
                claim_digest=lease["holder_grant_claim_digest"],
                capability_id="task.execute",
            )
            manager = self._grant_matches(
                grant_id=lease["manager_grant_id"],
                subject_id=lease["manager_subject_id"],
                claim_digest=lease["manager_grant_claim_digest"],
                capability_id="lease.manage",
            )
            if (
                holder is None
                or manager is None
                or manager["grant_id"] == holder["grant_id"]
            ):
                raise DomainError("checkpoint Lease manager/holder provenance is invalid")
            if lease["state"] == "CLOSED":
                close_ack = lease["close_ack"]
                closing_manager = (
                    self._grant_matches(
                        grant_id=close_ack.get("grant_id"),
                        subject_id=close_ack.get("acknowledged_by"),
                        claim_digest=close_ack.get("grant_claim_digest"),
                        capability_id="lease.manage",
                    )
                    if isinstance(close_ack, Mapping)
                    else None
                )
                if (
                    not isinstance(close_ack, Mapping)
                    or set(close_ack) != _LEASE_CLOSE_ACK_FIELDS
                    or closing_manager is None
                    or close_ack["grant_id"] == lease["holder_grant_id"]
                ):
                    raise DomainError("checkpoint Lease close acknowledgement is invalid")
                parse_timestamp(close_ack["acknowledged_at"])
            if lease["state"] in {"EXPIRED", "REVOKED"}:
                termination = lease.get("termination")
                terminating_manager = (
                    self._grant_matches(
                        grant_id=termination.get("grant_id"),
                        subject_id=termination.get("terminated_by"),
                        claim_digest=termination.get("grant_claim_digest"),
                        capability_id="lease.manage",
                    )
                    if isinstance(termination, Mapping)
                    else None
                )
                if (
                    not isinstance(termination, Mapping)
                    or set(termination) != _LEASE_TERMINATION_FIELDS
                    or termination.get("state") != lease["state"]
                    or termination.get("generation") != lease["generation"]
                    or termination.get("fencing_token") != lease["fencing_token"]
                    or terminating_manager is None
                    or termination["grant_id"] == lease["holder_grant_id"]
                ):
                    raise DomainError("checkpoint Lease termination provenance is invalid")
                terminated_at = parse_timestamp(termination["terminated_at"])
                if (
                    lease["state"] == "EXPIRED"
                    and terminated_at < parse_timestamp(lease["expires_at"])
                ) or terminated_at < parse_timestamp(lease["heartbeat_at"]):
                    raise DomainError("checkpoint Lease termination chronology is invalid")
            if "capacity_reconciliation" in lease:
                self._validate_capacity_reconciliation(
                    lease,
                    lease["capacity_reconciliation"],
                    capacity_policy,
                )
            leases[lease["lease_id"]] = self._copy(lease)
            task_id = lease["task_id"]
            if lease["generation"] > derived_generations.get(task_id, 0):
                derived_generations[task_id] = lease["generation"]
                derived_fences[task_id] = lease["fencing_token"]
        expected_generations = [
            {"task_id": task_id, "generation": generation}
            for task_id, generation in sorted(derived_generations.items())
        ]
        expected_fences = [
            {"task_id": task_id, "fencing_token": token}
            for task_id, token in sorted(derived_fences.items())
        ]
        if value["task_lease_generations"] != expected_generations:
            raise DomainError("Domain checkpoint Lease generation index mismatch")
        if value["task_fences"] != expected_fences:
            raise DomainError("Domain checkpoint fencing index mismatch")
        if value["leases"] != [leases[key] for key in sorted(leases)]:
            raise DomainError("Domain checkpoint Leases are not canonically ordered")
        for task_id in tasks:
            active = [
                lease
                for lease in leases.values()
                if lease["task_id"] == task_id
                and lease["state"] in {"ACTIVE", "CLOSING"}
            ]
            if len(active) > 1:
                raise DomainError("checkpoint has multiple active Leases for one Task")
        self._validate_capacity_fence_progression(
            leases.values(),
            capacity_policy,
        )
        occupied = sum(
            self._lease_occupies_capacity(lease, capacity_policy)
            for lease in leases.values()
        )
        if occupied > ceiling:
            raise DomainError("checkpoint exceeds the runtime parallelism ceiling")

        findings: dict[str, dict[str, Any]] = {}
        for finding in value["findings"]:
            expected = _FINDING_FIELDS | (
                {"disposition_decision_id"}
                if finding.get("status") in {"RESOLVED", "WAIVED"}
                else set()
            )
            if set(finding) != expected or finding.get("record_type") != "Finding":
                raise DomainError("Finding does not match the checkpoint shape")
            self._assert_activation(finding)
            if (
                finding["finding_id"] in findings
                or finding["candidate_digest"] not in candidate_ids_by_digest
                or finding["status"] not in {"OPEN", "RESOLVED", "WAIVED"}
                or finding["severity"] not in {"P0", "P1", "P2", "P3"}
            ):
                raise DomainError("invalid checkpoint Finding")
            evidence_artifacts = finding["evidence_artifacts"]
            if (
                not isinstance(finding["blocking"], bool)
                or (
                    finding["status"] in {"RESOLVED", "WAIVED"}
                    and finding["blocking"] is not False
                )
                or not isinstance(finding["statement"], str)
                or not finding["statement"]
            ):
                raise DomainError("invalid checkpoint Finding evidence or statement")
            try:
                resolved_finding_artifacts = self._artifact_records(evidence_artifacts)
            except DomainError as exc:
                raise DomainError("invalid checkpoint Finding evidence or statement") from exc
            self._reject_harness_product_mix(
                artifact
                for _reference, _record, artifact in resolved_finding_artifacts
            )
            if any(
                artifact.get("artifact_kind") != "evidence"
                or artifact.get("outcome") not in {"fail", "blocked", "error"}
                or artifact.get("stale") is not False
                or artifact.get("unresolved") is not False
                or artifact.get("evidence_binding", {}).get("activation_digest")
                != finding["activation_digest"]
                or artifact.get("evidence_binding", {}).get("candidate_digest")
                != finding["candidate_digest"]
                or parse_timestamp(artifact.get("created_at"))
                > parse_timestamp(finding["created_at"])
                or not self._artifact_is_current(reference)
                for reference, _record, artifact in resolved_finding_artifacts
            ):
                raise DomainError("invalid checkpoint Finding Artifact binding")
            parse_timestamp(finding["created_at"])
            findings[finding["finding_id"]] = self._copy(finding)
        if value["findings"] != [findings[key] for key in sorted(findings)]:
            raise DomainError("Domain checkpoint Findings are not canonically ordered")
        for task in tasks.values():
            self._validate_task_gate_definitions(
                task,
                finding_records=findings,
                allow_historical_findings=True,
            )

        gate_runs: dict[str, dict[str, Any]] = {}
        for run in value["gate_runs"]:
            if (
                not isinstance(run, Mapping)
                or set(run) != _RUN_FIELDS
                or run.get("record_type") != "Run"
                or not isinstance(run.get("run_id"), str)
                or not run["run_id"]
                or run["run_id"] in gate_runs
            ):
                raise DomainError("invalid checkpoint GateResult Run")
            gate_runs[run["run_id"]] = self._copy(run)
        if value["gate_runs"] != [gate_runs[key] for key in sorted(gate_runs)]:
            raise DomainError("Domain checkpoint GateResult Runs are not canonically ordered")

        gate_results: dict[tuple[str, str], dict[str, Any]] = {}
        for result in value["gate_results"]:
            self._require_gate_fields(result)
            self._assert_activation(result)
            key = (result["gate_id"], result["run_id"])
            task = tasks.get(result["task_id"])
            definitions = (
                [
                    binding["definition"]
                    for binding in task["gate_run_definitions"]
                    if binding["definition_digest"] == result["definition_digest"]
                    and canonical_digest(binding["definition"])
                    == result["definition_digest"]
                ]
                if task is not None
                else []
            )
            if (
                key in gate_results
                or result["candidate_digest"] not in candidate_ids_by_digest
                or len(definitions) != 1
            ):
                raise DomainError("invalid checkpoint GateResult identity or Candidate")
            definition = definitions[0]
            run = gate_runs.get(result["run_id"])
            if run is None:
                raise DomainError("checkpoint GateResult Run is unresolved")
            self._validate_gate_run(run, result, definition, None)
            if (
                result["status"] not in {"pass", "fail", "blocked", "skipped"}
                or result["outcome"] != result["status"]
                or result["pass_credit"]
                is not (
                    result["status"] == "pass"
                    and definition["product_credit_required"]
                )
                or any(
                    result[field] != definition[field]
                    for field in (
                        "gate_id",
                        "candidate_digest",
                        "policy_digest",
                        "tool_digest",
                        "activation_digest",
                    )
                )
                or result["evidence_class"]
                != definition["expected_evidence_class"]
                or (
                    result["status"] == "skipped"
                    and result["evidence_artifacts"]
                )
            ):
                raise DomainError("invalid checkpoint GateResult pass credit")
            finding_ids = [
                item["value"]
                for item in definition["target_scope"]
                if item["kind"] == "finding"
            ]
            if definition["target_kind"] == "finding":
                if len(finding_ids) != 1 or finding_ids[0] not in findings:
                    raise DomainError("checkpoint GateResult Finding target is unresolved")
            elif finding_ids:
                raise DomainError("checkpoint Candidate Gate carries a Finding target")
            if (
                self.implementation_closure_digest is None
                or definition["implementation_closure_digest"]
                != self.implementation_closure_digest
            ):
                raise DomainError("checkpoint GateResult implementation is stale")
            try:
                self.evidence.validate_gate_evidence(
                    result,
                    gate_run_definition=definition,
                    run_record=run,
                )
            except EvidenceError as exc:
                raise DomainError("checkpoint GateResult Artifact is unbound") from exc
            gate_results[key] = self._copy(result)
        if value["gate_results"] != [
            gate_results[key] for key in sorted(gate_results)
        ]:
            raise DomainError("Domain checkpoint GateResults are not canonically ordered")
        if set(gate_runs) != {result["run_id"] for result in gate_results.values()}:
            raise DomainError("Domain checkpoint GateResult Run set is not exact")
        gate_result_order = [
            (item.get("gate_id"), item.get("run_id"))
            for item in value["gate_result_order"]
            if isinstance(item, Mapping) and set(item) == {"gate_id", "run_id"}
        ]
        if (
            len(gate_result_order) != len(value["gate_result_order"])
            or len(gate_result_order) != len(set(gate_result_order))
            or set(gate_result_order) != set(gate_results)
        ):
            raise DomainError("Domain checkpoint GateResult chronology is invalid")

        scratch = DomainState(
            self.authority,
            self.evidence,
            required_acceptance=self.required_acceptance,
            provider_binding_digest=self.provider_binding_digest,
            implementation_closure_digest=self.implementation_closure_digest,
            gate_authorization_scope_contract=self.gate_authorization_scope_contract,
        )
        scratch.tasks = tasks
        scratch.candidates = candidates
        scratch.findings = findings
        scratch.gate_results = gate_results
        scratch._gate_runs = gate_runs
        scratch._candidate_ids_by_digest = candidate_ids_by_digest
        scratch._gate_result_order = gate_result_order

        decisions: dict[str, dict[str, Any]] = {}
        for decision in value["decisions"]:
            self._require_decision_fields(decision)
            self._assert_activation(decision)
            if decision["decision_id"] in decisions:
                raise DomainError("duplicate checkpoint Decision identity")
            if (
                not isinstance(decision["rationale"], str)
                or not decision["rationale"]
                or not decision["evidence_artifacts"]
            ):
                raise DomainError("invalid checkpoint Decision evidence or rationale")
            resolved_decision_artifacts = self._artifact_records(
                decision["evidence_artifacts"]
            )
            self._reject_harness_product_mix(
                artifact
                for _reference, _record, artifact in resolved_decision_artifacts
            )
            decision_time = parse_timestamp(decision["created_at"])
            if any(
                parse_timestamp(artifact.get("created_at")) > decision_time
                for _reference, _record, artifact in resolved_decision_artifacts
            ):
                raise DomainError("checkpoint Decision predates its evidence")
            grant = self.authority.resolve_grant(decision["grant_id"])
            if (
                grant is None
                or grant["subject_id"] != decision["subject_id"]
                or grant["claim_digest"] != decision["grant_claim_digest"]
            ):
                raise DomainError("checkpoint Decision Grant provenance is unresolved")
            if decision["decision_kind"] == "waive" and parse_timestamp(
                decision["expires_at"]
            ) <= parse_timestamp(decision["created_at"]):
                raise DomainError("checkpoint Finding waiver expiry is invalid")
            decisions[decision["decision_id"]] = self._copy(decision)
        if value["decisions"] != [decisions[key] for key in sorted(decisions)]:
            raise DomainError("Domain checkpoint Decisions are not canonically ordered")
        for decision in decisions.values():
            target_type = decision["target_type"]
            target_grant = (
                self.authority.resolve_grant(decision["target_id"])
                if target_type == "Grant"
                else None
            )
            target_exists = (
                decision["target_id"] in tasks
                if target_type == "Task"
                else decision["target_id"] in candidates
                if target_type == "Candidate"
                else decision["target_id"] in findings
                if target_type == "Finding"
                else target_grant is not None
                if target_type == "Grant"
                else False
            )
            if not target_exists:
                raise DomainError("checkpoint Decision target is unresolved")
            target = (
                tasks[decision["target_id"]]
                if target_type == "Task"
                else candidates[decision["target_id"]]
                if target_type == "Candidate"
                else findings[decision["target_id"]]
                if target_type == "Finding"
                else target_grant
            )
            kind = decision["decision_kind"]
            if kind != "revoke" and target.get("candidate_digest") != decision["candidate_digest"]:
                raise DomainError("checkpoint Decision Candidate binding is invalid")
            if (
                (kind in {"resolve", "waive"} and decision["target_type"] != "Finding")
                or (kind in {"promote", "release"} and decision["target_type"] != "Candidate")
                or (
                    kind in {"accept", "reject"}
                    and decision["target_type"] not in {"Task", "Candidate"}
                )
                or (kind == "revoke" and target_type != "Grant")
            ):
                raise DomainError("checkpoint Decision target type is invalid")
            target_digest_matches = (
                decision["target_digest"] in self._open_finding_digests(target)
                if target_type == "Finding"
                else canonical_digest(target) == decision["target_digest"]
            )
            if target_type != "Task" and not target_digest_matches:
                raise DomainError("checkpoint Decision exact target binding is invalid")
            if kind in {"resolve", "waive"} and (
                decision["finding_digest"] != decision["target_digest"]
            ):
                raise DomainError("checkpoint Decision Finding digest is invalid")
            grant = self.authority.resolve_grant(decision["grant_id"])
            if grant is None:
                raise DomainError("checkpoint Decision Grant is unresolved")
            if grant["capability_id"] != self._decision_capability(kind):
                raise DomainError("checkpoint Decision Grant capability is invalid")
            if kind not in {"reject", "revoke"} and not scratch._decision_evidence_creditable(
                decision,
                purpose="product"
                if kind in {"accept", "promote", "release"}
                else "gate",
            ):
                raise DomainError("checkpoint Decision evidence lacks gate provenance")
            if kind in {"reject", "revoke"}:
                resolved = self._artifact_records(decision["evidence_artifacts"])
                if any(
                    artifact.get("artifact_kind") != "evidence"
                    or artifact.get("stale") is not False
                    or artifact.get("unresolved") is not False
                    or artifact.get("evidence_binding", {}).get("activation_digest")
                    != decision["activation_digest"]
                    or not self._artifact_is_current(reference)
                    for reference, _record, artifact in resolved
                ):
                    raise DomainError("checkpoint Decision evidence is degraded")
            if kind == "release":
                subject = next(
                    (
                        value
                        for value in self.authority.authority_init["subjects"]
                        if value["subject_id"] == decision["subject_id"]
                    ),
                    None,
                )
                if subject is None or subject["kind"] != "human":
                    raise DomainError("checkpoint release Decision is not human")
        decision_order = value["decision_order"]
        if (
            any(not isinstance(item, str) or not item for item in decision_order)
            or len(decision_order) != len(set(decision_order))
            or set(decision_order) != set(decisions)
        ):
            raise DomainError("Domain checkpoint Decision chronology is invalid")
        for finding in findings.values():
            if finding["status"] != "OPEN":
                decision = decisions.get(finding["disposition_decision_id"])
                expected_kind = "resolve" if finding["status"] == "RESOLVED" else "waive"
                if (
                    decision is None
                    or decision["decision_kind"] != expected_kind
                    or decision["target_id"] != finding["finding_id"]
                ):
                    raise DomainError("checkpoint Finding disposition is unresolved")

        self.tasks = tasks
        self.candidates = candidates
        self.leases = leases
        self.findings = findings
        self.gate_results = gate_results
        self.decisions = decisions
        self._candidate_ids_by_digest = candidate_ids_by_digest
        self._task_lease_generation = derived_generations
        self._task_fence = derived_fences
        self._gate_runs = gate_runs
        self._gate_result_order = gate_result_order
        self._decision_order = list(decision_order)
        return {
            "record_type": "DomainCheckpointRestoreResult",
            "status": "restored-nonauthoritative-cache",
            "authoritative": False,
            "head_sequence": expected_head_sequence,
            "head_digest": expected_head_digest,
            "state_binding_digest": expected_state_binding_digest,
            "domain_state_digest": value["domain_state_digest"],
        }

    def approval_status(
        self,
        candidate_digest: str,
        *,
        current_activation_digest: str | None = None,
        current_provider_binding_digest: str | None = None,
        current_implementation_closure_digest: str | None = None,
        evaluated_at: str | None = None,
    ) -> dict[str, Any]:
        """Derive current release validity without rewriting historical Decisions."""

        releases = [
            self.decisions[decision_id]
            for decision_id in self._decision_order
            if self.decisions[decision_id]["decision_kind"] == "release"
            and self.decisions[decision_id]["candidate_digest"] == candidate_digest
        ]
        historical = releases[-1] if releases else None
        activation = current_activation_digest or self.authority.activation_digest
        provider = current_provider_binding_digest or self.provider_binding_digest
        implementation = (
            current_implementation_closure_digest
            or self.implementation_closure_digest
        )
        if not _valid_digest(activation):
            raise DomainError("current Activation digest is invalid")
        if provider is not None and not _valid_digest(provider):
            raise DomainError("current provider binding digest is invalid")
        if implementation is not None and not _valid_digest(implementation):
            raise DomainError("current implementation closure digest is invalid")
        if evaluated_at is not None:
            parse_timestamp(evaluated_at)

        reasons: set[str] = set()
        current_closure: str | None = None
        if historical is None:
            reasons.add("no-historical-release-decision")
        else:
            candidate_id = self._candidate_ids_by_digest.get(candidate_digest)
            if (
                candidate_id is None
                or self.candidates[candidate_id].get("creditable") is not True
            ):
                reasons.add("candidate-non-creditable")
            if activation != historical["activation_digest"]:
                reasons.add("activation-drift")
            if provider is None:
                reasons.add("provider-binding-unresolved")
            elif provider != historical["provider_binding_digest"]:
                reasons.add("provider-drift")
            if implementation is None:
                reasons.add("implementation-closure-unresolved")
            elif implementation != self.implementation_closure_digest:
                reasons.add("implementation-drift")

            required, latest = self._latest_required_gates(candidate_digest)
            missing = required - set(latest)
            if missing:
                reasons.add("required-gate-missing")
            for gate_id in required & set(latest):
                result = latest[gate_id]
                if result["status"] != "pass" or not result["pass_credit"]:
                    reasons.add("required-gate-failed")
                elif not self._gate_evidence_current(result):
                    reasons.add("evidence-drift")
            if not self._decision_evidence_creditable(historical, purpose="product"):
                reasons.add("evidence-drift")
            for finding in self.findings.values():
                if finding["candidate_digest"] != candidate_digest:
                    continue
                blocked, reason = self._finding_block_state(finding, evaluated_at)
                if blocked and reason is not None:
                    reasons.add(reason)

            if provider is not None and implementation is not None:
                current_closure = self.release_closure_digest(
                    candidate_digest,
                    activation_digest=activation,
                    provider_binding_digest=provider,
                    implementation_closure_digest=implementation,
                    evaluated_at=evaluated_at,
                )
                if current_closure != historical["release_closure_digest"]:
                    reasons.add("release-closure-drift")

        eligible = historical is not None and not reasons
        return {
            "candidate_digest": candidate_digest,
            "product_acceptance": False,
            "product_acceptance_pass_credit": False,
            "public_release_approved": False,
            "public_release_status": "not_approved",
            "current_release_eligible": eligible,
            "historical_release_decision_id": historical["decision_id"]
            if historical
            else None,
            "human_decision_id": historical["decision_id"] if historical else None,
            "release_closure_digest": historical["release_closure_digest"]
            if historical
            else None,
            "current_closure_digest": current_closure,
            "invalidation_reasons": sorted(reasons),
        }
