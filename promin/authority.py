"""Fail-closed Promin authority evaluation.

The JSON Core remains the normative owner.  This module is the runtime
enforcement boundary for Grants; it deliberately has no implicit owner or
ambient administrator authority.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
import posixpath
import re
from typing import Any, Callable, Generic, Iterable, Iterator, Mapping, TypeVar
import unicodedata

from .canonical import (
    CanonicalError,
    ParseLimits,
    canonical_bytes,
    digest_value as _digest_value,
    digest_value_streaming as _digest_value_streaming,
    format_utc_second,
    parse_utc_second,
)


_DERIVED_CHECKPOINT_DIGEST_LIMITS = ParseLimits(
    max_bytes=512 * 1024 * 1024,
    max_items=5_000_000,
)


class AuthorityError(ValueError):
    """Raised when an authority claim cannot be proven exactly."""


SignatureVerifier = Callable[[Mapping[str, Any], Mapping[str, Any]], bool]
DecisionResolver = Callable[[str], Mapping[str, Any] | None]


_K = TypeVar("_K")
_V = TypeVar("_V")
_INHERIT_RESOLVER = object()


@dataclass(frozen=True)
class AuthorityFreezeResult:
    snapshot: AuthorityEngine
    changed_leaf_count: int
    compacted: bool
    compacted_record_count: int
    compacted_payload_bytes: int


class _PersistentOverlayMap(Generic[_K, _V]):
    """A sealed-base map with transaction-local writes.

    Forking is O(1). Reads walk the bounded overlay chain, and writes affect only
    the current layer. A threshold compaction may materialize the composed map;
    that cost is explicitly O(total state * overlay depth), amortized across
    prior transactions and bounded by the injected compaction depth.
    """

    __slots__ = ("_base", "_changes", "_sealed", "_depth")

    def __init__(
        self,
        *,
        base: _PersistentOverlayMap[_K, _V] | None = None,
        values: Mapping[_K, _V] | None = None,
        sealed: bool = False,
    ) -> None:
        if base is not None and not base.sealed:
            raise AuthorityError("authority overlay base must be frozen")
        self._base = base
        self._changes = dict(values or {})
        self._sealed = sealed
        self._depth = 0 if base is None else base.depth + 1

    @property
    def sealed(self) -> bool:
        return self._sealed

    @property
    def depth(self) -> int:
        return self._depth

    @property
    def change_count(self) -> int:
        return len(self._changes)

    def fork(self) -> _PersistentOverlayMap[_K, _V]:
        if not self._sealed:
            raise AuthorityError("authority overlay must be frozen before fork")
        return _PersistentOverlayMap(base=self)

    def seal(self) -> None:
        self._sealed = True

    def compacted(self) -> _PersistentOverlayMap[_K, _V]:
        return _PersistentOverlayMap(values=self.to_dict(), sealed=True)

    def __contains__(self, key: object) -> bool:
        return key in self._changes or (
            self._base is not None and key in self._base
        )

    def __getitem__(self, key: _K) -> _V:
        try:
            return self._changes[key]
        except KeyError:
            if self._base is None:
                raise
            return self._base[key]

    def __setitem__(self, key: _K, value: _V) -> None:
        if self._sealed:
            raise AuthorityError("frozen authority snapshot cannot be mutated")
        self._changes[key] = value

    def get(self, key: _K, default: Any = None) -> _V | Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __iter__(self) -> Iterator[_K]:
        yielded: set[_K] = set()
        for key in self._changes:
            yielded.add(key)
            yield key
        if self._base is not None:
            for key in self._base:
                if key not in yielded:
                    yield key

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def keys(self) -> tuple[_K, ...]:
        return tuple(self)

    def values(self) -> Iterator[_V]:
        for key in self:
            yield self[key]

    def items(self) -> Iterator[tuple[_K, _V]]:
        for key in self:
            yield key, self[key]

    def to_dict(self) -> dict[_K, _V]:
        if self._base is None:
            return dict(self._changes)
        result = self._base.to_dict()
        result.update(self._changes)
        return result


_RUNTIME_POLICY_FIELDS = frozenset(
    {
        "record_type",
        "authority_model_digest",
        "capability_ids",
        "separation_of_duties",
        "separation_of_duties_capability_ids",
        "separation_of_duties_contract",
        "delegation_depth_max",
        "scope_contract",
        "grant_contract",
        "canonical_timestamp_contract",
        "policy_digest",
    }
)
_GRANT_ISSUE_AUTHORIZATION_FIELDS = frozenset(
    {
        "record_type",
        "authorization_kind",
        "command_digest",
        "command_intent_digest",
        "activation_digest",
        "subject_id",
        "issuer_grant_id",
        "issuer_signed_claim_digest",
        "issuer_revocation_state_digest",
        "child_grant_id",
        "child_claim_digest",
        "requested_scope",
        "evaluated_at",
        "authorization_digest",
    }
)
_STORED_DECISION_BINDING_FIELDS = frozenset(
    {
        "record_type",
        "decision_id",
        "decision_digest",
        "event_id",
        "event_digest",
        "activation_digest",
        "target_grant_id",
        "authorizing_grant_id",
        "authorizing_claim_digest",
        "subject_id",
        "decided_at",
    }
)
_REVOCATION_DECISION_FIELDS = frozenset(
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
_ARTIFACT_REFERENCE_FIELDS = frozenset(
    {"artifact_id", "artifact_record_digest"}
)
_ACTION_AUTHORIZATION_FIELDS = frozenset(
    {
        "subject_id",
        "grant_id",
        "claim_digest",
        "evaluated_at",
        "requested_scope",
    }
)
_ACTION_PROVENANCE_FIELDS = frozenset(
    {
        "record_type",
        "target_kind",
        "target_id",
        "subject_id",
        "grant_id",
        "grant_claim_digest",
        "evaluated_at",
        "activation_digest",
        "capability_id",
        "effect_scope",
    }
)


def canonical_digest(value: Any) -> str:
    """Return the Promin canonical JSON digest for a JSON-compatible value."""

    return _digest_value(value)


def derived_checkpoint_digest(value: Any) -> str:
    """Digest a large derived checkpoint with exact bounded canonical identity."""

    return _digest_value_streaming(value, limits=_DERIVED_CHECKPOINT_DIGEST_LIMITS)


def parse_timestamp(value: str) -> datetime:
    """Parse the Core canonical second-resolution UTC timestamp."""

    try:
        return parse_utc_second(value)
    except CanonicalError as exc:
        raise AuthorityError(f"non-canonical UTC timestamp: {value}") from exc


def _valid_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _scope_key(
    selector: Mapping[str, Any], scope_contract: Mapping[str, Any]
) -> tuple[str, str]:
    selector_fields = scope_contract["selector_fields"]
    if set(selector) != set(selector_fields):
        raise AuthorityError("scope selector fields differ from Core policy")
    kind = selector.get("kind")
    value = selector.get("value")
    if (
        kind not in scope_contract["kinds"]
        or not isinstance(value, str)
        or not scope_contract["value_min_length"]
        <= len(value)
        <= scope_contract["value_max_length"]
    ):
        raise AuthorityError("invalid scope selector")
    value = unicodedata.normalize("NFC", value)
    all_selector = scope_contract["all_selector"]
    if kind == all_selector["kind"]:
        if value != all_selector["value"]:
            raise AuthorityError("all scope must use value '*'")
        return kind, value
    if (
        scope_contract["wildcard_outside_all"] == "reject"
        and value == all_selector["value"]
    ):
        raise AuthorityError("wildcard is permitted only for all scope")
    path_selector = scope_contract["path_selector"]
    if kind == path_selector["kind"]:
        normalized = posixpath.normpath(value)
        if (
            "\\" in value
            or
            value.startswith("/")
            or normalized in {"", ".", ".."}
            or normalized.startswith("../")
            or "\x00" in value
            or normalized != value.rstrip("/")
        ):
            raise AuthorityError("unsafe or non-canonical path scope")
        value = normalized
    return kind, value


def _scope_keys(
    scope: Iterable[Mapping[str, Any]],
    scope_contract: Mapping[str, Any],
    *,
    max_items: int,
) -> tuple[tuple[str, str], ...]:
    items = tuple(_scope_key(selector, scope_contract) for selector in scope)
    if not items or len(items) > max_items:
        raise AuthorityError("scope size differs from Core policy")
    if len(items) != len(set(items)):
        raise AuthorityError("duplicate scope selector")
    project_selector = scope_contract["project_selector"]
    projects = [
        value for kind, value in items if kind == project_selector["kind"]
    ]
    if len(projects) > project_selector["items_max"]:
        raise AuthorityError("scope may contain at most one project selector")
    all_selector = scope_contract["all_selector"]
    if (
        (all_selector["kind"], all_selector["value"]) in items
        and all_selector["exclusive"]
        and len(items) != 1
    ):
        raise AuthorityError("all scope cannot be combined with other selectors")
    return items


def scope_is_subset(
    requested: Iterable[Mapping[str, Any]],
    allowed: Iterable[Mapping[str, Any]],
    scope_contract: Mapping[str, Any],
    *,
    requested_max_items: int | None = None,
    allowed_max_items: int | None = None,
) -> bool:
    """Evaluate conjunctive scope without selector-drop broadening."""

    requested_set = set(
        _scope_keys(
            requested,
            scope_contract,
            max_items=(
                scope_contract["requested_scope_items_max"]
                if requested_max_items is None
                else requested_max_items
            ),
        )
    )
    allowed_set = set(
        _scope_keys(
            allowed,
            scope_contract,
            max_items=(
                scope_contract["grant_scope_items_max"]
                if allowed_max_items is None
                else allowed_max_items
            ),
        )
    )
    all_selector = scope_contract["all_selector"]
    all_key = (all_selector["kind"], all_selector["value"])
    if all_key in allowed_set:
        return True
    if all_key in requested_set:
        return False

    project_kind = scope_contract["project_selector"]["kind"]
    allowed_projects = {
        value for kind, value in allowed_set if kind == project_kind
    }
    requested_projects = {
        value for kind, value in requested_set if kind == project_kind
    }
    if allowed_projects and requested_projects != allowed_projects:
        return False

    allowed_specific = {
        (kind, value) for kind, value in allowed_set if kind != project_kind
    }
    requested_specific = {
        (kind, value) for kind, value in requested_set if kind != project_kind
    }
    return allowed_specific <= requested_specific


GATE_AUTHORIZATION_SCOPE_CONTRACT = {
    "all_selector": "reject",
    "allowed_extra_kinds": ["project", "task"],
    "lease_bound_task_selector_required": True,
    "project_items_max": 1,
    "target_scope_relation": "subset",
    "task_items_max": 1,
    "task_value_rule": "GateResult.task_id",
    "unrelated_selector": "reject",
}


def validate_gate_authorization_scope(
    requested: Iterable[Mapping[str, Any]],
    target: Iterable[Mapping[str, Any]],
    *,
    task_id: str,
    scope_contract: Mapping[str, Any],
    gate_scope_contract: Mapping[str, Any],
    lease_bound_task_id: str | None = None,
) -> tuple[tuple[str, str], ...]:
    """Validate semantic gate target plus bounded operational containment.

    ``GateRunDefinition.target_scope`` owns the semantic target.  A command may
    additionally carry the exact project and Task selectors needed to bind a
    lease-backed WorkCard.  No unrelated selector may broaden or change the
    target.  The returned tuple is canonical and useful to callers that need a
    stable diagnostic representation; it is not an authority receipt.
    """

    if dict(gate_scope_contract) != GATE_AUTHORIZATION_SCOPE_CONTRACT:
        raise AuthorityError("gate authorization scope policy is unsupported")
    if not isinstance(task_id, str) or not task_id:
        raise AuthorityError("GateResult Task identity is invalid")
    if lease_bound_task_id is not None and lease_bound_task_id != task_id:
        raise AuthorityError("lease-bound GateResult Task containment mismatch")

    requested_keys = _scope_keys(
        requested,
        scope_contract,
        max_items=scope_contract["requested_scope_items_max"],
    )
    target_keys = _scope_keys(
        target,
        scope_contract,
        max_items=scope_contract["requested_scope_items_max"],
    )
    requested_set = set(requested_keys)
    target_set = set(target_keys)
    all_selector = scope_contract["all_selector"]
    all_key = (all_selector["kind"], all_selector["value"])
    if all_key in requested_set:
        raise AuthorityError("GateResult authorization cannot use all scope")
    if not target_set <= requested_set:
        raise AuthorityError("GateResult authorization omits its semantic target scope")

    extras = requested_set - target_set
    allowed_extra_kinds = set(gate_scope_contract["allowed_extra_kinds"])
    unrelated = sorted(
        (kind, value) for kind, value in extras if kind not in allowed_extra_kinds
    )
    if unrelated:
        raise AuthorityError(
            f"GateResult authorization carries an unrelated selector: {unrelated}"
        )

    projects = [value for kind, value in extras if kind == "project"]
    tasks = [value for kind, value in extras if kind == "task"]
    if len(projects) > gate_scope_contract["project_items_max"]:
        raise AuthorityError("GateResult authorization has too many project selectors")
    if len(tasks) > gate_scope_contract["task_items_max"]:
        raise AuthorityError("GateResult authorization has too many Task selectors")
    if tasks and tasks != [task_id]:
        raise AuthorityError("GateResult Task containment selector is not exact")
    if (
        lease_bound_task_id is not None
        and gate_scope_contract["lease_bound_task_selector_required"]
        and tasks != [task_id]
    ):
        raise AuthorityError("lease-bound GateResult requires exact Task containment")
    return requested_keys


def grant_claim_identity(grant: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in grant.items()
        if key not in {"claim_digest", "trust_proofs"}
    }


class AuthorityEngine:
    """Stateful Grant, revocation, and separation-of-duties evaluator."""

    def __init__(
        self,
        authority_init: Mapping[str, Any],
        activation_digest: str,
        runtime_policy: Mapping[str, Any],
        signature_verifier: SignatureVerifier | None = None,
        *,
        decision_resolver: DecisionResolver | None = None,
    ) -> None:
        self._authority_init = deepcopy(dict(authority_init))
        self.activation_digest = activation_digest
        self._runtime_policy = deepcopy(dict(runtime_policy))
        self._validate_runtime_policy()
        self.capabilities = frozenset(self._runtime_policy["capability_ids"])
        self._separation_of_duties = tuple(
            deepcopy(self._runtime_policy["separation_of_duties"])
        )
        self.signature_verifier = signature_verifier
        self.signature_provider_evidence = deepcopy(
            getattr(signature_verifier, "provider_evidence", None)
        )
        if decision_resolver is not None and not callable(decision_resolver):
            raise AuthorityError("decision resolver must be callable")
        self.decision_resolver = decision_resolver
        self.max_delegation_depth = self._runtime_policy["delegation_depth_max"]
        self._grants: _PersistentOverlayMap[str, dict[str, Any]] = (
            _PersistentOverlayMap()
        )
        self._revocations: _PersistentOverlayMap[str, dict[str, Any]] = (
            _PersistentOverlayMap()
        )
        self._nonces: _PersistentOverlayMap[str, str] = _PersistentOverlayMap()
        self._grant_issue_authorizations: dict[str, dict[str, Any]] = {}
        self._candidate_actions: _PersistentOverlayMap[
            tuple[str, str], tuple[dict[str, Any], ...]
        ] = _PersistentOverlayMap()
        self._finding_actions: _PersistentOverlayMap[
            tuple[str, str], tuple[dict[str, Any], ...]
        ] = _PersistentOverlayMap()
        self._last_live_evaluation: datetime | None = None
        self._last_replay_evaluation: datetime | None = None
        self._live_evaluation_changed = False
        self._replay_evaluation_changed = False
        self._is_frozen = False
        self._freeze_compaction_depth: int | None = None
        self._freeze_result: AuthorityFreezeResult | None = None
        self._validate_authority_init()

    def _validate_runtime_policy(self) -> None:
        policy = self._runtime_policy
        if set(policy) != _RUNTIME_POLICY_FIELDS:
            raise AuthorityError("authority runtime policy has an invalid shape")
        if policy.get("record_type") != "AuthorityRuntimePolicy":
            raise AuthorityError("authority runtime policy identity is invalid")
        if not _valid_digest(policy.get("authority_model_digest")):
            raise AuthorityError("authority runtime policy lacks a Core owner digest")
        capabilities = policy.get("capability_ids")
        if (
            not isinstance(capabilities, list)
            or not capabilities
            or len(capabilities) != len(set(capabilities))
            or any(not isinstance(value, str) or not value for value in capabilities)
        ):
            raise AuthorityError("authority runtime capability set is invalid")
        depth = policy.get("delegation_depth_max")
        if (
            not isinstance(depth, int)
            or isinstance(depth, bool)
            or depth < 1
        ):
            raise AuthorityError("authority delegation depth policy is invalid")

        scope_contract = policy.get("scope_contract")
        if not isinstance(scope_contract, Mapping):
            raise AuthorityError("authority scope contract is invalid")
        required_scope_contract_fields = {
            "all_selector",
            "conjunctive_effect_scope",
            "duplicate_selector",
            "grant_scope_items_max",
            "kinds",
            "path_selector",
            "project_selector",
            "requested_scope_items_max",
            "selector_fields",
            "unique_items",
            "unknown_kind",
            "value_max_length",
            "value_min_length",
            "wildcard_outside_all",
        }
        if set(scope_contract) != required_scope_contract_fields:
            raise AuthorityError("authority scope contract shape is invalid")
        scope_kinds = scope_contract.get("kinds")
        if (
            not isinstance(scope_kinds, list)
            or not scope_kinds
            or len(scope_kinds) != len(set(scope_kinds))
            or scope_contract.get("selector_fields") != ["kind", "value"]
            or scope_contract.get("conjunctive_effect_scope") is not True
            or scope_contract.get("duplicate_selector") != "reject"
            or scope_contract.get("unique_items") is not True
            or scope_contract.get("unknown_kind") != "reject"
            or scope_contract.get("wildcard_outside_all") != "reject"
        ):
            raise AuthorityError("authority scope dispatcher policy is invalid")
        for scope_kind in scope_kinds:
            match scope_kind:
                case "all" | "artifact" | "candidate" | "finding" | "path" | "project" | "task":
                    pass
                case _:
                    raise AuthorityError("authority scope dispatcher mismatch")
        all_selector = scope_contract.get("all_selector")
        path_selector = scope_contract.get("path_selector")
        project_selector = scope_contract.get("project_selector")
        if (
            not isinstance(all_selector, Mapping)
            or set(all_selector) != {"exclusive", "kind", "value"}
            or all_selector.get("kind") not in scope_kinds
            or all_selector.get("exclusive") is not True
            or not isinstance(all_selector.get("value"), str)
            or not all_selector["value"]
            or not isinstance(path_selector, Mapping)
            or set(path_selector)
            != {"absolute", "dot_segments", "kind", "normalization"}
            or path_selector.get("kind") not in scope_kinds
            or path_selector.get("absolute") != "reject"
            or path_selector.get("dot_segments") != "reject"
            or path_selector.get("normalization") != "NFC POSIX relative path"
            or not isinstance(project_selector, Mapping)
            or set(project_selector) != {"items_max", "kind"}
            or project_selector.get("kind") not in scope_kinds
            or not isinstance(project_selector.get("items_max"), int)
            or isinstance(project_selector.get("items_max"), bool)
            or project_selector["items_max"] < 1
        ):
            raise AuthorityError("authority scope kind policy is invalid")
        for field in (
            "grant_scope_items_max",
            "requested_scope_items_max",
            "value_max_length",
            "value_min_length",
        ):
            value = scope_contract.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise AuthorityError("authority scope limit policy is invalid")
        if scope_contract["value_min_length"] > scope_contract["value_max_length"]:
            raise AuthorityError("authority scope value limits are inverted")

        grant_contract = policy.get("grant_contract")
        if not isinstance(grant_contract, Mapping) or set(grant_contract) != {
            "claim_digest_rule",
            "nonce",
            "required_fields",
            "scope_items_max_source",
            "trust_proof_kinds",
            "trust_proofs_max",
            "trust_proofs_min",
            "trust_proofs_unique",
            "unknown_proof_kind",
        }:
            raise AuthorityError("authority Grant contract shape is invalid")
        required_grant_fields = grant_contract.get("required_fields")
        nonce_contract = grant_contract.get("nonce")
        proof_contracts = grant_contract.get("trust_proof_kinds")
        if (
            not isinstance(required_grant_fields, list)
            or not required_grant_fields
            or len(required_grant_fields) != len(set(required_grant_fields))
            or any(
                not isinstance(field, str) or not field
                for field in required_grant_fields
            )
            or grant_contract.get("scope_items_max_source")
            != "scope_contract.grant_scope_items_max"
            or not isinstance(nonce_contract, Mapping)
            or set(nonce_contract) != {"max_length", "min_length", "pattern"}
            or not isinstance(proof_contracts, Mapping)
            or not proof_contracts
            or grant_contract.get("trust_proofs_unique") is not True
            or grant_contract.get("unknown_proof_kind") != "reject"
        ):
            raise AuthorityError("authority Grant contract is invalid")
        for field in ("min_length", "max_length"):
            value = nonce_contract.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise AuthorityError("authority Grant nonce contract is invalid")
        if (
            nonce_contract["min_length"] > nonce_contract["max_length"]
            or not isinstance(nonce_contract.get("pattern"), str)
            or not nonce_contract["pattern"]
        ):
            raise AuthorityError("authority Grant nonce contract is invalid")
        try:
            re.compile(nonce_contract["pattern"])
        except re.error as exc:
            raise AuthorityError("authority Grant nonce pattern is invalid") from exc
        for field in ("trust_proofs_min", "trust_proofs_max"):
            value = grant_contract.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise AuthorityError("authority Grant proof limits are invalid")
        if grant_contract["trust_proofs_min"] > grant_contract["trust_proofs_max"]:
            raise AuthorityError("authority Grant proof limits are inverted")
        for proof_kind, proof_contract in proof_contracts.items():
            match proof_kind:
                case "issuer-grant" | "local-root" | "signature":
                    pass
                case _:
                    raise AuthorityError("authority Grant proof dispatcher mismatch")
            if not isinstance(proof_contract, Mapping):
                raise AuthorityError("authority Grant proof contract is invalid")
            expected_contract_fields = {"required_fields"}
            if proof_kind == "signature":
                expected_contract_fields |= {
                    "signature_max_length",
                    "signature_min_length",
                }
            fields = proof_contract.get("required_fields")
            if (
                set(proof_contract) != expected_contract_fields
                or not isinstance(fields, list)
                or not fields
                or len(fields) != len(set(fields))
                or any(not isinstance(field, str) or not field for field in fields)
            ):
                raise AuthorityError("authority Grant proof contract is invalid")
            if proof_kind == "signature":
                minimum = proof_contract.get("signature_min_length")
                maximum = proof_contract.get("signature_max_length")
                if (
                    not isinstance(minimum, int)
                    or isinstance(minimum, bool)
                    or minimum < 1
                    or not isinstance(maximum, int)
                    or isinstance(maximum, bool)
                    or maximum < minimum
                ):
                    raise AuthorityError("signature proof limits are invalid")

        sod_contract = policy.get("separation_of_duties_contract")
        if not isinstance(sod_contract, Mapping) or set(sod_contract) != {
            "base_fields",
            "capability_values_max",
            "external_capability_ids",
            "rules_max",
            "supported_rule_fields",
            "unknown_rule_field",
        }:
            raise AuthorityError("authority separation-of-duties contract is invalid")
        base_fields = sod_contract.get("base_fields")
        supported_rule_fields = sod_contract.get("supported_rule_fields")
        external_capabilities = sod_contract.get("external_capability_ids")
        sod_capabilities = policy.get("separation_of_duties_capability_ids")
        if (
            not isinstance(base_fields, list)
            or not base_fields
            or len(base_fields) != len(set(base_fields))
            or any(not isinstance(field, str) or not field for field in base_fields)
            or not isinstance(supported_rule_fields, Mapping)
            or sod_contract.get("unknown_rule_field") != "reject"
            or not isinstance(external_capabilities, list)
            or len(external_capabilities) != len(set(external_capabilities))
            or any(
                not isinstance(value, str) or not value
                for value in external_capabilities
            )
            or not isinstance(sod_capabilities, list)
            or sod_capabilities != [*capabilities, *external_capabilities]
            or len(sod_capabilities) != len(set(sod_capabilities))
        ):
            raise AuthorityError("authority separation-of-duties dispatcher mismatch")
        for rule_field in supported_rule_fields:
            match rule_field:
                case (
                    "forbid_lease_derived_capabilities"
                    | "forbid_same_key_capabilities"
                    | "forbid_same_subject_for_same_candidate"
                    | "forbid_same_subject_for_same_finding"
                ):
                    pass
                case _:
                    raise AuthorityError(
                        "authority separation-of-duties dispatcher mismatch"
                    )
        for field in ("rules_max", "capability_values_max"):
            value = sod_contract.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise AuthorityError("authority separation-of-duties limits are invalid")
        for field, rule_shape in supported_rule_fields.items():
            if not isinstance(rule_shape, Mapping):
                raise AuthorityError("authority separation-of-duties shape is invalid")
            cardinality = rule_shape.get("cardinality")
            if cardinality == "unique-list":
                if (
                    set(rule_shape) != {"cardinality", "items_min"}
                    or not isinstance(rule_shape.get("items_min"), int)
                    or isinstance(rule_shape.get("items_min"), bool)
                    or rule_shape["items_min"] < 1
                ):
                    raise AuthorityError("authority SOD list shape is invalid")
            elif cardinality == "unique-pair":
                if (
                    set(rule_shape) != {"cardinality", "items_exact"}
                    or not isinstance(rule_shape.get("items_exact"), int)
                    or isinstance(rule_shape.get("items_exact"), bool)
                    or rule_shape["items_exact"] < 1
                ):
                    raise AuthorityError("authority SOD pair shape is invalid")
            else:
                raise AuthorityError("authority SOD cardinality dispatcher mismatch")
        rules = policy.get("separation_of_duties")
        if (
            not isinstance(rules, list)
            or not rules
            or len(rules) > sod_contract["rules_max"]
            or len({item.get("id") for item in rules if isinstance(item, Mapping)})
            != len(rules)
        ):
            raise AuthorityError("authority separation-of-duties policy is invalid")
        for rule in rules:
            rule_fields = set(rule) - set(base_fields) if isinstance(rule, Mapping) else set()
            if (
                not isinstance(rule, Mapping)
                or not set(base_fields) <= set(rule)
                or not rule_fields
                or not rule_fields <= set(supported_rule_fields)
                or not all(
                    isinstance(rule.get(field), str) and rule[field]
                    for field in base_fields
                )
            ):
                raise AuthorityError("authority separation-of-duties rule is invalid")
            for field in rule_fields:
                values = rule[field]
                shape = supported_rule_fields[field]
                minimum = shape.get("items_min", shape.get("items_exact"))
                maximum = shape.get(
                    "items_exact", sod_contract["capability_values_max"]
                )
                if (
                    not isinstance(values, list)
                    or len(values) < minimum
                    or len(values) > maximum
                    or len(values) != len(set(values))
                    or any(not isinstance(value, str) or not value for value in values)
                    or not set(values) <= set(sod_capabilities)
                ):
                    raise AuthorityError(
                        "authority separation-of-duties capabilities are invalid"
                    )
                if field == "forbid_lease_derived_capabilities" and rule[
                    "scope_kind"
                ] != "lease":
                    raise AuthorityError("lease separation-of-duties scope is invalid")
                if field == "forbid_same_subject_for_same_finding" and rule[
                    "scope_kind"
                ] != "finding":
                    raise AuthorityError("finding separation-of-duties scope is invalid")
                if field == "forbid_same_subject_for_same_candidate" and rule[
                    "scope_kind"
                ] not in {"candidate", "candidate-and-key"}:
                    raise AuthorityError("candidate separation-of-duties scope is invalid")
                if field == "forbid_same_key_capabilities" and rule[
                    "scope_kind"
                ] != "candidate-and-key":
                    raise AuthorityError("key separation-of-duties scope is invalid")

        timestamp_contract = policy.get("canonical_timestamp_contract")
        parser_identity = f"{parse_utc_second.__module__}.{parse_utc_second.__name__}"
        formatter_identity = (
            f"{format_utc_second.__module__}.{format_utc_second.__name__}"
        )
        if (
            not isinstance(timestamp_contract, Mapping)
            or not isinstance(timestamp_contract.get("parser_api"), str)
            or not timestamp_contract["parser_api"].startswith(parser_identity)
            or not isinstance(timestamp_contract.get("formatter_api"), str)
            or not timestamp_contract["formatter_api"].startswith(formatter_identity)
        ):
            raise AuthorityError("authority canonical timestamp dispatcher mismatch")
        identity = {
            key: deepcopy(value)
            for key, value in policy.items()
            if key != "policy_digest"
        }
        if policy.get("policy_digest") != canonical_digest(identity):
            raise AuthorityError("authority runtime policy digest mismatch")

    def _scope_keys_for(
        self, scope: Iterable[Mapping[str, Any]], *, scope_role: str
    ) -> tuple[tuple[str, str], ...]:
        contract = self._runtime_policy["scope_contract"]
        limit_fields = {
            "grant": "grant_scope_items_max",
            "requested": "requested_scope_items_max",
        }
        limit_field = limit_fields.get(scope_role)
        if limit_field is None:
            raise AuthorityError("unknown scope policy role")
        return _scope_keys(scope, contract, max_items=contract[limit_field])

    def _scope_is_subset(
        self,
        requested: Iterable[Mapping[str, Any]],
        allowed: Iterable[Mapping[str, Any]],
        *,
        requested_scope_role: str,
        allowed_scope_role: str,
    ) -> bool:
        contract = self._runtime_policy["scope_contract"]
        limit_fields = {
            "grant": "grant_scope_items_max",
            "requested": "requested_scope_items_max",
        }
        requested_field = limit_fields.get(requested_scope_role)
        allowed_field = limit_fields.get(allowed_scope_role)
        if requested_field is None or allowed_field is None:
            raise AuthorityError("unknown scope policy role")
        return scope_is_subset(
            requested,
            allowed,
            contract,
            requested_max_items=contract[requested_field],
            allowed_max_items=contract[allowed_field],
        )

    @property
    def authority_init(self) -> dict[str, Any]:
        return deepcopy(self._authority_init)

    @property
    def runtime_policy(self) -> dict[str, Any]:
        return deepcopy(self._runtime_policy)

    @property
    def separation_of_duties(self) -> tuple[dict[str, Any], ...]:
        return tuple(deepcopy(self._separation_of_duties))

    @property
    def grants(self) -> dict[str, dict[str, Any]]:
        return deepcopy(self._grants.to_dict())

    @property
    def revocations(self) -> dict[str, dict[str, Any]]:
        return deepcopy(self._revocations.to_dict())

    def resolve_grant(self, grant_id: str) -> dict[str, Any] | None:
        """Resolve one exact Grant without materializing the authority map."""

        if not isinstance(grant_id, str) or not grant_id:
            raise AuthorityError("invalid Grant identity")
        grant = self._grants.get(grant_id)
        return None if grant is None else deepcopy(grant)

    @property
    def is_frozen(self) -> bool:
        return self._is_frozen

    def _ensure_mutable(self) -> None:
        if self._is_frozen:
            raise AuthorityError("frozen authority snapshot cannot be mutated")

    def fork(
        self,
        *,
        decision_resolver: DecisionResolver | None | object = _INHERIT_RESOLVER,
    ) -> AuthorityEngine:
        """Create an O(1) isolated transaction overlay over this snapshot."""

        if not self._is_frozen:
            raise AuthorityError("authority snapshot must be frozen before fork")
        selected_resolver = (
            self.decision_resolver
            if decision_resolver is _INHERIT_RESOLVER
            else decision_resolver
        )
        if selected_resolver is not None and not callable(selected_resolver):
            raise AuthorityError("decision resolver must be callable")
        forked = object.__new__(AuthorityEngine)
        forked._authority_init = self._authority_init
        forked.activation_digest = self.activation_digest
        forked._runtime_policy = self._runtime_policy
        forked.capabilities = self.capabilities
        forked._separation_of_duties = self._separation_of_duties
        forked.signature_verifier = self.signature_verifier
        forked.signature_provider_evidence = self.signature_provider_evidence
        forked.decision_resolver = selected_resolver
        forked.max_delegation_depth = self.max_delegation_depth
        forked._grants = self._grants.fork()
        forked._revocations = self._revocations.fork()
        forked._nonces = self._nonces.fork()
        forked._grant_issue_authorizations = {}
        forked._candidate_actions = self._candidate_actions.fork()
        forked._finding_actions = self._finding_actions.fork()
        forked._last_live_evaluation = self._last_live_evaluation
        forked._last_replay_evaluation = self._last_replay_evaluation
        forked._live_evaluation_changed = False
        forked._replay_evaluation_changed = False
        forked._is_frozen = False
        forked._freeze_compaction_depth = None
        forked._freeze_result = None
        return forked

    def freeze(
        self, *, runtime_overlay_compaction_depth: int
    ) -> AuthorityFreezeResult:
        """Seal this transaction as a publishable immutable snapshot.

        The compaction threshold comes from the verified EventStorePolicy.
        Ordinary sealing is O(changed leaves). Threshold compaction is explicitly
        O(total state * overlay depth), with its record and canonical payload
        sizes reported.
        """

        if (
            not isinstance(runtime_overlay_compaction_depth, int)
            or isinstance(runtime_overlay_compaction_depth, bool)
            or runtime_overlay_compaction_depth < 1
        ):
            raise AuthorityError("invalid authority overlay compaction depth")
        if self._grant_issue_authorizations:
            raise AuthorityError(
                "authority snapshot has unconsumed Grant issue authorizations"
            )
        if self._is_frozen:
            if self._freeze_compaction_depth != runtime_overlay_compaction_depth:
                raise AuthorityError("frozen authority snapshot compaction policy changed")
            if self._freeze_result is None:
                raise AuthorityError("frozen authority snapshot lacks freeze metrics")
            return self._freeze_result
        overlays = (
            self._grants,
            self._revocations,
            self._nonces,
            self._candidate_actions,
            self._finding_actions,
        )
        changed_leaf_count = sum(overlay.change_count for overlay in overlays)
        changed_leaf_count += int(self._live_evaluation_changed)
        changed_leaf_count += int(self._replay_evaluation_changed)
        for overlay in overlays:
            overlay.seal()
        compacted = (
            max(overlay.depth for overlay in overlays)
            >= runtime_overlay_compaction_depth
        )
        compacted_record_count = 0
        compacted_payload_bytes = 0
        if compacted:
            def metric_value(value: Any) -> Any:
                if isinstance(value, (set, frozenset)):
                    return sorted(value)
                if isinstance(value, dict):
                    return {
                        key: metric_value(item)
                        for key, item in sorted(value.items())
                    }
                if isinstance(value, list):
                    return [metric_value(item) for item in value]
                if isinstance(value, tuple):
                    return [metric_value(item) for item in value]
                if isinstance(value, datetime):
                    return format_utc_second(value)
                return value

            named_overlays = (
                ("grants", self._grants),
                ("revocations", self._revocations),
                ("nonces", self._nonces),
                ("candidate_actions", self._candidate_actions),
                ("finding_actions", self._finding_actions),
            )
            for map_name, overlay in named_overlays:
                for key, value in sorted(overlay.items()):
                    compacted_record_count += 1
                    compacted_payload_bytes += len(
                        canonical_bytes(
                            {
                                "map": map_name,
                                "key": metric_value(key),
                                "value": metric_value(value),
                            }
                        )
                    )
            for cursor_name, cursor in (
                ("last_live_evaluation", self._last_live_evaluation),
                ("last_replay_evaluation", self._last_replay_evaluation),
            ):
                if cursor is not None:
                    compacted_record_count += 1
                    compacted_payload_bytes += len(
                        canonical_bytes(
                            {"cursor": cursor_name, "value": metric_value(cursor)}
                        )
                    )
            self._grants = self._grants.compacted()
            self._revocations = self._revocations.compacted()
            self._nonces = self._nonces.compacted()
            self._candidate_actions = self._candidate_actions.compacted()
            self._finding_actions = self._finding_actions.compacted()
        self._is_frozen = True
        self._freeze_compaction_depth = runtime_overlay_compaction_depth
        self._freeze_result = AuthorityFreezeResult(
            snapshot=self,
            changed_leaf_count=changed_leaf_count,
            compacted=compacted,
            compacted_record_count=compacted_record_count,
            compacted_payload_bytes=compacted_payload_bytes,
        )
        return self._freeze_result

    def checkpoint(self) -> dict[str, Any]:
        """Return a canonical, derived snapshot of authority replay state."""

        def actions(
            values: Mapping[tuple[str, str], tuple[dict[str, Any], ...]],
            target_kind: str,
        ) -> list[dict[str, Any]]:
            rows: list[dict[str, Any]] = []
            for (target_id, capability), provenance in sorted(values.items()):
                for action in sorted(
                    provenance,
                    key=lambda value: (
                        value["subject_id"],
                        value["grant_id"],
                        value["evaluated_at"],
                        canonical_digest(value),
                    ),
                ):
                    if (
                        action.get("target_kind") != target_kind
                        or action.get("target_id") != target_id
                        or action.get("capability_id") != capability
                    ):
                        raise AuthorityError(
                            "authority action provenance differs from its state key"
                        )
                    rows.append(deepcopy(action))
            return rows

        def timestamp(value: datetime | None) -> str | None:
            if value is None:
                return None
            try:
                return format_utc_second(value)
            except CanonicalError as exc:
                raise AuthorityError("invalid authority evaluation timestamp") from exc

        identity = {
            "record_type": "AuthorityCheckpoint",
            "activation_digest": self.activation_digest,
            "authority_init_digest": canonical_digest(self._authority_init),
            "runtime_policy_digest": self._runtime_policy["policy_digest"],
            "grants": [deepcopy(self._grants[key]) for key in sorted(self._grants)],
            "revocations": [
                deepcopy(self._revocations[key]) for key in sorted(self._revocations)
            ],
            "nonces": [
                {"nonce": nonce, "grant_id": self._nonces[nonce]}
                for nonce in sorted(self._nonces)
            ],
            "candidate_actions": actions(
                self._candidate_actions, "candidate"
            ),
            "finding_actions": actions(self._finding_actions, "finding"),
            "last_live_evaluation": timestamp(self._last_live_evaluation),
            "last_replay_evaluation": timestamp(self._last_replay_evaluation),
        }
        return {**identity, "checkpoint_digest": derived_checkpoint_digest(identity)}

    def restore_checkpoint(self, checkpoint: Mapping[str, Any]) -> None:
        """Strictly validate then atomically restore a derived authority snapshot."""

        self._ensure_mutable()
        if self._grant_issue_authorizations:
            raise AuthorityError(
                "cannot restore over unconsumed Grant issue authorizations"
            )
        fields = {
            "record_type",
            "activation_digest",
            "authority_init_digest",
            "runtime_policy_digest",
            "grants",
            "revocations",
            "nonces",
            "candidate_actions",
            "finding_actions",
            "last_live_evaluation",
            "last_replay_evaluation",
            "checkpoint_digest",
        }
        if not isinstance(checkpoint, Mapping) or set(checkpoint) != fields:
            raise AuthorityError("invalid authority checkpoint shape")
        if checkpoint.get("record_type") != "AuthorityCheckpoint":
            raise AuthorityError("invalid authority checkpoint identity")
        if checkpoint.get("activation_digest") != self.activation_digest:
            raise AuthorityError("authority checkpoint Activation mismatch")
        if checkpoint.get("authority_init_digest") != canonical_digest(
            self._authority_init
        ):
            raise AuthorityError("authority checkpoint init mismatch")
        if checkpoint.get("runtime_policy_digest") != self._runtime_policy["policy_digest"]:
            raise AuthorityError("authority checkpoint runtime policy mismatch")
        identity = {
            key: deepcopy(value)
            for key, value in checkpoint.items()
            if key != "checkpoint_digest"
        }
        if checkpoint.get("checkpoint_digest") != derived_checkpoint_digest(identity):
            raise AuthorityError("authority checkpoint digest mismatch")

        list_fields = (
            "grants",
            "revocations",
            "nonces",
            "candidate_actions",
            "finding_actions",
        )
        if any(not isinstance(checkpoint[name], list) for name in list_fields):
            raise AuthorityError("authority checkpoint collections must be arrays")
        if any(len(checkpoint[name]) > 100_000 for name in list_fields):
            raise AuthorityError("authority checkpoint collection exceeds bound")

        scratch = AuthorityEngine(
            self._authority_init,
            self.activation_digest,
            self._runtime_policy,
            signature_verifier=self.signature_verifier,
            decision_resolver=self.decision_resolver,
        )
        grants: dict[str, dict[str, Any]] = {}
        for grant in checkpoint["grants"]:
            if not isinstance(grant, Mapping):
                raise AuthorityError("authority checkpoint Grant is not an object")
            stored = deepcopy(dict(grant))
            grant_id = stored.get("grant_id")
            if not isinstance(grant_id, str) or not grant_id or grant_id in grants:
                raise AuthorityError("duplicate or invalid checkpoint Grant")
            grants[grant_id] = stored
        scratch._grants = _PersistentOverlayMap(values=grants)
        for grant_id in sorted(grants):
            scratch._validate_grant(grants[grant_id], grants[grant_id].get("issued_at"))

        expected_nonces = {
            grant["nonce"]: grant_id for grant_id, grant in grants.items()
        }
        nonces: dict[str, str] = {}
        for item in checkpoint["nonces"]:
            if (
                not isinstance(item, Mapping)
                or set(item) != {"nonce", "grant_id"}
                or not isinstance(item.get("nonce"), str)
                or not isinstance(item.get("grant_id"), str)
                or item["nonce"] in nonces
            ):
                raise AuthorityError("invalid authority checkpoint nonce")
            nonces[item["nonce"]] = item["grant_id"]
        if nonces != expected_nonces:
            raise AuthorityError("authority checkpoint nonce map mismatch")

        revocations: dict[str, dict[str, Any]] = {}
        for item in checkpoint["revocations"]:
            if (
                not isinstance(item, Mapping)
                or set(item)
                != {
                    "grant_id",
                    "decision_id",
                    "decision_binding",
                    "reason",
                    "revoked_at",
                }
                or item.get("grant_id") not in grants
                or not isinstance(item.get("decision_id"), str)
                or not item.get("decision_id")
                or not isinstance(item.get("decision_binding"), Mapping)
                or not isinstance(item.get("reason"), str)
                or not item.get("reason")
                or item["grant_id"] in revocations
            ):
                raise AuthorityError("invalid checkpoint Grant revocation")
            parse_timestamp(item.get("revoked_at"))
            revocations[item["grant_id"]] = deepcopy(dict(item))

        scratch._revocations = _PersistentOverlayMap(values=revocations)
        for item in revocations.values():
            scratch._validate_stored_decision_binding(
                item["decision_binding"],
                decision_id=item["decision_id"],
                grant_id=item["grant_id"],
                revoked_at=item["revoked_at"],
            )
            if scratch._resolve_revocation_decision(
                item["decision_id"],
                item["grant_id"],
                item["reason"],
                item["revoked_at"],
                authorizing_grant_id=item["decision_binding"][
                    "authorizing_grant_id"
                ],
                subject_id=item["decision_binding"]["subject_id"],
            ) != dict(item["decision_binding"]):
                raise AuthorityError(
                    "checkpoint Grant revocation Decision binding changed"
                )

        def restore_actions(
            rows: Iterable[Mapping[str, Any]], target_kind: str
        ) -> dict[tuple[str, str], tuple[dict[str, Any], ...]]:
            restored: dict[tuple[str, str], tuple[dict[str, Any], ...]] = {}
            seen: set[tuple[str, str, str, str, str]] = set()
            for row in rows:
                effect_scope = row.get("effect_scope") if isinstance(row, Mapping) else None
                grant = (
                    grants.get(row.get("grant_id"))
                    if isinstance(row, Mapping)
                    else None
                )
                if (
                    not isinstance(row, Mapping)
                    or set(row) != _ACTION_PROVENANCE_FIELDS
                    or row.get("record_type") != "AuthorityActionProvenance"
                    or row.get("target_kind") != target_kind
                    or not isinstance(row.get("target_id"), str)
                    or not row.get("target_id")
                    or (target_kind == "candidate" and not _valid_digest(row["target_id"]))
                    or row.get("capability_id") not in self.capabilities
                    or row.get("activation_digest") != self.activation_digest
                    or not isinstance(row.get("subject_id"), str)
                    or not row["subject_id"]
                    or not isinstance(row.get("grant_id"), str)
                    or not row["grant_id"]
                    or not _valid_digest(row.get("grant_claim_digest"))
                    or not isinstance(effect_scope, list)
                    or not effect_scope
                    or any(not isinstance(selector, Mapping) for selector in effect_scope)
                    or grant is None
                    or grant.get("subject_id") != row.get("subject_id")
                    or grant.get("capability_id") != row.get("capability_id")
                    or grant.get("claim_digest") != row.get("grant_claim_digest")
                ):
                    raise AuthorityError(
                        "invalid authority checkpoint action provenance"
                    )
                evaluated_at = row.get("evaluated_at")
                parse_timestamp(evaluated_at)
                scratch._scope_keys_for(effect_scope, scope_role="requested")
                scratch._validate_grant(grant, evaluated_at)
                if not scratch._scope_is_subset(
                    effect_scope,
                    grant["scope"],
                    requested_scope_role="requested",
                    allowed_scope_role="grant",
                ):
                    raise AuthorityError(
                        "authority checkpoint action scope exceeds its Grant"
                    )
                action_identity = (
                    row["target_id"],
                    row["capability_id"],
                    row["subject_id"],
                    row["grant_id"],
                    row["evaluated_at"],
                )
                if action_identity in seen:
                    raise AuthorityError(
                        "duplicate authority checkpoint action provenance"
                    )
                seen.add(action_identity)
                action_key = (row["target_id"], row["capability_id"])
                restored[action_key] = (
                    *restored.get(action_key, ()),
                    deepcopy(dict(row)),
                )
            return restored

        candidate_actions = restore_actions(
            checkpoint["candidate_actions"], "candidate"
        )
        finding_actions = restore_actions(checkpoint["finding_actions"], "finding")

        def restore_timestamp(name: str) -> datetime | None:
            value = checkpoint[name]
            if value is None:
                return None
            return parse_timestamp(value)

        last_live = restore_timestamp("last_live_evaluation")
        last_replay = restore_timestamp("last_replay_evaluation")

        scratch._nonces = _PersistentOverlayMap(values=nonces)
        scratch._candidate_actions = _PersistentOverlayMap(values=candidate_actions)
        scratch._finding_actions = _PersistentOverlayMap(values=finding_actions)
        for (target_id, capability_id), provenance_rows in candidate_actions.items():
            for provenance in provenance_rows:
                scratch.assert_separation_of_duties(
                    provenance["subject_id"],
                    capability_id,
                    candidate_digest=target_id,
                )
        for (target_id, capability_id), provenance_rows in finding_actions.items():
            for provenance in provenance_rows:
                scratch.assert_separation_of_duties(
                    provenance["subject_id"],
                    capability_id,
                    finding_id=target_id,
                )
        scratch._last_live_evaluation = last_live
        scratch._last_replay_evaluation = last_replay
        scratch._live_evaluation_changed = last_live is not None
        scratch._replay_evaluation_changed = last_replay is not None
        for grant_id in sorted(grants):
            scratch._validate_grant(
                grants[grant_id],
                grants[grant_id]["issued_at"],
                ignore_revocation=frozenset({grant_id}),
            )
        for grant in grants.values():
            scratch._assert_grant_separation_of_duties(grant)
        for (candidate_digest, capability_id), provenance in candidate_actions.items():
            for action in provenance:
                scratch.assert_separation_of_duties(
                    action["subject_id"],
                    capability_id,
                    candidate_digest=candidate_digest,
                )
        for (finding_id, capability_id), provenance in finding_actions.items():
            for action in provenance:
                scratch.assert_separation_of_duties(
                    action["subject_id"],
                    capability_id,
                    finding_id=finding_id,
                )
        if scratch.checkpoint() != dict(checkpoint):
            raise AuthorityError("authority checkpoint is not in canonical order")

        self._grants = scratch._grants
        self._revocations = scratch._revocations
        self._nonces = scratch._nonces
        self._candidate_actions = scratch._candidate_actions
        self._finding_actions = scratch._finding_actions
        self._last_live_evaluation = scratch._last_live_evaluation
        self._last_replay_evaluation = scratch._last_replay_evaluation
        self._live_evaluation_changed = scratch._live_evaluation_changed
        self._replay_evaluation_changed = scratch._replay_evaluation_changed

    def _validate_authority_init(self) -> None:
        init = self._authority_init
        if init.get("record_type") != "AuthorityInit":
            raise AuthorityError("authority init record_type must be AuthorityInit")
        if init.get("trust_mode") not in {"local-owner", "team-signed"}:
            raise AuthorityError("unsupported trust mode")
        subjects = init.get("subjects")
        roots = init.get("roots")
        if not isinstance(subjects, list) or not subjects:
            raise AuthorityError("authority init requires configured subjects")
        if not isinstance(roots, list) or not roots:
            raise AuthorityError("authority init requires configured roots")
        subject_ids = [item.get("subject_id") for item in subjects]
        if any(not isinstance(item, str) or not item for item in subject_ids):
            raise AuthorityError("invalid authority subject")
        if len(subject_ids) != len(set(subject_ids)):
            raise AuthorityError("duplicate authority subject")
        root_ids: set[str] = set()
        for root in roots:
            if set(root) != {"subject_id", "capability_ceiling", "scope"}:
                raise AuthorityError("invalid configured root shape")
            subject = root["subject_id"]
            if subject not in subject_ids or subject in root_ids:
                raise AuthorityError("root is unknown or duplicated")
            root_ids.add(subject)
            ceiling = root["capability_ceiling"]
            if (
                not isinstance(ceiling, list)
                or not ceiling
                or len(ceiling) != len(set(ceiling))
                or not set(ceiling) <= self.capabilities
            ):
                raise AuthorityError("invalid configured root capability ceiling")
            self._scope_keys_for(root["scope"], scope_role="grant")
        if init["trust_mode"] == "team-signed":
            keys = init.get("keys")
            policy = init.get("team_policy")
            if not isinstance(keys, list) or not keys or not isinstance(policy, Mapping):
                raise AuthorityError("team-signed authority requires keys and policy")
            key_ids = [item.get("key_id") for item in keys]
            if len(key_ids) != len(set(key_ids)):
                raise AuthorityError("duplicate trust key")
            configured = policy.get("key_ids")
            threshold = policy.get("threshold")
            if (
                not isinstance(configured, list)
                or not configured
                or not set(configured) <= set(key_ids)
                or not isinstance(threshold, int)
                or isinstance(threshold, bool)
                or threshold < 1
                or threshold > len(set(configured))
            ):
                raise AuthorityError("invalid team signature threshold")
        elif "keys" in init or "team_policy" in init:
            raise AuthorityError("local-owner authority must not contain team keys")

    def _root(self, subject_id: str) -> Mapping[str, Any] | None:
        return next(
            (
                root
                for root in self._authority_init["roots"]
                if root["subject_id"] == subject_id
            ),
            None,
        )

    def _verified_signature_keys(
        self,
        proofs: Iterable[Mapping[str, Any]],
        signed_digest: str,
        *,
        proof_kind: str = "signature",
        digest_field: str = "signed_digest",
        required_fields: Iterable[str] | None = None,
    ) -> set[str]:
        if self.signature_verifier is None:
            raise AuthorityError("team signatures require a verifier")
        keys = {item["key_id"]: item for item in self._authority_init.get("keys", [])}
        signature_contract = self._runtime_policy["grant_contract"][
            "trust_proof_kinds"
        ]["signature"]
        exact_fields = set(
            signature_contract["required_fields"]
            if required_fields is None
            else required_fields
        )
        valid: set[str] = set()
        for proof in proofs:
            key = keys.get(proof.get("key_id"))
            signature = proof.get("signature")
            if (
                set(proof) != exact_fields
                or proof.get("kind") != proof_kind
                or key is None
                or proof.get("algorithm") != key.get("algorithm")
                or proof.get(digest_field) != signed_digest
                or not isinstance(signature, str)
                or not signature_contract["signature_min_length"]
                <= len(signature)
                <= signature_contract["signature_max_length"]
            ):
                continue
            try:
                accepted = bool(self.signature_verifier(proof, key))
            except Exception as exc:
                raise AuthorityError("signature verifier failed closed") from exc
            if accepted:
                valid.add(proof["key_id"])
        return valid

    def authorize_bootstrap_command(
        self, command: Mapping[str, Any], *, replay: bool = False
    ) -> dict[str, Any]:
        """Validate the one configured-root command that establishes authority.manage."""

        if command.get("record_type") != "CommandRequest":
            raise AuthorityError("bootstrap authorization requires a CommandRequest")
        if command.get("activation_digest") != self.activation_digest:
            raise AuthorityError("bootstrap command Activation mismatch")
        if command.get("command_kind") != "grant.issue":
            raise AuthorityError("root authorization may only bootstrap authority.manage")
        if any(grant["capability_id"] == "authority.manage" for grant in self._grants.values()):
            raise AuthorityError("root authorization is disabled after authority bootstrap")
        intent_identity = {
            key: deepcopy(value)
            for key, value in command.items()
            if key not in {"intent_digest", "authorization"}
        }
        if command.get("intent_digest") != canonical_digest(intent_identity):
            raise AuthorityError("bootstrap command intent digest mismatch")
        authorization = command.get("authorization")
        if not isinstance(authorization, Mapping) or set(authorization) != {
            "kind",
            "subject_id",
            "proofs",
        }:
            raise AuthorityError("invalid root command authorization")
        if authorization.get("kind") != "root" or authorization.get("subject_id") != command.get(
            "subject_id"
        ):
            raise AuthorityError("root command subject mismatch")
        root = self._root(command.get("subject_id"))
        if root is None:
            raise AuthorityError("bootstrap subject is not a configured root")
        payload = command.get("payload")
        if not isinstance(payload, Mapping) or payload.get("capability_id") != "authority.manage":
            raise AuthorityError("bootstrap payload must be an authority.manage Grant")
        if payload.get("subject_id") != command.get("subject_id"):
            raise AuthorityError("bootstrap Grant subject must be the configured root")
        requested_scope = command.get("requested_scope")
        if not isinstance(requested_scope, list):
            raise AuthorityError("bootstrap command requested scope is invalid")
        if not self._scope_is_subset(
            requested_scope,
            root["scope"],
            requested_scope_role="requested",
            allowed_scope_role="grant",
        ):
            raise AuthorityError("bootstrap command exceeds configured root scope")
        if not self._scope_is_subset(
            payload.get("scope", []),
            requested_scope,
            requested_scope_role="grant",
            allowed_scope_role="requested",
        ):
            raise AuthorityError("bootstrap Grant exceeds command scope")
        if payload.get("issued_at") != command.get("issued_at"):
            raise AuthorityError("bootstrap Grant not-before time differs from command")
        evaluation = self._check_evaluation_time(command["issued_at"], replay=replay)
        proofs = authorization["proofs"]
        proof_policy = self._runtime_policy["grant_contract"]
        if (
            not isinstance(proofs, list)
            or not proof_policy["trust_proofs_min"]
            <= len(proofs)
            <= proof_policy["trust_proofs_max"]
        ):
            raise AuthorityError("root command requires bounded proofs")
        if (
            proof_policy["trust_proofs_unique"]
            and len({canonical_digest(proof) for proof in proofs}) != len(proofs)
        ):
            raise AuthorityError("duplicate root command proof")
        if self._authority_init["trust_mode"] == "local-owner":
            if len(proofs) != 1 or set(proofs[0]) != {
                "kind",
                "subject_id",
                "authority_init_digest",
                "signed_intent_digest",
            }:
                raise AuthorityError("invalid local root command proof")
            proof = proofs[0]
            if (
                proof.get("kind") != "local-root-command"
                or proof.get("subject_id") != command["subject_id"]
                or proof.get("authority_init_digest")
                != canonical_digest(self._authority_init)
                or proof.get("signed_intent_digest") != command["intent_digest"]
            ):
                raise AuthorityError("local root command proof mismatch")
        else:
            valid = self._verified_signature_keys(
                proofs,
                command["intent_digest"],
                proof_kind="signature-command",
                digest_field="signed_intent_digest",
                required_fields=(
                    "kind",
                    "key_id",
                    "algorithm",
                    "signed_intent_digest",
                    "signature",
                ),
            )
            policy = self._authority_init["team_policy"]
            if len(valid & set(policy["key_ids"])) < policy["threshold"]:
                raise AuthorityError("root command lacks verified signature threshold")
        self._validate_grant(payload, command["issued_at"])
        self._record_evaluation_time(evaluation, replay=replay)
        return deepcopy(dict(payload))

    def authorize_grant_issue_command(
        self, command: Mapping[str, Any], *, replay: bool = False
    ) -> dict[str, Any]:
        """Authorize one exact grant.issue command and return an immutable receipt.

        The receipt is the only accepted bridge between command authorization and
        Grant persistence.  It binds the command-authorizing Grant separately from
        the child claim so a caller cannot authorize one issuer and persist another.
        """

        self._ensure_mutable()
        if (
            not isinstance(command, Mapping)
            or command.get("record_type") != "CommandRequest"
            or command.get("command_kind") != "grant.issue"
            or command.get("activation_digest") != self.activation_digest
        ):
            raise AuthorityError("Grant issue authorization requires an exact command")
        grant = command.get("payload")
        if not isinstance(grant, Mapping):
            raise AuthorityError("Grant issue command payload is not a Grant")
        if command.get("issued_at") != grant.get("issued_at"):
            raise AuthorityError("Grant issue command time differs from child not-before")
        requested_scope = command.get("requested_scope")
        if not isinstance(requested_scope, list):
            raise AuthorityError("Grant issue command scope is invalid")
        self._scope_keys_for(requested_scope, scope_role="requested")
        if not self._scope_is_subset(
            grant.get("scope", []),
            requested_scope,
            requested_scope_role="grant",
            allowed_scope_role="requested",
        ):
            raise AuthorityError("Grant issue child scope exceeds command scope")
        intent_identity = {
            key: deepcopy(value)
            for key, value in command.items()
            if key not in {"intent_digest", "authorization"}
        }
        if command.get("intent_digest") != canonical_digest(intent_identity):
            raise AuthorityError("Grant issue command intent digest mismatch")
        authorization = command.get("authorization")
        if not isinstance(authorization, Mapping):
            raise AuthorityError("Grant issue command authorization is invalid")

        if authorization.get("kind") == "root":
            self.authorize_bootstrap_command(command, replay=replay)
            authorization_kind = "root"
            subject_id = command.get("subject_id")
            issuer_grant_id = None
            issuer_claim_digest = None
            issuer_revocation_state_digest = None
        elif set(authorization) == {"kind", "grant_id", "grant_claim_digest"} and authorization.get(
            "kind"
        ) == "grant":
            manager = self.authorize(
                command.get("subject_id"),
                "authority.manage",
                requested_scope,
                authorization.get("grant_id"),
                authorization.get("grant_claim_digest"),
                command.get("issued_at"),
                replay=replay,
            )
            authorization_kind = "grant"
            subject_id = manager["subject_id"]
            issuer_grant_id = manager["grant_id"]
            issuer_claim_digest = manager["claim_digest"]
            issuer_revocation_state_digest = self.grant_revocation_state_digest(
                manager["grant_id"]
            )
            proofs = grant.get("trust_proofs")
            if not isinstance(proofs, list) or not proofs or any(
                not isinstance(proof, Mapping) for proof in proofs
            ):
                raise AuthorityError("Grant issue child trust proofs are invalid")
            proof_kinds = {proof.get("kind") for proof in proofs}
            if proof_kinds == {"issuer-grant"}:
                issuer_proof_fields = set(
                    self._runtime_policy["grant_contract"]["trust_proof_kinds"][
                        "issuer-grant"
                    ]["required_fields"]
                )
                if (
                    len(proofs) != 1
                    or set(proofs[0]) != issuer_proof_fields
                    or proofs[0].get("issuer_grant_id") != issuer_grant_id
                    or proofs[0].get("issuer_signed_claim_digest")
                    != issuer_claim_digest
                ):
                    raise AuthorityError(
                        "Grant issuer proof differs from command-authorized Grant"
                    )
            elif proof_kinds == {"signature"}:
                # In team-signed mode the command-authorizing manager and the
                # cryptographic claim approvers are intentionally independent.
                # Full signature threshold and root-ceiling checks remain in
                # _validate_grant() before the child can be persisted.
                if self._authority_init.get("trust_mode") != "team-signed":
                    raise AuthorityError(
                        "signature-backed Grant issue requires team trust mode"
                    )
            else:
                raise AuthorityError(
                    "Grant issue child trust proofs are mixed or unsupported"
                )
        else:
            raise AuthorityError("Grant issue command authorization is unsupported")

        identity = {
            "record_type": "GrantIssueAuthorization",
            "authorization_kind": authorization_kind,
            "command_digest": canonical_digest(command),
            "command_intent_digest": command["intent_digest"],
            "activation_digest": self.activation_digest,
            "subject_id": subject_id,
            "issuer_grant_id": issuer_grant_id,
            "issuer_signed_claim_digest": issuer_claim_digest,
            "issuer_revocation_state_digest": issuer_revocation_state_digest,
            "child_grant_id": grant.get("grant_id"),
            "child_claim_digest": grant.get("claim_digest"),
            "requested_scope": deepcopy(requested_scope),
            "evaluated_at": command["issued_at"],
        }
        receipt = {**identity, "authorization_digest": canonical_digest(identity)}
        authorization_digest = receipt["authorization_digest"]
        prior = self._grant_issue_authorizations.get(authorization_digest)
        if prior is not None and prior != receipt:
            raise AuthorityError("Grant issue authorization identity collision")
        self._grant_issue_authorizations[authorization_digest] = deepcopy(receipt)
        return deepcopy(receipt)

    def _validate_grant_issue_authorization(
        self,
        grant: Mapping[str, Any],
        evaluation_time: str,
        issue_authorization: Mapping[str, Any],
    ) -> None:
        if (
            not isinstance(issue_authorization, Mapping)
            or set(issue_authorization) != _GRANT_ISSUE_AUTHORIZATION_FIELDS
            or issue_authorization.get("record_type") != "GrantIssueAuthorization"
        ):
            raise AuthorityError("Grant issue requires an exact authorization receipt")
        identity = {
            key: deepcopy(value)
            for key, value in issue_authorization.items()
            if key != "authorization_digest"
        }
        if issue_authorization.get("authorization_digest") != canonical_digest(identity):
            raise AuthorityError("Grant issue authorization receipt digest mismatch")
        issued = self._grant_issue_authorizations.get(
            issue_authorization["authorization_digest"]
        )
        if issued is None or issued != dict(issue_authorization):
            raise AuthorityError(
                "Grant issue authorization was not issued by this authority transaction"
            )
        if (
            issue_authorization.get("activation_digest") != self.activation_digest
            or grant.get("activation_digest") != self.activation_digest
            or issue_authorization.get("child_grant_id") != grant.get("grant_id")
            or issue_authorization.get("child_claim_digest") != grant.get("claim_digest")
            or issue_authorization.get("evaluated_at") != evaluation_time
            or grant.get("issued_at") != evaluation_time
            or not isinstance(issue_authorization.get("requested_scope"), list)
            or not self._scope_is_subset(
                grant.get("scope", []),
                issue_authorization["requested_scope"],
                requested_scope_role="grant",
                allowed_scope_role="requested",
            )
        ):
            raise AuthorityError("Grant issue authorization receipt binding mismatch")

        kind = issue_authorization.get("authorization_kind")
        if kind == "root":
            if any(
                issue_authorization.get(field) is not None
                for field in (
                    "issuer_grant_id",
                    "issuer_signed_claim_digest",
                    "issuer_revocation_state_digest",
                )
            ) or grant.get("subject_id") != issue_authorization.get("subject_id"):
                raise AuthorityError("root Grant issue authorization is inconsistent")
            if any(
                existing["capability_id"] == "authority.manage"
                and existing["grant_id"] != grant.get("grant_id")
                for existing in self._grants.values()
            ):
                raise AuthorityError("root Grant issue authorization is one-time")
            return
        if kind != "grant":
            raise AuthorityError("unknown Grant issue authorization kind")
        issuer_id = issue_authorization.get("issuer_grant_id")
        issuer = self._grants.get(issuer_id)
        if issuer is None:
            raise AuthorityError("command-authorized issuer Grant is unresolved")
        if (
            issuer.get("claim_digest")
            != issue_authorization.get("issuer_signed_claim_digest")
            or issuer.get("subject_id") != issue_authorization.get("subject_id")
            or issuer.get("capability_id") != "authority.manage"
            or self.grant_revocation_state_digest(issuer_id)
            != issue_authorization.get("issuer_revocation_state_digest")
        ):
            raise AuthorityError("command-authorized issuer Grant binding changed")
        self._validate_grant(issuer, evaluation_time)
        if not self._scope_is_subset(
            grant.get("scope", []),
            issuer["scope"],
            requested_scope_role="grant",
            allowed_scope_role="grant",
        ):
            raise AuthorityError("Grant child scope exceeds command-authorized issuer")

    def _revoked_at(self, grant_id: str, evaluation: datetime) -> bool:
        revocation = self._revocations.get(grant_id)
        return revocation is not None and parse_timestamp(
            revocation["revoked_at"]
        ) <= evaluation

    def _check_evaluation_time(self, value: str, *, replay: bool) -> datetime:
        evaluation = parse_timestamp(value)
        previous = (
            self._last_replay_evaluation if replay else self._last_live_evaluation
        )
        if previous is not None and evaluation < previous:
            mode = "replay" if replay else "live"
            raise AuthorityError(f"{mode} authority clock rollback")
        return evaluation

    def _record_evaluation_time(self, evaluation: datetime, *, replay: bool) -> None:
        self._ensure_mutable()
        if replay:
            if self._last_replay_evaluation != evaluation:
                self._replay_evaluation_changed = True
            self._last_replay_evaluation = evaluation
        else:
            if self._last_live_evaluation != evaluation:
                self._live_evaluation_changed = True
            self._last_live_evaluation = evaluation

    def _validate_grant(
        self,
        grant: Mapping[str, Any],
        evaluation_time: str,
        *,
        seen: frozenset[str] = frozenset(),
        ignore_revocation: frozenset[str] = frozenset(),
    ) -> tuple[set[str], int]:
        grant_contract = self._runtime_policy["grant_contract"]
        proof_contracts = grant_contract["trust_proof_kinds"]
        if (
            set(grant) != set(grant_contract["required_fields"])
            or grant.get("record_type") != "Grant"
        ):
            raise AuthorityError("Grant does not match the Core shape")
        grant_id = grant.get("grant_id")
        if not isinstance(grant_id, str) or not grant_id or grant_id in seen:
            raise AuthorityError("invalid or cyclic Grant identity")
        if grant.get("activation_digest") != self.activation_digest:
            raise AuthorityError("Grant Activation mismatch")
        expected_claim = canonical_digest(grant_claim_identity(grant))
        if grant.get("claim_digest") != expected_claim:
            raise AuthorityError("Grant claim digest mismatch")
        capability = grant.get("capability_id")
        if capability not in self.capabilities:
            raise AuthorityError("unknown Grant capability")
        subjects = {
            item["subject_id"] for item in self._authority_init["subjects"]
        }
        if grant.get("subject_id") not in subjects:
            raise AuthorityError("Grant subject is not configured")
        scope = grant.get("scope")
        if not isinstance(scope, list):
            raise AuthorityError("Grant scope must be an array")
        self._scope_keys_for(scope, scope_role="grant")
        issued = parse_timestamp(grant.get("issued_at"))
        expires = parse_timestamp(grant.get("expires_at"))
        evaluation = parse_timestamp(evaluation_time)
        if issued >= expires:
            raise AuthorityError("Grant expiry must be after not-before time")
        if evaluation < issued or evaluation >= expires:
            raise AuthorityError("Grant is not active at evaluation time")
        if grant_id not in ignore_revocation and self._revoked_at(grant_id, evaluation):
            raise AuthorityError("Grant is revoked at evaluation time")
        nonce = grant.get("nonce")
        nonce_contract = grant_contract["nonce"]
        if (
            not isinstance(nonce, str)
            or not nonce_contract["min_length"]
            <= len(nonce)
            <= nonce_contract["max_length"]
            or re.fullmatch(nonce_contract["pattern"], nonce) is None
        ):
            raise AuthorityError("invalid Grant nonce")
        proofs = grant.get("trust_proofs")
        if (
            not isinstance(proofs, list)
            or not grant_contract["trust_proofs_min"]
            <= len(proofs)
            <= grant_contract["trust_proofs_max"]
            or any(not isinstance(proof, Mapping) for proof in proofs)
        ):
            raise AuthorityError("Grant requires trust proofs")
        if (
            grant_contract["trust_proofs_unique"]
            and len({canonical_digest(proof) for proof in proofs}) != len(proofs)
        ):
            raise AuthorityError("Grant trust proofs must be unique and bounded")
        kinds = {proof.get("kind") for proof in proofs}
        if not kinds <= set(proof_contracts):
            raise AuthorityError("unknown Grant trust proof kind")

        if kinds == {"local-root"}:
            if len(proofs) != 1 or self._authority_init["trust_mode"] != "local-owner":
                raise AuthorityError("invalid local-root proof set")
            proof = proofs[0]
            if set(proof) != set(
                proof_contracts["local-root"]["required_fields"]
            ):
                raise AuthorityError("invalid local-root proof shape")
            root = self._root(proof.get("root_subject_id"))
            if (
                root is None
                or grant["subject_id"] != root["subject_id"]
                or proof.get("authority_init_digest")
                != canonical_digest(self._authority_init)
                or proof.get("signed_claim_digest") != expected_claim
                or capability != "authority.manage"
                or capability not in root["capability_ceiling"]
                or not self._scope_is_subset(
                    scope,
                    root["scope"],
                    requested_scope_role="grant",
                    allowed_scope_role="grant",
                )
            ):
                raise AuthorityError("Grant exceeds configured-root bootstrap")
            if any(
                item["capability_id"] == "authority.manage"
                and {p["kind"] for p in item["trust_proofs"]} == {"local-root"}
                for item in self._grants.values()
                if item["grant_id"] != grant_id
            ):
                raise AuthorityError("configured-root bootstrap is one-time")
            return set(root["capability_ceiling"]), 0

        if kinds == {"issuer-grant"}:
            if len(proofs) != 1:
                raise AuthorityError("issuer proof must be singular")
            proof = proofs[0]
            if set(proof) != set(
                proof_contracts["issuer-grant"]["required_fields"]
            ):
                raise AuthorityError("invalid issuer proof shape")
            if proof.get("signed_claim_digest") != expected_claim:
                raise AuthorityError("issuer proof does not bind the exact claim")
            issuer = self._grants.get(proof.get("issuer_grant_id"))
            if issuer is None:
                raise AuthorityError("issuer Grant is unresolved")
            if proof.get("issuer_signed_claim_digest") != issuer.get("claim_digest"):
                raise AuthorityError("issuer proof does not bind the exact issuer claim")
            ceiling, depth = self._validate_grant(
                issuer,
                evaluation_time,
                seen=seen | {grant_id},
                ignore_revocation=ignore_revocation,
            )
            if depth >= self.max_delegation_depth:
                raise AuthorityError("Grant delegation depth exceeded")
            if issuer["capability_id"] != "authority.manage":
                raise AuthorityError("issuer lacks authority.manage")
            if capability not in ceiling:
                raise AuthorityError("delegated capability exceeds root ceiling")
            if not self._scope_is_subset(
                scope,
                issuer["scope"],
                requested_scope_role="grant",
                allowed_scope_role="grant",
            ):
                raise AuthorityError("delegated scope exceeds issuer scope")
            if issued < parse_timestamp(issuer["issued_at"]) or expires > parse_timestamp(
                issuer["expires_at"]
            ):
                raise AuthorityError("delegated interval exceeds issuer interval")
            return ceiling, depth + 1

        if kinds == {"signature"}:
            if self._authority_init["trust_mode"] != "team-signed":
                raise AuthorityError("signature proofs require team trust mode")
            used = self._verified_signature_keys(proofs, expected_claim)
            policy = self._authority_init["team_policy"]
            if len(used & set(policy["key_ids"])) < policy["threshold"]:
                raise AuthorityError("Grant lacks verified signature threshold")
            ceiling = set().union(
                *(set(root["capability_ceiling"]) for root in self._authority_init["roots"])
            )
            if capability not in ceiling:
                raise AuthorityError("signed Grant exceeds configured root ceilings")
            if not any(
                self._scope_is_subset(
                    scope,
                    root["scope"],
                    requested_scope_role="grant",
                    allowed_scope_role="grant",
                )
                for root in self._authority_init["roots"]
                if capability in root["capability_ceiling"]
            ):
                raise AuthorityError("signed Grant exceeds configured root scopes")
            return ceiling, 0

        raise AuthorityError("mixed or unsupported Grant trust proofs")

    def _scope_overlap_for_sod(
        self,
        left: Iterable[Mapping[str, Any]],
        right: Iterable[Mapping[str, Any]],
        scope_kind: str,
    ) -> bool:
        left_keys = set(self._scope_keys_for(left, scope_role="grant"))
        right_keys = set(self._scope_keys_for(right, scope_role="grant"))
        project_kind = self._runtime_policy["scope_contract"]["project_selector"][
            "kind"
        ]
        left_projects = {
            value for kind, value in left_keys if kind == project_kind
        }
        right_projects = {
            value for kind, value in right_keys if kind == project_kind
        }
        if left_projects and right_projects and left_projects != right_projects:
            return False
        left_targets = {value for kind, value in left_keys if kind == scope_kind}
        right_targets = {value for kind, value in right_keys if kind == scope_kind}
        return not (
            left_targets and right_targets and left_targets.isdisjoint(right_targets)
        )

    @staticmethod
    def _grant_intervals_overlap(
        left: Mapping[str, Any],
        right: Mapping[str, Any],
        left_revocation: Mapping[str, Any] | None,
    ) -> bool:
        left_start = parse_timestamp(left["issued_at"])
        left_end = parse_timestamp(left["expires_at"])
        if left_revocation is not None:
            left_end = min(left_end, parse_timestamp(left_revocation["revoked_at"]))
        right_start = parse_timestamp(right["issued_at"])
        right_end = parse_timestamp(right["expires_at"])
        return max(left_start, right_start) < min(left_end, right_end)

    def _sod_rule_fields(self, rule: Mapping[str, Any]) -> tuple[str, ...]:
        base_fields = set(
            self._runtime_policy["separation_of_duties_contract"]["base_fields"]
        )
        return tuple(field for field in rule if field not in base_fields)

    @staticmethod
    def _grant_signature_keys(grant: Mapping[str, Any]) -> frozenset[str]:
        return frozenset(
            proof["key_id"]
            for proof in grant.get("trust_proofs", [])
            if isinstance(proof, Mapping)
            and proof.get("kind") == "signature"
            and isinstance(proof.get("key_id"), str)
        )

    def _assert_grant_separation_of_duties(
        self, grant: Mapping[str, Any]
    ) -> None:
        for rule in self._separation_of_duties:
            for field in self._sod_rule_fields(rule):
                capabilities = rule[field]
                if grant.get("capability_id") not in capabilities:
                    continue
                conflicts = set(capabilities) - {grant["capability_id"]}
                if field == "forbid_lease_derived_capabilities":
                    # GrantTrustProof has no lease-derived proof kind; validation
                    # above keeps this rule structurally enforced by default deny.
                    continue
                if field == "forbid_same_subject_for_same_candidate":
                    scope_kind = "candidate"
                    identity_matches = lambda existing: (
                        existing["subject_id"] == grant.get("subject_id")
                    )
                elif field == "forbid_same_subject_for_same_finding":
                    scope_kind = "finding"
                    identity_matches = lambda existing: (
                        existing["subject_id"] == grant.get("subject_id")
                    )
                elif field == "forbid_same_key_capabilities":
                    scope_kind = "candidate"
                    grant_keys = self._grant_signature_keys(grant)
                    identity_matches = lambda existing: bool(
                        grant_keys & self._grant_signature_keys(existing)
                    )
                else:
                    raise AuthorityError("authority SOD runtime dispatcher mismatch")
                for existing in self._grants.values():
                    if (
                        identity_matches(existing)
                        and existing["capability_id"] in conflicts
                        and self._grant_intervals_overlap(
                            existing,
                            grant,
                            self._revocations.get(existing["grant_id"]),
                        )
                        and self._scope_overlap_for_sod(
                            existing["scope"], grant.get("scope", []), scope_kind
                        )
                    ):
                        raise AuthorityError(
                            f"{scope_kind} separation-of-duties Grant conflict"
                        )

    def issue_grant(
        self,
        grant: Mapping[str, Any],
        evaluation_time: str,
        *,
        issue_authorization: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Validate and persist one immutable Grant."""

        self._ensure_mutable()
        self._validate_grant_issue_authorization(
            grant, evaluation_time, issue_authorization
        )
        grant_id = grant.get("grant_id")
        existing = self._grants.get(grant_id)
        if existing is not None:
            if canonical_digest(existing) == canonical_digest(grant):
                self._grant_issue_authorizations.pop(
                    issue_authorization["authorization_digest"], None
                )
                return deepcopy(existing)
            raise AuthorityError("Grant ID already identifies a different claim")
        nonce = grant.get("nonce")
        prior = self._nonces.get(nonce)
        if prior is not None:
            raise AuthorityError(f"Grant nonce already used by {prior}")
        self._validate_grant(grant, evaluation_time)
        self._assert_grant_separation_of_duties(grant)
        stored = deepcopy(dict(grant))
        self._grants[stored["grant_id"]] = stored
        self._nonces[stored["nonce"]] = stored["grant_id"]
        self._grant_issue_authorizations.pop(
            issue_authorization["authorization_digest"], None
        )
        return deepcopy(stored)

    def authorize(
        self,
        subject_id: str,
        capability_id: str,
        requested_scope: Iterable[Mapping[str, Any]],
        grant_id: str,
        claim_digest: str,
        evaluation_time: str,
        *,
        candidate_digest: str | None = None,
        finding_id: str | None = None,
        replay: bool = False,
    ) -> dict[str, Any]:
        """Resolve one exact Grant claim for one subject/capability/scope."""

        grant = self._grants.get(grant_id)
        if grant is None:
            raise AuthorityError("authorization Grant is unresolved")
        if grant["claim_digest"] != claim_digest:
            raise AuthorityError("authorization does not bind the exact Grant claim")
        evaluation = self._check_evaluation_time(evaluation_time, replay=replay)
        self._validate_grant(grant, evaluation_time)
        if grant["subject_id"] != subject_id:
            raise AuthorityError("authorization subject mismatch")
        if grant["capability_id"] != capability_id:
            raise AuthorityError("authorization capability mismatch")
        requested = list(requested_scope)
        if not self._scope_is_subset(
            requested,
            grant["scope"],
            requested_scope_role="requested",
            allowed_scope_role="grant",
        ):
            raise AuthorityError("requested scope exceeds Grant scope")
        self.assert_separation_of_duties(
            subject_id,
            capability_id,
            candidate_digest=candidate_digest,
            finding_id=finding_id,
        )
        self._record_evaluation_time(evaluation, replay=replay)
        return deepcopy(grant)

    def grant_revocation_state_digest(self, grant_id: str) -> str:
        """Bind a bearer to the current revocation state of one exact Grant."""

        grant = self._grants.get(grant_id)
        if grant is None:
            raise AuthorityError("authorization Grant is unresolved")
        return canonical_digest(
            {
                "record_type": "GrantRevocationState",
                "activation_digest": self.activation_digest,
                "grant_id": grant_id,
                "claim_digest": grant["claim_digest"],
                "revocation": deepcopy(self._revocations.get(grant_id)),
            }
        )

    def authorize_current_access(
        self,
        authorization: Mapping[str, Any],
        capability_id: str,
        requested_scope: Iterable[Mapping[str, Any]],
        activation_digest: str,
        *,
        candidate_digest: str | None = None,
        finding_id: str | None = None,
        replay: bool = False,
    ) -> dict[str, Any]:
        """Resolve a read/resume request against one current exact Grant claim.

        The explicit Activation field prevents a valid Grant from being reused
        across activations.  The receipt gives continuation-token code a stable
        revocation binding without exposing mutable engine internals.
        """

        fields = {
            "subject_id",
            "grant_id",
            "claim_digest",
            "evaluated_at",
            "activation_digest",
        }
        if not isinstance(authorization, Mapping) or set(authorization) != fields:
            raise AuthorityError("current access authorization has an invalid shape")
        if activation_digest != self.activation_digest:
            raise AuthorityError("current access Activation mismatch")
        if authorization.get("activation_digest") != activation_digest:
            raise AuthorityError("current access authorization Activation mismatch")
        try:
            requested = deepcopy(list(requested_scope))
        except TypeError as exc:
            raise AuthorityError("current access requested scope is not iterable") from exc
        if any(not isinstance(selector, Mapping) for selector in requested):
            raise AuthorityError("current access requested scope contains a non-object")
        grant = self.authorize(
            authorization.get("subject_id"),
            capability_id,
            requested,
            authorization.get("grant_id"),
            authorization.get("claim_digest"),
            authorization.get("evaluated_at"),
            candidate_digest=candidate_digest,
            finding_id=finding_id,
            replay=replay,
        )
        return {
            "record_type": "CurrentAccessAuthorization",
            "subject_id": grant["subject_id"],
            "grant_id": grant["grant_id"],
            "claim_digest": grant["claim_digest"],
            "capability_id": capability_id,
            "activation_digest": activation_digest,
            "evaluated_at": authorization["evaluated_at"],
            "requested_scope": requested,
            "revocation_state_digest": self.grant_revocation_state_digest(
                grant["grant_id"]
            ),
            "grant": grant,
        }

    def _validate_stored_decision_binding(
        self,
        binding: Mapping[str, Any],
        *,
        decision_id: str,
        grant_id: str,
        revoked_at: str,
    ) -> None:
        manager = (
            self._grants.get(binding.get("authorizing_grant_id"))
            if isinstance(binding, Mapping)
            else None
        )
        if (
            not isinstance(binding, Mapping)
            or set(binding) != _STORED_DECISION_BINDING_FIELDS
            or binding.get("record_type") != "ImmutableDecisionEventBinding"
            or binding.get("decision_id") != decision_id
            or binding.get("target_grant_id") != grant_id
            or binding.get("activation_digest") != self.activation_digest
            or not _valid_digest(binding.get("decision_digest"))
            or not _valid_digest(binding.get("event_digest"))
            or not isinstance(binding.get("authorizing_grant_id"), str)
            or not binding["authorizing_grant_id"]
            or not _valid_digest(binding.get("authorizing_claim_digest"))
            or not isinstance(binding.get("subject_id"), str)
            or not binding["subject_id"]
            or not isinstance(binding.get("event_id"), str)
            or not binding["event_id"]
            or manager is None
            or manager.get("subject_id") != binding.get("subject_id")
            or manager.get("capability_id") != "authority.manage"
            or manager.get("claim_digest")
            != binding.get("authorizing_claim_digest")
        ):
            raise AuthorityError("Grant revocation decision binding is invalid")
        decided = parse_timestamp(binding.get("decided_at"))
        if decided > parse_timestamp(revoked_at):
            raise AuthorityError("Grant revocation precedes its Decision")

    def _resolve_revocation_decision(
        self,
        decision_id: str,
        grant_id: str,
        reason: str,
        revoked_at: str,
        *,
        authorizing_grant_id: str,
        subject_id: str,
    ) -> dict[str, Any]:
        if self.decision_resolver is None:
            raise AuthorityError("Grant revocation Decision is unresolved")
        try:
            resolved = self.decision_resolver(decision_id)
        except Exception as exc:
            raise AuthorityError("Grant revocation Decision resolver failed closed") from exc
        if not isinstance(resolved, Mapping) or set(resolved) != {"decision", "event"}:
            raise AuthorityError("Grant revocation Decision is unresolved")
        decision = resolved.get("decision")
        event = resolved.get("event")
        target = self._grants.get(grant_id)
        manager = self._grants.get(authorizing_grant_id)
        evidence_artifacts = (
            decision.get("evidence_artifacts")
            if isinstance(decision, Mapping)
            else None
        )
        if (
            not isinstance(decision, Mapping)
            or set(decision) != _REVOCATION_DECISION_FIELDS
            or decision.get("record_type") != "Decision"
            or decision.get("decision_id") != decision_id
            or decision.get("decision_kind") != "revoke"
            or decision.get("subject_id") != subject_id
            or decision.get("grant_id") != authorizing_grant_id
            or not _valid_digest(decision.get("grant_claim_digest"))
            or decision.get("target_type") != "Grant"
            or decision.get("target_id") != grant_id
            or decision.get("activation_digest") != self.activation_digest
            or target is None
            or decision.get("target_digest") != canonical_digest(target)
            or manager is None
            or manager.get("subject_id") != subject_id
            or manager.get("capability_id") != "authority.manage"
            or manager.get("claim_digest") != decision.get("grant_claim_digest")
            or not isinstance(decision.get("rationale"), str)
            or decision["rationale"] != reason
            or not isinstance(evidence_artifacts, list)
            or not evidence_artifacts
            or len(evidence_artifacts) > 64
            or any(
                not isinstance(reference, Mapping)
                or set(reference) != _ARTIFACT_REFERENCE_FIELDS
                or not isinstance(reference.get("artifact_id"), str)
                or not reference["artifact_id"]
                or not _valid_digest(reference.get("artifact_record_digest"))
                for reference in evidence_artifacts
            )
            or len(
                {
                    (
                        reference["artifact_id"],
                        reference["artifact_record_digest"],
                    )
                    for reference in evidence_artifacts
                }
            )
            != len(evidence_artifacts)
        ):
            raise AuthorityError("Grant revocation Decision target binding mismatch")
        decided_at = decision.get("created_at")
        if not isinstance(decided_at, str):
            raise AuthorityError("Grant revocation Decision lacks canonical time")
        self._validate_grant(
            manager,
            decided_at,
            ignore_revocation=(
                frozenset({grant_id})
                if manager.get("grant_id") == grant_id
                else frozenset()
            ),
        )
        if not self._scope_is_subset(
            target["scope"],
            manager["scope"],
            requested_scope_role="grant",
            allowed_scope_role="grant",
        ):
            raise AuthorityError("Grant revocation Decision scope omits its target")
        if (
            not isinstance(event, Mapping)
            or set(event)
            != {
                "record_type",
                "event_id",
                "event_kind",
                "activation_digest",
                "payload",
            }
            or event.get("record_type") != "Event"
            or event.get("event_kind") != "decision.recorded"
            or event.get("activation_digest") != self.activation_digest
            or event.get("payload") != dict(decision)
            or not isinstance(event.get("event_id"), str)
            or not event["event_id"]
        ):
            raise AuthorityError("Grant revocation Decision Event binding mismatch")
        binding = {
            "record_type": "ImmutableDecisionEventBinding",
            "decision_id": decision_id,
            "decision_digest": canonical_digest(decision),
            "event_id": event["event_id"],
            "event_digest": canonical_digest(event),
            "activation_digest": self.activation_digest,
            "target_grant_id": grant_id,
            "authorizing_grant_id": authorizing_grant_id,
            "authorizing_claim_digest": manager["claim_digest"],
            "subject_id": subject_id,
            "decided_at": decided_at,
        }
        self._validate_stored_decision_binding(
            binding,
            decision_id=decision_id,
            grant_id=grant_id,
            revoked_at=revoked_at,
        )
        return binding

    def revoke_grant(
        self,
        revocation: Mapping[str, Any],
        authorizing_grant_id: str,
        subject_id: str,
    ) -> dict[str, Any]:
        """Record a time-effective revocation authorized by authority.manage."""

        self._ensure_mutable()
        required = {"grant_id", "reason", "revoked_at"}
        if (
            not isinstance(revocation, Mapping)
            or set(revocation) != required | {"decision_id"}
            or not revocation.get("reason")
            or not isinstance(revocation.get("decision_id"), str)
            or not revocation.get("decision_id")
        ):
            raise AuthorityError("invalid Grant revocation shape")
        target = self._grants.get(revocation.get("grant_id"))
        if target is None:
            raise AuthorityError("cannot revoke an unresolved Grant")
        manager = self._grants.get(authorizing_grant_id)
        if manager is None:
            raise AuthorityError("revocation authority Grant is unresolved")
        at = revocation["revoked_at"]
        self.authorize(
            subject_id,
            "authority.manage",
            target["scope"],
            authorizing_grant_id,
            manager["claim_digest"],
            at,
        )
        decision_id = revocation["decision_id"]
        decision_binding = self._resolve_revocation_decision(
            decision_id,
            target["grant_id"],
            revocation["reason"],
            revocation["revoked_at"],
            authorizing_grant_id=authorizing_grant_id,
            subject_id=subject_id,
        )
        stored = {
            "grant_id": target["grant_id"],
            "decision_id": decision_id,
            "decision_binding": decision_binding,
            "reason": revocation["reason"],
            "revoked_at": revocation["revoked_at"],
        }
        prior = self._revocations.get(target["grant_id"])
        if prior is not None:
            if canonical_digest(prior) == canonical_digest(stored):
                return deepcopy(prior)
            raise AuthorityError("Grant already has a different revocation")
        self._revocations[target["grant_id"]] = stored
        return deepcopy(stored)

    def assert_separation_of_duties(
        self,
        subject_id: str,
        capability_id: str,
        *,
        candidate_digest: str | None = None,
        finding_id: str | None = None,
    ) -> None:
        for rule in self._separation_of_duties:
            for field in self._sod_rule_fields(rule):
                capabilities = rule[field]
                if capability_id not in capabilities:
                    continue
                conflicts = set(capabilities) - {capability_id}
                if field == "forbid_same_subject_for_same_candidate":
                    identity = candidate_digest
                    actions = self._candidate_actions
                    label = "candidate"
                elif field == "forbid_same_subject_for_same_finding":
                    identity = finding_id
                    actions = self._finding_actions
                    label = "finding"
                elif field in {
                    "forbid_lease_derived_capabilities",
                    "forbid_same_key_capabilities",
                }:
                    # Lease derivation is not an AuthorityEngine input and key SOD
                    # is enforced at signed Grant issue / external release authority.
                    continue
                else:
                    raise AuthorityError("authority SOD runtime dispatcher mismatch")
                if identity is None:
                    continue
                prior_subjects = set().union(
                    *(
                        {
                            action["subject_id"]
                            for action in actions.get((identity, conflict), ())
                        }
                        for conflict in conflicts
                    )
                )
                if subject_id in prior_subjects:
                    raise AuthorityError(f"{label} separation-of-duties violation")

    def record_action(
        self,
        subject_id: str,
        capability_id: str,
        *,
        authorization: Mapping[str, Any],
        candidate_digest: str | None = None,
        finding_id: str | None = None,
    ) -> None:
        """Record an already committed action with its exact Grant provenance."""

        self._ensure_mutable()
        if (
            not isinstance(authorization, Mapping)
            or set(authorization) != _ACTION_AUTHORIZATION_FIELDS
            or authorization.get("subject_id") != subject_id
            or authorization.get("grant_id") is None
            or authorization.get("claim_digest") is None
        ):
            raise AuthorityError("action authorization has an invalid exact shape")
        if (
            (candidate_digest is None and finding_id is None)
            or (candidate_digest is not None and not _valid_digest(candidate_digest))
            or (
                finding_id is not None
                and (not isinstance(finding_id, str) or not finding_id)
            )
        ):
            raise AuthorityError("action provenance target is invalid")
        requested_scope = authorization.get("requested_scope")
        if (
            not isinstance(requested_scope, list)
            or not requested_scope
            or any(not isinstance(selector, Mapping) for selector in requested_scope)
        ):
            raise AuthorityError("action authorization requested scope is invalid")
        grant = self.authorize(
            subject_id,
            capability_id,
            requested_scope,
            authorization["grant_id"],
            authorization["claim_digest"],
            authorization["evaluated_at"],
            candidate_digest=candidate_digest,
            finding_id=finding_id,
        )
        targets = (
            ("candidate", candidate_digest, self._candidate_actions),
            ("finding", finding_id, self._finding_actions),
        )
        for target_kind, target_id, actions in targets:
            if target_id is None:
                continue
            provenance = {
                "record_type": "AuthorityActionProvenance",
                "target_kind": target_kind,
                "target_id": target_id,
                "subject_id": subject_id,
                "grant_id": grant["grant_id"],
                "grant_claim_digest": grant["claim_digest"],
                "evaluated_at": authorization["evaluated_at"],
                "activation_digest": self.activation_digest,
                "capability_id": capability_id,
                "effect_scope": deepcopy(requested_scope),
            }
            action_key = (target_id, capability_id)
            prior = actions.get(action_key, ())
            if any(canonical_digest(item) == canonical_digest(provenance) for item in prior):
                continue
            actions[action_key] = (*prior, provenance)
