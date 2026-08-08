"""Typed, non-promoting handoff records for work that needs a live host.

The static admission route may describe a future dynamic validation, but it may
not run it or infer its result.  This module intentionally contains only pure
validation and canonical serialization helpers; it has no provider, process,
runtime, or database boundary.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import json
import re


class DynamicHandoffError(ValueError):
    """Raised when a dynamic handoff does not remain safely pending."""


HANDOFF_SCHEMA = "promin.dynamic-handoff.v1"
RECEIPT_SCHEMA = "promin.dynamic-handoff-receipt.v1"
PENDING_DYNAMIC = "PENDING_DYNAMIC"

_REQUIRED_FIELDS = frozenset(
    {
        "id",
        "status",
        "allowed_write_scope",
        "forbidden",
        "required_evidence",
        "acceptance_predicate",
        "invalidation_class",
        "stop_conditions",
    }
)
_INVALIDATION_CLASSES = frozenset(
    {
        "BODY_ONLY",
        "IMPORT_SURFACE",
        "CMAKE_TOPOLOGY",
        "TOOLING_ONLY",
    }
)
_HANDOFF_ID = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _require_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise DynamicHandoffError(f"{label} must be a mapping")
    if any(not isinstance(key, str) for key in value):
        raise DynamicHandoffError(f"{label} keys must be strings")
    return value


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise DynamicHandoffError(f"{label} must be a string")
    if not value or value != value.strip() or "\x00" in value:
        raise DynamicHandoffError(f"{label} must be a non-empty trimmed string")
    return value


def _require_text_list(value: object, label: str) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise DynamicHandoffError(f"{label} must be a non-empty string list")
    normalized = [_require_text(item, f"{label}[{index}]") for index, item in enumerate(value)]
    if not normalized:
        raise DynamicHandoffError(f"{label} must be non-empty")
    if len(set(normalized)) != len(normalized):
        raise DynamicHandoffError(f"{label} must not contain duplicates")
    return normalized


def _validate_scope(scope: str) -> str:
    if "\\" in scope or scope.startswith("/") or ":" in scope:
        raise DynamicHandoffError("allowed_write_scope entries must be safe relative paths")
    pieces = scope.split("/")
    if (
        not pieces
        or any(piece in {"", ".", ".."} for piece in pieces)
        or all(set(piece) <= {"*", "?", "[", "]", "!"} for piece in pieces)
    ):
        raise DynamicHandoffError("allowed_write_scope entries must be safe relative paths")
    return scope


def validate_dynamic_handoff(contract: Mapping[str, object]) -> dict[str, object]:
    """Validate and normalize an exact dynamic contract without executing it.

    The exact field set is deliberate: promotion fields such as
    ``acceptance_pass`` cannot be smuggled into a pending contract.
    """

    candidate = _require_mapping(contract, "dynamic handoff")
    actual_fields = frozenset(candidate)
    if actual_fields != _REQUIRED_FIELDS:
        missing = sorted(_REQUIRED_FIELDS - actual_fields)
        unexpected = sorted(actual_fields - _REQUIRED_FIELDS)
        detail: list[str] = []
        if missing:
            detail.append(f"missing={missing}")
        if unexpected:
            detail.append(f"unexpected={unexpected}")
        joined = "; ".join(detail) or "field mismatch"
        raise DynamicHandoffError(f"dynamic handoff fields must be exactly required fields ({joined})")

    handoff_id = _require_text(candidate["id"], "id")
    if not _HANDOFF_ID.fullmatch(handoff_id):
        raise DynamicHandoffError("id must be a lowercase, hyphenated identifier")

    status = _require_text(candidate["status"], "status")
    if status != PENDING_DYNAMIC:
        raise DynamicHandoffError(f"status must be {PENDING_DYNAMIC}")

    scopes = _require_text_list(candidate["allowed_write_scope"], "allowed_write_scope")
    normalized_scopes = [_validate_scope(scope) for scope in scopes]
    forbidden = _require_text_list(candidate["forbidden"], "forbidden")
    evidence = _require_text_list(candidate["required_evidence"], "required_evidence")
    predicate = _require_text(candidate["acceptance_predicate"], "acceptance_predicate")
    invalidation_class = _require_text(candidate["invalidation_class"], "invalidation_class")
    if invalidation_class not in _INVALIDATION_CLASSES:
        choices = ", ".join(sorted(_INVALIDATION_CLASSES))
        raise DynamicHandoffError(f"invalidation_class must be one of: {choices}")
    stops = _require_text_list(candidate["stop_conditions"], "stop_conditions")

    return {
        "id": handoff_id,
        "status": PENDING_DYNAMIC,
        "allowed_write_scope": normalized_scopes,
        "forbidden": forbidden,
        "required_evidence": evidence,
        "acceptance_predicate": predicate,
        "invalidation_class": invalidation_class,
        "stop_conditions": stops,
    }


def dynamic_handoff_receipt(contract: Mapping[str, object]) -> dict[str, object]:
    """Return a deterministic receipt which documents pending work only.

    No result from a static route can promote this contract.  A future live
    validator must create separate evidence and evaluate its own predicate.
    """

    normalized = validate_dynamic_handoff(contract)
    digest = hashlib.sha256(_canonical_bytes(normalized)).hexdigest()
    return {
        "schema": RECEIPT_SCHEMA,
        "record_type": "DynamicHandoffReceipt",
        "id": normalized["id"],
        "status": PENDING_DYNAMIC,
        "contract_digest": digest,
        "allowed_write_scope": list(normalized["allowed_write_scope"]),
        "required_evidence": list(normalized["required_evidence"]),
        "invalidation_class": normalized["invalidation_class"],
        "promotion_allowed": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "pass_credit": False,
    }


__all__ = [
    "DynamicHandoffError",
    "HANDOFF_SCHEMA",
    "PENDING_DYNAMIC",
    "RECEIPT_SCHEMA",
    "dynamic_handoff_receipt",
    "validate_dynamic_handoff",
]
