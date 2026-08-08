from __future__ import annotations

import pytest

from promin.dynamic_handoff import (
    DynamicHandoffError,
    dynamic_handoff_receipt,
    validate_dynamic_handoff,
)


def _contract() -> dict[str, object]:
    return {
        "id": "render-evidence",
        "status": "PENDING_DYNAMIC",
        "allowed_write_scope": ["artifacts/render/**"],
        "forbidden": ["synthetic-pass-credit", "direct-projection-edit"],
        "required_evidence": ["captured-render", "bound-runtime-receipt"],
        "acceptance_predicate": "A real render route produces the bound evidence.",
        "invalidation_class": "IMPORT_SURFACE",
        "stop_conditions": ["source identity changes", "required evidence is unavailable"],
    }


def test_dynamic_handoff_is_pending_only_and_non_promoting() -> None:
    contract = validate_dynamic_handoff(_contract())
    receipt = dynamic_handoff_receipt(contract)

    assert contract["status"] == "PENDING_DYNAMIC"
    assert receipt["status"] == "PENDING_DYNAMIC"
    assert receipt["promotion_allowed"] is False
    assert receipt["acceptance_pass"] is False
    assert receipt["pass_credit"] is False
    assert receipt["product_acceptance_pass"] is False
    assert len(receipt["contract_digest"]) == 64


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("status", "PASS", "PENDING_DYNAMIC"),
        ("invalidation_class", "GIT_HEAD", "invalidation"),
        ("allowed_write_scope", ["../escape/**"], "safe relative"),
        ("forbidden", [], "non-empty"),
    ],
)
def test_dynamic_handoff_rejects_promotion_and_unsafe_contracts(
    field: str, value: object, message: str
) -> None:
    candidate = _contract()
    candidate[field] = value

    with pytest.raises(DynamicHandoffError, match=message):
        validate_dynamic_handoff(candidate)


def test_dynamic_handoff_rejects_unknown_promotion_claims() -> None:
    candidate = _contract() | {"acceptance_pass": True}

    with pytest.raises(DynamicHandoffError, match="exactly"):
        validate_dynamic_handoff(candidate)
