from __future__ import annotations

import copy
from pathlib import Path

import pytest

from promin.autonomy_policy import (
    AutonomyPolicyError,
    classify_standing_action,
    load_autonomy_policy,
    validate_autonomy_policy,
)


_ASSET_PATH = Path(__file__).resolve().parents[1] / "capability_profiles" / "standing-reversible.json"


def _policy() -> dict[str, object]:
    return load_autonomy_policy(_ASSET_PATH)


def test_reversible_action_is_classified_but_receives_no_authority_or_credit() -> None:
    decision = classify_standing_action(
        _policy(),
        {
            "action_id": "update-portable-summary",
            "action_class": "project-mutation",
            "reversible": True,
            "affects_user_owned_data": True,
            "recoverable_backup": True,
            "external_effect": False,
        },
    )
    assert decision["status"] == "STANDING_ALLOWED"
    assert decision["owner_decision_required"] is False
    assert decision["requires_current_authorization"] is True
    assert decision["authority_granted"] is False
    assert decision["pass_credit"] is False
    assert decision["acceptance_pass"] is False


def test_owner_only_and_unbacked_destructive_actions_fail_closed() -> None:
    public = classify_standing_action(
        _policy(),
        {
            "action_id": "publish-package",
            "action_class": "remote-publication",
            "reversible": True,
            "affects_user_owned_data": False,
            "recoverable_backup": False,
            "external_effect": True,
        },
    )
    assert public["status"] == "OWNER_DECISION_REQUIRED"
    assert public["reason_code"] == "owner-only-action-class"

    destructive = classify_standing_action(
        _policy(),
        {
            "action_id": "replace-user-file",
            "action_class": "project-mutation",
            "reversible": False,
            "affects_user_owned_data": True,
            "recoverable_backup": False,
            "external_effect": False,
        },
    )
    assert destructive["status"] == "OWNER_DECISION_REQUIRED"
    assert destructive["reason_code"] == "not-reversible-or-not-backed-up"

    unknown = classify_standing_action(
        _policy(),
        {
            "action_id": "unknown-operation",
            "action_class": "unclassified",
            "reversible": True,
            "affects_user_owned_data": False,
            "recoverable_backup": False,
            "external_effect": False,
        },
    )
    assert unknown["status"] == "OWNER_DECISION_REQUIRED"
    assert unknown["reason_code"] == "unclassified-action"


def test_policy_cannot_claim_authority_or_admit_owner_only_class() -> None:
    policy = copy.deepcopy(_policy())
    policy["authority_effect"] = "grant"
    with pytest.raises(AutonomyPolicyError, match="authority_effect"):
        validate_autonomy_policy(policy)

    policy = copy.deepcopy(_policy())
    policy["standing_action_classes"].append("remote-publication")
    with pytest.raises(AutonomyPolicyError, match="owner-only"):
        validate_autonomy_policy(policy)
