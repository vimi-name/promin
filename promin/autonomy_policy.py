"""Non-authoritative standing reversible-action classification.

This module intentionally does not issue a Grant, acquire a Lease, or execute a
mutation.  It supplies the extra policy predicate that an integrator can require
*in addition to* the authoritative Core authorization path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .canonical import digest_value


class AutonomyPolicyError(ValueError):
    """Raised for malformed policy or action classification input."""


AUTONOMY_POLICY_SCHEMA = "promin.standing-autonomy-policy.v1"


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AutonomyPolicyError(f"{label} must be an object")
    return dict(value)


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise AutonomyPolicyError(f"{label} must be a non-empty bounded identifier")
    if any(character in value for character in "\\/\r\n\t"):
        raise AutonomyPolicyError(f"{label} must not be a path")
    return value


def _id_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise AutonomyPolicyError(f"{label} must be a non-empty array")
    result = [_id(item, f"{label} item") for item in value]
    if len(result) != len(set(result)):
        raise AutonomyPolicyError(f"{label} contains duplicates")
    return result


def validate_autonomy_policy(value: object) -> dict[str, Any]:
    """Validate a policy that can classify but never widen Core authority."""

    policy = _mapping(value, "autonomy policy")
    expected = {
        "schema",
        "policy_id",
        "authority_effect",
        "standing_action_classes",
        "owner_only_action_classes",
        "require_current_authorization",
        "owner_only_decision",
    }
    if set(policy) != expected:
        raise AutonomyPolicyError("autonomy policy has an unsupported field set")
    if policy["schema"] != AUTONOMY_POLICY_SCHEMA:
        raise AutonomyPolicyError("autonomy policy schema is invalid")
    if policy["authority_effect"] != "none":
        raise AutonomyPolicyError("authority_effect must be none")
    if policy["require_current_authorization"] is not True:
        raise AutonomyPolicyError("standing autonomy must require current authorization")
    if policy["owner_only_decision"] != "explicit-owner-decision-required":
        raise AutonomyPolicyError("owner-only decision contract is invalid")
    standing = _id_list(policy["standing_action_classes"], "standing_action_classes")
    owner_only = _id_list(policy["owner_only_action_classes"], "owner_only_action_classes")
    overlap = sorted(set(standing) & set(owner_only))
    if overlap:
        raise AutonomyPolicyError("owner-only action class cannot be standing-reversible")
    return {
        "schema": AUTONOMY_POLICY_SCHEMA,
        "policy_id": _id(policy["policy_id"], "policy_id"),
        "authority_effect": "none",
        "standing_action_classes": standing,
        "owner_only_action_classes": owner_only,
        "require_current_authorization": True,
        "owner_only_decision": "explicit-owner-decision-required",
    }


def load_autonomy_policy(path: Path | str) -> dict[str, Any]:
    """Load a portable policy without executing or authorizing any operation."""

    candidate = Path(path)
    try:
        with candidate.open("r", encoding="utf-8", newline="") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AutonomyPolicyError(f"autonomy policy cannot be loaded: {candidate}") from exc
    return validate_autonomy_policy(value)


def _action(value: object) -> dict[str, Any]:
    action = _mapping(value, "action")
    expected = {
        "action_id",
        "action_class",
        "reversible",
        "affects_user_owned_data",
        "recoverable_backup",
        "external_effect",
    }
    if set(action) != expected:
        raise AutonomyPolicyError("action has an unsupported field set")
    for name in (
        "reversible",
        "affects_user_owned_data",
        "recoverable_backup",
        "external_effect",
    ):
        if not isinstance(action[name], bool):
            raise AutonomyPolicyError(f"action {name} must be boolean")
    return {
        "action_id": _id(action["action_id"], "action_id"),
        "action_class": _id(action["action_class"], "action_class"),
        "reversible": action["reversible"],
        "affects_user_owned_data": action["affects_user_owned_data"],
        "recoverable_backup": action["recoverable_backup"],
        "external_effect": action["external_effect"],
    }


def classify_standing_action(
    policy_value: Mapping[str, Any], action_value: Mapping[str, Any]
) -> dict[str, Any]:
    """Fail closed unless one action is explicitly reversible and in policy scope.

    A ``STANDING_ALLOWED`` result remains a classification.  Callers must still
    prove the normal Grant, Lease, Candidate, WorkCard, and effect-scope checks.
    """

    policy = validate_autonomy_policy(policy_value)
    action = _action(action_value)
    action_class = action["action_class"]
    reason: str | None = None
    if action_class in policy["owner_only_action_classes"]:
        reason = "owner-only-action-class"
    elif action["external_effect"]:
        reason = "external-effect"
    elif action_class not in policy["standing_action_classes"]:
        reason = "unclassified-action"
    elif not action["reversible"] or (
        action["affects_user_owned_data"] and not action["recoverable_backup"]
    ):
        reason = "not-reversible-or-not-backed-up"

    identity = {
        "record_type": "StandingAutonomyDecision",
        "schema": "promin.standing-autonomy-decision.v1",
        "policy_id": policy["policy_id"],
        "policy_digest": digest_value(policy),
        "action_id": action["action_id"],
        "action_class": action_class,
        "status": "STANDING_ALLOWED" if reason is None else "OWNER_DECISION_REQUIRED",
        "reason_code": reason,
        "owner_decision_required": reason is not None,
        "requires_current_authorization": True,
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
    }
    return {**identity, "decision_digest": digest_value(identity)}
