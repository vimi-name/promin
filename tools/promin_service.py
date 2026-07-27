"""Import-only validation helpers for the installed Promin service."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
if str(PACKAGE_ROOT) in sys.path:
    sys.path.remove(str(PACKAGE_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT))

from promin.init import ActivationGuard
from promin.service import ProminService, ServiceError


def activation(root: Path | str) -> dict[str, Any]:
    context = ActivationGuard(Path(root).resolve()).verify()
    value = getattr(context, "activation", None)
    if not isinstance(value, dict):
        raise ServiceError("ActivationGuard returned no Activation record")
    return value


def validate_grant(
    root: Path | str,
    grant_id: str,
    subject: str,
    capability: str,
    scope: list[dict[str, str]],
    at_time: str,
    replay: bool = False,
) -> dict[str, Any]:
    service = ProminService(root)
    context = service._context()
    store = service._event_store(context)
    authority, _ = service._runtime_state(context, store)
    grant = authority.grants.get(grant_id)
    if not isinstance(grant, dict):
        raise ServiceError("Grant does not exist")
    authority.authorize(
        subject,
        capability,
        scope,
        grant_id,
        grant["claim_digest"],
        at_time,
        replay=replay,
    )
    return dict(grant)


__all__ = [
    "ServiceError",
    "activation",
    "validate_grant",
]
