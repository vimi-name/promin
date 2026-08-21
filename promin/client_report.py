from __future__ import annotations

import json
from collections.abc import Mapping

from .product_inspection import serialize_product_inspection


class ClientReportError(ValueError):
    """Raised when an inspection cannot produce a safe client report."""


def report_from_inspection(report: Mapping[str, object]) -> dict[str, object]:
    """Derive a non-crediting client report from one strict inspection record."""

    if not isinstance(report, Mapping):
        raise ClientReportError("inspection report must be an object")
    claims = report.get("claims")
    if not isinstance(claims, Mapping) or any(value is not False for value in claims.values()):
        raise ClientReportError("inspection report carries promoted claims")
    try:
        client = json.loads(serialize_product_inspection(report, audience="client"))
    except (TypeError, ValueError) as exc:
        raise ClientReportError(str(exc)) from exc
    return {
        "schema": "promin.client-report.v1",
        "record_type": "ProminClientReport",
        "inspection": client,
        "claims": {str(key): False for key in claims},
    }


__all__ = ["ClientReportError", "report_from_inspection"]
