"""Canonical portable projection for one bounded saturation query page chain."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from .canonical import digest_value


class SaturationQueryTraceError(ValueError):
    """Raised when a saturation query trace is missing or internally invalid."""


TRACE_FIELDS = frozenset(
    {
        "pages",
        "continuation_pages",
        "first_truncated",
        "initial_expiry",
        "expiry_monotonic",
        "renewal_count",
        "renewal_events",
        "maximum_token_bytes",
        "selected_closure_complete",
        "atoms",
        "atoms_count",
        "atoms_digest",
        "page_digests",
        "page_identity_digests",
        "identity_digests",
    }
)
_RENEWAL_FIELDS = frozenset({"cursor", "old_expiry", "new_expiry", "renewed_at"})


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise SaturationQueryTraceError(f"renewal {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SaturationQueryTraceError(f"renewal {label} is invalid") from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.utcoffset().total_seconds() != 0
        or parsed.microsecond != 0
        or parsed.isoformat(timespec="seconds").replace("+00:00", "Z") != value
    ):
        raise SaturationQueryTraceError(f"renewal {label} is not canonical UTC")
    return parsed


def _digest(value: Any, label: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(
        char not in "0123456789abcdef" for char in value
    ):
        raise SaturationQueryTraceError(f"{label} is not lowercase SHA-256")


def _integer(value: Any, label: str, *, minimum: int = 0) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise SaturationQueryTraceError(f"{label} is invalid")


def validate_saturation_query_trace(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != TRACE_FIELDS:
        raise SaturationQueryTraceError("saturation query trace shape is invalid")

    pages = value["pages"]
    continuation_pages = value["continuation_pages"]
    _integer(pages, "pages", minimum=1)
    _integer(continuation_pages, "continuation_pages")
    if continuation_pages != pages - 1:
        raise SaturationQueryTraceError("page counts are inconsistent")
    if not isinstance(value["first_truncated"], bool):
        raise SaturationQueryTraceError("first_truncated is invalid")
    if not value["first_truncated"] and continuation_pages != 0:
        raise SaturationQueryTraceError("first page truncation is inconsistent")
    if value["first_truncated"] and continuation_pages == 0:
        raise SaturationQueryTraceError("first page truncation has no continuation")
    if value["selected_closure_complete"] is not True:
        raise SaturationQueryTraceError("selected closure is incomplete")
    if value["expiry_monotonic"] is not True:
        raise SaturationQueryTraceError("renewal expiry is not monotonic")
    _integer(value["maximum_token_bytes"], "maximum_token_bytes")
    initial_expiry = value["initial_expiry"]
    if initial_expiry is None:
        if pages != 1:
            raise SaturationQueryTraceError("initial expiry is missing")
    else:
        if pages == 1:
            raise SaturationQueryTraceError("initial expiry is present for single page")
        _timestamp(initial_expiry, "initial_expiry")

    atoms = value["atoms"]
    if not isinstance(atoms, list) or any(not isinstance(item, str) or not item for item in atoms):
        raise SaturationQueryTraceError("atoms are not sorted and unique")
    if atoms != sorted(set(atoms)):
        raise SaturationQueryTraceError("atoms are not sorted and unique")
    _integer(value["atoms_count"], "atoms_count")
    if value["atoms_count"] != len(atoms) or value["atoms_digest"] != digest_value(atoms):
        raise SaturationQueryTraceError("atom count or digest is inconsistent")
    _digest(value["atoms_digest"], "atoms_digest")

    for field in ("page_digests", "page_identity_digests"):
        entries = value[field]
        if (
            not isinstance(entries, list)
            or len(entries) != pages
            or any(not isinstance(item, str) for item in entries)
            or any(
                len(item) != 64
                or any(char not in "0123456789abcdef" for char in item)
                for item in entries
                if isinstance(item, str)
            )
            or (field == "page_identity_digests" and len(set(entries)) != len(entries))
        ):
            raise SaturationQueryTraceError(f"{field} are inconsistent")
    identities = value["identity_digests"]
    if not isinstance(identities, list) or any(
        not isinstance(item, str) for item in identities
    ):
        raise SaturationQueryTraceError("identity digests are not sorted and unique")
    if len(identities) != len(atoms):
        raise SaturationQueryTraceError("identity digests do not match atom cardinality")
    if identities != sorted(set(identities)):
        raise SaturationQueryTraceError("identity digests are not sorted and unique")
    for item in identities:
        _digest(item, "identity digest")

    events = value["renewal_events"]
    _integer(value["renewal_count"], "renewal_count")
    if not isinstance(events, list) or value["renewal_count"] != len(events):
        raise SaturationQueryTraceError("renewal count is inconsistent")
    if value["renewal_count"] > continuation_pages:
        raise SaturationQueryTraceError("renewal count exceeds continuation pages")
    previous_cursor = -1
    for event in events:
        if not isinstance(event, Mapping) or set(event) != _RENEWAL_FIELDS:
            raise SaturationQueryTraceError("renewal event shape is invalid")
        _integer(event["cursor"], "renewal cursor")
        old = _timestamp(event["old_expiry"], "old expiry")
        new = _timestamp(event["new_expiry"], "new expiry")
        renewed = _timestamp(event["renewed_at"], "renewed at")
        if (
            event["cursor"] <= previous_cursor
            or renewed > old
            or new <= old
            or renewed > new
        ):
            raise SaturationQueryTraceError("renewal expiry facts are inconsistent")
        previous_cursor = event["cursor"]
    return dict(value)


def build_saturation_query_trace(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SaturationQueryTraceError("internal page chain is not a mapping")
    try:
        atoms = sorted(value["atoms"])
        renewals = value["renewals"]
        trace = {
            "pages": value["pages"],
            "continuation_pages": value["continuation_pages"],
            "first_truncated": value["first_truncated"],
            "initial_expiry": value["initial_expiry"],
            "expiry_monotonic": value["expiry_monotonic"],
            "renewal_count": len(renewals),
            "renewal_events": [
                {
                    "cursor": event["cursor"],
                    "old_expiry": event["old_expiry"],
                    "new_expiry": event["new_expiry"],
                    "renewed_at": event["renewed_at"],
                }
                for event in renewals
            ],
            "maximum_token_bytes": value["maximum_token_bytes"],
            "selected_closure_complete": value["selected_closure_complete"],
            "atoms": atoms,
            "atoms_count": len(atoms),
            "atoms_digest": digest_value(atoms),
            "page_digests": list(value["page_digests"]),
            "page_identity_digests": list(value["page_identity_digests"]),
            "identity_digests": sorted(value["identity_digests"]),
        }
    except (KeyError, TypeError) as exc:
        raise SaturationQueryTraceError("internal page chain is incomplete") from exc
    return validate_saturation_query_trace(trace)
