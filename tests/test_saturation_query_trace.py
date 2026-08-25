from __future__ import annotations

from copy import deepcopy

import pytest

from promin.saturation_query_trace import (
    SaturationQueryTraceError,
    build_saturation_query_trace,
    validate_saturation_query_trace,
)


def internal_chain_fixture() -> dict[str, object]:
    return {
        "atoms": {"atom:b", "atom:a"},
        "page_digests": ["1" * 64, "2" * 64],
        "page_identity_digests": ["a" * 64, "b" * 64],
        "pages": 2,
        "continuation_pages": 1,
        "first_truncated": True,
        "initial_expiry": "2026-08-25T10:00:00Z",
        "expiry_monotonic": True,
        "renewals": [
            {
                "cursor": 7,
                "old_expiry": "2026-08-25T10:00:00Z",
                "new_expiry": "2026-08-25T10:01:00Z",
                "renewed_at": "2026-08-25T09:59:30Z",
                "old_expiry_instant": None,
                "new_expiry_instant": None,
            }
        ],
        "maximum_token_bytes": 32,
        "identity_digests": {"b" * 64, "a" * 64},
        "selected_closure_complete": True,
    }


def legacy_trace_fixture() -> dict[str, object]:
    return {
        "pages": 1,
        "continuation_pages": 0,
        "first_truncated": False,
        "maximum_token_bytes": 0,
        "selected_closure_complete": True,
        "atoms": ["atom"],
        "atoms_count": 1,
        "atoms_digest": "0" * 64,
        "page_digests": ["0" * 64],
    }


def test_trace_round_trip_preserves_renewal_and_identity_evidence() -> None:
    trace = build_saturation_query_trace(internal_chain_fixture())

    assert validate_saturation_query_trace(trace) == trace
    assert trace["renewal_count"] == 1
    assert trace["page_identity_digests"] == ["a" * 64, "b" * 64]
    assert trace["identity_digests"] == ["a" * 64, "b" * 64]


def test_trace_allows_single_page_without_continuation_expiry() -> None:
    internal = internal_chain_fixture()
    internal.update(
        pages=1,
        continuation_pages=0,
        first_truncated=False,
        initial_expiry=None,
        renewals=[],
        page_digests=["1" * 64],
        page_identity_digests=["a" * 64],
    )

    trace = build_saturation_query_trace(internal)
    assert validate_saturation_query_trace(trace) == trace


def test_trace_rejects_single_page_with_continuation_expiry() -> None:
    trace = build_saturation_query_trace(internal_chain_fixture())
    trace.update(
        pages=1,
        continuation_pages=0,
        first_truncated=False,
        renewal_count=0,
        renewal_events=[],
        page_digests=["1" * 64],
        page_identity_digests=["a" * 64],
    )

    with pytest.raises(SaturationQueryTraceError, match="initial expiry"):
        validate_saturation_query_trace(trace)


def test_trace_accepts_unrenewed_continuation_pages() -> None:
    internal = internal_chain_fixture()
    internal["renewals"] = []
    # Continuation pages can exist without a safety-window renewal event.
    internal["pages"] = 2
    internal["continuation_pages"] = 1
    internal["page_digests"] = ["1" * 64, "2" * 64]
    internal["page_identity_digests"] = ["a" * 64, "b" * 64]
    trace = build_saturation_query_trace(internal)
    assert trace["renewal_count"] == 0


def test_trace_has_exact_fifteen_field_boundary() -> None:
    trace = build_saturation_query_trace(internal_chain_fixture())
    assert set(trace) == {
        "pages", "continuation_pages", "first_truncated", "initial_expiry",
        "expiry_monotonic", "renewal_count", "renewal_events",
        "maximum_token_bytes", "selected_closure_complete", "atoms",
        "atoms_count", "atoms_digest", "page_digests",
        "page_identity_digests", "identity_digests",
    }


@pytest.mark.parametrize(
    ("field", "replacement"),
    [("atoms", ["atom:a", 3]), ("identity_digests", ["a" * 64, 3])],
)
def test_trace_rejects_mixed_type_entries(field: str, replacement: object) -> None:
    trace = build_saturation_query_trace(internal_chain_fixture())
    trace[field] = replacement
    with pytest.raises(SaturationQueryTraceError):
        validate_saturation_query_trace(trace)


def test_trace_rejects_noncanonical_timestamp_and_extra_event_key() -> None:
    trace = build_saturation_query_trace(internal_chain_fixture())
    trace["initial_expiry"] = "2026-08-25T10:00:00+00:00"
    with pytest.raises(SaturationQueryTraceError, match="canonical"):
        validate_saturation_query_trace(trace)

    trace = build_saturation_query_trace(internal_chain_fixture())
    trace["renewal_events"][0]["unexpected"] = True
    with pytest.raises(SaturationQueryTraceError, match="renewal event shape"):
        validate_saturation_query_trace(trace)


def test_trace_accepts_first_renewal_after_unrenewed_continuation() -> None:
    trace = build_saturation_query_trace(internal_chain_fixture())
    trace["renewal_events"][0]["old_expiry"] = "2026-08-25T09:59:00Z"
    trace["renewal_events"][0]["renewed_at"] = "2026-08-25T09:58:30Z"

    assert validate_saturation_query_trace(trace) == trace


def test_trace_rejects_invalid_digest_scalar() -> None:
    trace = build_saturation_query_trace(internal_chain_fixture())
    trace["page_digests"] = [None, "2" * 64]
    with pytest.raises(SaturationQueryTraceError):
        validate_saturation_query_trace(trace)


def test_trace_rejects_truncated_first_page_without_continuation() -> None:
    internal = internal_chain_fixture()
    internal.update(
        pages=1,
        continuation_pages=0,
        first_truncated=True,
        initial_expiry=None,
        renewals=[],
        page_digests=["1" * 64],
        page_identity_digests=["a" * 64],
    )

    with pytest.raises(SaturationQueryTraceError, match="truncation"):
        build_saturation_query_trace(internal)


def test_trace_rejects_renewal_after_old_expiry() -> None:
    trace = build_saturation_query_trace(internal_chain_fixture())
    trace["renewal_events"][0]["renewed_at"] = "2026-08-25T10:00:01Z"

    with pytest.raises(SaturationQueryTraceError, match="renewal expiry"):
        validate_saturation_query_trace(trace)


def test_trace_rejects_legacy_nine_field_projection() -> None:
    with pytest.raises(SaturationQueryTraceError, match="shape"):
        validate_saturation_query_trace(legacy_trace_fixture())


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("page_identity_digests", ["a" * 64]),
        ("identity_digests", ["a" * 64, "a" * 64]),
        ("atoms", ["atom:b", "atom:a"]),
        ("continuation_pages", 0),
        ("selected_closure_complete", False),
        ("renewal_count", 2),
    ],
)
def test_trace_rejects_inconsistent_page_chain_facts(
    field: str, replacement: object
) -> None:
    trace = build_saturation_query_trace(internal_chain_fixture())
    trace[field] = replacement

    with pytest.raises(SaturationQueryTraceError):
        validate_saturation_query_trace(trace)


def test_trace_rejects_identity_digest_cardinality_mismatch() -> None:
    trace = build_saturation_query_trace(internal_chain_fixture())
    trace["identity_digests"] = ["a" * 64]

    with pytest.raises(SaturationQueryTraceError, match="identity digests"):
        validate_saturation_query_trace(trace)


def test_trace_rejects_non_monotonic_or_malformed_renewal() -> None:
    trace = build_saturation_query_trace(internal_chain_fixture())
    trace["renewal_events"][0]["new_expiry"] = "2026-08-25T09:59:00Z"

    with pytest.raises(SaturationQueryTraceError, match="renewal"):
        validate_saturation_query_trace(trace)

    malformed = deepcopy(build_saturation_query_trace(internal_chain_fixture()))
    malformed["renewal_events"][0]["renewed_at"] = "not-a-timestamp"
    with pytest.raises(SaturationQueryTraceError, match="renewal"):
        validate_saturation_query_trace(malformed)
