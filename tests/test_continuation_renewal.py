from __future__ import annotations

from datetime import datetime, timedelta, timezone

import base64
import hashlib
import pytest

from promin.authority import AuthorityError
from promin.projection import ProjectionError
from promin.service import ServiceError
from tools import promin_saturation as saturation
from tests.test_service_cli import (
    _bind_mutation,
    _command,
    _grant,
    _grant_authorization,
    _leased_service,
    _mutation_card,
)
from promin.service import _reconciled_evidence


_BUDGET = {
    "max_bytes": 8192,
    "max_entities": 2,
    "max_relations": 2,
    "max_fanout_per_entity": 1,
    "top_k": 1,
}
_RESUME_BINDING = {
    "activation_digest": "a" * 64,
    "capability_id": "projection.read",
    "grant_claim_digest": "1" * 64,
    "grant_id": "reader",
    "implementation_closure_digest": "d" * 64,
    "requested_scope_digest": "2" * 64,
    "revocation_epoch": "3" * 64,
    "subject_id": "owner",
}
_RESUME_BINDING_DIGEST = saturation._digest(_RESUME_BINDING)


def _canonical_token(seed: int) -> str:
    handle = base64.urlsafe_b64encode(bytes([seed]) * 16).rstrip(b"=").decode("ascii")
    row_digest = f"{seed:064x}"
    signature = base64.urlsafe_b64encode(bytes([seed + 1]) * 32).rstrip(b"=").decode(
        "ascii"
    )
    return f"promin-v2.{handle}.{row_digest}.{signature}"


def _page(entity_id: str, continuation: dict | None) -> dict:
    page = {
        "query": "grant",
        "depth": 1,
        "budget": dict(_BUDGET),
        "ranking": "bm25-v1",
        "entities": [{"id": entity_id}],
        "relations": [],
        "evidence": [],
        "truncated": continuation is not None,
        "stream_cursor": 0 if continuation is None else continuation["cursor"] - 1,
        "refinement_required": False,
        "refinement_hints": [],
        "selected_seed_count": 1,
        "unselected_matches_traversable": False,
        "silent_truncation": False,
        "selected_closure_complete": continuation is None,
    }
    if continuation is not None:
        page.update(
            {
                "continuation": continuation,
                "continuation_version": 2,
                "next_stream_cursor": continuation["cursor"],
            }
        )
    return page


def test_harness_renews_only_before_expiry_and_keeps_workload_unchanged() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    expiry = (now + timedelta(seconds=10)).isoformat().replace("+00:00", "Z")
    token = _canonical_token(1)
    continuation = {
        "version": 2,
        "traversal": "typed-bfs-v2",
        "token": token,
        "cursor": 1,
        "expiry": expiry,
        "activation_digest": "a" * 64,
        "head_digest": "b" * 64,
        "projection_digest": "c" * 64,
        "implementation_closure_digest": "d" * 64,
        "ranking": "bm25-v1",
        "depth": 1,
        "budget_digest": "e" * 64,
        "resume_binding_digest": _RESUME_BINDING_DIGEST,
    }

    class Runtime:
        def __init__(self) -> None:
            self.renewals: list[dict] = []
            self.searches: list[str] = []

        def renew_search(self, token: str, **kwargs: object) -> dict:
            self.renewals.append({"token": token, **kwargs})
            return {
                "record_type": "ContinuationRenewal",
                "version": 2,
                "traversal": "typed-bfs-v2",
                "token": _canonical_token(2),
                "query": "grant",
                "depth": 1,
                "budget": dict(_BUDGET),
                "ranking": "bm25-v1",
                "cursor": 1,
                "expiry": (now + timedelta(seconds=900)).isoformat().replace(
                    "+00:00", "Z"
                ),
                "issued_at": now.isoformat().replace("+00:00", "Z"),
                "ttl_seconds": 900,
                "activation_digest": "a" * 64,
                "head_digest": "b" * 64,
                "projection_digest": "c" * 64,
                "implementation_closure_digest": "d" * 64,
                    "resume_binding": dict(_RESUME_BINDING),
                "budget_digest": saturation._digest(_BUDGET),
                    "resume_binding_digest": _RESUME_BINDING_DIGEST,
                "authorization_binding": {
                    "subject_id": "owner",
                    "grant_id": "reader",
                    "grant_claim_digest": "1" * 64,
                    "capability_id": "projection.read",
                    "requested_scope_digest": "2" * 64,
                    "revocation_epoch": "3" * 64,
                },
            }

        def search(self, *_args: object, **kwargs: object) -> dict:
            self.searches.append(kwargs["continuation_token"])
            return _page("entity:final", None)

    runtime = Runtime()
    result = saturation._drain_pages(
        runtime,
        _page("entity:first", continuation),
        _BUDGET,
        query_grant={"subject_id": "owner", "grant_id": "reader"},
        ttl_seconds=900,
        clock=lambda: now,
    )

    assert len(runtime.renewals) == 1
    assert runtime.searches == [_canonical_token(2)]
    assert result["renewals"][0]["cursor"] == 1
    assert result["expiry_monotonic"] is True
    assert result["pages"] == 2
    assert result["atoms"] == {"entity:entity:first", "entity:entity:final"}


def test_service_renewal_reauthorizes_subject_and_grant_and_rejects_expired_or_tampered(
    tmp_path,
) -> None:
    service, grants, _task, _lease, _head = _leased_service(tmp_path)
    try:
        service.rebuild()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        budget = {
            "max_bytes": 8192,
            "max_entities": 1,
            "max_relations": 1,
            "max_fanout_per_entity": 1,
            "top_k": 8,
        }
        first = service.search(
            "grant",
            1,
            budget=budget,
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=now,
            ttl_seconds=60,
        )
        token = first["continuation"]["token"]
        renewed = service.renew_search(
            token,
            query="grant",
            depth=1,
            budget=budget,
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=now + timedelta(seconds=1),
            ttl_seconds=60,
        )
        assert renewed["record_type"] == "ContinuationRenewal"
        assert renewed["authorization_binding"]["grant_id"] == grants["reader"]["grant_id"]
        assert renewed["cursor"] == first["continuation"]["cursor"]

        with pytest.raises((AuthorityError, ServiceError)):
            service.renew_search(
                token,
                query="grant",
                depth=1,
                budget=budget,
                subject_id="different-subject",
                grant_id=grants["reader"]["grant_id"],
                now=now + timedelta(seconds=1),
                ttl_seconds=60,
            )
        with pytest.raises((AuthorityError, ServiceError)):
            service.renew_search(
                token,
                query="grant",
                depth=1,
                budget=budget,
                subject_id="owner",
                grant_id=grants["manager"]["grant_id"],
                now=now + timedelta(seconds=1),
                ttl_seconds=60,
            )
        with pytest.raises((ProjectionError, ServiceError)):
            service.renew_search(
                token,
                query="grant",
                depth=1,
                budget=budget,
                subject_id="owner",
                grant_id=grants["reader"]["grant_id"],
                now=now + timedelta(seconds=61),
                ttl_seconds=60,
            )
        parts = token.split(".")
        signature = bytearray(
            base64.urlsafe_b64decode(parts[-1] + "=" * (-len(parts[-1]) % 4))
        )
        signature[0] ^= 1
        parts[-1] = base64.urlsafe_b64encode(bytes(signature)).rstrip(b"=").decode("ascii")
        with pytest.raises((ProjectionError, ServiceError)):
            service.renew_search(
                ".".join(parts),
                query="grant",
                depth=1,
                budget=budget,
                subject_id="owner",
                grant_id=grants["reader"]["grant_id"],
                now=now + timedelta(seconds=1),
                ttl_seconds=60,
            )
    finally:
        service.close()


def test_service_renewal_uses_public_search_union_and_fails_closed_on_stale_or_revoked_state(
    tmp_path,
) -> None:
    service, grants, task, lease, _head = _leased_service(tmp_path)
    try:
        service.rebuild()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        budget = {
            "max_bytes": 8192,
            "max_entities": 1,
            "max_relations": 1,
            "max_fanout_per_entity": 1,
            "top_k": 8,
        }

        first = service.search(
            "grant",
            1,
            budget=budget,
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=now,
            ttl_seconds=60,
        )
        baseline = saturation._drain_pages(
            service,
            first,
            budget,
            query_grant=grants["reader"],
            ttl_seconds=60,
            clock=lambda: now + timedelta(seconds=1),
        )
        renewed_first = service.search(
            "grant",
            1,
            budget=budget,
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=now,
            ttl_seconds=60,
        )
        renewed = saturation._drain_pages(
            service,
            renewed_first,
            budget,
            query_grant=grants["reader"],
            ttl_seconds=60,
            clock=lambda: now + timedelta(seconds=31),
        )
        assert renewed["renewals"]
        assert renewed["renewals"][0]["new_token"] != renewed["renewals"][0]["old_token"]
        assert renewed["identity_digests"] == baseline["identity_digests"]
        assert renewed["atoms"] == baseline["atoms"]

        authority = service._context().plans["authority.json"]
        alternate_reader = _grant(
            authority,
            task["activation_digest"],
            grants["manager"]["issued_at"],
            grant_id="grant:renewal-stale-head-reader",
            capability="projection.read",
            issuer=grants["manager"],
        )
        current_head = service._event_store(service._context()).head()["batch_digest"]
        current_head = service.commit(
            _command(
                activation_digest=task["activation_digest"],
                command_id="command:renewal-stale-head-reader",
                command_kind="grant.issue",
                payload=alternate_reader,
                expected_head=current_head,
                issued_at=alternate_reader["issued_at"],
                authorization=_grant_authorization(grants["manager"]),
            )
        )["batch_digest"]
        with pytest.raises((ProjectionError, ServiceError)):
            service.renew_search(
                renewed_first["continuation"]["token"],
                query="grant",
                depth=1,
                budget=budget,
                subject_id="owner",
                grant_id=grants["reader"]["grant_id"],
                now=now + timedelta(seconds=1),
                ttl_seconds=60,
            )

        service.rebuild()
        with pytest.raises((ProjectionError, ServiceError)):
            service.renew_search(
                renewed_first["continuation"]["token"],
                query="grant",
                depth=1,
                budget=budget,
                subject_id="owner",
                grant_id=grants["reader"]["grant_id"],
                now=now + timedelta(seconds=1),
                ttl_seconds=60,
            )

        fresh = service.search(
            "grant",
            1,
            budget=budget,
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=now,
            ttl_seconds=60,
        )
        evidence_bytes = b"renewal revocation evidence\n"
        context = service._context()
        artifact = {
            "record_type": "Artifact",
            "artifact_id": "artifact:renewal-revocation",
            "artifact_kind": "evidence",
            "digest": hashlib.sha256(evidence_bytes).hexdigest(),
            "media_type": "text/plain",
            "size_bytes": len(evidence_bytes),
            "retention_class": "audit",
            "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "evidence_binding": {
                "activation_digest": task["activation_digest"],
                "candidate_digest": task["candidate_digest"],
                "policy_digest": "4" * 64,
                "tool_digest": "5" * 64,
                "input_digests": ["6" * 64],
                "implementation_closure_digest": context.implementation_closure_digest,
            },
            "outcome": "fail",
            "stale": False,
            "unresolved": False,
            "evidence_class": "validator",
            "evidence_purpose": "gate",
            "product_credit_eligible": False,
        }
        artifact_card = _mutation_card(
            service,
            task,
            lease,
            grants["holder"],
            grants["reader"],
            "artifact.record",
        )
        artifact_command = _bind_mutation(
            _command(
                activation_digest=task["activation_digest"],
                command_id="command:renewal-revocation-evidence",
                command_kind="artifact.record",
                payload=artifact,
                expected_head=current_head,
                issued_at=artifact["created_at"],
                authorization=_grant_authorization(grants["publisher"]),
                effect_scope=[{"kind": "artifact", "value": artifact["artifact_id"]}],
            ),
            artifact_card,
            grants["holder"],
        )
        published = service.publish_evidence(
            artifact_command,
            evidence_bytes,
            workcard=artifact_card,
        )
        current_head = published["command_result"]["batch_digest"]
        finalized = _reconciled_evidence(
            service.root,
            service._event_store(service._context()),
        ).get_record(artifact["artifact_id"])
        decision = {
            "record_type": "Decision",
            "decision_id": "decision:renewal-revoke-reader",
            "decision_kind": "revoke",
            "subject_id": "owner",
            "grant_id": grants["manager"]["grant_id"],
            "grant_claim_digest": grants["manager"]["claim_digest"],
            "activation_digest": task["activation_digest"],
            "target_type": "Grant",
            "target_id": grants["reader"]["grant_id"],
            "target_digest": saturation._digest(grants["reader"]),
            "rationale": "exercise renewal revocation fail closed path",
            "evidence_artifacts": [
                {
                    "artifact_id": artifact["artifact_id"],
                    "artifact_record_digest": saturation._digest(finalized),
                }
            ],
            "created_at": (now + timedelta(seconds=1)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
        current_head = service.commit(
            _command(
                activation_digest=task["activation_digest"],
                command_id="command:renewal-revoke-reader-decision",
                command_kind="decision.record",
                payload=decision,
                expected_head=current_head,
                issued_at=decision["created_at"],
                authorization=_grant_authorization(grants["manager"]),
            )
        )["batch_digest"]
        revocation = {
            "grant_id": grants["reader"]["grant_id"],
            "decision_id": decision["decision_id"],
            "reason": "exercise renewal revocation fail closed path",
            "revoked_at": (now + timedelta(seconds=2)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }
        service.commit(
            _command(
                activation_digest=task["activation_digest"],
                command_id="command:renewal-revoke-reader",
                command_kind="grant.revoke",
                payload=revocation,
                expected_head=current_head,
                issued_at=revocation["revoked_at"],
                authorization=_grant_authorization(grants["manager"]),
            )
        )
        service.rebuild()
        with pytest.raises((AuthorityError, ServiceError)):
            service.renew_search(
                fresh["continuation"]["token"],
                query="grant",
                depth=1,
                budget=budget,
                subject_id="owner",
                grant_id=grants["reader"]["grant_id"],
                now=now + timedelta(seconds=3),
                ttl_seconds=60,
            )
    finally:
        service.close()


@pytest.mark.parametrize(
    ("remaining", "should_renew"),
    [(29, True), (30, True), (31, False)],
)
def test_harness_safety_margin_boundaries(remaining: int, should_renew: bool) -> None:
    now = datetime(2026, 8, 22, 3, 0, 0, tzinfo=timezone.utc)
    expiry = (now + timedelta(seconds=remaining)).isoformat().replace("+00:00", "Z")
    source = {
        "version": 2,
        "traversal": "typed-bfs-v2",
        "token": _canonical_token(1),
        "cursor": 1,
        "expiry": expiry,
        "activation_digest": "a" * 64,
        "head_digest": "b" * 64,
        "projection_digest": "c" * 64,
        "implementation_closure_digest": "d" * 64,
        "ranking": "bm25-v1",
        "depth": 1,
        "budget_digest": saturation._digest(_BUDGET),
        "resume_binding_digest": _RESUME_BINDING_DIGEST,
    }

    class Runtime:
        def __init__(self) -> None:
            self.renewed = 0

        def renew_search(self, token: str, **kwargs: object) -> dict:
            self.renewed += 1
            issued = now
            return {
                "record_type": "ContinuationRenewal",
                "version": 2,
                "traversal": "typed-bfs-v2",
                "token": _canonical_token(2),
                "query": "grant",
                "depth": 1,
                "budget": dict(_BUDGET),
                "ranking": "bm25-v1",
                "cursor": 1,
                "issued_at": issued.isoformat().replace("+00:00", "Z"),
                "expiry": (issued + timedelta(seconds=900)).isoformat().replace(
                    "+00:00", "Z"
                ),
                "ttl_seconds": 900,
                "activation_digest": "a" * 64,
                "head_digest": "b" * 64,
                "projection_digest": "c" * 64,
                "implementation_closure_digest": "d" * 64,
                "resume_binding": dict(_RESUME_BINDING),
                "budget_digest": saturation._digest(_BUDGET),
                "resume_binding_digest": _RESUME_BINDING_DIGEST,
                "authorization_binding": {
                    "subject_id": "owner", "grant_id": "reader",
                    "grant_claim_digest": "1" * 64, "capability_id": "projection.read",
                    "requested_scope_digest": "2" * 64, "revocation_epoch": "3" * 64,
                },
            }

        def search(self, *_args: object, **_kwargs: object) -> dict:
            return _page("final", None)

    runtime = Runtime()
    result = saturation._drain_pages(
        runtime,
        _page("first", source),
        _BUDGET,
        query_grant={"subject_id": "owner", "grant_id": "reader"},
        ttl_seconds=900,
        clock=lambda: now,
    )
    assert (runtime.renewed == 1) is should_renew
    assert result["expiry_monotonic"] is True


def test_harness_rejects_expired_and_malformed_expiry() -> None:
    now = datetime(2026, 8, 22, 3, 0, 0, tzinfo=timezone.utc)
    source = {
        "version": 2, "traversal": "typed-bfs-v2",
        "token": _canonical_token(1), "cursor": 1,
        "expiry": "2026-08-22T02:59:59Z", "activation_digest": "a" * 64,
        "head_digest": "b" * 64, "projection_digest": "c" * 64,
        "implementation_closure_digest": "d" * 64, "ranking": "bm25-v1",
        "depth": 1, "budget_digest": saturation._digest(_BUDGET),
        "resume_binding_digest": _RESUME_BINDING_DIGEST,
    }

    class Runtime:
        def renew_search(self, *_args: object, **_kwargs: object) -> dict:
            raise AssertionError("expired token must not renew")

        def search(self, *_args: object, **_kwargs: object) -> dict:
            return _page("final", None)

    with pytest.raises(saturation.SaturationError, match="expired before renewal"):
        saturation._drain_pages(
            Runtime(), _page("first", source), _BUDGET,
            query_grant={"subject_id": "owner", "grant_id": "reader"},
            ttl_seconds=900, clock=lambda: now,
        )
    source["expiry"] = "2026-08-22T03:00:00+00:00"
    with pytest.raises(saturation.SaturationError, match="not canonical UTC"):
        saturation._drain_pages(
            Runtime(), _page("first", source), _BUDGET,
            query_grant={"subject_id": "owner", "grant_id": "reader"},
            ttl_seconds=900, clock=lambda: now,
        )

    class RuntimeWithoutRenewal:
        def search(self, *_args: object, **_kwargs: object) -> dict:
            raise AssertionError("expired continuation must not reach search")

    source["expiry"] = "2026-08-22T02:59:59Z"
    with pytest.raises(saturation.SaturationError, match="expired before renewal"):
        saturation._drain_pages(
            RuntimeWithoutRenewal(), _page("first", source), _BUDGET,
            query_grant={"subject_id": "owner", "grant_id": "reader"},
            ttl_seconds=900, clock=lambda: now,
        )
    source["expiry"] = "2026-08-22T03:01:00Z"
    source["projection_digest"] = "sha256:" + "c" * 64
    with pytest.raises(saturation.SaturationError, match="canonical"):
        saturation._drain_pages(
            Runtime(), _page("first", source), _BUDGET,
            query_grant={"subject_id": "owner", "grant_id": "reader"},
            ttl_seconds=900, clock=lambda: now,
        )
    source["expiry"] = "2026-08-22T03:00:29Z"
    source["projection_digest"] = "c" * 64
    with pytest.raises(
        saturation.SaturationError,
        match="renewal is required inside its safety window",
    ):
        saturation._drain_pages(
            RuntimeWithoutRenewal(), _page("first", source), _BUDGET,
            query_grant={"subject_id": "owner", "grant_id": "reader"},
            ttl_seconds=900, clock=lambda: now,
        )


def test_canonical_atom_identity_includes_complete_payload_metadata() -> None:
    base = _page("first", None)
    changed = dict(base)
    changed["entities"] = [{"id": "first", "kind": "changed"}]
    evidence_changed = dict(base)
    evidence_changed["evidence"] = [{"id": "evidence:1", "path": "other"}]

    base_identity = saturation._page_atom_identity_digests(base)
    assert base_identity != saturation._page_atom_identity_digests(changed)
    assert base_identity != saturation._page_atom_identity_digests(evidence_changed)


def test_renewal_rejects_stale_snapshot_and_query_authorization_binding() -> None:
    now = datetime(2026, 8, 22, 3, 0, 0, tzinfo=timezone.utc)
    source = {
        "version": 2,
        "traversal": "typed-bfs-v2",
        "token": _canonical_token(1),
        "cursor": 1,
        "expiry": "2026-08-22T03:00:10Z",
        "activation_digest": "a" * 64,
        "head_digest": "b" * 64,
        "projection_digest": "c" * 64,
        "implementation_closure_digest": "d" * 64,
        "ranking": "bm25-v1",
        "depth": 1,
        "budget_digest": saturation._digest(_BUDGET),
        "resume_binding_digest": _RESUME_BINDING_DIGEST,
    }
    grant = {
        "subject_id": "owner",
        "grant_id": "reader",
        "claim_digest": "1" * 64,
        "capability_id": "projection.read",
        "scope": [{"kind": "task", "value": "task:all"}],
        "revocation_epoch": "3" * 64,
    }
    expected_binding = {
        **_RESUME_BINDING,
        "requested_scope_digest": saturation._digest(grant["scope"]),
    }
    source["resume_binding_digest"] = saturation._digest(expected_binding)
    response = {
        "record_type": "ContinuationRenewal",
        "version": 2,
        "traversal": "typed-bfs-v2",
        "token": _canonical_token(2),
        "query": "grant",
        "depth": 1,
        "budget": dict(_BUDGET),
        "ranking": "bm25-v1",
        "cursor": 1,
        "issued_at": "2026-08-22T03:00:01Z",
        "expiry": "2026-08-22T03:15:01Z",
        "ttl_seconds": 900,
        "activation_digest": source["activation_digest"],
        "head_digest": source["head_digest"],
        "projection_digest": source["projection_digest"],
        "implementation_closure_digest": source["implementation_closure_digest"],
        "resume_binding": expected_binding,
        "budget_digest": saturation._digest(_BUDGET),
        "resume_binding_digest": source["resume_binding_digest"],
        "authorization_binding": {
            "subject_id": "owner",
            "grant_id": "reader",
            "grant_claim_digest": "1" * 64,
            "capability_id": "projection.read",
            "requested_scope_digest": saturation._digest(grant["scope"]),
            "revocation_epoch": "3" * 64,
        },
    }
    saturation._validate_renewal_response(
        response,
        source=source,
        query="grant",
        depth=1,
        budget=_BUDGET,
        ranking="bm25-v1",
        ttl_seconds=900,
        query_grant=grant,
        old_expiry=now,
        max_token_bytes=256,
    )
    for field in ("activation_digest", "head_digest", "projection_digest", "implementation_closure_digest"):
        altered = dict(response)
        altered[field] = "e" * 64
        with pytest.raises(saturation.SaturationError, match="differs from source"):
            saturation._validate_renewal_response(
                altered,
                source=source,
                query="grant",
                depth=1,
                budget=_BUDGET,
                ranking="bm25-v1",
                ttl_seconds=900,
                query_grant=grant,
                old_expiry=now,
                max_token_bytes=256,
            )
        altered = dict(response)
        altered[field] = "sha256:" + response[field]
        with pytest.raises(saturation.SaturationError, match="canonical"):
            saturation._validate_renewal_response(
                altered,
                source=source,
                query="grant",
                depth=1,
                budget=_BUDGET,
                ranking="bm25-v1",
                ttl_seconds=900,
                query_grant=grant,
                old_expiry=now,
                max_token_bytes=256,
            )
    altered = dict(response)
    altered["authorization_binding"] = dict(response["authorization_binding"])
    altered["authorization_binding"]["grant_claim_digest"] = "2" * 64
    with pytest.raises(saturation.SaturationError, match="grant claim"):
        saturation._validate_renewal_response(
            altered,
            source=source,
            query="grant",
            depth=1,
            budget=_BUDGET,
            ranking="bm25-v1",
            ttl_seconds=900,
            query_grant=grant,
            old_expiry=now,
            max_token_bytes=256,
        )
    oversized = dict(response)
    oversized["token"] = "x" * 257
    with pytest.raises(saturation.SaturationError, match="token exceeds"):
        saturation._validate_renewal_response(
            oversized,
            source=source,
            query="grant",
            depth=1,
            budget=_BUDGET,
            ranking="bm25-v1",
            ttl_seconds=900,
            query_grant=grant,
            old_expiry=now,
            max_token_bytes=256,
        )
