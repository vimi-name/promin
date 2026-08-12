from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import sqlite3

import pytest

from promin.canonical import digest_value, parse_json_strict
from promin.authority import AuthorityError
from promin.projection import ProjectionError
from promin.service import ServiceError
from tools import promin_saturation as saturation
from tests.test_service_cli import (
    _at,
    _command,
    _grant,
    _grant_authorization,
    _leased_service,
)


def test_public_retrieval_continuation_reauthorizes_exact_grant_claim(
    tmp_path, request: pytest.FixtureRequest
) -> None:
    service, grants, task, _lease, head = _leased_service(tmp_path)
    request.addfinalizer(service.close)
    issued_at = grants["manager"]["issued_at"]
    alternate_reader = _grant(
        service._context().plans["authority.json"],
        task["activation_digest"],
        issued_at,
        grant_id="grant:alternate-retrieval-reader",
        capability="projection.read",
        issuer=grants["manager"],
    )
    head = service.commit(
        _command(
            activation_digest=task["activation_digest"],
            command_id="command:issue-alternate-retrieval-reader",
            command_kind="grant.issue",
            payload=alternate_reader,
            expected_head=head,
            issued_at=issued_at,
            authorization=_grant_authorization(grants["manager"]),
        )
    )["batch_digest"]
    service.rebuild()

    budget = {
        "max_bytes": 8192,
        "max_entities": 1,
        "max_relations": 1,
        "max_fanout_per_entity": 1,
        "top_k": 8,
    }
    now = datetime.now(timezone.utc).replace(microsecond=0)
    first = service.search(
        "grant",
        1,
        budget=budget,
        subject_id="owner",
        grant_id=grants["reader"]["grant_id"],
        now=now,
        ttl_seconds=60,
    )
    assert first["record_type"] == "RetrievalPage"
    assert first["truncated"] is True
    continuation = first["continuation"]
    assert isinstance(continuation, dict)
    assert set(continuation) == {
        "version",
        "traversal",
        "token",
        "cursor",
        "expiry",
        "activation_digest",
        "head_digest",
        "projection_digest",
        "implementation_closure_digest",
        "ranking",
        "depth",
        "budget_digest",
        "resume_binding_digest",
    }
    assert "grant_claim_digest" not in continuation
    token = continuation["token"]

    projection_path = (
        service.root / ".promin" / "state" / "projection" / "promin.sqlite3"
    )
    handle = token.split(".")[1]
    connection = sqlite3.connect(projection_path)
    try:
        stored = connection.execute(
            "SELECT payload_json FROM continuations WHERE handle=?",
            (handle,),
        ).fetchone()
    finally:
        connection.close()
    assert stored is not None
    payload = parse_json_strict(stored[0].encode("utf-8"))
    assert payload["resume_binding"]["grant_claim_digest"] == grants["reader"][
        "claim_digest"
    ]
    assert continuation["resume_binding_digest"] == digest_value(
        payload["resume_binding"]
    )

    continued = service.search(
        "grant",
        1,
        budget=budget,
        continuation_token=token,
        subject_id="owner",
        grant_id=grants["reader"]["grant_id"],
        now=now + timedelta(seconds=1),
        ttl_seconds=60,
    )
    assert continued["record_type"] == "RetrievalPage"
    assert continued["stream_cursor"] == continuation["cursor"]

    with pytest.raises(ProjectionError, match="continuation ttl_seconds binding mismatch"):
        service.search(
            "grant",
            1,
            budget=budget,
            continuation_token=token,
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=now + timedelta(seconds=1),
            ttl_seconds=61,
        )

    with pytest.raises(
        ServiceError,
        match="public continue accepts only a ReadyFrontier continuation",
    ):
        service.continue_search(
            token,
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=now + timedelta(seconds=1),
        )

    with pytest.raises(ProjectionError, match="continuation query binding mismatch"):
        service.search(
            "different-query",
            1,
            budget=budget,
            continuation_token=token,
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=now + timedelta(seconds=1),
            ttl_seconds=60,
        )
    with pytest.raises(ProjectionError, match="continuation budget binding mismatch"):
        service.search(
            "grant",
            1,
            budget={**budget, "max_bytes": budget["max_bytes"] - 1},
            continuation_token=token,
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=now + timedelta(seconds=1),
            ttl_seconds=60,
        )
    with pytest.raises(ServiceError, match="continuation token must be non-empty"):
        service.search(
            "grant",
            1,
            budget=budget,
            continuation_token="",
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=now + timedelta(seconds=1),
        )

    drained = saturation._drain_pages(
        service,
        first,
        budget,
        query_grant=grants["reader"],
        ttl_seconds=60,
    )
    assert drained["first_truncated"] is True
    assert drained["continuation_pages"] >= 1
    assert drained["selected_closure_complete"] is True

    with pytest.raises(ProjectionError, match="resume_binding binding mismatch"):
        service.search(
            "grant",
            1,
            budget=budget,
            continuation_token=token,
            subject_id="owner",
            grant_id=alternate_reader["grant_id"],
            now=now + timedelta(seconds=1),
            ttl_seconds=60,
        )

    parts = token.split(".")
    signature = bytearray(
        base64.urlsafe_b64decode(parts[-1] + "=" * (-len(parts[-1]) % 4))
    )
    signature[0] ^= 0x01
    parts[-1] = base64.urlsafe_b64encode(bytes(signature)).rstrip(b"=").decode("ascii")
    with pytest.raises(ProjectionError, match="continuation signature mismatch"):
        service.search(
            "grant",
            1,
            budget=budget,
            continuation_token=".".join(parts),
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=now + timedelta(seconds=1),
            ttl_seconds=60,
        )

    with pytest.raises((AuthorityError, ServiceError)):
        service.search(
            "grant",
            1,
            budget=budget,
            continuation_token=token,
            subject_id="different-subject",
            grant_id=grants["reader"]["grant_id"],
            now=now + timedelta(seconds=1),
            ttl_seconds=60,
        )

    post_token_reader = _grant(
        service._context().plans["authority.json"],
        task["activation_digest"],
        issued_at,
        grant_id="grant:post-token-reader",
        capability="projection.read",
        issuer=grants["manager"],
    )
    service.commit(
        _command(
            activation_digest=task["activation_digest"],
            command_id="command:issue-post-token-reader",
            command_kind="grant.issue",
            payload=post_token_reader,
            expected_head=head,
            issued_at=issued_at,
            authorization=_grant_authorization(grants["manager"]),
        )
    )
    with pytest.raises(ProjectionError, match="continuation state is missing or substituted"):
        service.search(
            "grant",
            1,
            budget=budget,
            continuation_token=token,
            subject_id="owner",
            grant_id=grants["reader"]["grant_id"],
            now=now + timedelta(seconds=1),
            ttl_seconds=60,
        )
