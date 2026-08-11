from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from promin.canonical import digest_value
from promin.revalidation import (
    ReadOnlyRevalidationCallback,
    RevalidationError,
    RevalidationObservation,
    RevalidationPhase,
    RevalidationPlan,
    RevalidationReceipt,
    RevalidationStatus,
    prepare_revalidation_report,
    reconsolidate_revalidation,
    revalidate_recovery,
)


def _plan(label: str = "baseline") -> RevalidationPlan:
    return RevalidationPlan(
        plan_id="recovery-recheck",
        input_identity={
            "recovery_identity": digest_value({"label": label}),
            "activation_identity": digest_value({"activation": label}),
            "acceptance_pass": False,
            "pass_credit": False,
        },
        phases=(
            RevalidationPhase("tracked-docs", 2.0),
            RevalidationPhase("extension-boundary", 2.0),
        ),
    )


def _callback(
    phase_id: str,
    calls: list[str],
    *,
    output_label: str,
    observed_input: str | None = None,
) -> ReadOnlyRevalidationCallback:
    def evaluate(context):
        calls.append(phase_id)
        return RevalidationObservation(
            status=RevalidationStatus.PASS,
            observed_input_digest=(
                context.expected_input_digest if observed_input is None else observed_input
            ),
            output_identity={
                "authority": phase_id,
                "output_label": output_label,
                "read_only": True,
                "acceptance_pass": False,
                "pass_credit": False,
            },
        )

    return ReadOnlyRevalidationCallback(phase_id, evaluate)


def test_heavy_revalidation_runs_bounded_read_only_phases_and_keeps_credit_false() -> None:
    plan = _plan()
    calls: list[str] = []

    receipt = revalidate_recovery(
        plan,
        (
            _callback("tracked-docs", calls, output_label="docs"),
            _callback("extension-boundary", calls, output_label="extensions"),
        ),
    )

    assert calls == ["tracked-docs", "extension-boundary"]
    assert receipt.status is RevalidationStatus.PASS
    assert receipt.next_phase_id is None
    assert len(receipt.checkpoints) == 2
    assert all(checkpoint.read_only is True for checkpoint in receipt.checkpoints)
    assert all(checkpoint.pass_credit is False for checkpoint in receipt.checkpoints)
    assert all(checkpoint.acceptance_pass is False for checkpoint in receipt.checkpoints)
    assert all(
        checkpoint.product_acceptance_pass is False
        for checkpoint in receipt.checkpoints
    )
    restored = RevalidationReceipt.from_record(receipt.to_record())
    assert restored == receipt
    report = prepare_revalidation_report(restored)
    assert report["report_authoritative"] is False
    assert report["acceptance_pass"] is False
    assert report["product_acceptance_pass"] is False
    assert report["pass_credit"] is False
    assert report["effects"] == {
        "sqlite_connections": 0,
        "projection_edits": 0,
        "filesystem_writes": 0,
        "provider_invocations": 0,
    }


def test_heavy_revalidation_resumes_only_the_exact_remaining_checkpoint_prefix() -> None:
    plan = _plan()
    calls: list[str] = []
    callbacks = (
        _callback("tracked-docs", calls, output_label="docs"),
        _callback("extension-boundary", calls, output_label="extensions"),
    )

    interrupted = revalidate_recovery(plan, callbacks, max_phases=1)
    resumed = revalidate_recovery(
        plan,
        (_callback("extension-boundary", calls, output_label="extensions"),),
        prior_receipts=interrupted.to_record(),
    )

    assert interrupted.status is RevalidationStatus.PENDING
    assert interrupted.next_phase_id == "extension-boundary"
    assert resumed.status is RevalidationStatus.PASS
    assert calls == ["tracked-docs", "extension-boundary"]
    assert resumed.checkpoints[0].to_record() == interrupted.checkpoints[0].to_record()


def test_heavy_revalidation_marks_nonmatching_restart_receipt_stale() -> None:
    old_plan = _plan("old")
    old_receipt = revalidate_recovery(
        old_plan,
        (
            _callback("tracked-docs", [], output_label="docs"),
            _callback("extension-boundary", [], output_label="extensions"),
        ),
    )

    stale = reconsolidate_revalidation(_plan("new"), (old_receipt,))

    assert stale.status is RevalidationStatus.STALE
    assert stale.checkpoints == ()
    assert stale.next_phase_id == "tracked-docs"
    assert stale.stale_receipt_digests == (old_receipt.receipt_digest,)
    assert stale.reason is not None


def test_heavy_revalidation_detects_changed_phase_input_identity() -> None:
    plan = _plan()
    changed_digest = digest_value({"changed": "after-checkpoint"})

    receipt = revalidate_recovery(
        plan,
        (
            _callback(
                "tracked-docs",
                [],
                output_label="docs",
                observed_input=changed_digest,
            ),
            _callback("extension-boundary", [], output_label="extensions"),
        ),
    )

    assert receipt.status is RevalidationStatus.CHANGED
    checkpoint = receipt.checkpoints[-1]
    assert checkpoint.input_digest != checkpoint.observed_input_digest
    report = prepare_revalidation_report(receipt)
    assert report["changed_identities"] == [
        {
            "phase_id": "tracked-docs",
            "expected_input_digest": checkpoint.input_digest,
            "observed_input_digest": changed_digest,
        }
    ]
    assert report["pass_credit"] is False


def test_reconsolidation_rejects_conflicting_checkpoint_outputs() -> None:
    plan = _plan()
    first = revalidate_recovery(
        plan,
        (
            _callback("tracked-docs", [], output_label="first-docs"),
            _callback("extension-boundary", [], output_label="extensions"),
        ),
    )
    second = revalidate_recovery(
        plan,
        (
            _callback("tracked-docs", [], output_label="second-docs"),
            _callback("extension-boundary", [], output_label="extensions"),
        ),
    )

    consolidated = reconsolidate_revalidation(plan, (first, second))

    assert consolidated.status is RevalidationStatus.CHANGED
    assert consolidated.reason is not None
    assert consolidated.checkpoints == ()
    assert consolidated.next_phase_id == "tracked-docs"


def test_terminal_changed_reconciliation_never_auto_retries_as_pending() -> None:
    plan = _plan()
    first = revalidate_recovery(
        plan,
        (
            _callback("tracked-docs", [], output_label="first-docs"),
            _callback("extension-boundary", [], output_label="extensions"),
        ),
    )
    second = revalidate_recovery(
        plan,
        (
            _callback("tracked-docs", [], output_label="second-docs"),
            _callback("extension-boundary", [], output_label="extensions"),
        ),
    )
    changed = reconsolidate_revalidation(plan, (first, second))
    calls: list[str] = []

    resumed = revalidate_recovery(
        plan,
        (
            _callback("tracked-docs", calls, output_label="third-docs"),
            _callback("extension-boundary", calls, output_label="extensions"),
        ),
        prior_receipts=changed,
    )

    assert changed.status is RevalidationStatus.CHANGED
    assert resumed.status is RevalidationStatus.CHANGED
    assert resumed.receipt_digest == changed.receipt_digest
    assert calls == []


def test_heavy_revalidation_never_opens_sqlite_or_edits_projection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    state = tmp_path / ".promin" / "state"
    state.mkdir(parents=True)
    database = state / "projection.sqlite3"
    database.write_bytes(b"do-not-open")
    before = database.read_bytes()

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("heavy revalidation touched SQLite")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    receipt = revalidate_recovery(
        _plan(),
        (
            _callback("tracked-docs", [], output_label="docs"),
            _callback("extension-boundary", [], output_label="extensions"),
        ),
    )

    assert receipt.status is RevalidationStatus.PASS
    assert database.read_bytes() == before


def test_heavy_revalidation_rejects_callback_without_explicit_read_only_declaration() -> None:
    with pytest.raises(RevalidationError, match="read_only"):
        ReadOnlyRevalidationCallback(
            "tracked-docs",
            lambda _context: None,  # type: ignore[arg-type]
            read_only=False,
        )
