from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

import promin.recovery as recovery_module
from promin.canonical import digest_value
from promin.recovery import (
    CleanReinitializationIntent,
    CleanReinitializationPhase,
    CleanReinitializationRestartOutcome,
    OwnerConfirmation,
    PublishedCleanReinitialization,
    RecoveryError,
    RecoveryInterruption,
    RecoveryIntentMismatch,
    TrackedExtensionRoot,
    admit_clean_state,
    admit_tracked_extensions,
    run_bounded_clean_reinitialization,
)
from promin.writer_identity import (
    ProcessObservation,
    WriterIdentity,
    WriterLiveness,
    classify_writer_liveness,
)


def _digest(label: str) -> str:
    return digest_value({"test": "heavy-recovery-stress", "label": label})


def _admission(workspace: Path):
    source = workspace / "package"
    docs = source / ".promin" / "docs"
    docs.mkdir(parents=True)
    (docs / "CLEAN.md").write_bytes(b"bounded clean recovery extension\n")
    extensions = admit_tracked_extensions(
        source,
        (
            TrackedExtensionRoot(
                root=".promin/docs",
                max_files=4,
                max_total_bytes=1024,
                max_file_bytes=512,
            ),
        ),
    )
    intent = CleanReinitializationIntent(
        project_identity=_digest("project"),
        package_digest=_digest("package"),
        profile_id="minimal",
        extension_admission_digest=extensions.admission_digest,
    )
    admission = admit_clean_state(
        intent,
        OwnerConfirmation(
            owner_id="owner:local",
            confirmation_id="confirmation:heavy-recovery",
            intent_digest=intent.intent_digest,
            confirmed_at_ns=1,
        ),
        extensions,
    )
    return admission, intent, source


def _old_control(project: Path) -> None:
    state = project / ".promin" / "state"
    state.mkdir(parents=True)
    (state / "old-progress.json").write_bytes(b"old progress must never replay\n")
    receipts = project / ".promin" / "receipts"
    receipts.mkdir()
    (receipts / "old-receipt.json").write_bytes(b"old receipt must never replay\n")


def _published_result(intent: CleanReinitializationIntent) -> PublishedCleanReinitialization:
    return PublishedCleanReinitialization(
        intent_digest=intent.intent_digest,
        package_digest=intent.package_digest,
        extension_admission_digest=intent.extension_admission_digest,
        activation_digest=_digest("fresh-activation"),
    )


def _fresh_control(project: Path) -> None:
    activation = project / ".promin" / "init" / "activation.json"
    activation.parent.mkdir(parents=True)
    activation.write_bytes(b"fresh activation only\n")


def _permitted_liveness():
    return classify_writer_liveness(None)


def test_many_interrupted_phases_restore_full_root_before_a_bounded_restart(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _old_control(project)
    admission, intent, _source = _admission(tmp_path)
    interruptions = (
        "standard-init",
        "extension-overlay",
        "task-import",
        "minimal-postcheck",
        "activation-verify",
        "activation-publish",
    )
    observed_ordinals: list[int] = []

    def perform(transaction, ordinal: int) -> PublishedCleanReinitialization:
        observed_ordinals.append(ordinal)
        assert transaction.phase is CleanReinitializationPhase.QUARANTINED
        assert not (project / ".promin").exists()
        if ordinal <= len(interruptions):
            receipt = transaction.receipt
            assert receipt is not None
            assert (
                receipt.quarantine_root / "state" / "old-progress.json"
            ).read_bytes() == b"old progress must never replay\n"
            raise RecoveryInterruption(interruptions[ordinal - 1])
        _fresh_control(project)
        return _published_result(intent)

    report = run_bounded_clean_reinitialization(
        project,
        admission,
        _permitted_liveness(),
        max_attempts=len(interruptions) + 1,
        existing=None,
        verifier=lambda result: result.activation_digest == _digest("fresh-activation"),
        attempt=perform,
    )

    assert observed_ordinals == list(range(1, len(interruptions) + 2))
    assert report.terminal_outcome is CleanReinitializationRestartOutcome.PUBLISHED
    assert [item.outcome for item in report.attempts[:-1]] == [
        CleanReinitializationRestartOutcome.INTERRUPTED_ROLLED_BACK
    ] * len(interruptions)
    assert [item.stage for item in report.attempts[:-1]] == list(interruptions)
    assert report.attempts[-1].transaction_phase is CleanReinitializationPhase.PUBLISHED
    assert (project / ".promin" / "init" / "activation.json").read_bytes() == (
        b"fresh activation only\n"
    )
    assert not (project / ".promin" / "state").exists()
    assert not (project / ".promin" / "receipts").exists()
    quarantined = project / ".promin-host" / "recovery" / intent.intent_digest
    assert (
        quarantined / "state" / "old-progress.json"
    ).read_bytes() == b"old progress must never replay\n"
    record = report.to_record()
    assert record["state_migration_supported"] is False
    assert record["previous_progress_replay_supported"] is False
    assert record["previous_progress_imported"] is False
    assert record["acceptance_pass"] is False
    assert record["pass_credit"] is False
    assert record["product_credit"] is False
    assert record["authoritative"] is False


def test_restart_cap_returns_a_stable_no_credit_report_and_restores_old_root(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _old_control(project)
    admission, intent, _source = _admission(tmp_path)

    def interrupted(_transaction, _ordinal: int) -> PublishedCleanReinitialization:
        raise RecoveryInterruption("task-import")

    report = run_bounded_clean_reinitialization(
        project,
        admission,
        _permitted_liveness(),
        max_attempts=5,
        existing=None,
        verifier=lambda _result: True,
        attempt=interrupted,
    )

    assert report.terminal_outcome is CleanReinitializationRestartOutcome.RESTART_LIMIT_REACHED
    assert report.restart_limit_reached is True
    assert report.published is False
    assert len(report.attempts) == 5
    assert all(
        item.outcome is CleanReinitializationRestartOutcome.INTERRUPTED_ROLLED_BACK
        and item.stage == "task-import"
        and item.transaction_phase is CleanReinitializationPhase.ROLLED_BACK
        for item in report.attempts
    )
    assert (
        project / ".promin" / "state" / "old-progress.json"
    ).read_bytes() == b"old progress must never replay\n"
    assert not (project / ".promin-host" / "recovery" / intent.intent_digest).exists()
    record = report.to_record()
    assert record["published"] is False
    assert record["restart_limit_reached"] is True
    assert record["acceptance_pass"] is False
    assert record["pass_credit"] is False


def test_interruption_after_a_new_root_stops_without_a_second_destructive_attempt(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _old_control(project)
    admission, intent, _source = _admission(tmp_path)
    callback_calls: list[int] = []

    def leaves_new_root(_transaction, ordinal: int) -> PublishedCleanReinitialization:
        callback_calls.append(ordinal)
        _fresh_control(project)
        raise RecoveryInterruption("activation-verify")

    report = run_bounded_clean_reinitialization(
        project,
        admission,
        _permitted_liveness(),
        max_attempts=8,
        existing=None,
        verifier=lambda _result: True,
        attempt=leaves_new_root,
    )

    assert report.terminal_outcome is CleanReinitializationRestartOutcome.ROLLBACK_BLOCKED
    assert len(report.attempts) == 1
    assert report.attempts[0].stage == "rollback"
    assert callback_calls == [1]
    assert (project / ".promin" / "init" / "activation.json").read_bytes() == (
        b"fresh activation only\n"
    )
    quarantined = project / ".promin-host" / "recovery" / intent.intent_digest
    assert (
        quarantined / "state" / "old-progress.json"
    ).read_bytes() == b"old progress must never replay\n"
    assert report.to_record()["acceptance_pass"] is False


def test_untyped_callback_failure_rolls_back_once_without_retrying(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _old_control(project)
    admission, _intent, _source = _admission(tmp_path)
    callback_calls: list[int] = []

    def fails_without_restart(_transaction, ordinal: int) -> PublishedCleanReinitialization:
        callback_calls.append(ordinal)
        raise RecoveryError("ordinary pre-publication failure")

    report = run_bounded_clean_reinitialization(
        project,
        admission,
        _permitted_liveness(),
        max_attempts=8,
        existing=None,
        verifier=lambda _result: True,
        attempt=fails_without_restart,
    )

    assert (
        report.terminal_outcome
        is CleanReinitializationRestartOutcome.OPERATION_FAILED_ROLLED_BACK
    )
    assert len(report.attempts) == 1
    assert report.attempts[0].stage == "operation"
    assert report.attempts[0].transaction_phase is CleanReinitializationPhase.ROLLED_BACK
    assert callback_calls == [1]
    assert (
        project / ".promin" / "state" / "old-progress.json"
    ).read_bytes() == b"old progress must never replay\n"
    assert not (project / ".promin-host" / "recovery" / admission.intent.intent_digest).exists()


def test_exact_existing_result_is_reused_before_any_new_attempt_or_mutation(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _old_control(project)
    admission, intent, _source = _admission(tmp_path)
    existing = _published_result(intent)
    callback_calls: list[int] = []

    report = run_bounded_clean_reinitialization(
        project,
        admission,
        _permitted_liveness(),
        max_attempts=3,
        existing=existing,
        verifier=lambda value: value is existing,
        attempt=lambda _transaction, ordinal: callback_calls.append(ordinal),
    )

    assert report.terminal_outcome is CleanReinitializationRestartOutcome.REUSED_EXISTING
    assert report.published_result is existing
    assert callback_calls == []
    assert (
        project / ".promin" / "state" / "old-progress.json"
    ).read_bytes() == b"old progress must never replay\n"
    assert not (project / ".promin-host").exists()

    other = CleanReinitializationIntent(
        project_identity=intent.project_identity,
        package_digest=intent.package_digest,
        profile_id="diagnostic",
        extension_admission_digest=intent.extension_admission_digest,
    )
    wrong_existing = PublishedCleanReinitialization(
        intent_digest=other.intent_digest,
        package_digest=other.package_digest,
        extension_admission_digest=other.extension_admission_digest,
        activation_digest=_digest("other-activation"),
    )
    with pytest.raises(RecoveryIntentMismatch, match="does not match"):
        run_bounded_clean_reinitialization(
            project,
            admission,
            _permitted_liveness(),
            max_attempts=3,
            existing=wrong_existing,
            verifier=lambda _value: (_ for _ in ()).throw(AssertionError("not called")),
            attempt=lambda _transaction, _ordinal: (_ for _ in ()).throw(
                AssertionError("not called")
            ),
        )
    assert callback_calls == []
    assert (project / ".promin" / "state" / "old-progress.json").exists()


def test_extension_mutation_blocks_the_restart_before_quarantine(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _old_control(project)
    admission, _intent, source = _admission(tmp_path)
    selected = source / ".promin" / "docs" / "CLEAN.md"
    selected.write_bytes(b"mutated extension must block recovery\n")
    callback_calls: list[int] = []

    report = run_bounded_clean_reinitialization(
        project,
        admission,
        _permitted_liveness(),
        max_attempts=4,
        existing=None,
        verifier=lambda _result: True,
        attempt=lambda _transaction, ordinal: callback_calls.append(ordinal),
    )

    assert report.terminal_outcome is CleanReinitializationRestartOutcome.ADMISSION_BLOCKED
    assert report.attempts[0].stage == "quarantine"
    assert report.attempts[0].transaction_phase is CleanReinitializationPhase.ADMITTED
    assert callback_calls == []
    assert (
        project / ".promin" / "state" / "old-progress.json"
    ).read_bytes() == b"old progress must never replay\n"
    assert not (project / ".promin-host").exists()


def test_extension_mutation_after_preflight_blocks_the_reserved_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _old_control(project)
    admission, _intent, source = _admission(tmp_path)
    selected = source / ".promin" / "docs" / "CLEAN.md"
    original_verify = recovery_module.verify_tracked_extension_admission
    verification_calls = 0

    def verify_then_mutate(value):
        nonlocal verification_calls
        verification_calls += 1
        observed = original_verify(value)
        if verification_calls == 1:
            selected.write_bytes(b"changed after first closure verification\n")
        return observed

    monkeypatch.setattr(
        recovery_module,
        "verify_tracked_extension_admission",
        verify_then_mutate,
    )
    report = run_bounded_clean_reinitialization(
        project,
        admission,
        _permitted_liveness(),
        max_attempts=2,
        existing=None,
        verifier=lambda _result: True,
        attempt=lambda _transaction, _ordinal: (_ for _ in ()).throw(
            AssertionError("attempt must not run")
        ),
    )

    assert verification_calls == 2
    assert report.terminal_outcome is CleanReinitializationRestartOutcome.ADMISSION_BLOCKED
    assert report.attempts[0].stage == "quarantine"
    assert (
        project / ".promin" / "state" / "old-progress.json"
    ).read_bytes() == b"old progress must never replay\n"
    assert not (project / ".promin-host" / "recovery" / admission.intent.intent_digest).exists()


def test_writer_liveness_matrix_is_deterministic_under_repeated_recovery_load() -> None:
    identity = WriterIdentity(
        writer_id="writer:heavy-recovery",
        pid=771,
        process_birth_token="windows-filetime:100",
        activation_digest="a" * 64,
        intent_digest="b" * 64,
        lease_started_ns=100,
        lease_expires_ns=200,
    )
    matrix: tuple[
        tuple[
            str,
            WriterIdentity | None,
            int,
            Callable[[int], ProcessObservation],
            WriterLiveness,
            bool,
        ],
        ...,
    ] = (
        (
            "absent",
            None,
            150,
            lambda pid: ProcessObservation(pid=pid, exists=False),
            WriterLiveness.ABSENT,
            True,
        ),
        (
            "dead",
            identity,
            150,
            lambda pid: ProcessObservation(pid=pid, exists=False),
            WriterLiveness.INACTIVE,
            True,
        ),
        (
            "pid-reused",
            identity,
            150,
            lambda pid: ProcessObservation(
                pid=pid,
                exists=True,
                process_birth_token="windows-filetime:101",
            ),
            WriterLiveness.INACTIVE,
            True,
        ),
        (
            "live",
            identity,
            150,
            lambda pid: ProcessObservation(
                pid=pid,
                exists=True,
                process_birth_token="windows-filetime:100",
            ),
            WriterLiveness.LIVE,
            False,
        ),
        (
            "expired-live",
            identity,
            201,
            lambda pid: ProcessObservation(
                pid=pid,
                exists=True,
                process_birth_token="windows-filetime:100",
            ),
            WriterLiveness.LEASE_EXPIRED,
            False,
        ),
        (
            "denied",
            identity,
            150,
            lambda pid: ProcessObservation(
                pid=pid,
                exists=None,
                inspection_error="windows-open-process:5",
            ),
            WriterLiveness.INDETERMINATE,
            False,
        ),
        (
            "birth-unavailable",
            identity,
            150,
            lambda pid: ProcessObservation(pid=pid, exists=True),
            WriterLiveness.INDETERMINATE,
            False,
        ),
    )

    baseline: dict[str, dict[str, object]] = {}
    for _round in range(32):
        for name, persisted, now_ns, observer, expected, permitted in matrix:
            report = classify_writer_liveness(
                persisted,
                now_ns=now_ns,
                observer=observer,
            )
            assert report.status is expected
            assert report.recovery_permitted is permitted
            record = report.to_record()
            if _round == 0:
                baseline[name] = record
            else:
                assert record == baseline[name]


def test_clean_attempt_entry_allows_only_absent_or_inactive_writer_matrix(
    tmp_path: Path,
) -> None:
    admission, _intent, _source = _admission(tmp_path)
    identity = WriterIdentity(
        writer_id="writer:entry-matrix",
        pid=771,
        process_birth_token="windows-filetime:100",
        activation_digest="a" * 64,
        intent_digest="b" * 64,
        lease_started_ns=100,
        lease_expires_ns=200,
    )
    matrix = (
        (
            "absent",
            classify_writer_liveness(None),
            CleanReinitializationRestartOutcome.RESTART_LIMIT_REACHED,
        ),
        (
            "dead",
            classify_writer_liveness(
                identity,
                now_ns=150,
                observer=lambda pid: ProcessObservation(pid=pid, exists=False),
            ),
            CleanReinitializationRestartOutcome.RESTART_LIMIT_REACHED,
        ),
        (
            "pid-reused",
            classify_writer_liveness(
                identity,
                now_ns=150,
                observer=lambda pid: ProcessObservation(
                    pid=pid,
                    exists=True,
                    process_birth_token="windows-filetime:101",
                ),
            ),
            CleanReinitializationRestartOutcome.RESTART_LIMIT_REACHED,
        ),
        (
            "live",
            classify_writer_liveness(
                identity,
                now_ns=150,
                observer=lambda pid: ProcessObservation(
                    pid=pid,
                    exists=True,
                    process_birth_token="windows-filetime:100",
                ),
            ),
            CleanReinitializationRestartOutcome.ADMISSION_BLOCKED,
        ),
        (
            "expired-live",
            classify_writer_liveness(
                identity,
                now_ns=201,
                observer=lambda pid: ProcessObservation(
                    pid=pid,
                    exists=True,
                    process_birth_token="windows-filetime:100",
                ),
            ),
            CleanReinitializationRestartOutcome.ADMISSION_BLOCKED,
        ),
        (
            "indeterminate",
            classify_writer_liveness(
                identity,
                now_ns=150,
                observer=lambda pid: ProcessObservation(
                    pid=pid,
                    exists=None,
                    inspection_error="windows-open-process:5",
                ),
            ),
            CleanReinitializationRestartOutcome.ADMISSION_BLOCKED,
        ),
    )

    for label, liveness, expected_outcome in matrix:
        project = tmp_path / "projects" / label
        project.mkdir(parents=True)
        _old_control(project)
        callback_calls: list[int] = []

        def interrupted(_transaction, ordinal: int) -> PublishedCleanReinitialization:
            callback_calls.append(ordinal)
            raise RecoveryInterruption("standard-init")

        report = run_bounded_clean_reinitialization(
            project,
            admission,
            liveness,
            max_attempts=1,
            existing=None,
            verifier=lambda _result: True,
            attempt=interrupted,
        )

        assert report.terminal_outcome is expected_outcome
        assert callback_calls == ([1] if liveness.recovery_permitted else [])
        assert (
            project / ".promin" / "state" / "old-progress.json"
        ).read_bytes() == b"old progress must never replay\n"


def test_restart_report_is_byte_deterministic_across_independent_real_roots(
    tmp_path: Path,
) -> None:
    records: list[dict[str, object]] = []
    for label in ("first", "second"):
        workspace = tmp_path / label
        project = workspace / "project"
        project.mkdir(parents=True)
        _old_control(project)
        admission, intent, _source = _admission(workspace)

        def perform(_transaction, ordinal: int) -> PublishedCleanReinitialization:
            if ordinal < 3:
                raise RecoveryInterruption("minimal-postcheck")
            _fresh_control(project)
            return _published_result(intent)

        report = run_bounded_clean_reinitialization(
            project,
            admission,
            _permitted_liveness(),
            max_attempts=3,
            existing=None,
            verifier=lambda result: result.activation_digest == _digest("fresh-activation"),
            attempt=perform,
        )
        records.append(report.to_record())

    assert records[0] == records[1]
