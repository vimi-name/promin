from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from promin.canonical import digest_value
from promin.recovery import (
    CleanReinitializationIntent,
    CleanReinitializationPhase,
    CleanReinitializationTransaction,
    OwnerConfirmation,
    PublishedCleanReinitialization,
    RecoveryError,
    RecoveryIntentMismatch,
    TrackedExtensionRoot,
    admit_clean_state,
    admit_tracked_extensions,
    reuse_verified_clean_reinitialization,
)
from promin.writer_identity import (
    ProcessObservation,
    WriterIdentity,
    WriterIdentityError,
    WriterLiveness,
    classify_writer_liveness,
    create_current_writer_identity,
    observe_process,
    require_recovery_permitted,
)


def _digest(label: str) -> str:
    return digest_value({"test": "alpha4-recovery-locks", "label": label})


def _extension_admission(tmp_path: Path):
    source = tmp_path / "package-seeds"
    docs = source / ".promin" / "docs"
    docs.mkdir(parents=True)
    (docs / "CLEAN.md").write_bytes(b"clean reinitialization seed\n")
    return admit_tracked_extensions(
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


def _admission(tmp_path: Path, *, profile_id: str = "minimal"):
    extensions = _extension_admission(tmp_path)
    intent = CleanReinitializationIntent(
        project_identity=_digest("project"),
        package_digest=_digest("package"),
        profile_id=profile_id,
        extension_admission_digest=extensions.admission_digest,
    )
    confirmation = OwnerConfirmation(
        owner_id="owner:local",
        confirmation_id="confirmation:clean-init",
        intent_digest=intent.intent_digest,
        confirmed_at_ns=1,
    )
    return admit_clean_state(intent, confirmation, extensions), intent


def test_exact_existing_intent_reuse_rejects_mismatch_before_verification(
    tmp_path: Path,
) -> None:
    _admitted, requested = _admission(tmp_path / "requested", profile_id="minimal")
    _other_admitted, other = _admission(tmp_path / "other", profile_id="diagnostic")
    existing = PublishedCleanReinitialization(
        intent_digest=other.intent_digest,
        package_digest=other.package_digest,
        extension_admission_digest=other.extension_admission_digest,
        activation_digest=_digest("other-activation"),
    )
    calls: list[PublishedCleanReinitialization] = []

    with pytest.raises(RecoveryIntentMismatch, match="does not match"):
        reuse_verified_clean_reinitialization(
            requested,
            existing,
            verifier=lambda value: calls.append(value) is None,
        )

    assert calls == []


def test_exact_existing_intent_reuses_only_a_verified_matching_result(
    tmp_path: Path,
) -> None:
    _admitted, intent = _admission(tmp_path / "requested")
    existing = PublishedCleanReinitialization(
        intent_digest=intent.intent_digest,
        package_digest=intent.package_digest,
        extension_admission_digest=intent.extension_admission_digest,
        activation_digest=_digest("activation"),
    )
    calls: list[PublishedCleanReinitialization] = []

    reused = reuse_verified_clean_reinitialization(
        intent,
        existing,
        verifier=lambda value: calls.append(value) is None,
    )

    assert reused is existing
    assert calls == [existing]


def test_clean_state_requires_owner_confirmation_bound_to_exact_intent(tmp_path: Path) -> None:
    extensions = _extension_admission(tmp_path / "package")
    requested = CleanReinitializationIntent(
        project_identity=_digest("project"),
        package_digest=_digest("package"),
        profile_id="minimal",
        extension_admission_digest=extensions.admission_digest,
    )
    other = CleanReinitializationIntent(
        project_identity=_digest("project"),
        package_digest=_digest("package"),
        profile_id="standard",
        extension_admission_digest=extensions.admission_digest,
    )
    wrong_confirmation = OwnerConfirmation(
        owner_id="owner:local",
        confirmation_id="confirmation:other-intent",
        intent_digest=other.intent_digest,
        confirmed_at_ns=1,
    )

    with pytest.raises(RecoveryIntentMismatch, match="owner confirmation"):
        admit_clean_state(requested, wrong_confirmation, extensions)
    with pytest.raises(RecoveryError, match="explicit owner approval"):
        OwnerConfirmation(
            owner_id="owner:local",
            confirmation_id="confirmation:declined",
            intent_digest=requested.intent_digest,
            confirmed_at_ns=1,
            approved=False,
        )


def test_writer_liveness_distinguishes_dead_reused_live_and_expired_processes() -> None:
    identity = WriterIdentity(
        writer_id="writer:alpha4",
        pid=771,
        process_birth_token="windows-filetime:100",
        activation_digest="a" * 64,
        intent_digest="b" * 64,
        lease_started_ns=100,
        lease_expires_ns=200,
    )

    dead = classify_writer_liveness(
        identity,
        now_ns=150,
        observer=lambda pid: ProcessObservation(pid=pid, exists=False),
    )
    reused = classify_writer_liveness(
        identity,
        now_ns=150,
        observer=lambda pid: ProcessObservation(
            pid=pid,
            exists=True,
            process_birth_token="windows-filetime:101",
        ),
    )
    live = classify_writer_liveness(
        identity,
        now_ns=150,
        observer=lambda pid: ProcessObservation(
            pid=pid,
            exists=True,
            process_birth_token="windows-filetime:100",
        ),
    )
    expired = classify_writer_liveness(
        identity,
        now_ns=201,
        observer=lambda pid: ProcessObservation(
            pid=pid,
            exists=True,
            process_birth_token="windows-filetime:100",
        ),
    )

    assert dead.status is WriterLiveness.INACTIVE
    assert reused.status is WriterLiveness.INACTIVE
    assert dead.recovery_permitted and reused.recovery_permitted
    assert live.status is WriterLiveness.LIVE
    assert expired.status is WriterLiveness.LEASE_EXPIRED
    with pytest.raises(WriterIdentityError, match="writer recovery is blocked"):
        require_recovery_permitted(live)
    with pytest.raises(WriterIdentityError, match="writer recovery is blocked"):
        require_recovery_permitted(expired)


def test_writer_identity_record_is_exact_and_digest_bound() -> None:
    identity = WriterIdentity(
        writer_id="writer:record",
        pid=771,
        process_birth_token="windows-filetime:100",
        activation_digest="a" * 64,
        intent_digest="b" * 64,
        lease_started_ns=100,
        lease_expires_ns=200,
    )
    record = identity.to_record()

    assert WriterIdentity.from_record(record) == identity
    changed = {**record, "lease_expires_ns": 201}
    with pytest.raises(WriterIdentityError, match="digest"):
        WriterIdentity.from_record(changed)
    with pytest.raises(WriterIdentityError, match="inexact field set"):
        WriterIdentity.from_record({**record, "unexpected": True})


def test_current_host_writer_identity_uses_a_strong_birth_identity_when_available() -> None:
    if os.name != "nt" and not sys.platform.startswith("linux"):
        pytest.skip("this layer deliberately has no strong process-birth probe on this host")

    identity = create_current_writer_identity(
        writer_id="writer:current-host",
        activation_digest="a" * 64,
        intent_digest="b" * 64,
        lease_duration_ns=1_000_000_000,
    )
    observation = observe_process(os.getpid())
    report = classify_writer_liveness(
        identity,
        now_ns=identity.lease_started_ns,
        observer=observe_process,
    )

    assert observation.exists is True
    assert observation.process_birth_token == identity.process_birth_token
    assert report.status is WriterLiveness.LIVE


def test_full_root_quarantine_rolls_back_without_copying_prior_state(tmp_path: Path) -> None:
    project = tmp_path / "project"
    control = project / ".promin"
    (control / "init").mkdir(parents=True)
    (control / "state").mkdir()
    (control / "init" / "activation.json").write_bytes(b"old-activation\n")
    (control / "state" / "progress.json").write_bytes(b"old-progress\n")
    admission, _intent = _admission(tmp_path / "package")
    no_writer = classify_writer_liveness(None)

    transaction = CleanReinitializationTransaction(project, admission, no_writer)
    receipt = transaction.quarantine_previous_root()

    assert receipt is not None
    assert transaction.phase is CleanReinitializationPhase.QUARANTINED
    assert not control.exists()
    assert receipt.quarantine_root.parent == project / ".promin-host" / "recovery"
    assert (receipt.quarantine_root / "init" / "activation.json").read_bytes() == b"old-activation\n"
    assert (receipt.quarantine_root / "state" / "progress.json").read_bytes() == b"old-progress\n"

    transaction.rollback_before_publication()

    assert transaction.phase is CleanReinitializationPhase.ROLLED_BACK
    assert (control / "init" / "activation.json").read_bytes() == b"old-activation\n"
    assert (control / "state" / "progress.json").read_bytes() == b"old-progress\n"
    assert not receipt.quarantine_root.exists()


def test_rollback_refuses_to_replace_a_new_active_control_root(tmp_path: Path) -> None:
    project = tmp_path / "project"
    old_control = project / ".promin"
    (old_control / "state").mkdir(parents=True)
    (old_control / "state" / "old-progress.json").write_bytes(b"old\n")
    admission, _intent = _admission(tmp_path / "package")
    transaction = CleanReinitializationTransaction(
        project,
        admission,
        classify_writer_liveness(None),
    )
    receipt = transaction.quarantine_previous_root()
    assert receipt is not None

    new_control = project / ".promin"
    (new_control / "init").mkdir(parents=True)
    (new_control / "init" / "activation.json").write_bytes(b"new\n")

    with pytest.raises(RecoveryError, match="active root before rollback"):
        transaction.rollback_before_publication()

    assert transaction.phase is CleanReinitializationPhase.QUARANTINED
    assert (receipt.quarantine_root / "state" / "old-progress.json").read_bytes() == b"old\n"
    assert (new_control / "init" / "activation.json").read_bytes() == b"new\n"


def test_clean_reinitialization_rejects_extensions_sourced_from_old_control_root(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    old_docs = project / ".promin" / "docs"
    old_docs.mkdir(parents=True)
    (old_docs / "OLD.md").write_bytes(b"old control documentation\n")
    extensions = admit_tracked_extensions(
        project,
        (
            TrackedExtensionRoot(
                root=".promin/docs",
                max_files=1,
                max_total_bytes=128,
                max_file_bytes=128,
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
            confirmation_id="confirmation:old-source",
            intent_digest=intent.intent_digest,
            confirmed_at_ns=1,
        ),
        extensions,
    )
    transaction = CleanReinitializationTransaction(
        project,
        admission,
        classify_writer_liveness(None),
    )

    with pytest.raises(RecoveryError, match="prior active control root"):
        transaction.quarantine_previous_root()

    assert (old_docs / "OLD.md").read_bytes() == b"old control documentation\n"


def test_clean_reinitialization_rechecks_extension_bytes_before_quarantine(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    control = project / ".promin"
    (control / "state").mkdir(parents=True)
    (control / "state" / "old-progress.json").write_bytes(b"old\n")
    source = tmp_path / "package"
    docs = source / ".promin" / "docs"
    docs.mkdir(parents=True)
    selected = docs / "CLEAN.md"
    selected.write_bytes(b"before\n")
    extensions = admit_tracked_extensions(
        source,
        (
            TrackedExtensionRoot(
                root=".promin/docs",
                max_files=1,
                max_total_bytes=64,
                max_file_bytes=64,
            ),
        ),
    )
    selected.write_bytes(b"after\n")
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
            confirmation_id="confirmation:changed-source",
            intent_digest=intent.intent_digest,
            confirmed_at_ns=1,
        ),
        extensions,
    )

    with pytest.raises(RecoveryError, match="closure changed"):
        CleanReinitializationTransaction(
            project,
            admission,
            classify_writer_liveness(None),
        ).quarantine_previous_root()

    assert (control / "state" / "old-progress.json").read_bytes() == b"old\n"


def test_live_writer_blocks_destructive_clean_transaction(tmp_path: Path) -> None:
    admission, _intent = _admission(tmp_path / "package")
    identity = WriterIdentity(
        writer_id="writer:active",
        pid=771,
        process_birth_token="windows-filetime:100",
        activation_digest="a" * 64,
        intent_digest="b" * 64,
        lease_started_ns=100,
        lease_expires_ns=200,
    )
    live = classify_writer_liveness(
        identity,
        now_ns=150,
        observer=lambda pid: ProcessObservation(
            pid=pid,
            exists=True,
            process_birth_token="windows-filetime:100",
        ),
    )

    with pytest.raises(RecoveryError, match="writer recovery is blocked"):
        CleanReinitializationTransaction(tmp_path / "project", admission, live)


def test_inspection_and_owner_admission_are_read_only_until_transaction_is_started(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    control = project / ".promin" / "state"
    control.mkdir(parents=True)
    progress = control / "progress.json"
    progress.write_bytes(b"existing progress must remain untouched\n")

    admission, intent = _admission(tmp_path / "package")
    before = progress.read_bytes()

    # Admission is the inspect/authorization boundary; it must not quarantine,
    # clean, or otherwise rewrite the active project root.
    assert admission.intent.intent_digest == intent.intent_digest
    assert progress.read_bytes() == before
    assert not (project / ".promin-host").exists()

    wrong_intent = CleanReinitializationIntent(
        project_identity=intent.project_identity,
        package_digest=intent.package_digest,
        profile_id="diagnostic",
        extension_admission_digest=intent.extension_admission_digest,
    )
    with pytest.raises(RecoveryIntentMismatch, match="owner confirmation"):
        admit_clean_state(
            wrong_intent,
            admission.owner_confirmation,
            admission.extension_admission,
        )
    assert progress.read_bytes() == before

    # Even an exact owner-bound admission remains blocked while a writer is live.
    live = WriterIdentity(
        writer_id="writer:owner-gate",
        pid=771,
        process_birth_token="windows-filetime:100",
        activation_digest="a" * 64,
        intent_digest=intent.intent_digest,
        lease_started_ns=100,
        lease_expires_ns=200,
    )
    liveness = classify_writer_liveness(
        live,
        now_ns=150,
        observer=lambda pid: ProcessObservation(
            pid=pid,
            exists=True,
            process_birth_token="windows-filetime:100",
        ),
    )
    with pytest.raises(RecoveryError, match="writer recovery is blocked"):
        CleanReinitializationTransaction(project, admission, liveness)
    assert progress.read_bytes() == before
