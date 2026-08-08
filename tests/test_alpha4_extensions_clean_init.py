from __future__ import annotations

import os
from pathlib import Path

import pytest

from promin.canonical import digest_value
from promin.recovery import (
    CleanReinitializationIntent,
    OwnerConfirmation,
    RecoveryError,
    TrackedExtensionRoot,
    admit_clean_state,
    admit_tracked_extensions,
    validate_tracked_extension_roots,
)


def _digest(label: str) -> str:
    return digest_value({"test": "alpha4-extensions", "label": label})


def test_typed_extensions_admit_only_exact_link_free_member_closure(tmp_path: Path) -> None:
    source = tmp_path / "package"
    docs = source / ".promin" / "docs"
    docs.mkdir(parents=True)
    (docs / "CLEAN.md").write_bytes(b"clean\n")
    (docs / "AGENT_ENTRY.md").write_bytes(b"entry\n")
    roots = (
        TrackedExtensionRoot(
            root=".promin/docs",
            max_files=2,
            max_total_bytes=64,
            max_file_bytes=32,
        ),
    )

    admission = admit_tracked_extensions(source, roots)

    assert [member.path for member in admission.members] == [
        ".promin/docs/AGENT_ENTRY.md",
        ".promin/docs/CLEAN.md",
    ]
    assert admission.total_bytes == len(b"clean\n") + len(b"entry\n")
    assert len(admission.admission_digest) == 64
    assert admission.to_record()["link_policy"] == "reject-links-and-reparse-points"


@pytest.mark.parametrize(
    "root",
    [
        ".promin",
        ".promin/init",
        ".promin/state",
        ".promin/providers",
        ".promin/evidence",
        ".promin/cache",
        ".promin/locks",
        ".promin/leases",
        ".promin/portable",
        ".promin-host/recovery",
    ],
)
def test_operational_and_host_local_extensions_are_rejected(root: str) -> None:
    with pytest.raises(RecoveryError):
        TrackedExtensionRoot(
            root=root,
            max_files=1,
            max_total_bytes=1,
            max_file_bytes=1,
        )


def test_extension_roots_reject_nested_and_case_colliding_authority() -> None:
    docs = TrackedExtensionRoot(
        root=".promin/docs",
        max_files=2,
        max_total_bytes=64,
        max_file_bytes=64,
    )
    nested = TrackedExtensionRoot(
        root=".promin/docs/uk",
        max_files=2,
        max_total_bytes=64,
        max_file_bytes=64,
    )
    external_docs = TrackedExtensionRoot(
        root="docs",
        max_files=3,
        max_total_bytes=64,
        max_file_bytes=64,
    )
    external_docs_case_variant = TrackedExtensionRoot(
        root="DOCS",
        max_files=3,
        max_total_bytes=64,
        max_file_bytes=64,
    )

    with pytest.raises(RecoveryError, match="overlap"):
        validate_tracked_extension_roots((docs, nested))
    with pytest.raises(RecoveryError, match="case folding"):
        validate_tracked_extension_roots((external_docs, external_docs_case_variant))


def test_extension_byte_budget_is_enforced_before_clean_state_admission(tmp_path: Path) -> None:
    source = tmp_path / "package"
    docs = source / ".promin" / "docs"
    docs.mkdir(parents=True)
    (docs / "large.md").write_bytes(b"too-large")

    with pytest.raises(RecoveryError, match="byte limit"):
        admit_tracked_extensions(
            source,
            (
                TrackedExtensionRoot(
                    root=".promin/docs",
                    max_files=1,
                    max_total_bytes=3,
                    max_file_bytes=3,
                ),
            ),
        )


def test_clean_state_admission_is_non_authoritative_and_grants_no_old_credit(
    tmp_path: Path,
) -> None:
    source = tmp_path / "package"
    docs = source / ".promin" / "docs"
    docs.mkdir(parents=True)
    (docs / "CLEAN.md").write_bytes(b"clean\n")
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
            confirmation_id="confirmation:clean",
            intent_digest=intent.intent_digest,
            confirmed_at_ns=1,
        ),
        extensions,
    )

    record = admission.to_record()
    assert record["state_migration_supported"] is False
    assert record["previous_progress_replay_supported"] is False
    assert record["previous_progress_imported"] is False
    assert record["acceptance_pass"] is False
    assert record["pass_credit"] is False
    assert record["product_credit"] is False
    assert record["authoritative"] is False


def test_extension_symbolic_link_is_rejected_when_host_can_create_one(tmp_path: Path) -> None:
    source = tmp_path / "package"
    docs = source / ".promin" / "docs"
    docs.mkdir(parents=True)
    outside = tmp_path / "outside.md"
    outside.write_bytes(b"outside\n")
    link = docs / "linked.md"
    try:
        os.symlink(outside, link)
    except OSError:
        pytest.skip("host does not permit test symbolic links")

    with pytest.raises(RecoveryError, match="links are forbidden"):
        admit_tracked_extensions(
            source,
            (
                TrackedExtensionRoot(
                    root=".promin/docs",
                    max_files=2,
                    max_total_bytes=64,
                    max_file_bytes=64,
                ),
            ),
        )
