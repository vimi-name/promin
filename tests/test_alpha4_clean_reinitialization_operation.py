from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from promin.canonical import canonical_bytes, digest_value
from promin.clean_reinitialization import (
    CleanReinitializationOperationError,
    CleanReinitializationState,
    StandardInitializationPublication,
    clean_reinitialize_project,
    prepare_clean_reinitialization,
)
from promin.recovery import OwnerConfirmation, PublishedCleanReinitialization


def _digest(label: str) -> str:
    return digest_value({"test": "alpha4-clean-reinitialization-operation", "label": label})


def _write_canonical(path: Path, value: object) -> None:
    path.write_bytes(canonical_bytes(value))


def _make_package(tmp_path: Path, *, docs_payload: bytes) -> Path:
    package = tmp_path / "portable-package"
    docs = package / "seeds" / "docs"
    docs.mkdir(parents=True)
    (docs / "CLEAN.md").write_bytes(docs_payload)
    member = {
        "source_path": "seeds/docs/CLEAN.md",
        "target_path": ".promin/docs/CLEAN.md",
        "member_class": "portable-doc",
        "bytes": len(docs_payload),
        "sha256": hashlib.sha256(docs_payload).hexdigest(),
        "mode": 0o644,
    }
    base = {
        "schema": "promin.project-package.v1",
        "package_id": "portable-alpha4",
        "package_version": "1.0.0-alpha.4",
        "standard_version": "1.0.0-alpha.4",
        "default_profile": "minimal",
        "profiles": ["minimal"],
        "tracked_extension_roots": [".promin/docs"],
        "operational_roots": [
            ".promin/cache",
            ".promin/evidence",
            ".promin/init",
            ".promin/leases",
            ".promin/locks",
            ".promin/providers",
            ".promin/state",
        ],
        "state_migration_supported": False,
        "previous_progress_replay_supported": False,
    }
    content = {
        "schema": "promin.project-package-content.v1",
        "package_id": base["package_id"],
        "package_version": base["package_version"],
        "seed_surfaces": [
            {
                "surface_id": "docs",
                "surface_kind": "portable-doc",
                "source_root": "seeds/docs",
                "target_root": ".promin/docs",
            }
        ],
        "host_integrations": [],
        "members": [member],
        "tree_sha256": hashlib.sha256(canonical_bytes([member])).hexdigest(),
    }
    _write_canonical(package / "project-package.json", base)
    _write_canonical(package / "project-package-content.json", content)
    return package


def _confirmation(package: Path) -> OwnerConfirmation:
    preparation = prepare_clean_reinitialization(
        package,
        project_identity=_digest("project"),
    )
    return OwnerConfirmation(
        owner_id="owner:local",
        confirmation_id="confirmation:clean-reinitialization",
        intent_digest=preparation.intent.intent_digest,
        confirmed_at_ns=1,
    )


def _old_project(tmp_path: Path) -> tuple[Path, bytes]:
    project = tmp_path / "project"
    progress = b"old operational progress must not be copied\n"
    (project / ".promin" / "state").mkdir(parents=True)
    (project / ".promin" / "state" / "progress.json").write_bytes(progress)
    return project, progress


def test_owner_confirmation_is_required_before_any_destructive_work(tmp_path: Path) -> None:
    project, old_progress = _old_project(tmp_path)
    package = _make_package(tmp_path, docs_payload=b"new docs\n")
    calls: list[object] = []

    with pytest.raises(CleanReinitializationOperationError, match="OwnerConfirmation"):
        clean_reinitialize_project(
            project,
            package,
            project_identity=_digest("project"),
            owner_confirmation=None,  # type: ignore[arg-type]
            standard_initializer=lambda request: calls.append(request),
        )

    assert calls == []
    assert (project / ".promin" / "state" / "progress.json").read_bytes() == old_progress
    assert not (project / ".promin-host").exists()


def test_default_operation_is_pending_and_preserves_the_active_root(tmp_path: Path) -> None:
    project, old_progress = _old_project(tmp_path)
    package = _make_package(tmp_path, docs_payload=b"new docs\n")

    result = clean_reinitialize_project(
        project,
        package,
        project_identity=_digest("project"),
        owner_confirmation=_confirmation(package),
    )

    assert result.state is CleanReinitializationState.PENDING
    assert result.initializer_called is False
    assert (project / ".promin" / "state" / "progress.json").read_bytes() == old_progress
    assert not (project / ".promin-host").exists()
    assert result.to_record()["acceptance_pass"] is False
    assert result.to_record()["pass_credit"] is False


def test_initializer_failure_quarantines_and_rolls_back_the_whole_old_root(
    tmp_path: Path,
) -> None:
    project, old_progress = _old_project(tmp_path)
    package_payload = b"byte-exact package docs\n"
    package = _make_package(tmp_path, docs_payload=package_payload)
    confirmation = _confirmation(package)
    observed: dict[str, object] = {}

    def failing_initializer(request):
        observed["docs"] = (request.docs_shell / "docs" / "CLEAN.md").read_bytes()
        observed["shell_entries"] = sorted(path.name for path in request.docs_shell.iterdir())
        observed["old_root_absent"] = not (request.project_root / ".promin").exists()
        observed["old_progress"] = (
            request.project_root
            / ".promin-host"
            / "recovery"
            / request.intent.intent_digest
            / "state"
            / "progress.json"
        ).read_bytes()
        raise RuntimeError("initializer refusal")

    with pytest.raises(CleanReinitializationOperationError, match="prior control root was restored"):
        clean_reinitialize_project(
            project,
            package,
            project_identity=_digest("project"),
            owner_confirmation=confirmation,
            standard_initializer=failing_initializer,
        )

    assert observed == {
        "docs": package_payload,
        "shell_entries": ["docs"],
        "old_root_absent": True,
        "old_progress": old_progress,
    }
    assert (project / ".promin" / "state" / "progress.json").read_bytes() == old_progress
    assert not (project / ".promin-host" / "recovery" / confirmation.intent_digest).exists()


def test_successful_initializer_receives_exact_docs_and_copies_no_old_progress(
    tmp_path: Path,
) -> None:
    project, old_progress = _old_project(tmp_path)
    package_payload = b"fresh package documentation\n"
    package = _make_package(tmp_path, docs_payload=package_payload)
    confirmation = _confirmation(package)

    def initializer(request):
        assert (request.docs_shell / "docs" / "CLEAN.md").read_bytes() == package_payload
        assert not (request.docs_shell / "state").exists()
        active_docs = request.project_root / ".promin" / "docs"
        active_docs.mkdir(parents=True)
        (active_docs / "CLEAN.md").write_bytes(
            (request.docs_shell / "docs" / "CLEAN.md").read_bytes()
        )
        return StandardInitializationPublication(
            result=PublishedCleanReinitialization(
                intent_digest=request.intent.intent_digest,
                package_digest=request.intent.package_digest,
                extension_admission_digest=request.intent.extension_admission_digest,
                activation_digest=_digest("fresh-activation"),
            ),
            verifier=lambda result: result.activation_digest == _digest("fresh-activation"),
        )

    result = clean_reinitialize_project(
        project,
        package,
        project_identity=_digest("project"),
        owner_confirmation=confirmation,
        standard_initializer=initializer,
    )

    assert result.state is CleanReinitializationState.PUBLISHED
    assert (project / ".promin" / "docs" / "CLEAN.md").read_bytes() == package_payload
    assert not (project / ".promin" / "state" / "progress.json").exists()
    assert result.quarantine_root is not None
    assert (result.quarantine_root / "state" / "progress.json").read_bytes() == old_progress
    record = result.to_record()
    assert record["state_migration_supported"] is False
    assert record["previous_progress_imported"] is False
    assert record["acceptance_pass"] is False
    assert record["pass_credit"] is False
    assert record["product_credit"] is False


def test_prepare_then_owner_confirmed_operation_reports_the_full_black_box_lifecycle(
    tmp_path: Path,
) -> None:
    project, old_progress = _old_project(tmp_path)
    package = _make_package(tmp_path, docs_payload=b"lifecycle docs\n")
    preparation = prepare_clean_reinitialization(
        package,
        project_identity=_digest("project"),
    )
    assert project.joinpath(".promin", "state", "progress.json").read_bytes() == old_progress
    assert not (project / ".promin-host").exists()

    confirmation = OwnerConfirmation(
        owner_id="owner:local",
        confirmation_id="confirmation:lifecycle",
        intent_digest=preparation.intent.intent_digest,
        confirmed_at_ns=1,
    )

    def initializer(request):
        active_docs = request.project_root / ".promin" / "docs"
        active_docs.mkdir(parents=True)
        (active_docs / "CLEAN.md").write_bytes(
            (request.docs_shell / "docs" / "CLEAN.md").read_bytes()
        )
        return StandardInitializationPublication(
            result=PublishedCleanReinitialization(
                intent_digest=request.intent.intent_digest,
                package_digest=request.intent.package_digest,
                extension_admission_digest=request.intent.extension_admission_digest,
                activation_digest=_digest("lifecycle-activation"),
            ),
            verifier=lambda result: (
                result.activation_digest == _digest("lifecycle-activation")
                and (project / ".promin" / "docs" / "CLEAN.md").read_bytes()
                == b"lifecycle docs\n"
                and not (project / ".promin" / "state").exists()
                and (project / ".promin-host" / "recovery" / result.intent_digest
                     / "state" / "progress.json").read_bytes() == old_progress
            ),
        )

    result = clean_reinitialize_project(
        project,
        package,
        project_identity=_digest("project"),
        owner_confirmation=confirmation,
        standard_initializer=initializer,
    )
    record = result.to_record()

    assert result.state is CleanReinitializationState.PUBLISHED
    assert (project / ".promin" / "docs" / "CLEAN.md").read_bytes() == b"lifecycle docs\n"
    assert not (project / ".promin" / "state").exists()
    assert (
        result.quarantine_root is not None
        and (result.quarantine_root / "state" / "progress.json").read_bytes() == old_progress
    )
    assert record["quarantine_performed"] is True
    assert record["published_result_present"] is True
    assert record["acceptance_pass"] is False
    assert record["pass_credit"] is False
