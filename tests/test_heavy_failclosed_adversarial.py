from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unicodedata

import pytest

import promin.canonical as canonical
from promin import service as service_runtime
from promin.clean_reinitialization import (
    CleanReinitializationOperationError,
    clean_reinitialize_project,
    prepare_clean_reinitialization,
)
from promin.dynamic_handoff import validate_dynamic_handoff
from promin.init_profiles import InitProfileError, validate_init_profile
from promin.input_identity import (
    identity_partition,
    identity_record,
    provider_input_identity,
    validate_source_selection,
)
from promin.language_analysis import AnalysisError
from promin.project_package import project_package_tree_digest
from promin.provider_envelope import (
    ProviderEnvelopeError,
    ScanMode,
    provider_coverage_union,
    provider_driver,
    provider_envelope,
    seal_physical_artifact,
    verify_envelope_physical_artifact,
    verify_provider_envelope_record,
)
from promin.provider_receipts import (
    ProviderReceiptError,
    bind_target_merkle_receipt,
    scan_target_closure,
    validate_target_merkle_receipt,
)
from promin.recovery import OwnerConfirmation
from promin.semantic_scope import build_module_graph
from promin.static_admission import run_static_admission


def _digest(label: str) -> str:
    return hashlib.sha256(f"heavy-failclosed:{label}".encode("utf-8")).hexdigest()


def _source_selection(root: Path):
    source = root / "src" / "unit.cpp"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"int unit() { return 1; }\n")
    return validate_source_selection(root, ("src/unit.cpp",), allowed_roots=("src",))


def _receipt_fixture(tmp_path: Path):
    root = tmp_path / "receipt-source"
    selection = _source_selection(root)
    closure = scan_target_closure(selection)
    artifact = root / "provider.bin"
    artifact.write_bytes(b"provider-v1")
    identity = provider_input_identity(
        repository=identity_partition(
            "repository",
            (identity_record("repository-content", "content-tree", "1" * 64),),
        ),
        tooling=identity_partition(
            "tooling",
            (identity_record("compiler-driver", "driver", "2" * 64),),
        ),
        dependencies=identity_partition(
            "dependencies",
            (identity_record("provider-dependencies", "dependency-tree", "3" * 64),),
        ),
        target=identity_partition(
            "target",
            (identity_record("target-source-selection", "source-selection", selection.selection_digest),),
        ),
    )
    envelope = provider_envelope(
        provider_id="heavy-provider",
        scan_mode=ScanMode.FULL_SCAN,
        input_identity=identity,
        physical_seal=seal_physical_artifact(artifact, artifact_id="heavy-provider-bin"),
        global_drivers=(provider_driver("cpp-compiler", "cxx", "4" * 64),),
        required_driver_roles=("cpp-compiler",),
        module_subset=("module.heavy",),
        covered_modules=("module.heavy",),
    )
    coverage = provider_coverage_union(
        ("module.heavy",),
        (envelope,),
        expected_input_identity_digest=identity.input_digest,
        required_driver_roles=("cpp-compiler",),
    )
    receipt = bind_target_merkle_receipt(
        target_id="heavy-target",
        selection=selection,
        closure=closure,
        input_identity=identity,
        envelope=envelope,
        coverage_union=coverage,
        provider_artifact_path=artifact,
    )
    return artifact, selection, closure, identity, envelope, coverage, receipt


def test_mutation_cache_rejects_same_size_byte_substitution_with_restored_mtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cache identity must include byte evidence, not only mutable metadata."""

    control = tmp_path / ".promin"
    (control / "providers").mkdir(parents=True)
    bound = tmp_path / "bound-receipt.json"
    bound.write_bytes(b"bound-receipt-v1")
    context = SimpleNamespace(control_root=control)
    monkeypatch.setattr(
        service_runtime,
        "activation_read_bindings",
        lambda _context: (("bound-receipt", bound, "file"),),
    )

    bindings = service_runtime._mutation_cache_bindings(context)
    baseline = service_runtime._fast_implementation_stat_fingerprint(
        context, tmp_path, bindings=bindings
    )
    assert baseline is not None
    before = bound.stat()
    payload = bound.read_bytes()
    bound.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
    os.utime(bound, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = bound.stat()
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns

    assert (
        service_runtime._fast_implementation_stat_fingerprint(
            context, tmp_path, bindings=bindings
        )
        != baseline
    )


@pytest.mark.parametrize(
    "aliases",
    (
        ("src/Case.cpp", "src/case.cpp"),
        (
            "src/" + unicodedata.normalize("NFC", "café") + ".cpp",
            "src/" + unicodedata.normalize("NFD", "café") + ".cpp",
        ),
    ),
    ids=("casefold", "nfc"),
)
def test_module_graph_rejects_portable_case_or_nfc_aliases(
    aliases: tuple[str, str],
) -> None:
    """A graph cannot admit two identifiers for one portable source path."""

    first, second = aliases
    assert first != second
    assert unicodedata.normalize("NFC", first).casefold() == unicodedata.normalize(
        "NFC", second
    ).casefold()
    graph = {
        "src/root.cpp": (first, second),
        first: (),
        second: (),
    }

    with pytest.raises(AnalysisError, match=r"(?i)(case|nfc|portable|collision)"):
        build_module_graph(graph)


def test_corrupt_provider_bytes_and_credit_shaped_receipts_fail_closed(
    tmp_path: Path,
) -> None:
    """Physical receipts must reject byte drift and serialized false credit."""

    artifact, selection, closure, identity, envelope, coverage, receipt = _receipt_fixture(
        tmp_path
    )
    before = artifact.stat()
    original = artifact.read_bytes()
    artifact.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    os.utime(artifact, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = artifact.stat()
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns
    assert verify_envelope_physical_artifact(envelope, artifact) is False

    with pytest.raises(ProviderReceiptError):
        validate_target_merkle_receipt(
            receipt,
            selection=selection,
            closure=closure,
            input_identity=identity,
            envelope=envelope,
            coverage_union=coverage,
            provider_artifact_path=artifact,
        )

    forged = deepcopy(envelope.to_record())
    forged["pass_credit"] = True
    with pytest.raises(ProviderEnvelopeError, match="must not claim pass credit"):
        verify_provider_envelope_record(forged)


def test_interrupted_atomic_write_keeps_the_last_complete_file_and_cleans_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A publication interruption may not replace a known-good receipt body."""

    target = tmp_path / "receipt.json"
    target.write_bytes(b"last-complete-receipt")

    def interrupted_replace(_source: object, _destination: object) -> None:
        raise InterruptedError("controlled publication interruption")

    monkeypatch.setattr(canonical.os, "replace", interrupted_replace)
    with pytest.raises(InterruptedError, match="controlled publication interruption"):
        canonical.atomic_write_bytes(target, b"incomplete-replacement")

    assert target.read_bytes() == b"last-complete-receipt"
    assert list(tmp_path.glob(".p-*.tmp")) == []


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("artifact_profile", "runtime"),
        ("canonical_build_owners", 2),
        ("pass_credit", True),
    ),
    ids=("unknown-artifact-profile", "multiple-canonical-owners", "credit-field"),
)
def test_init_profile_rejects_invalid_or_credit_shaped_input(
    field: str, value: object
) -> None:
    """Profile selection is configuration, never a carrier of authority credit."""

    profile_path = Path(__file__).resolve().parents[1] / "capability_profiles" / "standard-init.json"
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    profile[field] = value

    with pytest.raises(InitProfileError):
        validate_init_profile(profile)


def test_static_pass_never_promotes_dynamic_or_product_credit(tmp_path: Path) -> None:
    root = tmp_path / "static-root"
    docs = root / ".promin" / "docs"
    docs.mkdir(parents=True)
    (root / "README.md").write_text("portable source\n", encoding="utf-8")
    (docs / "CURRENT.md").write_text("# current\n", encoding="utf-8")
    handoff = validate_dynamic_handoff(
        {
            "id": "heavy-runtime-proof",
            "status": "PENDING_DYNAMIC",
            "allowed_write_scope": ["artifacts/heavy/**"],
            "forbidden": ["synthetic-pass-credit"],
            "required_evidence": ["bound-runtime-evidence"],
            "acceptance_predicate": "A real dynamic runtime route binds fresh evidence.",
            "invalidation_class": "BODY_ONLY",
            "stop_conditions": ["input identity changes"],
        }
    )

    result = run_static_admission(root, profile="minimal", handoff=handoff)

    assert result["status"] == "PASS"
    assert result["claims"] == {
        "compiler_validated": False,
        "runtime_validated": False,
        "acceptance_pass": False,
        "pass_credit": False,
    }
    assert result["product_acceptance_pass"] is False
    assert result["release_eligible"] is False
    assert result["pass_credit"] is False


def _write_canonical(path: Path, value: object) -> None:
    path.write_bytes(canonical.canonical_bytes(value))


def _clean_package(tmp_path: Path) -> Path:
    package = tmp_path / "clean-package"
    docs = package / "seeds" / "docs"
    docs.mkdir(parents=True)
    payload = b"fresh portable docs\n"
    (docs / "CLEAN.md").write_bytes(payload)
    member = {
        "source_path": "seeds/docs/CLEAN.md",
        "target_path": ".promin/docs/CLEAN.md",
        "member_class": "portable-doc",
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "mode": 0o644,
    }
    base = {
        "schema": "promin.project-package.v1",
        "package_id": "heavy-clean-package",
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
        "tree_sha256": project_package_tree_digest([member]),
    }
    _write_canonical(package / "project-package.json", base)
    _write_canonical(package / "project-package-content.json", content)
    return package


def test_interrupted_clean_reinitialization_preserves_quarantine_and_refuses_overwrite(
    tmp_path: Path,
) -> None:
    """A partial new root must not cause automatic restoration over live bytes."""

    project = tmp_path / "project"
    old_progress = b"old progress must stay quarantined\n"
    (project / ".promin" / "state").mkdir(parents=True)
    (project / ".promin" / "state" / "progress.json").write_bytes(old_progress)
    package = _clean_package(tmp_path)
    preparation = prepare_clean_reinitialization(package, project_identity=_digest("project"))
    confirmation = OwnerConfirmation(
        owner_id="owner:heavy-test",
        confirmation_id="confirmation:interrupted-clean-reinit",
        intent_digest=preparation.intent.intent_digest,
        confirmed_at_ns=1,
    )

    def partial_initializer(request: object) -> object:
        active = project / ".promin"
        active.mkdir()
        (active / "partial-activation.json").write_bytes(b"incomplete new state")
        raise InterruptedError("controlled initializer interruption")

    with pytest.raises(CleanReinitializationOperationError, match="rollback was blocked"):
        clean_reinitialize_project(
            project,
            package,
            project_identity=_digest("project"),
            owner_confirmation=confirmation,
            standard_initializer=partial_initializer,
        )

    quarantine = project / ".promin-host" / "recovery" / confirmation.intent_digest
    assert (project / ".promin" / "partial-activation.json").read_bytes() == b"incomplete new state"
    assert (quarantine / "state" / "progress.json").read_bytes() == old_progress
    assert not (project / ".promin" / "state" / "progress.json").exists()
