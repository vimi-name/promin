from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path

import pytest

from promin.input_identity import (
    InputIdentityError,
    identity_partition,
    identity_record,
    provider_input_identity,
    source_selection_identity,
    validate_source_selection,
)
from promin.provider_envelope import (
    ScanMode,
    conservative_timestamp_interval,
    provider_coverage_union,
    provider_driver,
    provider_envelope,
    seal_physical_artifact,
)
from promin.provider_receipts import (
    ProviderReceiptError,
    bind_target_merkle_receipt,
    canonical_target_merkle_receipt_bytes,
    scan_target_closure,
    validate_target_merkle_receipt,
)


def _tree(root: Path) -> None:
    (root / "src" / "left").mkdir(parents=True)
    (root / "src" / "right" / "nested").mkdir(parents=True)
    (root / "src" / "left" / "a.txt").write_bytes(b"alpha\n")
    (root / "src" / "right" / "b.txt").write_bytes(b"bravo\n")
    (root / "src" / "right" / "nested" / "c.bin").write_bytes(b"charlie\x00")


def _selection(root: Path, paths: tuple[str, ...] | None = None):
    return validate_source_selection(
        root,
        paths
        or (
            "src/left/a.txt",
            "src/right/b.txt",
            "src/right/nested/c.bin",
        ),
        allowed_roots=("src",),
    )


def _input_identity(selection):
    return provider_input_identity(
        repository=identity_partition(
            "repository",
            [identity_record("repository-content", "content-tree", "1" * 64)],
        ),
        tooling=identity_partition(
            "tooling",
            [identity_record("provider-driver", "driver", "2" * 64)],
        ),
        dependencies=identity_partition(
            "dependencies",
            [identity_record("provider-dependencies", "dependency-tree", "3" * 64)],
        ),
        target=identity_partition(
            "target",
            [source_selection_identity(selection)],
        ),
        repository_observation={"git_head": "f" * 40},
    )


def _canonical_provider(
    root: Path,
    selection,
    *,
    scan_mode: ScanMode,
):
    artifact = root / "provider.bin"
    artifact.write_bytes(b"provider-v1")
    identity = _input_identity(selection)
    envelope = provider_envelope(
        provider_id="semantic-provider",
        scan_mode=scan_mode,
        input_identity=identity,
        physical_seal=seal_physical_artifact(artifact, artifact_id="semantic-provider-bin"),
        global_drivers=(provider_driver("c-compiler", "cc", "5" * 64, version="1.0"),),
        required_driver_roles=("c-compiler",),
        module_subset=("module.alpha",),
        covered_modules=("module.alpha",),
    )
    coverage = provider_coverage_union(
        ("module.alpha",),
        (envelope,),
        expected_input_identity_digest=identity.input_digest,
        required_driver_roles=("c-compiler",),
    )
    assert coverage.status == "PASS"
    return artifact, identity, envelope, coverage


def test_byte_substitution_with_restored_mtime_changes_the_merkle_closure(tmp_path: Path) -> None:
    _tree(tmp_path)
    selection = _selection(tmp_path)
    first = scan_target_closure(selection)
    changed = tmp_path / "src" / "right" / "b.txt"
    original = changed.read_bytes()
    original_state = changed.stat()

    changed.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    os.utime(changed, ns=(original_state.st_atime_ns, original_state.st_mtime_ns))
    restored = changed.stat()
    assert restored.st_size == original_state.st_size
    assert restored.st_mtime_ns == original_state.st_mtime_ns
    if os.name == "nt":
        # Windows exposes creation time through st_ctime; byte writes do not
        # move it.  This reproduces the metadata-only guard blind spot that
        # motivated the byte-authoritative receipt path.
        assert (
            restored.st_mode,
            restored.st_dev,
            restored.st_ino,
            restored.st_size,
            restored.st_mtime_ns,
            restored.st_ctime_ns,
        ) == (
            original_state.st_mode,
            original_state.st_dev,
            original_state.st_ino,
            original_state.st_size,
            original_state.st_mtime_ns,
            original_state.st_ctime_ns,
        )

    if os.name != "nt":
        # POSIX ctime catches the change during the canonical source-selection
        # revalidation.  That is still fail-closed before any receipt reuse.
        with pytest.raises(ProviderReceiptError, match="changed after containment preflight"):
            scan_target_closure(selection)
        return

    # On Windows all six ordinary metadata witnesses are unchanged, so only
    # re-hashing exact bytes can invalidate this path.
    second = scan_target_closure(selection)
    assert second.merkle_root != first.merkle_root
    first_by_path = {item.path: item.sha256 for item in first.leaves}
    second_by_path = {item.path: item.sha256 for item in second.leaves}
    assert second_by_path["src/right/b.txt"] != first_by_path["src/right/b.txt"]


def test_target_closure_uses_canonical_selection_and_explicit_transient_exclusion(
    tmp_path: Path,
) -> None:
    _tree(tmp_path)
    generated = tmp_path / "src" / "right" / "cache" / "generated.json"
    generated.parent.mkdir()
    generated.write_text("{}", encoding="utf-8")
    selection = _selection(
        tmp_path,
        (
            "src/left/a.txt",
            "src/right/b.txt",
            "src/right/cache/generated.json",
            "src/right/nested/c.bin",
        ),
    )

    closure = scan_target_closure(selection, transient_paths=("src/right/cache",))
    assert closure.excluded_paths == ("src/right/cache/generated.json",)
    assert closure.transient_paths == ("src/right/cache",)
    assert all(not item.path.startswith("src/right/cache/") for item in closure.leaves)
    assert closure.as_dict()["acceptance_pass"] is False
    assert closure.as_dict()["pass_credit"] is False

    with pytest.raises(ProviderReceiptError, match="outside the selected target closure"):
        scan_target_closure(selection, transient_paths=("src/not-selected",))
    with pytest.raises(ProviderReceiptError, match="typed source selection"):
        scan_target_closure(tmp_path)  # type: ignore[arg-type]


def test_linked_input_is_rejected_by_the_canonical_pre_hash_selection(tmp_path: Path) -> None:
    _tree(tmp_path)
    outside = tmp_path.parent / f"outside-{hashlib.sha256(str(tmp_path).encode()).hexdigest()}.txt"
    outside.write_text("outside", encoding="utf-8")
    link = tmp_path / "src" / "left" / "outside-link"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are unavailable on this host")

    with pytest.raises(InputIdentityError, match="symbolic link or reparse"):
        validate_source_selection(
            tmp_path,
            ("src/left/outside-link",),
            allowed_roots=("src",),
        )


def test_fullscan_receipt_rebinds_canonical_owner_records_without_host_path(tmp_path: Path) -> None:
    _tree(tmp_path)
    selection = _selection(tmp_path)
    closure = scan_target_closure(selection)
    artifact, identity, envelope, coverage = _canonical_provider(
        tmp_path,
        selection,
        scan_mode=ScanMode.FULL_SCAN,
    )
    interval = conservative_timestamp_interval(
        "2026-08-08T12:00:00.900000Z",
        "2026-08-08T12:00:01.100000Z",
    )

    receipt = bind_target_merkle_receipt(
        target_id="alpha4-target",
        selection=selection,
        closure=closure,
        input_identity=identity,
        envelope=envelope,
        coverage_union=coverage,
        provider_artifact_path=artifact,
        lifecycle_interval=interval,
    )
    validated = validate_target_merkle_receipt(
        receipt,
        selection=selection,
        closure=closure,
        input_identity=identity,
        envelope=envelope,
        coverage_union=coverage,
        provider_artifact_path=artifact,
        lifecycle_interval=interval,
    )
    payload = canonical_target_merkle_receipt_bytes(
        validated,
        selection=selection,
        closure=closure,
        input_identity=identity,
        envelope=envelope,
        coverage_union=coverage,
        provider_artifact_path=artifact,
        lifecycle_interval=interval,
    )
    record = validated.to_record()

    assert record["lineage"] == {"kind": "root"}
    assert record["provider_envelope"]["envelope_digest"] == envelope.envelope_digest
    assert record["coverage_union"]["coverage_union_digest"] == coverage.to_record()[
        "coverage_union_digest"
    ]
    assert record["lifecycle_interval"]["interval_digest"] == interval.to_record()["interval_digest"]
    assert record["acceptance_pass"] is False
    assert record["pass_credit"] is False
    assert str(tmp_path).encode("utf-8") not in payload

    artifact.write_bytes(b"provider-v2")
    with pytest.raises(ProviderReceiptError, match="physical artifact"):
        validate_target_merkle_receipt(
            validated,
            selection=selection,
            closure=closure,
            input_identity=identity,
            envelope=envelope,
            coverage_union=coverage,
            provider_artifact_path=artifact,
            lifecycle_interval=interval,
        )


def test_reuse_requires_explicit_target_receipt_lineage(tmp_path: Path) -> None:
    _tree(tmp_path)
    selection = _selection(tmp_path)
    closure = scan_target_closure(selection)
    artifact, identity, envelope, coverage = _canonical_provider(
        tmp_path,
        selection,
        scan_mode=ScanMode.REUSE,
    )

    with pytest.raises(ProviderReceiptError, match="requires an explicit parent"):
        bind_target_merkle_receipt(
            target_id="alpha4-target",
            selection=selection,
            closure=closure,
            input_identity=identity,
            envelope=envelope,
            coverage_union=coverage,
            provider_artifact_path=artifact,
        )

    receipt = bind_target_merkle_receipt(
        target_id="alpha4-target",
        selection=selection,
        closure=closure,
        input_identity=identity,
        envelope=envelope,
        coverage_union=coverage,
        provider_artifact_path=artifact,
        parent_target_receipt_digest="c" * 64,
    )
    assert receipt.to_record()["lineage"] == {
        "kind": "reuse",
        "parent_target_receipt_digest": "c" * 64,
    }


def test_receipt_fails_closed_for_wrong_input_or_tampered_binding(tmp_path: Path) -> None:
    _tree(tmp_path)
    selection = _selection(tmp_path)
    closure = scan_target_closure(selection)
    artifact, identity, envelope, coverage = _canonical_provider(
        tmp_path,
        selection,
        scan_mode=ScanMode.FULL_SCAN,
    )
    receipt = bind_target_merkle_receipt(
        target_id="alpha4-target",
        selection=selection,
        closure=closure,
        input_identity=identity,
        envelope=envelope,
        coverage_union=coverage,
        provider_artifact_path=artifact,
    )

    other_identity = provider_input_identity(
        repository=identity.repository,
        tooling=identity.tooling,
        dependencies=identity.dependencies,
        target=identity_partition(
            "target",
            [identity_record("different-target", "source-selection", "9" * 64)],
        ),
    )
    with pytest.raises(ProviderReceiptError, match="input identity"):
        bind_target_merkle_receipt(
            target_id="alpha4-target",
            selection=selection,
            closure=closure,
            input_identity=other_identity,
            envelope=envelope,
            coverage_union=coverage,
            provider_artifact_path=artifact,
        )

    detached_coverage = replace(
        coverage,
        contributing_envelope_digests=("0" * 64,),
    )
    with pytest.raises(ProviderReceiptError, match="does not bind the current envelope"):
        bind_target_merkle_receipt(
            target_id="alpha4-target",
            selection=selection,
            closure=closure,
            input_identity=identity,
            envelope=envelope,
            coverage_union=detached_coverage,
            provider_artifact_path=artifact,
        )

    tampered = replace(receipt, target_closure_digest="0" * 64)
    with pytest.raises(ProviderReceiptError, match="receipt digest mismatch"):
        validate_target_merkle_receipt(
            tampered,
            selection=selection,
            closure=closure,
            input_identity=identity,
            envelope=envelope,
            coverage_union=coverage,
            provider_artifact_path=artifact,
        )
