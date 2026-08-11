from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from promin.gate_admission import (
    InvalidationClass,
    ReceiptInvalidationClass,
    gate_plan_for_receipt_invalidation,
)
from promin.input_identity import (
    identity_partition,
    identity_record,
    provider_input_identity,
    source_selection_identity,
    validate_source_selection,
)
from promin.provider_envelope import (
    ScanMode,
    provider_coverage_union,
    provider_driver,
    provider_envelope,
    seal_physical_artifact,
)
from promin.provider_receipts import (
    MerkleLeafCache,
    MerkleLeafCacheLimits,
    ProviderReceiptError,
    TargetClosureLimits,
    benchmark_target_closure_capture,
    bind_target_merkle_receipt,
    capture_target_closure,
    classify_target_receipt_invalidation,
)


def _source_tree(root: Path, count: int = 12) -> tuple[str, ...]:
    source = root / "src" / "dependency"
    source.mkdir(parents=True)
    paths: list[str] = []
    for index in range(count):
        relative = f"src/dependency/unit-{index:04d}.cpp"
        (source / f"unit-{index:04d}.cpp").write_bytes(
            f"int unit_{index}(void) {{ return {index}; }}\n".encode("utf-8")
        )
        paths.append(relative)
    return tuple(paths)


def _selection(root: Path, paths: tuple[str, ...]):
    return validate_source_selection(root, paths, allowed_roots=("src",))


def _identity(selection):
    return provider_input_identity(
        repository=identity_partition(
            "repository",
            [identity_record("repository-content", "content-tree", "1" * 64)],
        ),
        tooling=identity_partition(
            "tooling",
            [identity_record("compiler", "driver", "2" * 64)],
        ),
        dependencies=identity_partition(
            "dependencies",
            [identity_record("dependencies", "dependency-tree", "3" * 64)],
        ),
        target=identity_partition("target", [source_selection_identity(selection)]),
    )


def _provider_inputs(root: Path, selection):
    identity = _identity(selection)
    full_artifact = root / "full-provider.bin"
    reuse_artifact = root / "reuse-provider.bin"
    full_artifact.write_bytes(b"full-provider")
    reuse_artifact.write_bytes(b"reuse-provider")
    driver = provider_driver("c-compiler", "cc", "5" * 64, version="1.0")
    full = provider_envelope(
        provider_id="full-provider",
        scan_mode=ScanMode.FULL_SCAN,
        input_identity=identity,
        physical_seal=seal_physical_artifact(full_artifact, artifact_id="full-provider-bin"),
        global_drivers=(driver,),
        required_driver_roles=("c-compiler",),
        module_subset=("module.alpha",),
        covered_modules=("module.alpha",),
    )
    reuse = provider_envelope(
        provider_id="reuse-provider",
        scan_mode=ScanMode.REUSE,
        input_identity=identity,
        physical_seal=seal_physical_artifact(reuse_artifact, artifact_id="reuse-provider-bin"),
        global_drivers=(driver,),
        required_driver_roles=("c-compiler",),
        module_subset=("module.beta",),
        covered_modules=("module.beta",),
    )
    complete = provider_coverage_union(
        ("module.alpha", "module.beta"),
        (full, reuse),
        expected_input_identity_digest=identity.input_digest,
        required_driver_roles=("c-compiler",),
    )
    primary_only = provider_coverage_union(
        ("module.alpha",),
        (full,),
        expected_input_identity_digest=identity.input_digest,
        required_driver_roles=("c-compiler",),
    )
    assert complete.status == "PASS"
    assert primary_only.status == "PASS"
    return identity, full_artifact, full, reuse, complete, primary_only


def test_one_pass_cache_rehashes_byte_substitution_before_reuse(tmp_path: Path) -> None:
    paths = _source_tree(tmp_path)
    selection = _selection(tmp_path, paths)
    cache = MerkleLeafCache(MerkleLeafCacheLimits(max_entries=64, max_bytes=64 * 1024))

    first = capture_target_closure(selection, leaf_cache=cache)
    assert first.physical_traversal_passes == 1
    assert first.files_byte_validated == len(paths)
    assert first.leaf_cache_hits == 0
    assert first.leaf_cache_misses == len(paths)
    assert cache.statistics().entry_count == len(paths)

    changed = tmp_path / "src" / "dependency" / "unit-0005.cpp"
    original = changed.read_bytes()
    before = changed.stat()
    changed.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    os.utime(changed, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = changed.stat()
    assert after.st_size == before.st_size
    assert after.st_mtime_ns == before.st_mtime_ns
    if os.name == "nt":
        assert (
            after.st_mode,
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) == (
            before.st_mode,
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )

    # Re-preflight provides the current SourceSelection on POSIX (where ctime
    # changes); Windows still has the same metadata witness.  In both cases the
    # cache validates bytes freshly and only the changed leaf misses.
    second = capture_target_closure(_selection(tmp_path, paths), leaf_cache=cache)
    assert second.physical_traversal_passes == 1
    assert second.files_byte_validated == len(paths)
    assert second.leaf_cache_hits == len(paths) - 1
    assert second.leaf_cache_misses == 1
    assert second.closure.merkle_root != first.closure.merkle_root
    assert classify_target_receipt_invalidation(
        first.closure,
        second.closure,
    ) is ReceiptInvalidationClass.BYTE_CONTENT_CHANGED


def test_bounds_are_explicit_and_cache_eviction_never_widens_memory(tmp_path: Path) -> None:
    paths = _source_tree(tmp_path, count=5)
    selection = _selection(tmp_path, paths)
    cache = MerkleLeafCache(MerkleLeafCacheLimits(max_entries=2, max_bytes=1024))
    capture = capture_target_closure(selection, leaf_cache=cache)

    stats = cache.statistics()
    assert stats.entry_count <= 2
    assert stats.accounted_bytes <= cache.limits.max_bytes
    assert capture.leaf_cache_evictions >= 3
    assert TargetClosureLimits().max_files >= 100_001
    assert MerkleLeafCacheLimits().max_entries >= 100_001

    with pytest.raises(ProviderReceiptError, match="selected-file bound"):
        capture_target_closure(
            selection,
            limits=TargetClosureLimits(max_files=4, max_total_bytes=1024 * 1024, max_leaf_accounted_bytes=1024 * 1024),
        )
    with pytest.raises(ProviderReceiptError, match="materialized leaf bound"):
        capture_target_closure(
            selection,
            limits=TargetClosureLimits(max_files=8, max_total_bytes=1024 * 1024, max_leaf_accounted_bytes=1),
        )


def test_contributor_lineage_drives_dependency_invalidation_and_gate_cost(tmp_path: Path) -> None:
    paths = _source_tree(tmp_path, count=3)
    selection = _selection(tmp_path, paths)
    capture = capture_target_closure(selection)
    identity, artifact, full, reuse, complete, primary_only = _provider_inputs(tmp_path, selection)

    full_lineage = bind_target_merkle_receipt(
        target_id="heavy-target",
        selection=selection,
        closure=capture.closure,
        input_identity=identity,
        envelope=full,
        coverage_union=complete,
        provider_artifact_path=artifact,
    )
    primary_lineage = bind_target_merkle_receipt(
        target_id="heavy-target",
        selection=selection,
        closure=capture.closure,
        input_identity=identity,
        envelope=full,
        coverage_union=primary_only,
        provider_artifact_path=artifact,
    )
    record = full_lineage.to_record()
    assert record["contributor_lineage"]["contributing_envelope_digests"] == sorted(
        (full.envelope_digest, reuse.envelope_digest)
    )
    assert classify_target_receipt_invalidation(
        capture.closure,
        capture.closure,
        previous_receipt=full_lineage,
        current_receipt=primary_lineage,
    ) is ReceiptInvalidationClass.DEPENDENCY_CLOSURE_CHANGED

    plan = gate_plan_for_receipt_invalidation(
        ReceiptInvalidationClass.DEPENDENCY_CLOSURE_CHANGED,
        input_digest=hashlib.sha256(b"heavy-dependency").hexdigest(),
        scope_count=len(paths),
    )
    assert plan.invalidation is InvalidationClass.CMAKE_TOPOLOGY
    assert plan.phase_ids[-1] == "provider-refresh"


def test_controlled_benchmark_is_diagnostic_only_and_bounded(tmp_path: Path) -> None:
    paths = _source_tree(tmp_path, count=8)
    selection = _selection(tmp_path, paths)
    cache = MerkleLeafCache(MerkleLeafCacheLimits(max_entries=16, max_bytes=16 * 1024))

    benchmark = benchmark_target_closure_capture(
        selection,
        leaf_cache=cache,
        warmup_samples=1,
        samples=2,
        budget_seconds=60.0,
    )
    report = benchmark.as_dict()
    assert benchmark.file_count == len(paths)
    assert benchmark.cache_hits == len(paths) * 2
    assert benchmark.cache_misses == 0
    assert len(benchmark.elapsed_seconds) == 2
    assert report["classification"] == "DIAGNOSTIC_ONLY"
    assert report["performance_acceptance"] is False
    assert report["acceptance_pass"] is False
    assert report["pass_credit"] is False

    with pytest.raises(ProviderReceiptError, match="between one and five"):
        benchmark_target_closure_capture(selection, samples=6)
