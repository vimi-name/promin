from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from promin.input_identity import (
    InputIdentityError,
    identity_partition,
    identity_record,
    provider_input_identity,
    revalidate_source_selection,
    validate_source_selection,
)
from promin.provider_envelope import (
    ProviderEnvelopeError,
    ScanMode,
    conservative_timestamp_interval,
    provider_coverage_union,
    provider_driver,
    provider_envelope,
    seal_physical_artifact,
    verify_envelope_physical_artifact,
    verify_provider_envelope_record,
)


def _input_identity(*, git_head: str = "a" * 40):
    return provider_input_identity(
        repository=identity_partition(
            "repository",
            [identity_record("repository-content", "content-tree", "1" * 64)],
        ),
        tooling=identity_partition(
            "tooling",
            [identity_record("cmake-driver", "driver", "2" * 64)],
        ),
        dependencies=identity_partition(
            "dependencies",
            [identity_record("provider-dependencies", "dependency-tree", "3" * 64)],
        ),
        target=identity_partition(
            "target",
            [identity_record("selected-target", "source-selection", "4" * 64)],
        ),
        repository_observation={"git_head": git_head},
    )


def test_input_identity_strictly_separates_authority_from_git_observation() -> None:
    before = _input_identity(git_head="a" * 40)
    after = _input_identity(git_head="b" * 40)

    assert before.input_digest == after.input_digest
    record = before.to_record()
    assert record["repository_observation"]["authoritative"] is False
    assert record["acceptance_pass"] is False
    assert record["pass_credit"] is False


def test_source_selection_is_pre_hash_and_rejects_nonportable_membership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "src" / "unit.c"
    source.parent.mkdir()
    source.write_text("int unit(void) { return 0; }\n", encoding="utf-8")

    def fail_open(*_args, **_kwargs):
        raise AssertionError("source preflight must not read or hash selected bytes")

    monkeypatch.setattr(Path, "open", fail_open)
    selection = validate_source_selection(
        tmp_path, ["src/unit.c"], allowed_roots=("src",)
    )
    assert selection.to_record()["content_hashed"] is False

    with pytest.raises(InputIdentityError, match="case-colliding"):
        validate_source_selection(
            tmp_path,
            ["src/unit.c", "SRC/unit.c"],
            allowed_roots=("src",),
        )
    with pytest.raises(InputIdentityError, match="outside allowed"):
        validate_source_selection(
            tmp_path, ["outside.c"], allowed_roots=("src",)
        )


def test_source_selection_revalidation_detects_drift_before_later_mutation(tmp_path: Path) -> None:
    source = tmp_path / "src" / "unit.c"
    source.parent.mkdir()
    source.write_text("int unit(void) { return 0; }\n", encoding="utf-8")
    selection = validate_source_selection(
        tmp_path, ["src/unit.c"], allowed_roots=("src",)
    )

    source.write_text("int unit(void) { return 100; }\n", encoding="utf-8")
    with pytest.raises(InputIdentityError, match="changed after preflight"):
        revalidate_source_selection(selection)


def test_fullscan_and_reuse_envelopes_use_explicit_coverage_union_and_c_driver(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "provider.bin"
    artifact.write_bytes(b"provider-v1")
    identity = _input_identity()
    seal = seal_physical_artifact(artifact, artifact_id="provider-artifact")
    drivers = (
        provider_driver("c-compiler", "cc", "5" * 64, version="1.0"),
        provider_driver("cpp-compiler", "cxx", "6" * 64, version="1.0"),
    )
    full = provider_envelope(
        provider_id="semantic-provider",
        scan_mode=ScanMode.FULL_SCAN,
        input_identity=identity,
        physical_seal=seal,
        global_drivers=drivers,
        required_driver_roles=("c-compiler", "cpp-compiler"),
        module_subset=("module.alpha",),
        covered_modules=("module.alpha",),
    )
    reuse = provider_envelope(
        provider_id="semantic-provider",
        scan_mode=ScanMode.REUSE,
        input_identity=identity,
        physical_seal=seal,
        global_drivers=drivers,
        required_driver_roles=("c-compiler", "cpp-compiler"),
        module_subset=("module.beta",),
        covered_modules=("module.beta",),
    )

    coverage = provider_coverage_union(
        ("module.alpha", "module.beta"),
        (full, reuse),
        expected_input_identity_digest=identity.input_digest,
        required_driver_roles=("c-compiler", "cpp-compiler"),
    )
    assert coverage.status == "PASS"
    assert coverage.scan_modes == (ScanMode.FULL_SCAN, ScanMode.REUSE)
    assert coverage.contributing_envelope_digests == tuple(
        sorted((full.envelope_digest, reuse.envelope_digest))
    )
    assert coverage.required_driver_roles == ("c-compiler", "cpp-compiler")
    assert coverage.to_record()["pass_credit"] is False
    assert full.to_record()["acceptance_pass"] is False

    with pytest.raises(ProviderEnvelopeError, match="misses required roles"):
        provider_envelope(
            provider_id="semantic-provider",
            scan_mode=ScanMode.FULL_SCAN,
            input_identity=identity,
            physical_seal=seal,
            global_drivers=(drivers[1],),
            required_driver_roles=("c-compiler",),
            module_subset=("module.alpha",),
            covered_modules=("module.alpha",),
        )


def test_provider_envelope_is_bound_to_physical_bytes_and_exact_serialization(tmp_path: Path) -> None:
    artifact = tmp_path / "provider.bin"
    artifact.write_bytes(b"provider-v1")
    identity = _input_identity()
    envelope = provider_envelope(
        provider_id="semantic-provider",
        scan_mode="FullScan",
        input_identity=identity,
        physical_seal=seal_physical_artifact(artifact, artifact_id="provider-artifact"),
        global_drivers=(provider_driver("c-compiler", "cc", "5" * 64),),
        required_driver_roles=("c-compiler",),
        module_subset=("module.alpha",),
        covered_modules=("module.alpha",),
    )
    record = envelope.to_record()
    assert verify_provider_envelope_record(record).envelope_digest == envelope.envelope_digest
    assert verify_envelope_physical_artifact(envelope, artifact) is True

    artifact.write_bytes(b"provider-v2")
    assert verify_envelope_physical_artifact(envelope, artifact) is False
    tampered = deepcopy(record)
    tampered["coverage"]["coverage_digest"] = "0" * 64
    with pytest.raises(ProviderEnvelopeError, match="coverage digest mismatch"):
        verify_provider_envelope_record(tampered)


def test_conservative_timestamp_interval_only_widens_microsecond_bounds() -> None:
    interval = conservative_timestamp_interval(
        "2026-08-08T12:00:00.999999Z",
        "2026-08-08T12:00:01.000001Z",
    )

    assert interval.valid_from == "2026-08-08T12:00:00Z"
    assert interval.valid_until == "2026-08-08T12:00:02Z"
    record = interval.to_record()
    assert record["conversion"] == "floor-start-ceil-completed"
    assert record["acceptance_pass"] is False
    assert record["pass_credit"] is False

    with pytest.raises(ProviderEnvelopeError, match="UTC Z notation"):
        conservative_timestamp_interval("2026-08-08T12:00:00", "2026-08-08T12:00:01Z")
    with pytest.raises(ProviderEnvelopeError, match="precedes"):
        conservative_timestamp_interval("2026-08-08T12:00:02Z", "2026-08-08T12:00:01Z")
