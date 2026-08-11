from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from promin.input_identity import (
    InputIdentityError,
    bounded_module_closure,
    identity_partition,
    identity_record,
    module_closure_identity,
    provider_input_identity,
)
from promin.provider_envelope import (
    ProviderLanguage,
    ScanMode,
    aggregate_large_project_envelopes,
    contributor_digest_from_artifact,
    contributor_provenance,
    language_driver,
    large_project_provider_envelope,
    multi_language_driver_set,
    provider_driver,
    provider_envelope,
    seal_physical_artifact,
    verify_contributor_artifacts,
)


_LANGUAGE_DRIVERS = (
    (ProviderLanguage.C, "c-compiler", "cc"),
    (ProviderLanguage.CPP, "cpp-compiler", "cxx"),
    (ProviderLanguage.CSHARP, "csharp-compiler", "csc"),
    (ProviderLanguage.JAVA, "java-toolchain", "javac"),
    (ProviderLanguage.JAVASCRIPT, "javascript-runtime", "node"),
    (ProviderLanguage.PYTHON, "python-runtime", "python"),
)


def _module_graph(count: int) -> dict[str, tuple[str, ...]]:
    return {
        f"module-{index:05d}": (() if index + 1 == count else (f"module-{index + 1:05d}",))
        for index in range(count)
    }


def _identity(closure):
    return provider_input_identity(
        repository=identity_partition(
            "repository",
            [identity_record("repository-tree", "content-tree", "1" * 64)],
        ),
        tooling=identity_partition(
            "tooling",
            [identity_record("provider-toolchain", "driver-set", "2" * 64)],
        ),
        dependencies=identity_partition(
            "dependencies",
            [identity_record("provider-dependencies", "dependency-tree", "3" * 64)],
        ),
        target=identity_partition("target", [module_closure_identity(closure)]),
        repository_observation={"git_head": "a" * 40},
    )


def _drivers():
    values = []
    for index, (language, role, driver_id) in enumerate(_LANGUAGE_DRIVERS, start=4):
        values.append(
            language_driver(
                language,
                provider_driver(role, driver_id, f"{index:x}" * 64, version="1.0"),
            )
        )
    return multi_language_driver_set(
        values,
        required_languages=tuple(language for language, _role, _driver in _LANGUAGE_DRIVERS),
    )


@pytest.mark.performance
def test_large_project_identity_aggregate_is_deterministic_and_measures_reuse(
    tmp_path: Path,
) -> None:
    count = 4096
    graph = _module_graph(count)
    reversed_graph = dict(reversed(tuple(graph.items())))
    started = time.perf_counter()
    closure = bounded_module_closure(
        ("module-00000",), graph, max_modules=count, max_edges=count
    )
    reversed_closure = bounded_module_closure(
        ("module-00000",), reversed_graph, max_modules=count, max_edges=count
    )
    assert closure.complete is True
    assert closure.closure_digest == reversed_closure.closure_digest

    identity = _identity(closure)
    language_set = _drivers()
    provider_artifact = tmp_path / "semantic-provider.bin"
    provider_artifact.write_bytes(b"provider-binary-v1")
    provider_seal = seal_physical_artifact(
        provider_artifact, artifact_id="semantic-provider-artifact"
    )

    artifact_paths: dict[str, Path] = {}
    contributors = []
    chunk = count // 8
    for index in range(8):
        contributor_id = f"contributor-{index:02d}"
        artifact = tmp_path / f"{contributor_id}.bin"
        artifact.write_bytes((contributor_id + "\n").encode("utf-8") * 64)
        artifact_paths[contributor_id] = artifact
        lower = index * chunk
        upper = count if index == 7 else (index + 1) * chunk
        contributors.append(
            contributor_digest_from_artifact(
                artifact,
                contributor_id=contributor_id,
                contribution_kind="source-batch",
                module_ids=closure.modules[lower:upper],
            )
        )
    provenance = contributor_provenance(closure, contributors)
    byte_check = verify_contributor_artifacts(provenance, artifact_paths)
    assert byte_check.status == "PASS"
    assert byte_check.checked_contributor_count == 8
    assert byte_check.bytes_rehashed == sum(path.stat().st_size for path in artifact_paths.values())

    midpoint = count // 2
    common = {
        "provider_id": "multi-language-provider",
        "input_identity": identity,
        "physical_seal": provider_seal,
        "global_drivers": language_set.global_drivers,
        "required_driver_roles": tuple(driver.role for driver in language_set.global_drivers),
    }
    full = provider_envelope(
        scan_mode=ScanMode.FULL_SCAN,
        module_subset=closure.modules[:midpoint],
        covered_modules=closure.modules[:midpoint],
        **common,
    )
    reuse = provider_envelope(
        scan_mode=ScanMode.REUSE,
        module_subset=closure.modules[midpoint:],
        covered_modules=closure.modules[midpoint:],
        **common,
    )
    full_large = large_project_provider_envelope(
        envelope=full,
        module_closure=closure,
        contributor_provenance=provenance,
        language_drivers=language_set,
    )
    reuse_parent = "f" * 64
    reuse_large = large_project_provider_envelope(
        envelope=reuse,
        module_closure=closure,
        contributor_provenance=provenance,
        language_drivers=language_set,
        reuse_parent_aggregate_digest=reuse_parent,
    )

    aggregate = aggregate_large_project_envelopes(
        closure,
        (full_large, reuse_large),
        expected_input_identity_digest=identity.input_digest,
        required_languages=tuple(language for language, _role, _driver in _LANGUAGE_DRIVERS),
        known_reuse_parent_aggregate_digests=(reuse_parent,),
        max_envelopes=8,
    )
    reversed_aggregate = aggregate_large_project_envelopes(
        closure,
        (reuse_large, full_large),
        expected_input_identity_digest=identity.input_digest,
        required_languages=tuple(language for language, _role, _driver in _LANGUAGE_DRIVERS),
        known_reuse_parent_aggregate_digests=(reuse_parent,),
        max_envelopes=8,
    )

    assert aggregate.status == "PASS", aggregate.errors
    assert aggregate.aggregate_digest == reversed_aggregate.aggregate_digest
    assert aggregate.metrics.envelope_count == 2
    assert aggregate.metrics.full_scan_envelope_count == 1
    assert aggregate.metrics.reuse_envelope_count == 1
    assert aggregate.metrics.reused_module_count == midpoint
    assert aggregate.metrics.contributor_count == 8
    assert aggregate.metrics.reused_contributor_count == 8
    assert aggregate.metrics.elapsed_seconds >= 0
    assert aggregate.to_record()["acceptance_pass"] is False
    assert aggregate.to_record()["pass_credit"] is False
    # This is a real 4k-node/4k-edge deterministic closure, not a reduced
    # proxy sample.  Keep only a deliberately generous regression ceiling.
    assert time.perf_counter() - started < 12.0


def test_large_project_reuse_requires_known_parent_and_byte_authoritative_contributors(
    tmp_path: Path,
) -> None:
    graph = _module_graph(32)
    closure = bounded_module_closure(
        ("module-00000",), graph, max_modules=32, max_edges=32
    )
    identity = _identity(closure)
    language_set = _drivers()
    provider_artifact = tmp_path / "provider.bin"
    provider_artifact.write_bytes(b"provider-v1")
    contributor_artifact = tmp_path / "contributor.bin"
    contributor_artifact.write_bytes(b"contributor-bytes-v1")
    contributor = contributor_digest_from_artifact(
        contributor_artifact,
        contributor_id="contributor-one",
        contribution_kind="source-batch",
        module_ids=closure.modules,
    )
    provenance = contributor_provenance(closure, (contributor,))
    common = {
        "provider_id": "multi-language-provider",
        "input_identity": identity,
        "physical_seal": seal_physical_artifact(provider_artifact, artifact_id="provider-artifact"),
        "global_drivers": language_set.global_drivers,
        "required_driver_roles": tuple(driver.role for driver in language_set.global_drivers),
        "module_subset": closure.modules,
        "covered_modules": closure.modules,
    }
    full = large_project_provider_envelope(
        envelope=provider_envelope(scan_mode="FullScan", **common),
        module_closure=closure,
        contributor_provenance=provenance,
        language_drivers=language_set,
    )
    parent = "e" * 64
    reuse = large_project_provider_envelope(
        envelope=provider_envelope(scan_mode="Reuse", **common),
        module_closure=closure,
        contributor_provenance=provenance,
        language_drivers=language_set,
        reuse_parent_aggregate_digest=parent,
    )
    unknown_parent = aggregate_large_project_envelopes(
        closure,
        (full, reuse),
        expected_input_identity_digest=identity.input_digest,
    )
    assert unknown_parent.status == "FAIL"
    assert any("parent aggregate" in error for error in unknown_parent.errors)

    original = contributor_artifact.read_bytes()
    original_state = contributor_artifact.stat()
    contributor_artifact.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    os.utime(contributor_artifact, ns=(original_state.st_atime_ns, original_state.st_mtime_ns))
    byte_check = verify_contributor_artifacts(
        provenance, {"contributor-one": contributor_artifact}
    )
    assert byte_check.status == "FAIL"
    assert byte_check.failed_contributor_ids == ("contributor-one",)


def test_bounded_module_closure_cannot_be_promoted_when_truncated() -> None:
    closure = bounded_module_closure(
        ("module-00000",), _module_graph(256), max_modules=64, max_edges=256
    )

    assert closure.status == "UNAVAILABLE"
    assert closure.truncated is True
    assert closure.to_record()["pass_credit"] is False
    with pytest.raises(InputIdentityError, match="truncated module closure"):
        module_closure_identity(closure)

    scoped = bounded_module_closure(
        ("@scope/web",),
        {"@scope/web": ("python.package",), "python.package": ()},
        max_modules=2,
        max_edges=1,
    )
    assert scoped.complete is True
    assert scoped.modules == ("@scope/web", "python.package")
