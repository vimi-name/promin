from __future__ import annotations

from copy import deepcopy
import shutil
import sys
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = PACKAGE_ROOT / "tools"
for entry in (str(TOOLS_ROOT), str(PACKAGE_ROOT)):
    while entry in sys.path:
        sys.path.remove(entry)
    sys.path.insert(0, entry)

from promin.authority import canonical_digest
from promin.evidence import EvidenceError, _validate_exact_artifact_binding
from promin_package import _write_archive, write_integrity
from promin_saturation import build_artifact_binding
from promin_validate import CANONICAL_PACKAGE_FILES


def _candidate_binding() -> dict[str, object]:
    identity: dict[str, object] = {
        "record_type": "StandardReleaseCandidateBinding",
        "standard_name": "promin",
        "version": "1.0.0-alpha.4",
        "archive_sha256": "0" * 64,
        "archive_bytes": 9_296_433,
        "archive_member_manifest_digest": "1" * 64,
        "package_manifest_digest": "2" * 64,
        "checksums_digest": "3" * 64,
        "core_bundle_digest": "4" * 64,
        "preset_digest": "5" * 64,
        "package_tool_digest": "6" * 64,
        "validator_digest": "7" * 64,
        "test_manifest_digest": "8" * 64,
        "portable_implementation_closure_digest": "9" * 64,
        "evidence_tool_digests": {
            "tools/generate_human.py": "a" * 64,
            "tools/promin_no_degradation.py": "b" * 64,
            "tools/promin_package.py": "c" * 64,
            "tools/promin_saturation.py": "d" * 64,
            "tools/promin_saturation_audit.py": "e" * 64,
            "tools/promin_validate.py": "f" * 64,
        },
    }
    return {**identity, "candidate_binding_digest": canonical_digest(identity)}


def _artifact_binding(archive_name: str) -> tuple[dict[str, object], dict[str, object]]:
    candidate = _candidate_binding()
    platform_identity = {
        "system": "windows",
        "release": "fixture",
        "machine": "amd64",
        "python_implementation": "CPython",
        "python_version": "3.14.0",
        "python_executable_sha256": "sha256:" + "a" * 64,
        "sqlite_version": "3.50.4",
        "profile_key": "windows-amd64-cpython-3.14",
    }
    platform = {
        **platform_identity,
        "binding_digest": "sha256:" + canonical_digest(platform_identity),
    }
    binding: dict[str, object] = {
        "record_type": "ExactArtifactBinding",
        "protocol_version": "promin-evidence-v1",
        "archive": {
            "name": archive_name,
            "sha256": "sha256:" + str(candidate["archive_sha256"]),
            "bytes": candidate["archive_bytes"],
            "member_count": 245,
            "manifest_member_bytes_match": True,
        },
        "package_manifest_sha256": "sha256:" + str(candidate["package_manifest_digest"]),
        "checksums_sha256": "sha256:" + str(candidate["checksums_digest"]),
        "core_bundle_digest": "sha256:" + str(candidate["core_bundle_digest"]),
        "preset": {
            "path": "presets/semantic-standard.json",
            "sha256": "sha256:" + str(candidate["preset_digest"]),
        },
        "tools": [
            {
                "path": path,
                "version": "fixture-v1",
                "sha256": "sha256:" + digest,
                "bytes": 1,
            }
            for path, digest in candidate["evidence_tool_digests"].items()
            if path != "tools/generate_human.py"
        ],
        "platform": platform,
        "standard_candidate_binding": deepcopy(candidate),
        "candidate_binding_digest": candidate["candidate_binding_digest"],
    }
    binding["binding_digest"] = "sha256:" + canonical_digest(binding)
    return binding, candidate


@pytest.mark.parametrize(
    "archive_name",
    [
        "promin-1.0.0-alpha.4-heavy-verified-r6.zip",
        "promin-1.0.0-alpha.4-heavy-verified-r7.zip",
    ],
)
def test_exact_binding_accepts_digest_bound_versioned_archive_basename(
    archive_name: str,
) -> None:
    binding, candidate = _artifact_binding(archive_name)

    _validate_exact_artifact_binding(binding, candidate=candidate)


def test_real_versioned_archive_name_roundtrips_through_producer_and_validator(
    tmp_path: Path,
) -> None:
    package_root = tmp_path / "promin"
    for relative in sorted(CANONICAL_PACKAGE_FILES, key=lambda value: value.encode("utf-8")):
        source = PACKAGE_ROOT.joinpath(*relative.split("/"))
        target = package_root.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    write_integrity(package_root)
    archive = tmp_path / "promin-1.0.0-alpha.4-heavy-verified-r7.zip"
    _write_archive(package_root, archive)

    binding = build_artifact_binding(package_root, archive)

    assert binding["archive"]["name"] == archive.name
    _validate_exact_artifact_binding(
        binding,
        candidate=binding["standard_candidate_binding"],
    )


@pytest.mark.parametrize(
    "archive_name",
    [
        "",
        ".",
        "..",
        "../promin.zip",
        "subdir/promin.zip",
        "subdir\\promin.zip",
        "promin.ZIP",
        "promin.zip\x00suffix",
        "pro\u0301min.zip",
        "CON.zip",
        "promin:.zip",
        "promin space.zip",
        "a" * 125 + ".zip",
    ],
)
def test_exact_binding_rejects_unsafe_archive_basename_even_when_resigned(
    archive_name: str,
) -> None:
    binding, candidate = _artifact_binding("promin.zip")
    binding["archive"]["name"] = archive_name
    binding["binding_digest"] = "sha256:" + canonical_digest(
        {key: value for key, value in binding.items() if key != "binding_digest"}
    )

    with pytest.raises(EvidenceError, match="safe ZIP basename"):
        _validate_exact_artifact_binding(binding, candidate=candidate)


def test_exact_binding_still_rejects_archive_identity_drift() -> None:
    binding, candidate = _artifact_binding("promin-1.0.0-alpha.4-heavy-verified-r7.zip")
    binding["archive"]["sha256"] = "sha256:" + "f" * 64
    binding["binding_digest"] = "sha256:" + canonical_digest(
        {key: value for key, value in binding.items() if key != "binding_digest"}
    )

    with pytest.raises(EvidenceError, match="archive binding is invalid"):
        _validate_exact_artifact_binding(binding, candidate=candidate)
