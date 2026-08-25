from __future__ import annotations

import json
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from jsonschema import Draft202012Validator

from promin.evidence import (
    EvidenceError,
    canonical_digest,
    _is_valid_saturation_raw_artifact_binding,
    _parse_raw_jsonl,
    _resolve_saturation_raw_artifact_binding,
    _saturation_continuation_state_within_limit,
    _validate_saturation_raw_artifacts,
    _validate_saturation_continuation_state,
)

import tools.promin_saturation as saturation


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CONTINUATION_ROLE = "continuation-state-manifest"
REQUIRED_NONEMPTY_ROLES = (
    "inventory-stream",
    "physical-relation-evidence",
    "query-results",
    "process-samples",
    "phase-log",
    "operation-metrics",
)
ARTIFACT_LAYOUT = {
    "inventory-stream": ("raw/inventory-stream.jsonl", "application/x-ndjson"),
    "physical-relation-evidence": (
        "raw/physical-relation-evidence.jsonl",
        "application/x-ndjson",
    ),
    "query-results": ("raw/query-results.jsonl", "application/x-ndjson"),
    "process-samples": ("raw/process-samples.json", "application/json"),
    CONTINUATION_ROLE: (
        "raw/continuation-state-manifest.jsonl",
        "application/x-ndjson",
    ),
    "phase-log": ("raw/phase-log.jsonl", "application/x-ndjson"),
    "operation-metrics": ("raw/operation-metrics.json", "application/json"),
}


def _artifact(*, role: str, byte_count: int, record_count: int) -> dict[str, object]:
    path, media_type = ARTIFACT_LAYOUT[role]
    return {
        "role": role,
        "path": path,
        "media_type": media_type,
        "sha256": "0" * 64,
        "bytes": byte_count,
        "records": record_count,
    }


def _artifact_validator() -> Draft202012Validator:
    schema = json.loads(
        (PACKAGE_ROOT / "core" / "contracts.schema.json").read_text(encoding="utf-8")
    )
    return Draft202012Validator(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": (
                "#/$defs/SaturationEvidence/properties/raw_artifact_manifest/"
                "properties/artifacts/items"
            ),
            "$defs": schema["$defs"],
        }
    )


def _raw_manifest_validator() -> Draft202012Validator:
    schema = json.loads(
        (PACKAGE_ROOT / "core" / "contracts.schema.json").read_text(encoding="utf-8")
    )
    return Draft202012Validator(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": "#/$defs/SaturationEvidence/properties/raw_artifact_manifest",
            "$defs": schema["$defs"],
        }
    )


def test_empty_continuation_manifest_is_a_bound_zero_record_artifact() -> None:
    validator = _artifact_validator()

    assert list(
        validator.iter_errors(
            _artifact(role=CONTINUATION_ROLE, byte_count=0, record_count=0)
        )
    ) == []
    assert _is_valid_saturation_raw_artifact_binding(
        _artifact(role=CONTINUATION_ROLE, byte_count=0, record_count=0)
    )
    empty_state = {
        "files": 0,
        "maximum_bytes": 0,
        "total_bytes": 0,
        "preexisting_files_excluded": 0,
    }
    assert saturation._continuation_state_within_limit(empty_state) is True
    assert (
        _parse_raw_jsonl(
            b"",
            "continuation state manifest",
            max_records=100_000,
            allow_empty=True,
        )
        == []
    )


def test_raw_jsonl_remains_nonempty_by_default() -> None:
    with pytest.raises(EvidenceError, match="must be non-empty"):
        _parse_raw_jsonl(b"", "query results", max_records=100_000)


def test_semantic_validator_accepts_empty_stateless_continuation_manifest() -> None:
    binding = _artifact(role=CONTINUATION_ROLE, byte_count=0, record_count=0)
    search = {
        "continuation_state": {
            "files": 0,
            "maximum_bytes": 0,
            "total_bytes": 0,
            "preexisting_files_excluded": 0,
        }
    }

    assert _validate_saturation_continuation_state(binding, b"", search) == []

    for field, value in (("files", 1), ("maximum_bytes", 1), ("total_bytes", 1)):
        tampered = json.loads(json.dumps(search))
        tampered["continuation_state"][field] = value
        with pytest.raises(EvidenceError, match="summary cannot be recomputed"):
            _validate_saturation_continuation_state(binding, b"", tampered)


def test_physical_empty_continuation_artifact_is_exactly_content_bound() -> None:
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        raw = root / "raw"
        raw.mkdir()
        target = raw / "continuation-state-manifest.jsonl"
        target.write_bytes(b"")
        binding = _artifact(
            role=CONTINUATION_ROLE,
            byte_count=0,
            record_count=0,
        )
        binding["sha256"] = hashlib.sha256(b"").hexdigest()

        relative, stable = _resolve_saturation_raw_artifact_binding(
            binding,
            source_directory=root,
            evidence_root=root,
        )
        assert relative == "raw/continuation-state-manifest.jsonl"
        assert stable.payload == b""
        assert stable.sha256 == hashlib.sha256(b"").hexdigest()

        wrong_digest = dict(binding)
        wrong_digest["sha256"] = "0" * 64
        with pytest.raises(EvidenceError, match="content binding mismatch"):
            _resolve_saturation_raw_artifact_binding(
                wrong_digest,
                source_directory=root,
                evidence_root=root,
            )

        for field, value in (
            ("media_type", "application/json"),
            ("role", "query-results"),
        ):
            malformed = dict(binding)
            malformed[field] = value
            with pytest.raises(EvidenceError, match="binding is invalid"):
                _resolve_saturation_raw_artifact_binding(
                    malformed,
                    source_directory=root,
                    evidence_root=root,
                )

        target.unlink()
        with pytest.raises(EvidenceError):
            _resolve_saturation_raw_artifact_binding(
                binding,
                source_directory=root,
                evidence_root=root,
            )


@pytest.mark.parametrize("role", REQUIRED_NONEMPTY_ROLES)
def test_required_saturation_artifacts_remain_nonempty(role: str) -> None:
    validator = _artifact_validator()

    assert list(
        validator.iter_errors(_artifact(role=role, byte_count=0, record_count=0))
    )
    assert not _is_valid_saturation_raw_artifact_binding(
        _artifact(role=role, byte_count=0, record_count=0)
    )
    records = 198_999 if role == "physical-relation-evidence" else 1
    assert list(validator.iter_errors(_artifact(role=role, byte_count=1, record_count=records))) == []


@pytest.mark.parametrize(
    ("byte_count", "record_count"),
    ((0, 1), (1, 0)),
)
def test_continuation_manifest_zero_cardinality_is_atomic(
    byte_count: int,
    record_count: int,
) -> None:
    validator = _artifact_validator()

    artifact = _artifact(
        role=CONTINUATION_ROLE,
        byte_count=byte_count,
        record_count=record_count,
    )
    assert list(validator.iter_errors(artifact))
    assert not _is_valid_saturation_raw_artifact_binding(artifact)


def test_artifact_role_cannot_claim_another_roles_path() -> None:
    validator = _artifact_validator()
    artifact = _artifact(role="query-results", byte_count=1, record_count=1)
    artifact["path"] = ARTIFACT_LAYOUT[CONTINUATION_ROLE][0]

    assert list(validator.iter_errors(artifact))
    assert not _is_valid_saturation_raw_artifact_binding(artifact)


def test_exact_physical_inventory_is_one_stream_artifact_not_per_file_semantic_artifacts() -> None:
    """The raw manifest binds the 100k-file stream, never 100k Artifact records."""

    validator = _artifact_validator()
    manifest_validator = _raw_manifest_validator()
    seven_role_artifacts = [
        _artifact(
            role=role,
            byte_count=1,
            record_count=198_999 if role == "physical-relation-evidence" else 1,
        )
        for role in ARTIFACT_LAYOUT
    ]
    assert len(seven_role_artifacts) == 7
    assert all(list(validator.iter_errors(item)) == [] for item in seven_role_artifacts)

    manifest_base = {
        "record_type": "SaturationRawArtifactManifest",
        "path_scope": "saturation-result-directory",
        "evidence_class": "harness_generated",
        "product_acceptance_credit": False,
        "artifacts": seven_role_artifacts,
        "artifact_count": 7,
        "inventory_stream_digest": "0" * 64,
        "inventory_identity_digest": "1" * 64,
        "manifest_digest": "2" * 64,
    }
    assert list(manifest_validator.iter_errors(manifest_base)) == []

    per_file_artifacts = [
        _artifact(role="inventory-stream", byte_count=1, record_count=1)
        for _ in range(8)
    ]
    # The seven-role closure is the guard against semantic materialization
    # of one Artifact record per physical file; physical rows remain in the
    # inventory stream and are validated by their exact stream digest/count.
    oversized_manifest = dict(manifest_base)
    oversized_manifest["artifacts"] = per_file_artifacts
    oversized_manifest["artifact_count"] = 8
    assert list(manifest_validator.iter_errors(oversized_manifest))


def test_physical_relation_evidence_binding_is_exactly_198999_records() -> None:
    relation = _artifact(
        role="physical-relation-evidence",
        byte_count=1,
        record_count=198_999,
    )
    assert relation["path"] == "raw/physical-relation-evidence.jsonl"
    assert relation["media_type"] == "application/x-ndjson"
    assert _is_valid_saturation_raw_artifact_binding(relation)

    for field, value in (
        ("path", "raw/inventory-stream.jsonl"),
        ("media_type", "application/json"),
        ("records", 198_998),
    ):
        malformed = dict(relation)
        malformed[field] = value
        assert not _is_valid_saturation_raw_artifact_binding(malformed)


def test_production_validator_rejects_duplicate_inventory_and_missing_relation_roles(
    tmp_path: Path,
) -> None:
    """Seven-role closure rejects duplicate inventory and missing relation roles."""

    raw = tmp_path / "raw"
    raw.mkdir()
    payload = b"{}\n"
    artifacts = []
    for index in range(6):
        relative = f"raw/inventory-{index}.jsonl"
        (tmp_path / relative).write_bytes(payload)
        artifacts.append(
            {
                "role": "inventory-stream",
                "path": relative,
                "media_type": "application/x-ndjson",
                "sha256": hashlib.sha256(payload).hexdigest(),
                "bytes": len(payload),
                "records": 1,
            }
        )
    identity = {
        "record_type": "SaturationRawArtifactManifest",
        "path_scope": "saturation-result-directory",
        "evidence_class": "harness_generated",
        "product_acceptance_credit": False,
        "artifacts": artifacts,
        "artifact_count": len(artifacts),
        "inventory_stream_digest": hashlib.sha256(payload).hexdigest(),
        "inventory_identity_digest": "1" * 64,
    }
    manifest = {**identity, "manifest_digest": canonical_digest(identity)}

    with pytest.raises(EvidenceError, match="saturation raw artifact set is incomplete"):
        _validate_saturation_raw_artifacts(
            {"raw_artifact_manifest": manifest},
            source_path=tmp_path / "saturation-result.json",
            evidence_root=tmp_path,
        )


@pytest.mark.parametrize(
    "metrics",
    (
        {"files": 1, "maximum_bytes": 0, "total_bytes": 0, "preexisting_files_excluded": 0},
        {"files": 0, "maximum_bytes": 1, "total_bytes": 1, "preexisting_files_excluded": 0},
        {"files": 1, "maximum_bytes": 2, "total_bytes": 1, "preexisting_files_excluded": 0},
        {"files": 2, "maximum_bytes": 1, "total_bytes": 1, "preexisting_files_excluded": 0},
        {"files": 1, "maximum_bytes": 1, "total_bytes": 2, "preexisting_files_excluded": 0},
        {"files": 1, "maximum_bytes": 16_385, "total_bytes": 16_385, "preexisting_files_excluded": 0},
        {"files": True, "maximum_bytes": 1, "total_bytes": 1, "preexisting_files_excluded": 0},
    ),
)
def test_continuation_state_limit_rejects_inconsistent_metrics(metrics: dict) -> None:
    assert saturation._continuation_state_within_limit(metrics) is False
    assert _saturation_continuation_state_within_limit(metrics) is False
