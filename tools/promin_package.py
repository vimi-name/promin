#!/usr/bin/env python3
"""Build and verify a deterministic, self-verifying promin archive."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
import secrets
import stat
import sys
import tempfile
import unicodedata
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

sys.dont_write_bytecode = True

TOOLS_ROOT = Path(__file__).resolve().parent
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
for entry in (str(TOOLS_ROOT), str(PACKAGE_ROOT)):
    while entry in sys.path:
        sys.path.remove(entry)
if os.environ.get("PROMIN_INSTALLED_TEST_MODE") == "1":
    sys.path.append(str(TOOLS_ROOT))
else:
    sys.path.insert(0, str(PACKAGE_ROOT))
    sys.path.insert(1, str(TOOLS_ROOT))

from promin.evidence import (
    EvidenceError,
    load_external_json_stable,
    read_external_bytes_stable,
    release_evidence_invocation,
    release_evidence_producer,
    seal_release_evidence,
    standard_distribution_status,
    validate_standard_release_candidate_binding,
    validate_standard_release_decision,
    validate_standard_release_evidence_manifest,
)
from promin.authority import parse_timestamp

from promin_validate import (
    CANONICAL_PACKAGE_FILES,
    GENERATED_SURFACES,
    ValidationFailure,
    add_verification_arguments,
    build_human_document_verification,
    _validate_schema_instance,
    distribution_identity,
    font_bindings_from_args,
    iter_regular_files,
    load_json,
    normalized_path_key,
    sha256_file,
    validate_relative_path,
    validate_tree,
    verify_package_inventory,
    verify_package_integrity,
)


FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
ZIP_METHOD = zipfile.ZIP_STORED
MAX_ARCHIVE_FILES = 10_000
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_COMPRESSION_RATIO = 1_000


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _write_json(path: Path, value: Any) -> None:
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(rendered, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def _canonical_digest(value: Any) -> str:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    return hashlib.sha256(payload).hexdigest()


def _stable_archive_digest(path: Path) -> tuple[str, os.stat_result]:
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or path.is_symlink():
        raise ValidationFailure(f"archive must be a regular non-symlink file: {path}")
    digest = sha256_file(path)
    after = path.stat(follow_symlinks=False)
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after:
        raise ValidationFailure(f"archive changed while hashing: {path}")
    return digest, after


def _candidate_binding(artifact_binding: dict[str, Any], archive_bytes: int) -> dict[str, Any]:
    identity = {
        "record_type": "StandardReleaseCandidateBinding",
        "standard_name": "promin",
        "version": artifact_binding["version"],
        "archive_sha256": artifact_binding["archive_sha256"],
        "archive_bytes": archive_bytes,
        "archive_member_manifest_digest": artifact_binding["archive_member_manifest_digest"],
        "package_manifest_digest": artifact_binding["package_manifest_digest"],
        "checksums_digest": artifact_binding["checksums_digest"],
        "core_bundle_digest": artifact_binding["core_bundle_digest"],
        "preset_digest": artifact_binding["preset_digest"],
        "package_tool_digest": artifact_binding["package_tool_digest"],
        "validator_digest": artifact_binding["validator_digest"],
        "test_manifest_digest": artifact_binding["test_manifest_digest"],
        "portable_implementation_closure_digest": artifact_binding[
            "portable_implementation_closure_digest"
        ],
        "evidence_tool_digests": artifact_binding["evidence_tool_digests"],
    }
    binding = {**identity, "candidate_binding_digest": _canonical_digest(identity)}
    validate_standard_release_candidate_binding(binding)
    return binding


def build_evidence_manifest(
    archive_path: Path,
    candidate_binding_path: Path,
    evidence_root: Path,
    plan_path: Path,
    trust_configuration_path: Path,
    output_path: Path,
    *,
    expected_trust_root_sha256: str,
) -> dict[str, Any]:
    exact = verify_archive(
        archive_path,
        install_mode=None,
        candidate_binding=candidate_binding_path,
    )
    candidate = exact["candidate_binding"]
    trust_read = load_external_json_stable(trust_configuration_path)
    if (
        not isinstance(expected_trust_root_sha256, str)
        or len(expected_trust_root_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_trust_root_sha256)
        or trust_read.sha256 != expected_trust_root_sha256
    ):
        raise ValidationFailure("standard evidence trust configuration differs from the pinned SHA-256")
    trust = trust_read.value
    plan = load_external_json_stable(plan_path).value
    if (
        set(plan)
        != {"record_type", "entries", "matrix_aggregate", "supplemental_lanes"}
        or plan.get("record_type") != "StandardReleaseEvidencePlan"
    ):
        raise ValidationFailure("standard evidence plan shape is invalid")
    planned = plan.get("entries")
    required_roles = {
        "human-documents",
        "linux",
        "linux-no-degradation",
        "physical-scale",
        "saturation-audit",
        "windows",
        "windows-no-degradation",
    }
    if (
        not isinstance(planned, list)
        or len(planned) != 7
        or any(not isinstance(item, dict) for item in planned)
        or {item.get("evidence_role") for item in planned} != required_roles
    ):
        raise ValidationFailure("standard evidence plan must contain exactly seven roles")
    root = evidence_root.absolute()
    entries: list[dict[str, Any]] = []
    completion_times: list[tuple[datetime, str]] = []
    for item in planned:
        if not isinstance(item, dict) or set(item) != {
            "evidence_id",
            "evidence_role",
            "path",
            "predicates",
        }:
            raise ValidationFailure("standard evidence plan entry shape is invalid")
        relative = item["path"]
        validate_relative_path(relative)
        path = root.joinpath(*PurePosixPath(relative).parts)
        try:
            path.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as exc:
            raise ValidationFailure("standard evidence plan path is unresolved") from exc
        evidence_read = load_external_json_stable(path, root=root)
        evidence = evidence_read.value
        invocation = evidence.get("invocation")
        if not isinstance(invocation, dict):
            raise EvidenceError("release evidence record omits its invocation")
        completed_at = invocation.get("completed_at")
        try:
            completed_time = parse_timestamp(completed_at)
        except Exception as exc:
            raise ValidationFailure("standard evidence completion time is invalid") from exc
        completion_times.append((completed_time, completed_at))
        entries.append(
            {
                **item,
                "sha256": evidence_read.sha256,
                "size_bytes": evidence_read.size_bytes,
                "record_type": evidence.get("record_type"),
                "status": evidence.get("status"),
                "candidate_binding_digest": evidence.get("candidate_binding_digest"),
            }
        )
    matrix_plan = plan.get("matrix_aggregate")
    if not isinstance(matrix_plan, dict) or set(matrix_plan) != {"path"}:
        raise ValidationFailure("standard evidence plan matrix binding shape is invalid")
    matrix_relative = matrix_plan.get("path")
    if matrix_relative != "matrix-current/platform-no-degradation-matrix.json":
        raise ValidationFailure("standard evidence plan matrix path is not canonical")
    validate_relative_path(matrix_relative)
    matrix_path = root.joinpath(*PurePosixPath(matrix_relative).parts)
    matrix_read = load_external_json_stable(matrix_path, root=root)
    matrix = matrix_read.value
    matrix_binding = {
        "path": matrix_relative,
        "sha256": matrix_read.sha256,
        "size_bytes": matrix_read.size_bytes,
        "record_type": matrix.get("record_type"),
        "matrix_digest": matrix.get("matrix_digest"),
        "lane_count": matrix.get("lane_count"),
        "matrix_authoritative": matrix.get("matrix_authoritative"),
        "pass_credit": matrix.get("pass_credit"),
        "acceptance_pass": matrix.get("acceptance_pass"),
        "product_acceptance_pass": matrix.get("product_acceptance_pass"),
        "product_public_approval": matrix.get("product_public_approval"),
    }
    supplemental_plan = plan.get("supplemental_lanes")
    if (
        not isinstance(supplemental_plan, list)
        or len(supplemental_plan) != 4
        or any(
            not isinstance(item, dict) or set(item) != {"lane_id", "path"}
            for item in supplemental_plan
        )
        or [(item["lane_id"], item["path"]) for item in supplemental_plan]
        != [
            (
                "linux-cp314-offline",
                "no-degradation-current/linux-cp314-offline.json",
            ),
            (
                "linux-cp314-online",
                "platform-matrix-current/linux-cp314-online.json",
            ),
            (
                "windows-cp314-offline",
                "no-degradation-current/windows-cp314-offline.json",
            ),
            (
                "windows-cp314-online",
                "platform-matrix-current/windows-cp314-online.json",
            ),
        ]
    ):
        raise ValidationFailure("standard evidence plan CP314 supplemental lane set is not exact")
    supplemental_lanes: list[dict[str, Any]] = []
    for item in supplemental_plan:
        relative = item["path"]
        validate_relative_path(relative)
        record_read = load_external_json_stable(
            root.joinpath(*PurePosixPath(relative).parts),
            root=root,
        )
        record = record_read.value
        invocation = record.get("invocation")
        attestation = record.get("producer_attestation")
        if not isinstance(invocation, dict) or not isinstance(attestation, dict):
            raise ValidationFailure("supplemental CP314 evidence envelope is absent")
        completed_at = invocation.get("completed_at")
        try:
            completion_times.append((parse_timestamp(completed_at), completed_at))
        except Exception as exc:
            raise ValidationFailure("supplemental CP314 completion time is invalid") from exc
        supplemental_lanes.append(
            {
                "lane_id": item["lane_id"],
                "path": relative,
                "sha256": record_read.sha256,
                "size_bytes": record_read.size_bytes,
                "record_type": record.get("record_type"),
                "status": record.get("status"),
                "candidate_binding_digest": record.get("candidate_binding_digest"),
                "result_digest": record.get("result_digest"),
                "evidence_role": attestation.get("evidence_role"),
                "producer_attestation_digest": _canonical_digest(attestation),
            }
        )
    identity = {
        "record_type": "StandardReleaseEvidenceManifest",
        "standard_name": "promin",
        "version": candidate["version"],
        "candidate_binding_digest": candidate["candidate_binding_digest"],
        "entries": entries,
        "matrix_aggregate": matrix_binding,
        "supplemental_lanes": supplemental_lanes,
        "max_evidence_completed_at": max(completion_times, key=lambda row: row[0])[0]
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
    manifest = {**identity, "evidence_manifest_digest": _canonical_digest(identity)}
    validate_standard_release_evidence_manifest(
        manifest,
        candidate_binding=candidate,
        evidence_root=root,
        trust_configuration=trust,
        candidate_document_members=exact["candidate_document_members"],
    )
    _write_json(output_path.resolve(), manifest)
    return manifest


def sign_standard_decision(
    archive_path: Path,
    candidate_binding_path: Path,
    evidence_manifest_path: Path,
    evidence_root: Path,
    trust_configuration_path: Path,
    private_key_path: Path,
    output_path: Path,
    *,
    decision_id: str,
    outcome: str,
    decider_id: str,
    key_id: str,
    decided_at: str,
    nonce: str | None = None,
) -> dict[str, Any]:
    exact = verify_archive(
        archive_path,
        install_mode=None,
        candidate_binding=candidate_binding_path,
    )
    candidate = exact["candidate_binding"]
    evidence_manifest = load_external_json_stable(evidence_manifest_path).value
    trust = load_external_json_stable(trust_configuration_path).value
    validate_standard_release_evidence_manifest(
        evidence_manifest,
        candidate_binding=candidate,
        evidence_root=evidence_root,
        trust_configuration=trust,
        candidate_document_members=exact["candidate_document_members"],
    )
    identity = {
        "record_type": "StandardReleaseDecision",
        "decision_id": decision_id,
        "standard_name": "promin",
        "version": candidate["version"],
        "candidate_binding_digest": candidate["candidate_binding_digest"],
        "evidence_manifest_digest": evidence_manifest.get("evidence_manifest_digest"),
        "outcome": outcome,
        "decider_id": decider_id,
        "release_capability": "standard.distribute",
        "trust_root_id": trust.get("trust_root_id"),
        "signature_provider_id": trust.get("signature_provider_id"),
        "key_id": key_id,
        "nonce": nonce or base64.b64encode(secrets.token_bytes(24)).decode("ascii"),
        "decided_at": decided_at,
    }
    claim_digest = _canonical_digest(identity)
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = serialization.load_pem_private_key(
            read_external_bytes_stable(
                private_key_path, max_bytes=64 * 1024
            ).payload,
            password=None,
        )
        if not isinstance(key, Ed25519PrivateKey):
            raise ValidationFailure("standard decision private key must be Ed25519")
        signature = key.sign(bytes.fromhex(claim_digest))
    except ImportError as exc:
        raise ValidationFailure("configured Ed25519 signer is unavailable") from exc
    decision = {
        **identity,
        "signed_claim_digest": claim_digest,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    validate_standard_release_decision(
        decision,
        candidate_binding=candidate,
        evidence_manifest=evidence_manifest,
        evidence_root=evidence_root,
        trust_configuration=trust,
        candidate_document_members=exact["candidate_document_members"],
    )
    _write_json(output_path.resolve(), decision)
    return decision


def sync_version(root: Path) -> None:
    manifest = load_json(root / "core" / "promin.manifest.json")
    preset_path = root / "presets" / "semantic-morok-tower.json"
    distribution = distribution_identity(root)
    version = {
        "canonical_name": "promin",
        "core_bundle_digest": manifest["bundle_digest"],
        "integrity": {
            "archive_sha256": "external",
            "checksums": "SHA256SUMS.txt",
            "manifest": "MANIFEST.json",
        },
        "record_type": "StandardVersion",
        "selected_preset": {
            "path": "presets/semantic-morok-tower.json",
            "sha256": sha256_file(preset_path),
        },
        "version": distribution["version"],
    }
    _write_json(root / "VERSION.json", version)


def write_integrity(root: Path) -> dict[str, Any]:
    root = root.resolve()
    verify_package_inventory(root, require_generated=False)
    distribution = distribution_identity(root)
    for name in GENERATED_SURFACES:
        candidate = root / name
        if candidate.exists():
            if candidate.is_symlink() or not candidate.is_file():
                raise ValidationFailure(f"generated surface is not a regular file: {name}")
    payload = iter_regular_files(root, include_generated=False)
    manifest = {
        "builder": "tools/promin_package.py",
        "files": [
            {"path": rel, "sha256": sha256_file(path), "size": path.stat().st_size}
            for rel, path in payload
        ],
        "generated_surfaces": sorted(GENERATED_SURFACES),
        "record_type": "ProminPackageManifest",
        "root": "promin",
        "version": distribution["version"],
    }
    _write_json(root / "MANIFEST.json", manifest)
    checksum_files = sorted(
        payload + [("MANIFEST.json", root / "MANIFEST.json")],
        key=lambda item: item[0].encode("utf-8"),
    )
    lines = [f"{sha256_file(path)}  {rel}" for rel, path in checksum_files]
    sums_path = root / "SHA256SUMS.txt"
    sums_temporary = sums_path.with_name(sums_path.name + ".tmp")
    sums_temporary.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    os.replace(sums_temporary, sums_path)
    return {"payload_files": len(payload), "checksum_entries": len(lines)}


def _write_archive(root: Path, destination: Path) -> None:
    verify_package_integrity(root)
    files = iter_regular_files(root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        destination,
        mode="w",
        compression=ZIP_METHOD,
        strict_timestamps=True,
    ) as archive:
        archive.comment = b""
        for rel, path in files:
            name = f"promin/{rel}"
            info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
            info.compress_type = ZIP_METHOD
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.internal_attr = 0
            archive.writestr(info, path.read_bytes(), compress_type=ZIP_METHOD)


def build_archive(
    root: Path,
    destination: Path,
    *,
    install_mode: str | None = "current-environment",
    wheelhouse: Path | None = None,
    rebuild_docs: bool = False,
    font_bindings: dict[str, tuple[Path, str]] | None = None,
    candidate_binding_output: Path | None = None,
) -> dict[str, Any]:
    if root.is_symlink():
        raise ValidationFailure("source root symlink rejected")
    root = root.resolve()
    if destination.is_symlink():
        raise ValidationFailure("archive destination symlink rejected")
    destination = destination.resolve()
    if root.name != "promin":
        raise ValidationFailure("source root must be exactly lowercase promin")
    try:
        destination.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValidationFailure("archive destination must be outside the packaged root")
    if candidate_binding_output is not None:
        binding_path = candidate_binding_output.resolve()
        try:
            binding_path.relative_to(root)
        except ValueError:
            pass
        else:
            raise ValidationFailure("candidate binding must remain outside the canonical package")
        if binding_path == destination:
            raise ValidationFailure("candidate binding and archive paths must differ")
    sync_version(root)
    # The clean-archive verification below is the authoritative document check:
    # it parses the exact PDF bytes that will become the candidate.  Running the
    # same expensive text extraction for the source tree at both preflight and
    # post-integrity stages does not add coverage, because integrity generation
    # cannot change a human document.  Keep structural/source checks here and
    # defer the document check to ``verify_archive``.
    preflight = validate_tree(root, require_integrity=False, require_docs=False)
    if not preflight.valid:
        raise ValidationFailure("preflight failed: " + "; ".join(preflight.errors))
    integrity = write_integrity(root)
    final_tree = validate_tree(root, require_integrity=True, require_docs=False)
    if not final_tree.valid:
        raise ValidationFailure("integrity validation failed: " + "; ".join(final_tree.errors))
    temporary = destination.with_name(destination.name + ".tmp")
    if temporary.exists():
        temporary.unlink()
    try:
        _write_archive(root, temporary)
        verified = verify_archive(
            temporary,
            install_mode=install_mode,
            wheelhouse=wheelhouse,
            rebuild_docs=rebuild_docs,
            font_bindings=font_bindings,
        )
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    result = {
        "archive": str(destination),
        "archive_sha256": sha256_file(destination),
        "archive_bytes": destination.stat().st_size,
        "candidate_only": True,
        "current_distribution_eligible": False,
        "product_acceptance_pass": False,
        "integrity": integrity,
        "verification": verified,
    }
    if candidate_binding_output is not None:
        candidate_binding_output.parent.mkdir(parents=True, exist_ok=True)
        _write_json(candidate_binding_output.resolve(), verified["candidate_binding"])
    return result


def _archive_entry_mode(info: zipfile.ZipInfo) -> int:
    return (info.external_attr >> 16) & 0xFFFF


def _validate_archive_entries(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    if archive.comment:
        raise ValidationFailure("ZIP comment is forbidden")
    infos = archive.infolist()
    if not infos or len(infos) > MAX_ARCHIVE_FILES:
        raise ValidationFailure("archive file count is empty or exceeds the hard ceiling")
    names: list[str] = []
    seen: dict[str, str] = {}
    total = 0
    for info in infos:
        if info.is_dir():
            raise ValidationFailure(f"directory ZIP entries are not canonical: {info.filename}")
        if info.flag_bits & 0x1:
            raise ValidationFailure(f"encrypted ZIP entry rejected: {info.filename}")
        if info.flag_bits & ~0x800:
            raise ValidationFailure(f"non-canonical ZIP flags rejected: {info.filename}")
        if info.extra or info.comment or info.internal_attr != 0:
            raise ValidationFailure(f"non-canonical ZIP metadata rejected: {info.filename}")
        name = info.filename
        if "\\" in name or unicodedata.normalize("NFC", name) != name:
            raise ValidationFailure(f"non-canonical archive path: {name!r}")
        parts = PurePosixPath(name).parts
        if len(parts) < 2 or parts[0] != "promin":
            raise ValidationFailure(f"archive must have exactly one lowercase promin root: {name}")
        rel = "/".join(parts[1:])
        validate_relative_path(rel)
        key = normalized_path_key(name)
        if key in seen:
            raise ValidationFailure(f"archive normalized path collision: {seen[key]} vs {name}")
        seen[key] = name
        mode = _archive_entry_mode(info)
        expected_external = (stat.S_IFREG | 0o644) << 16
        if (
            info.create_system != 3
            or info.external_attr != expected_external
            or not stat.S_ISREG(mode)
            or stat.S_IMODE(mode) != 0o644
        ):
            raise ValidationFailure(f"archive special file or non-canonical mode rejected: {name}")
        if info.date_time != FIXED_ZIP_TIME or info.compress_type != ZIP_METHOD:
            raise ValidationFailure(f"archive metadata is not deterministic: {name}")
        total += info.file_size
        if total > MAX_ARCHIVE_BYTES:
            raise ValidationFailure("archive uncompressed size exceeds hard ceiling")
        if info.file_size and info.compress_size == 0:
            raise ValidationFailure(f"invalid compressed size: {name}")
        if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
            raise ValidationFailure(f"archive expansion ratio exceeds hard ceiling: {name}")
        names.append(name)
    expected_order = sorted(names, key=lambda value: value.encode("utf-8"))
    if names != expected_order:
        raise ValidationFailure("archive entries are not in deterministic byte order")
    expected_names = {f"promin/{rel}" for rel in CANONICAL_PACKAGE_FILES}
    actual_names = set(names)
    missing_names = sorted(
        expected_names - actual_names,
        key=lambda value: value.encode("utf-8"),
    )
    unexpected_names = sorted(
        actual_names - expected_names,
        key=lambda value: value.encode("utf-8"),
    )
    if missing_names or unexpected_names:
        raise ValidationFailure(
            "canonical archive member inventory mismatch: "
            f"missing={missing_names} unexpected={unexpected_names}"
        )
    return infos


def _extract_clean(archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo], destination: Path) -> Path:
    destination.mkdir(parents=True, exist_ok=False)
    for info in infos:
        relative = PurePosixPath(info.filename)
        output = destination.joinpath(*relative.parts)
        output.parent.mkdir(parents=True, exist_ok=True)
        data = archive.read(info)
        if len(data) != info.file_size:
            raise ValidationFailure(f"archive size mismatch while extracting: {info.filename}")
        output.write_bytes(data)
    return destination / "promin"


def verify_archive(
    archive_path: Path,
    *,
    install_mode: str | None = "current-environment",
    wheelhouse: Path | None = None,
    rebuild_docs: bool = False,
    font_bindings: dict[str, tuple[Path, str]] | None = None,
    candidate_binding: Path | None = None,
    evidence_manifest: Path | None = None,
    evidence_root: Path | None = None,
    release_decision: Path | None = None,
    trust_configuration: Path | None = None,
    expected_trust_root_sha256: str | None = None,
) -> dict[str, Any]:
    if archive_path.is_symlink():
        raise ValidationFailure(f"archive symlink rejected: {archive_path}")
    archive_path = archive_path.resolve()
    if archive_path.is_symlink() or not archive_path.is_file():
        raise ValidationFailure(f"archive must be a regular file: {archive_path}")
    initial_digest, initial_stat = _stable_archive_digest(archive_path)
    with tempfile.TemporaryDirectory(prefix="promin-verify-") as temporary_name:
        temporary = Path(temporary_name)
        with zipfile.ZipFile(archive_path, "r") as archive:
            bad = archive.testzip()
            if bad is not None:
                raise ValidationFailure(f"ZIP CRC failure: {bad}")
            infos = _validate_archive_entries(archive)
            extracted_root = _extract_clean(archive, infos, temporary / "clean")
        report = validate_tree(
            extracted_root,
            require_integrity=True,
            require_docs=True,
            install_mode=install_mode,
            wheelhouse=wheelhouse,
            rebuild_docs=rebuild_docs,
            font_bindings=font_bindings,
        )
        if not report.valid:
            raise ValidationFailure("clean extraction validation failed: " + "; ".join(report.errors))
        rebuilt = temporary / "rebuilt.zip"
        _write_archive(extracted_root, rebuilt)
        original_digest, final_stat = _stable_archive_digest(archive_path)
        if (
            initial_digest != original_digest
            or (initial_stat.st_dev, initial_stat.st_ino, initial_stat.st_size, initial_stat.st_mtime_ns)
            != (final_stat.st_dev, final_stat.st_ino, final_stat.st_size, final_stat.st_mtime_ns)
        ):
            raise ValidationFailure("archive changed during exact verification")
        rebuilt_digest = sha256_file(rebuilt)
        if original_digest != rebuilt_digest or archive_path.stat().st_size != rebuilt.stat().st_size:
            raise ValidationFailure("archive is structurally valid but not byte-deterministic")
        test_rows = [
            {"path": rel, "sha256": sha256_file(path), "size": path.stat().st_size}
            for rel, path in iter_regular_files(extracted_root)
            if rel.startswith("tests/test_") and rel.endswith(".py")
        ]
        member_rows = [
            {
                "path": info.filename,
                "sha256": sha256_file(extracted_root / PurePosixPath(info.filename).relative_to("promin")),
                "size": info.file_size,
            }
            for info in infos
        ]
        identity = report.checks["identity_binding"]
        distribution = distribution_identity(extracted_root)
        artifact_binding = {
            "standard_name": "promin",
            "version": distribution["version"],
            "archive_sha256": original_digest,
            "archive_member_manifest_digest": _canonical_digest(member_rows),
            "package_manifest_digest": sha256_file(extracted_root / "MANIFEST.json"),
            "checksums_digest": sha256_file(extracted_root / "SHA256SUMS.txt"),
            "core_bundle_digest": report.checks["core"]["bundle_digest"],
            "selected_preset_sha256": report.checks["preset"]["sha256"],
            "preset_digest": report.checks["preset"]["sha256"],
            "package_tool_digest": identity["tool_digests"]["tools/promin_package.py"],
            "validator_digest": identity["tool_digests"]["tools/promin_validate.py"],
            "test_manifest_digest": _canonical_digest(test_rows),
            "portable_implementation_closure_digest": identity["implementation_closure"]["digest"],
            "observed_environment_closure_digest": identity["implementation_closure"][
                "observed_environment_digest"
            ],
            "tool_digests": identity["tool_digests"],
            "tool_versions": identity["tool_versions"],
            "evidence_tool_digests": {
                relative: sha256_file(extracted_root / relative)
                for relative in (
                    "tools/generate_human.py",
                    "tools/promin_no_degradation.py",
                    "tools/promin_package.py",
                    "tools/promin_saturation.py",
                    "tools/promin_saturation_audit.py",
                    "tools/promin_validate.py",
                )
            },
        }
        exact_candidate = _candidate_binding(artifact_binding, archive_path.stat().st_size)
        supplied_candidate = exact_candidate
        if candidate_binding is not None:
            supplied_candidate = validate_standard_release_candidate_binding(
                load_external_json_stable(candidate_binding).value,
                expected=exact_candidate,
            )
        trust_record: dict[str, Any] | None = None
        trust_sha256: str | None = None
        if trust_configuration is not None:
            trust_read = load_external_json_stable(trust_configuration)
            trust_record = trust_read.value
            trust_sha256 = trust_read.sha256
        supplied_manifest: dict[str, Any] | None = None
        evidence_result: dict[str, Any] | None = None
        if evidence_manifest is not None or evidence_root is not None:
            if (
                candidate_binding is None
                or evidence_manifest is None
                or evidence_root is None
                or trust_record is None
            ):
                raise ValidationFailure(
                    "evidence verification requires candidate binding, evidence manifest, evidence root, and producer trust"
                )
            supplied_manifest = load_external_json_stable(evidence_manifest).value
            evidence_result = validate_standard_release_evidence_manifest(
                supplied_manifest,
                candidate_binding=supplied_candidate,
                evidence_root=evidence_root,
                trust_configuration=trust_record,
                candidate_document_members=report.checks["documents"]["documents"],
            )
        decision_result: dict[str, Any] | None = None
        decision_record: dict[str, Any] | None = None
        if release_decision is not None:
            if (
                candidate_binding is None
                or supplied_manifest is None
                or release_decision is None
                or trust_record is None
            ):
                raise ValidationFailure(
                    "decision verification requires the exact candidate, resolved evidence, decision, and trust configuration"
                )
            decision_record = load_external_json_stable(release_decision).value
            decision_result = validate_standard_release_decision(
                decision_record,
                candidate_binding=supplied_candidate,
                evidence_manifest=supplied_manifest,
                evidence_root=evidence_root,
                trust_configuration=trust_record,
                candidate_document_members=report.checks["documents"]["documents"],
            )
        distribution_status = standard_distribution_status(
            decision_record,
            candidate_binding=exact_candidate,
            evidence_manifest=supplied_manifest,
            evidence_root=evidence_root,
            trust_configuration=trust_record,
            candidate_document_members=report.checks["documents"]["documents"],
            trust_configuration_sha256=trust_sha256,
            expected_trust_root_sha256=expected_trust_root_sha256,
        )
        return {
            "record_type": "ExactPackageVerification",
            "status": "pass",
            "valid": True,
            "candidate_binding_digest": exact_candidate["candidate_binding_digest"],
            "archive_sha256": original_digest,
            "archive_bytes": archive_path.stat().st_size,
            "file_entries": len(infos),
            "clean_extraction": True,
            "byte_deterministic": True,
            "second_build_sha256": rebuilt_digest,
            "artifact_binding": artifact_binding,
            "candidate_binding": exact_candidate,
            "candidate_document_members": report.checks["documents"]["documents"],
            "evidence_manifest": evidence_result,
            "standard_release_decision": decision_result,
            "standard_distribution_status": distribution_status,
            "product_acceptance_pass": False,
            "product_public_approval": "not_approved",
            "tree": report.to_dict(),
        }


def verify_platform(
    archive_path: Path,
    *,
    candidate_binding: Path,
    install_mode: str,
    wheelhouse: Path | None = None,
) -> dict[str, Any]:
    """Verify one exact candidate and its installed command on the current platform."""

    started_at = _utc_now()
    if install_mode != "online-clean" or wheelhouse is not None:
        raise ValidationFailure(
            "platform verification requires the online-clean compatibility lane"
        )
    exact = verify_archive(
        archive_path,
        install_mode=install_mode,
        wheelhouse=wheelhouse,
        candidate_binding=candidate_binding,
    )
    installability = exact.get("tree", {}).get("checks", {}).get("installability")
    if (
        not isinstance(installability, dict)
        or installability.get("performed") is not True
        or installability.get("verified") is not True
        or installability.get("console_script", {}).get("present") is not True
        or installability.get("console_script", {}).get("installed_wrapper_checked") is not True
        or not isinstance(installability.get("installed_environment_observation"), dict)
        or not isinstance(installability.get("pip_report"), dict)
    ):
        raise ValidationFailure("platform verification lacks clean installed command evidence")
    artifact = exact["artifact_binding"]
    observed = installability["installed_environment_observation"]
    observed_python = observed.get("python", {})
    observed_platform = observed.get("platform", {})
    platform_identity = {
        "platform": observed_platform.get("system"),
        "machine": observed_platform.get("machine"),
        "platform_release": observed_platform.get("release"),
        "sys_platform": observed_platform.get("sys_platform"),
        "platform_tags": observed_platform.get("tags"),
        "python_version": observed_python.get("version"),
        "python_implementation": observed_python.get("implementation"),
        "python_executable": observed_python.get("executable"),
        "python_executable_sha256": observed_python.get("executable_sha256"),
        "python_abi_tag": observed_python.get("abi_tag"),
    }
    dependencies = {
        "declared_runtime": installability.get("declared_runtime_dependencies"),
        "declared_build": installability.get("declared_build_dependencies"),
        "resolved_runtime": installability.get("resolved_runtime_dependencies"),
        "closure_check": installability.get("dependency_closure_check"),
    }
    dependency_closure = {
        **dependencies,
        "transitive_distributions": observed.get("transitive_distributions"),
        "transitive_distribution_digest": observed.get("transitive_distribution_digest"),
        "dependency_artifact_digest": installability["pip_report"].get("artifact_digest"),
    }
    dependency_closure["digest"] = _canonical_digest(dependency_closure)
    installation = {
        "environment": installability.get("environment"),
        "installation_performed": installability.get("installation_performed"),
        "nested_venv_created": installability.get("nested_venv_created"),
        "runtime_dependency_source": installability.get("runtime_dependency_source"),
        "build_dependency_source": installability.get("build_dependency_source"),
        "network_disabled": installability.get("network_disabled"),
        "declared_python_requirement": installability.get("declared_python_requirement"),
        "installed_distribution": {
            "name": "promin",
            "version": installability.get("python_distribution_version"),
            "runtime_version": installability.get("version"),
        },
        "console_script": installability.get("console_script"),
        "command_invocations": installability.get("invocations"),
        "dependency_closure": dependency_closure,
        "installed_environment_observation": observed,
        "pip_report": installability["pip_report"],
        "sbom": observed.get("sbom"),
        "license_closure": observed.get("license_closure"),
        "build_backend": observed.get("build_backend"),
    }
    completed_at = _utc_now()
    record = {
        "record_type": "PlatformVerificationResult",
        "status": "pass",
        "candidate_binding_digest": exact["candidate_binding_digest"],
        "platform": platform_identity["platform"],
        "platform_identity": platform_identity,
        "exact_candidate_verified": True,
        "archive_sha256": exact["archive_sha256"],
        "archive_bytes": exact["archive_bytes"],
        "portable_implementation_closure_digest": artifact[
            "portable_implementation_closure_digest"
        ],
        "observed_environment_closure_digest": observed.get("observation_digest"),
        "install_mode": install_mode,
        "installed_command_verified": True,
        "installation": installation,
        "product_acceptance_pass": False,
        "product_public_approval": "not_approved",
        "producer": release_evidence_producer(
            PACKAGE_ROOT,
            "tools/promin_package.py",
            version=exact["candidate_binding"]["version"],
        ),
        "invocation": release_evidence_invocation(
            invocation_id=f"verify-platform:{uuid.uuid4().hex}",
            operation="verify-platform",
            arguments={
                "archive_sha256": exact["archive_sha256"],
                "candidate_binding_digest": exact["candidate_binding_digest"],
                "install_mode": install_mode,
            },
            started_at=started_at,
            completed_at=completed_at,
            exit_code=0,
            platform_binding=platform_identity,
        ),
    }
    return seal_release_evidence(record)


def _print(value: Any) -> None:
    sys.stdout.write(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="refresh integrity surfaces, build ZIP, and verify the exact ZIP")
    build.add_argument("root", type=Path)
    build.add_argument("archive", type=Path)
    build.add_argument("--candidate-binding-output", type=Path)
    add_verification_arguments(build)
    verify = commands.add_parser("verify", help="verify the exact ZIP after clean extraction")
    verify.add_argument("archive", type=Path)
    verify.add_argument("--candidate-binding", type=Path)
    verify.add_argument("--output", type=Path)
    add_verification_arguments(verify)
    platform_verify = commands.add_parser(
        "verify-platform",
        help="verify exact candidate installation and command behavior on the current platform",
    )
    platform_verify.add_argument("archive", type=Path)
    platform_verify.add_argument("candidate_binding", type=Path)
    platform_verify.add_argument("output", type=Path)
    add_verification_arguments(platform_verify)
    platform_verify.set_defaults(install_mode="online-clean")
    closure = commands.add_parser(
        "verify-closure",
        help="resolve exact candidate evidence and verify one configured approve/reject decision",
    )
    closure.add_argument("archive", type=Path)
    closure.add_argument("candidate_binding", type=Path)
    closure.add_argument("evidence_manifest", type=Path)
    closure.add_argument("evidence_root", type=Path)
    closure.add_argument("decision", type=Path)
    closure.add_argument("trust_configuration", type=Path)
    closure.add_argument(
        "--expected-trust-root-sha256",
        required=True,
        help="operator-pinned SHA-256 of the exact trust configuration bytes",
    )
    closure.add_argument("--output", type=Path)
    add_verification_arguments(closure)
    evidence = commands.add_parser(
        "build-evidence-manifest",
        help="resolve a typed evidence plan and write its exact manifest",
    )
    evidence.add_argument("archive", type=Path)
    evidence.add_argument("candidate_binding", type=Path)
    evidence.add_argument("evidence_root", type=Path)
    evidence.add_argument("plan", type=Path)
    evidence.add_argument("trust_configuration", type=Path)
    evidence.add_argument("output", type=Path)
    evidence.add_argument(
        "--expected-trust-root-sha256",
        required=True,
        help="operator-pinned SHA-256 of the exact trust configuration bytes",
    )
    sign = commands.add_parser(
        "sign-decision",
        help="sign an external approve/reject decision with a configured Ed25519 key",
    )
    sign.add_argument("archive", type=Path)
    sign.add_argument("candidate_binding", type=Path)
    sign.add_argument("evidence_manifest", type=Path)
    sign.add_argument("evidence_root", type=Path)
    sign.add_argument("trust_configuration", type=Path)
    sign.add_argument("private_key", type=Path)
    sign.add_argument("output", type=Path)
    sign.add_argument("--decision-id", required=True)
    sign.add_argument("--outcome", required=True, choices=("approve", "reject"))
    sign.add_argument("--decider-id", required=True)
    sign.add_argument("--key-id", required=True)
    sign.add_argument("--decided-at", required=True)
    sign.add_argument("--nonce")
    documents = commands.add_parser(
        "build-document-evidence",
        help="rebuild all PDFs and bind an external all-pages visual review to a candidate",
    )
    documents.add_argument("root", type=Path)
    documents.add_argument("archive", type=Path)
    documents.add_argument("candidate_binding", type=Path)
    documents.add_argument("visual_review", type=Path)
    documents.add_argument("render_root", type=Path)
    documents.add_argument("output", type=Path)
    for role in ("regular", "bold", "italic", "mono"):
        documents.add_argument(f"--font-{role.replace('_', '-')}", type=Path)
        documents.add_argument(f"--font-{role.replace('_', '-')}-sha256")
    refresh = commands.add_parser("refresh", help="refresh VERSION and package integrity surfaces")
    refresh.add_argument("root", type=Path)
    add_verification_arguments(refresh)
    tree = commands.add_parser("verify-tree", help="verify an unpacked canonical folder")
    tree.add_argument("root", type=Path)
    add_verification_arguments(tree)
    args = parser.parse_args(argv)
    try:
        install_mode = (
            None
            if not hasattr(args, "install_mode") or args.install_mode == "none"
            else args.install_mode
        )
        font_bindings = (
            font_bindings_from_args(args)
            if hasattr(args, "rebuild_docs")
            else None
        )
        if args.command == "build":
            result = build_archive(
                args.root,
                args.archive,
                install_mode=install_mode,
                wheelhouse=args.wheelhouse,
                rebuild_docs=args.rebuild_docs,
                font_bindings=font_bindings,
                candidate_binding_output=args.candidate_binding_output,
            )
        elif args.command == "verify":
            result = verify_archive(
                args.archive,
                install_mode=install_mode,
                wheelhouse=args.wheelhouse,
                rebuild_docs=args.rebuild_docs,
                font_bindings=font_bindings,
                candidate_binding=args.candidate_binding,
            )
            if args.output is not None:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                _write_json(args.output.resolve(), result)
        elif args.command == "verify-platform":
            if install_mode is None:
                raise ValidationFailure("verify-platform cannot skip install verification")
            result = verify_platform(
                args.archive,
                candidate_binding=args.candidate_binding,
                install_mode=install_mode,
                wheelhouse=args.wheelhouse,
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            _write_json(args.output.resolve(), result)
        elif args.command == "verify-closure":
            result = verify_archive(
                args.archive,
                install_mode=install_mode,
                wheelhouse=args.wheelhouse,
                rebuild_docs=args.rebuild_docs,
                font_bindings=font_bindings,
                candidate_binding=args.candidate_binding,
                evidence_manifest=args.evidence_manifest,
                evidence_root=args.evidence_root,
                release_decision=args.decision,
                trust_configuration=args.trust_configuration,
                expected_trust_root_sha256=args.expected_trust_root_sha256,
            )
            if args.output is not None:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                _write_json(args.output.resolve(), result)
        elif args.command == "build-evidence-manifest":
            args.output.parent.mkdir(parents=True, exist_ok=True)
            result = build_evidence_manifest(
                args.archive,
                args.candidate_binding,
                args.evidence_root,
                args.plan,
                args.trust_configuration,
                args.output,
                expected_trust_root_sha256=args.expected_trust_root_sha256,
            )
        elif args.command == "sign-decision":
            args.output.parent.mkdir(parents=True, exist_ok=True)
            result = sign_standard_decision(
                args.archive,
                args.candidate_binding,
                args.evidence_manifest,
                args.evidence_root,
                args.trust_configuration,
                args.private_key,
                args.output,
                decision_id=args.decision_id,
                outcome=args.outcome,
                decider_id=args.decider_id,
                key_id=args.key_id,
                decided_at=args.decided_at,
                nonce=args.nonce,
            )
        elif args.command == "build-document-evidence":
            document_fonts = font_bindings_from_args(args)
            if document_fonts is None:
                raise ValidationFailure(
                    "document evidence requires all four exact font bindings"
                )
            exact_documents = verify_archive(
                args.archive,
                install_mode=None,
                candidate_binding=args.candidate_binding,
            )
            result = build_human_document_verification(
                args.root,
                candidate_binding=exact_documents["candidate_binding"],
                candidate_document_members=exact_documents[
                    "candidate_document_members"
                ],
                visual_review=load_external_json_stable(args.visual_review).value,
                render_root=args.render_root,
                evidence_base=args.output.parent,
                font_bindings=document_fonts,
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            _write_json(args.output.resolve(), result)
        elif args.command == "refresh":
            sync_version(args.root.resolve())
            result = write_integrity(args.root.resolve())
            report = validate_tree(
                args.root,
                require_integrity=True,
                require_docs=True,
                install_mode=install_mode,
                wheelhouse=args.wheelhouse,
                rebuild_docs=args.rebuild_docs,
                font_bindings=font_bindings,
            )
            if not report.valid:
                raise ValidationFailure("refreshed tree failed validation: " + "; ".join(report.errors))
            result["validation"] = report.to_dict()
        else:
            report = validate_tree(
                args.root,
                require_integrity=True,
                require_docs=True,
                install_mode=install_mode,
                wheelhouse=args.wheelhouse,
                rebuild_docs=args.rebuild_docs,
                font_bindings=font_bindings,
            )
            if not report.valid:
                raise ValidationFailure("tree validation failed: " + "; ".join(report.errors))
            result = report.to_dict()
        _print(result)
        return 0
    except (OSError, KeyError, ValueError, zipfile.BadZipFile, EvidenceError, ValidationFailure) as exc:
        _print({"valid": False, "error": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
