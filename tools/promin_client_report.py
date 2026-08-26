"""Strict, tools-only boundary for Promin client-report rendering/publication."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import hashlib
import html
import json
import math
import os
import platform
from pathlib import Path
import re
import statistics
import stat
import sys
import tempfile
from typing import Any, Sequence

# A direct ``python tools/promin_client_report.py`` invocation starts with the
# tools directory on ``sys.path``.  Put the checked-out package root first so
# the sibling ``tools/promin.py`` cannot shadow the actual ``promin`` package.
if __package__ in {None, ""}:
    _REPO_ROOT = Path(__file__).resolve().parents[1]
    _repo_root_text = str(_REPO_ROOT)
    sys.path[:] = [entry for entry in sys.path if entry != _repo_root_text]
    sys.path.insert(0, _repo_root_text)

from promin.canonical import CanonicalError, canonical_bytes, load_json_strict
from promin.client_report import report_from_inspection
from promin import product_inspection
from promin.evidence import validate_saturation_evidence, validate_standard_release_candidate_binding
from promin.version import standard_version
from tools.promin_comparative_bench import BenchmarkConfig, expected_bucket_keys, result_key_closure
from tools.promin_saturation import inspect_saturation_lifecycle


class ClientReportToolError(ValueError):
    """Raised when a client report cannot safely enter the renderer."""


_REQUIRED_KEYS = frozenset({"claims", "inspection", "record_type", "schema"})
_INSPECTION_KEYS = frozenset(
    {
        "claims",
        "evidence_confidence",
        "record_type",
        "schema",
        "static_risk_counts",
        "status",
        "summary",
    }
)
_SUMMARY_KEYS = frozenset(
    {
        "declared_tool_profile_count",
        "directory_count",
        "documentation_status",
        "excluded_host_transient_bytes",
        "excluded_host_transient_file_count",
        "file_count",
        "recovery_status",
        "source_file_count",
    }
)
_INVENTORY_STATUSES = frozenset({"COMPLETE", "PARTIAL"})
_CAPABILITY_STATUSES = frozenset({"DECLARED", "PARTIAL", "UNAVAILABLE"})
_CONFIDENCE_LEVELS = frozenset({"BOUNDED_STATIC", "LIMITED"})
_INSPECTION_LIMITATIONS = (
    "no-provider-execution",
    "no-configure-execution",
    "no-build-execution",
    "no-runtime-execution",
    "no-database-access",
    "lexical-dependency-signals-are-review-only",
    "tree-observation-is-partial",
    "some-source-files-were-unavailable",
)
_STATIC_RISK_CODES = frozenset(
    {
        "oversized-file", "unreadable-file", "binary-file", "non-utf8-text",
        "unreadable-directory", "tree-entry-budget-exceeded", "duplicate-relative-path",
        "casefold-collision", "non-nfc-path", "unreadable-entry", "link-or-reparse-point",
        "non-regular-entry", "tree-byte-budget-exceeded", "sensitive-name",
        "binary-or-archive-suffix",
    }
)
_MAX_INPUT_BYTES = 16 * 1024 * 1024
_MAX_LIFECYCLE_BYTES = 2 * 1024 * 1024
_MAX_CLIENT_NUMERIC = 10**18
_LEAK_KEYS = frozenset({"environment", "hostname", "host_name", "package_root"})
_ISO_TIMESTAMP_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})\b")
_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
_EVIDENCE_CLAIMS = (
    "acceptance_pass",
    "pass_credit",
    "product_acceptance_pass",
    "runtime_validated",
    "performance_acceptance",
    "visual_acceptance",
    "release_eligible",
    "comparative_superiority",
    "proxy_acceptance",
)
_TRUTHY_CLAIM_KEYS = frozenset(
    {
        "claim",
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
        "public_release_approved",
        "release_eligible",
        "runtime_validated",
        "performance_acceptance",
        "visual_acceptance",
        "comparative_superiority",
    }
)
_EVIDENCE_PACKET_KEYS = frozenset(
    {
        "schema",
        "record_type",
        "platform",
        "claims",
        "inspection",
        "saturation",
        "comparative",
        "input_bindings",
    }
)
_EVIDENCE_PACKET_CLAIMS = frozenset(_EVIDENCE_CLAIMS)
_CLIENT_REPORT_CLAIMS = frozenset(
    {
        "acceptance_pass",
        "pass_credit",
        "product_acceptance_pass",
        "release_eligible",
        "runtime_validated",
    }
)
_EVIDENCE_PACKET_INSPECTION_KEYS = frozenset(
    {"source_sha256", "source_bytes", "report"}
)
_EVIDENCE_PACKET_SATURATION_KEYS = frozenset(
    {
        "result_sha256",
        "result_bytes",
        "lifecycle_sha256",
        "lifecycle_bytes",
        "physical_files",
        "physical_relations",
        "runtime_queries",
        "semantic_control_records",
        "semantic_control_envelopes",
        "query_p50_ms",
        "query_p95_ms",
        "query_p99_ms",
        "commit_p95_ms",
        "commit_p99_ms",
        "peak_rss_bytes",
        "all_predicates",
    }
)
_EVIDENCE_PACKET_COMPARATIVE_KEYS = frozenset(
    {"source_sha256", "source_bytes", "scenarios"}
)
_EVIDENCE_PACKET_SCENARIO_KEYS = frozenset(
    {
        "scenario",
        "bucket_count",
        "median_latency_p50_ms",
        "median_storage_p50_bytes",
    }
)
_EVIDENCE_PACKET_INPUT_BINDING_KEYS = frozenset(
    {
        "inspection",
        "candidate_binding",
        "saturation_result",
        "saturation_lifecycle",
        "comparative",
        "candidate_binding_digest",
        "artifact_binding_digest",
        "platform_binding_digest",
    }
)
_EVIDENCE_PACKET_SOURCE_ROLES = (
    "inspection",
    "candidate_binding",
    "saturation_result",
    "saturation_lifecycle",
    "comparative",
)
_EVIDENCE_PACKET_SCALE = {
    "physical_files": 100000,
    "physical_relations": 198999,
    "runtime_queries": 600,
}
_PUBLICATION_MAX_JSON_BYTES = 64 * 1024 * 1024
_PUBLICATION_MAX_PDF_BYTES = 64 * 1024 * 1024
_PUBLICATION_MAX_RECEIPT_BYTES = 2 * 1024 * 1024
_SEMANTIC_CONTROL_RECORDS = 165
_SEMANTIC_CONTROL_ENVELOPES = 137
_FORBIDDEN_NARRATIVE_TERMS = (
    "faster",
    "better",
    "production-ready",
    "accepted",
    "release-ready",
)
_CLI_ERROR_MAX_CHARS = 480


def _nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validate_client_report(value: Any) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ClientReportToolError("client report must be a JSON object")
    claims = value.get("claims")
    if isinstance(claims, Mapping) and any(item is not False for item in claims.values()):
        raise ClientReportToolError("client report carries promoted claims")
    if set(value) != _REQUIRED_KEYS:
        raise ClientReportToolError("client report fields are not exact")
    if value.get("schema") != "promin.client-report.v1":
        raise ClientReportToolError("client report schema is invalid")
    if value.get("record_type") != "ProminClientReport":
        raise ClientReportToolError("client report record_type is invalid")
    if not isinstance(claims, Mapping):
        raise ClientReportToolError("client report claims must be an object")
    if any(item is not False for item in claims.values()):
        raise ClientReportToolError("client report carries promoted claims")
    inspection = value.get("inspection")
    if not isinstance(inspection, Mapping):
        raise ClientReportToolError("client report inspection must be an object")
    if set(inspection) != _INSPECTION_KEYS:
        raise ClientReportToolError("client report inspection fields are not exact")
    if inspection.get("schema") != "promin.product-inspection.v1":
        raise ClientReportToolError("client report inspection schema is invalid")
    if inspection.get("record_type") != "ProductInspectionClientSummary":
        raise ClientReportToolError("client report inspection record_type is invalid")
    summary = inspection.get("summary")
    if not isinstance(summary, Mapping) or set(summary) != _SUMMARY_KEYS:
        raise ClientReportToolError("client report inspection summary must be an object")
    for key in (
        "declared_tool_profile_count",
        "directory_count",
        "excluded_host_transient_bytes",
        "excluded_host_transient_file_count",
        "file_count",
        "source_file_count",
    ):
        if not _nonnegative_int(summary.get(key)):
            raise ClientReportToolError(f"client report summary field is invalid: {key}")
    if summary.get("documentation_status") not in _CAPABILITY_STATUSES:
        raise ClientReportToolError("client report summary documentation_status is invalid")
    if summary.get("recovery_status") not in _CAPABILITY_STATUSES:
        raise ClientReportToolError("client report summary recovery_status is invalid")
    if inspection.get("status") not in _INVENTORY_STATUSES:
        raise ClientReportToolError("client report inspection status is invalid")
    if not isinstance(inspection.get("static_risk_counts"), Mapping):
        raise ClientReportToolError("client report inspection risk counts must be an object")
    if any(
        not isinstance(key, str) or not _nonnegative_int(value)
        for key, value in inspection["static_risk_counts"].items()
    ):
        raise ClientReportToolError("client report inspection risk counts are invalid")
    confidence = inspection.get("evidence_confidence")
    if (
        not isinstance(confidence, Mapping)
        or set(confidence) != {"level", "limitations"}
        or confidence.get("level") not in _CONFIDENCE_LEVELS
        or not isinstance(confidence.get("limitations"), list)
        or any(not isinstance(item, str) for item in confidence["limitations"])
    ):
        raise ClientReportToolError("client report inspection confidence is invalid")
    if inspection.get("claims") != dict(claims):
        raise ClientReportToolError("client report inspection claims do not match")
    return value


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _is_prefixed_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and _is_digest(value[7:])
    )


def _validate_packet_source_binding(value: Any, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"sha256", "bytes"}:
        raise ClientReportToolError(f"evidence packet {label} binding fields are not exact")
    if not _is_digest(value.get("sha256")) or not _nonnegative_int(value.get("bytes")):
        raise ClientReportToolError(f"evidence packet {label} binding digest/bytes are invalid")
    return {"sha256": value["sha256"], "bytes": value["bytes"]}


def _validate_observation(value: Any, label: str) -> int | float:
    if type(value) not in (int, float):
        raise ClientReportToolError(f"evidence packet {label} observation is not numeric")
    if value < 0 or value > _MAX_CLIENT_NUMERIC:
        raise ClientReportToolError(f"evidence packet {label} observation is out of bounds")
    if isinstance(value, float) and not math.isfinite(value):
        raise ClientReportToolError(f"evidence packet {label} observation is not finite")
    return value


def _validate_evidence_packet(packet: Mapping[str, object]) -> dict[str, object]:
    """Validate the complete packet boundary before any client publication."""

    if not isinstance(packet, Mapping):
        raise ClientReportToolError("evidence packet must be an object")
    try:
        # Normalize through the same bounded JSON representation that is written
        # to disk.  This rejects custom Mapping values, non-JSON objects, NaN,
        # and non-string keys before any output temporary is created.
        normalized = json.loads(canonical_bytes(dict(packet)))
    except (CanonicalError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ClientReportToolError(f"evidence packet is not canonical JSON: {exc}") from exc
    if not isinstance(normalized, dict) or set(normalized) != _EVIDENCE_PACKET_KEYS:
        raise ClientReportToolError("evidence packet fields are not exact")
    if normalized.get("schema") != "promin.client-report-evidence.v1":
        raise ClientReportToolError("evidence packet schema is invalid")
    if normalized.get("record_type") != "ProminClientReportEvidence":
        raise ClientReportToolError("evidence packet record_type is invalid")
    if normalized.get("platform") != "windows":
        raise ClientReportToolError("evidence packet platform must be windows")

    claims = normalized.get("claims")
    if (
        not isinstance(claims, Mapping)
        or set(claims) != _EVIDENCE_PACKET_CLAIMS
        or any(type(value) is not bool or value is not False for value in claims.values())
    ):
        raise ClientReportToolError("evidence packet claims are not the exact nine false values")

    inspection = normalized.get("inspection")
    if not isinstance(inspection, Mapping) or set(inspection) != _EVIDENCE_PACKET_INSPECTION_KEYS:
        raise ClientReportToolError("evidence packet inspection fields are not exact")
    inspection_binding = _validate_packet_source_binding(
        {"sha256": inspection.get("source_sha256"), "bytes": inspection.get("source_bytes")},
        "inspection",
    )
    report = inspection.get("report")
    if not isinstance(report, dict):
        raise ClientReportToolError("evidence packet inspection report must be an object")
    validated_report = _validate_client_report(report)
    if set(validated_report["claims"]) != _CLIENT_REPORT_CLAIMS:
        raise ClientReportToolError("evidence packet client report claims are not exact")

    saturation = normalized.get("saturation")
    if not isinstance(saturation, Mapping) or set(saturation) != _EVIDENCE_PACKET_SATURATION_KEYS:
        raise ClientReportToolError("evidence packet saturation fields are not exact")
    result_binding = _validate_packet_source_binding(
        {"sha256": saturation.get("result_sha256"), "bytes": saturation.get("result_bytes")},
        "saturation result",
    )
    lifecycle_binding = _validate_packet_source_binding(
        {"sha256": saturation.get("lifecycle_sha256"), "bytes": saturation.get("lifecycle_bytes")},
        "saturation lifecycle",
    )
    for key, expected in _EVIDENCE_PACKET_SCALE.items():
        if saturation.get(key) != expected:
            raise ClientReportToolError(f"evidence packet saturation {key} is not the exact Windows scale")
    if (
        saturation.get("semantic_control_records") != _SEMANTIC_CONTROL_RECORDS
        or saturation.get("semantic_control_envelopes") != _SEMANTIC_CONTROL_ENVELOPES
    ):
        raise ClientReportToolError(
            "evidence packet semantic control counts are not the exact Windows values"
        )
    for key in ("semantic_control_records", "semantic_control_envelopes"):
        if not _nonnegative_int(saturation.get(key)) or saturation[key] > _MAX_CLIENT_NUMERIC:
            raise ClientReportToolError(f"evidence packet saturation {key} is invalid")
    for key in (
        "query_p50_ms",
        "query_p95_ms",
        "query_p99_ms",
        "commit_p95_ms",
        "commit_p99_ms",
        "peak_rss_bytes",
    ):
        _validate_observation(saturation.get(key), f"saturation {key}")
    predicates = saturation.get("all_predicates")
    if (
        not isinstance(predicates, Mapping)
        or any(not isinstance(key, str) or type(value) is not bool for key, value in predicates.items())
    ):
        raise ClientReportToolError("evidence packet saturation predicates must be booleans")

    comparative = normalized.get("comparative")
    if not isinstance(comparative, Mapping) or set(comparative) != _EVIDENCE_PACKET_COMPARATIVE_KEYS:
        raise ClientReportToolError("evidence packet comparative fields are not exact")
    comparative_binding = _validate_packet_source_binding(
        {"sha256": comparative.get("source_sha256"), "bytes": comparative.get("source_bytes")},
        "comparative",
    )
    scenarios = comparative.get("scenarios")
    expected_scenarios = ("promin", "markdown", "empty")
    if not isinstance(scenarios, list) or len(scenarios) != len(expected_scenarios):
        raise ClientReportToolError("evidence packet comparative scenarios must contain exactly three rows")
    for row, expected_name in zip(scenarios, expected_scenarios):
        if not isinstance(row, Mapping) or set(row) != _EVIDENCE_PACKET_SCENARIO_KEYS:
            raise ClientReportToolError("evidence packet comparative row fields are not exact")
        if row.get("scenario") != expected_name or row.get("bucket_count") != 24:
            raise ClientReportToolError("evidence packet comparative scenario order/count is invalid")
        _validate_observation(row.get("median_latency_p50_ms"), f"{expected_name} latency")
        _validate_observation(row.get("median_storage_p50_bytes"), f"{expected_name} storage")

    input_bindings = normalized.get("input_bindings")
    if not isinstance(input_bindings, Mapping) or set(input_bindings) != _EVIDENCE_PACKET_INPUT_BINDING_KEYS:
        raise ClientReportToolError("evidence packet input binding fields are not exact")
    source_bindings = {
        role: _validate_packet_source_binding(input_bindings.get(role), role)
        for role in _EVIDENCE_PACKET_SOURCE_ROLES
    }
    if input_bindings.get("candidate_binding_digest") is None or not _is_digest(input_bindings.get("candidate_binding_digest")):
        raise ClientReportToolError("evidence packet candidate binding digest is invalid")
    if not _is_prefixed_digest(input_bindings.get("artifact_binding_digest")):
        raise ClientReportToolError("evidence packet artifact binding digest is invalid")
    if not _is_prefixed_digest(input_bindings.get("platform_binding_digest")):
        raise ClientReportToolError("evidence packet platform binding digest is invalid")
    if source_bindings["inspection"] != inspection_binding:
        raise ClientReportToolError("evidence packet inspection source binding mismatch")
    if source_bindings["saturation_result"] != result_binding:
        raise ClientReportToolError("evidence packet saturation result binding mismatch")
    if source_bindings["saturation_lifecycle"] != lifecycle_binding:
        raise ClientReportToolError("evidence packet saturation lifecycle binding mismatch")
    if source_bindings["comparative"] != comparative_binding:
        raise ClientReportToolError("evidence packet comparative source binding mismatch")

    _reject_truthy_claims(normalized)
    _validate_numbers(normalized)
    _assert_packet_safe(normalized)
    return normalized


def load_client_report(path: Path) -> dict[str, object]:
    """Load one exact canonical, claim-free client report."""

    source = Path(path)
    try:
        value = load_json_strict(source, root=source.parent)
        validated = _validate_client_report(value)
        raw = source.read_bytes()
        if canonical_bytes(value) != raw:
            raise ClientReportToolError("client report is not canonical")
    except ClientReportToolError:
        raise
    except (CanonicalError, OSError, TypeError, ValueError) as exc:
        raise ClientReportToolError(f"invalid canonical client report: {exc}") from exc
    return validated


def sha256_canonical(report: Mapping[str, object]) -> str:
    """Return the digest bound to the exact canonical report value."""

    return hashlib.sha256(canonical_bytes(dict(report))).hexdigest()


def _source_bytes(path: Path, *, maximum: int = _MAX_INPUT_BYTES) -> bytes:
    """Read one physical regular file with a bounded, link-free boundary."""

    try:
        info = path.lstat()
    except OSError as exc:
        raise ClientReportToolError(f"input is unavailable: {path}") from exc
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or int(getattr(info, "st_file_attributes", 0)) & reparse_flag
    ):
        raise ClientReportToolError(f"input must be a regular file: {path}")
    if info.st_size > maximum:
        raise ClientReportToolError(f"input exceeds declared size bound: {path}")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ClientReportToolError(f"input cannot be read: {path}") from exc
    if len(payload) != info.st_size or len(payload) > maximum:
        raise ClientReportToolError(f"input changed during read: {path}")
    return payload


def _load_canonical_source(path: Path, *, maximum: int = _MAX_INPUT_BYTES) -> tuple[dict[str, Any], bytes]:
    payload = _source_bytes(path, maximum=maximum)
    try:
        value = load_json_strict(path, root=path.parent)
        if not isinstance(value, dict) or canonical_bytes(value) != payload:
            raise ClientReportToolError(f"input is not canonical JSON: {path}")
    except ClientReportToolError:
        raise
    except (CanonicalError, OSError, TypeError, ValueError) as exc:
        raise ClientReportToolError(f"invalid canonical JSON input: {path}") from exc
    return value, payload


def _assert_unchanged(path: Path, original: bytes, *, maximum: int = _MAX_INPUT_BYTES) -> None:
    if _source_bytes(path, maximum=maximum) != original:
        raise ClientReportToolError(f"input changed during validation: {path.name}")


def _saturation_root_identity(path: Path) -> tuple[int, int, int, int]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ClientReportToolError("saturation root is unavailable") from exc
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or int(getattr(info, "st_file_attributes", 0)) & reparse_flag
    ):
        raise ClientReportToolError("saturation root must be a real directory")
    return (
        int(getattr(info, "st_dev", 0)),
        int(getattr(info, "st_ino", 0)),
        int(getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000))),
        int(getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))),
    )


def _assert_packet_safe(value: Any, *, key: object = None) -> None:
    if isinstance(value, Mapping):
        for name, item in value.items():
            if isinstance(name, str):
                if name.casefold() in _LEAK_KEYS:
                    raise ClientReportToolError("packet contains source environment or hostname data")
                _assert_packet_safe(name)
            _assert_packet_safe(item, key=name)
    elif isinstance(value, list):
        for item in value:
            _assert_packet_safe(item, key=key)
    elif isinstance(value, str):
        if re.search(r"(?:[A-Za-z]:[\\/]|\\\\|^/)", value) or _ISO_TIMESTAMP_RE.search(value) or _UUID_RE.search(value):
            raise ClientReportToolError("packet contains an unstable path, timestamp, or UUID")


def _reject_truthy_claims(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if key in _TRUTHY_CLAIM_KEYS and item is not False:
                raise ClientReportToolError(f"comparative evidence carries promoted claim: {key}")
            _reject_truthy_claims(item)
    elif isinstance(value, list):
        for item in value:
            _reject_truthy_claims(item)


def _numeric_field_name(key: object) -> bool:
    if not isinstance(key, str):
        return False
    lowered = key.casefold()
    return lowered in {"size", "p50", "p95", "p99", "count", "index"} or lowered.endswith(("_ms", "_bytes", "_count", "_size", "_records", "_envelopes", "_files", "_relations", "_queries", "_duration", "_elapsed"))


def _validate_numbers(value: Any, *, key: object = None) -> None:
    if isinstance(value, bool):
        if _numeric_field_name(key):
            raise ClientReportToolError("comparative evidence contains a boolean numeric field")
        return
    if isinstance(value, int):
        if value < 0 or value > _MAX_CLIENT_NUMERIC:
            raise ClientReportToolError("comparative evidence contains an invalid numeric observation")
    elif isinstance(value, float) and (value < 0 or value > _MAX_CLIENT_NUMERIC or not math.isfinite(value)):
        raise ClientReportToolError("comparative evidence contains an invalid numeric observation")
    if isinstance(value, Mapping):
        for name, item in value.items():
            _validate_numbers(item, key=name)
    elif isinstance(value, list):
        for item in value:
            _validate_numbers(item, key=key)


def _validate_inspection(value: Mapping[str, Any]) -> dict[str, object]:
    if set(value) != {"schema", "record_type", "status", "machine", "client", "claims"}:
        raise ClientReportToolError("inspection record fields are not exact")
    if value.get("schema") != "promin.product-inspection.v1" or value.get("record_type") != "ProductInspection":
        raise ClientReportToolError("inspection record identity is invalid")
    claims = value.get("claims")
    if not isinstance(claims, Mapping) or any(item is not False for item in claims.values()):
        raise ClientReportToolError("inspection carries promoted claims")
    machine = value.get("machine")
    client = value.get("client")
    if not isinstance(machine, Mapping) or not isinstance(client, Mapping):
        raise ClientReportToolError("inspection machine/client surfaces are missing")
    if set(machine) != {
        "schema", "record_type", "status", "profile", "limits", "inventory",
        "architecture", "documentation", "tool_profiles", "recovery_capability",
        "static_risk", "hotspots", "evidence_confidence", "effects", "claims",
    } or set(client) != _INSPECTION_KEYS:
        raise ClientReportToolError("inspection machine/client surfaces are not complete")
    if (
        machine.get("schema") != "promin.product-inspection.v1"
        or machine.get("record_type") != "ProductInspectionMachineReport"
        or machine.get("status") != value.get("status")
        or not isinstance(machine.get("claims"), Mapping)
        or machine.get("claims") != dict(claims)
        or any(item is not False for item in machine["claims"].values())
        or not isinstance(machine.get("profile"), Mapping)
        or not isinstance(machine.get("limits"), Mapping)
        or not isinstance(machine.get("inventory"), Mapping)
        or not isinstance(machine.get("architecture"), Mapping)
        or not isinstance(machine.get("documentation"), Mapping)
        or not isinstance(machine.get("recovery_capability"), Mapping)
        or not isinstance(machine.get("static_risk"), Mapping)
        or not isinstance(machine.get("hotspots"), Mapping)
        or not isinstance(machine.get("evidence_confidence"), Mapping)
        or not isinstance(machine.get("effects"), Mapping)
    ):
        raise ClientReportToolError("inspection machine claims or identity are invalid")
    static_risk = machine["static_risk"]
    if not isinstance(static_risk.get("by_code"), Mapping) or not set(static_risk["by_code"]).issubset(_STATIC_RISK_CODES):
        raise ClientReportToolError("inspection static risk code is not source-owned")
    try:
        derived_client = product_inspection._build_client_summary(machine, claims)
    except Exception as exc:
        raise ClientReportToolError(f"inspection client projection cannot be derived: {exc}") from exc
    if value.get("client") != derived_client:
        raise ClientReportToolError("inspection client projection is not source-derived")
    supplied_limitations = value["client"]["evidence_confidence"]["limitations"]
    expected_limitations = [item for item in _INSPECTION_LIMITATIONS if item in supplied_limitations]
    if supplied_limitations != expected_limitations:
        raise ClientReportToolError("inspection confidence limitations are not source-owned")
    try:
        derived = report_from_inspection(value)
        return _validate_client_report(derived)
    except Exception as exc:
        if isinstance(exc, ClientReportToolError):
            raise
        raise ClientReportToolError(f"inspection cannot produce client report: {exc}") from exc


def _saturation_summary(result: Mapping[str, Any]) -> dict[str, object]:
    physical = result.get("physical")
    search = result.get("search")
    performance = result.get("performance")
    resources = result.get("resources")
    predicates = result.get("contract_predicates")
    if not all(isinstance(item, Mapping) for item in (physical, search, performance, resources, predicates)):
        raise ClientReportToolError("saturation evidence summary sections are missing")
    observed = performance.get("observed")
    if not isinstance(observed, Mapping):
        raise ClientReportToolError("saturation performance observations are missing")
    required = {
        "physical_files": physical.get("files"),
        "physical_relations": physical.get("physical_relation_evidence_count"),
        "runtime_queries": search.get("actual_runtime_queries"),
        "semantic_control_records": physical.get("semantic_control_records"),
        "semantic_control_envelopes": physical.get("semantic_control_envelopes"),
        "query_p50_ms": observed.get("p50_ms"),
        "query_p95_ms": observed.get("p95_ms"),
        "query_p99_ms": observed.get("p99_ms"),
        "commit_p95_ms": observed.get("commit_p95_ms"),
        "commit_p99_ms": observed.get("commit_p99_ms"),
        "peak_rss_bytes": observed.get("peak_rss_bytes"),
    }
    if any(item is None for item in required.values()):
        raise ClientReportToolError("saturation evidence lacks required client-safe observations")
    if (
        required["semantic_control_records"] != _SEMANTIC_CONTROL_RECORDS
        or required["semantic_control_envelopes"] != _SEMANTIC_CONTROL_ENVELOPES
    ):
        raise ClientReportToolError(
            "saturation evidence semantic control counts are not the exact Windows values"
        )
    all_predicates = dict(predicates)
    perf_predicates = performance.get("predicates")
    if isinstance(perf_predicates, Mapping):
        all_predicates.update({str(key): value for key, value in perf_predicates.items()})
    if any(type(item) is not bool for item in all_predicates.values()):
        raise ClientReportToolError("saturation predicate values must be booleans")
    return {**required, "all_predicates": all_predicates}


def _comparative_summary(report: Mapping[str, Any]) -> list[dict[str, object]]:
    config = report.get("config")
    execution = report.get("execution")
    results = report.get("results")
    if report.get("schema") != "promin.comparative-benchmark.v1" or report.get("record_type") != "ProminComparativeBenchmark":
        raise ClientReportToolError("comparative benchmark identity is invalid")
    for flag in ("claim", "pass_credit", "acceptance_pass", "product_acceptance_pass", "public_release_approved"):
        if report.get(flag) is not False:
            raise ClientReportToolError("comparative benchmark carries a promoted claim")
    if not isinstance(config, Mapping) or not isinstance(execution, Mapping) or not isinstance(results, list):
        raise ClientReportToolError("comparative benchmark sections are missing")
    expected_config = {
        "sizes": [16, 64, 256], "warmup_runs": 1, "measured_runs": 3,
        "sampling_interval_ms": 5, "scenarios": ["promin", "markdown", "empty"],
        "operations": ["init", "update", "query", "docs"],
        "temperatures": ["cold", "warm"],
        "execution_order": "sequential; no benchmark samples run concurrently",
        "fixed_workload": True, "fixed_bucket_count": 72,
    }
    if dict(config) != expected_config:
        raise ClientReportToolError("comparative benchmark config is not the fixed 72-bucket protocol")
    if (
        any(type(item) is not int for item in config["sizes"])
        or any(type(config[key]) is not int for key in ("warmup_runs", "measured_runs", "sampling_interval_ms", "fixed_bucket_count"))
        or type(config["fixed_workload"]) is not bool
        or any(type(item) is not str for key in ("scenarios", "operations", "temperatures") for item in config[key])
    ):
        raise ClientReportToolError("comparative benchmark contains a boolean numeric field")
    if execution.get("performed") is not True or execution.get("status") != "completed" or execution.get("all_samples_succeeded") is not True or execution.get("full_comparison_scope_selected") is not True:
        raise ClientReportToolError("comparative benchmark is not a completed full-scope execution")
    bench_config = BenchmarkConfig()
    for row in results:
        if not isinstance(row, Mapping) or row.get("status") != "measured":
            raise ClientReportToolError("every comparative bucket must be measured")
        if type(row.get("size")) is not int:
            raise ClientReportToolError("comparative bucket size is not an integer")
        for metric_name in ("latency_ms", "cpu_ms", "storage_total_bytes", "storage_control_bytes"):
            metric = row.get(metric_name)
            if metric is None:
                continue
            if not isinstance(metric, Mapping):
                raise ClientReportToolError("comparative metric must be an object")
            for metric_value in metric.values():
                if type(metric_value) not in (int, float) or (isinstance(metric_value, int) and metric_value > _MAX_CLIENT_NUMERIC) or (isinstance(metric_value, float) and (not math.isfinite(metric_value) or metric_value > _MAX_CLIENT_NUMERIC)) or metric_value < 0:
                    raise ClientReportToolError("comparative evidence contains an invalid numeric observation")
        for metric_name in ("latency_ms", "storage_total_bytes"):
            metric = row.get(metric_name)
            if not isinstance(metric, Mapping) or type(metric.get("p50")) not in (int, float) or (isinstance(metric.get("p50"), int) and metric["p50"] > _MAX_CLIENT_NUMERIC) or (isinstance(metric.get("p50"), float) and (not math.isfinite(metric["p50"]) or metric["p50"] > _MAX_CLIENT_NUMERIC)) or metric["p50"] < 0:
                raise ClientReportToolError("comparative bucket p50 observation is invalid")
        _validate_numbers(row)
    recomputed = result_key_closure(expected_bucket_keys(bench_config), results)
    if report.get("result_key_closure") != recomputed or not recomputed["complete"] or recomputed["unique_bucket_count"] != 72 or any(recomputed[key] for key in ("missing_count", "unexpected_count", "duplicate_count", "malformed_count")):
        raise ClientReportToolError("comparative result bucket closure is incomplete or altered")
    _reject_truthy_claims(report)
    _validate_numbers(report)
    rows: list[dict[str, object]] = []
    for scenario in ("promin", "markdown", "empty"):
        selected = [item for item in results if isinstance(item, Mapping) and item.get("scenario") == scenario]
        if len(selected) != 24:
            raise ClientReportToolError("comparative scenario does not contain exactly 24 buckets")
        latency = [item["latency_ms"]["p50"] for item in selected if isinstance(item.get("latency_ms"), Mapping) and isinstance(item["latency_ms"].get("p50"), (int, float)) and not isinstance(item["latency_ms"].get("p50"), bool)]
        storage = [item["storage_total_bytes"]["p50"] for item in selected if isinstance(item.get("storage_total_bytes"), Mapping) and isinstance(item["storage_total_bytes"].get("p50"), (int, float)) and not isinstance(item["storage_total_bytes"].get("p50"), bool)]
        if len(latency) != 24 or len(storage) != 24:
            raise ClientReportToolError("comparative bucket observations are incomplete")
        rows.append({
            "scenario": scenario,
            "bucket_count": 24,
            "median_latency_p50_ms": round(float(statistics.median(latency)), 6),
            "median_storage_p50_bytes": round(float(statistics.median(storage)), 6),
        })
    return rows


def build_evidence_packet(
    inspection_path: Path,
    saturation_root: Path,
    candidate_binding_path: Path,
    comparative_path: Path,
) -> dict[str, object]:
    """Validate independent Windows evidence and return a canonical data packet."""

    # This must remain the first operation: Linux/WSL callers must not inspect input paths.
    if platform.system().casefold() != "windows":
        raise ClientReportToolError("client evidence packet requires Windows")
    inspection_path = Path(inspection_path)
    saturation_root = Path(saturation_root)
    candidate_binding_path = Path(candidate_binding_path)
    comparative_path = Path(comparative_path)
    try:
        inspection, inspection_raw = _load_canonical_source(inspection_path)
        candidate, candidate_raw = _load_canonical_source(candidate_binding_path)
        comparative, comparative_raw = _load_canonical_source(comparative_path)
        if not isinstance(inspection, Mapping):
            raise ClientReportToolError("inspection must be an object")
        client_report = _validate_inspection(inspection)
        try:
            candidate_validated = validate_standard_release_candidate_binding(candidate)
        except Exception as exc:
            raise ClientReportToolError(f"candidate binding is invalid: {exc}") from exc
        if candidate_validated.get("version") != standard_version():
            raise ClientReportToolError(
                "candidate binding version must match current standard version"
            )
        # Inspect the root before touching any lifecycle/result child path.
        root_identity = _saturation_root_identity(saturation_root)
        lifecycle = inspect_saturation_lifecycle(saturation_root)
        if lifecycle.get("status") != "result-published" or lifecycle.get("lifecycle_event_count") != 14 or lifecycle.get("terminal_failure_receipt_present") is not False:
            raise ClientReportToolError("saturation lifecycle is not a complete result publication")
        lifecycle_path = saturation_root / "saturation-run-lifecycle.jsonl"
        result_path = saturation_root / "saturation-result.json"
        lifecycle_raw = _source_bytes(lifecycle_path, maximum=_MAX_LIFECYCLE_BYTES)
        result, result_raw = _load_canonical_source(result_path)
        try:
            saturation_validated = validate_saturation_evidence(result, candidate_binding=candidate_validated, source_path=result_path, evidence_root=saturation_root, require_pass=True)
        except Exception as exc:
            raise ClientReportToolError(f"saturation evidence is invalid: {exc}") from exc
        if not isinstance(saturation_validated, Mapping):
            raise ClientReportToolError("saturation validator did not return an evidence object")
        lifecycle_after = inspect_saturation_lifecycle(saturation_root)
        if lifecycle_after != lifecycle:
            raise ClientReportToolError("saturation lifecycle changed during validation")
        if _saturation_root_identity(saturation_root) != root_identity:
            raise ClientReportToolError("saturation root changed during validation")
        artifact = saturation_validated.get("artifact_binding")
        if not isinstance(artifact, Mapping) or not isinstance(artifact.get("platform"), Mapping) or str(artifact["platform"].get("system", "")).casefold() != "windows":
            raise ClientReportToolError("saturation result is not bound to Windows")
        comparative_summary = _comparative_summary(comparative)
        saturation_summary = _saturation_summary(saturation_validated)
        bindings = {
            "inspection": {"sha256": hashlib.sha256(inspection_raw).hexdigest(), "bytes": len(inspection_raw)},
            "candidate_binding": {"sha256": hashlib.sha256(candidate_raw).hexdigest(), "bytes": len(candidate_raw)},
            "saturation_result": {"sha256": hashlib.sha256(result_raw).hexdigest(), "bytes": len(result_raw)},
            "saturation_lifecycle": {"sha256": hashlib.sha256(lifecycle_raw).hexdigest(), "bytes": len(lifecycle_raw)},
            "comparative": {"sha256": hashlib.sha256(comparative_raw).hexdigest(), "bytes": len(comparative_raw)},
            "candidate_binding_digest": candidate_validated["candidate_binding_digest"],
            "artifact_binding_digest": artifact["binding_digest"],
            "platform_binding_digest": artifact["platform"]["binding_digest"],
        }
        claims = {key: False for key in _EVIDENCE_CLAIMS}
        packet = {
            "schema": "promin.client-report-evidence.v1",
            "record_type": "ProminClientReportEvidence",
            "platform": "windows",
            "claims": claims,
            "inspection": {"source_sha256": bindings["inspection"]["sha256"], "source_bytes": bindings["inspection"]["bytes"], "report": client_report},
            "saturation": {"result_sha256": bindings["saturation_result"]["sha256"], "result_bytes": bindings["saturation_result"]["bytes"], "lifecycle_sha256": bindings["saturation_lifecycle"]["sha256"], "lifecycle_bytes": bindings["saturation_lifecycle"]["bytes"], **saturation_summary},
            "comparative": {"source_sha256": bindings["comparative"]["sha256"], "source_bytes": bindings["comparative"]["bytes"], "scenarios": comparative_summary},
            "input_bindings": bindings,
        }
        _assert_unchanged(inspection_path, inspection_raw)
        _assert_unchanged(candidate_binding_path, candidate_raw)
        _assert_unchanged(comparative_path, comparative_raw)
        _assert_unchanged(result_path, result_raw)
        _assert_unchanged(lifecycle_path, lifecycle_raw, maximum=_MAX_LIFECYCLE_BYTES)
        _assert_packet_safe(packet)
        if _saturation_root_identity(saturation_root) != root_identity:
            raise ClientReportToolError("saturation root changed during validation")
        return packet
    except ClientReportToolError:
        raise
    except (OSError, TypeError, ValueError, KeyError, RuntimeError) as exc:
        raise ClientReportToolError(f"evidence packet validation failed: {exc}") from exc


def _paragraph_for_evidence(text: str, style: Any) -> Any:
    from reportlab.platypus import Paragraph

    return Paragraph(html.escape(text).replace("\n", "<br/>"), style)


def _format_observation(value: object) -> str:
    if isinstance(value, float):
        return format(value, ".6g")
    return str(value)


def _evidence_pdf_sections(packet: Mapping[str, object]) -> tuple[tuple[str, str], ...]:
    inspection = packet["inspection"]
    saturation = packet["saturation"]
    comparative = packet["comparative"]
    assert isinstance(inspection, Mapping)
    assert isinstance(saturation, Mapping)
    assert isinstance(comparative, Mapping)
    report = inspection["report"]
    assert isinstance(report, Mapping)
    report_inspection = report["inspection"]
    assert isinstance(report_inspection, Mapping)
    summary = report_inspection["summary"]
    confidence = report_inspection["evidence_confidence"]
    assert isinstance(summary, Mapping)
    assert isinstance(confidence, Mapping)
    scenarios = comparative["scenarios"]
    assert isinstance(scenarios, list)
    comparison_lines = []
    for row in scenarios:
        assert isinstance(row, Mapping)
        comparison_lines.append(
            f"{str(row['scenario']).capitalize()}: {row['bucket_count']} measured buckets; "
            f"median p50 latency {_format_observation(row['median_latency_p50_ms'])} ms; "
            f"median p50 storage {_format_observation(row['median_storage_p50_bytes'])} bytes."
        )
    limitations = confidence["limitations"]
    assert isinstance(limitations, list)
    return (
        (
            "Evidence scope",
            "This document binds the supplied canonical evidence packet. Claims remain false. "
            "Values marked here are an observed host-local measurement or a capability distinction; "
            "the packet does not rank the compared scenarios.",
        ),
        (
            "What Promin is and can do",
            "Promin is a standards and tooling workflow for structured project evidence. "
            "It can organize inspection data, preserve source bindings, and present bounded "
            "comparison observations for review.",
        ),
        (
            "Host-local comparison (Promin / Markdown / Empty baseline)",
            "\n".join(comparison_lines)
            + " Markdown is a file/index/search baseline and Empty is filesystem overhead; "
            "they are not feature-equivalent products.",
        ),
        (
            "Exact Windows scale (100000 / 198999 / 600)",
            f"The packet records {saturation['physical_files']} physical files, "
            f"{saturation['physical_relations']} physical relations, and "
            f"{saturation['runtime_queries']} runtime queries. These are observed host-local "
            "measurements bound to the Windows evidence route.",
        ),
        (
            "Product inspection",
            f"Inspection status: {report_inspection['status']}; files: {summary['file_count']}; "
            f"directories: {summary['directory_count']}; source files: {summary['source_file_count']}; "
            f"documentation: {summary['documentation_status']}; recovery: {summary['recovery_status']}. "
            f"Evidence confidence: {confidence['level']}.",
        ),
        (
            "Limitations and next safe actions",
            "Limitations recorded by inspection: "
            + "; ".join(str(item) for item in limitations)
            + ". Resolve those limitations and collect the next bounded evidence before making "
            "a stronger claim.",
        ),
    )


def _build_evidence_pdf(packet: Mapping[str, object], destination: Path) -> None:
    """Build the deterministic six-section PDF for one validated packet."""

    try:
        from reportlab import rl_config
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Spacer
    except Exception as exc:
        raise ClientReportToolError(f"client evidence PDF renderer unavailable: {exc}") from exc

    sections = _evidence_pdf_sections(packet)
    narrative = "\n".join(f"{heading}\n{body}" for heading, body in sections)
    lowered = narrative.casefold()
    if any(term in lowered for term in _FORBIDDEN_NARRATIVE_TERMS):
        raise ClientReportToolError("client evidence narrative contains a forbidden comparative claim")

    # ReportLab reads this global while constructing the document/canvas.  Set
    # it before SimpleDocTemplate construction so IDs and metadata are stable.
    rl_config.invariant = 1
    styles = getSampleStyleSheet()
    story: list[Any] = [
        _paragraph_for_evidence("Promin client evidence report", styles["Title"]),
        Spacer(1, 0.15 * inch),
    ]
    for heading, body in sections:
        story.extend(
            (
                _paragraph_for_evidence(heading, styles["Heading2"]),
                _paragraph_for_evidence(body, styles["BodyText"]),
                Spacer(1, 0.12 * inch),
            )
        )
    document = SimpleDocTemplate(
        str(destination),
        pagesize=LETTER,
        title="Promin client evidence report",
        author="Promin",
        subject="Canonical Windows evidence summary",
    )
    document.build(story)


def _path_reparse(info: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    return stat.S_ISLNK(info.st_mode) or bool(int(getattr(info, "st_file_attributes", 0)) & reparse_flag)


def _validate_publication_destination(path: Path) -> None:
    """Require an absent destination under an existing, link-free directory."""

    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ClientReportToolError(f"publication destination cannot be inspected: {path}") from exc
    else:
        raise ClientReportToolError(f"publication destination already exists: {path}")

    parent = path.parent
    try:
        parent = parent.absolute()
    except OSError as exc:
        raise ClientReportToolError(f"publication parent cannot be resolved: {path}") from exc
    current = parent
    while True:
        try:
            info = current.lstat()
        except OSError as exc:
            raise ClientReportToolError(f"publication parent is unavailable: {current}") from exc
        if not stat.S_ISDIR(info.st_mode) or _path_reparse(info):
            raise ClientReportToolError(f"publication parent must be a real directory: {current}")
        if current == current.parent:
            break
        current = current.parent


def _publication_destination_key(path: Path) -> str:
    try:
        return os.path.normcase(os.path.abspath(os.fspath(path)))
    except (OSError, TypeError, ValueError) as exc:
        raise ClientReportToolError(f"publication destination is invalid: {path}") from exc


def _make_publication_temp(destination: Path) -> Path:
    try:
        fd, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent)
        )
        os.close(fd)
        return Path(name)
    except OSError as exc:
        raise ClientReportToolError(f"publication temporary cannot be created: {destination}") from exc


def _write_publication_temp(path: Path, data: bytes) -> None:
    try:
        with path.open("wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise ClientReportToolError(f"publication temporary cannot be written: {path.name}") from exc


def _regular_file_identity(path: Path) -> tuple[int, int]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ClientReportToolError(f"published output cannot be inspected: {path}") from exc
    if not stat.S_ISREG(info.st_mode) or _path_reparse(info):
        raise ClientReportToolError(f"published output is not a regular file: {path}")
    return int(getattr(info, "st_dev", 0)), int(getattr(info, "st_ino", 0))


def _published_identity(path: Path) -> tuple[int, int]:
    """Read and validate a regular output identity at its current path."""

    return _regular_file_identity(path)


def _unlink_created(path: Path, identity: tuple[int, int] | None = None) -> None:
    try:
        if identity is not None:
            try:
                if _regular_file_identity(path) != identity:
                    return
            except ClientReportToolError:
                return
        path.unlink()
    except (FileNotFoundError, OSError):
        pass


def _validate_published_receipt(
    receipt: Mapping[str, object], packet: Mapping[str, object], report_bytes: bytes, pdf_bytes: bytes
) -> dict[str, object]:
    expected_keys = {
        "schema",
        "record_type",
        "platform",
        "input_digests",
        "candidate_binding_digest",
        "saturation_result_digest",
        "saturation_lifecycle_sha256",
        "comparative_sha256",
        "bound_report_sha256",
        "pdf_sha256",
        "pdf_bytes",
        "claims",
        "receipt_digest",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != expected_keys:
        raise ClientReportToolError("published receipt fields are not exact")
    if receipt.get("schema") != "promin.client-report-evidence-receipt.v1" or receipt.get("record_type") != "ClientReportEvidenceReceipt" or receipt.get("platform") != "windows":
        raise ClientReportToolError("published receipt identity is invalid")
    bindings = packet["input_bindings"]
    assert isinstance(bindings, Mapping)
    expected_input_digests = {
        role: bindings[role] for role in _EVIDENCE_PACKET_SOURCE_ROLES
    }
    if receipt.get("input_digests") != expected_input_digests:
        raise ClientReportToolError("published receipt input digests do not mirror packet bindings")
    if receipt.get("candidate_binding_digest") != bindings["candidate_binding_digest"]:
        raise ClientReportToolError("published receipt candidate binding digest mismatch")
    if receipt.get("saturation_result_digest") != bindings["saturation_result"]["sha256"]:
        raise ClientReportToolError("published receipt saturation result digest mismatch")
    if receipt.get("saturation_lifecycle_sha256") != bindings["saturation_lifecycle"]["sha256"]:
        raise ClientReportToolError("published receipt saturation lifecycle digest mismatch")
    if receipt.get("comparative_sha256") != bindings["comparative"]["sha256"]:
        raise ClientReportToolError("published receipt comparative digest mismatch")
    if receipt.get("bound_report_sha256") != hashlib.sha256(report_bytes).hexdigest():
        raise ClientReportToolError("published receipt report digest mismatch")
    if receipt.get("pdf_sha256") != hashlib.sha256(pdf_bytes).hexdigest() or receipt.get("pdf_bytes") != len(pdf_bytes):
        raise ClientReportToolError("published receipt PDF binding mismatch")
    if receipt.get("claims") != packet["claims"]:
        raise ClientReportToolError("published receipt claims do not match packet")
    receipt_digest = receipt.get("receipt_digest")
    if not _is_digest(receipt_digest):
        raise ClientReportToolError("published receipt digest is invalid")
    unsigned = dict(receipt)
    unsigned.pop("receipt_digest")
    if hashlib.sha256(canonical_bytes(unsigned)).hexdigest() != receipt_digest:
        raise ClientReportToolError("published receipt digest does not match receipt body")
    return dict(receipt)


def publish_evidence_packet(
    packet: Mapping[str, object],
    report_out: Path,
    pdf_out: Path,
    receipt_out: Path,
) -> dict[str, object]:
    """Publish one validated packet, deterministic PDF, and final receipt."""

    if platform.system().casefold() != "windows":
        raise ClientReportToolError("client evidence publication requires Windows")
    validated = _validate_evidence_packet(packet)
    destinations = {
        "report": Path(report_out),
        "pdf": Path(pdf_out),
        "receipt": Path(receipt_out),
    }
    keys = [_publication_destination_key(path) for path in destinations.values()]
    if len(set(keys)) != len(keys):
        raise ClientReportToolError("publication destinations must be pairwise distinct")
    for path in destinations.values():
        _validate_publication_destination(path)

    report_bytes = canonical_bytes(validated)
    temporary: dict[str, Path] = {}
    try:
        # Reserve all three sibling temporary names before constructing any
        # output.  No destination is linked until all three files are complete.
        temporary = {}
        for name, path in destinations.items():
            temporary[name] = _make_publication_temp(path)
        _write_publication_temp(temporary["report"], report_bytes)
        _build_pdf(validated, temporary["pdf"])
        pdf_bytes = _source_bytes(temporary["pdf"], maximum=_PUBLICATION_MAX_PDF_BYTES)

        bindings = validated["input_bindings"]
        assert isinstance(bindings, Mapping)
        input_digests = {
            role: dict(bindings[role]) for role in _EVIDENCE_PACKET_SOURCE_ROLES
        }
        receipt_body: dict[str, object] = {
            "schema": "promin.client-report-evidence-receipt.v1",
            "record_type": "ClientReportEvidenceReceipt",
            "platform": "windows",
            "input_digests": input_digests,
            "candidate_binding_digest": bindings["candidate_binding_digest"],
            "saturation_result_digest": bindings["saturation_result"]["sha256"],
            "saturation_lifecycle_sha256": bindings["saturation_lifecycle"]["sha256"],
            "comparative_sha256": bindings["comparative"]["sha256"],
            "bound_report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            "pdf_sha256": hashlib.sha256(pdf_bytes).hexdigest(),
            "pdf_bytes": len(pdf_bytes),
            "claims": dict(validated["claims"]),
        }
        receipt = {
            **receipt_body,
            "receipt_digest": hashlib.sha256(canonical_bytes(receipt_body)).hexdigest(),
        }
        receipt_bytes = canonical_bytes(receipt)
        _write_publication_temp(temporary["receipt"], receipt_bytes)

        # Link is create-only and fails if a destination appeared after the
        # initial check.  The receipt is deliberately linked last.
        for name in ("report", "pdf", "receipt"):
            expected_identity = _published_identity(temporary[name])
            os.link(temporary[name], destinations[name])
            # Record the successful create-only link immediately, before any
            # destination identity inspection.  Cleanup can therefore compare
            # against the completed temporary's expected identity even when
            # the destination was concurrently replaced or became a reparse
            # point between link and inspection.
            actual_identity = _published_identity(destinations[name])
            if actual_identity != expected_identity:
                raise ClientReportToolError(
                    f"published {name} destination identity changed during publication"
                )

        reread_report = _source_bytes(destinations["report"], maximum=_PUBLICATION_MAX_JSON_BYTES)
        reread_pdf = _source_bytes(destinations["pdf"], maximum=_PUBLICATION_MAX_PDF_BYTES)
        reread_receipt = _source_bytes(destinations["receipt"], maximum=_PUBLICATION_MAX_RECEIPT_BYTES)
        if reread_report != report_bytes or reread_pdf != pdf_bytes or reread_receipt != receipt_bytes:
            raise ClientReportToolError("published output bytes changed during verification")
        try:
            reread_packet = json.loads(reread_report)
            reread_receipt_value = json.loads(reread_receipt)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ClientReportToolError("published JSON cannot be reread") from exc
        reread_packet = _validate_evidence_packet(reread_packet)
        if reread_packet != validated:
            raise ClientReportToolError("published report does not match validated packet")
        verified_receipt = _validate_published_receipt(
            reread_receipt_value, reread_packet, reread_report, reread_pdf
        )
        if verified_receipt != receipt:
            raise ClientReportToolError("published receipt does not match receipt bytes")
        return verified_receipt
    except ClientReportToolError:
        raise
    except (OSError, TypeError, ValueError, KeyError, RuntimeError) as exc:
        raise ClientReportToolError(f"client evidence publication failed: {exc}") from exc
    finally:
        for path in temporary.values():
            _unlink_created(path)


def _paragraph(text: str):
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph

    style = getSampleStyleSheet()["BodyText"]
    return Paragraph(html.escape(text).replace("\n", "<br/>"), style)


def _build_pdf(report: Mapping[str, object], destination: Path) -> None:
    """Build one client-facing PDF from the validated report only."""

    if report.get("schema") == "promin.client-report-evidence.v1":
        # Keep one patchable build seam for the legacy renderer and the
        # evidence publication route while retaining their separate layouts.
        _build_evidence_pdf(report, destination)
        return

    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    inspection = report["inspection"]
    assert isinstance(inspection, Mapping)
    summary = inspection["summary"]
    confidence = inspection["evidence_confidence"]
    assert isinstance(summary, Mapping)
    assert isinstance(confidence, Mapping)
    claims = report["claims"]
    assert isinstance(claims, Mapping)
    styles = getSampleStyleSheet()
    heading = styles["Heading2"]
    story = [Paragraph("Promin client report", styles["Title"]), Spacer(1, 0.15 * inch)]

    sections = (
        (
            "What Promin is",
            "Promin is described by this report as a tools-only, evidence-bounded workflow. "
            "This document reports the supplied fields and does not add runtime or release claims.",
        ),
        (
            "Minimal initialization",
            "Recovery status: " + str(summary["recovery_status"])
            + "; documentation status: " + str(summary["documentation_status"])
            + "; source files: " + str(summary["source_file_count"]),
        ),
        (
            "Expert configuration",
            "Declared tool profiles: " + str(summary["declared_tool_profile_count"])
            + "; files: " + str(summary["file_count"])
            + "; directories: " + str(summary["directory_count"]),
        ),
        (
            "Verified current evidence",
            "Inspection status: " + str(inspection["status"])
            + "; evidence confidence: " + str(confidence["level"])
            + "; static risk counts: " + json.dumps(inspection["static_risk_counts"], sort_keys=True),
        ),
        (
            "Evidence limits",
            "Claims are false: " + json.dumps(dict(claims), sort_keys=True)
            + ". Evidence limitations: " + "; ".join(str(item) for item in confidence["limitations"])
            + ". This report does not establish runtime, tool, platform, performance, visual, or acceptance success.",
        ),
        (
            "Next safe actions",
            "Review the source evidence, resolve stated limitations, and rerun the bounded checks before making any claim.",
        ),
    )
    for title, body in sections:
        story.extend((Paragraph(title, heading), _paragraph(body), Spacer(1, 0.12 * inch)))
    document = SimpleDocTemplate(str(destination), pagesize=LETTER, title="Promin client report")
    document.build(story)


def render_client_report(
    report: Mapping[str, object], output: Path
) -> dict[str, object]:
    """Render a validated report using create-only, same-directory publication."""

    validated = _validate_client_report(dict(report) if isinstance(report, Mapping) else report)
    destination = Path(output)
    if destination.exists():
        raise ClientReportToolError(f"output destination already exists: {destination}")
    if not destination.parent.is_dir():
        raise ClientReportToolError(f"output directory does not exist: {destination.parent}")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        os.close(fd)
        _build_pdf(validated, temporary)
        with temporary.open("r+b") as stream:
            stream.flush()
            os.fsync(stream.fileno())
            output_digest = hashlib.sha256(stream.read()).hexdigest()
        os.link(temporary, destination)
        temporary.unlink()
    except Exception as exc:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        if isinstance(exc, ClientReportToolError):
            raise
        raise ClientReportToolError(f"client PDF render failed: {exc}") from exc
    output_bytes = destination.stat().st_size
    return {
        "schema": "promin.client-report-render-receipt.v1",
        "record_type": "ClientReportRenderReceipt",
        "source_report_sha256": sha256_canonical(validated),
        "output_sha256": output_digest,
        "output_bytes": output_bytes,
        "claims": dict(validated["claims"]),
    }


class _BoundedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        bounded = str(message).replace("\r", " ").replace("\n", " ")[:_CLI_ERROR_MAX_CHARS]
        raise ClientReportToolError(f"invalid command line: {bounded}")


def _publication_parser() -> argparse.ArgumentParser:
    parser = _BoundedArgumentParser(
        description="Publish a canonical Promin Windows evidence packet and client PDF."
    )
    parser.add_argument("--inspection", type=Path, required=True)
    parser.add_argument("--saturation-root", type=Path, required=True)
    parser.add_argument("--candidate-binding", type=Path, required=True)
    parser.add_argument("--comparative", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    parser.add_argument("--pdf-out", type=Path, required=True)
    parser.add_argument("--receipt-out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _publication_parser()
    try:
        try:
            args = parser.parse_args(argv)
        except SystemExit as exc:
            # argparse has already emitted its bounded usage/help text.
            return 0 if exc.code == 0 else 2
        packet = build_evidence_packet(
            args.inspection,
            args.saturation_root,
            args.candidate_binding,
            args.comparative,
        )
        publish_evidence_packet(packet, args.report_out, args.pdf_out, args.receipt_out)
        return 0
    except Exception as exc:
        message = str(exc).replace("\r", " ").replace("\n", " ")[:512]
        print(f"promin client report failed: {message or type(exc).__name__}", file=sys.stderr)
        return 2


__all__ = [
    "ClientReportToolError",
    "build_evidence_packet",
    "load_client_report",
    "main",
    "publish_evidence_packet",
    "render_client_report",
    "sha256_canonical",
]


if __name__ == "__main__":
    raise SystemExit(main())
