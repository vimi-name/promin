"""Staged immutable evidence CAS with authoritative event finalization."""

from __future__ import annotations

from copy import deepcopy
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import posixpath
import re
import stat
import tempfile
from typing import Any, Iterable, Mapping
import unicodedata
import xml.etree.ElementTree as ElementTree

from .authority import AuthorityError, canonical_digest, parse_timestamp
from .resources import bundle_root
from .version import standard_version
from .canonical import CanonicalError, ParseLimits, canonical_bytes, parse_json_strict
from .platform_paths import filesystem_path


class EvidenceError(ValueError):
    """Raised when evidence is unresolved, mutable, stale, or non-creditable."""


@dataclass(frozen=True)
class StableExternalJson:
    """One bounded external JSON read whose digest and value share exact bytes."""

    value: dict[str, Any]
    sha256: str
    size_bytes: int
    file_identity: str


@dataclass(frozen=True)
class StableExternalBytes:
    """One bounded external binary read with stable path/file identity."""

    payload: bytes
    sha256: str
    size_bytes: int
    file_identity: str


_OUTCOMES = frozenset({"pass", "fail", "blocked", "skipped", "error"})
_RETENTION = frozenset({"ephemeral", "project", "release", "audit"})
_EVIDENCE_CLASSES = frozenset(
    {"product-execution", "validator", "harness-generated", "migration"}
)
_BASE_ARTIFACT_FIELDS = frozenset(
    {
        "record_type",
        "artifact_id",
        "artifact_kind",
        "digest",
        "media_type",
        "size_bytes",
        "retention_class",
        "created_at",
    }
)
_EVIDENCE_ARTIFACT_FIELDS = frozenset(
    {
        *_BASE_ARTIFACT_FIELDS,
        "evidence_binding",
        "outcome",
        "stale",
        "unresolved",
        "evidence_class",
        "evidence_purpose",
        "product_credit_eligible",
    }
)
_DELTA_ARTIFACT_FIELDS = frozenset({*_BASE_ARTIFACT_FIELDS, "candidate_delta"})
_EVIDENCE_BINDING_FIELDS = frozenset(
    {
        "activation_digest",
        "implementation_closure_digest",
        "candidate_digest",
        "policy_digest",
        "tool_digest",
        "input_digests",
    }
)
_EVIDENCE_BINDING_OPTIONAL_FIELDS = frozenset(
    {"finding_digest", "provider_invocations"}
)
_PROVIDER_INVOCATION_FIELDS = frozenset(
    {
        "capability_id",
        "provider_id",
        "invocation_kind",
        "identity_kind",
        "identity_digest",
        "adapter_id",
        "protocol_id",
        "operation",
        "operation_contract_digest",
        "dependency_receipt_digest",
        "implementation_closure_digest",
        "invoked",
        "started_at",
        "completed_at",
        "outcome",
        "exit_code",
        "invocation_request_digest",
        "input_digest",
        "output_digest",
        "output_size_bytes",
        "output_size_ceiling_bytes",
        "stdout_capture_digest",
        "stdout_capture_size_bytes",
        "stdout_capture_truncated",
        "stderr_capture_digest",
        "stderr_capture_size_bytes",
        "stderr_capture_truncated",
        "invocation_receipt_digest",
        "authoritative",
        "pass_credit",
    }
)
_PROVIDER_CAPABILITIES = frozenset(
    {
        "control-runtime",
        "shape-validation",
        "content-identity",
        "local-serialization",
        "query-projection",
        "filesystem-inventory",
        "export-scan",
        "signature",
        "build-dependency",
    }
)
_INVOCATION_KINDS = frozenset(
    {"python-runtime", "python-module", "executable", "platform-service"}
)
_IDENTITY_KINDS = frozenset(
    {
        "file-digest",
        "module-file-digest",
        "distribution-tree-digest",
        "module-closure-digest",
        "platform-attestation",
    }
)
_ARTIFACT_REFERENCE_FIELDS = frozenset(
    {"artifact_id", "artifact_record_digest"}
)
_GATE_EVIDENCE_ARTIFACT_BINDING_FIELDS = frozenset(
    {"artifact_id", "artifact_record_digest", "run_id", "run_digest"}
)
_GATE_RUN_DEFINITION_FIELDS = frozenset(
    {
        "definition_kind",
        "definition_id",
        "owner_kind",
        "owner_digest",
        "defined_at_head_digest",
        "gate_id",
        "run_kind",
        "expected_evidence_class",
        "expected_evidence_purpose",
        "product_credit_required",
        "target_kind",
        "target_digest",
        "target_scope",
        "candidate_digest",
        "policy_digest",
        "tool_digest",
        "implementation_closure_digest",
        "provider_binding_digest",
        "input_digests",
        "activation_digest",
    }
)
_GATE_RESULT_FIELDS = frozenset(
    {
        "record_type",
        "task_id",
        "gate_id",
        "run_id",
        "run_digest",
        "definition_digest",
        "status",
        "outcome",
        "pass_credit",
        "activation_digest",
        "candidate_digest",
        "policy_digest",
        "tool_digest",
        "evidence_class",
        "evidence_artifacts",
    }
)
_GATE_RUN_FIELDS = frozenset(
    {
        "record_type",
        "run_id",
        "run_kind",
        "task_id",
        "candidate_digest",
        "policy_digest",
        "tool_digest",
        "input_digests",
        "status",
        "started_at",
        "finished_at",
        "activation_digest",
        "definition_digest",
        "implementation_closure_digest",
        "provider_binding_digest",
    }
)
_GATE_PURPOSE_CLASSES = {
    "diagnostic": frozenset({"validator"}),
    "gate": frozenset({"validator", "product-execution"}),
    "product": frozenset({"product-execution"}),
}
_EVIDENCE_PURPOSE_CLASSES = {
    "gate": frozenset({"validator", "product-execution"}),
    "product": frozenset({"product-execution"}),
    "diagnostic": frozenset(
        {"validator", "harness-generated", "migration"}
    ),
}
_CANDIDATE_DELTA_FIELDS = frozenset(
    {
        "base_candidate_digest",
        "new_candidate_digest",
        "workcard_digest",
        "changed_paths",
    }
)
_COMMIT_FIELDS = frozenset(
    {
        "command_digest",
        "batch_digest",
        "primary_event_id",
        "primary_event_digest",
    }
)

_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
_STANDARD_CANDIDATE_IDENTITY_FIELDS = frozenset(
    {
        "record_type",
        "standard_name",
        "version",
        "archive_sha256",
        "archive_bytes",
        "archive_member_manifest_digest",
        "package_manifest_digest",
        "checksums_digest",
        "core_bundle_digest",
        "preset_digest",
        "package_tool_digest",
        "validator_digest",
        "test_manifest_digest",
        "portable_implementation_closure_digest",
        "evidence_tool_digests",
    }
)
_EVIDENCE_TOOL_PATHS = frozenset(
    {
        "tools/generate_human.py",
        "tools/promin_no_degradation.py",
        "tools/promin_package.py",
        "tools/promin_saturation.py",
        "tools/promin_saturation_audit.py",
        "tools/promin_validate.py",
    }
)
_STANDARD_CANDIDATE_FIELDS = frozenset(
    {*_STANDARD_CANDIDATE_IDENTITY_FIELDS, "candidate_binding_digest"}
)
_STANDARD_EVIDENCE_ENTRY_FIELDS = frozenset(
    {
        "evidence_id",
        "evidence_role",
        "path",
        "sha256",
        "size_bytes",
        "record_type",
        "status",
        "candidate_binding_digest",
        "predicates",
    }
)
_STANDARD_EVIDENCE_MATRIX_FIELDS = frozenset(
    {
        "path",
        "sha256",
        "size_bytes",
        "record_type",
        "matrix_digest",
        "lane_count",
        "matrix_authoritative",
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
        "product_public_approval",
    }
)
_STANDARD_EVIDENCE_SUPPLEMENTAL_FIELDS = frozenset(
    {
        "lane_id",
        "path",
        "sha256",
        "size_bytes",
        "record_type",
        "status",
        "candidate_binding_digest",
        "result_digest",
        "evidence_role",
        "producer_attestation_digest",
    }
)
_STANDARD_EVIDENCE_MANIFEST_IDENTITY_FIELDS = frozenset(
    {
        "record_type",
        "standard_name",
        "version",
        "candidate_binding_digest",
        "entries",
        "matrix_aggregate",
        "supplemental_lanes",
        "max_evidence_completed_at",
    }
)
_STANDARD_DECISION_FUTURE_SKEW_SECONDS = 300
_STANDARD_EVIDENCE_MANIFEST_FIELDS = frozenset(
    {*_STANDARD_EVIDENCE_MANIFEST_IDENTITY_FIELDS, "evidence_manifest_digest"}
)
_STANDARD_RELEASE_DECISION_IDENTITY_FIELDS = frozenset(
    {
        "record_type",
        "decision_id",
        "standard_name",
        "version",
        "candidate_binding_digest",
        "evidence_manifest_digest",
        "outcome",
        "decider_id",
        "release_capability",
        "trust_root_id",
        "signature_provider_id",
        "key_id",
        "nonce",
        "decided_at",
    }
)
_STANDARD_RELEASE_DECISION_FIELDS = frozenset(
    {
        *_STANDARD_RELEASE_DECISION_IDENTITY_FIELDS,
        "signed_claim_digest",
        "signature",
    }
)
_STANDARD_TRUST_CONFIGURATION_FIELDS = frozenset(
    {
        "record_type",
        "trust_root_id",
        "signature_provider_id",
        "algorithm",
        "keys",
    }
)
_STANDARD_TRUST_KEY_FIELDS = frozenset(
    {
        "key_id",
        "subject_id",
        "capabilities",
        "evidence_roles",
        "platforms",
        "public_key",
        "not_before",
        "not_after",
        "revoked",
    }
)
_EVIDENCE_ATTESTATION_IDENTITY_FIELDS = frozenset(
    {
        "record_type",
        "claim_domain",
        "candidate_binding_digest",
        "evidence_role",
        "evidence_record_type",
        "platform",
        "invocation_id",
        "payload_digest",
        "raw_artifact_manifest_digest",
        "producer_id",
        "trust_root_id",
        "signature_provider_id",
        "key_id",
        "public_key",
        "nonce",
        "signed_at",
    }
)
_EVIDENCE_ATTESTATION_FIELDS = frozenset(
    {
        *_EVIDENCE_ATTESTATION_IDENTITY_FIELDS,
        "signed_claim_digest",
        "signature",
    }
)
_EVIDENCE_ATTESTATION_DOMAIN = "promin.release-evidence.producer-attestation.v1"
_EVIDENCE_PRODUCE_CAPABILITY = "evidence.produce"
_STANDARD_DISTRIBUTE_CAPABILITY = "standard.distribute"
_REQUIRED_STANDARD_EVIDENCE = {
    "linux": "PlatformVerificationResult",
    "windows": "PlatformVerificationResult",
    "physical-scale": "SaturationEvidence",
    "saturation-audit": "SaturationAudit",
    "human-documents": "HumanDocumentVerification",
    "linux-no-degradation": "NoDegradationResult",
    "windows-no-degradation": "NoDegradationResult",
}
_REQUIRED_STANDARD_EVIDENCE_PLATFORMS = {
    "human-documents": ["windows"],
    "linux": ["linux"],
    "linux-no-degradation": ["linux"],
    "physical-scale": ["windows"],
    "saturation-audit": ["windows"],
    "windows": ["windows"],
    "windows-no-degradation": ["windows"],
}
_REQUIRED_MATRIX_LANES: dict[str, dict[str, str]] = {
    "linux-cp313-offline": {
        "path": "no-degradation-current/linux-cp313-offline.json",
        "platform": "linux",
        "python_minor": "3.13",
        "abi_prefix": "cpython-313-",
        "install_mode": "offline-wheelhouse",
        "record_type": "NoDegradationResult",
        "evidence_role": "linux-no-degradation",
    },
    "linux-cp313-online": {
        "path": "platform-matrix-current/linux-cp313-online.json",
        "platform": "linux",
        "python_minor": "3.13",
        "abi_prefix": "cpython-313-",
        "install_mode": "online-clean",
        "record_type": "PlatformVerificationResult",
        "evidence_role": "linux",
    },
    "linux-cp314-offline": {
        "path": "no-degradation-current/linux-cp314-offline.json",
        "platform": "linux",
        "python_minor": "3.14",
        "abi_prefix": "cpython-314-",
        "install_mode": "offline-wheelhouse",
        "record_type": "NoDegradationResult",
        "evidence_role": "linux-no-degradation",
    },
    "linux-cp314-online": {
        "path": "platform-matrix-current/linux-cp314-online.json",
        "platform": "linux",
        "python_minor": "3.14",
        "abi_prefix": "cpython-314-",
        "install_mode": "online-clean",
        "record_type": "PlatformVerificationResult",
        "evidence_role": "linux",
    },
    "windows-cp313-offline": {
        "path": "no-degradation-current/windows-cp313-offline.json",
        "platform": "windows",
        "python_minor": "3.13",
        "abi_prefix": "cp313-",
        "install_mode": "offline-wheelhouse",
        "record_type": "NoDegradationResult",
        "evidence_role": "windows-no-degradation",
    },
    "windows-cp313-online": {
        "path": "platform-matrix-current/windows-cp313-online.json",
        "platform": "windows",
        "python_minor": "3.13",
        "abi_prefix": "cp313-",
        "install_mode": "online-clean",
        "record_type": "PlatformVerificationResult",
        "evidence_role": "windows",
    },
    "windows-cp314-offline": {
        "path": "no-degradation-current/windows-cp314-offline.json",
        "platform": "windows",
        "python_minor": "3.14",
        "abi_prefix": "cp314-",
        "install_mode": "offline-wheelhouse",
        "record_type": "NoDegradationResult",
        "evidence_role": "windows-no-degradation",
    },
    "windows-cp314-online": {
        "path": "platform-matrix-current/windows-cp314-online.json",
        "platform": "windows",
        "python_minor": "3.14",
        "abi_prefix": "cp314-",
        "install_mode": "online-clean",
        "record_type": "PlatformVerificationResult",
        "evidence_role": "windows",
    },
}
_REQUIRED_SUPPLEMENTAL_MATRIX_LANES = frozenset(
    {
        "linux-cp314-offline",
        "linux-cp314-online",
        "windows-cp314-offline",
        "windows-cp314-online",
    }
)
_MATRIX_ROW_FIELDS = frozenset(
    {
        "lane_id",
        "path",
        "sha256",
        "size_bytes",
        "result_digest",
        "record_type",
        "status",
        "os",
        "python_version",
        "python_implementation",
        "python_abi",
        "install_mode",
        "evidence_role",
        "key_id",
        "subject_id",
        "attestation_digest",
        "invocation_id",
        "nonce",
        "semantic_valid",
    }
)
_MATRIX_IDENTITY_FIELDS = frozenset(
    {
        "record_type",
        "standard_name",
        "version",
        "candidate_binding_digest",
        "archive_sha256",
        "archive_bytes",
        "trust_configuration_sha256",
        "lanes",
        "lane_count",
        "complete",
        "semantic_validation_complete",
        "unique_invocation_ids",
        "unique_key_nonces",
        "matrix_authoritative",
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
        "product_public_approval",
    }
)
_REQUIRED_STANDARD_EVIDENCE_PREDICATES: dict[str, dict[str, Any]] = {
    "linux": {
        "/platform": "linux",
        "/exact_candidate_verified": True,
    },
    "windows": {
        "/platform": "windows",
        "/exact_candidate_verified": True,
    },
    "physical-scale": {
        "/physical_files": 100_000,
        "/core_valid_relations": 198_999,
        "/core_valid_relations_exact_198999": True,
        "/runtime_queries": 600,
        "/silent_truncations": 0,
        "/selected_closure_union_completeness": 1,
        "/memory_amplification_at_most_32": True,
        "/broad_query_refinement_required": True,
        "/high_cardinality_terms_verified": True,
        "/content_search_verified": True,
        "/miss_behavior_verified": True,
        "/hostile_proxy_content_verified": True,
        "/exact_artifact_search_verified": True,
        "/mixed_query_classes_complete": True,
        "/continuation_token_bytes_at_most_256": True,
        "/continuation_state_bytes_at_most_16384": True,
        "/continuation_token_overhead_at_most_10_percent": True,
    },
    "saturation-audit": {
        "/zero_new_iterations": 3,
        "/new_findings": 0,
    },
    "human-documents": {
        "/deterministic_rebuild": True,
        "/visual_review_scope/completed": True,
        "/visual_review_scope/clipping_detected": False,
        "/visual_review_scope/unreadable_text_detected": False,
    },
    "linux-no-degradation": {
        "/platform": "linux",
        "/no_degradation": True,
    },
    "windows-no-degradation": {
        "/platform": "windows",
        "/no_degradation": True,
    },
}
_HUMAN_DOCUMENT_FIELDS = frozenset(
    {
        "path",
        "sha256",
        "size_bytes",
        "page_count",
        "extracted_characters",
        "blank_pages",
        "extraction_errors",
    }
)
_HUMAN_DOCUMENT_VERIFICATION_FIELDS = frozenset(
    {
        "record_type",
        "status",
        "candidate_binding_digest",
        "documents",
        "deterministic_rebuild",
        "rebuild_digest",
        "page_count",
        "extraction_diagnostics",
        "visual_review_scope",
        "font_bindings",
        "generator_result_digest",
        "render_environment",
        "render_manifest",
        "render_manifest_digest",
        "product_acceptance_pass",
        "producer",
        "invocation",
        "raw_artifact_manifest_digest",
        "producer_attestation",
        "result_digest",
    }
)
_HUMAN_EXTRACTION_FIELDS = frozenset(
    {
        "documents_parsed",
        "total_extracted_characters",
        "blank_pages",
        "errors",
    }
)
_HUMAN_VISUAL_REVIEW_FIELDS = frozenset(
    {
        "completed",
        "reviewer_id",
        "reviewed_at",
        "rendered_page_count",
        "pages_reviewed",
        "clipping_detected",
        "unreadable_text_detected",
        "render_manifest_digest",
    }
)
_HUMAN_RENDER_ROW_FIELDS = frozenset(
    {
        "document_path",
        "page",
        "image_path",
        "image_sha256",
        "image_bytes",
    }
)
_PLATFORM_VERIFICATION_FIELDS = frozenset(
    {
        "record_type",
        "status",
        "candidate_binding_digest",
        "platform",
        "platform_identity",
        "exact_candidate_verified",
        "archive_sha256",
        "archive_bytes",
        "portable_implementation_closure_digest",
        "observed_environment_closure_digest",
        "install_mode",
        "installed_command_verified",
        "installation",
        "product_acceptance_pass",
        "product_public_approval",
        "producer",
        "invocation",
        "raw_artifact_manifest_digest",
        "producer_attestation",
        "result_digest",
    }
)
_PLATFORM_IDENTITY_FIELDS = frozenset(
    {
        "platform",
        "machine",
        "platform_release",
        "sys_platform",
        "platform_tags",
        "python_version",
        "python_implementation",
        "python_executable",
        "python_executable_sha256",
        "python_abi_tag",
    }
)
_PLATFORM_INSTALLATION_FIELDS = frozenset(
    {
        "environment",
        "installation_performed",
        "nested_venv_created",
        "runtime_dependency_source",
        "build_dependency_source",
        "network_disabled",
        "declared_python_requirement",
        "installed_distribution",
        "console_script",
        "command_invocations",
        "dependency_closure",
        "installed_environment_observation",
        "pip_report",
        "sbom",
        "license_closure",
        "build_backend",
    }
)
_PLATFORM_CONSOLE_FIELDS = frozenset(
    {
        "present",
        "declared",
        "installed_wrapper_checked",
        "source_module_invoked",
        "posix_execute_bits",
        "path",
        "sha256",
        "size_bytes",
    }
)
_PLATFORM_COMMAND_FIELDS = frozenset(
    {
        "command",
        "argv_digest",
        "returncode",
        "stdout_sha256",
        "stdout_bytes",
        "stderr_sha256",
        "stderr_bytes",
    }
)
_RELEASE_EVIDENCE_PRODUCER_FIELDS = frozenset(
    {"tool_path", "tool_sha256", "tool_version"}
)
_RELEASE_EVIDENCE_INVOCATION_FIELDS = frozenset(
    {
        "invocation_id",
        "operation",
        "arguments_digest",
        "started_at",
        "completed_at",
        "exit_code",
        "platform_binding_digest",
    }
)
_RELEASE_EVIDENCE_ENVELOPE_FIELDS = frozenset(
    {
        "producer",
        "invocation",
        "raw_artifact_manifest_digest",
        "producer_attestation",
        "result_digest",
    }
)
_NO_DEGRADATION_FIELDS = frozenset(
    {
        "record_type",
        "status",
        "platform",
        "no_degradation",
        "source",
        "root",
        "artifact_binding",
        "candidate_binding_digest",
        "test_manifest",
        "install_mode",
        "required_predicates",
        "validation",
        "tests",
        "passed",
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
        "product_public_approval",
        "scale_selection",
        "artifact_binding_unchanged",
        "standard_distribution_gate_pass",
        "phases",
        "execution_budget",
        *_RELEASE_EVIDENCE_ENVELOPE_FIELDS,
    }
)
_NO_DEGRADATION_INSTALLATION_FIELDS = frozenset(
    {
        "performed",
        "verified",
        "mode",
        "environment",
        "runtime_dependency_source",
        "build_dependency_source",
        "network_disabled",
        "installation_performed",
        "nested_venv_created",
        "wheelhouse_binding",
        "declared_runtime_dependencies",
        "declared_build_dependencies",
        "declared_python_requirement",
        "resolved_runtime_dependencies",
        "dependency_closure_check",
        "installed_environment_observation",
        "pip_report",
        "wheelhouse_lock",
        "origin_assertion",
        "test_dependencies_installed",
        "version",
        "python_distribution_version",
        "console_script",
        "invocations",
        "interpreter",
        "platform",
        "product_acceptance_pass",
    }
)
_SATURATION_EVIDENCE_FIELDS = frozenset(
    {
        "record_type",
        "status",
        "candidate_binding_digest",
        "artifact_binding",
        "artifact_binding_unchanged",
        "workspace_initialization",
        "runtime_binding",
        "physical_files",
        "core_valid_relations",
        "runtime_queries",
        "silent_truncations",
        "selected_closure_union_completeness",
        "memory_amplification_at_most_32",
        "core_valid_relations_exact_198999",
        "broad_query_refinement_required",
        "high_cardinality_terms_verified",
        "content_search_verified",
        "miss_behavior_verified",
        "hostile_proxy_content_verified",
        "exact_artifact_search_verified",
        "mixed_query_classes_complete",
        "continuation_token_bytes_at_most_256",
        "continuation_state_bytes_at_most_16384",
        "continuation_token_overhead_at_most_10_percent",
        "pass_credit",
        "physical",
        "inventory",
        "projection",
        "query_authorization",
        "search",
        "resources",
        "performance",
        "contract_predicates",
        "raw_artifact_manifest",
        "current_release_regression",
        "claim_scope",
        "acceptance_pass",
        "product_acceptance_pass",
        "public_release_approved",
        *_RELEASE_EVIDENCE_ENVELOPE_FIELDS,
    }
)
_SATURATION_AUDIT_FIELDS = frozenset(
    {
        "record_type",
        "status",
        "candidate_binding_digest",
        "zero_new_iterations",
        "new_findings",
        "pass_credit",
        "artifact_binding",
        "families",
        "collection",
        "iterations",
        "consecutive_full_zero_new",
        "requirements",
        "predeclared_zero_new",
        "acceptance_pass",
        "product_acceptance_pass",
        *_RELEASE_EVIDENCE_ENVELOPE_FIELDS,
    }
)
_EXPECTED_HUMAN_DOCUMENT_PATHS = frozenset(
    {
        "human/promin_appendices_en.pdf",
        "human/promin_appendices_ua.pdf",
        "human/promin_main_en.pdf",
        "human/promin_main_ua.pdf",
    }
)

_EXTERNAL_JSON_LIMITS = ParseLimits(
    max_bytes=16 * 1024 * 1024,
    max_depth=64,
    max_items=200_000,
    max_string_length=1_048_576,
    max_number_length=256,
)
_EXTERNAL_CONTAINER_MEMBERS_MAX = 100_000
_WINDOWS_REPARSE_POINT = 0x400
_RELEASE_SCHEMA_CACHE: dict[str, Any] | None = None


def _valid_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _valid_semver(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= 128 and _SEMVER.fullmatch(value) is not None


def release_evidence_producer(
    package_root: Path | str,
    tool_path: str,
    *,
    version: str | None = None,
) -> dict[str, Any]:
    """Build an exact producer identity for an external release-evidence record."""

    normalized = _external_relative_path(tool_path)
    version = standard_version() if version is None else version
    if normalized not in _EVIDENCE_TOOL_PATHS or not _valid_semver(version):
        raise EvidenceError("release evidence producer identity is invalid")
    resolved = Path(package_root).joinpath(*normalized.split("/"))
    if resolved.is_symlink() or not resolved.is_file():
        raise EvidenceError("release evidence producer tool is unavailable")
    return {
        "tool_path": normalized,
        "tool_sha256": _digest_file(resolved),
        "tool_version": version,
    }


def release_evidence_invocation(
    *,
    invocation_id: str,
    operation: str,
    arguments: Mapping[str, Any],
    started_at: str,
    completed_at: str,
    exit_code: int,
    platform_binding: Mapping[str, Any] | str,
) -> dict[str, Any]:
    """Build a bounded invocation identity without embedding unbounded command output."""

    _safe_id(invocation_id)
    _safe_id(operation)
    started = parse_timestamp(started_at)
    completed = parse_timestamp(completed_at)
    if completed < started:
        raise EvidenceError("release evidence invocation completion precedes its start")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise EvidenceError("release evidence invocation exit code is invalid")
    platform_digest = (
        platform_binding
        if isinstance(platform_binding, str)
        else canonical_digest(dict(platform_binding))
    )
    if not _valid_digest(platform_digest):
        raise EvidenceError("release evidence platform binding digest is invalid")
    return {
        "invocation_id": invocation_id,
        "operation": operation,
        "arguments_digest": canonical_digest(dict(arguments)),
        "started_at": started_at,
        "completed_at": completed_at,
        "exit_code": exit_code,
        "platform_binding_digest": platform_digest,
    }


def _normalized_evidence_platform(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return "cross-platform"
    lowered = value.casefold()
    if lowered.startswith("win"):
        return "windows"
    if lowered.startswith("linux"):
        return "linux"
    if lowered.startswith("darwin") or lowered.startswith("mac"):
        return "darwin"
    if lowered == "cross-platform":
        return lowered
    return lowered[:64]


def _release_evidence_role(record: Mapping[str, Any]) -> str:
    record_type = record.get("record_type")
    if record_type == "PlatformVerificationResult":
        platform_name = _normalized_evidence_platform(record.get("platform"))
        if platform_name not in {"linux", "windows"}:
            raise EvidenceError("platform evidence has no configured release role")
        return platform_name
    if record_type == "NoDegradationResult":
        platform_name = _normalized_evidence_platform(record.get("platform"))
        if platform_name not in {"linux", "windows"}:
            raise EvidenceError("no-degradation evidence has no configured release role")
        return f"{platform_name}-no-degradation"
    roles = {
        "SaturationEvidence": "physical-scale",
        "SaturationAudit": "saturation-audit",
        "HumanDocumentVerification": "human-documents",
    }
    role = roles.get(record_type)
    if role is None:
        raise EvidenceError("release evidence record type has no producer role")
    return role


def _release_evidence_platform(record: Mapping[str, Any]) -> str:
    if isinstance(record.get("platform"), str):
        return _normalized_evidence_platform(record["platform"])
    binding = record.get("artifact_binding")
    if isinstance(binding, Mapping):
        platform_binding = binding.get("platform")
        if isinstance(platform_binding, Mapping):
            return _normalized_evidence_platform(platform_binding.get("system"))
    render_environment = record.get("render_environment")
    if isinstance(render_environment, Mapping):
        return _normalized_evidence_platform(render_environment.get("platform"))
    return "cross-platform"


def _release_evidence_raw_identity(record: Mapping[str, Any]) -> dict[str, Any]:
    explicit = record.get("raw_artifact_manifest")
    if isinstance(explicit, Mapping):
        return deepcopy(dict(explicit))
    record_type = record.get("record_type")
    fields_by_type = {
        "PlatformVerificationResult": (
            "installation",
            "platform_identity",
            "observed_environment_closure_digest",
        ),
        "NoDegradationResult": (
            "artifact_binding",
            "test_manifest",
            "validation",
            "tests",
            "phases",
            "execution_budget",
        ),
        "SaturationEvidence": (
            "artifact_binding",
            "physical",
            "inventory",
            "projection",
            "search",
            "resources",
            "performance",
            "contract_predicates",
            "current_release_regression",
        ),
        "SaturationAudit": (
            "artifact_binding",
            "families",
            "collection",
            "iterations",
            "requirements",
        ),
        "HumanDocumentVerification": (
            "documents",
            "extraction_diagnostics",
            "font_bindings",
            "render_environment",
            "render_manifest",
        ),
    }
    fields = fields_by_type.get(record_type)
    if fields is None:
        raise EvidenceError("release evidence has no raw-artifact identity owner")
    return {field: deepcopy(record.get(field)) for field in fields}


def _load_evidence_private_key(path: Path) -> Any:
    try:
        payload = read_external_bytes_stable(path, max_bytes=64 * 1024).payload
    except (OSError, EvidenceError) as exc:
        raise EvidenceError("configured evidence producer private key is unavailable") from exc
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        if len(payload) == 32:
            return Ed25519PrivateKey.from_private_bytes(payload)
        key = serialization.load_pem_private_key(payload, password=None)
    except (ImportError, TypeError, ValueError) as exc:
        raise EvidenceError("configured evidence producer private key is invalid") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise EvidenceError("configured evidence producer key must be Ed25519")
    return key


def _configured_evidence_signer(
    role: str,
    platform_name: str,
    *,
    private_key_path: Path | str,
    trust_configuration_path: Path | str,
    key_id: str,
    producer_id: str | None = None,
    signed_at: datetime | str | None = None,
) -> tuple[Any, dict[str, Any]]:
    try:
        trust_read = load_external_json_stable(Path(trust_configuration_path))
    except (OSError, CanonicalError, EvidenceError) as exc:
        raise EvidenceError("evidence producer trust configuration is invalid") from exc
    trust = _validate_trust_configuration(trust_read.value)
    matches = [key for key in trust["keys"] if key["key_id"] == key_id]
    if len(matches) != 1:
        raise EvidenceError("evidence producer key is not configured")
    key = matches[0]
    effective_producer_id = producer_id or key["subject_id"]
    if signed_at is None:
        effective_time = datetime.now(timezone.utc)
    elif isinstance(signed_at, datetime):
        if signed_at.tzinfo is None or signed_at.utcoffset() is None:
            raise EvidenceError("evidence producer signing time must be timezone-aware")
        effective_time = signed_at.astimezone(timezone.utc)
    else:
        effective_time = parse_timestamp(signed_at)
    if (
        _EVIDENCE_PRODUCE_CAPABILITY not in key["capabilities"]
        or _STANDARD_DISTRIBUTE_CAPABILITY in key["capabilities"]
        or role not in key["evidence_roles"]
        or platform_name not in key["platforms"]
        or key["revoked"] is True
        or effective_time < parse_timestamp(key["not_before"])
        or effective_time >= parse_timestamp(key["not_after"])
    ):
        raise EvidenceError(
            "evidence producer key has the wrong role, platform, validity, or SOD scope"
        )
    if effective_producer_id != key["subject_id"]:
        raise EvidenceError("configured evidence producer identity differs from its trust key")
    private_key = _load_evidence_private_key(Path(private_key_path))
    try:
        from cryptography.hazmat.primitives import serialization

        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except (ImportError, ValueError) as exc:
        raise EvidenceError("evidence producer public key cannot be derived") from exc
    public_key_text = base64.b64encode(public_key).decode("ascii")
    if public_key_text != key["public_key"]:
        raise EvidenceError("evidence producer private key does not match its trust key")
    return private_key, {
        "producer_id": effective_producer_id,
        "trust_root_id": trust["trust_root_id"],
        "key_id": key["key_id"],
        "configured_public_key": key["public_key"],
        "trust_configuration_sha256": trust_read.sha256,
        "evidence_role": role,
        "platform": platform_name,
    }


def validate_release_evidence_producer_configuration(
    *,
    role: str,
    platform_name: str,
    private_key_path: Path | str,
    trust_configuration_path: Path | str,
    key_id: str,
    producer_id: str | None = None,
    signed_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Preflight one configured producer without exposing private key material."""

    _, metadata = _configured_evidence_signer(
        role,
        platform_name,
        private_key_path=private_key_path,
        trust_configuration_path=trust_configuration_path,
        key_id=key_id,
        producer_id=producer_id,
        signed_at=signed_at,
    )
    return deepcopy(metadata)


def _evidence_signer(
    role: str,
    platform_name: str,
    *,
    signed_at: datetime | str | None = None,
) -> tuple[Any, dict[str, Any]]:
    private_path = os.environ.get("PROMIN_EVIDENCE_PRIVATE_KEY")
    trust_path = os.environ.get("PROMIN_EVIDENCE_TRUST_CONFIGURATION")
    key_id = os.environ.get("PROMIN_EVIDENCE_KEY_ID")
    producer_id = os.environ.get("PROMIN_EVIDENCE_PRODUCER_ID")
    configured = (private_path, trust_path, key_id)
    if (any(configured) and not all(configured)) or (producer_id and not all(configured)):
        raise EvidenceError("evidence producer signing configuration is partial")
    if all(configured):
        return _configured_evidence_signer(
            role,
            platform_name,
            private_key_path=private_path,
            trust_configuration_path=trust_path,
            key_id=key_id,
            producer_id=producer_id,
            signed_at=signed_at,
        )
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
    except ImportError as exc:
        raise EvidenceError("Ed25519 evidence producer is unavailable") from exc
    return private_key, {
        "producer_id": "untrusted-local-producer",
        "trust_root_id": "untrusted-ephemeral",
        "key_id": "untrusted-ephemeral-key",
        "configured_public_key": None,
    }


def _producer_attestation(
    record: Mapping[str, Any],
    *,
    raw_artifact_manifest_digest: str,
) -> dict[str, Any]:
    role = _release_evidence_role(record)
    platform_name = _release_evidence_platform(record)
    invocation = record.get("invocation")
    if not isinstance(invocation, Mapping):
        raise EvidenceError("release evidence lacks its invocation identity")
    private_key, signer = _evidence_signer(
        role,
        platform_name,
        signed_at=invocation.get("completed_at"),
    )
    try:
        from cryptography.hazmat.primitives import serialization

        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except (ImportError, ValueError) as exc:
        raise EvidenceError("evidence producer public key cannot be derived") from exc
    public_key_text = base64.b64encode(public_key).decode("ascii")
    if signer["configured_public_key"] not in {None, public_key_text}:
        raise EvidenceError("evidence producer private key does not match its trust key")
    payload_digest = canonical_digest(dict(record))
    identity = {
        "record_type": "EvidenceProducerAttestation",
        "claim_domain": _EVIDENCE_ATTESTATION_DOMAIN,
        "candidate_binding_digest": record.get("candidate_binding_digest"),
        "evidence_role": role,
        "evidence_record_type": record.get("record_type"),
        "platform": platform_name,
        "invocation_id": invocation.get("invocation_id"),
        "payload_digest": payload_digest,
        "raw_artifact_manifest_digest": raw_artifact_manifest_digest,
        "producer_id": signer["producer_id"],
        "trust_root_id": signer["trust_root_id"],
        "signature_provider_id": "cryptography-ed25519-v1",
        "key_id": signer["key_id"],
        "public_key": public_key_text,
        "nonce": base64.b64encode(os.urandom(24)).decode("ascii"),
        "signed_at": invocation.get("completed_at"),
    }
    claim_digest = canonical_digest(identity)
    return {
        **identity,
        "signed_claim_digest": claim_digest,
        "signature": base64.b64encode(
            private_key.sign(bytes.fromhex(claim_digest))
        ).decode("ascii"),
    }


def seal_release_evidence(record: Mapping[str, Any]) -> dict[str, Any]:
    """Attest and seal one release-evidence result without granting release credit."""

    if (
        not isinstance(record, Mapping)
        or "result_digest" in record
        or "producer_attestation" in record
        or "raw_artifact_manifest_digest" in record
    ):
        raise EvidenceError("release evidence must be one unattested, unsealed object")
    stored = deepcopy(dict(record))
    raw_digest = canonical_digest(_release_evidence_raw_identity(stored))
    stored["raw_artifact_manifest_digest"] = raw_digest
    stored["producer_attestation"] = _producer_attestation(
        stored,
        raw_artifact_manifest_digest=raw_digest,
    )
    return {**stored, "result_digest": canonical_digest(stored)}


def _digest_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(filesystem_path(path), "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or any(
            char
            not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-"
            for char in value
        )
    ):
        raise EvidenceError("invalid evidence artifact ID")
    return value


def _decode_base64(value: Any, label: str, *, expected_bytes: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise EvidenceError(f"{label} is not bounded base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise EvidenceError(f"{label} is not canonical base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise EvidenceError(f"{label} is not canonical base64")
    if expected_bytes is not None and len(decoded) != expected_bytes:
        raise EvidenceError(f"{label} has the wrong length")
    return decoded


def _external_relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096:
        raise EvidenceError("evidence path is invalid")
    if unicodedata.normalize("NFC", value) != value or "\\" in value or "\x00" in value:
        raise EvidenceError("evidence path is not canonical POSIX NFC")
    normalized = posixpath.normpath(value)
    if (
        value.startswith("/")
        or normalized in {"", ".", ".."}
        or normalized.startswith("../")
        or normalized != value
    ):
        raise EvidenceError("evidence path escapes its configured root")
    return normalized


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
    )


def _is_link_or_reparse(value: os.stat_result) -> bool:
    return stat.S_ISLNK(value.st_mode) or bool(
        getattr(value, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
    )


def _external_components(value: Path) -> tuple[str, ...]:
    parts = tuple(value.parts)
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise EvidenceError("external evidence path components are not canonical")
    if os.name == "nt":
        reserved = {
            "con",
            "prn",
            "aux",
            "nul",
            *(f"com{index}" for index in range(1, 10)),
            *(f"lpt{index}" for index in range(1, 10)),
        }
        for part in parts:
            stem = part.split(".", 1)[0].casefold()
            if ":" in part or part.endswith((".", " ")) or stem in reserved:
                raise EvidenceError("external evidence path uses unsafe Windows syntax")
    return parts


def _external_file_plan(
    path: Path | str,
    root: Path | str | None,
) -> tuple[Path, Path, tuple[str, ...]]:
    absolute = Path(os.path.abspath(path))
    if root is None:
        base = absolute.parent
        relative = Path(absolute.name)
    else:
        base = Path(os.path.abspath(root))
        try:
            common = Path(os.path.commonpath((str(absolute), str(base))))
        except ValueError as exc:
            raise EvidenceError("external evidence path is on another filesystem root") from exc
        if os.path.normcase(str(common)) != os.path.normcase(str(base)):
            raise EvidenceError("external evidence path escapes its configured root")
        relative_text = os.path.relpath(absolute, base)
        if relative_text == ".":
            raise EvidenceError("external evidence file cannot be the configured root")
        relative = Path(relative_text)
    return absolute, base, _external_components(relative)


def _open_posix_directory_absolute(path: Path) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None or os.open not in os.supports_dir_fd:
        raise EvidenceError("descriptor-relative no-follow traversal is unavailable")
    flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    anchor = Path(path.anchor)
    try:
        current = os.open(anchor, flags)
    except OSError as exc:
        raise EvidenceError("external filesystem root cannot be opened safely") from exc
    try:
        for component in _external_components(Path(*path.parts[1:])) if len(path.parts) > 1 else ():
            following = os.open(component, flags, dir_fd=current)
            inspected = os.fstat(following)
            if not stat.S_ISDIR(inspected.st_mode):
                os.close(following)
                raise EvidenceError("external path component is not a directory")
            os.close(current)
            current = following
        return current
    except (OSError, EvidenceError) as exc:
        try:
            os.close(current)
        except OSError:
            pass
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError("external directory descriptor walk failed") from exc


def _open_posix_file(base: Path, parts: tuple[str, ...]) -> int:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise EvidenceError("descriptor-relative no-follow traversal is unavailable")
    current = _open_posix_directory_absolute(base)
    directory_flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        for component in parts[:-1]:
            following = os.open(component, directory_flags, dir_fd=current)
            inspected = os.fstat(following)
            if not stat.S_ISDIR(inspected.st_mode):
                os.close(following)
                raise EvidenceError("external path component is not a directory")
            os.close(current)
            current = following
        return os.open(parts[-1], file_flags, dir_fd=current)
    except OSError as exc:
        raise EvidenceError("external evidence descriptor walk failed") from exc
    finally:
        os.close(current)


def _open_windows_handle(
    base: Path,
    parts: tuple[str, ...],
    *,
    final_directory: bool,
) -> tuple[int, Any]:
    import ctypes
    from ctypes import wintypes

    class UnicodeString(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        ]

    class ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(UnicodeString)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        ]

    class IoStatusBlock(ctypes.Structure):
        _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [("FileAttributes", wintypes.DWORD), ("ReparseTag", wintypes.DWORD)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    get_information = kernel32.GetFileInformationByHandleEx
    get_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    get_information.restype = wintypes.BOOL
    nt_create = ntdll.NtCreateFile
    nt_create.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(ObjectAttributes),
        ctypes.POINTER(IoStatusBlock),
        ctypes.c_void_p,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
    ]
    nt_create.restype = ctypes.c_long

    file_attribute_reparse = 0x00000400
    file_attribute_directory = 0x00000010
    invalid = ctypes.c_void_p(-1).value

    def inspect(handle: int, *, directory_expected: bool) -> None:
        information = FileAttributeTagInfo()
        if not get_information(
            handle,
            9,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            raise EvidenceError(
                f"external Windows handle inspection failed: winerror={ctypes.get_last_error()}"
            )
        is_directory = bool(information.FileAttributes & file_attribute_directory)
        if information.FileAttributes & file_attribute_reparse or is_directory != directory_expected:
            raise EvidenceError("external Windows path contains a reparse point or wrong entry kind")

    anchor = Path(base.anchor)
    current = create_file(
        str(anchor),
        0x00100000 | 0x00000080,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    if current == invalid:
        raise EvidenceError(
            f"external Windows filesystem root open failed: winerror={ctypes.get_last_error()}"
        )
    current_value = int(current)
    try:
        inspect(current_value, directory_expected=True)
        base_components = (
            _external_components(Path(*base.parts[1:])) if len(base.parts) > 1 else ()
        )
        components = (*base_components, *parts)
        base_count = max(0, len(base.parts) - 1)
        for index, component in enumerate(components):
            is_last = index == len(components) - 1
            directory_expected = index < base_count or not is_last or final_directory
            buffer = ctypes.create_unicode_buffer(component)
            name = UnicodeString(
                Length=len(component.encode("utf-16-le")),
                MaximumLength=len(component.encode("utf-16-le")) + 2,
                Buffer=ctypes.cast(buffer, wintypes.LPWSTR),
            )
            attributes = ObjectAttributes(
                Length=ctypes.sizeof(ObjectAttributes),
                RootDirectory=current_value,
                ObjectName=ctypes.pointer(name),
                Attributes=0x00000040,
                SecurityDescriptor=None,
                SecurityQualityOfService=None,
            )
            status_block = IoStatusBlock()
            following = wintypes.HANDLE()
            options = 0x00200000 | 0x00000020 | (0x00000001 if directory_expected else 0x00000040)
            access = 0x00100000 | 0x00000080 | (0x00000020 if directory_expected else 0x00000001)
            status = nt_create(
                ctypes.byref(following),
                access,
                ctypes.byref(attributes),
                ctypes.byref(status_block),
                None,
                0,
                0x00000001 | 0x00000002 | 0x00000004,
                1,
                options,
                None,
                0,
            )
            if status < 0:
                raise EvidenceError(
                    f"external Windows relative open failed: ntstatus=0x{status & 0xffffffff:08x}"
                )
            following_value = int(following.value)
            try:
                inspect(following_value, directory_expected=directory_expected)
            except Exception:
                close_handle(following_value)
                raise
            close_handle(current_value)
            current_value = following_value
        return current_value, close_handle
    except Exception:
        close_handle(current_value)
        raise


def _open_external_file_descriptor(path: Path | str, root: Path | str | None) -> tuple[int, Path]:
    absolute, base, parts = _external_file_plan(path, root)
    if os.name != "nt":
        return _open_posix_file(base, parts), absolute
    import msvcrt

    handle, close_handle = _open_windows_handle(base, parts, final_directory=False)
    try:
        descriptor = msvcrt.open_osfhandle(
            handle,
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        )
    except OSError:
        close_handle(handle)
        raise
    return descriptor, absolute


def _require_external_root(path: Path, root: Path | str | None) -> Path:
    absolute = Path(os.path.abspath(path))
    if root is not None:
        configured = Path(os.path.abspath(root))
        try:
            common = Path(os.path.commonpath((str(absolute), str(configured))))
        except ValueError as exc:
            raise EvidenceError("external evidence path is on another filesystem root") from exc
        if os.path.normcase(str(common)) != os.path.normcase(str(configured)):
            raise EvidenceError("external evidence path escapes its configured root")
    if os.name == "nt":
        handle, close_handle = _open_windows_handle(absolute, (), final_directory=True)
        close_handle(handle)
    else:
        descriptor = _open_posix_directory_absolute(absolute)
        os.close(descriptor)
    return absolute


def _validate_external_collections(value: Any) -> None:
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, dict):
            if len(current) > _EXTERNAL_CONTAINER_MEMBERS_MAX:
                raise EvidenceError("external evidence object member limit exceeded")
            casefolded: dict[str, str] = {}
            for key, item in current.items():
                folded = unicodedata.normalize("NFC", key).casefold()
                previous = casefolded.get(folded)
                if previous is not None and previous != key:
                    raise EvidenceError(
                        f"external evidence key collision after NFC/casefold: {previous!r} vs {key!r}"
                    )
                casefolded[folded] = key
                pending.append(item)
        elif isinstance(current, list):
            if len(current) > _EXTERNAL_CONTAINER_MEMBERS_MAX:
                raise EvidenceError("external evidence array item limit exceeded")
            pending.extend(current)


def read_external_bytes_stable(
    path: Path | str,
    *,
    root: Path | str | None = None,
    max_bytes: int = 16 * 1024 * 1024,
) -> StableExternalBytes:
    """Read and hash one bounded file from one descriptor and unchanged identity."""

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1:
        raise EvidenceError("external byte limit must be a positive integer")
    try:
        descriptor, absolute = _open_external_file_descriptor(path, root)
    except (OSError, EvidenceError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError(f"external evidence file cannot be opened safely: {path}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise EvidenceError("external evidence must be a bounded regular file")
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1 - observed))
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > max_bytes:
                raise EvidenceError(f"external evidence exceeds {max_bytes} bytes")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if _stat_identity(before) != _stat_identity(after) or observed != after.st_size:
        raise EvidenceError("external evidence changed during its stable read")
    payload = b"".join(chunks)
    identity = canonical_digest(
        {
            "device": after.st_dev,
            "inode": after.st_ino,
            "size_bytes": after.st_size,
            "modified_ns": after.st_mtime_ns,
        }
    )
    return StableExternalBytes(
        payload=payload,
        sha256=_digest_bytes(payload),
        size_bytes=len(payload),
        file_identity=identity,
    )


def load_external_json_stable(
    path: Path | str,
    *,
    root: Path | str | None = None,
) -> StableExternalJson:
    """Read, hash, and parse one external file without a hash/parse reopen window."""

    stable = read_external_bytes_stable(
        path,
        root=root,
        max_bytes=_EXTERNAL_JSON_LIMITS.max_bytes,
    )
    try:
        value = parse_json_strict(stable.payload, limits=_EXTERNAL_JSON_LIMITS)
    except CanonicalError as exc:
        raise EvidenceError(f"external evidence is not bounded canonical UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError("external evidence file must contain one object")
    _validate_external_collections(value)
    return StableExternalJson(
        value=value,
        sha256=stable.sha256,
        size_bytes=stable.size_bytes,
        file_identity=stable.file_identity,
    )


def _load_external_json(path: Path, *, root: Path | str | None = None) -> dict[str, Any]:
    return load_external_json_stable(path, root=root).value


def _validate_producer_attestation(
    record: Mapping[str, Any],
    *,
    candidate: Mapping[str, Any],
    expected_role: str,
    expected_platform: str,
) -> dict[str, Any]:
    attestation = record.get("producer_attestation")
    if (
        not isinstance(attestation, Mapping)
        or set(attestation) != _EVIDENCE_ATTESTATION_FIELDS
        or attestation.get("record_type") != "EvidenceProducerAttestation"
        or attestation.get("claim_domain") != _EVIDENCE_ATTESTATION_DOMAIN
        or attestation.get("candidate_binding_digest")
        != candidate.get("candidate_binding_digest")
        or attestation.get("evidence_role") != expected_role
        or attestation.get("evidence_record_type") != record.get("record_type")
        or attestation.get("platform") != expected_platform
    ):
        raise EvidenceError("release evidence producer attestation scope is invalid")
    for field in ("producer_id", "trust_root_id", "key_id", "invocation_id"):
        _safe_id(attestation.get(field))
    if attestation.get("signature_provider_id") != "cryptography-ed25519-v1":
        raise EvidenceError("release evidence producer signature provider is invalid")
    invocation = record.get("invocation")
    if (
        not isinstance(invocation, Mapping)
        or attestation.get("invocation_id") != invocation.get("invocation_id")
        or attestation.get("signed_at") != invocation.get("completed_at")
    ):
        raise EvidenceError("release evidence attestation binds another invocation")
    parse_timestamp(attestation.get("signed_at"))
    raw_digest = canonical_digest(_release_evidence_raw_identity(record))
    if (
        record.get("raw_artifact_manifest_digest") != raw_digest
        or attestation.get("raw_artifact_manifest_digest") != raw_digest
    ):
        raise EvidenceError("release evidence raw-artifact manifest digest mismatch")
    payload = {
        key: deepcopy(value)
        for key, value in record.items()
        if key not in {"producer_attestation", "result_digest"}
    }
    if attestation.get("payload_digest") != canonical_digest(payload):
        raise EvidenceError("release evidence producer attestation payload drift")
    identity = {
        field: deepcopy(attestation[field])
        for field in _EVIDENCE_ATTESTATION_IDENTITY_FIELDS
    }
    claim_digest = canonical_digest(identity)
    if attestation.get("signed_claim_digest") != claim_digest:
        raise EvidenceError("release evidence producer claim digest mismatch")
    public_key = _decode_base64(
        attestation.get("public_key"),
        "evidence producer public key",
        expected_bytes=32,
    )
    nonce = _decode_base64(attestation.get("nonce"), "evidence producer nonce")
    if len(nonce) < 16 or len(nonce) > 64:
        raise EvidenceError("release evidence producer nonce length is invalid")
    signature = _decode_base64(
        attestation.get("signature"),
        "evidence producer signature",
        expected_bytes=64,
    )
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            bytes.fromhex(claim_digest),
        )
    except ImportError as exc:
        raise EvidenceError("configured Ed25519 verifier is unavailable") from exc
    except (InvalidSignature, ValueError) as exc:
        raise EvidenceError("release evidence producer signature is invalid") from exc
    return deepcopy(dict(attestation))


def _verification_time_utc(value: datetime | str | None, label: str) -> datetime:
    verified_at = (
        datetime.now(timezone.utc)
        if value is None
        else parse_timestamp(value)
        if isinstance(value, str)
        else value
    )
    if (
        not isinstance(verified_at, datetime)
        or verified_at.tzinfo is None
        or verified_at.utcoffset() is None
    ):
        raise EvidenceError(f"{label} verification time must be timezone-aware")
    return verified_at.astimezone(timezone.utc)


def _validate_release_evidence_chronology(
    record: Mapping[str, Any],
    *,
    verification_time: datetime | str | None,
) -> datetime:
    invocation = record.get("invocation")
    attestation = record.get("producer_attestation")
    if not isinstance(invocation, Mapping) or not isinstance(attestation, Mapping):
        raise EvidenceError("release evidence chronology envelope is absent")
    started_at = parse_timestamp(invocation.get("started_at"))
    completed_at = parse_timestamp(invocation.get("completed_at"))
    signed_at = parse_timestamp(attestation.get("signed_at"))
    if completed_at < started_at or signed_at != completed_at:
        raise EvidenceError("release evidence invocation/attestation chronology is invalid")
    verified_at = _verification_time_utc(verification_time, "release evidence")
    if completed_at > verified_at + timedelta(
        seconds=_STANDARD_DECISION_FUTURE_SKEW_SECONDS
    ):
        raise EvidenceError("release evidence exceeds the bounded verifier clock skew")
    return completed_at


def _validate_nested_completion(
    nested_completed_at: datetime,
    outer_completed_at: datetime,
) -> None:
    if nested_completed_at > outer_completed_at:
        raise EvidenceError(
            "saturation audit nested physical completion follows outer completion"
        )


def _validate_human_review_chronology(
    reviewed_at: datetime,
    invocation_started_at: datetime,
    invocation_completed_at: datetime,
    attestation_signed_at: datetime,
) -> None:
    if not (
        invocation_started_at
        <= reviewed_at
        <= invocation_completed_at
        == attestation_signed_at
    ):
        raise EvidenceError(
            "HumanDocumentVerification review time is outside its signed invocation"
        )


def _derived_max_evidence_completion(times: Iterable[datetime]) -> str:
    rows = list(times)
    if not rows:
        raise EvidenceError("evidence completion set is empty")
    if any(
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
        for value in rows
    ):
        raise EvidenceError("evidence completion set contains a naive timestamp")
    return max(value.astimezone(timezone.utc) for value in rows).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def _validate_release_evidence_envelope(
    record: Mapping[str, Any],
    *,
    candidate: Mapping[str, Any],
    expected_tool_path: str,
    expected_operation: str,
    expected_role: str,
    expected_platform: str,
    expected_exit_code: int = 0,
    verification_time: datetime | str | None = None,
) -> None:
    producer = record.get("producer")
    if (
        not isinstance(producer, Mapping)
        or set(producer) != _RELEASE_EVIDENCE_PRODUCER_FIELDS
        or producer.get("tool_path") != expected_tool_path
        or producer.get("tool_version") != candidate.get("version")
        or producer.get("tool_sha256")
        != candidate.get("evidence_tool_digests", {}).get(expected_tool_path)
    ):
        raise EvidenceError("release evidence producer does not match the exact candidate")
    invocation = record.get("invocation")
    if (
        not isinstance(invocation, Mapping)
        or set(invocation) != _RELEASE_EVIDENCE_INVOCATION_FIELDS
        or invocation.get("operation") != expected_operation
        or invocation.get("exit_code") != expected_exit_code
        or not _valid_digest(invocation.get("arguments_digest"))
        or not _valid_digest(invocation.get("platform_binding_digest"))
    ):
        raise EvidenceError("release evidence invocation identity is invalid")
    _safe_id(invocation.get("invocation_id"))
    attestation = _validate_producer_attestation(
        record,
        candidate=candidate,
        expected_role=expected_role,
        expected_platform=expected_platform,
    )
    _validate_release_evidence_chronology(
        record,
        verification_time=verification_time,
    )
    supplied_digest = record.get("result_digest")
    unsigned = {key: deepcopy(value) for key, value in record.items() if key != "result_digest"}
    if not _valid_digest(supplied_digest) or supplied_digest != canonical_digest(unsigned):
        raise EvidenceError("release evidence result digest mismatch")


def _validate_release_evidence_schema(record_type: str, record: Mapping[str, Any]) -> None:
    global _RELEASE_SCHEMA_CACHE
    if _RELEASE_SCHEMA_CACHE is None:
        schema_path = bundle_root() / "core" / "contracts.schema.json"
        try:
            schema = parse_json_strict(schema_path.read_bytes())
        except (OSError, CanonicalError) as exc:
            raise EvidenceError("compiled release-evidence schema is unavailable") from exc
        if not isinstance(schema, dict) or not isinstance(schema.get("$defs"), dict):
            raise EvidenceError("compiled release-evidence schema is malformed")
        _RELEASE_SCHEMA_CACHE = schema
    if record_type not in {
        "PlatformVerificationResult",
        "SaturationEvidence",
        "SaturationAudit",
        "HumanDocumentVerification",
        "NoDegradationResult",
        "ProminPlatformNoDegradationMatrix",
        "StandardReleaseEvidenceManifest",
        "StandardReleaseTrustConfiguration",
    }:
        raise EvidenceError("release evidence has no exact compiled role schema")
    try:
        from jsonschema import Draft202012Validator

        validator = Draft202012Validator(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$ref": f"#/$defs/{record_type}",
                "$defs": _RELEASE_SCHEMA_CACHE["$defs"],
            }
        )
        error = next(validator.iter_errors(dict(record)), None)
    except ImportError as exc:
        raise EvidenceError("Draft 2020-12 evidence schema validator is unavailable") from exc
    if error is not None:
        location = "/".join(str(part) for part in error.absolute_path)
        raise EvidenceError(
            f"release evidence violates exact {record_type} schema at {location or '/'}: {error.message}"
        )


def _resolve_pointer(value: Any, pointer: str) -> Any:
    if not isinstance(pointer, str) or not pointer.startswith("/") or len(pointer) > 1024:
        raise EvidenceError("evidence predicate pointer is invalid")
    current = value
    for raw in pointer[1:].split("/"):
        key = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping) and key in current:
            current = current[key]
        elif isinstance(current, list) and key.isdigit() and int(key) < len(current):
            current = current[int(key)]
        else:
            raise EvidenceError(f"evidence predicate path is unresolved: {pointer}")
    return current


def validate_standard_release_candidate_binding(
    binding: Mapping[str, Any],
    *,
    expected: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(binding, Mapping) or set(binding) != _STANDARD_CANDIDATE_FIELDS:
        raise EvidenceError("invalid StandardReleaseCandidateBinding shape")
    if binding.get("record_type") != "StandardReleaseCandidateBinding":
        raise EvidenceError("candidate binding record type is invalid")
    if binding.get("standard_name") != "promin" or not _valid_semver(binding.get("version")):
        raise EvidenceError("candidate binding identity or SemVer is invalid")
    if (
        not isinstance(binding.get("archive_bytes"), int)
        or isinstance(binding.get("archive_bytes"), bool)
        or binding["archive_bytes"] <= 0
    ):
        raise EvidenceError("candidate binding archive size is invalid")
    digest_fields = _STANDARD_CANDIDATE_IDENTITY_FIELDS - {
        "record_type",
        "standard_name",
        "version",
        "archive_bytes",
        "evidence_tool_digests",
    }
    if any(not _valid_digest(binding.get(field)) for field in digest_fields):
        raise EvidenceError("candidate binding contains an invalid digest")
    evidence_tools = binding.get("evidence_tool_digests")
    if (
        not isinstance(evidence_tools, Mapping)
        or set(evidence_tools) != _EVIDENCE_TOOL_PATHS
        or any(not _valid_digest(value) for value in evidence_tools.values())
    ):
        raise EvidenceError("candidate binding evidence tool digests are incomplete")
    identity = {field: deepcopy(binding[field]) for field in _STANDARD_CANDIDATE_IDENTITY_FIELDS}
    expected_digest = canonical_digest(identity)
    if binding.get("candidate_binding_digest") != expected_digest:
        raise EvidenceError("candidate binding digest mismatch")
    if expected is not None:
        validated_expected = validate_standard_release_candidate_binding(expected)
        mismatched = sorted(
            field for field in _STANDARD_CANDIDATE_FIELDS if binding[field] != validated_expected[field]
        )
        if mismatched:
            raise EvidenceError("candidate binding differs from exact package: " + ", ".join(mismatched))
    return deepcopy(dict(binding))


def _valid_prefixed_digest(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("sha256:") and _valid_digest(value[7:])


def _validate_release_platform_binding(value: Any) -> dict[str, Any]:
    fields = {
        "binding_digest",
        "system",
        "release",
        "machine",
        "python_implementation",
        "python_version",
        "python_executable_sha256",
        "sqlite_version",
        "profile_key",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or value.get("system") not in {"darwin", "linux", "windows"}
        or value.get("python_implementation") != "CPython"
        or not isinstance(value.get("release"), str)
        or not value["release"]
        or not isinstance(value.get("machine"), str)
        or not value["machine"]
        or not isinstance(value.get("python_version"), str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["python_version"])
        is None
        or not isinstance(value.get("sqlite_version"), str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["sqlite_version"])
        is None
        or not _valid_prefixed_digest(value.get("python_executable_sha256"))
        or not _valid_prefixed_digest(value.get("binding_digest"))
    ):
        raise EvidenceError("release evidence platform binding shape is invalid")
    major, minor, _patch = value["python_version"].split(".")
    expected_profile = "-".join(
        (
            value["system"],
            value["machine"],
            value["python_implementation"].casefold(),
            f"{major}.{minor}",
        )
    )
    identity = {key: deepcopy(item) for key, item in value.items() if key != "binding_digest"}
    if (
        value.get("profile_key") != expected_profile
        or value.get("binding_digest") != "sha256:" + canonical_digest(identity)
    ):
        raise EvidenceError("release evidence platform binding identity is invalid")
    return deepcopy(dict(value))


def _validate_exact_artifact_binding(
    binding: Mapping[str, Any],
    *,
    candidate: Mapping[str, Any],
    allow_canonical_verification: bool = False,
) -> None:
    expected_fields = {
        "archive",
        "binding_digest",
        "candidate_binding_digest",
        "checksums_sha256",
        "core_bundle_digest",
        "package_manifest_sha256",
        "platform",
        "preset",
        "protocol_version",
        "record_type",
        "standard_candidate_binding",
        "tools",
    }
    if allow_canonical_verification:
        expected_fields.add("canonical_archive_verification")
    if (
        not isinstance(binding, Mapping)
        or set(binding) != expected_fields
        or binding.get("record_type") != "ExactArtifactBinding"
        or binding.get("protocol_version") != "promin-evidence-v1"
        or binding.get("candidate_binding_digest") != candidate["candidate_binding_digest"]
    ):
        raise EvidenceError("exact artifact binding shape or candidate identity is invalid")
    validate_standard_release_candidate_binding(
        binding.get("standard_candidate_binding", {}),
        expected=candidate,
    )
    archive = binding.get("archive")
    if (
        not isinstance(archive, Mapping)
        or set(archive)
        != {"bytes", "manifest_member_bytes_match", "member_count", "name", "sha256"}
        or archive.get("bytes") != candidate["archive_bytes"]
        or archive.get("sha256") != "sha256:" + candidate["archive_sha256"]
        or archive.get("manifest_member_bytes_match") is not True
        or archive.get("name") != "promin.zip"
        or not isinstance(archive.get("member_count"), int)
        or archive["member_count"] < 1
    ):
        raise EvidenceError("exact artifact archive binding is invalid")
    for field, candidate_field in (
        ("checksums_sha256", "checksums_digest"),
        ("core_bundle_digest", "core_bundle_digest"),
        ("package_manifest_sha256", "package_manifest_digest"),
    ):
        if binding.get(field) != "sha256:" + candidate[candidate_field]:
            raise EvidenceError(f"exact artifact binding drift: {field}")
    preset = binding.get("preset")
    if (
        not isinstance(preset, Mapping)
        or set(preset) != {"path", "sha256"}
        or preset.get("path") != "presets/semantic-standard.json"
        or preset.get("sha256") != "sha256:" + candidate["preset_digest"]
    ):
        raise EvidenceError("exact artifact preset binding is invalid")
    _validate_release_platform_binding(binding.get("platform"))
    tools = binding.get("tools")
    if not isinstance(tools, list) or not tools:
        raise EvidenceError("exact artifact tool closure is empty")
    tool_paths: set[str] = set()
    for tool in tools:
        if (
            not isinstance(tool, Mapping)
            or set(tool) != {"bytes", "path", "sha256", "version"}
            or tool.get("path") not in candidate["evidence_tool_digests"]
            or tool.get("sha256")
            != "sha256:" + candidate["evidence_tool_digests"][tool["path"]]
            or not isinstance(tool.get("bytes"), int)
            or tool["bytes"] < 1
            or not isinstance(tool.get("version"), str)
            or not tool["version"]
            or tool["path"] in tool_paths
        ):
            raise EvidenceError("exact artifact tool closure is invalid")
        tool_paths.add(tool["path"])
    required_tools = {
        "tools/promin_no_degradation.py",
        "tools/promin_package.py",
        "tools/promin_saturation.py",
        "tools/promin_saturation_audit.py",
        "tools/promin_validate.py",
    }
    if tool_paths != required_tools:
        raise EvidenceError("exact artifact tool closure is incomplete")
    unsigned = {key: deepcopy(value) for key, value in binding.items() if key != "binding_digest"}
    if binding.get("binding_digest") != "sha256:" + canonical_digest(unsigned):
        raise EvidenceError("exact artifact binding digest mismatch")


def _validate_no_degradation_wheelhouse_binding(value: Any) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"files", "file_count", "manifest_sha256"}
        or not isinstance(value.get("files"), list)
        or not value["files"]
        or len(value["files"]) > 256
        or value.get("file_count") != len(value["files"])
        or value.get("manifest_sha256") != canonical_digest(value["files"])
    ):
        raise EvidenceError("no-degradation wheelhouse binding is invalid")
    names: list[str] = []
    for row in value["files"]:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"path", "bytes", "sha256"}
            or not isinstance(row.get("path"), str)
            or not row["path"].casefold().endswith(".whl")
            or "/" in row["path"]
            or "\\" in row["path"]
            or not isinstance(row.get("bytes"), int)
            or isinstance(row.get("bytes"), bool)
            or row["bytes"] < 1
            or not _valid_digest(row.get("sha256"))
        ):
            raise EvidenceError("no-degradation wheelhouse file binding is invalid")
        names.append(row["path"])
    if names != sorted(set(names), key=lambda name: name.encode("utf-8")):
        raise EvidenceError("no-degradation wheelhouse paths are duplicate or non-canonical")
    return deepcopy(dict(value))


def _normalized_observed_runtime_path(
    value: Any,
    *,
    expected_platform: str,
    label: str,
) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise EvidenceError(f"no-degradation {label} path is invalid")
    portable = value.replace("\\", "/")
    if expected_platform == "windows":
        if re.fullmatch(r"[A-Za-z]:/.*", portable) is None:
            raise EvidenceError(f"no-degradation {label} path is not absolute")
    elif not portable.startswith("/") or "\\" in value:
        raise EvidenceError(f"no-degradation {label} path is not absolute")
    normalized = posixpath.normpath(portable)
    if normalized != portable.rstrip("/") or "/../" in portable + "/":
        raise EvidenceError(f"no-degradation {label} path is non-canonical")
    return normalized.casefold() if expected_platform == "windows" else normalized


def _validate_no_degradation_runtime_cross_binding(
    platform_binding: Any,
    installed_observation: Any,
    *,
    expected_platform: str,
    validation_tool_versions: Any,
) -> None:
    """Bind one exact controller/runtime profile to its clean venv and base interpreter."""

    platform_fields = {
        "binding_digest",
        "machine",
        "profile_key",
        "python_executable_sha256",
        "python_implementation",
        "python_version",
        "release",
        "sqlite_version",
        "system",
    }
    tool_fields = {
        "python",
        "python_implementation",
        "python_executable_sha256",
        "python_abi_tag",
        "system",
        "machine",
        "release",
        "sys_platform",
        "platform_tags",
        "profile_key",
        "jsonschema",
        "sqlite",
    }
    if (
        expected_platform not in {"linux", "windows"}
        or not isinstance(platform_binding, Mapping)
        or set(platform_binding) != platform_fields
        or not _valid_prefixed_digest(platform_binding.get("binding_digest"))
        or not _valid_prefixed_digest(platform_binding.get("python_executable_sha256"))
        or not all(
            isinstance(platform_binding.get(field), str) and platform_binding[field]
            for field in platform_fields - {"binding_digest", "python_executable_sha256"}
        )
        or not isinstance(validation_tool_versions, Mapping)
        or set(validation_tool_versions) != tool_fields
        or not all(
            isinstance(validation_tool_versions.get(field), str)
            and validation_tool_versions[field]
            for field in tool_fields - {"platform_tags"}
        )
        or not isinstance(validation_tool_versions.get("platform_tags"), list)
        or not validation_tool_versions["platform_tags"]
        or len(validation_tool_versions["platform_tags"]) > 64
        or any(
            not isinstance(tag, str) or not tag
            for tag in validation_tool_versions["platform_tags"]
        )
    ):
        raise EvidenceError("no-degradation controller runtime binding is invalid")
    if not isinstance(installed_observation, Mapping):
        raise EvidenceError("no-degradation installed runtime observation is invalid")
    observed_python = installed_observation.get("python")
    observed_platform = installed_observation.get("platform")
    if not isinstance(observed_python, Mapping) or not isinstance(observed_platform, Mapping):
        raise EvidenceError("no-degradation installed runtime identity is invalid")

    system = platform_binding["system"]
    machine = platform_binding["machine"]
    release = platform_binding["release"]
    python_version = platform_binding["python_version"]
    python_implementation = platform_binding["python_implementation"]
    if (
        system != expected_platform
        or observed_platform.get("system") != system
        or observed_platform.get("machine") != machine
        or observed_platform.get("release") != release
        or validation_tool_versions.get("system") != system
        or validation_tool_versions.get("machine") != machine
        or validation_tool_versions.get("release") != release
    ):
        raise EvidenceError("no-degradation controller/installed platform identity drift")

    expected_sys_platform = "win32" if expected_platform == "windows" else "linux"
    if (
        observed_platform.get("sys_platform") != expected_sys_platform
        or validation_tool_versions.get("sys_platform") != expected_sys_platform
    ):
        raise EvidenceError("no-degradation controller/installed sys.platform drift")
    if (
        python_implementation != "CPython"
        or observed_python.get("implementation") != "cpython"
        or validation_tool_versions.get("python_implementation") != "CPython"
    ):
        raise EvidenceError("no-degradation controller/installed implementation drift")
    if (
        observed_python.get("version") != python_version
        or validation_tool_versions.get("python") != python_version
    ):
        raise EvidenceError("no-degradation controller/installed Python version drift")

    version_match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)", python_version)
    if version_match is None:
        raise EvidenceError("no-degradation controller Python version is not full")
    major, minor, _ = version_match.groups()
    expected_profile = "-".join(
        (system, machine, python_implementation.casefold(), f"{major}.{minor}")
    )
    if (
        platform_binding.get("profile_key") != expected_profile
        or validation_tool_versions.get("profile_key") != expected_profile
    ):
        raise EvidenceError("no-degradation controller runtime profile derivation drift")

    abi_tag = observed_python.get("abi_tag")
    platform_tags = observed_platform.get("tags")
    if (
        abi_tag != validation_tool_versions.get("python_abi_tag")
        or platform_tags != validation_tool_versions.get("platform_tags")
    ):
        raise EvidenceError("no-degradation controller/installed ABI drift")

    sqlite_version = installed_observation.get("sqlite_version")
    if (
        not isinstance(sqlite_version, str)
        or sqlite_version != platform_binding.get("sqlite_version")
        or sqlite_version != validation_tool_versions.get("sqlite")
    ):
        raise EvidenceError("no-degradation controller/installed SQLite drift")

    executable = _normalized_observed_runtime_path(
        observed_python.get("executable"),
        expected_platform=expected_platform,
        label="venv executable",
    )
    prefix = _normalized_observed_runtime_path(
        observed_python.get("prefix"),
        expected_platform=expected_platform,
        label="venv prefix",
    )
    base_executable = _normalized_observed_runtime_path(
        observed_python.get("base_executable"),
        expected_platform=expected_platform,
        label="base executable",
    )
    base_prefix = _normalized_observed_runtime_path(
        observed_python.get("base_prefix"),
        expected_platform=expected_platform,
        label="base prefix",
    )
    if prefix == base_prefix or not executable.startswith(prefix + "/"):
        raise EvidenceError("no-degradation installed executable is outside the exact venv prefix")
    if not base_executable.startswith(base_prefix + "/"):
        raise EvidenceError("no-degradation base executable is outside the base prefix")
    if not _valid_digest(observed_python.get("executable_sha256")):
        raise EvidenceError("no-degradation installed executable identity is invalid")
    controller_sha256 = platform_binding["python_executable_sha256"][7:]
    if (
        not _valid_digest(observed_python.get("base_executable_sha256"))
        or observed_python.get("base_executable_sha256") != controller_sha256
        or validation_tool_versions.get("python_executable_sha256") != controller_sha256
    ):
        raise EvidenceError("no-degradation controller executable SHA-256 drift")


def _validate_no_degradation_installation(
    value: Any,
    *,
    candidate: Mapping[str, Any],
    expected_platform: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, Mapping)
        or set(value) != _NO_DEGRADATION_INSTALLATION_FIELDS
        or value.get("performed") is not True
        or value.get("verified") is not True
        or value.get("mode") != "offline-wheelhouse"
        or value.get("environment") != "clean-venv"
        or value.get("runtime_dependency_source") != "offline-wheelhouse"
        or value.get("build_dependency_source") != "offline-wheelhouse"
        or value.get("network_disabled") is not True
        or value.get("installation_performed") is not True
        or value.get("nested_venv_created") is not True
        or value.get("dependency_closure_check") != "pass"
        or value.get("test_dependencies_installed") is not True
        or value.get("version") != candidate["version"]
        or value.get("python_distribution_version") != candidate["version"]
        or value.get("product_acceptance_pass") is not False
    ):
        raise EvidenceError("no-degradation did not use the required clean offline installation")
    wheelhouse = _validate_no_degradation_wheelhouse_binding(
        value.get("wheelhouse_binding")
    )
    wheelhouse_lock = value.get("wheelhouse_lock")
    if (
        not isinstance(wheelhouse_lock, Mapping)
        or set(wheelhouse_lock)
        != {
            "source_binding",
            "locked_copy_binding",
            "source_unchanged",
            "copy_verified",
        }
        or wheelhouse_lock.get("source_unchanged") is not True
        or wheelhouse_lock.get("copy_verified") is not True
    ):
        raise EvidenceError("no-degradation wheelhouse lock is incomplete")
    source_binding = _validate_no_degradation_wheelhouse_binding(
        wheelhouse_lock.get("source_binding")
    )
    copy_binding = _validate_no_degradation_wheelhouse_binding(
        wheelhouse_lock.get("locked_copy_binding")
    )
    if source_binding != copy_binding or source_binding != wheelhouse:
        raise EvidenceError("no-degradation wheelhouse copy differs from the pinned source")
    observed = _validate_installed_environment_observation(
        value.get("installed_environment_observation"),
        candidate=candidate,
        expected_platform=expected_platform,
    )
    if "pytest" not in {
        row.get("name")
        for row in observed["transitive_distributions"]
        if isinstance(row, Mapping)
    }:
        raise EvidenceError("no-degradation installed environment omits the test dependency")
    origin = value.get("origin_assertion")
    if (
        not isinstance(origin, Mapping)
        or set(origin)
        != {
            "isolated_mode",
            "safe_path",
            "module_file",
            "module_sha256",
            "site_packages",
            "inside_site_packages",
            "outside_install_source",
            "source_absent_from_sys_path",
            "sys_path_digest",
        }
        or origin.get("isolated_mode") is not True
        or origin.get("safe_path") is not True
        or origin.get("inside_site_packages") is not True
        or origin.get("outside_install_source") is not True
        or origin.get("source_absent_from_sys_path") is not True
        or origin.get("module_file") != observed["promin"]["module_file"]
        or origin.get("module_sha256") != observed["promin"]["module_sha256"]
        or origin.get("site_packages") != observed["site_packages"]
        or not _valid_digest(origin.get("sys_path_digest"))
    ):
        raise EvidenceError("no-degradation installed import-origin assertion is invalid")
    interpreter = value.get("interpreter")
    platform_value = value.get("platform")
    expected_os_name = "nt" if expected_platform == "windows" else "posix"
    if (
        not isinstance(interpreter, Mapping)
        or set(interpreter) != {"executable", "nested_venv_created"}
        or interpreter.get("nested_venv_created") is not True
        or interpreter.get("executable") != observed["python"]["executable"]
        or not isinstance(platform_value, Mapping)
        or set(platform_value) != {"os_name", "sys_platform", "python"}
        or platform_value.get("os_name") != expected_os_name
        or platform_value.get("sys_platform") != observed["platform"]["sys_platform"]
        or platform_value.get("python") != observed["python"]["version"]
    ):
        raise EvidenceError("no-degradation installed interpreter/platform identity is invalid")
    console = value.get("console_script")
    if (
        not isinstance(console, Mapping)
        or set(console) != _PLATFORM_CONSOLE_FIELDS
        or console.get("present") is not True
        or console.get("declared") is not True
        or console.get("installed_wrapper_checked") is not True
        or console.get("source_module_invoked") is not False
        or console.get("path") != observed["console_wrapper"]["path"]
        or console.get("sha256") != observed["console_wrapper"]["sha256"]
        or console.get("size_bytes") != observed["console_wrapper"]["bytes"]
        or (expected_platform == "linux" and console.get("posix_execute_bits") is not True)
        or (expected_platform == "windows" and console.get("posix_execute_bits") is not None)
    ):
        raise EvidenceError("no-degradation installed command identity is invalid")
    commands = value.get("invocations")
    expected_commands = [
        "--help",
        "init --help",
        "doctor --help",
        "status --help",
        "next --help",
        "validate --help",
        "continue --help",
    ]
    if (
        not isinstance(commands, list)
        or [row.get("command") for row in commands if isinstance(row, Mapping)]
        != expected_commands
        or any(
            not isinstance(row, Mapping)
            or set(row) != _PLATFORM_COMMAND_FIELDS
            or row.get("returncode") != 0
            or not all(
                _valid_digest(row.get(field))
                for field in ("argv_digest", "stdout_sha256", "stderr_sha256")
            )
            for row in commands
        )
    ):
        raise EvidenceError("no-degradation installed command probes are incomplete")
    if (
        not isinstance(value.get("declared_runtime_dependencies"), list)
        or not value["declared_runtime_dependencies"]
        or not isinstance(value.get("declared_build_dependencies"), list)
        or not value["declared_build_dependencies"]
        or not isinstance(value.get("declared_python_requirement"), str)
        or not value["declared_python_requirement"]
        or not isinstance(value.get("resolved_runtime_dependencies"), Mapping)
        or set(value["resolved_runtime_dependencies"])
        != {"cryptography", "jsonschema", "pypdf"}
    ):
        raise EvidenceError("no-degradation declared dependency closure is incomplete")
    pip_report = value.get("pip_report")
    if (
        not isinstance(pip_report, Mapping)
        or set(pip_report) != {"reports", "report_count", "artifact_digest"}
        or not isinstance(pip_report.get("reports"), list)
        or pip_report.get("report_count") != 2
        or len(pip_report["reports"]) != 2
        or pip_report.get("artifact_digest") != canonical_digest(pip_report["reports"])
    ):
        raise EvidenceError("no-degradation pip report binding is invalid")
    roles: list[str] = []
    for report in pip_report["reports"]:
        if (
            not isinstance(report, Mapping)
            or set(report)
            != {
                "role",
                "sha256",
                "bytes",
                "pip_version",
                "install_count",
                "artifacts",
                "artifact_digest",
            }
            or not _valid_digest(report.get("sha256"))
            or not isinstance(report.get("bytes"), int)
            or isinstance(report.get("bytes"), bool)
            or not (1 <= report["bytes"] <= 16 * 1024 * 1024)
            or not isinstance(report.get("artifacts"), list)
            or not report["artifacts"]
            or report.get("install_count") != len(report["artifacts"])
            or report.get("artifact_digest") != canonical_digest(report["artifacts"])
        ):
            raise EvidenceError("no-degradation pip report row is invalid")
        roles.append(report["role"])
    if roles != ["build-requirements", "candidate-install"]:
        raise EvidenceError("no-degradation pip report roles are incomplete")
    return deepcopy(dict(value))


def _validate_no_degradation_raw_test_artifacts(
    tests: Mapping[str, Any],
) -> tuple[dict[str, bytes], dict[str, int]]:
    artifacts = tests.get("raw_artifacts")
    expected_roles = ["required-junit", "required-stdout", "required-stderr"]
    if (
        not isinstance(artifacts, list)
        or [row.get("role") for row in artifacts if isinstance(row, Mapping)]
        != expected_roles
        or tests.get("raw_artifact_manifest_digest") != canonical_digest(artifacts)
    ):
        raise EvidenceError("no-degradation raw test-artifact manifest is invalid")
    payloads: dict[str, bytes] = {}
    expected_media = {
        "required-junit": "application/xml",
        "required-stdout": "text/plain; charset=utf-8",
        "required-stderr": "text/plain; charset=utf-8",
    }
    for row in artifacts:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"role", "media_type", "bytes", "sha256", "encoding", "data"}
            or row.get("media_type") != expected_media.get(row.get("role"))
            or row.get("encoding") != "base64"
            or not isinstance(row.get("bytes"), int)
            or isinstance(row.get("bytes"), bool)
            or not (0 <= row["bytes"] <= 16 * 1024 * 1024)
            or not _valid_digest(row.get("sha256"))
            or not isinstance(row.get("data"), str)
        ):
            raise EvidenceError("no-degradation raw test artifact is invalid")
        try:
            payload = base64.b64decode(row["data"], validate=True)
        except (ValueError, TypeError) as exc:
            raise EvidenceError("no-degradation raw test artifact is not strict base64") from exc
        if len(payload) != row["bytes"] or hashlib.sha256(payload).hexdigest() != row["sha256"]:
            raise EvidenceError("no-degradation raw test artifact digest mismatch")
        payloads[row["role"]] = payload
    try:
        junit_root = ElementTree.fromstring(payloads["required-junit"])
    except ElementTree.ParseError as exc:
        raise EvidenceError("no-degradation raw JUnit artifact is malformed") from exc
    suites = [junit_root] if junit_root.tag == "testsuite" else list(junit_root.findall("testsuite"))
    if not suites:
        raise EvidenceError("no-degradation raw JUnit artifact has no suites")
    try:
        counts = {
            field: sum(int(suite.attrib.get(field, "0")) for suite in suites)
            for field in ("tests", "failures", "errors", "skipped")
        }
    except ValueError as exc:
        raise EvidenceError("no-degradation raw JUnit counts are invalid") from exc
    return payloads, counts


def validate_no_degradation_result(
    verification: Mapping[str, Any],
    *,
    candidate_binding: Mapping[str, Any],
    expected_platform: str,
) -> dict[str, Any]:
    """Recompute a bounded no-degradation result from its execution details."""

    candidate = validate_standard_release_candidate_binding(candidate_binding)
    if (
        expected_platform not in {"linux", "windows"}
        or not isinstance(verification, Mapping)
        or set(verification) != _NO_DEGRADATION_FIELDS
        or verification.get("record_type") != "NoDegradationResult"
        or verification.get("status") != "pass"
        or verification.get("platform") != expected_platform
        or verification.get("candidate_binding_digest")
        != candidate["candidate_binding_digest"]
        or verification.get("source") != "live_files_and_executable_tests"
        or verification.get("install_mode") != "offline-wheelhouse"
        or verification.get("no_degradation") is not True
        or verification.get("passed") is not True
        or verification.get("artifact_binding_unchanged") is not True
        or verification.get("pass_credit") is not False
        or verification.get("acceptance_pass") is not False
        or verification.get("product_acceptance_pass") is not False
        or verification.get("standard_distribution_gate_pass") is not False
        or verification.get("product_public_approval") != "not_approved"
    ):
        raise EvidenceError("NoDegradationResult shape or candidate binding is invalid")
    binding = verification.get("artifact_binding")
    _validate_exact_artifact_binding(
        binding,
        candidate=candidate,
        allow_canonical_verification=True,
    )
    _validate_release_evidence_envelope(
        verification,
        candidate=candidate,
        expected_tool_path="tools/promin_no_degradation.py",
        expected_operation="no-degradation",
        expected_role=f"{expected_platform}-no-degradation",
        expected_platform=expected_platform,
    )
    if verification["invocation"]["platform_binding_digest"] != binding["platform"]["binding_digest"][7:]:
        raise EvidenceError("no-degradation invocation binds another platform")
    raw_tests = verification.get("tests")
    raw_installation = (
        raw_tests.get("installed_environment") if isinstance(raw_tests, Mapping) else None
    )
    raw_observation = (
        raw_installation.get("installed_environment_observation")
        if isinstance(raw_installation, Mapping)
        else None
    )
    validation = verification.get("validation")
    validation_checks = validation.get("checks") if isinstance(validation, Mapping) else None
    validation_identity = (
        validation_checks.get("identity_binding")
        if isinstance(validation_checks, Mapping)
        else None
    )
    validation_tool_versions = (
        validation_identity.get("tool_versions")
        if isinstance(validation_identity, Mapping)
        else None
    )
    _validate_no_degradation_runtime_cross_binding(
        binding.get("platform"),
        raw_observation,
        expected_platform=expected_platform,
        validation_tool_versions=validation_tool_versions,
    )
    manifest = verification.get("test_manifest")
    if (
        not isinstance(manifest, Mapping)
        or set(manifest) != {"files", "file_count", "digest"}
        or not isinstance(manifest.get("files"), list)
        or manifest.get("file_count") != len(manifest["files"])
        or manifest.get("digest") != canonical_digest(manifest["files"])
        or manifest.get("digest") != candidate["test_manifest_digest"]
    ):
        raise EvidenceError("no-degradation test manifest differs from the exact candidate")
    predicates = verification.get("required_predicates")
    if (
        not isinstance(predicates, Mapping)
        or predicates.get("complete") is not True
        or predicates.get("missing_policies") != []
        or predicates.get("missing_acceptance_predicates") != []
        or predicates.get("missing_mutation_families") != []
    ):
        raise EvidenceError("no-degradation required predicate closure is incomplete")
    if (
        not isinstance(validation, Mapping)
        or validation.get("record_type") != "ProminValidationResult"
        or validation.get("valid") is not True
        or validation.get("errors") != []
    ):
        raise EvidenceError("no-degradation package validation did not pass")
    tests = verification.get("tests")
    counts = tests.get("required_counts") if isinstance(tests, Mapping) else None
    if (
        not isinstance(tests, Mapping)
        or set(tests)
        != {
            "ran",
            "command",
            "returncode",
            "stdout",
            "stderr",
            "timed_out",
            "timeout_seconds",
            "elapsed_ms",
            "process_group_cleanup",
            "required_counts",
            "required_skips_fail_closed",
            "optional_platform_tests_excluded",
            "marker_expression",
            "selection_expression",
            "junit_sha256",
            "raw_artifacts",
            "raw_artifact_manifest_digest",
            "installed_environment",
            "source_tree_shadowing_disabled",
            "passed",
            "scale_environment_configured",
        }
        or tests.get("ran") is not True
        or tests.get("returncode") != 0
        or tests.get("passed") is not True
        or tests.get("timed_out") is not False
        or tests.get("required_skips_fail_closed") is not True
        or tests.get("source_tree_shadowing_disabled") is not True
        or not _valid_digest(tests.get("junit_sha256"))
        or not isinstance(counts, Mapping)
        or counts.get("tests", 0) < 1
        or any(counts.get(field) != 0 for field in ("failures", "errors", "skipped"))
    ):
        raise EvidenceError("no-degradation required test execution is not creditable")
    installed = _validate_no_degradation_installation(
        tests.get("installed_environment"),
        candidate=candidate,
        expected_platform=expected_platform,
    )
    command = tests.get("command")
    if (
        not isinstance(command, list)
        or len(command) < 10
        or command[0] != installed["interpreter"]["executable"]
        or command[1:4] != ["-I", "-B", "-m"]
        or "pytest" not in command
        or "--import-mode=importlib" not in command
        or "-m" not in command[4:]
        or ["-m", "not scale"]
        != command[command.index("-m", 4) : command.index("-m", 4) + 2]
    ):
        raise EvidenceError("no-degradation required tests did not use isolated installed pytest")
    payloads, raw_counts = _validate_no_degradation_raw_test_artifacts(tests)
    if (
        dict(counts) != raw_counts
        or tests["junit_sha256"]
        != hashlib.sha256(payloads["required-junit"]).hexdigest()
    ):
        raise EvidenceError("no-degradation JUnit summary differs from raw bytes")
    for stream_name in ("stdout", "stderr"):
        stream = tests.get(stream_name)
        if (
            not isinstance(stream, Mapping)
            or set(stream) != {"text", "bytes", "sha256", "truncated", "selection"}
            or not _valid_digest(stream.get("sha256"))
            or not isinstance(stream.get("bytes"), int)
            or stream["bytes"] < 0
            or stream.get("selection") not in {"complete", "tail"}
            or stream.get("truncated") != (stream["selection"] == "tail")
        ):
            raise EvidenceError("no-degradation bounded output capture is invalid")
        payload = payloads[f"required-{stream_name}"]
        selected = payload[-64 * 1024 :] if len(payload) > 64 * 1024 else payload
        if (
            stream["bytes"] != len(payload)
            or stream["sha256"] != hashlib.sha256(payload).hexdigest()
            or stream["truncated"] != (len(payload) > 64 * 1024)
            or stream["selection"]
            != ("tail" if len(payload) > 64 * 1024 else "complete")
            or stream["text"] != selected.decode("utf-8", errors="replace")
        ):
            raise EvidenceError("no-degradation bounded output differs from raw bytes")
    phases = verification.get("phases")
    if (
        not isinstance(phases, list)
        or [row.get("phase") for row in phases if isinstance(row, Mapping)]
        != ["validation", "required-tests"]
        or any(
            row.get("status") != "pass"
            or row.get("returncode") != 0
            or row.get("process_group_cleanup") != "normal-exit"
            or not isinstance(row.get("elapsed_ms"), int)
            or row["elapsed_ms"] < 0
            or not isinstance(row.get("timeout_seconds"), int)
            or row["timeout_seconds"] < 1
            for row in phases
        )
    ):
        raise EvidenceError("no-degradation progress/timeout records are incomplete")
    budget = verification.get("execution_budget")
    if (
        not isinstance(budget, Mapping)
        or set(budget)
        != {
            "total_timeout_seconds",
            "validation_timeout_seconds",
            "test_timeout_seconds",
            "elapsed_ms",
            "started_at",
            "completed_at",
        }
        or budget.get("elapsed_ms", 0) < 0
        or budget.get("elapsed_ms", 0) > budget.get("total_timeout_seconds", 0) * 1000
        or budget.get("validation_timeout_seconds", 0)
        + budget.get("test_timeout_seconds", 0)
        > budget.get("total_timeout_seconds", 0)
    ):
        raise EvidenceError("no-degradation total execution budget is invalid")
    parse_timestamp(budget["started_at"])
    parse_timestamp(budget["completed_at"])
    return deepcopy(dict(verification))


def _parse_raw_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = parse_json_strict(payload)
    except CanonicalError as exc:
        raise EvidenceError(f"{label} is not canonical JSON") from exc
    if not isinstance(value, dict) or canonical_bytes(value) != payload:
        raise EvidenceError(f"{label} must be one canonical JSON object")
    return value


def _parse_raw_jsonl(
    payload: bytes,
    label: str,
    *,
    max_records: int,
    max_line_bytes: int = 1024 * 1024,
) -> list[dict[str, Any]]:
    if not payload or not payload.endswith(b"\n"):
        raise EvidenceError(f"{label} must be non-empty newline-terminated JSONL")
    rows: list[dict[str, Any]] = []
    for line in payload.splitlines(keepends=True):
        if len(line) > max_line_bytes or len(rows) >= max_records:
            raise EvidenceError(f"{label} exceeds its row or line bound")
        try:
            value = parse_json_strict(line)
        except CanonicalError as exc:
            raise EvidenceError(f"{label} contains invalid canonical JSONL") from exc
        if not isinstance(value, dict) or canonical_bytes(value) != line:
            raise EvidenceError(f"{label} contains a non-canonical object row")
        rows.append(value)
    return rows


def _nearest_rank(values: list[float], fraction: float) -> float:
    if not values:
        raise EvidenceError("raw latency collection is empty")
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * fraction) - 1)
    return round(float(ordered[index]), 6)


def _validate_raw_page_trace(value: Any) -> dict[str, Any]:
    fields = {
        "pages",
        "continuation_pages",
        "first_truncated",
        "maximum_token_bytes",
        "selected_closure_complete",
        "atoms",
        "atoms_count",
        "atoms_digest",
        "page_digests",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EvidenceError("raw query page trace shape is invalid")
    atoms = value.get("atoms")
    page_digests = value.get("page_digests")
    if (
        not isinstance(atoms, list)
        or atoms != sorted(set(atoms))
        or any(not isinstance(item, str) or not item for item in atoms)
        or value.get("atoms_count") != len(atoms)
        or value.get("atoms_digest") != canonical_digest(atoms)
        or not isinstance(page_digests, list)
        or not page_digests
        or any(not _valid_digest(item) for item in page_digests)
        or value.get("pages") != len(page_digests)
        or not isinstance(value.get("continuation_pages"), int)
        or isinstance(value.get("continuation_pages"), bool)
        or value["continuation_pages"] < 0
        or value["continuation_pages"] != value["pages"] - 1
        or not isinstance(value.get("maximum_token_bytes"), int)
        or isinstance(value.get("maximum_token_bytes"), bool)
        or value["maximum_token_bytes"] < 0
        or not isinstance(value.get("first_truncated"), bool)
        or value.get("selected_closure_complete") is not True
        or (value["first_truncated"] is False and value["continuation_pages"] != 0)
    ):
        raise EvidenceError("raw query page trace cannot be recomputed")
    return deepcopy(dict(value))


def _first_raw_entity_id(page: Mapping[str, Any]) -> str | None:
    entities = page.get("entities")
    if not isinstance(entities, list) or not entities:
        return None
    first = entities[0]
    return first.get("id") if isinstance(first, Mapping) and isinstance(first.get("id"), str) else None


def _raw_page_contains_artifact(page: Mapping[str, Any]) -> bool:
    entities = page.get("entities")
    return isinstance(entities, list) and any(
        isinstance(entity, Mapping)
        and isinstance(entity.get("id"), str)
        and entity["id"].startswith("artifact:file:")
        for entity in entities
    )


def _recompute_raw_query_result(
    row: Mapping[str, Any],
    *,
    expected_index: int,
    top_k: int,
) -> dict[str, Any]:
    fields = {
        "record_type",
        "index",
        "query_class",
        "query",
        "depth",
        "elapsed_ms",
        "first_page",
        "first_page_digest",
        "class_result_verified",
        "reference",
        "forced",
    }
    if (
        set(row) != fields
        or row.get("record_type") != "SaturationQueryObservation"
        or row.get("index") != expected_index
        or not isinstance(row.get("query_class"), str)
        or not isinstance(row.get("query"), str)
        or not isinstance(row.get("depth"), int)
        or isinstance(row.get("depth"), bool)
        or row["depth"] < 1
        or row["depth"] > 12
        or not isinstance(row.get("elapsed_ms"), (int, float))
        or isinstance(row.get("elapsed_ms"), bool)
        or row["elapsed_ms"] < 0
        or not isinstance(row.get("first_page"), Mapping)
        or row.get("first_page_digest") != canonical_digest(row["first_page"])
    ):
        raise EvidenceError("raw query observation shape or identity is invalid")
    page = row["first_page"]
    query_class = row["query_class"]
    if query_class == "broad":
        class_verified = (
            page.get("refinement_required") is True
            and isinstance(page.get("refinement_hints"), list)
            and 0 < len(page["refinement_hints"]) <= 4
            and page.get("unselected_matches_traversable") is False
        )
    elif query_class == "content-high-cardinality":
        class_verified = (
            page.get("refinement_required") is True
            and isinstance(page.get("selected_seed_count"), int)
            and not isinstance(page.get("selected_seed_count"), bool)
            and 0 < page["selected_seed_count"] <= top_k
            and page.get("unselected_matches_traversable") is False
            and _raw_page_contains_artifact(page)
        )
    elif query_class in {"content-probe", "hostile-content"}:
        class_verified = _raw_page_contains_artifact(page)
    elif query_class == "miss":
        class_verified = (
            page.get("entities") == []
            and page.get("relations") == []
            and page.get("evidence", page.get("evidence_digests", [])) == []
            and page.get("selected_seed_count") == 0
            and page.get("refinement_required") is False
            and page.get("truncated") is False
            and page.get("silent_truncation") is False
        )
    elif query_class == "hostile-exact":
        class_verified = _first_raw_entity_id(page) == "task:saturation:needle"
    elif query_class in {"exact-artifact", "exact-semantic"}:
        class_verified = _first_raw_entity_id(page) == row["query"]
    elif query_class == "forced-continuation":
        class_verified = True
    else:
        raise EvidenceError("raw query observation has an unknown query class")
    if row.get("class_result_verified") is not class_verified:
        raise EvidenceError("raw query semantic result flag cannot be recomputed")
    reference = _validate_raw_page_trace(row.get("reference"))
    forced_value = row.get("forced")
    forced: dict[str, Any] | None = None
    if forced_value is not None:
        if not isinstance(forced_value, Mapping) or "union_matches_reference" not in forced_value:
            raise EvidenceError("raw forced query trace shape is invalid")
        forced_identity = {
            key: deepcopy(value)
            for key, value in forced_value.items()
            if key != "union_matches_reference"
        }
        forced = _validate_raw_page_trace(forced_identity)
        union_matches = forced["atoms"] == reference["atoms"]
        if forced_value.get("union_matches_reference") is not union_matches or not union_matches:
            raise EvidenceError("raw forced continuation union differs from the reference")
    return {
        "query_class": query_class,
        "depth": row["depth"],
        "elapsed_ms": float(row["elapsed_ms"]),
        "class_verified": class_verified,
        "reference": reference,
        "forced": forced,
    }


def _validate_saturation_operation_metrics(
    payload: bytes,
    *,
    records: int,
    verification: Mapping[str, Any],
) -> dict[str, Any]:
    operation = _parse_raw_json(payload, "saturation operation metrics")
    if records != 1:
        raise EvidenceError("operation metrics must contain exactly one record")
    operation_fields = {
        "record_type",
        "evidence_class",
        "product_acceptance_credit",
        "status",
        "process_exit_code",
        "invocation_exit_code",
        "physical",
        "inventory",
        "projection",
        "search",
        "resources",
        "performance",
        "contract_predicates",
        "semantic_ingestion",
    }
    if (
        operation.get("status") != verification.get("status")
        or operation.get("process_exit_code") != operation.get("invocation_exit_code")
        or set(operation) != operation_fields
        or operation.get("record_type") != "SaturationOperationMetrics"
        or operation.get("evidence_class") != "harness_generated"
        or operation.get("product_acceptance_credit") is not False
    ):
        raise EvidenceError("saturation operation metrics shape is invalid")
    for field in (
        "physical",
        "inventory",
        "projection",
        "search",
        "resources",
        "performance",
        "contract_predicates",
    ):
        if operation[field] != verification.get(field):
            raise EvidenceError(
                f"saturation summary differs from raw operation metrics: {field}"
            )

    semantic_ingestion = operation["semantic_ingestion"]
    semantic_fields = {
        "record_type",
        "elapsed_seconds",
        "commit_count",
        "changed_records",
        "physical_payload_bytes",
        "bytes_per_changed_record",
        "p95_ms",
        "p99_ms",
        "checkpoint_count",
        "checkpoint_writes",
        "observations",
        "result_digest",
    }
    if (
        not isinstance(semantic_ingestion, Mapping)
        or set(semantic_ingestion) != semantic_fields
        or semantic_ingestion.get("record_type") != "SemanticIngestionMetrics"
        or not isinstance(semantic_ingestion.get("observations"), list)
        or not 1 <= len(semantic_ingestion["observations"]) <= 10_000
    ):
        raise EvidenceError("semantic ingestion raw metrics shape is invalid")
    commit_durations: list[float] = []
    changed_record_total = 0
    physical_payload_total = 0
    checkpoint_writes = 0
    checkpoint_count: int | None = None
    command_ids: set[str] = set()
    batch_digests: set[str] = set()
    observation_fields = {
        "sequence",
        "phase",
        "command_id",
        "batch_digest",
        "duration_ms",
        "changed_records",
        "physical_payload_bytes",
        "bytes_per_changed_record",
        "checkpoint_written",
        "checkpoint_count",
        "checkpoint_bytes",
        "checkpoint_tail_batches",
        "checkpoint_tail_bytes",
    }
    for index, observation in enumerate(semantic_ingestion["observations"], start=1):
        if (
            not isinstance(observation, Mapping)
            or set(observation) != observation_fields
            or observation.get("sequence") != index
            or observation.get("phase")
            not in {"semantic-corpus", "physical-relation-corpus"}
            or not _safe_id(observation.get("command_id"))
            or not _valid_digest(observation.get("batch_digest"))
            or not isinstance(observation.get("duration_ms"), (int, float))
            or isinstance(observation.get("duration_ms"), bool)
            or observation["duration_ms"] < 0
            or not isinstance(observation.get("changed_records"), int)
            or isinstance(observation.get("changed_records"), bool)
            or observation["changed_records"] < 1
            or not isinstance(observation.get("physical_payload_bytes"), int)
            or isinstance(observation.get("physical_payload_bytes"), bool)
            or observation["physical_payload_bytes"] < 1
            or not isinstance(
                observation.get("bytes_per_changed_record"), (int, float)
            )
            or isinstance(observation.get("bytes_per_changed_record"), bool)
            or observation["bytes_per_changed_record"]
            != round(
                observation["physical_payload_bytes"]
                / observation["changed_records"],
                6,
            )
            or not isinstance(observation.get("checkpoint_written"), bool)
            or not isinstance(observation.get("checkpoint_count"), int)
            or isinstance(observation.get("checkpoint_count"), bool)
            or observation["checkpoint_count"] < 1
            or not isinstance(observation.get("checkpoint_bytes"), int)
            or isinstance(observation.get("checkpoint_bytes"), bool)
            or observation["checkpoint_bytes"] < 0
            or (
                observation["checkpoint_written"]
                and observation["checkpoint_bytes"] < 1
            )
            or (
                not observation["checkpoint_written"]
                and observation["checkpoint_bytes"] != 0
            )
            or (
                checkpoint_count is None
                and observation["checkpoint_count"] != 1
            )
            or (
                checkpoint_count is not None
                and observation["checkpoint_written"]
                and observation["checkpoint_count"]
                != checkpoint_count + 1
            )
            or (
                checkpoint_count is not None
                and not observation["checkpoint_written"]
                and observation["checkpoint_count"] != checkpoint_count
            )
            or (
                observation["checkpoint_written"]
                and (
                    observation["checkpoint_tail_batches"] != 0
                    or observation["checkpoint_tail_bytes"] != 0
                )
            )
            or not isinstance(observation.get("checkpoint_tail_batches"), int)
            or isinstance(observation.get("checkpoint_tail_batches"), bool)
            or observation["checkpoint_tail_batches"] < 0
            or not isinstance(observation.get("checkpoint_tail_bytes"), int)
            or isinstance(observation.get("checkpoint_tail_bytes"), bool)
            or observation["checkpoint_tail_bytes"] < 0
            or observation["command_id"] in command_ids
            or observation["batch_digest"] in batch_digests
        ):
            raise EvidenceError("semantic ingestion observation is invalid")
        command_ids.add(observation["command_id"])
        batch_digests.add(observation["batch_digest"])
        commit_durations.append(float(observation["duration_ms"]))
        changed_record_total += observation["changed_records"]
        physical_payload_total += observation["physical_payload_bytes"]
        checkpoint_writes += int(observation["checkpoint_written"])
        checkpoint_count = observation["checkpoint_count"]
    expected_semantic_ingestion = {
        "record_type": "SemanticIngestionMetrics",
        "elapsed_seconds": semantic_ingestion["elapsed_seconds"],
        "commit_count": len(commit_durations),
        "changed_records": changed_record_total,
        "physical_payload_bytes": physical_payload_total,
        "bytes_per_changed_record": round(
            physical_payload_total / changed_record_total, 6
        ),
        "p95_ms": _nearest_rank(commit_durations, 0.95),
        "p99_ms": _nearest_rank(commit_durations, 0.99),
        "checkpoint_count": checkpoint_count,
        "checkpoint_writes": checkpoint_writes,
        "observations": semantic_ingestion["observations"],
        "result_digest": canonical_digest(semantic_ingestion["observations"]),
    }
    elapsed_seconds = semantic_ingestion.get("elapsed_seconds")
    if (
        not isinstance(elapsed_seconds, (int, float))
        or isinstance(elapsed_seconds, bool)
        or elapsed_seconds <= 0
        or elapsed_seconds + 0.001 < sum(commit_durations) / 1000.0
        or checkpoint_count is None
        or checkpoint_count < 1
        or dict(semantic_ingestion) != expected_semantic_ingestion
    ):
        raise EvidenceError("semantic ingestion summary cannot be recomputed")
    return operation


def _validate_saturation_raw_artifacts(
    verification: Mapping[str, Any],
    *,
    source_path: Path,
    evidence_root: Path,
) -> dict[str, Any]:
    manifest = verification.get("raw_artifact_manifest")
    manifest_fields = {
        "record_type",
        "path_scope",
        "evidence_class",
        "product_acceptance_credit",
        "artifacts",
        "artifact_count",
        "inventory_stream_digest",
        "inventory_identity_digest",
        "manifest_digest",
    }
    if (
        not isinstance(manifest, Mapping)
        or set(manifest) != manifest_fields
        or manifest.get("record_type") != "SaturationRawArtifactManifest"
        or manifest.get("path_scope") != "saturation-result-directory"
        or manifest.get("evidence_class") != "harness_generated"
        or manifest.get("product_acceptance_credit") is not False
        or not _valid_digest(manifest.get("inventory_stream_digest"))
        or not _valid_digest(manifest.get("inventory_identity_digest"))
    ):
        raise EvidenceError("saturation raw artifact manifest shape is invalid")
    manifest_identity = {key: deepcopy(value) for key, value in manifest.items() if key != "manifest_digest"}
    if manifest.get("manifest_digest") != canonical_digest(manifest_identity):
        raise EvidenceError("saturation raw artifact manifest digest mismatch")
    artifacts = manifest.get("artifacts")
    expected_roles = {
        "inventory-stream",
        "query-results",
        "process-samples",
        "continuation-state-manifest",
        "phase-log",
        "operation-metrics",
    }
    if (
        not isinstance(artifacts, list)
        or len(artifacts) != len(expected_roles)
        or manifest.get("artifact_count") != len(artifacts)
    ):
        raise EvidenceError("saturation raw artifact set is incomplete")
    source_directory = Path(os.path.abspath(source_path)).parent
    root = _require_external_root(Path(evidence_root), None)
    try:
        common = Path(os.path.commonpath((str(source_directory), str(root))))
    except ValueError as exc:
        raise EvidenceError("saturation raw artifacts are on another filesystem root") from exc
    if os.path.normcase(str(common)) != os.path.normcase(str(root)):
        raise EvidenceError("saturation raw artifact directory escapes the evidence root")
    resolved: dict[str, tuple[Mapping[str, Any], StableExternalBytes]] = {}
    paths: set[str] = set()
    for artifact in artifacts:
        if (
            not isinstance(artifact, Mapping)
            or set(artifact) != {"role", "path", "media_type", "sha256", "bytes", "records"}
            or artifact.get("role") not in expected_roles
            or artifact["role"] in resolved
            or artifact.get("media_type") not in {"application/json", "application/x-ndjson"}
            or not _valid_digest(artifact.get("sha256"))
            or not isinstance(artifact.get("bytes"), int)
            or isinstance(artifact.get("bytes"), bool)
            or artifact["bytes"] < 1
            or not isinstance(artifact.get("records"), int)
            or isinstance(artifact.get("records"), bool)
            or artifact["records"] < 1
        ):
            raise EvidenceError("saturation raw artifact binding is invalid")
        relative = _external_relative_path(artifact.get("path"))
        if relative in paths or not relative.startswith("raw/"):
            raise EvidenceError("saturation raw artifact path is duplicate or outside raw/")
        paths.add(relative)
        maximum = 256 * 1024 * 1024 if artifact["role"] == "inventory-stream" else 128 * 1024 * 1024
        stable = read_external_bytes_stable(
            source_directory.joinpath(*relative.split("/")),
            root=root,
            max_bytes=maximum,
        )
        if stable.sha256 != artifact["sha256"] or stable.size_bytes != artifact["bytes"]:
            raise EvidenceError("saturation raw artifact content binding mismatch")
        resolved[artifact["role"]] = (artifact, stable)
    if set(resolved) != expected_roles:
        raise EvidenceError("saturation raw artifact roles are incomplete")

    inventory_binding, inventory_raw = resolved["inventory-stream"]
    inventory_rows = _parse_raw_jsonl(
        inventory_raw.payload,
        "inventory stream",
        max_records=100_000,
        max_line_bytes=16_384,
    )
    inventory_digest = hashlib.sha256()
    previous_path: str | None = None
    for row in inventory_rows:
        if (
            set(row) != {"path", "digest", "size", "search_text"}
            or not isinstance(row.get("path"), str)
            or not row["path"]
            or row["path"].startswith("/")
            or "\\" in row["path"]
            or any(part in {"", ".", ".."} for part in row["path"].split("/"))
            or not _valid_digest(row.get("digest"))
            or not isinstance(row.get("size"), int)
            or isinstance(row.get("size"), bool)
            or row["size"] < 0
            or not isinstance(row.get("search_text"), str)
            or len(row["search_text"].encode("utf-8")) > 4096
            or (previous_path is not None and row["path"] <= previous_path)
        ):
            raise EvidenceError("raw inventory stream row is invalid or non-canonical")
        previous_path = row["path"]
        inventory_digest.update(
            canonical_bytes({key: row[key] for key in ("path", "digest", "size")})
        )
    if (
        len(inventory_rows) != 100_000
        or inventory_binding["records"] != len(inventory_rows)
        or inventory_raw.sha256 != manifest["inventory_stream_digest"]
        or inventory_digest.hexdigest() != manifest["inventory_identity_digest"]
    ):
        raise EvidenceError("raw inventory stream counts or identities cannot be recomputed")

    operation_binding, operation_raw = resolved["operation-metrics"]
    operation = _validate_saturation_operation_metrics(
        operation_raw.payload,
        records=operation_binding["records"],
        verification=verification,
    )

    query_binding, query_raw = resolved["query-results"]
    query_rows = _parse_raw_jsonl(
        query_raw.payload,
        "query results",
        max_records=100_000,
    )
    if query_binding["records"] != len(query_rows) or len(query_rows) < 600:
        raise EvidenceError("raw query result count is below the required minimum")
    search = operation["search"]
    budget = search.get("runtime_query_budget") if isinstance(search, Mapping) else None
    if not isinstance(budget, Mapping) or not isinstance(budget.get("top_k"), int):
        raise EvidenceError("raw query verification lacks the runtime query budget")
    query_mix: dict[str, int] = {}
    depth_counts: dict[str, int] = {}
    class_depths: dict[str, set[int]] = {}
    class_latencies: dict[str, list[float]] = {}
    latencies: list[float] = []
    page_digests: list[str] = []
    total_pages = 0
    continuation_pages = 0
    explicit_truncations = 0
    maximum_token_bytes = 0
    selected_closure_chains = 0
    forced_chains = 0
    forced_union_matches = 0
    forced_depths: set[int] = set()
    class_checks: dict[str, list[bool]] = {}
    for index, row in enumerate(query_rows):
        recomputed = _recompute_raw_query_result(row, expected_index=index, top_k=budget["top_k"])
        query_class = recomputed["query_class"]
        depth = recomputed["depth"]
        latency = recomputed["elapsed_ms"]
        reference = recomputed["reference"]
        forced = recomputed["forced"]
        query_mix[query_class] = query_mix.get(query_class, 0) + 1
        depth_counts[str(depth)] = depth_counts.get(str(depth), 0) + 1
        class_depths.setdefault(query_class, set()).add(depth)
        class_latencies.setdefault(query_class, []).append(latency)
        class_checks.setdefault(query_class, []).append(recomputed["class_verified"])
        latencies.append(latency)
        page_digests.extend(reference["page_digests"])
        total_pages += reference["pages"]
        continuation_pages += reference["continuation_pages"]
        explicit_truncations += int(reference["first_truncated"])
        maximum_token_bytes = max(maximum_token_bytes, reference["maximum_token_bytes"])
        selected_closure_chains += 1
        if forced is not None:
            forced_chains += 1
            forced_union_matches += 1
            forced_depths.add(depth)
            page_digests.extend(forced["page_digests"])
            total_pages += forced["pages"]
            continuation_pages += forced["continuation_pages"]
            explicit_truncations += int(forced["first_truncated"])
            maximum_token_bytes = max(maximum_token_bytes, forced["maximum_token_bytes"])
            selected_closure_chains += 1
    expected_class_latency = {
        name: {
            "count": len(values),
            "p50": _nearest_rank(values, 0.50),
            "p95": _nearest_rank(values, 0.95),
            "p99": _nearest_rank(values, 0.99),
        }
        for name, values in sorted(class_latencies.items())
    }
    if (
        search.get("actual_runtime_queries") != len(query_rows)
        or search.get("query_mix") != dict(sorted(query_mix.items()))
        or search.get("depth_counts") != dict(sorted(depth_counts.items(), key=lambda item: int(item[0])))
        or search.get("query_class_depths")
        != {name: sorted(values) for name, values in sorted(class_depths.items())}
        or search.get("query_class_latency_ms") != expected_class_latency
        or search.get("p50_ms") != _nearest_rank(latencies, 0.50)
        or search.get("p95_ms") != _nearest_rank(latencies, 0.95)
        or search.get("p99_ms") != _nearest_rank(latencies, 0.99)
        or search.get("result_digest") != canonical_digest(page_digests)
        or search.get("pages_observed") != total_pages
        or search.get("continuations_checked") != continuation_pages
        or search.get("explicit_truncations") != explicit_truncations
        or search.get("maximum_continuation_token_bytes") != maximum_token_bytes
        or search.get("selected_closure_chains") != selected_closure_chains
        or search.get("forced_continuation_chains") != forced_chains
        or search.get("forced_union_matches") != forced_union_matches
        or search.get("forced_depths") != sorted(forced_depths)
    ):
        raise EvidenceError("saturation query summary cannot be recomputed from raw results")
    required_class_checks = {
        "broad_query_refinement_required": all(class_checks.get("broad", [])),
        "high_cardinality_terms_verified": all(class_checks.get("content-high-cardinality", [])),
        "content_search_verified": all(class_checks.get("content-probe", [])),
        "miss_behavior_verified": all(class_checks.get("miss", [])),
        "hostile_proxy_content_verified": all(class_checks.get("hostile-content", []))
        and all(class_checks.get("hostile-exact", [])),
        "exact_artifact_search_verified": all(class_checks.get("exact-artifact", [])),
    }
    if any(not class_checks.get(name) for name in ("broad", "content-high-cardinality", "content-probe", "miss", "hostile-content", "hostile-exact", "exact-artifact")):
        raise EvidenceError("raw query results omit a required query class")
    if any(search.get(field) is not value for field, value in required_class_checks.items()):
        raise EvidenceError("saturation query semantic flags cannot be recomputed")

    continuation_binding, continuation_raw = resolved["continuation-state-manifest"]
    continuation_rows = _parse_raw_jsonl(
        continuation_raw.payload,
        "continuation state manifest",
        max_records=100_000,
    )
    continuation_paths: list[str] = []
    continuation_sizes: list[int] = []
    for row in continuation_rows:
        if (
            set(row) != {"path", "sha256", "bytes"}
            or not isinstance(row.get("path"), str)
            or not row["path"]
            or not _valid_digest(row.get("sha256"))
            or not isinstance(row.get("bytes"), int)
            or isinstance(row.get("bytes"), bool)
            or row["bytes"] < 1
        ):
            raise EvidenceError("continuation state manifest row is invalid")
        continuation_paths.append(row["path"])
        continuation_sizes.append(row["bytes"])
    if (
        continuation_paths != sorted(set(continuation_paths))
        or continuation_binding["records"] != len(continuation_rows)
        or search.get("continuation_state")
        != {
            "files": len(continuation_sizes),
            "maximum_bytes": max(continuation_sizes, default=0),
            "total_bytes": sum(continuation_sizes),
            "preexisting_files_excluded": 0,
        }
    ):
        raise EvidenceError("continuation state summary cannot be recomputed")

    samples_binding, samples_raw = resolved["process-samples"]
    process_samples = _parse_raw_json(samples_raw.payload, "process samples")
    if (
        set(process_samples) != {"record_type", "sample_interval_ms", "lifetime_peak_rss_bytes", "phases"}
        or process_samples.get("record_type") != "SaturationProcessSamples"
        or process_samples.get("sample_interval_ms") != 50
        or not isinstance(process_samples.get("lifetime_peak_rss_bytes"), int)
        or process_samples["lifetime_peak_rss_bytes"] < 1
        or not isinstance(process_samples.get("phases"), list)
        or len(process_samples["phases"]) != 2
    ):
        raise EvidenceError("raw process sample record is invalid")
    sample_total = 0
    phase_summaries: dict[str, dict[str, int]] = {}
    for expected_phase, phase in zip(("inventory", "projection"), process_samples["phases"], strict=True):
        if (
            not isinstance(phase, Mapping)
            or set(phase) != {"phase", "summary", "samples"}
            or phase.get("phase") != expected_phase
            or not isinstance(phase.get("samples"), list)
            or len(phase["samples"]) < 2
        ):
            raise EvidenceError("raw process sample phase is invalid")
        elapsed_values: list[int] = []
        rss_values: list[int] = []
        for sample in phase["samples"]:
            if (
                not isinstance(sample, Mapping)
                or set(sample) != {"elapsed_ns", "rss_bytes"}
                or not isinstance(sample.get("elapsed_ns"), int)
                or isinstance(sample.get("elapsed_ns"), bool)
                or sample["elapsed_ns"] < 0
                or not isinstance(sample.get("rss_bytes"), int)
                or isinstance(sample.get("rss_bytes"), bool)
                or sample["rss_bytes"] < 1
            ):
                raise EvidenceError("raw process RSS sample is invalid")
            elapsed_values.append(sample["elapsed_ns"])
            rss_values.append(sample["rss_bytes"])
        if elapsed_values != sorted(elapsed_values) or elapsed_values[0] != 0:
            raise EvidenceError("raw process sample times are non-monotonic")
        summary = {
            "baseline_bytes": rss_values[0],
            "peak_bytes": max(rss_values),
            "incremental_peak_bytes": max(rss_values) - rss_values[0],
        }
        if phase.get("summary") != summary:
            raise EvidenceError("raw process sample summary mismatch")
        phase_summaries[expected_phase] = summary
        sample_total += len(rss_values)
    if samples_binding["records"] != sample_total:
        raise EvidenceError("raw process sample count mismatch")
    resources = operation["resources"]
    stream_bytes = len(inventory_raw.payload)
    incremental_peak = max(
        phase_summaries["inventory"]["incremental_peak_bytes"],
        phase_summaries["projection"]["incremental_peak_bytes"],
    )
    absolute_peak = max(
        phase_summaries["inventory"]["peak_bytes"],
        phase_summaries["projection"]["peak_bytes"],
    )
    incremental_ratio = round(incremental_peak / stream_bytes, 9)
    absolute_ratio = round(absolute_peak / stream_bytes, 9)
    expected_metric = {
        "metric_id": "inventory-incremental-peak-over-stream-bytes",
        "numerator": "inventory_pipeline_incremental_peak_bytes",
        "denominator": "inventory_stream_bytes",
        "numerator_bytes": incremental_peak,
        "denominator_bytes": stream_bytes,
        "ratio": incremental_ratio,
        "threshold_max": 32.0,
        "within_threshold": incremental_ratio <= 32.0,
    }
    if (
        resources.get("inventory_stage_rss") != phase_summaries["inventory"]
        or resources.get("projection_stage_rss") != phase_summaries["projection"]
        or resources.get("inventory_pipeline_peak_rss_bytes") != absolute_peak
        or resources.get("inventory_pipeline_incremental_peak_bytes") != incremental_peak
        or resources.get("inventory_absolute_rss_amplification") != absolute_ratio
        or resources.get("inventory_incremental_memory_amplification") != incremental_ratio
        or resources.get("memory_amplification_metric") != expected_metric
        or resources.get("peak_rss_bytes") != process_samples["lifetime_peak_rss_bytes"]
    ):
        raise EvidenceError("saturation memory metrics cannot be recomputed from raw samples")

    phase_binding, phase_raw = resolved["phase-log"]
    phase_rows = _parse_raw_jsonl(phase_raw.payload, "phase log", max_records=32)
    if (
        phase_binding["records"] != len(phase_rows)
        or [row.get("order") for row in phase_rows] != [1, 2, 3, 4, 5, 6]
        or [row.get("phase") for row in phase_rows]
        != [
            "physical-generation",
            "inventory",
            "semantic-ingestion",
            "projection",
            "runtime-queries",
            "result",
        ]
        or phase_rows[2].get("elapsed_ms")
        != round(semantic_ingestion["elapsed_seconds"] * 1000)
    ):
        raise EvidenceError("saturation phase log is incomplete or reordered")
    final_phase = phase_rows[-1]
    expected_exit = 0 if operation.get("status") == "pass" else 1
    if (
        final_phase.get("status") != operation.get("status")
        or final_phase.get("process_exit_code") != expected_exit
        or final_phase.get("invocation_exit_code") != expected_exit
        or operation.get("process_exit_code") != expected_exit
        or operation.get("invocation_exit_code") != expected_exit
        or verification.get("invocation", {}).get("exit_code") != expected_exit
    ):
        raise EvidenceError("saturation status and process/invocation exits disagree")
    return {
        "operation": operation,
        "inventory_entry_count": len(inventory_rows),
        "query_count": len(query_rows),
        "memory_within_threshold": incremental_ratio <= 32.0,
        "process_exit_code": expected_exit,
    }


def _validate_saturation_runtime_bindings(
    verification: Mapping[str, Any],
    *,
    binding: Mapping[str, Any],
    projection: Mapping[str, Any],
    query_authorization: Any,
    search: Mapping[str, Any],
    resources: Mapping[str, Any],
    performance: Mapping[str, Any],
) -> None:
    initialization = verification.get("workspace_initialization")
    runtime = verification.get("runtime_binding")
    initialization_fields = {
        "record_type",
        "status",
        "project_id",
        "activation_digest",
        "implementation_closure_digest",
        "product_tree_scans",
        "init_record_count",
        "init_records",
        "snapshot_provider_id",
        "snapshot_provider_version",
    }
    runtime_fields = {
        "activation_digest",
        "implementation_closure_digest",
        "platform_binding_digest",
    }
    query_fields = {
        "subject_id",
        "grant_id",
        "claim_digest",
        "capability_id",
        "scope",
        "activation_digest",
        "expires_at",
    }
    if (
        not isinstance(initialization, Mapping)
        or set(initialization) != initialization_fields
        or initialization.get("record_type")
        != "SaturationWorkspaceInitialization"
        or initialization.get("status") not in {"created", "reused"}
        or initialization.get("project_id") != "promin-physical-saturation"
        or not _valid_digest(initialization.get("activation_digest"))
        or not _valid_digest(initialization.get("implementation_closure_digest"))
        or initialization.get("product_tree_scans") != 0
        or initialization.get("init_record_count") != 5
        or initialization.get("init_records")
        != [
            "activation.json",
            "authority.json",
            "project.json",
            "standards.json",
            "technologies.json",
        ]
        or initialization.get("snapshot_provider_id")
        != "git-filesystem-inventory"
        or not isinstance(initialization.get("snapshot_provider_version"), str)
        or not initialization["snapshot_provider_version"]
        or not isinstance(runtime, Mapping)
        or set(runtime) != runtime_fields
        or not isinstance(query_authorization, Mapping)
        or set(query_authorization) != query_fields
    ):
        raise EvidenceError("saturation initialization or runtime binding is invalid")
    activation_digest = initialization["activation_digest"]
    implementation_digest = initialization["implementation_closure_digest"]
    platform_binding = _validate_release_platform_binding(binding.get("platform"))
    scope = query_authorization.get("scope")
    if (
        runtime.get("activation_digest") != activation_digest
        or runtime.get("implementation_closure_digest") != implementation_digest
        or runtime.get("platform_binding_digest")
        != platform_binding["binding_digest"]
        or projection.get("implementation_closure_digest")
        != implementation_digest
        or query_authorization.get("activation_digest") != activation_digest
        or query_authorization.get("capability_id") != "projection.read"
        or not _safe_id(query_authorization.get("subject_id"))
        or not _safe_id(query_authorization.get("grant_id"))
        or not _valid_digest(query_authorization.get("claim_digest"))
        or not isinstance(scope, list)
        or not scope
        or len(scope) > 128
        or any(not isinstance(item, Mapping) or not item for item in scope)
    ):
        raise EvidenceError("saturation runtime generation bindings disagree")
    try:
        parse_timestamp(query_authorization.get("expires_at"))
    except (AuthorityError, TypeError, ValueError) as exc:
        raise EvidenceError("saturation query authorization expiry is invalid") from exc

    observed = performance.get("observed")
    compatible_platforms = performance.get("compatible_platforms")
    if (
        performance.get("profile_id") != "portable-local-v1"
        or performance.get("platform_binding") != platform_binding
        or not isinstance(compatible_platforms, list)
        or platform_binding["system"] not in compatible_platforms
        or performance.get("requires_same_runner_no_degradation") is not True
        or not isinstance(observed, Mapping)
        or observed.get("p50_ms") != search.get("p50_ms")
        or observed.get("p95_ms") != search.get("p95_ms")
        or observed.get("p99_ms") != search.get("p99_ms")
        or observed.get("peak_rss_bytes") != resources.get("peak_rss_bytes")
        or observed.get("database_bytes") != projection.get("database_bytes")
        or observed.get("projection_amplification")
        != projection.get("projection_amplification")
        or observed.get("semantic_inflation")
        != projection.get("semantic_inflation")
    ):
        raise EvidenceError("saturation performance profile binding is invalid")


_SATURATION_SEMANTIC_REUSE_FIELDS = (
    "reused",
    "search_fixture_reused",
    "physical_relation_fixture_reused",
)
_SATURATION_PROJECTION_ENTITY_TYPE_COUNTS = {
    "Artifact": 100_000,
    "Task": 1_599,
    "Grant": 4,
    "Candidate": 1,
}
_SATURATION_SEMANTIC_COMMIT_ENTITY_TYPES = ("Grant", "Candidate", "Task")


def _validate_saturation_fresh_semantic_corpus(
    value: Any,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceError("fresh saturation evidence requires its semantic corpus")
    missing_reuse_fields = [
        field for field in _SATURATION_SEMANTIC_REUSE_FIELDS if field not in value
    ]
    if missing_reuse_fields or any(
        value.get(field) is not False for field in _SATURATION_SEMANTIC_REUSE_FIELDS
    ):
        raise EvidenceError("fresh saturation cannot reuse semantic corpus state")
    search_fixture = value.get("search_fixture")
    physical_relation_fixture = value.get("physical_relation_fixture")
    if (
        value.get("record_type") != "SaturationSemanticCorpus"
        or value.get("generation") != "explicit-authorized-command-events"
        or value.get("harness_generated") is not True
        or value.get("product_acceptance_credit") is not False
        or value.get("task_count") != 1_599
        or value.get("relation_count") != 198_999
        or value.get("depths") != list(range(1, 13))
        or value.get("high_fanout") != 16
        or value.get("conflicting_exact_id_text") is not True
        or not isinstance(search_fixture, Mapping)
        or search_fixture.get("task_count") != 32
        or search_fixture.get("relation_count") != 28
        or search_fixture.get("depths") != list(range(1, 13))
        or search_fixture.get("high_fanout") != 16
        or not isinstance(physical_relation_fixture, Mapping)
        or physical_relation_fixture.get("task_count") != 1_567
        or physical_relation_fixture.get("relation_count") != 198_971
        or physical_relation_fixture.get("relation_kind") != "READS"
        or physical_relation_fixture.get("target_type") != "Artifact"
        or physical_relation_fixture.get("artifact_target_count") != 100_000
        or physical_relation_fixture.get("artifact_target_coverage") != 1.0
        or physical_relation_fixture.get("relations_per_atomic_batch_max") != 127
    ):
        raise EvidenceError(
            "fresh saturation semantic corpus shape or exact counts are invalid"
        )
    return deepcopy(dict(value))


def _validate_saturation_projection_entity_contour(
    projection: Any,
) -> dict[str, int]:
    if not isinstance(projection, Mapping):
        raise EvidenceError("saturation projection entity contour is missing")
    entity_type_counts = projection.get("entity_type_counts")
    expected_counts = _SATURATION_PROJECTION_ENTITY_TYPE_COUNTS
    if (
        not isinstance(entity_type_counts, Mapping)
        or set(entity_type_counts) != set(expected_counts)
        or any(type(count) is not int for count in entity_type_counts.values())
    ):
        raise EvidenceError("saturation projection entity contour shape is invalid")
    counts = dict(entity_type_counts)
    expected_entity_count = sum(expected_counts.values())
    if (
        counts != expected_counts
        or type(projection.get("entity_count")) is not int
        or projection["entity_count"] != expected_entity_count
        or projection["entity_count"] != sum(counts.values())
    ):
        raise EvidenceError("saturation projection entity contour is not exact")
    return counts


def validate_saturation_evidence(
    verification: Mapping[str, Any],
    *,
    candidate_binding: Mapping[str, Any],
    source_path: Path,
    evidence_root: Path,
    require_pass: bool = True,
) -> dict[str, Any]:
    """Recompute physical scale, search, continuation, and performance predicates."""

    candidate = validate_standard_release_candidate_binding(candidate_binding)
    _validate_release_evidence_schema("SaturationEvidence", verification)
    if (
        not isinstance(verification, Mapping)
        or set(verification) != _SATURATION_EVIDENCE_FIELDS
        or verification.get("record_type") != "SaturationEvidence"
        or verification.get("status") not in {"pass", "fail"}
        or verification.get("candidate_binding_digest")
        != candidate["candidate_binding_digest"]
        or verification.get("pass_credit") is not False
        or verification.get("acceptance_pass") is not False
        or verification.get("product_acceptance_pass") is not False
        or verification.get("public_release_approved") is not False
    ):
        raise EvidenceError("SaturationEvidence shape or candidate binding is invalid")
    if require_pass and verification["status"] != "pass":
        raise EvidenceError("failed saturation evidence cannot satisfy a passing evidence role")
    binding = verification.get("artifact_binding")
    _validate_exact_artifact_binding(binding, candidate=candidate)
    _validate_release_evidence_envelope(
        verification,
        candidate=candidate,
        expected_tool_path="tools/promin_saturation.py",
        expected_operation="physical-saturation",
        expected_role="physical-scale",
        expected_platform=_release_evidence_platform(verification),
        expected_exit_code=0 if verification["status"] == "pass" else 1,
    )
    if verification["invocation"]["platform_binding_digest"] != binding["platform"]["binding_digest"][7:]:
        raise EvidenceError("saturation invocation binds another platform")
    raw = _validate_saturation_raw_artifacts(
        verification,
        source_path=source_path,
        evidence_root=evidence_root,
    )
    semantic_ingestion = raw["operation"]["semantic_ingestion"]
    physical = verification.get("physical")
    inventory = verification.get("inventory")
    projection = verification.get("projection")
    search = verification.get("search")
    resources = verification.get("resources")
    performance = verification.get("performance")
    predicates = verification.get("contract_predicates")
    if not all(isinstance(value, Mapping) for value in (physical, inventory, projection, search, resources, performance, predicates)):
        raise EvidenceError("saturation semantic sections are missing")
    _validate_saturation_runtime_bindings(
        verification,
        binding=binding,
        projection=projection,
        query_authorization=verification.get("query_authorization"),
        search=search,
        resources=resources,
        performance=performance,
    )
    corpus = _validate_saturation_fresh_semantic_corpus(
        physical.get("explicit_semantic_corpus")
    )
    entity_type_counts = _validate_saturation_projection_entity_contour(projection)
    expected_semantic_commit_count = sum(
        entity_type_counts[entity_type]
        for entity_type in _SATURATION_SEMANTIC_COMMIT_ENTITY_TYPES
    )
    if (
        physical.get("files") != 100_000
        or physical.get("raw_files") != 100_000
        or physical.get("raw_file_proxies") != 100_000
        or physical.get("semantic_proxies") != 100_000
        or physical.get("raw_file_proxy_ratio") != 1.0
        or physical.get("synthetic_task_count") != 0
        or physical.get("synthetic_task_ratio") != 0.0
        or physical.get("relations") != 198_999
        or physical.get("vcs_tree_files") != 100_000
        or inventory.get("entries") != 100_000
        or inventory.get("passes") != 1
        or projection.get("relation_count") != 198_999
        or projection.get("initial_inventory_passes") != 1
        or projection.get("initial_product_passes") != 0
        or projection.get("rebuild_inventory_passes") != 1
        or projection.get("rebuild_product_passes") != 0
        or projection.get("equal_semantic_digest") is not True
    ):
        raise EvidenceError("physical saturation counts or rebuild invariants failed")
    query_mix = search.get("query_mix")
    expected_query_classes = {
        "broad",
        "content-high-cardinality",
        "content-probe",
        "exact-artifact",
        "exact-semantic",
        "forced-continuation",
        "hostile-content",
        "hostile-exact",
        "miss",
    }
    depth_counts = search.get("depth_counts")
    if (
        search.get("actual_runtime_queries") != 600
        or not isinstance(query_mix, Mapping)
        or set(query_mix) != expected_query_classes
        or sum(query_mix.values()) != search["actual_runtime_queries"]
        or not isinstance(depth_counts, Mapping)
        or {int(key) for key in depth_counts} != set(range(1, 13))
        or any(value < 1 for value in depth_counts.values())
        or search.get("depth_min") != 1
        or search.get("depth_max") != 12
        or search.get("silent_truncations") != 0
        or search.get("continuation_union_completeness") != 1.0
        or search.get("selected_closure_union_completeness") != 1.0
        or search.get("maximum_continuation_token_bytes", 257) > 256
        or search.get("continuation_state", {}).get("maximum_bytes", 16_385) > 16_384
        or search.get("continuation_token_overhead_at_most_10_percent") is not True
    ):
        raise EvidenceError("runtime query mix, depth, or continuation closure failed")
    observed = performance.get("observed")
    thresholds = performance.get("thresholds")
    performance_predicates = performance.get("predicates")
    comparisons = {
        "p50_within_profile": ("p50_ms", "p50_ms_max"),
        "p95_within_profile": ("p95_ms", "p95_ms_max"),
        "p99_within_profile": ("p99_ms", "p99_ms_max"),
        "peak_rss_within_profile": ("peak_rss_bytes", "peak_rss_bytes_max"),
        "database_within_profile": ("database_bytes", "database_bytes_max"),
        "projection_amplification_within_profile": (
            "projection_amplification",
            "projection_amplification_max",
        ),
        "semantic_inflation_within_profile": (
            "semantic_inflation",
            "semantic_inflation_max",
        ),
        "commit_p95_within_profile": ("commit_p95_ms", "commit_p95_ms_max"),
        "commit_p99_within_profile": ("commit_p99_ms", "commit_p99_ms_max"),
        "commit_bytes_per_changed_record_within_profile": (
            "commit_bytes_per_changed_record",
            "commit_bytes_per_changed_record_max",
        ),
        "runtime_checkpoint_count_within_profile": (
            "runtime_checkpoint_count",
            "runtime_checkpoint_count_max",
        ),
        "semantic_ingestion_within_profile": (
            "semantic_ingestion_seconds",
            "semantic_ingestion_seconds_max",
        ),
    }
    if (
        not isinstance(observed, Mapping)
        or not isinstance(thresholds, Mapping)
        or not isinstance(performance_predicates, Mapping)
        or set(performance_predicates) != set(comparisons)
        or set(observed)
        != {observed_key for observed_key, _threshold_key in comparisons.values()}
        | {"runtime_checkpoint_writes"}
        or set(thresholds)
        != {threshold_key for _observed_key, threshold_key in comparisons.values()}
        or observed.get("commit_p95_ms") != semantic_ingestion["p95_ms"]
        or observed.get("commit_p99_ms") != semantic_ingestion["p99_ms"]
        or observed.get("commit_bytes_per_changed_record")
        != semantic_ingestion["bytes_per_changed_record"]
        or observed.get("runtime_checkpoint_count")
        != semantic_ingestion["checkpoint_count"]
        or observed.get("runtime_checkpoint_writes")
        != semantic_ingestion["checkpoint_writes"]
        or observed.get("semantic_ingestion_seconds")
        != semantic_ingestion["elapsed_seconds"]
    ):
        raise EvidenceError("saturation performance shape is invalid")
    expected_performance_predicates = {
        predicate: observed.get(observed_key, float("inf"))
        <= thresholds.get(threshold_key, float("-inf"))
        for predicate, (observed_key, threshold_key) in comparisons.items()
    }
    performance_within_profile = all(expected_performance_predicates.values())
    if (
        dict(performance_predicates) != expected_performance_predicates
        or performance.get("all_within_profile") is not performance_within_profile
    ):
        raise EvidenceError("saturation performance predicates cannot be recomputed")
    continuation_state = search.get("continuation_state")
    continuation_state_within_limit = (
        isinstance(continuation_state, Mapping)
        and isinstance(continuation_state.get("maximum_bytes"), int)
        and 0 < continuation_state["maximum_bytes"] <= 16_384
    )
    continuation_token_within_limit = (
        isinstance(search.get("maximum_continuation_token_bytes"), int)
        and search["maximum_continuation_token_bytes"] <= 256
    )
    memory_within_threshold = raw["memory_within_threshold"]
    required_query_classes_without_forced = {
        "broad",
        "content-high-cardinality",
        "content-probe",
        "exact-artifact",
        "exact-semantic",
        "hostile-content",
        "hostile-exact",
        "miss",
    }
    mixed_complete = all(
        query_mix.get(name, 0) >= max(1, search["actual_runtime_queries"] // 12)
        for name in required_query_classes_without_forced
    )
    required_top = {
        "physical_files": 100_000,
        "core_valid_relations": projection["relation_count"],
        "runtime_queries": search["actual_runtime_queries"],
        "silent_truncations": 0,
        "selected_closure_union_completeness": search["selected_closure_union_completeness"],
        "memory_amplification_at_most_32": memory_within_threshold,
        "core_valid_relations_exact_198999": projection["relation_count"] == 198_999,
        "broad_query_refinement_required": search["broad_query_refinement_required"],
        "high_cardinality_terms_verified": search["high_cardinality_terms_verified"],
        "content_search_verified": search["content_search_verified"],
        "miss_behavior_verified": search["miss_behavior_verified"],
        "hostile_proxy_content_verified": search["hostile_proxy_content_verified"],
        "exact_artifact_search_verified": search["exact_artifact_search_verified"],
        "mixed_query_classes_complete": mixed_complete,
        "continuation_token_bytes_at_most_256": continuation_token_within_limit,
        "continuation_state_bytes_at_most_16384": continuation_state_within_limit,
        "continuation_token_overhead_at_most_10_percent": (
            search.get("continuation_token_overhead_at_most_10_percent") is True
        ),
        "artifact_binding_unchanged": True,
    }
    if any(verification.get(key) != value for key, value in required_top.items()):
        raise EvidenceError("saturation summary fields disagree with recomputed metrics")
    relation_fixture = corpus.get("physical_relation_fixture") if isinstance(corpus, Mapping) else None
    expected_contract_predicates = {
        "broad_query_refinement_required": search.get("broad_query_refinement_required") is True,
        "content_search_verified": search.get("content_search_verified") is True,
        "continuation_state_bytes_at_most_16384": continuation_state_within_limit,
        "continuation_token_bytes_at_most_256": continuation_token_within_limit,
        "continuation_token_overhead_at_most_10_percent": search.get(
            "continuation_token_overhead_at_most_10_percent"
        )
        is True,
        "continuation_union_complete": search.get("forced_union_matches")
        == search.get("forced_continuation_chains"),
        "core_valid_relations_exact": projection.get("relation_count") == 198_999,
        "exact_artifact_binding_unchanged": verification.get("artifact_binding_unchanged") is True,
        "exact_artifact_search_verified": search.get("exact_artifact_search_verified") is True,
        "high_cardinality_terms_verified": search.get("high_cardinality_terms_verified") is True,
        "hostile_proxy_content_verified": search.get("hostile_proxy_content_verified") is True,
        "inventory_incremental_memory_amplification_at_most_32": memory_within_threshold,
        "inventory_passes_exact": inventory.get("passes") == 1,
        "miss_behavior_verified": search.get("miss_behavior_verified") is True,
        "mixed_query_classes_complete": mixed_complete,
        "physical_relation_artifact_coverage_complete": isinstance(relation_fixture, Mapping)
        and relation_fixture.get("artifact_target_count") == 100_000
        and relation_fixture.get("artifact_target_coverage") == 1.0,
        "raw_file_proxy_ratio_exact": physical.get("raw_file_proxy_ratio") == 1.0,
        "rebuild_digest_equal": projection.get("equal_semantic_digest") is True,
        "rebuild_product_passes_zero": projection.get("rebuild_product_passes") == 0,
        "runtime_depths_1_through_12": {int(key) for key in depth_counts} == set(range(1, 13)),
        "runtime_queries_exact": search.get("actual_runtime_queries") == 600,
        "runtime_query_budget_bounded": isinstance(search.get("runtime_query_budget"), Mapping),
        "selected_closure_union_complete": search.get("selected_closure_union_completeness") == 1.0,
        "semantic_commit_count_exact": semantic_ingestion.get("commit_count")
        == expected_semantic_commit_count,
        "silent_truncations_zero": search.get("silent_truncations") == 0,
        "synthetic_task_ratio_zero": physical.get("synthetic_task_ratio") == 0.0,
    }
    if dict(predicates) != expected_contract_predicates:
        raise EvidenceError("saturation contract predicates cannot be recomputed")
    expected_status = (
        "pass"
        if all(expected_contract_predicates.values()) and performance_within_profile
        else "fail"
    )
    if verification["status"] != expected_status:
        raise EvidenceError("saturation status disagrees with recomputed raw predicates")
    if require_pass and expected_status != "pass":
        raise EvidenceError("saturation evidence does not satisfy all passing predicates")
    return deepcopy(dict(verification))


def _validate_release_evidence_attestation_graph(
    attestations: Iterable[Mapping[str, Any]],
    *,
    trust_configuration: Mapping[str, Any],
) -> None:
    trust = _validate_trust_configuration(trust_configuration)
    rows = list(attestations)
    if not rows:
        raise EvidenceError("release evidence attestation graph is empty")
    nonces: set[tuple[str, str]] = set()
    claims: set[str] = set()
    invocations: set[str] = set()
    audit_rows: list[Mapping[str, Any]] = []
    physical_rows: list[Mapping[str, Any]] = []
    for attestation in rows:
        role = attestation.get("evidence_role")
        platform_name = _normalized_evidence_platform(attestation.get("platform"))
        _validate_evidence_attestation_trust(
            attestation,
            trust=trust,
            expected_role=role,
            expected_platform=platform_name,
        )
        nonce = (attestation.get("key_id"), attestation.get("nonce"))
        claim = attestation.get("signed_claim_digest")
        invocation = attestation.get("invocation_id")
        if nonce in nonces or claim in claims or invocation in invocations:
            raise EvidenceError("release evidence producer attestation graph contains replay")
        nonces.add(nonce)
        claims.add(claim)
        invocations.add(invocation)
        if role == "saturation-audit":
            audit_rows.append(attestation)
        elif role == "physical-scale":
            physical_rows.append(attestation)
    for audit_attestation in audit_rows:
        for physical_attestation in physical_rows:
            if (
                audit_attestation.get("key_id") == physical_attestation.get("key_id")
                or audit_attestation.get("producer_id")
                == physical_attestation.get("producer_id")
                or audit_attestation.get("public_key")
                == physical_attestation.get("public_key")
            ):
                raise EvidenceError(
                    "saturation audit and physical-scale producers violate separation of duties"
                )


def _validate_saturation_audit_producer_boundary(
    outer_attestation: Mapping[str, Any],
    nested_attestations: Iterable[Mapping[str, Any]],
    *,
    trust_configuration: Mapping[str, Any],
) -> None:
    nested_rows = list(nested_attestations)
    if len(nested_rows) < 3:
        raise EvidenceError("saturation audit lacks trusted nested physical producers")
    if any(
        attestation.get("platform") != outer_attestation.get("platform")
        for attestation in nested_rows
    ):
        raise EvidenceError("saturation audit nested physical producer platform differs")
    _validate_release_evidence_attestation_graph(
        [outer_attestation, *nested_rows],
        trust_configuration=trust_configuration,
    )


def _validate_saturation_audit_fresh_requirements(
    verification: Mapping[str, Any],
) -> None:
    requirements = verification.get("requirements")
    if (
        not isinstance(requirements, Mapping)
        or requirements.get("fresh_control_state_per_iteration") is not True
        or requirements.get("semantic_state_reused") is not False
        or requirements.get("init_product_tree_scans") != 0
    ):
        raise EvidenceError("saturation audit fresh-control requirements are invalid")


def _validate_saturation_audit_fresh_control_state(
    value: Any,
    *,
    candidate: Mapping[str, Any],
    run: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "status",
        "product_tree_scans",
        "init_record_count",
        "activation_digest",
        "implementation_closure_digest",
        "core_bundle_digest",
        "preset_digest",
        "semantic_state_reused",
        "product_tree_reused",
        "physical_corpus_recipe",
    }
    if (
        not isinstance(value, Mapping)
        or set(value) != fields
        or value.get("status") != "created"
        or value.get("product_tree_scans") != 0
        or value.get("init_record_count") != 5
        or not _valid_digest(value.get("activation_digest"))
        or not _valid_digest(value.get("implementation_closure_digest"))
        or value.get("core_bundle_digest") != candidate.get("core_bundle_digest")
        or value.get("preset_digest") != candidate.get("preset_digest")
        or value.get("semantic_state_reused") is not False
        or not isinstance(value.get("product_tree_reused"), bool)
    ):
        raise EvidenceError("saturation audit fresh control state is invalid")
    recipe = value.get("physical_corpus_recipe")
    if (
        not isinstance(recipe, Mapping)
        or set(recipe) != {"sha256", "bytes", "file_count"}
        or not _valid_digest(recipe.get("sha256"))
        or not isinstance(recipe.get("bytes"), int)
        or isinstance(recipe.get("bytes"), bool)
        or recipe["bytes"] < 1
        or recipe.get("file_count") != 100_000
    ):
        raise EvidenceError("saturation audit physical-corpus recipe binding is invalid")

    artifact_binding = run.get("artifact_binding")
    runtime_binding = run.get("runtime_binding")
    initialization = run.get("workspace_initialization")
    physical = run.get("physical")
    platform_binding = (
        artifact_binding.get("platform")
        if isinstance(artifact_binding, Mapping)
        else None
    )
    preset = (
        artifact_binding.get("preset")
        if isinstance(artifact_binding, Mapping)
        else None
    )
    if (
        not isinstance(runtime_binding, Mapping)
        or set(runtime_binding)
        != {
            "activation_digest",
            "implementation_closure_digest",
            "platform_binding_digest",
        }
        or not isinstance(initialization, Mapping)
        or set(initialization)
        != {
            "record_type",
            "status",
            "project_id",
            "activation_digest",
            "implementation_closure_digest",
            "product_tree_scans",
            "init_record_count",
            "init_records",
            "snapshot_provider_id",
            "snapshot_provider_version",
        }
        or not isinstance(platform_binding, Mapping)
        or not isinstance(preset, Mapping)
        or not isinstance(physical, Mapping)
    ):
        raise EvidenceError("saturation audit nested physical runtime binding is invalid")
    if (
        runtime_binding.get("activation_digest") != value["activation_digest"]
        or runtime_binding.get("implementation_closure_digest")
        != value["implementation_closure_digest"]
        or runtime_binding.get("platform_binding_digest")
        != platform_binding.get("binding_digest")
        or initialization.get("record_type")
        != "SaturationWorkspaceInitialization"
        or initialization.get("status") != "reused"
        or initialization.get("project_id") != "promin-physical-saturation"
        or initialization.get("activation_digest") != value["activation_digest"]
        or initialization.get("implementation_closure_digest")
        != value["implementation_closure_digest"]
        or initialization.get("product_tree_scans") != 0
        or initialization.get("init_record_count") != 5
        or initialization.get("init_records")
        != [
            "activation.json",
            "authority.json",
            "project.json",
            "standards.json",
            "technologies.json",
        ]
        or initialization.get("snapshot_provider_id")
        != "git-filesystem-inventory"
        or not isinstance(initialization.get("snapshot_provider_version"), str)
        or not initialization["snapshot_provider_version"]
        or artifact_binding.get("core_bundle_digest")
        != "sha256:" + value["core_bundle_digest"]
        or preset.get("sha256") != "sha256:" + value["preset_digest"]
        or physical.get("reused_product") is not value["product_tree_reused"]
    ):
        raise EvidenceError(
            "saturation audit fresh control state differs from nested physical evidence"
        )
    return deepcopy(dict(value))


def validate_saturation_audit(
    verification: Mapping[str, Any],
    *,
    candidate_binding: Mapping[str, Any],
    source_path: Path,
    evidence_root: Path,
    trust_configuration: Mapping[str, Any],
    attestation_graph: list[dict[str, Any]] | None = None,
    nested_completion_times: list[datetime] | None = None,
) -> dict[str, Any]:
    """Resolve every saturation run/log and recompute the zero-new streak."""

    candidate = validate_standard_release_candidate_binding(candidate_binding)
    _validate_release_evidence_schema("SaturationAudit", verification)
    if (
        not isinstance(verification, Mapping)
        or set(verification) != _SATURATION_AUDIT_FIELDS
        or verification.get("record_type") != "SaturationAudit"
        or verification.get("status") != "pass"
        or verification.get("candidate_binding_digest")
        != candidate["candidate_binding_digest"]
        or verification.get("pass_credit") is not False
        or verification.get("acceptance_pass") is not False
        or verification.get("product_acceptance_pass") is not False
        or verification.get("predeclared_zero_new") is not False
    ):
        raise EvidenceError("SaturationAudit shape or candidate binding is invalid")
    binding = verification.get("artifact_binding")
    _validate_exact_artifact_binding(binding, candidate=candidate)
    _validate_release_evidence_envelope(
        verification,
        candidate=candidate,
        expected_tool_path="tools/promin_saturation_audit.py",
        expected_operation="saturation-audit",
        expected_role="saturation-audit",
        expected_platform=_release_evidence_platform(verification),
    )
    outer_attestation = _validate_producer_attestation(
        verification,
        candidate=candidate,
        expected_role="saturation-audit",
        expected_platform=_release_evidence_platform(verification),
    )
    if verification["invocation"]["platform_binding_digest"] != binding["platform"]["binding_digest"][7:]:
        raise EvidenceError("saturation audit invocation binds another platform")
    families = verification.get("families")
    collection = verification.get("collection")
    requirements = verification.get("requirements")
    iterations = verification.get("iterations")
    if (
        not isinstance(families, list)
        or len(families) < 1
        or len(families) != len(set(families))
        or not isinstance(collection, Mapping)
        or collection.get("families_discovered") != len(families)
        or not _valid_prefixed_digest(collection.get("catalogue_digest"))
        or not isinstance(iterations, list)
        or len(iterations) < 3
        or len(iterations) > 18
        or not isinstance(requirements, Mapping)
        or requirements.get("minimum_consecutive_full_zero_new") != 3
        or requirements.get("maximum_iterations") != 18
        or requirements.get("physical_files") != 100_000
        or requirements.get("core_valid_relations") != 198_999
        or requirements.get("actual_runtime_queries") != 600
        or requirements.get("depths") != "1-12"
        or requirements.get("raw_file_proxy_ratio") != 1.0
        or requirements.get("synthetic_task_ratio") != 0.0
        or requirements.get("profile_bound_fail_closed") is not True
        or requirements.get("missing_scale_workspace_fails") is not True
    ):
        raise EvidenceError("saturation audit collection or requirement closure is invalid")
    _validate_saturation_audit_fresh_requirements(verification)
    audit_directory = source_path.parent
    streak = 0
    run_digests: set[str] = set()
    run_ids: set[str] = set()
    run_paths: set[str] = set()
    fresh_state_bindings: set[str] = set()
    physical_corpus_recipe: dict[str, Any] | None = None
    mutation_seeds: set[str] = set()
    nested_attestations: list[dict[str, Any]] = []
    outer_completed_at = parse_timestamp(verification["invocation"]["completed_at"])
    total_new = 0
    for index, row in enumerate(iterations, start=1):
        expected_row_fields = {
            "finding_fingerprints",
            "focused_and_integration_tests",
            "full_system_corpus_rerun",
            "iteration",
            "mutation_families_run",
            "mutation_seed",
            "new_finding_classes",
            "physical_runtime_saturation",
            "silent_truncations",
            "status",
            "streak_reset_reason",
            "unexpected_accepts",
            "unexpected_crashes",
            "unexpected_rejects",
            "zero_new_streak_after",
            "zero_new_streak_before",
        }
        if (
            not isinstance(row, Mapping)
            or set(row) != expected_row_fields
            or row.get("iteration") != index
            or row.get("mutation_families_run") != len(families)
            or not _valid_digest(row.get("mutation_seed"))
            or row["mutation_seed"] in mutation_seeds
            or row.get("full_system_corpus_rerun") is not True
        ):
            raise EvidenceError("saturation audit iteration identity is invalid")
        mutation_seeds.add(row["mutation_seed"])
        focused = row.get("focused_and_integration_tests")
        physical = row.get("physical_runtime_saturation")
        if not isinstance(focused, Mapping) or not isinstance(physical, Mapping):
            raise EvidenceError("saturation audit iteration execution details are missing")
        for path_field, digest_field, bytes_field in (
            ("log_path", "log_sha256", "log_bytes"),
            ("sentinel_path", "sentinel_sha256", "sentinel_bytes"),
        ):
            relative = _external_relative_path(focused.get(path_field))
            stable = read_external_bytes_stable(
                audit_directory.joinpath(*relative.split("/")),
                root=evidence_root,
            )
            if stable.sha256 != focused.get(digest_field) or stable.size_bytes != focused.get(bytes_field):
                raise EvidenceError("saturation audit focused log/sentinel binding mismatch")
        if (
            focused.get("exit_code") != 0
            or focused.get("runner") != "pytest"
            or focused.get("marker_expression") != "not scale"
            or focused.get("cache_provider_disabled") is not True
            or focused.get("pytest_only_sentinel_executed") is not True
            or focused.get("output_digest") != "sha256:" + focused["log_sha256"]
            or focused.get("pytest_only_sentinel_token_digest")
            != "sha256:" + focused["sentinel_sha256"]
        ):
            raise EvidenceError("saturation audit focused test execution is invalid")
        physical_log_relative = _external_relative_path(physical.get("log_path"))
        physical_log = read_external_bytes_stable(
            audit_directory.joinpath(*physical_log_relative.split("/")),
            root=evidence_root,
        )
        if (
            physical_log.sha256 != physical.get("log_sha256")
            or physical_log.size_bytes != physical.get("log_bytes")
            or physical.get("output_digest") != "sha256:" + physical_log.sha256
        ):
            raise EvidenceError("saturation audit physical log binding mismatch")
        run_relative = _external_relative_path(physical.get("record_path"))
        run_path = audit_directory.joinpath(*run_relative.split("/"))
        run_read = load_external_json_stable(run_path, root=evidence_root)
        if (
            run_read.sha256 != physical.get("record_sha256")
            or run_read.size_bytes != physical.get("record_bytes")
        ):
            raise EvidenceError("saturation audit physical run digest/size mismatch")
        run = validate_saturation_evidence(
            run_read.value,
            candidate_binding=candidate,
            source_path=run_path,
            evidence_root=Path(evidence_root),
        )
        fresh_control_state = _validate_saturation_audit_fresh_control_state(
            physical.get("fresh_control_state"),
            candidate=candidate,
            run=run,
        )
        current_recipe = deepcopy(fresh_control_state["physical_corpus_recipe"])
        if physical_corpus_recipe is None:
            physical_corpus_recipe = current_recipe
        elif current_recipe != physical_corpus_recipe:
            raise EvidenceError(
                "saturation audit physical-corpus recipe changed between fresh states"
            )
        nested_attestations.append(
            _validate_producer_attestation(
                run,
                candidate=candidate,
                expected_role="physical-scale",
                expected_platform=_release_evidence_platform(run),
            )
        )
        run_digest = run["result_digest"]
        run_id = run["invocation"]["invocation_id"]
        run_completed_at = parse_timestamp(run["invocation"]["completed_at"])
        _validate_nested_completion(run_completed_at, outer_completed_at)
        if nested_completion_times is not None:
            nested_completion_times.append(run_completed_at)
        fresh_state_binding = canonical_digest(
            {
                "fresh_control_state": fresh_control_state,
                "physical_result_digest": run_digest,
                "physical_invocation_id": run_id,
            }
        )
        if (
            physical.get("result_digest") != run_digest
            or physical.get("invocation_id") != run_id
            or run_digest in run_digests
            or run_id in run_ids
            or run_relative in run_paths
            or fresh_state_binding in fresh_state_bindings
            or physical.get("exit_code") != 0
            or physical.get("files") != 100_000
            or physical.get("queries") != 600
            or physical.get("artifact_binding_digest")
            != run["artifact_binding"]["binding_digest"]
            or physical.get("platform_binding_digest")
            != run["artifact_binding"]["platform"]["binding_digest"]
            or physical.get("immutable_snapshot_creditable") is not True
        ):
            raise EvidenceError("saturation audit physical run is duplicate, drifted, or incomplete")
        run_digests.add(run_digest)
        run_ids.add(run_id)
        run_paths.add(run_relative)
        fresh_state_bindings.add(fresh_state_binding)
        zero_new = (
            row.get("new_finding_classes") == 0
            and row.get("silent_truncations") == 0
            and row.get("unexpected_accepts") == 0
            and row.get("unexpected_crashes") == 0
            and row.get("unexpected_rejects") == 0
            and row.get("finding_fingerprints") == []
        )
        before = streak
        streak = streak + 1 if zero_new else 0
        total_new += row.get("new_finding_classes", 0)
        if (
            row.get("zero_new_streak_before") != before
            or row.get("zero_new_streak_after") != streak
            or row.get("status") != ("zero-new" if zero_new else "findings")
            or (zero_new and row.get("streak_reset_reason") is not None)
        ):
            raise EvidenceError("saturation audit zero-new streak cannot be recomputed")
    _validate_saturation_audit_producer_boundary(
        outer_attestation,
        nested_attestations,
        trust_configuration=trust_configuration,
    )
    if attestation_graph is not None:
        attestation_graph.extend(deepcopy(nested_attestations))
    if (
        streak != 3
        or verification.get("zero_new_iterations") != streak
        or verification.get("consecutive_full_zero_new") != streak
        or verification.get("new_findings") != total_new
        or total_new != 0
    ):
        raise EvidenceError("saturation audit does not close three physical zero-new runs")
    return deepcopy(dict(verification))


def _validate_distribution_record_binding(value: Any) -> None:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"path", "sha256", "bytes"}
        or not isinstance(value.get("path"), str)
        or not value["path"].endswith(".dist-info/RECORD")
        or not _valid_digest(value.get("sha256"))
        or not isinstance(value.get("bytes"), int)
        or isinstance(value.get("bytes"), bool)
        or value["bytes"] < 1
    ):
        raise EvidenceError("installed distribution RECORD binding is invalid")


def _validate_installed_environment_observation(
    value: Any,
    *,
    candidate: Mapping[str, Any],
    expected_platform: str,
) -> dict[str, Any]:
    fields = {
        "python",
        "platform",
        "sqlite_version",
        "site_packages",
        "promin",
        "console_wrapper",
        "transitive_distributions",
        "transitive_distribution_digest",
        "sbom",
        "license_closure",
        "build_backend",
        "observation_digest",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise EvidenceError("installed environment observation shape is invalid")
    python_identity = value.get("python")
    if (
        not isinstance(python_identity, Mapping)
        or set(python_identity)
        != {
            "executable",
            "executable_sha256",
            "base_executable",
            "base_executable_sha256",
            "implementation",
            "version",
            "abi_tag",
            "prefix",
            "base_prefix",
        }
        or not all(
            isinstance(python_identity.get(field), str) and python_identity[field]
            for field in (
                "executable",
                "base_executable",
                "implementation",
                "version",
                "abi_tag",
                "prefix",
                "base_prefix",
            )
        )
        or not _valid_digest(python_identity.get("executable_sha256"))
        or not _valid_digest(python_identity.get("base_executable_sha256"))
        or python_identity["prefix"] == python_identity["base_prefix"]
    ):
        raise EvidenceError("installed interpreter identity is invalid")
    platform_identity = value.get("platform")
    if (
        not isinstance(platform_identity, Mapping)
        or set(platform_identity) != {"system", "machine", "release", "sys_platform", "tags"}
        or _normalized_evidence_platform(platform_identity.get("system")) != expected_platform
        or not all(
            isinstance(platform_identity.get(field), str) and platform_identity[field]
            for field in ("system", "machine", "release", "sys_platform")
        )
        or not isinstance(platform_identity.get("tags"), list)
        or not platform_identity["tags"]
        or len(platform_identity["tags"]) > 64
        or any(not isinstance(tag, str) or not tag for tag in platform_identity["tags"])
    ):
        raise EvidenceError("installed platform/ABI tag observation is invalid")
    if not isinstance(value.get("sqlite_version"), str) or not value["sqlite_version"]:
        raise EvidenceError("installed SQLite identity is invalid")
    executable_path = _normalized_observed_runtime_path(
        python_identity["executable"],
        expected_platform=expected_platform,
        label="venv executable",
    )
    prefix_path = _normalized_observed_runtime_path(
        python_identity["prefix"],
        expected_platform=expected_platform,
        label="venv prefix",
    )
    base_executable_path = _normalized_observed_runtime_path(
        python_identity["base_executable"],
        expected_platform=expected_platform,
        label="base executable",
    )
    base_prefix_path = _normalized_observed_runtime_path(
        python_identity["base_prefix"],
        expected_platform=expected_platform,
        label="base prefix",
    )
    if prefix_path == base_prefix_path or not executable_path.startswith(prefix_path + "/"):
        raise EvidenceError("installed interpreter is outside its exact venv prefix")
    if not base_executable_path.startswith(base_prefix_path + "/"):
        raise EvidenceError("installed base interpreter is outside its base prefix")
    promin_identity = value.get("promin")
    if (
        not isinstance(promin_identity, Mapping)
        or set(promin_identity)
        != {
            "version",
            "module_file",
            "module_sha256",
            "record",
            "installed_files",
            "installed_files_digest",
            "installed_file_count",
        }
        or promin_identity.get("version") != candidate["version"]
        or not isinstance(promin_identity.get("module_file"), str)
        or not promin_identity["module_file"]
        or not _valid_digest(promin_identity.get("module_sha256"))
        or not isinstance(promin_identity.get("installed_files"), list)
        or not promin_identity["installed_files"]
        or promin_identity.get("installed_file_count") != len(promin_identity["installed_files"])
        or promin_identity.get("installed_files_digest")
        != canonical_digest(promin_identity["installed_files"])
    ):
        raise EvidenceError("installed promin tree observation is invalid")
    if not isinstance(value.get("site_packages"), str) or not value["site_packages"]:
        raise EvidenceError("installed site-packages identity is invalid")
    _validate_distribution_record_binding(promin_identity.get("record"))
    installed_paths: list[str] = []
    for row in promin_identity["installed_files"]:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"path", "sha256", "bytes"}
            or not isinstance(row.get("path"), str)
            or not row["path"]
            or not _valid_digest(row.get("sha256"))
            or not isinstance(row.get("bytes"), int)
            or isinstance(row.get("bytes"), bool)
            or row["bytes"] < 0
        ):
            raise EvidenceError("installed promin file tree row is invalid")
        installed_paths.append(row["path"])
    if installed_paths != sorted(set(installed_paths), key=lambda item: item.encode("utf-8")):
        raise EvidenceError("installed promin file tree is duplicate or non-canonical")
    module_rows = [
        row
        for row in promin_identity["installed_files"]
        if row["path"].replace("\\", "/").endswith("promin/__init__.py")
    ]
    if (
        len(module_rows) != 1
        or module_rows[0]["sha256"] != promin_identity["module_sha256"]
        or value["site_packages"].replace("\\", "/").rstrip("/") + "/"
        not in promin_identity["module_file"].replace("\\", "/")
    ):
        raise EvidenceError("installed promin import is not bound to the observed installed tree")
    wrapper = value.get("console_wrapper")
    if (
        not isinstance(wrapper, Mapping)
        or set(wrapper) != {"path", "sha256", "bytes"}
        or not isinstance(wrapper.get("path"), str)
        or not wrapper["path"]
        or not _valid_digest(wrapper.get("sha256"))
        or not isinstance(wrapper.get("bytes"), int)
        or isinstance(wrapper.get("bytes"), bool)
        or wrapper["bytes"] < 1
    ):
        raise EvidenceError("installed console wrapper observation is invalid")
    distributions = value.get("transitive_distributions")
    if (
        not isinstance(distributions, list)
        or not distributions
        or len(distributions) > 256
        or value.get("transitive_distribution_digest") != canonical_digest(distributions)
    ):
        raise EvidenceError("installed transitive distribution closure is invalid")
    names: list[str] = []
    distribution_by_name: dict[str, Mapping[str, Any]] = {}
    for row in distributions:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"name", "version", "record", "requires", "license"}
            or not all(isinstance(row.get(field), str) and row[field] for field in ("name", "version", "license"))
            or not isinstance(row.get("requires"), list)
            or row["requires"] != sorted(row["requires"])
        ):
            raise EvidenceError("installed transitive distribution row is invalid")
        _validate_distribution_record_binding(row.get("record"))
        names.append(row["name"])
        distribution_by_name[row["name"]] = row
    if names != sorted(set(names)) or "promin" not in names:
        raise EvidenceError("installed transitive distribution identities are not exact")
    if distribution_by_name["promin"]["record"] != promin_identity["record"]:
        raise EvidenceError("installed promin RECORD differs across the observation")
    sbom = value.get("sbom")
    if (
        not isinstance(sbom, Mapping)
        or set(sbom) != {"format", "components", "digest"}
        or sbom.get("format") != "promin-spdx-lite-v1"
        or not isinstance(sbom.get("components"), list)
        or sbom.get("digest") != canonical_digest(sbom["components"])
    ):
        raise EvidenceError("installed SBOM closure is invalid")
    expected_components = [
        {
            "name": row["name"],
            "version": row["version"],
            "record_sha256": row["record"]["sha256"],
        }
        for row in distributions
    ]
    if sbom["components"] != expected_components:
        raise EvidenceError("installed SBOM does not project the observed distributions")
    licenses = value.get("license_closure")
    if (
        not isinstance(licenses, Mapping)
        or set(licenses) != {"entries", "complete", "digest"}
        or licenses.get("complete") is not True
        or not isinstance(licenses.get("entries"), list)
        or licenses.get("digest") != canonical_digest(licenses["entries"])
    ):
        raise EvidenceError("installed license closure is incomplete")
    expected_licenses = [
        {"name": row["name"], "version": row["version"], "license": row["license"]}
        for row in distributions
    ]
    if licenses["entries"] != expected_licenses:
        raise EvidenceError("installed license closure does not project the observed distributions")
    build_backend = value.get("build_backend")
    if (
        not isinstance(build_backend, Mapping)
        or set(build_backend) != {"name", "distribution", "version", "record_sha256"}
        or build_backend.get("name") != "setuptools.build_meta"
        or build_backend.get("distribution") != "setuptools"
        or not isinstance(build_backend.get("version"), str)
        or not build_backend["version"]
        or not _valid_digest(build_backend.get("record_sha256"))
    ):
        raise EvidenceError("installed build backend closure is invalid")
    setuptools_distribution = distribution_by_name.get("setuptools")
    if (
        setuptools_distribution is None
        or build_backend["version"] != setuptools_distribution["version"]
        or build_backend["record_sha256"] != setuptools_distribution["record"]["sha256"]
    ):
        raise EvidenceError("installed build backend differs from its observed distribution")
    identity = {key: deepcopy(item) for key, item in value.items() if key != "observation_digest"}
    if value.get("observation_digest") != canonical_digest(identity):
        raise EvidenceError("installed environment observation digest mismatch")
    return deepcopy(dict(value))


def validate_platform_verification(
    verification: Mapping[str, Any],
    *,
    candidate_binding: Mapping[str, Any],
    expected_platform: str,
) -> dict[str, Any]:
    """Recompute the exact clean-install and command predicates for one platform."""

    candidate = validate_standard_release_candidate_binding(candidate_binding)
    if expected_platform not in {"linux", "windows"}:
        raise EvidenceError("platform evidence role is invalid")
    if (
        not isinstance(verification, Mapping)
        or set(verification) != _PLATFORM_VERIFICATION_FIELDS
        or verification.get("record_type") != "PlatformVerificationResult"
        or verification.get("status") != "pass"
        or verification.get("candidate_binding_digest")
        != candidate["candidate_binding_digest"]
        or verification.get("platform") != expected_platform
        or verification.get("exact_candidate_verified") is not True
        or verification.get("archive_sha256") != candidate["archive_sha256"]
        or verification.get("archive_bytes") != candidate["archive_bytes"]
        or verification.get("portable_implementation_closure_digest")
        != candidate["portable_implementation_closure_digest"]
        or not _valid_digest(verification.get("observed_environment_closure_digest"))
        or verification.get("install_mode") != "online-clean"
        or verification.get("installed_command_verified") is not True
        or verification.get("product_acceptance_pass") is not False
        or verification.get("product_public_approval") != "not_approved"
    ):
        raise EvidenceError("PlatformVerificationResult shape or candidate binding is invalid")
    identity = verification.get("platform_identity")
    if (
        not isinstance(identity, Mapping)
        or set(identity) != _PLATFORM_IDENTITY_FIELDS
        or identity.get("platform") != expected_platform
        or not all(
            isinstance(identity.get(field), str) and identity[field]
            for field in (
                "machine",
                "platform_release",
                "sys_platform",
                "python_version",
                "python_implementation",
                "python_executable",
                "python_abi_tag",
            )
        )
        or not _valid_digest(identity.get("python_executable_sha256"))
        or not isinstance(identity.get("platform_tags"), list)
        or not identity["platform_tags"]
        or len(identity["platform_tags"]) > 64
        or any(not isinstance(tag, str) or not tag for tag in identity["platform_tags"])
    ):
        raise EvidenceError("PlatformVerificationResult platform identity is invalid")
    _validate_release_evidence_envelope(
        verification,
        candidate=candidate,
        expected_tool_path="tools/promin_package.py",
        expected_operation="verify-platform",
        expected_role=expected_platform,
        expected_platform=expected_platform,
    )
    if verification["invocation"]["platform_binding_digest"] != canonical_digest(dict(identity)):
        raise EvidenceError("platform verification invocation binds another platform identity")
    installation = verification.get("installation")
    if (
        not isinstance(installation, Mapping)
        or set(installation) != _PLATFORM_INSTALLATION_FIELDS
        or installation.get("environment") != "clean-venv"
        or installation.get("installation_performed") is not True
        or installation.get("nested_venv_created") is not True
        or installation.get("runtime_dependency_source") != "online-index"
        or installation.get("build_dependency_source") != "online-index-explicit"
        or installation.get("network_disabled") is not False
        or not isinstance(installation.get("declared_python_requirement"), str)
    ):
        raise EvidenceError("platform verification did not prove an online-clean environment")
    observed = _validate_installed_environment_observation(
        installation.get("installed_environment_observation"),
        candidate=candidate,
        expected_platform=expected_platform,
    )
    expected_identity = {
        "platform": observed["platform"]["system"],
        "machine": observed["platform"]["machine"],
        "platform_release": observed["platform"]["release"],
        "sys_platform": observed["platform"]["sys_platform"],
        "platform_tags": observed["platform"]["tags"],
        "python_version": observed["python"]["version"],
        "python_implementation": observed["python"]["implementation"],
        "python_executable": observed["python"]["executable"],
        "python_executable_sha256": observed["python"]["executable_sha256"],
        "python_abi_tag": observed["python"]["abi_tag"],
    }
    if (
        dict(identity) != expected_identity
        or verification["observed_environment_closure_digest"] != observed["observation_digest"]
    ):
        raise EvidenceError("platform identity is not derived from the installed environment")
    distribution = installation.get("installed_distribution")
    if (
        not isinstance(distribution, Mapping)
        or set(distribution) != {"name", "version", "runtime_version"}
        or distribution.get("name") != "promin"
        or distribution.get("version") != candidate["version"]
        or distribution.get("runtime_version") != candidate["version"]
    ):
        raise EvidenceError("installed distribution identity differs from the exact candidate")
    console = installation.get("console_script")
    if (
        not isinstance(console, Mapping)
        or set(console) != _PLATFORM_CONSOLE_FIELDS
        or console.get("present") is not True
        or console.get("declared") is not True
        or console.get("installed_wrapper_checked") is not True
        or console.get("source_module_invoked") is not False
        or not isinstance(console.get("path"), str)
        or not console["path"]
        or not _valid_digest(console.get("sha256"))
        or not isinstance(console.get("size_bytes"), int)
        or isinstance(console.get("size_bytes"), bool)
        or console["size_bytes"] <= 0
        or (expected_platform == "linux" and console.get("posix_execute_bits") is not True)
        or (expected_platform == "windows" and console.get("posix_execute_bits") is not None)
    ):
        raise EvidenceError("installed console-script identity is incomplete")
    if (
        console["path"] != observed["console_wrapper"]["path"]
        or console["sha256"] != observed["console_wrapper"]["sha256"]
        or console["size_bytes"] != observed["console_wrapper"]["bytes"]
    ):
        raise EvidenceError("installed console-script differs from the nested observation")
    commands = installation.get("command_invocations")
    expected_commands = [
        "--help",
        "init --help",
        "doctor --help",
        "status --help",
        "next --help",
        "validate --help",
        "continue --help",
    ]
    if not isinstance(commands, list) or [item.get("command") for item in commands if isinstance(item, Mapping)] != expected_commands:
        raise EvidenceError("installed command invocation set is incomplete or reordered")
    for command in commands:
        if (
            not isinstance(command, Mapping)
            or set(command) != _PLATFORM_COMMAND_FIELDS
            or command.get("returncode") != 0
            or not _valid_digest(command.get("argv_digest"))
            or not _valid_digest(command.get("stdout_sha256"))
            or not _valid_digest(command.get("stderr_sha256"))
            or any(
                not isinstance(command.get(field), int)
                or isinstance(command.get(field), bool)
                or command[field] < 0
                or command[field] > 1024 * 1024
                for field in ("stdout_bytes", "stderr_bytes")
            )
        ):
            raise EvidenceError("installed command invocation evidence is invalid")
    closure = installation.get("dependency_closure")
    if not isinstance(closure, Mapping) or set(closure) != {
        "declared_runtime",
        "declared_build",
        "resolved_runtime",
        "closure_check",
        "transitive_distributions",
        "transitive_distribution_digest",
        "dependency_artifact_digest",
        "digest",
    }:
        raise EvidenceError("platform dependency closure shape is invalid")
    closure_identity = {key: deepcopy(value) for key, value in closure.items() if key != "digest"}
    if (
        closure.get("closure_check") != "pass"
        or not isinstance(closure.get("declared_runtime"), list)
        or not isinstance(closure.get("declared_build"), list)
        or not isinstance(closure.get("resolved_runtime"), Mapping)
        or set(closure["resolved_runtime"]) != {"cryptography", "jsonschema", "pypdf"}
        or closure.get("transitive_distributions") != observed["transitive_distributions"]
        or closure.get("transitive_distribution_digest")
        != observed["transitive_distribution_digest"]
        or not _valid_digest(closure.get("dependency_artifact_digest"))
        or closure.get("digest") != canonical_digest(closure_identity)
    ):
        raise EvidenceError("platform dependency closure cannot be recomputed")
    for name, dependency in closure["resolved_runtime"].items():
        if (
            not isinstance(dependency, Mapping)
            or set(dependency) != {"requirement", "version"}
            or not all(isinstance(value, str) and value for value in dependency.values())
        ):
            raise EvidenceError(f"resolved dependency identity is invalid: {name}")
    pip_report = installation.get("pip_report")
    if (
        not isinstance(pip_report, Mapping)
        or set(pip_report) != {"reports", "report_count", "artifact_digest"}
        or not isinstance(pip_report.get("reports"), list)
        or len(pip_report["reports"]) != 2
        or pip_report.get("report_count") != len(pip_report["reports"])
        or pip_report.get("artifact_digest") != canonical_digest(pip_report["reports"])
        or closure["dependency_artifact_digest"] != pip_report.get("artifact_digest")
    ):
        raise EvidenceError("pip installation report binding is invalid")
    report_roles: list[str] = []
    for report in pip_report["reports"]:
        if (
            not isinstance(report, Mapping)
            or set(report)
            != {
                "role",
                "sha256",
                "bytes",
                "pip_version",
                "install_count",
                "artifacts",
                "artifact_digest",
            }
            or report.get("role") not in {"build-requirements", "candidate-install"}
            or not _valid_digest(report.get("sha256"))
            or not isinstance(report.get("bytes"), int)
            or isinstance(report.get("bytes"), bool)
            or report["bytes"] < 1
            or not isinstance(report.get("pip_version"), str)
            or not report["pip_version"]
            or not isinstance(report.get("artifacts"), list)
            or not report["artifacts"]
            or report.get("install_count") != len(report["artifacts"])
            or report.get("artifact_digest") != canonical_digest(report["artifacts"])
        ):
            raise EvidenceError("pip installation report row is invalid")
        report_roles.append(report["role"])
        artifact_order: list[tuple[str, str]] = []
        for artifact in report["artifacts"]:
            if (
                not isinstance(artifact, Mapping)
                or set(artifact) != {"name", "version", "is_direct", "hashes"}
                or not isinstance(artifact.get("name"), str)
                or not artifact["name"]
                or not isinstance(artifact.get("version"), str)
                or not artifact["version"]
                or not isinstance(artifact.get("is_direct"), bool)
                or not isinstance(artifact.get("hashes"), list)
                or artifact["hashes"] != sorted(set(artifact["hashes"]))
                or any(not isinstance(item, str) or ":" not in item for item in artifact["hashes"])
            ):
                raise EvidenceError("pip installation artifact row is invalid")
            artifact_order.append((artifact["name"], artifact["version"]))
        if artifact_order != sorted(artifact_order):
            raise EvidenceError("pip installation artifact rows are non-canonical")
    if report_roles != ["build-requirements", "candidate-install"]:
        raise EvidenceError("pip installation report roles are incomplete or reordered")
    if (
        installation.get("sbom") != observed["sbom"]
        or installation.get("license_closure") != observed["license_closure"]
        or installation.get("build_backend") != observed["build_backend"]
    ):
        raise EvidenceError("platform installation projections differ from the nested observation")
    return deepcopy(dict(verification))


def validate_human_document_verification(
    verification: Mapping[str, Any],
    *,
    candidate_binding: Mapping[str, Any],
    candidate_document_members: Iterable[Mapping[str, Any]] = (),
    source_path: Path,
    evidence_root: Path,
) -> dict[str, Any]:
    """Validate exact PDF identity, extraction, rebuild, and visual-review evidence."""

    candidate = validate_standard_release_candidate_binding(candidate_binding)
    if (
        not isinstance(verification, Mapping)
        or set(verification) != _HUMAN_DOCUMENT_VERIFICATION_FIELDS
        or verification.get("record_type") != "HumanDocumentVerification"
        or verification.get("status") != "pass"
        or verification.get("candidate_binding_digest")
        != candidate["candidate_binding_digest"]
        or verification.get("deterministic_rebuild") is not True
        or verification.get("product_acceptance_pass") is not False
        or not _valid_digest(verification.get("rebuild_digest"))
        or not _valid_digest(verification.get("generator_result_digest"))
        or not _valid_digest(verification.get("render_manifest_digest"))
    ):
        raise EvidenceError("HumanDocumentVerification shape or binding is invalid")
    _validate_release_evidence_envelope(
        verification,
        candidate=candidate,
        expected_tool_path="tools/promin_package.py",
        expected_operation="build-document-evidence",
        expected_role="human-documents",
        expected_platform=_release_evidence_platform(verification),
    )
    documents = verification.get("documents")
    if not isinstance(documents, list) or len(documents) != 4:
        raise EvidenceError("HumanDocumentVerification must bind exactly four PDFs")
    paths: set[str] = set()
    total_pages = 0
    total_characters = 0
    rebuild_rows: list[dict[str, Any]] = []
    for document in documents:
        if not isinstance(document, Mapping) or set(document) != _HUMAN_DOCUMENT_FIELDS:
            raise EvidenceError("HumanDocumentVerification document shape is invalid")
        path = _external_relative_path(document.get("path"))
        if path in paths or path not in _EXPECTED_HUMAN_DOCUMENT_PATHS:
            raise EvidenceError("HumanDocumentVerification PDF set is not exact")
        paths.add(path)
        if not _valid_digest(document.get("sha256")):
            raise EvidenceError("HumanDocumentVerification PDF digest is invalid")
        for field in ("size_bytes", "page_count", "extracted_characters"):
            value = document.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise EvidenceError(f"HumanDocumentVerification {field} is invalid")
        if document.get("blank_pages") != [] or document.get("extraction_errors") != []:
            raise EvidenceError("HumanDocumentVerification contains blank pages or extraction errors")
        total_pages += document["page_count"]
        total_characters += document["extracted_characters"]
        rebuild_rows.append(
            {
                "path": path,
                "sha256": document["sha256"],
                "size_bytes": document["size_bytes"],
                "page_count": document["page_count"],
            }
        )
    if paths != set(_EXPECTED_HUMAN_DOCUMENT_PATHS):
        raise EvidenceError("HumanDocumentVerification PDF set is incomplete")
    member_rows = list(candidate_document_members)
    member_by_path = {
        item.get("path"): item for item in member_rows if isinstance(item, Mapping)
    }
    if set(member_by_path) != set(_EXPECTED_HUMAN_DOCUMENT_PATHS):
        raise EvidenceError("exact candidate PDF member set is incomplete")
    for document in documents:
        member = member_by_path[document["path"]]
        if (
            member.get("sha256") != document["sha256"]
            or member.get("bytes") != document["size_bytes"]
            or member.get("page_count") != document["page_count"]
        ):
            raise EvidenceError("HumanDocumentVerification differs from the exact candidate ZIP")
    if verification.get("rebuild_digest") != canonical_digest(
        sorted(rebuild_rows, key=lambda row: row["path"].encode("utf-8"))
    ):
        raise EvidenceError("HumanDocumentVerification deterministic rebuild digest mismatch")
    if verification.get("page_count") != total_pages:
        raise EvidenceError("HumanDocumentVerification page count mismatch")
    extraction = verification.get("extraction_diagnostics")
    if (
        not isinstance(extraction, Mapping)
        or set(extraction) != _HUMAN_EXTRACTION_FIELDS
        or extraction.get("documents_parsed") != 4
        or extraction.get("total_extracted_characters") != total_characters
        or extraction.get("blank_pages") != []
        or extraction.get("errors") != []
    ):
        raise EvidenceError("HumanDocumentVerification extraction diagnostics are invalid")
    visual = verification.get("visual_review_scope")
    if (
        not isinstance(visual, Mapping)
        or set(visual) != _HUMAN_VISUAL_REVIEW_FIELDS
        or visual.get("completed") is not True
        or visual.get("rendered_page_count") != total_pages
        or visual.get("pages_reviewed") != total_pages
        or visual.get("clipping_detected") is not False
        or visual.get("unreadable_text_detected") is not False
    ):
        raise EvidenceError("HumanDocumentVerification visual review is incomplete")
    _safe_id(visual.get("reviewer_id"))
    reviewed_at = parse_timestamp(visual.get("reviewed_at"))
    invocation_started_at = parse_timestamp(verification["invocation"]["started_at"])
    invocation_completed_at = parse_timestamp(verification["invocation"]["completed_at"])
    attestation_signed_at = parse_timestamp(
        verification["producer_attestation"]["signed_at"]
    )
    _validate_human_review_chronology(
        reviewed_at,
        invocation_started_at,
        invocation_completed_at,
        attestation_signed_at,
    )
    fonts = verification.get("font_bindings")
    if not isinstance(fonts, Mapping) or set(fonts) != {"regular", "bold", "italic", "mono"}:
        raise EvidenceError("HumanDocumentVerification font binding set is incomplete")
    for role, font in fonts.items():
        if (
            not isinstance(font, Mapping)
            or set(font) != {"bytes", "pdf_font_name", "sha256"}
            or not isinstance(font.get("bytes"), int)
            or font["bytes"] < 1
            or not isinstance(font.get("pdf_font_name"), str)
            or not font["pdf_font_name"]
            or not _valid_digest(font.get("sha256"))
        ):
            raise EvidenceError(f"HumanDocumentVerification font binding is invalid: {role}")
    render_environment = verification.get("render_environment")
    expected_environment_fields = {
        "generator_sha256",
        "reportlab_version",
        "python_version",
        "platform",
        "font_binding_digest",
    }
    if (
        not isinstance(render_environment, Mapping)
        or set(render_environment) != expected_environment_fields
        or render_environment.get("generator_sha256")
        != candidate["evidence_tool_digests"]["tools/generate_human.py"]
        or render_environment.get("font_binding_digest") != canonical_digest(dict(fonts))
        or not all(
            isinstance(render_environment.get(field), str)
            and render_environment[field]
            for field in ("reportlab_version", "python_version", "platform")
        )
    ):
        raise EvidenceError("HumanDocumentVerification render environment is invalid")
    if verification["invocation"]["platform_binding_digest"] != canonical_digest(
        dict(render_environment)
    ):
        raise EvidenceError("human document invocation binds another render environment")
    render_manifest = verification.get("render_manifest")
    if not isinstance(render_manifest, list) or len(render_manifest) != total_pages:
        raise EvidenceError("HumanDocumentVerification must resolve every rendered page")
    page_sets: dict[str, set[int]] = {path: set() for path in paths}
    image_paths: set[str] = set()
    for row in render_manifest:
        if not isinstance(row, Mapping) or set(row) != _HUMAN_RENDER_ROW_FIELDS:
            raise EvidenceError("HumanDocumentVerification render row shape is invalid")
        document_path = _external_relative_path(row.get("document_path"))
        image_path = _external_relative_path(row.get("image_path"))
        page = row.get("page")
        if (
            document_path not in page_sets
            or not isinstance(page, int)
            or isinstance(page, bool)
            or page < 1
            or page > member_by_path[document_path]["page_count"]
            or page in page_sets[document_path]
            or image_path in image_paths
        ):
            raise EvidenceError("HumanDocumentVerification render coverage is invalid")
        page_sets[document_path].add(page)
        image_paths.add(image_path)
        rendered = read_external_bytes_stable(
            source_path.parent.joinpath(*image_path.split("/")),
            root=evidence_root,
            max_bytes=32 * 1024 * 1024,
        )
        if (
            rendered.sha256 != row.get("image_sha256")
            or rendered.size_bytes != row.get("image_bytes")
            or not rendered.payload.startswith(b"\x89PNG\r\n\x1a\n")
        ):
            raise EvidenceError("HumanDocumentVerification rendered page identity is invalid")
    for path, pages in page_sets.items():
        if pages != set(range(1, member_by_path[path]["page_count"] + 1)):
            raise EvidenceError("HumanDocumentVerification all-page render coverage is incomplete")
    if verification.get("render_manifest_digest") != canonical_digest(render_manifest):
        raise EvidenceError("HumanDocumentVerification render manifest digest mismatch")
    if visual.get("render_manifest_digest") != verification["render_manifest_digest"]:
        raise EvidenceError("human visual review binds another render manifest")
    return deepcopy(dict(verification))


def _supplemental_matrix_bindings_by_id(
    value: Any,
) -> dict[str, Mapping[str, Any]]:
    if not isinstance(value, list):
        raise EvidenceError("CP314 supplemental lane bindings are absent")
    if any(
        not isinstance(row, Mapping)
        or set(row) != _STANDARD_EVIDENCE_SUPPLEMENTAL_FIELDS
        for row in value
    ):
        raise EvidenceError("CP314 supplemental lane binding shape is invalid")
    supplemental_ids = [row.get("lane_id") for row in value]
    if (
        supplemental_ids != sorted(_REQUIRED_SUPPLEMENTAL_MATRIX_LANES)
        or set(supplemental_ids) != _REQUIRED_SUPPLEMENTAL_MATRIX_LANES
    ):
        raise EvidenceError("CP314 supplemental lane set is not exact")
    return {str(row["lane_id"]): row for row in value}


def _validate_matrix_aggregate(
    binding: Any,
    supplemental_bindings: Any,
    *,
    candidate: Mapping[str, Any],
    evidence_root: Path,
    trust: Mapping[str, Any],
    authority_records: Mapping[str, Mapping[str, Any]],
    attestation_graph: list[dict[str, Any]],
    verification_time: datetime,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[datetime]]:
    if (
        not isinstance(binding, Mapping)
        or set(binding) != _STANDARD_EVIDENCE_MATRIX_FIELDS
    ):
        raise EvidenceError("platform matrix aggregate binding shape is invalid")
    supplemental_by_id = _supplemental_matrix_bindings_by_id(
        supplemental_bindings
    )
    matrix_path = _external_relative_path(binding.get("path"))
    if matrix_path != "matrix-current/platform-no-degradation-matrix.json":
        raise EvidenceError("platform matrix aggregate path is not canonical")
    matrix_read = load_external_json_stable(
        evidence_root.joinpath(*matrix_path.split("/")),
        root=evidence_root,
    )
    if (
        matrix_read.sha256 != binding.get("sha256")
        or matrix_read.size_bytes != binding.get("size_bytes")
    ):
        raise EvidenceError("platform matrix aggregate digest/size mismatch")
    matrix = matrix_read.value
    _validate_release_evidence_schema(
        "ProminPlatformNoDegradationMatrix",
        matrix,
    )
    if (
        set(matrix) != {*_MATRIX_IDENTITY_FIELDS, "matrix_digest"}
        or matrix.get("record_type") != "ProminPlatformNoDegradationMatrix"
        or matrix.get("standard_name") != "promin"
        or matrix.get("version") != standard_version()
        or matrix.get("version") != candidate.get("version")
        or matrix.get("candidate_binding_digest")
        != candidate.get("candidate_binding_digest")
        or matrix.get("archive_sha256") != candidate.get("archive_sha256")
        or matrix.get("archive_bytes") != candidate.get("archive_bytes")
        or matrix.get("trust_configuration_sha256") != canonical_digest(dict(trust))
        or matrix.get("lane_count") != 8
        or matrix.get("complete") is not True
        or matrix.get("semantic_validation_complete") is not True
        or matrix.get("unique_invocation_ids") is not True
        or matrix.get("unique_key_nonces") is not True
        or matrix.get("matrix_authoritative") is not False
        or matrix.get("pass_credit") is not False
        or matrix.get("acceptance_pass") is not False
        or matrix.get("product_acceptance_pass") is not False
        or matrix.get("product_public_approval") != "not_approved"
    ):
        raise EvidenceError("platform matrix aggregate identity or false-only flags drift")
    matrix_identity = {
        field: deepcopy(matrix[field]) for field in sorted(_MATRIX_IDENTITY_FIELDS)
    }
    if matrix.get("matrix_digest") != canonical_digest(matrix_identity):
        raise EvidenceError("platform matrix aggregate digest is not derived")
    for field in (
        "record_type",
        "matrix_digest",
        "lane_count",
        "matrix_authoritative",
        "pass_credit",
        "acceptance_pass",
        "product_acceptance_pass",
        "product_public_approval",
    ):
        if binding.get(field) != matrix.get(field):
            raise EvidenceError("platform matrix aggregate manifest binding drift")

    lanes = matrix.get("lanes")
    expected_lane_ids = sorted(_REQUIRED_MATRIX_LANES)
    if (
        not isinstance(lanes, list)
        or len(lanes) != 8
        or any(not isinstance(row, Mapping) or set(row) != _MATRIX_ROW_FIELDS for row in lanes)
        or [row.get("lane_id") for row in lanes] != expected_lane_ids
    ):
        raise EvidenceError("platform matrix aggregate lane set is not exact")
    invocation_ids: set[str] = set()
    key_nonces: set[tuple[str, str]] = set()
    supplemental_resolved: list[dict[str, Any]] = []
    supplemental_completion_times: list[datetime] = []
    for row in lanes:
        lane_id = row["lane_id"]
        spec = _REQUIRED_MATRIX_LANES[lane_id]
        path_text = _external_relative_path(row.get("path"))
        if (
            path_text != spec["path"]
            or row.get("record_type") != spec["record_type"]
            or row.get("status") != "pass"
            or row.get("os") != spec["platform"]
            or not isinstance(row.get("python_version"), str)
            or not row["python_version"].startswith(spec["python_minor"] + ".")
            or str(row.get("python_implementation")).lower() != "cpython"
            or not isinstance(row.get("python_abi"), str)
            or not row["python_abi"].startswith(spec["abi_prefix"])
            or row.get("install_mode") != spec["install_mode"]
            or row.get("evidence_role") != spec["evidence_role"]
            or row.get("semantic_valid") is not True
            or not _valid_digest(row.get("sha256"))
            or not isinstance(row.get("size_bytes"), int)
            or isinstance(row.get("size_bytes"), bool)
            or row["size_bytes"] < 1
            or not _valid_digest(row.get("result_digest"))
            or not _valid_digest(row.get("attestation_digest"))
        ):
            raise EvidenceError(f"platform matrix lane identity is invalid: {lane_id}")
        lane_read = load_external_json_stable(
            evidence_root.joinpath(*path_text.split("/")),
            root=evidence_root,
        )
        if (
            lane_read.sha256 != row["sha256"]
            or lane_read.size_bytes != row["size_bytes"]
        ):
            raise EvidenceError(f"platform matrix lane digest/size mismatch: {lane_id}")
        record = lane_read.value
        if (
            record.get("record_type") != spec["record_type"]
            or record.get("status") != "pass"
            or record.get("candidate_binding_digest")
            != candidate.get("candidate_binding_digest")
            or record.get("result_digest") != row["result_digest"]
            or record.get("product_acceptance_pass") is not False
        ):
            raise EvidenceError(f"platform matrix lane record drift: {lane_id}")
        _validate_release_evidence_schema(spec["record_type"], record)
        if spec["record_type"] == "PlatformVerificationResult":
            validated_record = validate_platform_verification(
                record,
                candidate_binding=candidate,
                expected_platform=spec["platform"],
            )
            identity = validated_record["platform_identity"]
            runtime_version = identity["python_version"]
            runtime_implementation = identity["python_implementation"]
            runtime_abi = identity["python_abi_tag"]
        else:
            validated_record = validate_no_degradation_result(
                record,
                candidate_binding=candidate,
                expected_platform=spec["platform"],
            )
            identity = validated_record["artifact_binding"]["platform"]
            runtime_version = identity["python_version"]
            runtime_implementation = identity["python_implementation"]
            runtime_abi = validated_record["tests"]["installed_environment"][
                "installed_environment_observation"
            ]["python"]["abi_tag"]
        if (
            runtime_version != row["python_version"]
            or str(runtime_implementation).lower() != row["python_implementation"]
            or runtime_abi != row["python_abi"]
        ):
            raise EvidenceError(f"platform matrix lane runtime identity drift: {lane_id}")
        attestation = _validate_producer_attestation(
            validated_record,
            candidate=candidate,
            expected_role=spec["evidence_role"],
            expected_platform=spec["platform"],
        )
        _validate_evidence_attestation_trust(
            attestation,
            trust=trust,
            expected_role=spec["evidence_role"],
            expected_platform=spec["platform"],
        )
        invocation = validated_record["invocation"]
        started_at = parse_timestamp(invocation["started_at"])
        completed_at = parse_timestamp(invocation["completed_at"])
        signed_at = parse_timestamp(attestation["signed_at"])
        if not started_at <= completed_at == signed_at:
            raise EvidenceError(f"platform matrix lane chronology is invalid: {lane_id}")
        if completed_at > verification_time + timedelta(
            seconds=_STANDARD_DECISION_FUTURE_SKEW_SECONDS
        ):
            raise EvidenceError(
                f"platform matrix lane exceeds bounded verifier clock skew: {lane_id}"
            )
        if (
            row.get("key_id") != attestation["key_id"]
            or row.get("subject_id") != attestation["producer_id"]
            or row.get("attestation_digest") != attestation["signed_claim_digest"]
            or row.get("invocation_id") != invocation["invocation_id"]
            or row.get("nonce") != attestation["nonce"]
        ):
            raise EvidenceError(f"platform matrix lane attestation drift: {lane_id}")
        invocation_id = invocation["invocation_id"]
        key_nonce = (attestation["key_id"], attestation["nonce"])
        if invocation_id in invocation_ids or key_nonce in key_nonces:
            raise EvidenceError("platform matrix lane invocation or nonce replay")
        invocation_ids.add(invocation_id)
        key_nonces.add(key_nonce)

        if lane_id in _REQUIRED_SUPPLEMENTAL_MATRIX_LANES:
            supplemental = supplemental_by_id[lane_id]
            expected_supplemental = {
                "lane_id": lane_id,
                "path": path_text,
                "sha256": lane_read.sha256,
                "size_bytes": lane_read.size_bytes,
                "record_type": spec["record_type"],
                "status": "pass",
                "candidate_binding_digest": candidate["candidate_binding_digest"],
                "result_digest": validated_record["result_digest"],
                "evidence_role": spec["evidence_role"],
                "producer_attestation_digest": canonical_digest(attestation),
            }
            if dict(supplemental) != expected_supplemental:
                raise EvidenceError(f"CP314 supplemental lane binding drift: {lane_id}")
            attestation_graph.append(attestation)
            supplemental_completion_times.append(completed_at)
            supplemental_resolved.append(deepcopy(expected_supplemental))
        else:
            authority = authority_records.get(spec["evidence_role"])
            if (
                not isinstance(authority, Mapping)
                or authority.get("path") != path_text
                or authority.get("sha256") != lane_read.sha256
                or authority.get("size_bytes") != lane_read.size_bytes
                or authority.get("result_digest") != validated_record["result_digest"]
                or authority.get("producer_attestation_digest")
                != canonical_digest(attestation)
                or authority.get("invocation_id") != invocation_id
            ):
                raise EvidenceError(f"CP313 matrix lane differs from authority role: {lane_id}")

    return (
        {
            "path": matrix_path,
            "sha256": matrix_read.sha256,
            "size_bytes": matrix_read.size_bytes,
            "matrix_digest": matrix["matrix_digest"],
            "lane_count": 8,
            "matrix_authoritative": False,
            "pass_credit": False,
        },
        supplemental_resolved,
        supplemental_completion_times,
    )


def validate_standard_release_evidence_manifest(
    manifest: Mapping[str, Any],
    *,
    candidate_binding: Mapping[str, Any],
    evidence_root: Path | str,
    trust_configuration: Mapping[str, Any],
    candidate_document_members: Iterable[Mapping[str, Any]] = (),
    verification_time: datetime | str | None = None,
) -> dict[str, Any]:
    candidate = validate_standard_release_candidate_binding(candidate_binding)
    trust = _validate_trust_configuration(
        trust_configuration,
        require_complete_evidence_roles=True,
    )
    _validate_release_evidence_schema(
        "StandardReleaseTrustConfiguration",
        trust,
    )
    verified_at = _verification_time_utc(verification_time, "evidence manifest")
    if not isinstance(manifest, Mapping) or set(manifest) != _STANDARD_EVIDENCE_MANIFEST_FIELDS:
        raise EvidenceError("invalid StandardReleaseEvidenceManifest shape")
    _validate_release_evidence_schema(
        "StandardReleaseEvidenceManifest",
        manifest,
    )
    if (
        manifest.get("record_type") != "StandardReleaseEvidenceManifest"
        or manifest.get("standard_name") != "promin"
        or manifest.get("version") != candidate["version"]
        or manifest.get("candidate_binding_digest") != candidate["candidate_binding_digest"]
    ):
        raise EvidenceError("evidence manifest candidate identity mismatch")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or len(entries) != len(_REQUIRED_STANDARD_EVIDENCE):
        raise EvidenceError("evidence manifest entry set is invalid")
    manifest_identity = {
        field: deepcopy(manifest[field]) for field in _STANDARD_EVIDENCE_MANIFEST_IDENTITY_FIELDS
    }
    if manifest.get("evidence_manifest_digest") != canonical_digest(manifest_identity):
        raise EvidenceError("evidence manifest digest mismatch")

    root = _require_external_root(Path(evidence_root), None)
    if not root.is_dir():
        raise EvidenceError("evidence root must be a real directory")
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    seen_roles: dict[str, str] = {}
    attestation_graph: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    platform_records: dict[str, dict[str, Any]] = {}
    authority_records: dict[str, dict[str, Any]] = {}
    evidence_completed_times: list[datetime] = []
    for entry in entries:
        if not isinstance(entry, Mapping) or set(entry) != _STANDARD_EVIDENCE_ENTRY_FIELDS:
            raise EvidenceError("evidence manifest entry shape is invalid")
        evidence_id = _safe_id(entry.get("evidence_id"))
        role = entry.get("evidence_role")
        path_text = _external_relative_path(entry.get("path"))
        if not isinstance(role, str) or role not in _REQUIRED_STANDARD_EVIDENCE:
            raise EvidenceError("evidence role is not a required typed role")
        if evidence_id in seen_ids or path_text in seen_paths or role in seen_roles:
            raise EvidenceError("evidence manifest IDs, paths, and roles must be unique")
        seen_ids.add(evidence_id)
        seen_paths.add(path_text)
        seen_roles[role] = evidence_id
        if entry.get("record_type") != _REQUIRED_STANDARD_EVIDENCE[role]:
            raise EvidenceError("evidence role and record type disagree")
        if (
            entry.get("status") != "pass"
            or not _valid_digest(entry.get("sha256"))
            or not isinstance(entry.get("size_bytes"), int)
            or isinstance(entry.get("size_bytes"), bool)
            or entry["size_bytes"] < 1
        ):
            raise EvidenceError("required evidence is not a passing digest-bound record")
        if entry.get("candidate_binding_digest") != candidate["candidate_binding_digest"]:
            raise EvidenceError("evidence entry binds another candidate")
        predicates = entry.get("predicates")
        if not isinstance(predicates, list) or not predicates or len(predicates) > 64:
            raise EvidenceError("evidence predicates are missing or unbounded")
        resolved_path = root.joinpath(*path_text.split("/"))
        stable = load_external_json_stable(resolved_path, root=root)
        if (
            stable.sha256 != entry["sha256"]
            or stable.size_bytes != entry["size_bytes"]
        ):
            raise EvidenceError("evidence file digest/size mismatch")
        evidence = stable.value
        if (
            evidence.get("record_type") != entry["record_type"]
            or evidence.get("status") != entry["status"]
            or evidence.get("candidate_binding_digest") != candidate["candidate_binding_digest"]
        ):
            raise EvidenceError("evidence content does not match its manifest entry")
        invocation = evidence.get("invocation")
        if not isinstance(invocation, Mapping):
            raise EvidenceError("release evidence invocation is absent")
        started_at = parse_timestamp(invocation.get("started_at"))
        completed_at = parse_timestamp(invocation.get("completed_at"))
        if completed_at < started_at:
            raise EvidenceError("release evidence invocation time interval is invalid")
        if completed_at > verified_at + timedelta(
            seconds=_STANDARD_DECISION_FUTURE_SKEW_SECONDS
        ):
            raise EvidenceError("release evidence exceeds the bounded verifier clock skew")
        evidence_completed_times.append(completed_at)
        _validate_release_evidence_schema(entry["record_type"], evidence)
        if role in {"linux", "windows"}:
            platform_records[role] = validate_platform_verification(
                evidence,
                candidate_binding=candidate,
                expected_platform=role,
            )
        elif role == "physical-scale":
            validate_saturation_evidence(
                evidence,
                candidate_binding=candidate,
                source_path=resolved_path,
                evidence_root=root,
            )
        elif role == "saturation-audit":
            validate_saturation_audit(
                evidence,
                candidate_binding=candidate,
                source_path=resolved_path,
                evidence_root=root,
                trust_configuration=trust,
                attestation_graph=attestation_graph,
                nested_completion_times=evidence_completed_times,
            )
        elif role == "human-documents":
            validate_human_document_verification(
                evidence,
                candidate_binding=candidate,
                candidate_document_members=candidate_document_members,
                source_path=resolved_path,
                evidence_root=root,
            )
        elif role in {"linux-no-degradation", "windows-no-degradation"}:
            validate_no_degradation_result(
                evidence,
                candidate_binding=candidate,
                expected_platform=role.removesuffix("-no-degradation"),
            )
        attestation = _validate_producer_attestation(
            evidence,
            candidate=candidate,
            expected_role=role,
            expected_platform=_release_evidence_platform(evidence),
        )
        _validate_evidence_attestation_trust(
            attestation,
            trust=trust,
            expected_role=role,
            expected_platform=_release_evidence_platform(evidence),
        )
        signed_at = parse_timestamp(attestation["signed_at"])
        if signed_at != completed_at:
            raise EvidenceError("release evidence attestation time differs from completion")
        if signed_at > verified_at + timedelta(
            seconds=_STANDARD_DECISION_FUTURE_SKEW_SECONDS
        ):
            raise EvidenceError(
                "release evidence attestation exceeds the bounded verifier clock skew"
            )
        attestation_graph.append(attestation)
        seen_pointers: set[str] = set()
        supplied_predicates: dict[str, Any] = {}
        for predicate in predicates:
            if not isinstance(predicate, Mapping) or set(predicate) != {"pointer", "equals"}:
                raise EvidenceError("evidence predicate shape is invalid")
            pointer = predicate.get("pointer")
            if not isinstance(pointer, str) or pointer in seen_pointers:
                raise EvidenceError("evidence predicate pointers must be unique")
            seen_pointers.add(pointer)
            supplied_predicates[pointer] = predicate.get("equals")
            if _resolve_pointer(evidence, pointer) != predicate.get("equals"):
                raise EvidenceError(f"evidence semantic predicate failed: {evidence_id}:{pointer}")
        required_predicates = _REQUIRED_STANDARD_EVIDENCE_PREDICATES[role]
        missing_predicates = sorted(
            pointer
            for pointer, expected_value in required_predicates.items()
            if supplied_predicates.get(pointer, object()) != expected_value
        )
        if missing_predicates:
            raise EvidenceError(
                f"evidence role lacks required semantic predicates: {role}:"
                + ",".join(missing_predicates)
            )
        resolved.append(
            {
                "evidence_id": evidence_id,
                "evidence_role": role,
                "path": path_text,
                "sha256": entry["sha256"],
                "size_bytes": entry["size_bytes"],
                "record_type": entry["record_type"],
                "status": entry["status"],
                "predicates_verified": len(predicates),
                "producer_key_id": attestation["key_id"],
                "producer_attestation_digest": canonical_digest(attestation),
            }
        )
        authority_records[role] = {
            "path": path_text,
            "sha256": entry["sha256"],
            "size_bytes": entry["size_bytes"],
            "result_digest": evidence["result_digest"],
            "producer_attestation_digest": canonical_digest(attestation),
            "invocation_id": invocation["invocation_id"],
        }
    missing = sorted(set(_REQUIRED_STANDARD_EVIDENCE) - set(seen_roles))
    if missing:
        raise EvidenceError("evidence manifest lacks required roles: " + ", ".join(missing))
    matrix_resolved, supplemental_resolved, supplemental_completion_times = (
        _validate_matrix_aggregate(
            manifest.get("matrix_aggregate"),
            manifest.get("supplemental_lanes"),
            candidate=candidate,
            evidence_root=root,
            trust=trust,
            authority_records=authority_records,
            attestation_graph=attestation_graph,
            verification_time=verified_at,
        )
    )
    evidence_completed_times.extend(supplemental_completion_times)
    _validate_release_evidence_attestation_graph(
        attestation_graph,
        trust_configuration=trust,
    )
    recomputed_max_completed_at = _derived_max_evidence_completion(
        evidence_completed_times
    )
    if manifest.get("max_evidence_completed_at") != recomputed_max_completed_at:
        raise EvidenceError("evidence manifest maximum completion time is not derived")
    platform_rows = [
        {
            "platform": name,
            "result_digest": platform_records[name]["result_digest"],
            "observed_environment_closure_digest": platform_records[name][
                "observed_environment_closure_digest"
            ],
            "platform_binding_digest": platform_records[name]["invocation"][
                "platform_binding_digest"
            ],
        }
        for name in ("linux", "windows")
    ]
    closure_identity = {
        "record_type": "DerivedMultiPlatformImplementationClosure",
        "candidate_binding_digest": candidate["candidate_binding_digest"],
        "portable_implementation_closure_digest": candidate[
            "portable_implementation_closure_digest"
        ],
        "platforms": platform_rows,
        "platforms_complete": True,
        "portable_implementation_closed": True,
        "product_acceptance_pass": False,
        "product_public_approval": "not_approved",
    }
    derived_closure = {
        **closure_identity,
        "closure_digest": canonical_digest(closure_identity),
    }
    return {
        **deepcopy(dict(manifest)),
        "resolved_entries": resolved,
        "resolved_matrix_aggregate": matrix_resolved,
        "resolved_supplemental_lanes": supplemental_resolved,
        "all_required_roles_resolved": True,
        "max_evidence_completed_at": recomputed_max_completed_at,
        "derived_multi_platform_implementation_closure": derived_closure,
    }


def _validate_trust_configuration(
    configuration: Mapping[str, Any],
    *,
    require_complete_evidence_roles: bool = False,
) -> dict[str, Any]:
    if not isinstance(configuration, Mapping) or set(configuration) != _STANDARD_TRUST_CONFIGURATION_FIELDS:
        raise EvidenceError("invalid StandardReleaseTrustConfiguration shape")
    if (
        configuration.get("record_type") != "StandardReleaseTrustConfiguration"
        or configuration.get("algorithm") != "Ed25519"
        or configuration.get("signature_provider_id") != "cryptography-ed25519-v1"
    ):
        raise EvidenceError("unsupported standard release trust configuration")
    _safe_id(configuration.get("trust_root_id"))
    keys = configuration.get("keys")
    if not isinstance(keys, list) or not keys or len(keys) > 32:
        raise EvidenceError("standard release trust key set is invalid")
    seen: set[str] = set()
    seen_public_keys: set[str] = set()
    evidence_subjects: set[str] = set()
    decision_subjects: set[str] = set()
    evidence_role_owners: dict[str, str] = {}
    for key in keys:
        if not isinstance(key, Mapping) or set(key) != _STANDARD_TRUST_KEY_FIELDS:
            raise EvidenceError("standard release trust key shape is invalid")
        key_id = _safe_id(key.get("key_id"))
        subject_id = _safe_id(key.get("subject_id"))
        if key_id in seen:
            raise EvidenceError("duplicate standard release trust key")
        seen.add(key_id)
        capabilities = key.get("capabilities")
        if (
            not isinstance(capabilities, list)
            or not capabilities
            or capabilities != sorted(set(capabilities))
            or not set(capabilities).issubset(
                {_EVIDENCE_PRODUCE_CAPABILITY, _STANDARD_DISTRIBUTE_CAPABILITY}
            )
        ):
            raise EvidenceError("standard release trust capabilities are invalid")
        roles = key.get("evidence_roles")
        platforms = key.get("platforms")
        if (
            not isinstance(roles, list)
            or roles != sorted(set(roles))
            or any(role not in _REQUIRED_STANDARD_EVIDENCE for role in roles)
            or not isinstance(platforms, list)
            or platforms != sorted(set(platforms))
            or any(not isinstance(name, str) or not name or len(name) > 64 for name in platforms)
        ):
            raise EvidenceError("standard release role/platform key scope is invalid")
        produces_evidence = _EVIDENCE_PRODUCE_CAPABILITY in capabilities
        distributes_standard = _STANDARD_DISTRIBUTE_CAPABILITY in capabilities
        if produces_evidence == distributes_standard:
            raise EvidenceError("evidence production and standard distribution require separate keys")
        if produces_evidence:
            if len(roles) != 1 or not platforms:
                raise EvidenceError("evidence producer key lacks role/platform scope")
            role = roles[0]
            if role in evidence_role_owners:
                raise EvidenceError("required evidence role has multiple configured keys")
            if subject_id in evidence_subjects:
                raise EvidenceError("required evidence roles must use distinct subjects")
            if platforms != _REQUIRED_STANDARD_EVIDENCE_PLATFORMS[role]:
                raise EvidenceError(
                    "required evidence role has an over-broad or wrong platform scope"
                )
            evidence_role_owners[role] = key_id
            evidence_subjects.add(subject_id)
        else:
            if roles or platforms:
                raise EvidenceError("standard distribution key cannot carry evidence scope")
            decision_subjects.add(subject_id)
        public_key = key.get("public_key")
        _decode_base64(public_key, "Ed25519 public key", expected_bytes=32)
        if public_key in seen_public_keys:
            raise EvidenceError("standard release trust keys must use distinct public keys")
        seen_public_keys.add(public_key)
        not_before = parse_timestamp(key.get("not_before"))
        not_after = parse_timestamp(key.get("not_after"))
        if not_before >= not_after:
            raise EvidenceError("standard release trust key interval is empty")
        if key.get("revoked") not in {True, False}:
            raise EvidenceError("standard release key revocation state is invalid")
    if evidence_subjects & decision_subjects:
        raise EvidenceError("evidence producer and standard distributor violate separation of duties")
    if require_complete_evidence_roles and set(evidence_role_owners) != set(
        _REQUIRED_STANDARD_EVIDENCE
    ):
        raise EvidenceError("trust configuration does not own exactly seven evidence roles")
    return deepcopy(dict(configuration))


def _validate_evidence_attestation_trust(
    attestation: Mapping[str, Any],
    *,
    trust: Mapping[str, Any],
    expected_role: str,
    expected_platform: str,
) -> dict[str, Any]:
    if (
        attestation.get("trust_root_id") != trust.get("trust_root_id")
        or attestation.get("signature_provider_id") != trust.get("signature_provider_id")
    ):
        raise EvidenceError("release evidence producer trust root or provider drift")
    matches = [key for key in trust["keys"] if key["key_id"] == attestation.get("key_id")]
    if len(matches) != 1:
        raise EvidenceError("release evidence producer key is not independently pinned")
    key = matches[0]
    signed_at = parse_timestamp(attestation.get("signed_at"))
    if (
        key["revoked"] is True
        or key["subject_id"] != attestation.get("producer_id")
        or _EVIDENCE_PRODUCE_CAPABILITY not in key["capabilities"]
        or _STANDARD_DISTRIBUTE_CAPABILITY in key["capabilities"]
        or expected_role not in key["evidence_roles"]
        or expected_platform not in key["platforms"]
        or key["public_key"] != attestation.get("public_key")
        or signed_at < parse_timestamp(key["not_before"])
        or signed_at >= parse_timestamp(key["not_after"])
    ):
        raise EvidenceError("release evidence producer authority is inactive or wrongly scoped")
    return deepcopy(dict(key))


def validate_standard_release_decision(
    decision: Mapping[str, Any],
    *,
    candidate_binding: Mapping[str, Any],
    evidence_manifest: Mapping[str, Any],
    evidence_root: Path | str,
    trust_configuration: Mapping[str, Any],
    candidate_document_members: Iterable[Mapping[str, Any]] = (),
    verification_time: datetime | str | None = None,
) -> dict[str, Any]:
    """Verify one external approve/reject judgement against configured authority."""

    candidate = validate_standard_release_candidate_binding(candidate_binding)
    trust = _validate_trust_configuration(trust_configuration)
    verified_at = _verification_time_utc(
        verification_time,
        "StandardReleaseDecision",
    )
    verified_manifest = validate_standard_release_evidence_manifest(
        evidence_manifest,
        candidate_binding=candidate,
        evidence_root=evidence_root,
        trust_configuration=trust,
        candidate_document_members=candidate_document_members,
        verification_time=verified_at,
    )
    if (
        not isinstance(decision, Mapping)
        or set(decision) != _STANDARD_RELEASE_DECISION_FIELDS
        or decision.get("record_type") != "StandardReleaseDecision"
    ):
        raise EvidenceError("invalid StandardReleaseDecision shape")
    for field in ("decision_id", "decider_id", "trust_root_id", "signature_provider_id", "key_id"):
        _safe_id(decision.get(field))
    if decision.get("standard_name") != "promin" or decision.get("version") != candidate["version"]:
        raise EvidenceError("StandardReleaseDecision identity or SemVer drift")
    if decision.get("candidate_binding_digest") != candidate["candidate_binding_digest"]:
        raise EvidenceError("StandardReleaseDecision candidate binding drift")
    if (
        verified_manifest.get("record_type") != "StandardReleaseEvidenceManifest"
        or verified_manifest.get("candidate_binding_digest") != candidate["candidate_binding_digest"]
        or decision.get("evidence_manifest_digest")
        != verified_manifest.get("evidence_manifest_digest")
    ):
        raise EvidenceError("StandardReleaseDecision evidence manifest drift")
    if decision.get("outcome") not in {"approve", "reject"}:
        raise EvidenceError("StandardReleaseDecision outcome must be approve or reject")
    if decision.get("release_capability") != "standard.distribute":
        raise EvidenceError("StandardReleaseDecision capability is invalid")
    if (
        decision.get("trust_root_id") != trust["trust_root_id"]
        or decision.get("signature_provider_id") != trust["signature_provider_id"]
    ):
        raise EvidenceError("StandardReleaseDecision trust root or provider drift")
    nonce = _decode_base64(decision.get("nonce"), "decision nonce")
    if len(nonce) < 16 or len(nonce) > 64:
        raise EvidenceError("StandardReleaseDecision nonce length is invalid")
    decided_at = parse_timestamp(decision.get("decided_at"))
    evidence_completed_at = parse_timestamp(
        verified_manifest.get("max_evidence_completed_at")
    )
    if decided_at <= evidence_completed_at:
        raise EvidenceError(
            "StandardReleaseDecision must follow required evidence completion"
        )
    if decided_at > verified_at + timedelta(seconds=_STANDARD_DECISION_FUTURE_SKEW_SECONDS):
        raise EvidenceError("StandardReleaseDecision exceeds the bounded verifier clock skew")
    identity = {
        field: deepcopy(decision[field])
        for field in _STANDARD_RELEASE_DECISION_IDENTITY_FIELDS
    }
    claim_digest = canonical_digest(identity)
    if decision.get("signed_claim_digest") != claim_digest:
        raise EvidenceError("StandardReleaseDecision signed claim digest mismatch")
    matching = [key for key in trust["keys"] if key["key_id"] == decision["key_id"]]
    if len(matching) != 1:
        raise EvidenceError("StandardReleaseDecision key is not configured")
    key = matching[0]
    if (
        key["revoked"] is True
        or key["subject_id"] != decision["decider_id"]
        or decision["release_capability"] not in key["capabilities"]
        or _EVIDENCE_PRODUCE_CAPABILITY in key["capabilities"]
        or key["evidence_roles"]
        or key["platforms"]
        or decided_at < parse_timestamp(key["not_before"])
        or decided_at >= parse_timestamp(key["not_after"])
    ):
        raise EvidenceError("StandardReleaseDecision authority is inactive or insufficient")
    public_key = _decode_base64(key["public_key"], "Ed25519 public key", expected_bytes=32)
    signature = _decode_base64(decision.get("signature"), "decision signature", expected_bytes=64)
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            bytes.fromhex(claim_digest),
        )
    except ImportError as exc:
        raise EvidenceError("configured Ed25519 verifier is unavailable") from exc
    except (InvalidSignature, ValueError) as exc:
        raise EvidenceError("StandardReleaseDecision signature is invalid") from exc
    stored = deepcopy(dict(decision))
    return {**stored, "decision_digest": canonical_digest(stored)}


def standard_distribution_status(
    decision: Mapping[str, Any] | None,
    *,
    candidate_binding: Mapping[str, Any],
    evidence_manifest: Mapping[str, Any] | None,
    evidence_root: Path | str | None,
    trust_configuration: Mapping[str, Any] | None,
    candidate_document_members: Iterable[Mapping[str, Any]] = (),
    trust_configuration_sha256: str | None = None,
    expected_trust_root_sha256: str | None = None,
) -> dict[str, Any]:
    """Return machine-readable distribution validity without product credit."""

    reasons: set[str] = set()
    validated: dict[str, Any] | None = None
    candidate = validate_standard_release_candidate_binding(candidate_binding)
    if decision is None:
        reasons.add("standard-decision-missing")
    elif evidence_manifest is None:
        reasons.add("standard-evidence-manifest-missing")
    elif evidence_root is None:
        reasons.add("standard-evidence-root-missing")
    elif trust_configuration is None:
        reasons.add("standard-trust-configuration-missing")
    else:
        try:
            validated = validate_standard_release_decision(
                decision,
                candidate_binding=candidate,
                evidence_manifest=evidence_manifest,
                evidence_root=evidence_root,
                trust_configuration=trust_configuration,
                candidate_document_members=candidate_document_members,
            )
        except (EvidenceError, OSError):
            reasons.add("standard-decision-invalid")
    trust_pin_matches = False
    if validated is not None and validated.get("outcome") == "approve":
        if expected_trust_root_sha256 is None:
            reasons.add("independent-trust-root-pin-missing")
        elif not _valid_digest(expected_trust_root_sha256):
            reasons.add("independent-trust-root-pin-invalid")
        elif not _valid_digest(trust_configuration_sha256):
            reasons.add("supplied-trust-root-digest-missing")
        elif trust_configuration_sha256 != expected_trust_root_sha256:
            reasons.add("independent-trust-root-pin-mismatch")
        else:
            trust_pin_matches = True
    if validated is None:
        distribution_status = "candidate" if decision is None else "invalidated"
    elif validated["outcome"] == "approve":
        if trust_pin_matches:
            distribution_status = "approved"
        elif expected_trust_root_sha256 is None:
            distribution_status = "signature_valid_under_supplied_root"
        else:
            distribution_status = "invalidated"
    else:
        distribution_status = "rejected"
    current_eligible = (
        validated is not None
        and validated["outcome"] == "approve"
        and trust_pin_matches
        and not reasons
    )
    historical_digest: str | None = None
    if isinstance(decision, Mapping):
        try:
            historical_digest = canonical_digest(dict(decision))
        except Exception:
            reasons.add("historical-decision-record-malformed")
            current_eligible = False
            distribution_status = "invalidated"
    return {
        "record_type": "StandardDistributionStatus",
        "standard_name": "promin",
        "version": candidate["version"],
        "candidate_binding_digest": candidate["candidate_binding_digest"],
        "distribution_status": distribution_status,
        "current_distribution_eligible": current_eligible,
        "product_acceptance_pass": False,
        "product_public_approval": "not_approved",
        "historical_decision_present": isinstance(decision, Mapping),
        "historical_decision_digest": historical_digest,
        "historical_decision_outcome": (
            decision.get("outcome") if isinstance(decision, Mapping) else None
        ),
        "historical_decision_decided_at": (
            decision.get("decided_at") if isinstance(decision, Mapping) else None
        ),
        "decision_id": validated.get("decision_id") if validated else None,
        "decision_digest": validated.get("decision_digest") if validated else None,
        "supplied_trust_root_sha256": trust_configuration_sha256,
        "expected_trust_root_sha256": expected_trust_root_sha256,
        "independent_trust_root_pin_verified": trust_pin_matches,
        "invalidation_reasons": sorted(reasons),
    }


def _relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise EvidenceError("invalid Candidate delta path")
    normalized_unicode = unicodedata.normalize("NFC", value)
    if normalized_unicode != value or "\\" in value or "\x00" in value:
        raise EvidenceError("Candidate delta path is not canonical POSIX NFC")
    normalized = posixpath.normpath(value)
    if (
        value.startswith("/")
        or normalized in {"", ".", ".."}
        or normalized.startswith("../")
        or normalized != value.rstrip("/")
    ):
        raise EvidenceError("Candidate delta path escapes the product root")
    return normalized


class EvidenceStore:
    """Durable CAS where only event-finalized evidence can resolve or earn credit."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).absolute()
        self._ensure_safe_root()
        self.objects = self.root / "objects" / "sha256"
        self.pending = self.root / "pending"
        self.records = self.root / "records"
        os.makedirs(filesystem_path(self.objects), exist_ok=True)
        os.makedirs(filesystem_path(self.pending), exist_ok=True)
        os.makedirs(filesystem_path(self.records), exist_ok=True)
        self._records: dict[str, dict[str, Any]] = {}
        self._by_digest: dict[str, list[str]] = {}
        self._authoritative_ids: set[str] = set()
        self._load_records()
        self._validate_pending()

    def _ensure_safe_root(self) -> None:
        cursor = Path(self.root.anchor)
        for part in self.root.parts[1:]:
            cursor = cursor / part
            if os.path.lexists(filesystem_path(cursor)) and os.path.islink(
                filesystem_path(cursor)
            ):
                raise EvidenceError("evidence root must not traverse a symlink")
        os.makedirs(filesystem_path(self.root), exist_ok=True)
        cursor = Path(self.root.anchor)
        for part in self.root.parts[1:]:
            cursor = cursor / part
            if os.path.islink(filesystem_path(cursor)):
                raise EvidenceError("evidence root must not traverse a symlink")

    @staticmethod
    def _portable_name(artifact_id: str) -> str:
        normalized = _safe_id(artifact_id)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest() + ".json"

    def _record_path(self, artifact_id: str) -> Path:
        return self.records / self._portable_name(artifact_id)

    def _pending_path(self, artifact_id: str) -> Path:
        return self.pending / self._portable_name(artifact_id)

    def _object_path(self, digest: str) -> Path:
        if not _valid_digest(digest):
            raise EvidenceError("invalid evidence digest")
        return self.objects / digest[:2] / digest[2:]

    @staticmethod
    def _validate_artifact(artifact: Mapping[str, Any]) -> None:
        artifact_kind = artifact.get("artifact_kind")
        expected_fields = (
            _EVIDENCE_ARTIFACT_FIELDS
            if artifact_kind == "evidence"
            else _DELTA_ARTIFACT_FIELDS
            if artifact_kind == "diff"
            else frozenset()
        )
        if (
            not expected_fields
            or set(artifact) != expected_fields
            or artifact.get("record_type") != "Artifact"
        ):
            raise EvidenceError("Artifact does not match a supported Core CAS shape")
        _safe_id(artifact.get("artifact_id"))
        if not _valid_digest(artifact.get("digest")):
            raise EvidenceError("invalid Artifact digest")
        if not isinstance(artifact.get("media_type"), str) or not artifact["media_type"]:
            raise EvidenceError("Artifact media type is required")
        if (
            not isinstance(artifact.get("size_bytes"), int)
            or isinstance(artifact.get("size_bytes"), bool)
            or artifact["size_bytes"] <= 0
        ):
            raise EvidenceError("Artifact size must be a positive integer")
        if artifact.get("retention_class") not in _RETENTION:
            raise EvidenceError("unknown Artifact retention class")
        parse_timestamp(artifact.get("created_at"))
        if artifact_kind == "diff":
            delta = artifact.get("candidate_delta")
            if not isinstance(delta, Mapping) or set(delta) != _CANDIDATE_DELTA_FIELDS:
                raise EvidenceError("invalid Candidate delta binding")
            if not all(
                _valid_digest(delta[key])
                for key in (
                    "base_candidate_digest",
                    "new_candidate_digest",
                    "workcard_digest",
                )
            ):
                raise EvidenceError("invalid Candidate delta digest binding")
            changed_paths = delta["changed_paths"]
            if (
                not isinstance(changed_paths, list)
                or not changed_paths
                or len(changed_paths) > 100_000
                or len(changed_paths) != len(set(changed_paths))
            ):
                raise EvidenceError("Candidate delta changed paths must be unique and bounded")
            if [_relative_path(value) for value in changed_paths] != changed_paths:
                raise EvidenceError("Candidate delta paths are not canonical")
            return

        binding = artifact.get("evidence_binding")
        binding_fields = frozenset(binding) if isinstance(binding, Mapping) else frozenset()
        if (
            not isinstance(binding, Mapping)
            or not _EVIDENCE_BINDING_FIELDS <= binding_fields
            or not binding_fields <= _EVIDENCE_BINDING_FIELDS | _EVIDENCE_BINDING_OPTIONAL_FIELDS
        ):
            raise EvidenceError("invalid evidence binding")
        inputs = binding["input_digests"]
        if (
            not isinstance(inputs, list)
            or len(inputs) != len(set(inputs))
            or len(inputs) > 128
        ):
            raise EvidenceError("invalid evidence input digest set")
        if not all(
            _valid_digest(binding[key])
            for key in (
                "activation_digest",
                "implementation_closure_digest",
                "candidate_digest",
                "policy_digest",
                "tool_digest",
            )
        ) or not all(_valid_digest(value) for value in inputs):
            raise EvidenceError("invalid evidence binding digest")
        if "finding_digest" in binding and not _valid_digest(binding["finding_digest"]):
            raise EvidenceError("invalid Finding evidence binding digest")
        invocations = binding.get("provider_invocations")
        if invocations is not None:
            if (
                not isinstance(invocations, list)
                or not invocations
                or len(invocations) > 32
                or len({canonical_digest(item) for item in invocations}) != len(invocations)
            ):
                raise EvidenceError("provider invocations must be unique and bounded")
            for invocation in invocations:
                if (
                    not isinstance(invocation, Mapping)
                    or set(invocation) != _PROVIDER_INVOCATION_FIELDS
                    or invocation["capability_id"] not in _PROVIDER_CAPABILITIES
                    or invocation["invocation_kind"] not in _INVOCATION_KINDS
                    or invocation["identity_kind"] not in _IDENTITY_KINDS
                    or invocation.get("invoked") is not True
                    or invocation.get("authoritative") is not False
                    or invocation.get("pass_credit") is not False
                    or invocation.get("outcome") not in {"success", "failure", "blocked"}
                    or not _valid_digest(invocation["identity_digest"])
                    or not _valid_digest(invocation["operation_contract_digest"])
                    or not _valid_digest(invocation["dependency_receipt_digest"])
                    or not _valid_digest(invocation["implementation_closure_digest"])
                    or not _valid_digest(invocation["invocation_request_digest"])
                    or not _valid_digest(invocation["input_digest"])
                    or not _valid_digest(invocation["output_digest"])
                    or not _valid_digest(invocation["stdout_capture_digest"])
                    or not _valid_digest(invocation["stderr_capture_digest"])
                    or invocation["implementation_closure_digest"]
                    != binding["implementation_closure_digest"]
                ):
                    raise EvidenceError("invalid provider invocation evidence")
                claimed_receipt_digest = invocation["invocation_receipt_digest"]
                receipt_body = dict(invocation)
                receipt_body.pop("invocation_receipt_digest")
                if canonical_digest(receipt_body) != claimed_receipt_digest:
                    raise EvidenceError("provider invocation receipt digest is invalid")
                for field in ("provider_id", "adapter_id", "protocol_id", "operation"):
                    _safe_id(invocation[field])
                started = parse_timestamp(invocation["started_at"])
                completed = parse_timestamp(invocation["completed_at"])
                exit_code = invocation["exit_code"]
                if (
                    started > completed
                    or (exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool)))
                    or (invocation["outcome"] == "success" and exit_code != 0)
                    or (invocation["outcome"] == "failure" and exit_code is None)
                    or (invocation["outcome"] == "blocked" and exit_code is not None)
                    or not isinstance(invocation["output_size_bytes"], int)
                    or isinstance(invocation["output_size_bytes"], bool)
                    or not isinstance(invocation["output_size_ceiling_bytes"], int)
                    or isinstance(invocation["output_size_ceiling_bytes"], bool)
                    or not 0 <= invocation["output_size_bytes"] <= invocation["output_size_ceiling_bytes"] <= 1_099_511_627_776
                    or any(
                        not isinstance(invocation[field], int)
                        or isinstance(invocation[field], bool)
                        or not 0 <= invocation[field] <= 1_048_576
                        for field in ("stdout_capture_size_bytes", "stderr_capture_size_bytes")
                    )
                    or not isinstance(invocation["stdout_capture_truncated"], bool)
                    or not isinstance(invocation["stderr_capture_truncated"], bool)
                ):
                    raise EvidenceError("invalid provider invocation evidence")
                unsigned_invocation = {
                    key: deepcopy(value)
                    for key, value in invocation.items()
                    if key != "invocation_receipt_digest"
                }
                if invocation["invocation_receipt_digest"] != canonical_digest(unsigned_invocation):
                    raise EvidenceError("provider invocation receipt digest mismatch")
        if artifact.get("outcome") not in _OUTCOMES:
            raise EvidenceError("unknown evidence outcome")
        if artifact.get("evidence_class") not in _EVIDENCE_CLASSES:
            raise EvidenceError("unknown evidence class")
        try:
            EvidenceStore._validate_purpose_class(
                artifact.get("evidence_purpose"), artifact["evidence_class"]
            )
        except EvidenceError as exc:
            raise EvidenceError("evidence purpose/class binding is invalid") from exc
        if not isinstance(artifact.get("stale"), bool) or not isinstance(
            artifact.get("unresolved"), bool
        ):
            raise EvidenceError("evidence stale/unresolved state must be boolean")
        if not isinstance(artifact.get("product_credit_eligible"), bool):
            raise EvidenceError("evidence product-credit state must be boolean")
        if artifact["product_credit_eligible"] and (
            artifact["outcome"] != "pass"
            or artifact["stale"]
            or artifact["unresolved"]
            or artifact["evidence_class"] != "product-execution"
            or artifact["evidence_purpose"] != "product"
            or not binding.get("provider_invocations")
        ):
            raise EvidenceError("product credit requires fresh passing product evidence")

    @staticmethod
    def _validate_commit_binding(binding: Mapping[str, Any]) -> None:
        if set(binding) != _COMMIT_FIELDS:
            raise EvidenceError("invalid evidence event binding")
        if not all(
            _valid_digest(binding[key])
            for key in ("command_digest", "batch_digest", "primary_event_digest")
        ):
            raise EvidenceError("invalid evidence event digest")
        _safe_id(binding.get("primary_event_id"))

    @classmethod
    def _validate_record(cls, record: Mapping[str, Any]) -> None:
        if set(record) != {"artifact", "commit_binding"}:
            raise EvidenceError("invalid finalized evidence metadata shape")
        artifact = record.get("artifact")
        binding = record.get("commit_binding")
        if not isinstance(artifact, Mapping) or not isinstance(binding, Mapping):
            raise EvidenceError("finalized evidence metadata is incomplete")
        cls._validate_artifact(artifact)
        cls._validate_commit_binding(binding)

    @classmethod
    def _validate_stage_record(cls, record: Mapping[str, Any]) -> None:
        if set(record) != {"artifact", "command_digest"}:
            raise EvidenceError("invalid staged evidence metadata shape")
        artifact = record.get("artifact")
        if not isinstance(artifact, Mapping):
            raise EvidenceError("staged evidence metadata lacks Artifact")
        cls._validate_artifact(artifact)
        if not _valid_digest(record.get("command_digest")):
            raise EvidenceError("invalid staged command digest")

    def _validate_object(self, artifact: Mapping[str, Any]) -> None:
        path = self._object_path(artifact["digest"])
        native = filesystem_path(path)
        if (
            not os.path.isfile(native)
            or os.path.islink(native)
            or os.stat(native).st_size != artifact["size_bytes"]
            or _digest_file(path) != artifact["digest"]
        ):
            raise EvidenceError(f"evidence object mismatch for {artifact['artifact_id']}")

    @staticmethod
    def _read_json_file(path: Path, label: str) -> dict[str, Any]:
        native = filesystem_path(path)
        if os.path.islink(native) or not stat.S_ISREG(os.stat(native).st_mode):
            raise EvidenceError(f"{label} entry is not a regular file")
        try:
            with open(native, encoding="utf-8") as stream:
                value = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            raise EvidenceError(f"unreadable {label}: {path.name}") from exc
        if not isinstance(value, dict):
            raise EvidenceError(f"{label} is not an object")
        return value

    @staticmethod
    def _metadata_paths(directory: Path) -> tuple[Path, ...]:
        """List metadata through the final filesystem boundary only.

        Returned paths retain their ordinary spelling so artifact identity and
        collision checks cannot accidentally persist a Windows transport prefix.
        """

        with os.scandir(filesystem_path(directory)) as entries:
            names = sorted(
                entry.name for entry in entries if entry.name.endswith(".json")
            )
        return tuple(directory / name for name in names)

    def _load_records(self) -> None:
        for path in self._metadata_paths(self.records):
            record = self._read_json_file(path, "evidence metadata")
            self._validate_record(record)
            artifact = record["artifact"]
            artifact_id = artifact["artifact_id"]
            if path != self._record_path(artifact_id) or artifact_id in self._records:
                raise EvidenceError("evidence metadata identity collision")
            self._validate_object(artifact)
            self._records[artifact_id] = record
            self._by_digest.setdefault(artifact["digest"], []).append(artifact_id)

    def _validate_pending(self) -> None:
        for path in self._metadata_paths(self.pending):
            record = self._read_json_file(path, "staged evidence metadata")
            self._validate_stage_record(record)
            artifact = record["artifact"]
            if path != self._pending_path(artifact["artifact_id"]):
                raise EvidenceError("staged evidence metadata identity collision")
            self._validate_object(artifact)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(filesystem_path(path), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _write_object_once(self, digest: str, payload: bytes) -> None:
        path = self._object_path(digest)
        native = filesystem_path(path)
        os.makedirs(filesystem_path(path.parent), exist_ok=True)
        if os.path.lexists(native):
            if os.path.islink(native) or _digest_file(path) != digest:
                raise EvidenceError("CAS digest path contains different content")
            return
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".p-", suffix=".tmp", dir=filesystem_path(path.parent)
        )
        temporary = Path(temporary_name)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            try:
                os.link(filesystem_path(temporary), native)
            except FileExistsError:
                if os.path.islink(native) or _digest_file(path) != digest:
                    raise EvidenceError("CAS digest raced with different content")
        finally:
            os.unlink(filesystem_path(temporary))
        try:
            os.chmod(native, 0o444)
        except OSError:
            pass
        self._fsync_directory(path.parent)

    def _write_json_once(
        self,
        path: Path,
        value: Mapping[str, Any],
        *,
        conflict: str,
    ) -> None:
        encoded = (
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        native = filesystem_path(path)
        if os.path.lexists(native):
            existing = self._read_json_file(path, path.parent.name)
            if canonical_digest(existing) != canonical_digest(value):
                raise EvidenceError(conflict)
            return
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".p-", suffix=".tmp", dir=filesystem_path(path.parent)
        )
        temporary = Path(temporary_name)
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            try:
                os.link(filesystem_path(temporary), native)
            except FileExistsError:
                existing = self._read_json_file(path, path.parent.name)
                if canonical_digest(existing) != canonical_digest(value):
                    raise EvidenceError(conflict)
            self._fsync_directory(path.parent)
        finally:
            os.unlink(filesystem_path(temporary))
        try:
            os.chmod(native, 0o444)
        except OSError:
            pass

    def stage(
        self,
        artifact: Mapping[str, Any],
        payload: bytes,
        *,
        command_digest: str,
    ) -> dict[str, Any]:
        """Durably stage bytes and metadata without making the Artifact resolvable."""

        self._validate_artifact(artifact)
        if not isinstance(payload, bytes) or not payload:
            raise EvidenceError("Artifact payload must be non-empty bytes")
        if not _valid_digest(command_digest):
            raise EvidenceError("invalid staged command digest")
        if _digest_bytes(payload) != artifact["digest"] or len(payload) != artifact["size_bytes"]:
            raise EvidenceError("Artifact payload differs from its digest or size")
        artifact_id = artifact["artifact_id"]
        finalized = self._records.get(artifact_id)
        if finalized is not None:
            if (
                finalized["artifact"] != dict(artifact)
                or finalized["commit_binding"]["command_digest"] != command_digest
            ):
                raise EvidenceError("Artifact ID already identifies different finalized evidence")
            status = "finalized"
        else:
            staged = {"artifact": deepcopy(dict(artifact)), "command_digest": command_digest}
            path = self._pending_path(artifact_id)
            status = (
                "already-staged"
                if os.path.lexists(filesystem_path(path))
                else "staged"
            )
            self._write_object_once(artifact["digest"], payload)
            self._write_json_once(
                path,
                staged,
                conflict="Artifact ID already identifies different staged evidence",
            )
        return {
            "record_type": "EvidenceStageReceipt",
            "status": status,
            "artifact_id": artifact_id,
            "artifact_digest": artifact["digest"],
            "command_digest": command_digest,
        }

    @staticmethod
    def _event_binding(
        artifact: Mapping[str, Any],
        command_digest: str,
        envelope: Mapping[str, Any],
    ) -> dict[str, Any]:
        if set(envelope) != {"record_type", "command", "batch"} or envelope.get(
            "record_type"
        ) != "JournalEnvelope":
            raise EvidenceError("Artifact finalization requires one JournalEnvelope")
        command = envelope.get("command")
        batch = envelope.get("batch")
        if not isinstance(command, Mapping) or not isinstance(batch, Mapping):
            raise EvidenceError("Artifact JournalEnvelope is incomplete")
        if canonical_digest(command) != command_digest:
            raise EvidenceError("Artifact command digest differs from staged command")
        if (
            command.get("record_type") != "CommandRequest"
            or command.get("command_kind") != "artifact.record"
            or command.get("payload") != dict(artifact)
        ):
            raise EvidenceError("Artifact JournalEnvelope command differs from Artifact")
        events = batch.get("events")
        if not isinstance(events, list) or len(events) != 1:
            raise EvidenceError("Artifact batch must contain exactly one primary Event")
        primary_event = events[0]
        if not isinstance(primary_event, Mapping):
            raise EvidenceError("Artifact primary Event is not an object")
        if set(primary_event) != {
            "record_type",
            "event_id",
            "event_kind",
            "activation_digest",
            "payload",
        } or primary_event.get("record_type") != "Event":
            raise EvidenceError("Artifact finalization requires one exact primary Event")
        if primary_event.get("event_kind") != "artifact.recorded":
            raise EvidenceError("Artifact finalization Event kind is not artifact.recorded")
        if primary_event.get("payload") != dict(artifact):
            raise EvidenceError("Artifact finalization Event payload differs from Artifact")
        artifact_activation = (
            artifact["evidence_binding"]["activation_digest"]
            if artifact["artifact_kind"] == "evidence"
            else command.get("activation_digest")
        )
        if primary_event.get("activation_digest") != artifact_activation:
            raise EvidenceError("Artifact Event Activation differs from its binding")
        if (
            batch.get("record_type") != "EventBatch"
            or batch.get("command_id") != command.get("command_id")
            or not _valid_digest(batch.get("activation_record_digest"))
            or command.get("activation_digest") != artifact_activation
            or batch.get("command_digest") != command_digest
            or batch.get("command_intent_digest") != command.get("intent_digest")
            or batch.get("subject_id") != command.get("subject_id")
            or batch.get("idempotency_key") != command.get("idempotency_key")
        ):
            raise EvidenceError("Artifact EventBatch differs from its command")
        binding = {
            "command_digest": command_digest,
            "batch_digest": canonical_digest(batch),
            "primary_event_id": primary_event["event_id"],
            "primary_event_digest": canonical_digest(primary_event),
        }
        EvidenceStore._validate_commit_binding(binding)
        return binding

    def finalize(
        self,
        artifact: Mapping[str, Any],
        *,
        command_digest: str,
        envelope: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Finalize staged bytes after their authoritative Artifact event commits."""

        self._validate_artifact(artifact)
        commit_binding = self._event_binding(artifact, command_digest, envelope)
        artifact_id = artifact["artifact_id"]
        final_record = {
            "artifact": deepcopy(dict(artifact)),
            "commit_binding": commit_binding,
        }
        existing = self._records.get(artifact_id)
        if existing is not None:
            if existing != final_record:
                raise EvidenceError("Artifact ID already has a different committed event")
            status = "already-finalized"
        else:
            pending_path = self._pending_path(artifact_id)
            if not os.path.isfile(filesystem_path(pending_path)):
                raise EvidenceError("Artifact cannot finalize without its staged CAS record")
            staged = self._read_json_file(pending_path, "staged evidence metadata")
            self._validate_stage_record(staged)
            if staged != {"artifact": dict(artifact), "command_digest": command_digest}:
                raise EvidenceError("staged bytes differ from committed Artifact command")
            self._validate_object(artifact)
            self._write_json_once(
                self._record_path(artifact_id),
                final_record,
                conflict="Artifact ID raced with a different committed event",
            )
            self._records[artifact_id] = deepcopy(final_record)
            self._by_digest.setdefault(artifact["digest"], []).append(artifact_id)
            status = "finalized"
        pending_path = self._pending_path(artifact_id)
        if os.path.lexists(filesystem_path(pending_path)):
            try:
                os.chmod(filesystem_path(pending_path), 0o600)
            except OSError:
                pass
            os.unlink(filesystem_path(pending_path))
        self._fsync_directory(self.pending)
        return {
            "record_type": "EvidenceFinalizeReceipt",
            "status": status,
            "artifact_id": artifact_id,
            "artifact_digest": artifact["digest"],
            **commit_binding,
        }

    def recover_finalize(
        self,
        artifact: Mapping[str, Any],
        *,
        command_digest: str,
        envelope: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Idempotently finalize only after the caller resolves an authoritative event."""

        return self.finalize(
            artifact,
            command_digest=command_digest,
            envelope=envelope,
        )

    def reconcile(
        self,
        envelopes: Iterable[Mapping[str, Any]],
        *,
        allow_trailing_records: bool = False,
    ) -> dict[str, Any]:
        """Bind finalized records to one validated journal snapshot.

        ``allow_trailing_records`` is reserved for historical read-only replay:
        records finalized by batches after the selected prefix remain
        non-authoritative for that snapshot instead of making the prefix
        unreadable. Current-state reconciliation remains exact by default.
        """

        authoritative: dict[
            str, tuple[dict[str, Any], dict[str, Any], dict[str, Any]]
        ] = {}
        for envelope_value in envelopes:
            envelope = deepcopy(dict(envelope_value))
            command = envelope.get("command")
            if not isinstance(command, Mapping) or command.get("command_kind") != "artifact.record":
                continue
            artifact = command.get("payload")
            if not isinstance(artifact, Mapping) or artifact.get("artifact_kind") not in {
                "evidence",
                "diff",
            }:
                continue
            self._validate_artifact(artifact)
            command_digest = canonical_digest(command)
            binding = self._event_binding(artifact, command_digest, envelope)
            artifact_id = artifact["artifact_id"]
            if artifact_id in authoritative:
                raise EvidenceError("journal contains duplicate Artifact identity")
            authoritative[artifact_id] = (
                deepcopy(dict(artifact)),
                binding,
                envelope,
            )

        for artifact_id, (artifact, binding, envelope) in authoritative.items():
            if artifact_id not in self._records:
                pending_path = self._pending_path(artifact_id)
                if not pending_path.is_file():
                    raise EvidenceError("authoritative Artifact Event lacks staged CAS bytes")
                self.finalize(
                    artifact,
                    command_digest=binding["command_digest"],
                    envelope=envelope,
                )

        reconciled: set[str] = set()
        for artifact_id, record in self._records.items():
            resolved = authoritative.get(artifact_id)
            if resolved is None:
                if allow_trailing_records:
                    continue
                raise EvidenceError("finalized Artifact lacks an authoritative journal Event")
            artifact, binding, _envelope = resolved
            if record != {"artifact": artifact, "commit_binding": binding}:
                raise EvidenceError("finalized Artifact differs from authoritative journal Event")
            reconciled.add(artifact_id)
        self._authoritative_ids = reconciled
        return {
            "record_type": "EvidenceReconcileResult",
            "status": "pass",
            "finalized_records": len(self._records),
            "authoritative_events": len(authoritative),
            "pending_orphans": len(self.pending_artifact_ids()),
        }

    def pending_artifact_ids(self) -> tuple[str, ...]:
        values: list[str] = []
        for path in self._metadata_paths(self.pending):
            staged = self._read_json_file(path, "staged evidence metadata")
            self._validate_stage_record(staged)
            values.append(staged["artifact"]["artifact_id"])
        return tuple(values)

    def finalized_artifact_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._records))

    def finalized_commit_bindings(self) -> tuple[dict[str, Any], ...]:
        """Expose immutable journal bindings for targeted authority reconciliation."""

        return tuple(
            deepcopy(self._records[artifact_id]["commit_binding"])
            for artifact_id in sorted(self._records)
        )

    def pending_record(self, artifact_id: str) -> dict[str, Any]:
        """Return one validated staged record for authoritative journal recovery."""

        path = self._pending_path(artifact_id)
        if not os.path.isfile(filesystem_path(path)):
            raise EvidenceError("staged evidence Artifact is unresolved")
        staged = self._read_json_file(path, "staged evidence metadata")
        self._validate_stage_record(staged)
        if staged["artifact"]["artifact_id"] != artifact_id:
            raise EvidenceError("staged evidence metadata identity mismatch")
        self._validate_object(staged["artifact"])
        return deepcopy(staged)

    def get(self, artifact_id: str) -> dict[str, Any]:
        record = self._records.get(artifact_id)
        if record is None or artifact_id not in self._authoritative_ids:
            raise EvidenceError("evidence Artifact is unresolved")
        if not self.is_resolved(record["artifact"]["digest"]):
            raise EvidenceError("evidence CAS object is corrupt")
        return deepcopy(record["artifact"])

    def get_record(self, artifact_id: str) -> dict[str, Any]:
        record = self._records.get(artifact_id)
        if record is None or artifact_id not in self._authoritative_ids:
            raise EvidenceError("evidence Artifact is unresolved")
        return deepcopy(record)

    def is_resolved(self, artifact_digest: str) -> bool:
        ids = self._by_digest.get(artifact_digest, [])
        if not ids:
            return False
        try:
            path = self._object_path(artifact_digest)
        except EvidenceError:
            return False
        native = filesystem_path(path)
        if (
            not os.path.isfile(native)
            or os.path.islink(native)
            or _digest_file(path) != artifact_digest
        ):
            return False
        return any(
            artifact_id in self._authoritative_ids
            and self._records[artifact_id]["artifact"]["size_bytes"]
            == os.stat(native).st_size
            for artifact_id in ids
        )

    def artifact_reference(self, artifact_id: str) -> dict[str, str]:
        """Return the only identity accepted by evidence-credit predicates."""

        record = self._records.get(artifact_id)
        if record is None or artifact_id not in self._authoritative_ids:
            raise EvidenceError("evidence Artifact is unresolved")
        self._validate_object(record["artifact"])
        return {
            "artifact_id": artifact_id,
            "artifact_record_digest": canonical_digest(record),
        }

    def _record_for_reference(
        self, artifact_id: str, artifact_record_digest: str
    ) -> dict[str, Any]:
        try:
            _safe_id(artifact_id)
        except EvidenceError:
            raise
        if not _valid_digest(artifact_record_digest):
            raise EvidenceError("invalid Artifact record digest")
        record = self._records.get(artifact_id)
        if (
            record is None
            or artifact_id not in self._authoritative_ids
            or canonical_digest(record) != artifact_record_digest
        ):
            raise EvidenceError("exact evidence Artifact record is unresolved")
        self._validate_object(record["artifact"])
        return record

    @staticmethod
    def _validate_purpose_class(purpose: str, evidence_class: str) -> None:
        allowed = _EVIDENCE_PURPOSE_CLASSES.get(purpose)
        if allowed is None or evidence_class not in allowed:
            raise EvidenceError("evidence purpose and class are incompatible")

    def _creditable_artifact(
        self,
        artifact_id: str,
        artifact_record_digest: str,
        *,
        candidate_digest: str,
        policy_digest: str,
        tool_digest: str,
        input_digests: Iterable[str],
        provider_invocation_digests: Iterable[str],
        activation_digest: str,
        implementation_closure_digest: str,
        evidence_class: str,
        purpose: str,
        expected_outcome: str | Iterable[str] = "pass",
        finding_digest: str | None = None,
        require_product_credit: bool = False,
    ) -> dict[str, Any] | None:
        self._validate_purpose_class(purpose, evidence_class)
        try:
            expected_inputs = list(input_digests)
            expected_providers = list(provider_invocation_digests)
            expected_outcomes = (
                [expected_outcome]
                if isinstance(expected_outcome, str)
                else list(expected_outcome)
            )
        except TypeError as exc:
            raise EvidenceError("evidence-credit digests are not iterable") from exc
        if (
            not expected_outcomes
            or len(expected_outcomes) != len(set(expected_outcomes))
            or not set(expected_outcomes) <= _OUTCOMES
            or not all(
                _valid_digest(value)
                for value in (
                    candidate_digest,
                    policy_digest,
                    tool_digest,
                    activation_digest,
                    implementation_closure_digest,
                )
            )
            or (finding_digest is not None and not _valid_digest(finding_digest))
            or not isinstance(require_product_credit, bool)
            or len(expected_inputs) != len(set(expected_inputs))
            or len(expected_inputs) > 128
            or len(expected_providers) != len(set(expected_providers))
            or len(expected_providers) > 32
            or not all(_valid_digest(value) for value in expected_inputs)
            or not all(_valid_digest(value) for value in expected_providers)
        ):
            raise EvidenceError("invalid exact evidence-credit expectation")
        try:
            record = self._record_for_reference(
                artifact_id, artifact_record_digest
            )
        except EvidenceError:
            return None
        artifact = record["artifact"]
        if artifact.get("artifact_kind") != "evidence":
            return None
        binding = artifact["evidence_binding"]
        actual_providers = [
            canonical_digest(invocation)
            for invocation in binding.get("provider_invocations", [])
        ]
        if (
            artifact["outcome"] not in expected_outcomes
            or artifact["stale"]
            or artifact["unresolved"]
            or artifact["evidence_class"] != evidence_class
            or artifact["evidence_purpose"] != purpose
            or binding["activation_digest"] != activation_digest
            or binding["implementation_closure_digest"]
            != implementation_closure_digest
            or binding["candidate_digest"] != candidate_digest
            or binding["policy_digest"] != policy_digest
            or binding["tool_digest"] != tool_digest
            or binding["input_digests"] != expected_inputs
            or actual_providers != expected_providers
            or binding.get("finding_digest") != finding_digest
            or (evidence_class == "product-execution" and not actual_providers)
            or (
                require_product_credit
                and (
                    not artifact["product_credit_eligible"]
                    or evidence_class != "product-execution"
                    or not actual_providers
                )
            )
        ):
            return None
        return artifact

    def has_product_credit(
        self,
        artifact_id: str,
        artifact_record_digest: str,
        *,
        candidate_digest: str,
        policy_digest: str,
        tool_digest: str,
        input_digests: Iterable[str],
        provider_invocation_digests: Iterable[str],
        activation_digest: str,
        implementation_closure_digest: str,
        finding_digest: str | None = None,
    ) -> bool:
        return self._creditable_artifact(
            artifact_id,
            artifact_record_digest,
            candidate_digest=candidate_digest,
            policy_digest=policy_digest,
            tool_digest=tool_digest,
            input_digests=input_digests,
            provider_invocation_digests=provider_invocation_digests,
            activation_digest=activation_digest,
            implementation_closure_digest=implementation_closure_digest,
            evidence_class="product-execution",
            purpose="product",
            finding_digest=finding_digest,
            require_product_credit=True,
        ) is not None

    def _resolve_digest(self, artifact_digest: str) -> list[dict[str, Any]]:
        ids = self._by_digest.get(artifact_digest, [])
        if not ids or not self.is_resolved(artifact_digest):
            raise EvidenceError("evidence digest is unresolved")
        return [self._records[artifact_id] for artifact_id in ids]

    def is_creditable(
        self,
        artifact_id: str,
        artifact_record_digest: str,
        *,
        candidate_digest: str,
        policy_digest: str,
        tool_digest: str,
        input_digests: Iterable[str],
        provider_invocation_digests: Iterable[str],
        activation_digest: str,
        implementation_closure_digest: str,
        evidence_class: str,
        purpose: str,
        expected_outcome: str | Iterable[str] = "pass",
        finding_digest: str | None = None,
        require_product_credit: bool = False,
    ) -> bool:
        return self._creditable_artifact(
            artifact_id,
            artifact_record_digest,
            candidate_digest=candidate_digest,
            policy_digest=policy_digest,
            tool_digest=tool_digest,
            input_digests=input_digests,
            provider_invocation_digests=provider_invocation_digests,
            activation_digest=activation_digest,
            implementation_closure_digest=implementation_closure_digest,
            evidence_class=evidence_class,
            purpose=purpose,
            expected_outcome=expected_outcome,
            finding_digest=finding_digest,
            require_product_credit=require_product_credit,
        ) is not None

    def require_creditable(
        self,
        artifact_id: str,
        artifact_record_digest: str,
        **expected: Any,
    ) -> dict[str, Any]:
        artifact = self._creditable_artifact(
            artifact_id, artifact_record_digest, **expected
        )
        if artifact is None:
            raise EvidenceError("evidence is failed, blocked, stale, unresolved, or unbound")
        return deepcopy(artifact)

    def resolved_artifacts(self, artifact_digest: str) -> list[dict[str, Any]]:
        """Return immutable metadata for every authoritative Artifact with this digest."""

        return [deepcopy(record["artifact"]) for record in self._resolve_digest(artifact_digest)]

    def has_current_implementation_binding(
        self,
        artifact_id: str,
        artifact_record_digest: str,
        *,
        activation_digest: str,
        implementation_closure_digest: str,
    ) -> bool:
        """Check an Artifact against the current Activation implementation closure."""

        try:
            record = self._record_for_reference(
                artifact_id, artifact_record_digest
            )
        except EvidenceError:
            return False
        return (
            record["artifact"].get("artifact_kind") == "evidence"
            and record["artifact"]["evidence_binding"]["activation_digest"]
            == activation_digest
            and record["artifact"]["evidence_binding"][
                "implementation_closure_digest"
            ]
            == implementation_closure_digest
        )

    def has_finding_binding(
        self,
        artifact_id: str,
        artifact_record_digest: str,
        *,
        finding_digest: str,
        candidate_digest: str,
        activation_digest: str,
        implementation_closure_digest: str,
        policy_digest: str,
        tool_digest: str,
        input_digests: Iterable[str],
        provider_invocation_digests: Iterable[str],
        evidence_class: str,
        purpose: str = "gate",
    ) -> bool:
        """Require fresh passing evidence bound to one exact Finding snapshot."""

        return self._creditable_artifact(
            artifact_id,
            artifact_record_digest,
            candidate_digest=candidate_digest,
            policy_digest=policy_digest,
            tool_digest=tool_digest,
            input_digests=input_digests,
            provider_invocation_digests=provider_invocation_digests,
            activation_digest=activation_digest,
            implementation_closure_digest=implementation_closure_digest,
            evidence_class=evidence_class,
            purpose=purpose,
            finding_digest=finding_digest,
        ) is not None

    def require_candidate_delta(
        self,
        artifact_digest: str,
        *,
        base_candidate_digest: str,
        new_candidate_digest: str,
        workcard_digest: str,
    ) -> dict[str, Any]:
        """Resolve one immutable diff Artifact with exact Candidate/WorkCard binding."""

        expected = {
            "base_candidate_digest": base_candidate_digest,
            "new_candidate_digest": new_candidate_digest,
            "workcard_digest": workcard_digest,
        }
        matches: list[dict[str, Any]] = []
        for record in self._resolve_digest(artifact_digest):
            artifact = record["artifact"]
            if artifact["artifact_kind"] != "diff":
                continue
            delta = artifact["candidate_delta"]
            if all(delta[key] == value for key, value in expected.items()):
                matches.append(artifact)
        if len(matches) != 1:
            raise EvidenceError("Candidate delta does not resolve one exact diff Artifact")
        return deepcopy(matches[0])

    def validate_gate_evidence(
        self,
        gate_result: Mapping[str, Any],
        *,
        gate_run_definition: Mapping[str, Any],
        run_record: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        """Validate one exact Run and its finalized Artifacts against a definition."""

        if not isinstance(gate_run_definition, Mapping):
            raise EvidenceError("GateRunDefinition is not an object")
        definition = deepcopy(dict(gate_run_definition))
        if (
            set(definition) != _GATE_RUN_DEFINITION_FIELDS
            or definition.get("definition_kind") != "GateRunDefinition"
            or definition.get("owner_kind") != "Task"
        ):
            raise EvidenceError("GateRunDefinition has an invalid canonical shape")
        for field in ("definition_id", "gate_id"):
            _safe_id(definition.get(field))
        defined_at_head = definition.get("defined_at_head_digest")
        digest_fields = (
            "owner_digest",
            "target_digest",
            "candidate_digest",
            "policy_digest",
            "tool_digest",
            "implementation_closure_digest",
            "provider_binding_digest",
            "activation_digest",
        )
        if (
            any(not _valid_digest(definition.get(field)) for field in digest_fields)
            or (defined_at_head is not None and not _valid_digest(defined_at_head))
            or definition.get("run_kind") not in {"execution", "validation"}
            or definition.get("target_kind") not in {"candidate", "finding"}
            or (
                definition.get("target_kind") == "candidate"
                and definition.get("target_digest")
                != definition.get("candidate_digest")
            )
        ):
            raise EvidenceError("GateRunDefinition target or digest is invalid")
        inputs = definition.get("input_digests")
        target_scope = definition.get("target_scope")
        if (
            not isinstance(inputs, list)
            or len(inputs) > 128
            or len(inputs) != len(set(inputs))
            or not all(_valid_digest(value) for value in inputs)
            or not isinstance(target_scope, list)
            or not target_scope
            or len(target_scope) > 32
            or any(
                not isinstance(selector, Mapping)
                or set(selector) != {"kind", "value"}
                or not isinstance(selector.get("kind"), str)
                or not selector["kind"]
                or not isinstance(selector.get("value"), str)
                or not selector["value"]
                for selector in target_scope
            )
            or len({canonical_digest(selector) for selector in target_scope})
            != len(target_scope)
        ):
            raise EvidenceError("GateRunDefinition inputs or target scope are invalid")
        expected_class = definition.get("expected_evidence_class")
        expected_purpose = definition.get("expected_evidence_purpose")
        product_credit_required = definition.get("product_credit_required")
        if (
            expected_purpose not in _GATE_PURPOSE_CLASSES
            or expected_class not in _GATE_PURPOSE_CLASSES[expected_purpose]
            or not isinstance(product_credit_required, bool)
            or (
                product_credit_required
                and (
                    expected_purpose != "product"
                    or expected_class != "product-execution"
                )
            )
        ):
            raise EvidenceError("GateRunDefinition evidence expectation is invalid")

        if not isinstance(run_record, Mapping):
            raise EvidenceError("GateResult Run is not an object")
        run = deepcopy(dict(run_record))
        if set(run) != _GATE_RUN_FIELDS or run.get("record_type") != "Run":
            raise EvidenceError("GateResult Run has an invalid canonical shape")
        for field in ("run_id", "task_id"):
            _safe_id(run.get(field))
        definition_digest = canonical_digest(definition)
        run_inputs = run.get("input_digests")
        run_status = run.get("status")
        normalized_run_status = (
            "fail" if run_status in {"fail", "error"} else run_status
        )
        if (
            run.get("run_kind") != definition["run_kind"]
            or run.get("definition_digest") != definition_digest
            or run.get("candidate_digest") != definition["candidate_digest"]
            or run.get("policy_digest") != definition["policy_digest"]
            or run.get("tool_digest") != definition["tool_digest"]
            or run.get("activation_digest") != definition["activation_digest"]
            or run.get("implementation_closure_digest")
            != definition["implementation_closure_digest"]
            or run.get("provider_binding_digest")
            != definition["provider_binding_digest"]
            or not isinstance(run_inputs, list)
            or run_inputs != inputs
            or len(run_inputs) != len(set(run_inputs))
            or any(not _valid_digest(value) for value in run_inputs)
            or run_status not in _OUTCOMES
            or normalized_run_status not in {"pass", "fail", "blocked", "skipped"}
        ):
            raise EvidenceError("GateResult Run differs from its GateRunDefinition")
        if parse_timestamp(run["started_at"]) > parse_timestamp(run["finished_at"]):
            raise EvidenceError("GateResult Run chronology is invalid")
        run_digest = canonical_digest(run)

        if not isinstance(gate_result, Mapping):
            raise EvidenceError("GateResult is not an object")
        result = deepcopy(dict(gate_result))
        status = result.get("status")
        required_fields = _GATE_RESULT_FIELDS | (
            {"reason"} if status in {"blocked", "skipped"} else set()
        )
        allowed_fields = _GATE_RESULT_FIELDS | (
            {"reason"} if status != "pass" else set()
        )
        if (
            not required_fields <= set(result)
            or not set(result) <= allowed_fields
            or result.get("record_type") != "GateResult"
        ):
            raise EvidenceError("GateResult has an invalid canonical shape")
        for field in ("task_id", "gate_id", "run_id"):
            _safe_id(result.get(field))
        if status not in {"pass", "fail", "blocked", "skipped"}:
            raise EvidenceError("GateResult status is invalid")
        if result.get("outcome") != status:
            raise EvidenceError("GateResult outcome differs from normalized status")
        if "reason" in result and (
            not isinstance(result["reason"], str) or not result["reason"]
        ):
            raise EvidenceError("GateResult reason is invalid")
        if (
            result.get("run_id") != run["run_id"]
            or result.get("task_id") != run["task_id"]
            or result.get("run_digest") != run_digest
            or result.get("status") != normalized_run_status
        ):
            raise EvidenceError("GateResult differs from its exact Run")
        for result_field, definition_field in (
            ("gate_id", "gate_id"),
            ("candidate_digest", "candidate_digest"),
            ("policy_digest", "policy_digest"),
            ("tool_digest", "tool_digest"),
            ("activation_digest", "activation_digest"),
            ("evidence_class", "expected_evidence_class"),
        ):
            if result.get(result_field) != definition[definition_field]:
                raise EvidenceError("GateResult differs from its GateRunDefinition")
        if result.get("definition_digest") != definition_digest:
            raise EvidenceError("GateResult definition digest is unresolved")
        expected_credit = status == "pass" and product_credit_required
        if result.get("pass_credit") is not expected_credit:
            raise EvidenceError("GateResult pass credit differs from its definition")

        references = result.get("evidence_artifacts")
        if not isinstance(references, list) or any(
            not isinstance(reference, Mapping)
            or set(reference) != _GATE_EVIDENCE_ARTIFACT_BINDING_FIELDS
            or reference.get("run_id") != run["run_id"]
            or reference.get("run_digest") != run_digest
            for reference in references
        ):
            raise EvidenceError("GateResult Artifact bindings are invalid")
        reference_identities = [
            (reference.get("artifact_id"), reference.get("artifact_record_digest"))
            for reference in references
        ]
        if (
            len(references) > 64
            or len(reference_identities) != len(set(reference_identities))
            or (status == "skipped" and references)
            or (status != "skipped" and not references)
        ):
            raise EvidenceError(
                "GateResult Artifact bindings must be exact, unique, and status-bound"
            )
        if status == "skipped":
            return []

        finding_digest = (
            definition["target_digest"]
            if definition["target_kind"] == "finding"
            else None
        )
        expected_outcomes: tuple[str, ...]
        if status == "pass":
            expected_outcomes = ("pass",)
        elif status == "fail":
            expected_outcomes = ("fail", "error")
        else:
            expected_outcomes = ("blocked",)
        resolved: list[dict[str, Any]] = []
        for reference in references:
            record = self._record_for_reference(
                reference["artifact_id"], reference["artifact_record_digest"]
            )
            artifact_record = record["artifact"]
            binding = artifact_record.get("evidence_binding")
            provider_invocations = (
                binding.get("provider_invocations", [])
                if isinstance(binding, Mapping)
                else []
            )
            provider_digests = [
                canonical_digest(invocation) for invocation in provider_invocations
            ]
            artifact = self._creditable_artifact(
                reference["artifact_id"],
                reference["artifact_record_digest"],
                candidate_digest=definition["candidate_digest"],
                policy_digest=definition["policy_digest"],
                tool_digest=definition["tool_digest"],
                input_digests=inputs,
                provider_invocation_digests=provider_digests,
                activation_digest=definition["activation_digest"],
                implementation_closure_digest=definition[
                    "implementation_closure_digest"
                ],
                evidence_class=expected_class,
                purpose=expected_purpose,
                expected_outcome=expected_outcomes,
                finding_digest=finding_digest,
                require_product_credit=expected_credit,
            )
            if artifact is None:
                raise EvidenceError(
                    "GateResult evidence differs from GateRunDefinition"
                )
            resolved.append(deepcopy(artifact))
        return resolved
