#!/usr/bin/env python3
"""Strict structural validator for the canonical promin standard folder."""

from __future__ import annotations

import argparse
import ast
from collections import OrderedDict
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import platform
import re
import signal
import shutil
import sqlite3
import stat
import subprocess
import sys
import sysconfig
import tempfile
import time
import tomllib
import unicodedata
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:  # pragma: no cover - reported as a validation failure
    Draft202012Validator = None  # type: ignore[assignment]
    FormatChecker = None  # type: ignore[assignment]


SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)
CORE_FILES = frozenset(
    {
        "promin.manifest.json",
        "semantic-model.json",
        "authority-model.json",
        "policy-set.json",
        "contracts.schema.json",
        "conformance.json",
    }
)
OWNER_DEFINITIONS = {
    "promin.manifest.json": "StandardManifest",
    "semantic-model.json": "SemanticModel",
    "authority-model.json": "AuthorityModel",
    "policy-set.json": "PolicySet",
    "conformance.json": "Conformance",
}
HUMAN_PDFS = frozenset(
    {
        "human/promin_main_ua.pdf",
        "human/promin_appendices_ua.pdf",
        "human/promin_main_en.pdf",
        "human/promin_appendices_en.pdf",
    }
)
# PDF text extraction is intentionally expensive.  Archive construction checks
# the same immutable PDF bytes through several clean copies, so retain only
# successful in-process summaries by their freshly recomputed content digest.
# This never persists a result, never bypasses the byte/header checks below,
# and never caches a parser failure.
_HUMAN_DOCUMENT_SUMMARIES: OrderedDict[str, tuple[int, int, tuple[int, ...]]] = OrderedDict()
_MAX_HUMAN_DOCUMENT_SUMMARIES = 32
INIT_DEFINITIONS = frozenset({"ProjectInit", "StandardsInit", "TechnologiesInit", "AuthorityInit", "Activation"})
GENERATED_SURFACES = frozenset({"MANIFEST.json", "SHA256SUMS.txt"})
CANONICAL_PACKAGE_FILE_COUNT = 285
CANONICAL_PACKAGE_DIRECTORY_COUNT = 17
CANONICAL_PACKAGE_FILES = frozenset(
    {
        '.gitattributes',
        '.github/workflows/alpha-portability.yml',
        '.gitignore',
        'capability_profiles/standard-init.json',
        'capability_profiles/standing-reversible.json',
        'CONTRIBUTING.md',
        'core/authority-model.json',
        'core/conformance.json',
        'core/contracts.schema.json',
        'core/policy-set.json',
        'core/promin.manifest.json',
        'core/semantic-model.json',
        'docs/ALPHA_SCOPE_UA.md',
        'docs/ARTIFACT_TAXONOMY_UA.md',
        'docs/C_CPP_CAPABILITY_PROFILE_UA.md',
        'docs/CLEAN_REINITIALIZATION_UA.md',
        'docs/COMPARATIVE_BENCHMARK_UA.md',
        'docs/EXPERT_CONFIG_UA.md',
        'docs/INIT_CAPABILITIES_UA.md',
        'docs/LANGUAGE_CAPABILITIES_UA.md',
        'docs/LINUX_MODEL_VALIDATION_UA.md',
        'docs/MIGRATION_ALPHA3_TO_ALPHA4_UA.md',
        'docs/MODEL_ROUTING_UA.md',
        'docs/PORTABILITY_UA.md',
        'docs/PORTABLE_CONTEXT_ARCHITECTURE_UA.md',
        'docs/PRODUCT_DOCTRINE_UA.md',
        'docs/PROFILE_CATALOG_UA.md',
        'docs/PRODUCT_INSPECTION_UA.md',
        'docs/PROVIDER_IDENTITIES_UA.md',
        'docs/QUICKSTART_IF_THEN_UA.md',
        'docs/RECEIPTS_AND_INVALIDATION_UA.md',
        'docs/REVALIDATION_AND_REPORTING_UA.md',
        'docs/RUNTIME_AUDIT_UA.md',
        'docs/SKILLS_UA.md',
        'docs/STATIC_ADMISSION_UA.md',
        'docs/SYSTEM_CHECKLIST_UA.md',
        'docs/WEAK_MODEL_EXECUTION_UA.md',
        'docs/audit/ALPHA4_HEAVY_HARDENING_WAVE_UA.md',
        'docs/audit/2026-08-21-client-report-implementation-plan.md',
        'docs/audit/2026-08-21-language-tooling-implementation-plan.md',
        'docs/audit/2026-08-21-public-workflow-and-tooling-design.md',
        'docs/audit/2026-08-21-public-workflow-implementation-plan.md',
        'docs/audit/2026-08-22-continuation-renewal-wave.md',
        'docs/audit/PROMIN_ALPHA4_VERIFIED_COMMIT_PHASE_WAVE.md',
        'examples/project-brief.json',
        'human/promin_appendices_en.pdf',
        'human/promin_appendices_ua.pdf',
        'human/promin_main_en.pdf',
        'human/promin_main_ua.pdf',
        'language_profiles/c-family-semantic.json',
        'language_profiles/csharp-semantic.json',
        'language_profiles/javascript-typescript-semantic.json',
        'language_profiles/jvm-semantic.json',
        'language_profiles/open-source-tooling.json',
        'language_profiles/python-semantic.json',
        'language_profiles/weak-host-fallback.json',
        'LICENSE',
        'MACHINE_README.md',
        'MANIFEST.json',
        'NOTICE',
        'presets/semantic-standard.json',
        'profiles/android-application.json',
        'profiles/ask.json',
        'profiles/c-family-development.json',
        'profiles/en.json',
        'profiles/general-development.json',
        'profiles/mobile-application.json',
        'profiles/README.md',
        'profiles/standing-reversible.json',
        'profiles/uk.json',
        'profiles/vibe-recovery.json',
        'profiles/web-application.json',
        'profiles/windows-development.json',
        'promin/__init__.py',
        'promin/__main__.py',
        'promin/client_report.py',
        'promin/language_tooling.py',
        'promin/public_recovery.py',
        'promin/artifact_policy.py',
        'promin/audit.py',
        'promin/authority.py',
        'promin/autonomy_policy.py',
        'promin/canonical.py',
        'promin/clean_reinitialization.py',
        'promin/cmake_file_api.py',
        'promin/compilation_database.py',
        'promin/conformance.py',
        'promin/context_index.py',
        'promin/contracts.py',
        'promin/cpp_lexical.py',
        'promin/documentation.py',
        'promin/domain.py',
        'promin/dynamic_handoff.py',
        'promin/events.py',
        'promin/evidence.py',
        'promin/experience.py',
        'promin/final_admission.py',
        'promin/gate_admission.py',
        'promin/gitpolicy.py',
        'promin/host_integration.py',
        'promin/init.py',
        'promin/init_profiles.py',
        'promin/initial_project_work.py',
        'promin/input_identity.py',
        'promin/language_analysis.py',
        'promin/language_catalog.py',
        'promin/limits.py',
        'promin/mutation_suite.py',
        'promin/platform_paths.py',
        'promin/portability.py',
        'promin/project_package.py',
        'promin/projection.py',
        'promin/product_inspection.py',
        'promin/provider_envelope.py',
        'promin/provider_receipts.py',
        'promin/provider_store.py',
        'promin/publication.py',
        'promin/recovery.py',
        'promin/revalidation.py',
        'promin/revalidation_workflow.py',
        'promin/refresh.py',
        'promin/resources.py',
        'promin/selector_shards.py',
        'promin/semantic_scope.py',
        'promin/service.py',
        'promin/skills.py',
        'promin/static_admission.py',
        'promin/system_check.py',
        'promin/telemetry.py',
        'promin/version.py',
        'promin/workspace.py',
        'promin/writer_identity.py',
        'promin/weak_model_execution.py',
        'promin/weak_model_workflow.py',
        'promin/windows_event_history.py',
        'prompts/INIT_PROMPT_EN.txt',
        'prompts/INIT_PROMPT_UA.txt',
        'pyproject.toml',
        'README.md',
        'SECURITY.md',
        'SHA256SUMS.txt',
        'skills/example/promin.skill.json',
        'skills/example/SKILL.md',
        'skills/README.md',
        'skills/skill.schema.json',
        'tests/ALPHA4_TEST_SHARDS.json',
        'tests/test_alpha_audit.py',
        'tests/test_alpha_context_index.py',
        'tests/test_alpha_deployable.py',
        'tests/test_alpha_experience.py',
        'tests/test_alpha_host_pickup.py',
        'tests/test_alpha_incremental_layer.py',
        'tests/test_alpha_monorepo_context.py',
        'tests/test_alpha_portability.py',
        'tests/test_alpha_promin_docs_shell.py',
        'tests/test_alpha_skills.py',
        'tests/test_alpha_skills_checklist.py',
        'tests/test_alpha3_ingress_budget.py',
        'tests/test_alpha3_opus_closure.py',
        'tests/test_alpha3_plan_headroom.py',
        'tests/test_alpha3_reconciliation_aliased_temp_tree.py',
        'tests/test_alpha3_reconciliation_package.py',
        'tests/test_alpha3_reconciliation_paths.py',
        'tests/test_alpha3_reconciliation_performance.py',
        'tests/test_alpha3_reconciliation_static.py',
        'tests/test_alpha3_reconciliation_windows.py',
        'tests/test_alpha3_workspace_budget.py',
        'tests/test_alpha4_artifact_lifecycle.py',
        'tests/test_alpha4_autonomy_policy.py',
        'tests/test_alpha4_bundled_language_catalog.py',
        'tests/test_alpha4_clean_reinitialization_operation.py',
        'tests/test_alpha4_cmake_file_api.py',
        'tests/test_alpha4_compilation_database.py',
        'tests/test_alpha4_dynamic_handoff.py',
        'tests/test_alpha4_extensions_clean_init.py',
        'tests/test_alpha4_final_package_admission.py',
        'tests/test_alpha4_gate_admission.py',
        'tests/test_alpha4_genericity.py',
        'tests/test_alpha4_init_evidence_first_profiles.py',
        'tests/test_alpha4_init_profiles.py',
        'tests/test_alpha4_language_analysis.py',
        'tests/test_alpha4_project_package.py',
        'tests/test_alpha4_provider_envelopes.py',
        'tests/test_alpha4_provider_receipts.py',
        'tests/test_alpha4_recovery_locks.py',
        'tests/test_alpha4_selector_shard_runner.py',
        'tests/test_alpha4_selector_shards.py',
        'tests/test_alpha4_semantic_scope_gates.py',
        'tests/test_alpha4_static_admission.py',
        'tests/test_alpha4_windows_publication.py',
        'tests/test_authority_domain.py',
        'tests/test_bootstrap_mutation_verification.py',
        'tests/test_canonical_init.py',
        'tests/test_concurrency_crash.py',
        'tests/test_contract_mutations.py',
        'tests/test_continuation_renewal.py',
        'tests/test_events_projection.py',
        'tests/test_expert_init_bundle_roundtrip.py',
        'tests/test_heavy_artifact_minimality.py',
        'tests/test_heavy_checkpoint_profile.py',
        'tests/test_heavy_comparative_bench.py',
        'tests/test_heavy_derived_storage.py',
        'tests/test_heavy_event_batching.py',
        'tests/test_heavy_eventstore_commit_io_profile.py',
        'tests/test_heavy_eventstore_lifecycle.py',
        'tests/test_heavy_eventstore_postcommit_index_failure.py',
        'tests/test_heavy_eventstore_prefix_witness.py',
        'tests/test_heavy_eventstore_validator_cache.py',
        'tests/test_heavy_failclosed_adversarial.py',
        'tests/test_heavy_init_profiles.py',
        'tests/test_heavy_language_analysis.py',
        'tests/test_heavy_language_catalog.py',
        'tests/test_heavy_language_profile_catalog.py',
        'tests/test_heavy_linux_model.py',
        'tests/test_heavy_performance_model.py',
        'tests/test_heavy_product_inspection.py',
        'tests/test_heavy_projection_bulk_rebuild.py',
        'tests/test_heavy_projection_incremental_shards.py',
        'tests/test_heavy_projection_profile.py',
        'tests/test_heavy_provider_identity.py',
        'tests/test_heavy_query_tail_scale.py',
        'tests/test_heavy_receipt_cache.py',
        'tests/test_heavy_recovery_stress.py',
        'tests/test_heavy_relation_ledger_hotpath.py',
        'tests/test_heavy_revalidation.py',
        'tests/test_heavy_runtime_checkpoint_incremental.py',
        'tests/test_heavy_saturation_continuation_sqlite.py',
        'tests/test_heavy_saturation_storage_budget.py',
        'tests/test_heavy_state_binding_batch_union.py',
        'tests/test_heavy_state_binding_batching.py',
        'tests/test_heavy_state_binding_storage.py',
        'tests/test_heavy_state_binding_storage_retention.py',
        'tests/test_heavy_weak_model_execution.py',
        'tests/test_heavy_weak_model_workflow.py',
        'tests/test_heavy_windows_event_history.py',
        'tests/test_heavy_windows_publication.py',
        'tests/test_heavy_windows_seal_scaling.py',
        'tests/test_initial_project_work.py',
        'tests/test_init_layer_configured_routes.py',
        'tests/test_installed_distribution.py',
        'tests/test_client_report_tool.py',
        'tests/test_language_tooling.py',
        'tests/test_package_validation.py',
        'tests/test_platform_paths_hotpath.py',
        'tests/test_projection_profile_cleanup.py',
        'tests/test_public_workflows_cli.py',
        'tests/test_retrieval_continuation_service.py',
        'tests/test_revalidation_workflow.py',
        'tests/test_saturation_archive_binding.py',
        'tests/test_saturation_raw_artifact_cardinality.py',
        'tests/test_saturation_schema_meta_policy.py',
        'tests/test_saturation_vcs_maintenance_policy.py',
        'tests/test_scale_orchestration.py',
        'tests/test_search_scale.py',
        'tests/test_service_cli.py',
        'tests/test_service_mutation_cache.py',
        'tests/test_verified_commit_phase.py',
        'tests/test_verified_commit_phase_activation_binding.py',
        'tests/test_verified_commit_phase_refresh_budget.py',
        'tests/test_verified_commit_phase_service.py',
        'tests/test_verified_commit_phase_tamper.py',
        'tests/test_verified_envelope_snapshot.py',
        'tests/test_verified_query_phase.py',
        'THIRD_PARTY_NOTICES.md',
        'tools/compile_schema.py',
        'tools/generate_human.py',
        'tools/promin.py',
        'tools/promin_alpha_check.py',
        'tools/promin_checkpoint_profile.py',
        'tools/promin_command_bench.py',
        'tools/promin_comparative_bench.py',
        'tools/promin_init.py',
        'tools/promin_linux_model.py',
        'tools/promin_no_degradation.py',
        'tools/promin_package.py',
        'tools/promin_client_report.py',
        'tools/promin_performance_model.py',
        'tools/promin_projection_profile.py',
        'tools/promin_runtime.py',
        'tools/promin_saturation.py',
        'tools/promin_saturation_audit.py',
        'tools/promin_service.py',
        'tools/promin_validate.py',
        'TRADEMARKS.md',
        'VERSION.json',
    }
)
CANONICAL_PACKAGE_DIRECTORIES = frozenset(
    {
        '.github',
        '.github/workflows',
        'capability_profiles',
        'core',
        'docs',
        'docs/audit',
        'examples',
        'human',
        'language_profiles',
        'presets',
        'profiles',
        'promin',
        'prompts',
        'skills',
        'skills/example',
        'tests',
        'tools',
    }
)
CANONICAL_PAYLOAD_FILES = CANONICAL_PACKAGE_FILES - GENERATED_SURFACES
IGNORED_TRANSIENTS = frozenset(
    {
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".cache",
        "cache",
        "_work",
        ".venv",
        "venv",
        "build",
        "dist",
        "htmlcov",
    }
)
TEXT_SUFFIXES = frozenset(
    {
        "",
        ".json",
        ".md",
        ".py",
        ".toml",
        ".txt",
        ".yaml",
        ".yml",
        ".tex",
        ".csv",
        ".ps1",
        ".sh",
    }
)
WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
)
OLD_IDENTITY = "agent" + "doc"
FULL_ALIAS_UNDERSCORE = "promin" + "_full"
FULL_ALIAS_HYPHEN = "promin" + "-full"
FORBIDDEN_ALIASES = (OLD_IDENTITY, FULL_ALIAS_UNDERSCORE, FULL_ALIAS_HYPHEN)
FORBIDDEN_DEVELOPMENT_LABELS = (
    re.compile(rb"\b" + b"ph" + rb"6(?:[-_][0-9]+)?\b", re.IGNORECASE),
    re.compile(rb"\b" + b"recovery" + rb"[-_ ]package\b", re.IGNORECASE),
    re.compile(rb"\b" + b"v" + b"6" + rb"probe[a-z0-9_-]*\b", re.IGNORECASE),
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_DISTRIBUTION_FILE_BYTES = 128 * 1024 * 1024
MAX_DISTRIBUTION_BYTES = 512 * 1024 * 1024
INSTALL_MODES = ("current-environment", "offline-wheelhouse", "online-clean")
FONT_ROLES = ("regular", "bold", "italic", "mono")
class ValidationFailure(RuntimeError):
    pass


def _canonical_standard_version(root: Path) -> str:
    try:
        value = json.loads((root / "core" / "promin.manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationFailure("canonical manifest version is unavailable") from exc
    version = value.get("version") if isinstance(value, dict) else None
    if not isinstance(version, str):
        raise ValidationFailure("canonical manifest version is invalid")
    return version



def _remaining_deadline_seconds(deadline_monotonic: float | None, phase: str) -> float | None:
    if deadline_monotonic is None:
        return None
    if not isinstance(deadline_monotonic, (int, float)) or isinstance(deadline_monotonic, bool):
        raise ValidationFailure("subprocess deadline must be a monotonic timestamp")
    remaining = float(deadline_monotonic) - time.monotonic()
    if remaining <= 0:
        raise ValidationFailure(f"{phase} exceeded the total execution deadline")
    return remaining


def _create_windows_kill_job() -> int | None:
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        return None
    information = ExtendedLimitInformation()
    information.BasicLimitInformation.LimitFlags = 0x00002000
    if not kernel32.SetInformationJobObject(
        job,
        9,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        kernel32.CloseHandle(job)
        return None
    return int(job)


def _assign_windows_kill_job(job_handle: int, process: subprocess.Popen[Any]) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    return bool(
        kernel32.AssignProcessToJobObject(
            wintypes.HANDLE(job_handle),
            wintypes.HANDLE(int(process._handle)),
        )
    )


def _resume_windows_process(process: subprocess.Popen[Any]) -> None:
    import ctypes
    from ctypes import wintypes

    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
    ntdll.NtResumeProcess.restype = ctypes.c_long
    status = ntdll.NtResumeProcess(wintypes.HANDLE(int(process._handle)))
    if status != 0:
        raise OSError(f"NtResumeProcess failed with status 0x{status & 0xFFFFFFFF:08x}")


def _close_windows_handle(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle(wintypes.HANDLE(handle))


def _windows_job_active_processes(job_handle: int) -> int | None:
    import ctypes
    from ctypes import wintypes

    class BasicAccountingInformation(ctypes.Structure):
        _fields_ = [
            ("TotalUserTime", ctypes.c_longlong),
            ("TotalKernelTime", ctypes.c_longlong),
            ("ThisPeriodTotalUserTime", ctypes.c_longlong),
            ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
            ("TotalPageFaultCount", wintypes.DWORD),
            ("TotalProcesses", wintypes.DWORD),
            ("ActiveProcesses", wintypes.DWORD),
            ("TotalTerminatedProcesses", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.QueryInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
    )
    kernel32.QueryInformationJobObject.restype = wintypes.BOOL
    information = BasicAccountingInformation()
    if not kernel32.QueryInformationJobObject(
        wintypes.HANDLE(job_handle),
        1,
        ctypes.byref(information),
        ctypes.sizeof(information),
        None,
    ):
        return None
    return int(information.ActiveProcesses)


def _terminate_windows_job(job_handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject(wintypes.HANDLE(job_handle), 1)


def _spawn_bounded_process(
    command: list[str],
    **kwargs: Any,
) -> tuple[subprocess.Popen[Any], int | None]:
    job_handle = _create_windows_kill_job()
    if os.name == "nt" and job_handle is None:
        raise ValidationFailure("Windows process-tree containment job could not be created")
    if os.name == "nt":
        kwargs["creationflags"] = int(kwargs.get("creationflags", 0)) | 0x00000004
    try:
        process = subprocess.Popen(command, **kwargs)
    except Exception:
        if job_handle is not None:
            _close_windows_handle(job_handle)
        raise
    try:
        if job_handle is not None and not _assign_windows_kill_job(job_handle, process):
            raise ValidationFailure("Windows process could not be assigned to its containment job")
        if os.name == "nt":
            _resume_windows_process(process)
    except Exception:
        if job_handle is not None:
            _terminate_windows_job(job_handle)
            _close_windows_handle(job_handle)
        else:
            process.kill()
        process.wait(timeout=5)
        raise
    return process, job_handle


def _close_bounded_process_tree(
    process: subprocess.Popen[Any],
    job_handle: int | None,
    *,
    force: bool,
) -> bool:
    """Close the whole tree even when the original process has already exited."""

    terminated = False
    if os.name == "nt" and job_handle is not None:
        active = _windows_job_active_processes(job_handle)
        terminated = force or active is None or active > 0
        if terminated:
            _terminate_windows_job(job_handle)
        _close_windows_handle(job_handle)
    elif os.name == "nt":
        if process.poll() is None:
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=10,
                )
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
            terminated = True
    else:
        try:
            os.killpg(process.pid, 0)
            group_exists = True
        except ProcessLookupError:
            group_exists = False
        except PermissionError:
            group_exists = True
        if group_exists:
            terminated = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    os.killpg(process.pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    if process.poll() is None:
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait(timeout=5)
            raise ValidationFailure("bounded subprocess tree could not be terminated") from exc
    return terminated


def _run_capture_with_deadline(
    command: list[str],
    *,
    cwd: Path | None,
    environment: dict[str, str],
    deadline_monotonic: float | None,
    phase: str,
) -> subprocess.CompletedProcess[str]:
    """Preserve ordinary package paths while bounding no-degradation descendants."""

    remaining = _remaining_deadline_seconds(deadline_monotonic, phase)
    if remaining is None:
        return subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
    creationflags = (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    )
    process, job_handle = _spawn_bounded_process(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=creationflags,
        start_new_session=os.name != "nt",
    )
    try:
        stdout, stderr = process.communicate(timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        _close_bounded_process_tree(process, job_handle, force=True)
        raise ValidationFailure(f"{phase} exceeded the total execution deadline") from exc
    _close_bounded_process_tree(process, job_handle, force=False)
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def distribution_identity(root: Path) -> dict[str, str]:
    standard = load_json(root / "core" / "promin.manifest.json")
    standard_version = standard.get("version")
    if not isinstance(standard_version, str) or SEMVER.fullmatch(standard_version) is None:
        raise ValidationFailure("Core manifest version must be structural SemVer")
    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = metadata.get("project")
    if not isinstance(project, dict) or project.get("name") != "promin":
        raise ValidationFailure("pyproject.toml distribution identity is invalid")
    python_version = project.get("version")
    expected_python = standard_version
    rc = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+)-rc\.([1-9][0-9]*)", standard_version)
    alpha = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+)-alpha\.([1-9][0-9]*)", standard_version)
    beta = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+)-beta\.([1-9][0-9]*)", standard_version)
    if rc:
        expected_python = f"{rc.group(1)}rc{rc.group(2)}"
    elif alpha:
        expected_python = f"{alpha.group(1)}a{alpha.group(2)}"
    elif beta:
        expected_python = f"{beta.group(1)}b{beta.group(2)}"
    if python_version != expected_python:
        raise ValidationFailure(
            "pyproject.toml version must be the PEP 440 projection of Core SemVer"
        )
    return {"version": standard_version, "python_version": expected_python}


def _reject_constant(value: str) -> None:
    raise ValidationFailure(f"non-finite JSON number rejected: {value}")


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    normalized: set[str] = set()
    for key, value in pairs:
        norm = unicodedata.normalize("NFC", key)
        folded = norm.casefold()
        if key in result:
            raise ValidationFailure(f"duplicate JSON key: {key}")
        if folded in normalized:
            raise ValidationFailure(f"normalized JSON key collision: {key}")
        normalized.add(folded)
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    try:
        raw = path.read_bytes()
        if raw.startswith((b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf")):
            raise ValidationFailure(f"JSON must be UTF-8 without BOM: {path}")
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationFailure(f"invalid JSON at {path}: {exc}") from exc


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _module_origin_digest(module_name: str) -> dict[str, str]:
    spec = importlib.util.find_spec(module_name)
    if spec is None or not isinstance(spec.origin, str):
        raise ValidationFailure(f"implementation module origin is unavailable: {module_name}")
    origin = Path(spec.origin)
    if origin.is_symlink():
        origin = origin.resolve()
    if not origin.is_file():
        raise ValidationFailure(f"implementation module is not a regular file: {module_name}")
    return {"module": module_name, "sha256": sha256_file(origin)}


def implementation_closure(root: Path) -> dict[str, Any]:
    runtime_rows = [
        {"path": f"promin/{rel}", "sha256": sha256_file(path), "size": path.stat().st_size}
        for rel, path in iter_regular_files(
            root / "promin", exclude_root_git_metadata=False
        )
    ]
    if not runtime_rows:
        raise ValidationFailure("promin runtime implementation is empty")
    executable = Path(sys.executable).resolve()
    if not executable.is_file():
        raise ValidationFailure("current Python executable is not a regular file")
    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = metadata.get("project")
    if not isinstance(project, dict):
        raise ValidationFailure("pyproject.toml project metadata is missing")
    declared_dependencies = project.get("dependencies")
    if (
        not isinstance(declared_dependencies, list)
        or not declared_dependencies
        or any(not isinstance(value, str) or not value for value in declared_dependencies)
    ):
        raise ValidationFailure("pyproject.toml runtime dependency set is invalid")
    portable = {
        "promin_runtime": {
            "files": len(runtime_rows),
            "digest": hashlib.sha256(canonical_bytes(runtime_rows)).hexdigest(),
        },
        "python": {"requirement": project.get("requires-python")},
        "runtime_dependencies": {
            "requirements": sorted(declared_dependencies, key=str.casefold),
        },
        "sqlite": {
            "provider": "python-stdlib-sqlite3",
            "observed_binding_required": True,
        },
        "adapter_components": {"binding_scope": "Activation", "observed_binding_required": True},
    }
    observed = {
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "cache_tag": sys.implementation.cache_tag,
            "executable_sha256": sha256_file(executable),
        },
        "runtime_dependencies": {
            name: {
                "version": importlib.metadata.version(name),
                **_module_origin_digest(name),
            }
            for name in ("cryptography", "jsonschema", "pypdf")
        },
        "sqlite": {
            "version": sqlite3.sqlite_version,
            **_module_origin_digest("_sqlite3"),
        },
        "adapter_components": {"binding_scope": "Activation", "package_components": []},
    }
    closure: dict[str, Any] = {
        "record_type": "PackageImplementationClosure",
        "portable": portable,
        "observed_environment": observed,
        "digest": hashlib.sha256(canonical_bytes(portable)).hexdigest(),
        "observed_environment_digest": hashlib.sha256(canonical_bytes(observed)).hexdigest(),
    }
    return closure


def validation_runtime_identity() -> dict[str, Any]:
    try:
        from packaging.tags import sys_tags
    except ImportError:
        from pip._vendor.packaging.tags import sys_tags

    executable = Path(sys.executable).resolve(strict=True)
    system = platform.system().casefold()
    machine = (platform.machine() or "unknown").casefold()
    python_implementation = platform.python_implementation()
    python_version = platform.python_version()
    return {
        "python": python_version,
        "python_implementation": python_implementation,
        "python_executable_sha256": sha256_file(executable),
        "python_abi_tag": sysconfig.get_config_var("SOABI") or "unknown",
        "system": system,
        "machine": machine,
        "release": platform.release(),
        "sys_platform": sys.platform,
        "platform_tags": [str(tag) for tag in list(sys_tags())[:64]],
        "profile_key": "-".join(
            (
                system,
                machine,
                python_implementation.casefold(),
                ".".join(python_version.split(".")[:2]),
            )
        ),
        "jsonschema": importlib.metadata.version("jsonschema"),
        "sqlite": sqlite3.sqlite_version,
    }


def normalized_path_key(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def validate_relative_path(path: str) -> None:
    if "\\" in path or not path or path.startswith("/") or ":" in path or any(ord(char) < 32 for char in path):
        raise ValidationFailure(f"non-canonical relative path: {path!r}")
    if unicodedata.normalize("NFC", path) != path:
        raise ValidationFailure(f"path is not NFC-normalized: {path!r}")
    pure = PurePosixPath(path)
    if any(part in {"", ".", ".."} for part in pure.parts):
        raise ValidationFailure(f"unsafe path segment: {path!r}")
    for part in pure.parts:
        stem = part.rstrip(" .").split(".", 1)[0].casefold()
        if part != part.rstrip(" .") or stem in WINDOWS_RESERVED:
            raise ValidationFailure(f"platform-unsafe path segment: {path!r}")


def _is_transient_directory(name: str) -> bool:
    folded = name.casefold()
    return folded in IGNORED_TRANSIENTS or folded.endswith(".egg-info")


def _is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
    return bool(attributes & reparse_flag)


def iter_regular_files(
    root: Path,
    *,
    include_generated: bool = True,
    exclude_root_git_metadata: bool = True,
) -> list[tuple[str, Path]]:
    """Return candidate files while classifying only root worktree metadata out-of-band.

    A linked Git worktree owns a root-level regular ``.git`` file outside the
    package payload.  A nested ``.git`` path remains ordinary candidate content
    and is therefore subject to the usual inventory/path policy.  Callers that
    scan a package subtree must opt out, so e.g. ``promin/.git`` is never
    mistaken for root worktree metadata.
    """

    if _is_link_or_reparse(root) or not root.is_dir():
        raise ValidationFailure(f"standard root must be a real directory: {root}")
    found: list[tuple[str, Path]] = []
    seen: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(dirpath)
        for name in list(dirnames):
            child = current / name
            rel = child.relative_to(root).as_posix()
            # Repository metadata is outside the candidate tree.  It is not a
            # packaged artifact and must never be scanned as one merely
            # because validation is invoked from a checkout.
            if exclude_root_git_metadata and rel == ".git":
                dirnames.remove(name)
                continue
            if rel == ".superpowers" or rel.startswith(".superpowers/") or rel == "docs/superpowers":
                # SDD scratch is local control material, never canonical package payload.
                dirnames.remove(name)
                continue
            if _is_transient_directory(name):
                raise ValidationFailure(f"transient directory is forbidden: {rel}")
            if _is_link_or_reparse(child):
                raise ValidationFailure(f"symlink or reparse directory rejected: {rel}")
            mode = child.stat(follow_symlinks=False).st_mode
            if not stat.S_ISDIR(mode):
                raise ValidationFailure(f"special directory entry rejected: {rel}")
        for name in filenames:
            path = current / name
            rel = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            if exclude_root_git_metadata and rel == ".git":
                if not stat.S_ISREG(mode) or _is_link_or_reparse(path):
                    raise ValidationFailure("root Git metadata file must be a real regular file")
                continue
            validate_relative_path(rel)
            key = normalized_path_key(rel)
            if key in seen:
                raise ValidationFailure(f"normalized path collision: {seen[key]} vs {rel}")
            seen[key] = rel
            if not stat.S_ISREG(mode) or _is_link_or_reparse(path):
                raise ValidationFailure(f"non-regular file rejected: {rel}")
            if include_generated or rel not in GENERATED_SURFACES:
                found.append((rel, path))
    found.sort(key=lambda item: item[0].encode("utf-8"))
    return found


def _validate_canonical_package_definition() -> None:
    if len(CANONICAL_PACKAGE_FILES) != CANONICAL_PACKAGE_FILE_COUNT:
        raise ValidationFailure(
            "canonical package definition must contain exactly "
            f"{CANONICAL_PACKAGE_FILE_COUNT} files"
        )
    if len(CANONICAL_PACKAGE_DIRECTORIES) != CANONICAL_PACKAGE_DIRECTORY_COUNT:
        raise ValidationFailure(
            "canonical package definition must contain exactly "
            f"{CANONICAL_PACKAGE_DIRECTORY_COUNT} directories"
        )
    if not GENERATED_SURFACES < CANONICAL_PACKAGE_FILES:
        raise ValidationFailure("generated surfaces must be canonical package files")

    declared_directories: set[str] = set()
    seen: dict[str, str] = {}
    for rel in CANONICAL_PACKAGE_FILES:
        validate_relative_path(rel)
        key = normalized_path_key(rel)
        if key in seen:
            raise ValidationFailure(
                f"canonical package definition path collision: {seen[key]} vs {rel}"
            )
        seen[key] = rel
        parts = PurePosixPath(rel).parts
        for length in range(1, len(parts)):
            declared_directories.add("/".join(parts[:length]))
    if declared_directories != CANONICAL_PACKAGE_DIRECTORIES:
        raise ValidationFailure(
            "canonical package directory definition differs from file parents: "
            f"declared={sorted(CANONICAL_PACKAGE_DIRECTORIES)} "
            f"derived={sorted(declared_directories)}"
        )


def verify_package_inventory(
    root: Path,
    *,
    require_generated: bool = True,
) -> dict[str, Any]:
    _validate_canonical_package_definition()
    # A linked Git worktree represents its administrative directory with a
    # root-level .git file.  It is host metadata, not package payload.
    actual_files = {rel for rel, _ in iter_regular_files(root)}
    required_files = (
        CANONICAL_PACKAGE_FILES if require_generated else CANONICAL_PAYLOAD_FILES
    )
    missing_files = sorted(required_files - actual_files, key=lambda value: value.encode("utf-8"))
    unexpected_files = sorted(
        actual_files - CANONICAL_PACKAGE_FILES,
        key=lambda value: value.encode("utf-8"),
    )
    if missing_files or unexpected_files:
        raise ValidationFailure(
            "canonical package file inventory mismatch: "
            f"missing={missing_files} unexpected={unexpected_files}"
        )

    actual_directories: set[str] = set()
    for dirpath, dirnames, _ in os.walk(root, topdown=True, followlinks=False):
        current = Path(dirpath)
        for name in list(dirnames):
            rel = (current / name).relative_to(root).as_posix()
            if rel == ".git":
                dirnames.remove(name)
                continue
            if rel == ".superpowers" or rel.startswith(".superpowers/") or rel == "docs/superpowers":
                dirnames.remove(name)
                continue
            validate_relative_path(rel)
            actual_directories.add(rel)
    missing_directories = sorted(
        CANONICAL_PACKAGE_DIRECTORIES - actual_directories,
        key=lambda value: value.encode("utf-8"),
    )
    unexpected_directories = sorted(
        actual_directories - CANONICAL_PACKAGE_DIRECTORIES,
        key=lambda value: value.encode("utf-8"),
    )
    if missing_directories or unexpected_directories:
        raise ValidationFailure(
            "canonical package directory inventory mismatch: "
            f"missing={missing_directories} unexpected={unexpected_directories}"
        )
    return {
        "files": len(actual_files),
        "directories": len(actual_directories),
        "generated_surfaces_required": require_generated,
        "exact": True,
    }



EXPECTED_EXPERIENCE_PROFILES = frozenset({
    "general-development",
    "c-family-development",
    "web-application",
    "android-application",
    "mobile-application",
    "windows-development",
    "vibe-recovery",
    "ask",
    "standing-reversible",
    "uk",
    "en",
})

def verify_experience_profiles(root: Path) -> dict[str, Any]:
    directory = root / "profiles"
    paths = sorted(directory.glob("*.json"), key=lambda value: value.name.encode("utf-8"))
    values: dict[str, dict[str, Any]] = {}
    for path in paths:
        value = load_json(path)
        required = {
            "record_type", "schema_version", "license", "trusted_by_default",
            "authority_effect", "dynamic_composition", "profile_id", "category",
            "purpose", "detect", "defaults",
        }
        optional = {"official_sources"}
        if not isinstance(value, dict) or not required <= set(value) or set(value) - required - optional:
            raise ValidationFailure(f"experience profile has invalid fields: {path.name}")
        profile_id = value.get("profile_id")
        if not isinstance(profile_id, str) or path.name != profile_id + ".json":
            raise ValidationFailure(f"experience profile identity/path mismatch: {path.name}")
        if value.get("record_type") != "ExperienceProfile" or value.get("schema_version") != 1:
            raise ValidationFailure(f"experience profile identity is invalid: {profile_id}")
        if value.get("license") != "Apache-2.0" or value.get("authority_effect") != "none":
            raise ValidationFailure(f"experience profile license/authority boundary is invalid: {profile_id}")
        if value.get("dynamic_composition") is not True or value.get("trusted_by_default") is not True:
            raise ValidationFailure(f"experience profile trust/composition boundary is invalid: {profile_id}")
        if not isinstance(value.get("detect"), list) or not isinstance(value.get("defaults"), dict):
            raise ValidationFailure(f"experience profile rules are invalid: {profile_id}")
        sources = value.get("official_sources", [])
        if not isinstance(sources, list) or any(not isinstance(uri, str) or not uri.startswith("https://") for uri in sources):
            raise ValidationFailure(f"experience profile source policy is invalid: {profile_id}")
        values[profile_id] = value
    if set(values) != EXPECTED_EXPERIENCE_PROFILES:
        raise ValidationFailure(
            "experience profile inventory mismatch: "
            f"missing={sorted(EXPECTED_EXPERIENCE_PROFILES - set(values))} "
            f"extra={sorted(set(values) - EXPECTED_EXPERIENCE_PROFILES)}"
        )
    return {
        "profile_count": len(values),
        "profile_ids": sorted(values),
        "authority_effect": "none",
        "dynamic_composition": True,
    }


def verify_skill_catalog(root: Path) -> dict[str, Any]:
    directory = root / "skills"
    schema_path = directory / "skill.schema.json"
    package_root = directory / "example"
    manifest_path = package_root / "promin.skill.json"
    skill_path = package_root / "SKILL.md"
    schema = load_json(schema_path)
    value = load_json(manifest_path)
    if Draft202012Validator is None:
        raise ValidationFailure("jsonschema dependency is unavailable")
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(value),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    )
    if errors:
        detail = "; ".join(
            f"/{'/'.join(map(str, error.absolute_path))}: {error.message}"
            for error in errors[:8]
        )
        raise ValidationFailure(f"example skill binding schema validation failed: {detail}")
    if value.get("record_type") != "ProminSkillBinding" or value.get("skill_id") != "example":
        raise ValidationFailure("example skill identity is invalid")
    if value.get("enabled") is not False:
        raise ValidationFailure("example skill must remain disabled until explicitly selected")
    if value.get("license") != "Apache-2.0" or value.get("security_scope") != "read-only":
        raise ValidationFailure("example skill license/security boundary is invalid")
    if skill_path.is_symlink() or not skill_path.is_file():
        raise ValidationFailure("example skill lacks a regular SKILL.md")
    content_files = []
    for path in sorted(package_root.rglob("*"), key=lambda item: item.relative_to(package_root).as_posix().encode("utf-8")):
        if path.is_symlink():
            raise ValidationFailure(f"example skill contains a symbolic link: {path}")
        if not path.is_file() or path.name == "promin.skill.json":
            continue
        relative = path.relative_to(package_root).as_posix()
        payload = path.read_bytes()
        content_files.append({
            "path": relative,
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
    content_digest = hashlib.sha256(
        canonical_bytes({"record_type": "AgentSkillContent", "files": content_files})
    ).hexdigest()
    if value.get("content_digest") != content_digest:
        raise ValidationFailure("example skill content digest is stale")
    return {
        "bundled_active_skills": 0,
        "example_manifest": "skills/example/promin.skill.json",
        "example_content_digest": content_digest,
        "remote_fetch_default": "disabled",
        "authority_effect": "none",
    }

def _require_unique(values: Iterable[str], label: str) -> None:
    items = list(values)
    keys = [normalized_path_key(item) for item in items]
    if len(keys) != len(set(keys)):
        raise ValidationFailure(f"duplicate or normalized collision in {label}")


def _validate_schema_instance(schema: dict[str, Any], definition: str, instance: Any) -> None:
    if Draft202012Validator is None:
        raise ValidationFailure("jsonschema dependency is unavailable")
    validator = Draft202012Validator(
        {"$ref": f"#/$defs/{definition}", "$defs": schema["$defs"]},
        format_checker=FormatChecker(),
    )
    errors = sorted(validator.iter_errors(instance), key=lambda item: tuple(str(x) for x in item.absolute_path))
    if errors:
        detail = "; ".join(f"/{'/'.join(map(str, err.absolute_path))}: {err.message}" for err in errors[:8])
        raise ValidationFailure(f"{definition} schema validation failed: {detail}")


def verify_core(root: Path) -> dict[str, Any]:
    standard_version = distribution_identity(root)["version"]
    core = root / "core"
    if core.is_symlink() or not core.is_dir():
        raise ValidationFailure("missing real core directory")
    actual = {path.name for path in core.iterdir() if path.is_file() and not path.is_symlink()}
    extra_entries = [path.name for path in core.iterdir() if not path.is_file() or path.is_symlink()]
    if actual != CORE_FILES or extra_entries:
        raise ValidationFailure(f"Core must contain exactly six regular artifacts: files={sorted(actual)} extra={extra_entries}")
    owners = {name: load_json(core / name) for name in CORE_FILES}
    schema = owners["contracts.schema.json"]
    if Draft202012Validator is None:
        raise ValidationFailure("jsonschema dependency is unavailable")
    Draft202012Validator.check_schema(schema)
    definitions = schema.get("$defs")
    if schema.get("version") != standard_version or not isinstance(definitions, dict) or not definitions:
        raise ValidationFailure("compiled schema must be a non-empty projection of Core SemVer")
    for definition in INIT_DEFINITIONS:
        projected = schema["$defs"].get(definition)
        if not isinstance(projected, dict) or projected.get("type") != "object" or projected.get("additionalProperties") is not False:
            raise ValidationFailure(f"init schema projection must be a strict object: {definition}")
    top_level_refs = {
        item.get("$ref") for item in schema.get("oneOf", []) if isinstance(item, dict)
    }
    expected_init_refs = {f"#/$defs/{name}" for name in INIT_DEFINITIONS}
    if not expected_init_refs <= top_level_refs:
        raise ValidationFailure("all five init records must be reachable through the compiled schema ingress")
    for filename, definition in OWNER_DEFINITIONS.items():
        owner = owners[filename]
        if owner.get("version") != standard_version:
            raise ValidationFailure(f"Core version mismatch: {filename}")
        _validate_schema_instance(schema, definition, owner)
    manifest = owners["promin.manifest.json"]
    if manifest.get("canonical_name") != "promin" or manifest.get("canonical_name_only") is not True:
        raise ValidationFailure("Core canonical identity must be lowercase promin only")
    if manifest.get("aliases") != []:
        raise ValidationFailure("Core aliases must be empty")
    expected_components = CORE_FILES - {"promin.manifest.json"}
    components = manifest.get("core_components", [])
    paths = [item.get("path") for item in components if isinstance(item, dict)]
    if len(paths) != 5 or set(paths) != expected_components:
        raise ValidationFailure("Core manifest must bind exactly the five non-manifest artifacts")
    _require_unique(paths, "Core component paths")
    for component in components:
        claimed = component.get("sha256")
        if not isinstance(claimed, str) or not HEX64.fullmatch(claimed):
            raise ValidationFailure(f"invalid Core digest claim: {component.get('path')}")
        actual_digest = sha256_file(core / component["path"])
        if claimed != actual_digest:
            raise ValidationFailure(f"Core digest mismatch: {component['path']}")
    identity = dict(manifest)
    claimed_bundle = identity.pop("bundle_digest", None)
    actual_bundle = hashlib.sha256(canonical_bytes(identity)).hexdigest()
    if claimed_bundle != actual_bundle:
        raise ValidationFailure("Core bundle digest does not bind the complete manifest identity")
    policies = owners["policy-set.json"].get("policies", [])
    if not isinstance(policies, list) or not policies:
        raise ValidationFailure("policy owner must contain a non-empty policy catalogue")
    _require_unique((item["id"] for item in policies), "policy ids")
    _require_unique((item["validator_id"] for item in policies), "policy validator ids")
    conformance = owners["conformance.json"]
    acceptance = conformance.get("required_acceptance", [])
    mutations = conformance.get("mutation_families", [])
    if not isinstance(acceptance, list) or not acceptance:
        raise ValidationFailure("conformance owner must contain a non-empty acceptance catalogue")
    if not isinstance(mutations, list) or not mutations:
        raise ValidationFailure("conformance owner must contain a non-empty mutation catalogue")
    _require_unique(acceptance, "acceptance predicates")
    _require_unique(mutations, "mutation families")
    semantic = owners["semantic-model.json"]
    authority = owners["authority-model.json"]
    structural_counts = {
        "core_artifact_count": len(CORE_FILES),
        "schema_definition_count": len(definitions),
        "selected_preset_count": 1,
        "persistent_entity_kind_count": len(semantic.get("persistent_entities", [])),
        "relation_kind_count": len(semantic.get("relations", [])),
        "technology_capability_count": len(semantic.get("technology_capabilities", [])),
        "action_capability_count": len(authority.get("capabilities", [])),
        "policy_count": len(policies),
        "acceptance_predicate_count": len(acceptance),
        "mutation_family_count": len(mutations),
    }
    for field, actual_count in structural_counts.items():
        claimed_count = manifest.get(field)
        if not isinstance(claimed_count, int) or isinstance(claimed_count, bool):
            raise ValidationFailure(f"Core manifest structural count is missing or invalid: {field}")
        if claimed_count != actual_count:
            raise ValidationFailure(
                f"Core manifest structural count mismatch: {field} claimed={claimed_count} actual={actual_count}"
            )
    return {
        "bundle_digest": actual_bundle,
        "structural_counts": structural_counts,
        "schema_definitions": structural_counts["schema_definition_count"],
        "policies": structural_counts["policy_count"],
        "acceptance_predicates": structural_counts["acceptance_predicate_count"],
        "mutation_families": structural_counts["mutation_family_count"],
    }


def verify_preset(root: Path, schema: dict[str, Any]) -> dict[str, Any]:
    standard_version = distribution_identity(root)["version"]
    presets = root / "presets"
    if presets.is_symlink() or not presets.is_dir():
        raise ValidationFailure("missing real presets directory")
    entries = list(presets.iterdir())
    if len(entries) != 1 or entries[0].name != "semantic-standard.json" or not entries[0].is_file() or entries[0].is_symlink():
        raise ValidationFailure("exactly one selected preset is required outside Core")
    preset = load_json(entries[0])
    if preset.get("version") != standard_version or preset.get("preset_id") != "semantic-standard":
        raise ValidationFailure("selected preset identity/version mismatch")
    _validate_schema_instance(schema, "Preset", preset)
    if preset.get("base_user_commands") != ["init", "doctor", "status", "next", "validate", "static-admission", "continue", "audit", "refresh", "context", "skills"]:
        raise ValidationFailure("selected preset must expose the exact alpha user workflows in canonical order")
    return {"path": "presets/semantic-standard.json", "sha256": sha256_file(entries[0])}


def verify_version(root: Path, core_result: dict[str, Any], preset_result: dict[str, Any]) -> dict[str, Any]:
    version = load_json(root / "VERSION.json")
    distribution = distribution_identity(root)
    if set(version) != {
        "record_type",
        "canonical_name",
        "version",
        "core_bundle_digest",
        "selected_preset",
        "integrity",
    }:
        raise ValidationFailure("VERSION.json key set is not exact")
    if version.get("record_type") != "StandardVersion" or version.get("canonical_name") != "promin":
        raise ValidationFailure("VERSION.json canonical identity mismatch")
    if version.get("version") != distribution["version"]:
        raise ValidationFailure(f"VERSION.json must describe distribution version {distribution['version']}")
    if not isinstance(version.get("core_bundle_digest"), str) or not HEX64.fullmatch(version["core_bundle_digest"]):
        raise ValidationFailure("VERSION.json Core digest is malformed")
    if version.get("core_bundle_digest") != core_result["bundle_digest"]:
        raise ValidationFailure("VERSION.json Core digest is stale")
    preset = version.get("selected_preset", {})
    if set(preset) != {"path", "sha256"}:
        raise ValidationFailure("VERSION.json selected_preset key set is not exact")
    if preset.get("path") != preset_result["path"] or preset.get("sha256") != preset_result["sha256"]:
        raise ValidationFailure("VERSION.json preset digest is stale")
    integrity = version.get("integrity", {})
    if integrity != {"archive_sha256": "external", "checksums": "SHA256SUMS.txt", "manifest": "MANIFEST.json"}:
        raise ValidationFailure("VERSION.json integrity surfaces are not exact")
    return version


def _font_generator_arguments(font_bindings: dict[str, tuple[Path, str]] | None) -> list[str]:
    if font_bindings is None or set(font_bindings) != set(FONT_ROLES):
        raise ValidationFailure("document rebuild requires explicit path and SHA-256 for regular, bold, italic, and mono fonts")
    arguments: list[str] = []
    for role in FONT_ROLES:
        path, claimed_digest = font_bindings[role]
        if path.is_symlink() or not path.is_file():
            raise ValidationFailure(f"document font must be a real file: {role}")
        if not HEX64.fullmatch(claimed_digest) or sha256_file(path) != claimed_digest:
            raise ValidationFailure(f"document font digest mismatch: {role}")
        arguments.extend([f"--font-{role}", str(path.resolve()), f"--font-{role}-sha256", claimed_digest])
    return arguments


def verify_human_documents(
    root: Path,
    *,
    rebuild: bool = False,
    font_bindings: dict[str, tuple[Path, str]] | None = None,
) -> dict[str, Any]:
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ValidationFailure("pypdf dependency is required for typed human document verification") from exc
    actual = {
        f"human/{rel}"
        for rel, _ in iter_regular_files(
            root / "human", exclude_root_git_metadata=False
        )
    }
    if actual != HUMAN_PDFS:
        raise ValidationFailure(f"human PDF set mismatch: expected={sorted(HUMAN_PDFS)} actual={sorted(actual)}")
    details: list[dict[str, Any]] = []
    for rel in sorted(HUMAN_PDFS):
        if rel != rel.lower():
            raise ValidationFailure(f"human document filename must be lowercase: {rel}")
        path = root / rel
        data = path.read_bytes()
        if len(data) < 1024 or not data.startswith(b"%PDF-") or b"%%EOF" not in data[-2048:]:
            raise ValidationFailure(f"malformed or implausibly small PDF: {rel}")
        digest = hashlib.sha256(data).hexdigest()
        summary = _HUMAN_DOCUMENT_SUMMARIES.get(digest)
        if summary is None:
            try:
                reader = PdfReader(path, strict=True)
                if reader.is_encrypted:
                    raise ValidationFailure(f"encrypted human document rejected: {rel}")
                page_text_characters: list[int] = []
                extraction_errors: list[dict[str, Any]] = []
                for page_index, page in enumerate(reader.pages):
                    try:
                        extracted = page.extract_text() or ""
                    except Exception as exc:
                        extraction_errors.append(
                            {"page": page_index + 1, "error_type": type(exc).__name__}
                        )
                        extracted = ""
                    page_text_characters.append(len(extracted.strip()))
            except ValidationFailure:
                raise
            except Exception as exc:
                raise ValidationFailure(f"human PDF parser rejected {rel}: {type(exc).__name__}") from exc
            if not page_text_characters or extraction_errors or sum(page_text_characters) == 0:
                raise ValidationFailure(f"human PDF text extraction is incomplete: {rel}")
            if len(_HUMAN_DOCUMENT_SUMMARIES) >= _MAX_HUMAN_DOCUMENT_SUMMARIES:
                _HUMAN_DOCUMENT_SUMMARIES.popitem(last=False)
            summary = (
                len(page_text_characters),
                sum(page_text_characters),
                tuple(index + 1 for index, characters in enumerate(page_text_characters) if characters == 0),
            )
            _HUMAN_DOCUMENT_SUMMARIES[digest] = summary
        else:
            _HUMAN_DOCUMENT_SUMMARIES.move_to_end(digest)
        page_count, extracted_characters, blank_text_pages = summary
        details.append(
            {
                "path": rel,
                "bytes": len(data),
                "sha256": digest,
                "page_count": page_count,
                "extracted_characters": extracted_characters,
                "blank_text_pages": list(blank_text_pages),
                "extraction_errors": [],
            }
        )
    result: dict[str, Any] = {
        "record_type": "HumanDocumentVerification",
        "status": "pass",
        "documents": details,
        "document_count": len(details),
        "page_count": sum(item["page_count"] for item in details),
        "extraction_errors": 0,
        "existing_pdf_verification": True,
        "rebuild_performed": False,
        "deterministic_rebuild": False,
        "visual_review_scope": {
            "mode": "external-render-review-required",
            "pages_reviewed": 0,
            "claim": "structural-and-text-extraction-only",
        },
        "product_acceptance_pass": False,
    }
    if not rebuild:
        if font_bindings is not None:
            raise ValidationFailure("font bindings are only valid with document rebuild enabled")
        return result

    generator = root / "tools" / "generate_human.py"
    if generator.is_symlink() or not generator.is_file():
        raise ValidationFailure("missing deterministic human document generator")
    font_arguments = _font_generator_arguments(font_bindings)
    protected = [root / "core" / name for name in sorted(CORE_FILES)] + [root / "presets" / "semantic-standard.json"]
    before = {str(path.relative_to(root)): sha256_file(path) for path in protected}
    with tempfile.TemporaryDirectory(prefix="promin-human-verify-") as temporary_name:
        regenerated = Path(temporary_name) / "human"
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        completed = subprocess.run(
            [sys.executable, "-B", str(generator), "--output", str(regenerated), *font_arguments],
            cwd=root,
            env=environment,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise ValidationFailure("human document regeneration failed: " + completed.stderr.strip())
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        try:
            generator_result = json.loads(lines[-1])
        except (IndexError, json.JSONDecodeError) as exc:
            raise ValidationFailure("human document generator returned no valid JSON result") from exc
        if (
            generator_result.get("record_type") != "ProminHumanProjectionBuildEvidence"
            or generator_result.get("status") != "pass"
            or generator_result.get("version") != 1
            or generator_result.get("mode") != "build"
            or generator_result.get("pass_credit") is not False
            or generator_result.get("product_acceptance_pass") is not False
        ):
            raise ValidationFailure("human document generator did not report a valid build evidence record")
        if generator_result.get("generator_sha256") != sha256_file(generator):
            raise ValidationFailure("human document build evidence generator digest mismatch")
        if generator_result.get("core_bundle_digest") != load_json(root / "core" / "promin.manifest.json").get("bundle_digest"):
            raise ValidationFailure("human document build evidence Core digest mismatch")
        if generator_result.get("selected_preset_sha256") != sha256_file(root / "presets" / "semantic-standard.json"):
            raise ValidationFailure("human document build evidence preset digest mismatch")
        evidence_fonts = generator_result.get("font_bindings")
        if not isinstance(evidence_fonts, dict) or set(evidence_fonts) != set(FONT_ROLES):
            raise ValidationFailure("human document build evidence font bindings are not exact")
        for role in FONT_ROLES:
            if not isinstance(evidence_fonts[role], dict) or evidence_fonts[role].get("sha256") != font_bindings[role][1]:
                raise ValidationFailure(f"human document build evidence font digest mismatch: {role}")
        generated_files = iter_regular_files(
            regenerated, exclude_root_git_metadata=False
        )
        generated_rel = {f"human/{rel}" for rel, _ in generated_files}
        if generated_rel != HUMAN_PDFS:
            raise ValidationFailure("human document generator output set is not exact")
        evidence_outputs = generator_result.get("outputs")
        if not isinstance(evidence_outputs, list):
            raise ValidationFailure("human document build evidence outputs are missing")
        evidence_by_path = {item.get("path"): item for item in evidence_outputs if isinstance(item, dict)}
        if set(evidence_by_path) != {Path(rel).name for rel in HUMAN_PDFS}:
            raise ValidationFailure("human document build evidence output set is not exact")
        for rel in HUMAN_PDFS:
            generated_path = regenerated / Path(rel).name
            evidence = evidence_by_path[generated_path.name]
            if evidence.get("bytes") != generated_path.stat().st_size or evidence.get("sha256") != sha256_file(generated_path):
                raise ValidationFailure(f"human document build evidence mismatch: {rel}")
            if (root / rel).read_bytes() != generated_path.read_bytes():
                raise ValidationFailure(f"human document is stale or nondeterministic: {rel}")
    after = {str(path.relative_to(root)): sha256_file(path) for path in protected}
    if before != after:
        raise ValidationFailure("human document generator mutated canonical sources")
    result["rebuild_performed"] = True
    result["deterministic_rebuild"] = True
    result["build_evidence"] = generator_result
    return result


def build_human_document_verification(
    root: Path,
    *,
    candidate_binding: Mapping[str, Any],
    candidate_document_members: Iterable[Mapping[str, Any]],
    visual_review: Mapping[str, Any],
    render_root: Path,
    evidence_base: Path,
    font_bindings: dict[str, tuple[Path, str]],
) -> dict[str, Any]:
    """Build one candidate-bound PDF verification record after exact regeneration."""

    from promin.evidence import (
        read_external_bytes_stable,
        release_evidence_invocation,
        release_evidence_producer,
        seal_release_evidence,
        validate_human_document_verification,
        validate_standard_release_candidate_binding,
    )

    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
    candidate = validate_standard_release_candidate_binding(candidate_binding)
    structural = verify_human_documents(
        root.resolve(),
        rebuild=True,
        font_bindings=font_bindings,
    )
    expected_review_fields = {
        "record_type",
        "candidate_binding_digest",
        "completed",
        "reviewer_id",
        "reviewed_at",
        "rendered_page_count",
        "pages_reviewed",
        "clipping_detected",
        "unreadable_text_detected",
        "render_manifest",
    }
    if (
        not isinstance(visual_review, Mapping)
        or set(visual_review) != expected_review_fields
        or visual_review.get("record_type") != "HumanDocumentVisualReview"
        or visual_review.get("candidate_binding_digest")
        != candidate["candidate_binding_digest"]
    ):
        raise ValidationFailure("human visual review shape or candidate binding is invalid")
    documents = [
        {
            "path": item["path"],
            "sha256": item["sha256"],
            "size_bytes": item["bytes"],
            "page_count": item["page_count"],
            "extracted_characters": item["extracted_characters"],
            "blank_pages": item["blank_text_pages"],
            "extraction_errors": item["extraction_errors"],
        }
        for item in structural["documents"]
    ]
    rebuild_rows = [
        {
            "path": item["path"],
            "sha256": item["sha256"],
            "size_bytes": item["size_bytes"],
            "page_count": item["page_count"],
        }
        for item in documents
    ]
    total_characters = sum(item["extracted_characters"] for item in documents)
    review_rows = visual_review.get("render_manifest")
    if not isinstance(review_rows, list) or len(review_rows) != structural["page_count"]:
        raise ValidationFailure("human visual review must list every rendered page")
    render_root = render_root.absolute()
    evidence_base = evidence_base.absolute()
    render_manifest: list[dict[str, Any]] = []
    for row in review_rows:
        if not isinstance(row, Mapping) or set(row) != {
            "document_path",
            "page",
            "image_path",
        }:
            raise ValidationFailure("human visual review render row shape is invalid")
        relative = row["image_path"]
        validate_relative_path(relative)
        image = render_root.joinpath(*PurePosixPath(relative).parts)
        stable = read_external_bytes_stable(image, root=render_root, max_bytes=32 * 1024 * 1024)
        try:
            evidence_path = image.absolute().relative_to(evidence_base).as_posix()
        except ValueError as exc:
            raise ValidationFailure("rendered pages must be stored below the evidence output root") from exc
        render_manifest.append(
            {
                "document_path": row["document_path"],
                "page": row["page"],
                "image_path": evidence_path,
                "image_sha256": stable.sha256,
                "image_bytes": stable.size_bytes,
            }
        )
    render_manifest_digest = hashlib.sha256(canonical_bytes(render_manifest)).hexdigest()
    generator_result = structural.get("build_evidence")
    if not isinstance(generator_result, Mapping):
        raise ValidationFailure("deterministic document rebuild omitted generator evidence")
    generator_fonts = generator_result.get("font_bindings")
    if not isinstance(generator_fonts, Mapping):
        raise ValidationFailure("deterministic document rebuild omitted exact font bindings")
    render_environment = {
        "generator_sha256": generator_result.get("generator_sha256"),
        "reportlab_version": generator_result.get("reportlab_version"),
        "python_version": platform.python_version(),
        "platform": platform.system().casefold(),
        "font_binding_digest": hashlib.sha256(canonical_bytes(dict(generator_fonts))).hexdigest(),
    }
    verification = {
        "record_type": "HumanDocumentVerification",
        "status": "pass",
        "candidate_binding_digest": candidate["candidate_binding_digest"],
        "documents": documents,
        "deterministic_rebuild": structural["deterministic_rebuild"],
        "rebuild_digest": hashlib.sha256(
            canonical_bytes(sorted(rebuild_rows, key=lambda row: row["path"].encode("utf-8")))
        ).hexdigest(),
        "page_count": structural["page_count"],
        "extraction_diagnostics": {
            "documents_parsed": len(documents),
            "total_extracted_characters": total_characters,
            "blank_pages": [
                {"path": item["path"], "page": page}
                for item in documents
                for page in item["blank_pages"]
            ],
            "errors": [
                {"path": item["path"], **error}
                for item in documents
                for error in item["extraction_errors"]
            ],
        },
        "visual_review_scope": {
            field: deepcopy(visual_review[field])
            for field in (
                "completed",
                "reviewer_id",
                "reviewed_at",
                "rendered_page_count",
                "pages_reviewed",
                "clipping_detected",
                "unreadable_text_detected",
            )
        }
        | {"render_manifest_digest": render_manifest_digest},
        "font_bindings": deepcopy(dict(generator_fonts)),
        "generator_result_digest": hashlib.sha256(
            canonical_bytes(dict(generator_result))
        ).hexdigest(),
        "render_environment": render_environment,
        "render_manifest": render_manifest,
        "render_manifest_digest": render_manifest_digest,
        "product_acceptance_pass": False,
        "producer": release_evidence_producer(
            root,
            "tools/promin_package.py",
            version=candidate["version"],
        ),
        "invocation": release_evidence_invocation(
            invocation_id=f"build-document-evidence:{uuid.uuid4().hex}",
            operation="build-document-evidence",
            arguments={
                "candidate_binding_digest": candidate["candidate_binding_digest"],
                "font_binding_digest": render_environment["font_binding_digest"],
                "render_manifest_digest": render_manifest_digest,
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            exit_code=0,
            platform_binding=render_environment,
        ),
    }
    verification = seal_release_evidence(verification)
    try:
        return validate_human_document_verification(
            verification,
            candidate_binding=candidate,
            candidate_document_members=candidate_document_members,
            source_path=evidence_base / "human-documents.json",
            evidence_root=evidence_base,
        )
    except ValueError as exc:
        raise ValidationFailure(str(exc)) from exc


def verify_executable_surfaces(
    root: Path,
    policy_validator_ids: set[str],
    acceptance_ids: set[str],
    mutation_ids: set[str],
) -> dict[str, Any]:
    required = {
        "promin/__main__.py",
        "promin/canonical.py",
        "promin/conformance.py",
        "promin/contracts.py",
        "promin/init.py",
        "promin/service.py",
        "promin/mutation_suite.py",
        "tools/compile_schema.py",
        "tools/promin_validate.py",
        "tools/promin_package.py",
        "tools/promin_no_degradation.py",
        "tools/generate_human.py",
    }
    actual = {rel for rel, _ in iter_regular_files(root)}
    missing = sorted(required - actual)
    if missing:
        raise ValidationFailure(f"missing executable validation/runtime surfaces: {missing}")
    tests = sorted(rel for rel in actual if rel.startswith("tests/test_") and rel.endswith(".py"))
    if not tests:
        raise ValidationFailure("no executable conformance tests found")
    compiled = subprocess.run(
        [sys.executable, "-B", str(root / "tools" / "compile_schema.py"), str(root), "--check"],
        cwd=root,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if compiled.returncode != 0:
        raise ValidationFailure(
            "contracts.schema.json is not the deterministic compiled projection: "
            + (compiled.stdout + compiled.stderr)[-4096:]
        )
    contracts_source = (root / "promin" / "contracts.py").read_text(encoding="utf-8")
    required_ingress = {"command", "import", "replay", "rebuild", "export"}
    missing_ingress = sorted(value for value in required_ingress if repr(value) not in contracts_source and f'"{value}"' not in contracts_source)
    if "validate_ingress" not in contracts_source or missing_ingress:
        raise ValidationFailure(f"unified validation ingress is incomplete: {missing_ingress}")
    probe = (
        "import json; from promin.contracts import POLICY_VALIDATORS as p, "
        "ACCEPTANCE_VALIDATORS as a, MUTATION_PROBES as m, INIT_FILES as i, PLAN_FILES as n; "
        "f=lambda x:{'keys':sorted(x),'all_callable':all(callable(v) for v in x.values())}; "
        "print(json.dumps({'policy':f(p),'acceptance':f(a),'mutation':f(m),'init_files':list(i),'plan_files':list(n)},sort_keys=True))"
    )
    completed = subprocess.run(
        [sys.executable, "-B", "-c", probe],
        cwd=root,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ValidationFailure("policy hook registry is not importable: " + completed.stderr.strip())
    try:
        policy_hooks = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValidationFailure("policy hook registry probe returned non-JSON output") from exc
    if set(policy_hooks.get("policy", {}).get("keys", [])) != policy_validator_ids or policy_hooks.get("policy", {}).get("all_callable") is not True:
        raise ValidationFailure(
            f"policy hook registry must map exactly all {len(policy_validator_ids)} canonical validator IDs to callables"
        )
    if set(policy_hooks.get("acceptance", {}).get("keys", [])) != acceptance_ids or policy_hooks.get("acceptance", {}).get("all_callable") is not True:
        raise ValidationFailure(
            f"acceptance hook registry must map exactly all {len(acceptance_ids)} canonical predicates to callables"
        )
    if set(policy_hooks.get("mutation", {}).get("keys", [])) != mutation_ids or policy_hooks.get("mutation", {}).get("all_callable") is not True:
        raise ValidationFailure(
            f"mutation probe registry must map exactly all {len(mutation_ids)} canonical families to callables"
        )
    if policy_hooks.get("plan_files") != ["project.json", "standards.json", "technologies.json", "authority.json"]:
        raise ValidationFailure("runtime init plan set is not exact")
    if policy_hooks.get("init_files") != ["project.json", "standards.json", "technologies.json", "authority.json", "activation.json"]:
        raise ValidationFailure("runtime must produce exactly five init records")
    return {
        "unified_ingress_operations": sorted(required_ingress),
        "policy_hooks": len(policy_validator_ids),
        "acceptance_hooks": len(acceptance_ids),
        "mutation_hooks": len(mutation_ids),
        "conformance_test_files": tests,
        "compiled_projection_check": "pass",
    }


def _declared_requirements(root: Path) -> tuple[list[str], list[str]]:
    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = metadata.get("project")
    build_system = metadata.get("build-system")
    if not isinstance(project, dict) or not isinstance(build_system, dict):
        raise ValidationFailure("pyproject.toml must declare project and build-system tables")
    dependencies = project.get("dependencies", [])
    build_requirements = build_system.get("requires", [])
    if not isinstance(dependencies, list) or not all(isinstance(item, str) and item.strip() for item in dependencies):
        raise ValidationFailure("project dependencies must be an explicit string list")
    if not isinstance(build_requirements, list) or not all(isinstance(item, str) and item.strip() for item in build_requirements):
        raise ValidationFailure("build-system requirements must be an explicit string list")
    return dependencies, build_requirements


def _wheelhouse_binding(wheelhouse: Path) -> dict[str, Any]:
    entries = sorted(wheelhouse.iterdir(), key=lambda path: path.name.encode("utf-8"))
    if not entries:
        raise ValidationFailure("offline wheelhouse is empty")
    names: list[str] = []
    files: list[dict[str, Any]] = []
    for path in entries:
        validate_relative_path(path.name)
        if path.is_symlink() or not path.is_file() or not stat.S_ISREG(path.stat(follow_symlinks=False).st_mode):
            raise ValidationFailure(f"offline wheelhouse entry must be a regular file: {path.name}")
        if path.suffix.casefold() != ".whl":
            raise ValidationFailure(f"offline wheelhouse may contain only wheel files: {path.name}")
        names.append(path.name)
        files.append({"path": path.name, "bytes": path.stat().st_size, "sha256": sha256_file(path)})
    _require_unique(names, "offline wheelhouse paths")
    return {
        "files": files,
        "file_count": len(files),
        "manifest_sha256": hashlib.sha256(canonical_bytes(files)).hexdigest(),
    }


def _pip_install_arguments(
    source: Path,
    mode: str,
    wheelhouse: Path | None,
    report_path: Path | None = None,
    *,
    extras: tuple[str, ...] = (),
) -> tuple[list[str], dict[str, Any]]:
    if mode not in INSTALL_MODES:
        raise ValidationFailure(f"unknown install verification mode: {mode}")
    if mode == "current-environment":
        if wheelhouse is not None:
            raise ValidationFailure("wheelhouse is only valid with offline-wheelhouse mode")
        return [], {
            "environment": "current-interpreter",
            "runtime_dependency_source": "current-environment",
            "build_dependency_source": "not-used",
            "network_access": "not-used",
            "installation_performed": False,
            "nested_venv_created": False,
        }
    if any(not isinstance(extra, str) or not extra or not re.fullmatch(r"[A-Za-z0-9._-]+", extra) for extra in extras):
        raise ValidationFailure("install extras must be canonical distribution extra names")
    source_requirement = str(source) + ("[" + ",".join(extras) + "]" if extras else "")
    if mode == "offline-wheelhouse":
        if wheelhouse is None:
            raise ValidationFailure("offline-wheelhouse mode requires --wheelhouse")
        if wheelhouse.is_symlink() or not wheelhouse.is_dir():
            raise ValidationFailure("offline wheelhouse must be a real directory")
        wheelhouse_binding = _wheelhouse_binding(wheelhouse)
        return [
            "-m",
            "pip",
            "--isolated",
            "install",
            "--disable-pip-version-check",
            "--no-index",
            "--find-links",
            str(wheelhouse.resolve()),
            "--no-build-isolation",
            "--report",
            str(report_path) if report_path is not None else os.devnull,
            source_requirement,
        ], {
            "environment": "clean-venv",
            "runtime_dependency_source": "offline-wheelhouse",
            "build_dependency_source": "offline-wheelhouse",
            "network_disabled": True,
            "installation_performed": True,
            "nested_venv_created": True,
            "wheelhouse_binding": wheelhouse_binding,
        }
    if wheelhouse is not None:
        raise ValidationFailure("wheelhouse is only valid with offline-wheelhouse mode")
    return [
        "-m",
        "pip",
        "--isolated",
        "install",
        "--disable-pip-version-check",
        "--no-build-isolation",
        "--report",
        str(report_path) if report_path is not None else os.devnull,
        source_requirement,
    ], {
        "environment": "clean-venv",
        "runtime_dependency_source": "online-index",
        "build_dependency_source": "online-index-explicit",
        "network_disabled": False,
        "installation_performed": True,
        "nested_venv_created": True,
    }


def _requirement_type() -> Any:
    try:
        from packaging.requirements import Requirement
    except ImportError:
        try:
            from pip._vendor.packaging.requirements import Requirement
        except ImportError as exc:  # pragma: no cover - uncommon stripped interpreter
            raise ValidationFailure(
                "current interpreter cannot parse declared requirements; packaging or pip is required"
            ) from exc
    return Requirement


def _resolve_current_dependencies(dependencies: list[str]) -> dict[str, dict[str, str]]:
    Requirement = _requirement_type()
    resolved: dict[str, dict[str, str]] = {}
    for declaration in dependencies:
        try:
            requirement = Requirement(declaration)
        except Exception as exc:
            raise ValidationFailure(f"invalid runtime dependency declaration: {declaration}") from exc
        if requirement.url is not None:
            raise ValidationFailure("direct-reference runtime dependencies are not allowed")
        if requirement.marker is not None and not requirement.marker.evaluate():
            continue
        try:
            installed_version = importlib.metadata.version(requirement.name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise ValidationFailure(f"current interpreter dependency is missing: {requirement.name}") from exc
        if installed_version not in requirement.specifier:
            raise ValidationFailure(
                f"current interpreter dependency is outside its declared constraint: "
                f"{requirement.name} {installed_version} not in {requirement.specifier}"
            )
        resolved[requirement.name] = {
            "requirement": str(requirement),
            "version": installed_version,
        }
    return dict(sorted(resolved.items(), key=lambda item: item[0].casefold()))


def _verify_current_python_requirement(root: Path) -> str:
    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = metadata.get("project")
    declared = project.get("requires-python") if isinstance(project, dict) else None
    if not isinstance(declared, str) or not declared:
        raise ValidationFailure("pyproject.toml requires-python is missing")
    Requirement = _requirement_type()
    try:
        requirement = Requirement("promin" + declared)
    except Exception as exc:
        raise ValidationFailure("pyproject.toml requires-python is invalid") from exc
    if platform.python_version() not in requirement.specifier:
        raise ValidationFailure(
            f"current interpreter {platform.python_version()} is outside requires-python {declared}"
        )
    return declared


def _declared_console_script(root: Path) -> None:
    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = metadata.get("project")
    scripts = project.get("scripts") if isinstance(project, dict) else None
    if scripts != {"promin": "promin.__main__:main"}:
        raise ValidationFailure("pyproject.toml must declare exactly the canonical promin console script")


def _invoke_workflow_help(
    *,
    root: Path,
    python: Path,
    environment: dict[str, str],
    executable: Path | None,
    deadline_monotonic: float | None = None,
) -> list[dict[str, Any]]:
    workflows = ["init", "doctor", "status", "next", "validate", "continue", "audit", "refresh", "context", "skills"]
    base = [str(executable)] if executable is not None else [str(python), "-B", "-m", "promin"]
    invoked: list[dict[str, Any]] = []
    for command in [None, *workflows]:
        arguments = base + ([] if command is None else [command]) + ["--help"]
        completed = _run_capture_with_deadline(
            arguments,
            cwd=root,
            environment=environment,
            deadline_monotonic=deadline_monotonic,
            phase="installed command probe",
        )
        if completed.returncode != 0:
            label = "root" if command is None else command
            raise ValidationFailure(f"promin {label} help failed: " + completed.stderr[-4096:])
        if command is None and not all(name in completed.stdout for name in workflows):
            raise ValidationFailure("promin help omits a stable workflow")
        stdout = completed.stdout.encode("utf-8")
        stderr = completed.stderr.encode("utf-8")
        if len(stdout) > 1024 * 1024 or len(stderr) > 1024 * 1024:
            raise ValidationFailure("promin help output exceeds its evidence bound")
        invoked.append(
            {
                "command": "--help" if command is None else f"{command} --help",
                "argv_digest": hashlib.sha256(canonical_bytes(arguments)).hexdigest(),
                "returncode": completed.returncode,
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
                "stdout_bytes": len(stdout),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
                "stderr_bytes": len(stderr),
            }
        )
    return invoked


def _create_clean_venv(
    destination: Path,
    environment: dict[str, str],
    *,
    deadline_monotonic: float | None = None,
) -> None:
    created = _run_capture_with_deadline(
        [sys.executable, "-B", "-m", "venv", str(destination)],
        cwd=None,
        environment=environment,
        deadline_monotonic=deadline_monotonic,
        phase="clean environment creation",
    )
    if created.returncode != 0:
        raise ValidationFailure("install verification environment creation failed: " + created.stderr[-4096:])


_INSTALLED_ENVIRONMENT_PROBE = r'''
import hashlib
import importlib.metadata as metadata
import json
import os
import pathlib
import platform
import sqlite3
import sys
import sysconfig

try:
    from packaging.tags import sys_tags
except ImportError:
    from pip._vendor.packaging.tags import sys_tags

def digest_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def canonical_digest(value):
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def record_binding(distribution):
    files = list(distribution.files or ())
    record_file = next((item for item in files if str(item).replace("\\", "/").endswith(".dist-info/RECORD")), None)
    if record_file is None:
        return {"path": None, "sha256": None, "bytes": 0}
    path = pathlib.Path(distribution.locate_file(record_file)).resolve()
    return {"path": str(record_file).replace("\\", "/"), "sha256": digest_file(path), "bytes": path.stat().st_size}

distributions = []
for distribution in metadata.distributions():
    name = distribution.metadata.get("Name")
    if not name:
        continue
    license_value = distribution.metadata.get("License-Expression") or distribution.metadata.get("License")
    if not license_value:
        license_files = sorted(distribution.metadata.get_all("License-File") or ())
        license_value = "License-File:" + ",".join(license_files) if license_files else "UNKNOWN"
    if len(license_value) > 2048:
        license_value = license_value[:2048]
    distributions.append({
        "name": name.casefold(),
        "version": distribution.version,
        "record": record_binding(distribution),
        "requires": sorted(distribution.requires or ()),
        "license": license_value,
    })
distributions.sort(key=lambda row: row["name"])

promin_distribution = metadata.distribution("promin")
promin_files = []
for item in sorted(promin_distribution.files or (), key=lambda value: str(value).encode("utf-8")):
    path = pathlib.Path(promin_distribution.locate_file(item)).resolve()
    if path.is_file():
        promin_files.append({"path": str(item).replace("\\", "/"), "sha256": digest_file(path), "bytes": path.stat().st_size})

import promin
executable = pathlib.Path(sys.executable).absolute()
base_executable = pathlib.Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
wrapper = pathlib.Path(sys.argv[1]).resolve()
purelib = pathlib.Path(sysconfig.get_paths()["purelib"]).resolve()
module_file = pathlib.Path(promin.__file__).resolve()
if purelib not in module_file.parents:
    raise RuntimeError("promin import did not resolve from installed site-packages")

build_distribution = next((row for row in distributions if row["name"] == "setuptools"), None)
if build_distribution is None:
    raise RuntimeError("setuptools build backend is absent from the clean environment")
license_rows = [{"name": row["name"], "version": row["version"], "license": row["license"]} for row in distributions]
result = {
    "python": {
        "executable": str(executable),
        "executable_sha256": digest_file(executable),
        "base_executable": str(base_executable),
        "base_executable_sha256": digest_file(base_executable),
        "implementation": platform.python_implementation().casefold(),
        "version": platform.python_version(),
        "abi_tag": sysconfig.get_config_var("SOABI") or "unknown",
        "prefix": str(pathlib.Path(sys.prefix).resolve()),
        "base_prefix": str(pathlib.Path(sys.base_prefix).resolve()),
    },
    "platform": {
        "system": platform.system().casefold(),
        "machine": (platform.machine() or "unknown").casefold(),
        "release": platform.release(),
        "sys_platform": sys.platform,
        "tags": [str(tag) for tag in list(sys_tags())[:64]],
    },
    "sqlite_version": sqlite3.sqlite_version,
    "site_packages": str(purelib),
    "promin": {
        "version": promin.__version__,
        "module_file": str(module_file),
        "module_sha256": digest_file(module_file),
        "record": record_binding(promin_distribution),
        "installed_files": promin_files,
        "installed_files_digest": canonical_digest(promin_files),
        "installed_file_count": len(promin_files),
    },
    "console_wrapper": {
        "path": str(wrapper),
        "sha256": digest_file(wrapper),
        "bytes": wrapper.stat().st_size,
    },
    "transitive_distributions": distributions,
    "transitive_distribution_digest": canonical_digest(distributions),
    "sbom": {
        "format": "promin-spdx-lite-v1",
        "components": [{"name": row["name"], "version": row["version"], "record_sha256": row["record"]["sha256"]} for row in distributions],
    },
    "license_closure": {
        "entries": license_rows,
        "complete": all(row["license"] != "UNKNOWN" for row in license_rows),
        "digest": canonical_digest(license_rows),
    },
    "build_backend": {
        "name": "setuptools.build_meta",
        "distribution": "setuptools",
        "version": build_distribution["version"],
        "record_sha256": build_distribution["record"]["sha256"],
    },
}
result["sbom"]["digest"] = canonical_digest(result["sbom"]["components"])
result["observation_digest"] = canonical_digest(result)
print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
'''


def _observe_installed_environment(
    *,
    python: Path,
    executable: Path,
    cwd: Path,
    canonical_root: Path,
    environment: dict[str, str],
    pip_report_paths: tuple[tuple[str, Path], ...],
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    observed = _run_capture_with_deadline(
        [str(python), "-I", "-B", "-c", _INSTALLED_ENVIRONMENT_PROBE, str(executable)],
        cwd=cwd,
        environment=environment,
        deadline_monotonic=deadline_monotonic,
        phase="installed environment observation",
    )
    if observed.returncode != 0:
        raise ValidationFailure("nested installed-environment observation failed: " + observed.stderr[-8192:])
    if len(observed.stdout.encode("utf-8")) > 16 * 1024 * 1024:
        raise ValidationFailure("nested installed-environment observation exceeds its bound")
    try:
        value = json.loads(observed.stdout)
    except json.JSONDecodeError as exc:
        raise ValidationFailure("nested installed-environment observation returned non-JSON output") from exc
    if (
        not isinstance(value, dict)
        or value.get("promin", {}).get("version")
        != _canonical_standard_version(canonical_root)
    ):
        raise ValidationFailure("nested installed-environment observation is incomplete")
    report_rows: list[dict[str, Any]] = []
    seen_roles: set[str] = set()
    for role, report_path in pip_report_paths:
        if role in seen_roles:
            raise ValidationFailure("pip install report roles must be unique")
        seen_roles.add(role)
        try:
            report_bytes = report_path.read_bytes()
            report = json.loads(report_bytes.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValidationFailure("pip install report is missing or malformed") from exc
        if len(report_bytes) > 16 * 1024 * 1024 or not isinstance(report, dict):
            raise ValidationFailure("pip install report exceeds its bound or has the wrong shape")
        installs = report.get("install")
        if not isinstance(installs, list) or not installs:
            raise ValidationFailure("pip install report contains no installed artifacts")
        artifacts: list[dict[str, Any]] = []
        for item in installs:
            if not isinstance(item, dict):
                raise ValidationFailure("pip install report entry has the wrong shape")
            metadata_value = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            download = item.get("download_info") if isinstance(item.get("download_info"), dict) else {}
            archive_info = download.get("archive_info") if isinstance(download.get("archive_info"), dict) else {}
            hashes = archive_info.get("hashes") if isinstance(archive_info.get("hashes"), dict) else {}
            artifacts.append(
                {
                    "name": str(metadata_value.get("name", "unknown")).casefold(),
                    "version": str(metadata_value.get("version", "unknown")),
                    "is_direct": bool(item.get("is_direct")),
                    "hashes": [f"{name}:{value}" for name, value in sorted(hashes.items())],
                }
            )
        artifacts.sort(key=lambda row: (row["name"], row["version"]))
        report_rows.append(
            {
                "role": role,
                "sha256": hashlib.sha256(report_bytes).hexdigest(),
                "bytes": len(report_bytes),
                "pip_version": str(report.get("pip_version", "unknown")),
                "install_count": len(installs),
                "artifacts": artifacts,
                "artifact_digest": hashlib.sha256(canonical_bytes(artifacts)).hexdigest(),
            }
        )
    report_binding = {
        "reports": report_rows,
        "report_count": len(report_rows),
        "artifact_digest": hashlib.sha256(canonical_bytes(report_rows)).hexdigest(),
    }
    return {"observation": value, "pip_report": report_binding}


def _current_environment_installability(
    root: Path,
    dependencies: list[str],
    build_requirements: list[str],
    environment: dict[str, str],
    distribution: dict[str, str],
) -> dict[str, Any]:
    _, mode_details = _pip_install_arguments(root, "current-environment", None)
    _declared_console_script(root)
    python_requirement = _verify_current_python_requirement(root)
    resolved = _resolve_current_dependencies(dependencies)
    probe = (
        "import json,promin,sys;"
        "print(json.dumps({'runtime_version':promin.__version__,'executable':sys.executable},sort_keys=True))"
    )
    completed = subprocess.run(
        [sys.executable, "-B", "-c", probe],
        cwd=root,
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise ValidationFailure("current interpreter cannot import promin: " + completed.stderr[-4096:])
    try:
        runtime = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValidationFailure("current interpreter runtime probe returned non-JSON output") from exc
    if runtime.get("runtime_version") != distribution["version"]:
        raise ValidationFailure("current interpreter promin runtime version differs from canonical standard version")
    current_python = Path(sys.executable).absolute()
    invoked = _invoke_workflow_help(
        root=root,
        python=current_python,
        environment=environment,
        executable=None,
    )
    return {
        "performed": True,
        "verified": True,
        "mode": "current-environment",
        **mode_details,
        "declared_runtime_dependencies": dependencies,
        "declared_build_dependencies": build_requirements,
        "declared_python_requirement": python_requirement,
        "resolved_runtime_dependencies": resolved,
        "dependency_closure_check": "direct-requirements-pass",
        "version": distribution["version"],
        "python_distribution_version": distribution["python_version"],
        "console_script": {
            "present": True,
            "declared": True,
            "installed_wrapper_checked": False,
            "source_module_invoked": True,
            "posix_execute_bits": None,
        },
        "invocations": invoked,
        "interpreter": {
            "executable": str(current_python),
            "reported_executable": runtime.get("executable"),
            "prefix": sys.prefix,
            "base_prefix": sys.base_prefix,
            "nested_venv_created": False,
        },
        "platform": {"os_name": os.name, "sys_platform": sys.platform, "python": platform.python_version()},
        "product_acceptance_pass": False,
    }


def _copy_locked_wheelhouse(source: Path, destination: Path) -> dict[str, Any]:
    source = source.resolve(strict=True)
    before = _wheelhouse_binding(source)
    if destination.exists():
        raise ValidationFailure("locked wheelhouse destination must not exist")
    destination.mkdir(parents=True)
    for row in before["files"]:
        source_path = source / row["path"]
        destination_path = destination / row["path"]
        with source_path.open("rb") as reader, destination_path.open("xb") as writer:
            for chunk in iter(lambda: reader.read(1024 * 1024), b""):
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
        if (
            destination_path.stat(follow_symlinks=False).st_size != row["bytes"]
            or sha256_file(destination_path) != row["sha256"]
        ):
            raise ValidationFailure("locked wheelhouse copy differs from its source binding")
    after = _wheelhouse_binding(source)
    copied = _wheelhouse_binding(destination)
    if before != after or before != copied:
        raise ValidationFailure("offline wheelhouse changed while it was being locked")
    return {
        "source_binding": before,
        "locked_copy_binding": copied,
        "source_unchanged": True,
        "copy_verified": True,
    }


_INSTALLED_ORIGIN_PROBE = r'''
import hashlib
import json
import pathlib
import promin
import sys
import sysconfig

module = pathlib.Path(promin.__file__).resolve()
site_packages = pathlib.Path(sysconfig.get_paths()["purelib"]).resolve()
install_source = pathlib.Path(sys.argv[1]).resolve()
paths = [str(pathlib.Path(item).resolve()) for item in sys.path if item]
inside_site_packages = site_packages == module.parent or site_packages in module.parents
outside_install_source = install_source != module and install_source not in module.parents
source_absent_from_sys_path = str(install_source) not in paths
if not inside_site_packages or not outside_install_source or not source_absent_from_sys_path:
    raise RuntimeError("installed import origin is shadowed by the source fixture")
result = {
    "isolated_mode": bool(sys.flags.isolated),
    "safe_path": bool(sys.flags.safe_path),
    "module_file": str(module),
    "module_sha256": hashlib.sha256(module.read_bytes()).hexdigest(),
    "site_packages": str(site_packages),
    "inside_site_packages": inside_site_packages,
    "outside_install_source": outside_install_source,
    "source_absent_from_sys_path": source_absent_from_sys_path,
    "sys_path_digest": hashlib.sha256((json.dumps(paths, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest(),
}
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'''


def create_clean_installed_environment(
    root: Path,
    destination: Path,
    *,
    mode: str,
    wheelhouse: Path | None = None,
    include_test_dependencies: bool = False,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Install one immutable source copy into a clean environment that the caller owns."""

    if mode not in {"offline-wheelhouse", "online-clean"}:
        raise ValidationFailure("clean installed environment requires offline-wheelhouse or online-clean")
    root = root.resolve(strict=True)
    destination = destination.absolute()
    if destination.exists():
        raise ValidationFailure("clean installed environment destination must not exist")
    _remaining_deadline_seconds(deadline_monotonic, "clean installation setup")
    destination.mkdir(parents=True)
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    environment["PYTHONSAFEPATH"] = "1"
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    source = destination / "install-source" / "promin"
    shutil.copytree(root, source)
    _remaining_deadline_seconds(deadline_monotonic, "candidate source copy")
    dependencies, build_requirements = _declared_requirements(source)
    distribution = distribution_identity(source)

    locked_wheelhouse: Path | None = None
    wheelhouse_lock: dict[str, Any] | None = None
    if mode == "offline-wheelhouse":
        if wheelhouse is None:
            raise ValidationFailure("offline-wheelhouse mode requires --wheelhouse")
        for name in (
            "PIP_INDEX_URL",
            "PIP_EXTRA_INDEX_URL",
            "PIP_FIND_LINKS",
            "PIP_TRUSTED_HOST",
        ):
            environment.pop(name, None)
        environment["PIP_NO_INDEX"] = "1"
        locked_wheelhouse = destination / "locked-wheelhouse"
        wheelhouse_lock = _copy_locked_wheelhouse(wheelhouse, locked_wheelhouse)
        _remaining_deadline_seconds(deadline_monotonic, "wheelhouse lock")
    else:
        if wheelhouse is not None:
            raise ValidationFailure("wheelhouse is only valid with offline-wheelhouse mode")
        environment.pop("PIP_NO_INDEX", None)

    venv = destination / "venv"
    _create_clean_venv(
        venv,
        environment,
        deadline_monotonic=deadline_monotonic,
    )
    scripts = venv / ("Scripts" if os.name == "nt" else "bin")
    python = scripts / ("python.exe" if os.name == "nt" else "python")
    if not python.is_file():
        raise ValidationFailure("clean installed interpreter is missing")
    pip_report_path = destination / "pip-install-report.json"
    build_report_path = destination / "pip-build-requirements-report.json"
    pip_arguments, mode_details = _pip_install_arguments(
        source,
        mode,
        locked_wheelhouse,
        pip_report_path,
        extras=("test",) if include_test_dependencies else (),
    )
    build_arguments = [
        "-m",
        "pip",
        "--isolated",
        "install",
        "--disable-pip-version-check",
        "--upgrade",
        "--force-reinstall",
    ]
    if mode == "offline-wheelhouse":
        build_arguments.extend(
            ["--no-index", "--find-links", str(locked_wheelhouse.resolve())]
        )
    build_arguments.extend(["--report", str(build_report_path), *build_requirements])
    build_installed = _run_capture_with_deadline(
        [str(python), "-I", "-B", *build_arguments],
        cwd=destination,
        environment=environment,
        deadline_monotonic=deadline_monotonic,
        phase=f"{mode} build dependency installation",
    )
    if build_installed.returncode != 0:
        raise ValidationFailure(
            f"{mode} declared build dependency install failed: "
            + (build_installed.stdout + build_installed.stderr)[-8192:]
        )
    installed = _run_capture_with_deadline(
        [str(python), "-I", "-B", *pip_arguments],
        cwd=destination,
        environment=environment,
        deadline_monotonic=deadline_monotonic,
        phase=f"{mode} candidate installation",
    )
    if installed.returncode != 0:
        raise ValidationFailure(
            f"{mode} package install failed: "
            + (installed.stdout + installed.stderr)[-8192:]
        )

    dependency_probe = (
        "import importlib.metadata as m,json,promin,sys;"
        "from pip._vendor.packaging.requirements import Requirement;"
        "out={};"
        "reqs=[Requirement(x) for x in json.loads(sys.argv[1])];"
        "active=[r for r in reqs if r.marker is None or r.marker.evaluate()];"
        "[(lambda v,r:(out.update({r.name:{'requirement':str(r),'version':v}}),"
        "(_ for _ in ()).throw(RuntimeError(f'unsatisfied requirement: {r} installed={v}')) if v not in r.specifier else None))"
        "(m.version(r.name),r) for r in active];"
        "print(json.dumps({'promin':m.version('promin'),'runtime':promin.__version__,'dependencies':out},sort_keys=True))"
    )
    probed = _run_capture_with_deadline(
        [str(python), "-I", "-B", "-c", dependency_probe, json.dumps(dependencies)],
        cwd=destination,
        environment=environment,
        deadline_monotonic=deadline_monotonic,
        phase="installed dependency verification",
    )
    if probed.returncode != 0:
        raise ValidationFailure("installed dependency verification failed: " + probed.stderr[-4096:])
    try:
        installed_metadata = json.loads(probed.stdout)
    except json.JSONDecodeError as exc:
        raise ValidationFailure("installed dependency verification returned non-JSON output") from exc
    if (
        installed_metadata.get("promin") != distribution["python_version"]
        or installed_metadata.get("runtime") != distribution["version"]
    ):
        raise ValidationFailure("installed distribution version mismatch")
    if include_test_dependencies:
        test_probe = _run_capture_with_deadline(
            [str(python), "-I", "-B", "-c", "import importlib.metadata as m; print(m.version('pytest'))"],
            cwd=destination,
            environment=environment,
            deadline_monotonic=deadline_monotonic,
            phase="installed test dependency verification",
        )
        if test_probe.returncode != 0 or not test_probe.stdout.strip():
            raise ValidationFailure("clean installed test dependency closure is incomplete")

    checked = _run_capture_with_deadline(
        [str(python), "-I", "-B", "-m", "pip", "check", "--disable-pip-version-check"],
        cwd=destination,
        environment=environment,
        deadline_monotonic=deadline_monotonic,
        phase="installed dependency closure check",
    )
    if checked.returncode != 0:
        raise ValidationFailure(
            f"{mode} dependency closure check failed: "
            + (checked.stdout + checked.stderr)[-4096:]
        )

    _declared_console_script(source)
    executable = scripts / ("promin.exe" if os.name == "nt" else "promin")
    if executable.is_symlink() or not executable.is_file():
        raise ValidationFailure("installed promin command is missing")
    posix_execute_bits: bool | None = None
    if os.name != "nt":
        posix_execute_bits = bool(
            stat.S_IMODE(executable.stat(follow_symlinks=False).st_mode) & 0o111
        )
        if not posix_execute_bits:
            raise ValidationFailure("installed promin command has no POSIX execute bit")
    wrapper_identity = {
        "path": str(executable),
        "sha256": sha256_file(executable),
        "size_bytes": executable.stat(follow_symlinks=False).st_size,
    }
    invoked = _invoke_workflow_help(
        root=destination,
        python=python,
        environment=environment,
        executable=executable,
        deadline_monotonic=deadline_monotonic,
    )
    installed_environment = _observe_installed_environment(
        python=python,
        executable=executable,
        cwd=destination,
        canonical_root=source,
        environment=environment,
        pip_report_paths=(
            ("build-requirements", build_report_path),
            ("candidate-install", pip_report_path),
        ),
        deadline_monotonic=deadline_monotonic,
    )
    observation = installed_environment["observation"]
    observed_python = observation.get("python", {})
    expected_base_executable = Path(
        getattr(sys, "_base_executable", sys.executable)
    ).resolve(strict=True)
    expected_observation = {
        "console_wrapper_sha256": wrapper_identity["sha256"],
        "console_wrapper_bytes": wrapper_identity["size_bytes"],
        "runtime_version": distribution["version"],
        "python_executable": str(python.absolute()),
        "base_executable_sha256": sha256_file(expected_base_executable),
        "sqlite_version": sqlite3.sqlite_version,
    }
    actual_observation = {
        "console_wrapper_sha256": observation.get("console_wrapper", {}).get("sha256"),
        "console_wrapper_bytes": observation.get("console_wrapper", {}).get("bytes"),
        "runtime_version": observation.get("promin", {}).get("version"),
        "python_executable": observed_python.get("executable"),
        "base_executable_sha256": observed_python.get("base_executable_sha256"),
        "sqlite_version": observation.get("sqlite_version"),
    }
    mismatches = {
        key: {"expected": expected_observation[key], "actual": actual_observation[key]}
        for key in expected_observation
        if actual_observation[key] != expected_observation[key]
    }
    if mismatches:
        raise ValidationFailure(
            "nested observation differs from the installed wrapper, interpreter, or distribution: "
            + json.dumps(mismatches, ensure_ascii=False, sort_keys=True)
        )
    origin = _run_capture_with_deadline(
        [str(python), "-I", "-B", "-c", _INSTALLED_ORIGIN_PROBE, str(source)],
        cwd=destination,
        environment=environment,
        deadline_monotonic=deadline_monotonic,
        phase="installed import-origin assertion",
    )
    if origin.returncode != 0:
        raise ValidationFailure("installed import-origin assertion failed: " + origin.stderr[-4096:])
    try:
        origin_assertion = json.loads(origin.stdout)
    except json.JSONDecodeError as exc:
        raise ValidationFailure("installed import-origin assertion returned non-JSON output") from exc
    if (
        origin_assertion.get("isolated_mode") is not True
        or origin_assertion.get("safe_path") is not True
        or origin_assertion.get("inside_site_packages") is not True
        or origin_assertion.get("outside_install_source") is not True
        or origin_assertion.get("source_absent_from_sys_path") is not True
        or origin_assertion.get("module_sha256")
        != observation.get("promin", {}).get("module_sha256")
    ):
        raise ValidationFailure("installed import-origin assertion is incomplete")

    evidence = {
        "performed": True,
        "verified": True,
        "mode": mode,
        **mode_details,
        "declared_runtime_dependencies": dependencies,
        "declared_build_dependencies": build_requirements,
        "declared_python_requirement": _verify_current_python_requirement(root),
        "resolved_runtime_dependencies": installed_metadata["dependencies"],
        "dependency_closure_check": "pass",
        "installed_environment_observation": observation,
        "pip_report": installed_environment["pip_report"],
        "wheelhouse_lock": wheelhouse_lock,
        "origin_assertion": origin_assertion,
        "test_dependencies_installed": include_test_dependencies,
        "version": distribution["version"],
        "python_distribution_version": distribution["python_version"],
        "console_script": {
            "present": True,
            "declared": True,
            "installed_wrapper_checked": True,
            "source_module_invoked": False,
            "posix_execute_bits": posix_execute_bits,
            **wrapper_identity,
        },
        "invocations": invoked,
        "interpreter": {
            "executable": str(python),
            "nested_venv_created": True,
        },
        "platform": {
            "os_name": os.name,
            "sys_platform": sys.platform,
            "python": platform.python_version(),
        },
        "product_acceptance_pass": False,
    }
    return {
        "python": python,
        "executable": executable,
        "source": source,
        "environment": environment,
        "evidence": evidence,
    }


def verify_installability(
    root: Path,
    *,
    mode: str = "current-environment",
    wheelhouse: Path | None = None,
) -> dict[str, Any]:
    if mode not in INSTALL_MODES:
        raise ValidationFailure(f"unknown install verification mode: {mode}")
    distribution = distribution_identity(root)
    dependencies, build_requirements = _declared_requirements(root)
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    if mode == "current-environment":
        if wheelhouse is not None:
            raise ValidationFailure("wheelhouse is only valid with offline-wheelhouse mode")
        return _current_environment_installability(
            root,
            dependencies,
            build_requirements,
            environment,
            distribution,
        )
    with tempfile.TemporaryDirectory(prefix="promin-install-verify-") as temporary_name:
        installed = create_clean_installed_environment(
            root,
            Path(temporary_name) / "environment",
            mode=mode,
            wheelhouse=wheelhouse,
            include_test_dependencies=False,
        )
        return installed["evidence"]


def scan_distribution(root: Path, *, require_generated: bool = True) -> dict[str, Any]:
    files = iter_regular_files(root)
    old_identity = OLD_IDENTITY.encode("utf-8")
    forbidden_segments = {"reports", "report", "importer", "migration", "legacy", "database", "db"}
    total_bytes = 0
    for rel, path in files:
        folded_path = normalized_path_key(rel)
        if any(alias in folded_path for alias in FORBIDDEN_ALIASES):
            raise ValidationFailure(f"forbidden old or alias identity in path: {rel}")
        encoded_path = rel.encode("utf-8")
        if any(pattern.search(encoded_path) for pattern in FORBIDDEN_DEVELOPMENT_LABELS):
            raise ValidationFailure(f"forbidden development label in path: {rel}")
        if any(part.casefold() in forbidden_segments for part in PurePosixPath(rel).parts):
            raise ValidationFailure(f"non-canonical final-package path segment: {rel}")
        lower_name = path.name.casefold()
        if lower_name in {"standard-release-decision.json", "standard_release_decision.json"}:
            raise ValidationFailure(f"external StandardReleaseDecision must not be packaged: {rel}")
        if lower_name in {".coverage", "coverage.xml"} or lower_name.endswith((".pyc", ".pyo")):
            raise ValidationFailure(f"generated coverage or bytecode file rejected: {rel}")
        if lower_name == ".env" or lower_name.startswith(".env.") or lower_name in {"credentials", "credentials.json", "secrets.json"} or path.suffix.casefold() in {".pem", ".key", ".p12", ".pfx"} or lower_name.startswith("id_rsa"):
            raise ValidationFailure(f"secret-bearing filename rejected: {rel}")
        if path.suffix.casefold() in {".pyc", ".pyo", ".db", ".sqlite", ".sqlite3"}:
            raise ValidationFailure(f"compiled cache or database rejected: {rel}")
        if path.suffix.casefold() in {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"}:
            raise ValidationFailure(f"nested archive rejected: {rel}")
        size = path.stat().st_size
        total_bytes += size
        if size > MAX_DISTRIBUTION_FILE_BYTES or total_bytes > MAX_DISTRIBUTION_BYTES:
            raise ValidationFailure(f"distribution size ceiling exceeded at: {rel}")
        data = path.read_bytes().lower()
        if old_identity in data or FULL_ALIAS_UNDERSCORE.encode() in data or FULL_ALIAS_HYPHEN.encode() in data:
            raise ValidationFailure(f"forbidden old or alias identity in content: {rel}")
        if path.suffix.casefold() in TEXT_SUFFIXES and any(pattern.search(data) for pattern in FORBIDDEN_DEVELOPMENT_LABELS):
            raise ValidationFailure(f"forbidden development label in content: {rel}")
        private_marker = b"-----begin " + b"private key-----"
        if private_marker in data:
            raise ValidationFailure(f"private key material rejected: {rel}")
        if path.suffix.casefold() in TEXT_SUFFIXES and data:
            token_patterns = (
                re.compile(rb"akia[0-9a-z]{16}"),
                re.compile(rb"gh[pousr]_[0-9a-z]{36,}"),
                re.compile(rb"sk-[0-9a-z]{20,}"),
            )
            if any(pattern.search(data) for pattern in token_patterns):
                raise ValidationFailure(f"credential-shaped content rejected: {rel}")
    inventory = verify_package_inventory(root, require_generated=require_generated)
    return {
        "regular_files": len(files),
        "bytes": total_bytes,
        "forbidden_identity_occurrences": 0,
        "secret_files": 0,
        "inventory": inventory,
    }


def _parse_checksums(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        if not match:
            raise ValidationFailure(f"invalid SHA256SUMS line {number}")
        digest, rel = match.groups()
        validate_relative_path(rel)
        if rel in result:
            raise ValidationFailure(f"duplicate checksum path: {rel}")
        result[rel] = digest
    return result


def verify_package_integrity(root: Path) -> dict[str, Any]:
    manifest_path = root / "MANIFEST.json"
    sums_path = root / "SHA256SUMS.txt"
    if not manifest_path.is_file() or not sums_path.is_file():
        raise ValidationFailure("MANIFEST.json and SHA256SUMS.txt are required")
    inventory = verify_package_inventory(root)
    manifest = load_json(manifest_path)
    if set(manifest) != {"record_type", "root", "version", "builder", "generated_surfaces", "files"}:
        raise ValidationFailure("package manifest key set is not exact")
    if manifest.get("record_type") != "ProminPackageManifest" or manifest.get("root") != "promin":
        raise ValidationFailure("package manifest identity mismatch")
    distribution = distribution_identity(root)
    if manifest.get("version") != distribution["version"]:
        raise ValidationFailure("package manifest distribution version mismatch")
    if manifest.get("builder") != "tools/promin_package.py":
        raise ValidationFailure("package manifest must name tools/promin_package.py as the sole builder")
    if set(manifest.get("generated_surfaces", [])) != GENERATED_SURFACES:
        raise ValidationFailure("package manifest generated surfaces declaration mismatch")
    listed = manifest.get("files", [])
    if not isinstance(listed, list):
        raise ValidationFailure("package manifest files must be an array")
    for entry in listed:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise ValidationFailure("package manifest file entry key set is not exact")
        if not isinstance(entry["path"], str) or not isinstance(entry["size"], int) or entry["size"] < 0:
            raise ValidationFailure("package manifest file entry types are invalid")
        if not isinstance(entry["sha256"], str) or not HEX64.fullmatch(entry["sha256"]):
            raise ValidationFailure("package manifest file digest is invalid")
        validate_relative_path(entry["path"])
    listed_paths = [entry.get("path") for entry in listed if isinstance(entry, dict)]
    _require_unique(listed_paths, "package manifest paths")
    if listed_paths != sorted(listed_paths, key=lambda value: value.encode("utf-8")):
        raise ValidationFailure("package manifest paths are not in deterministic byte order")
    actual_payload = {rel: path for rel, path in iter_regular_files(root, include_generated=False)}
    if set(listed_paths) != set(actual_payload):
        raise ValidationFailure("package manifest does not close over the payload file set")
    for entry in listed:
        rel = entry["path"]
        path = actual_payload[rel]
        if entry.get("size") != path.stat().st_size or entry.get("sha256") != sha256_file(path):
            raise ValidationFailure(f"package manifest entry mismatch: {rel}")
    sums = _parse_checksums(sums_path)
    if list(sums) != sorted(sums, key=lambda value: value.encode("utf-8")):
        raise ValidationFailure("checksum paths are not in deterministic byte order")
    expected_sum_paths = set(actual_payload) | {"MANIFEST.json"}
    if set(sums) != expected_sum_paths:
        raise ValidationFailure("SHA256SUMS.txt does not close over payload plus MANIFEST.json")
    for rel, claimed in sums.items():
        if sha256_file(root / rel) != claimed:
            raise ValidationFailure(f"checksum mismatch: {rel}")
    return {
        "payload_files": len(actual_payload),
        "checksums": len(sums),
        "closure": True,
        "inventory": inventory,
    }


def _dotted_call_name(node: ast.expr) -> str | None:
    """Return a static dotted name when *node* is a direct call target."""

    if isinstance(node, ast.Name):
        return node.id
    if not isinstance(node, ast.Attribute):
        return None
    parent = _dotted_call_name(node.value)
    return None if parent is None else f"{parent}.{node.attr}"


def _call_locations(tree: ast.AST, dotted_name: str) -> list[int]:
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _dotted_call_name(node.func) == dotted_name
    ]


def _function_definitions(tree: ast.AST, name: str) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]


def _contains_dotted_call(node: ast.AST, dotted_name: str) -> bool:
    return any(
        isinstance(candidate, ast.Call) and _dotted_call_name(candidate.func) == dotted_name
        for candidate in ast.walk(node)
    )


def _temporary_root_is_normalized(tree: ast.AST) -> bool:
    """Recognize the one concrete temporary-root normalization assignment."""

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        if not isinstance(node.targets[0], ast.Name) or node.targets[0].id != "temporary":
            continue
        value = node.value
        if not isinstance(value, ast.Call) or _dotted_call_name(value.func) != "resolve_identity_path":
            continue
        if not value.args or not isinstance(value.args[0], ast.Attribute):
            continue
        root_name = value.args[0]
        if not isinstance(root_name.value, ast.Name) or root_name.value.id != "temporary_directory":
            continue
        if root_name.attr != "name":
            continue
        if any(
            keyword.arg == "strict"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in value.keywords
        ):
            return True
    return False


def verify_reconciliation_path_ownership(root: Path) -> dict[str, Any]:
    """Fail closed on the identity/transport ownership invariant.

    This is deliberately a narrow static package gate.  It protects the seams
    where a second provider-path owner or a Windows transport spelling would
    otherwise be easy to reintroduce without changing a behavioural fixture.
    It does not infer that arbitrary project paths are provider identities.
    """

    package = root / "promin"
    platform_source = package / "platform_paths.py"
    init_source = package / "init.py"
    required_sources = (platform_source, init_source)
    missing = [path.relative_to(root).as_posix() for path in required_sources if not path.is_file()]
    if missing:
        return {
            "gate_id": "REC-006",
            "status": "fail",
            "pass_credit": False,
            "violations": [f"required source missing: {path}" for path in missing],
        }

    sources = {
        path.relative_to(root).as_posix(): ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for path in sorted(package.glob("*.py"), key=lambda value: value.name)
    }
    platform_rel = platform_source.relative_to(root).as_posix()
    init_rel = init_source.relative_to(root).as_posix()
    platform_tree = sources[platform_rel]
    init_tree = sources[init_rel]
    violations: list[str] = []

    identity_definitions = [
        relative
        for relative, tree in sources.items()
        if _function_definitions(tree, "resolve_identity_path")
    ]
    if identity_definitions != [platform_rel] or len(_function_definitions(platform_tree, "resolve_identity_path")) != 1:
        violations.append(
            "resolve_identity_path must have exactly one owner at promin/platform_paths.py"
        )

    forbidden_provider_helpers = {"_provider_path", "_configured_provider_path"}
    reintroduced_helpers = sorted(
        definition.name
        for definition in ast.walk(init_tree)
        if isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef))
        and definition.name in forbidden_provider_helpers
    )
    if reintroduced_helpers:
        violations.append(
            "forbidden provider identity helper(s): " + ", ".join(reintroduced_helpers)
        )
    if _call_locations(init_tree, "os.path.abspath"):
        violations.append("promin/init.py directly calls os.path.abspath")
    direct_resolve_lines = _call_locations(init_tree, "Path.resolve")
    direct_resolve_lines.extend(
        node.lineno
        for node in ast.walk(init_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "resolve"
    )
    if direct_resolve_lines:
        violations.append(
            "promin/init.py directly calls .resolve at line(s): "
            + ", ".join(str(line) for line in sorted(set(direct_resolve_lines)))
        )
    identity_adapters = _function_definitions(init_tree, "_init_identity_path")
    if len(identity_adapters) != 1 or not _contains_dotted_call(
        identity_adapters[0], "resolve_identity_path"
    ):
        violations.append("provider identity adapter must delegate to resolve_identity_path")

    process_runs = [
        node
        for node in ast.walk(init_tree)
        if isinstance(node, ast.Call) and _dotted_call_name(node.func) == "subprocess.run"
    ]
    if len(process_runs) != 1:
        violations.append(
            f"promin/init.py must retain one provider subprocess owner, found {len(process_runs)}"
        )
    positional_transport_lines: list[int] = []
    missing_executable_lines: list[int] = []
    for run in process_runs:
        if not any(keyword.arg == "executable" for keyword in run.keywords):
            missing_executable_lines.append(run.lineno)
        if any(_contains_dotted_call(argument, "subprocess_path") for argument in run.args):
            positional_transport_lines.append(run.lineno)
    if missing_executable_lines:
        violations.append(
            "provider subprocess.run lacks executable= at line(s): "
            + ", ".join(str(line) for line in missing_executable_lines)
        )
    if positional_transport_lines:
        violations.append(
            "subprocess_path appears in positional provider argv at line(s): "
            + ", ".join(str(line) for line in positional_transport_lines)
        )

    temporary_boundaries: dict[str, list[int]] = {}
    for relative, tree in sources.items():
        lines = _call_locations(tree, "tempfile.TemporaryDirectory")
        if lines:
            temporary_boundaries[relative] = lines
            if relative != platform_rel:
                violations.append(
                    f"runtime TemporaryDirectory bypasses resolved_temporary_directory: {relative}:{','.join(map(str, lines))}"
                )
    platform_temporary = temporary_boundaries.get(platform_rel, [])
    temporary_root_normalized = _temporary_root_is_normalized(platform_tree)
    if len(platform_temporary) != 1:
        violations.append(
            "promin/platform_paths.py must be the sole runtime TemporaryDirectory owner"
        )
    if not temporary_root_normalized:
        violations.append("runtime TemporaryDirectory root is not normalized by resolve_identity_path")

    return {
        "gate_id": "REC-006",
        "status": "pass" if not violations else "fail",
        # This is a static structural gate.  It is useful diagnostic evidence,
        # never product, acceptance, or release credit.
        "pass_credit": False,
        "scope": {
            "identity_owner": platform_rel,
            "provider_layer": init_rel,
            "runtime_modules_scanned": sorted(sources),
        },
        "identity": {
            "definitions": identity_definitions,
            "provider_adapter": "_init_identity_path",
            "forbidden_provider_helpers": sorted(forbidden_provider_helpers),
            "direct_path_resolve_lines": sorted(set(direct_resolve_lines)),
            "direct_abspath_lines": _call_locations(init_tree, "os.path.abspath"),
        },
        "process_transport": {
            "provider_subprocess_run_count": len(process_runs),
            "all_runs_bind_executable": not missing_executable_lines,
            "positional_argv_has_no_subprocess_path": not positional_transport_lines,
        },
        "temporary_boundaries": {
            "owners": temporary_boundaries,
            "all_routed_through_platform_owner": len(platform_temporary) == 1
            and set(temporary_boundaries) == {platform_rel}
            and temporary_root_normalized,
        },
        "violations": violations,
    }


@dataclass
class ValidationReport:
    root: str
    valid: bool = False
    checks: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"record_type": "ProminValidationResult", "root": self.root, "valid": self.valid, "checks": self.checks, "errors": self.errors}


def validate_tree(
    root: Path,
    *,
    require_integrity: bool = True,
    require_docs: bool = True,
    require_installability: bool = False,
    install_mode: str | None = None,
    wheelhouse: Path | None = None,
    rebuild_docs: bool = False,
    font_bindings: dict[str, tuple[Path, str]] | None = None,
) -> ValidationReport:
    if _is_link_or_reparse(root):
        return ValidationReport(
            root=str(root),
            errors=["standard root symlink or reparse point rejected"],
        )
    root = root.resolve()
    report = ValidationReport(root=str(root))
    try:
        report.checks["distribution"] = scan_distribution(
            root,
            require_generated=require_integrity,
        )
        report.checks["path_ownership"] = verify_reconciliation_path_ownership(root)
        if report.checks["path_ownership"]["status"] != "pass":
            raise ValidationFailure(
                "REC-006 path-ownership invariant failed: "
                + "; ".join(report.checks["path_ownership"]["violations"])
            )
        report.checks["core"] = verify_core(root)
        schema = load_json(root / "core" / "contracts.schema.json")
        report.checks["preset"] = verify_preset(root, schema)
        report.checks["experience_profiles"] = verify_experience_profiles(root)
        report.checks["skill_catalog"] = verify_skill_catalog(root)
        report.checks["identity_binding"] = {
            "core_bundle_digest": report.checks["core"]["bundle_digest"],
            "selected_preset_sha256": report.checks["preset"]["sha256"],
            "distribution_version": distribution_identity(root)["version"],
            "tool_digests": {
                "tools/promin_package.py": sha256_file(root / "tools" / "promin_package.py"),
                "tools/promin_validate.py": sha256_file(root / "tools" / "promin_validate.py"),
            },
            "tool_versions": validation_runtime_identity(),
            "implementation_closure": implementation_closure(root),
        }
        report.checks["version"] = verify_version(root, report.checks["core"], report.checks["preset"])
        policy_ids = {item["validator_id"] for item in load_json(root / "core" / "policy-set.json")["policies"]}
        conformance = load_json(root / "core" / "conformance.json")
        report.checks["executable_surfaces"] = verify_executable_surfaces(
            root,
            policy_ids,
            set(conformance["required_acceptance"]),
            set(conformance["mutation_families"]),
        )
        effective_install_mode = install_mode
        if require_installability and effective_install_mode is None:
            effective_install_mode = "current-environment"
        if effective_install_mode is not None:
            report.checks["installability"] = verify_installability(
                root,
                mode=effective_install_mode,
                wheelhouse=wheelhouse,
            )
        elif wheelhouse is not None:
            raise ValidationFailure("wheelhouse requires offline-wheelhouse install verification")
        else:
            report.checks["installability"] = {
                "performed": False,
                "verified": False,
                "mode": "none",
                "reason": "explicitly-skipped",
                "product_acceptance_pass": False,
            }
        if require_docs:
            report.checks["documents"] = verify_human_documents(
                root,
                rebuild=rebuild_docs,
                font_bindings=font_bindings,
            )
        elif rebuild_docs or font_bindings is not None:
            raise ValidationFailure("document rebuild inputs require document verification")
        if require_integrity:
            report.checks["package"] = verify_package_integrity(root)
        report.valid = True
    except (OSError, KeyError, TypeError, ValueError, ValidationFailure) as exc:
        report.errors.append(str(exc))
    return report


def add_verification_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--install-mode",
        choices=("none", *INSTALL_MODES),
        default="current-environment",
        help="dependency verification source; none skips only the install smoke",
    )
    parser.add_argument("--wheelhouse", type=Path, help="offline wheel directory; required only for offline-wheelhouse")
    parser.add_argument("--rebuild-docs", action="store_true", help="regenerate PDFs with explicit font inputs and compare exact bytes")
    for role in FONT_ROLES:
        parser.add_argument(f"--font-{role}", type=Path)
        parser.add_argument(f"--font-{role}-sha256")


def font_bindings_from_args(args: argparse.Namespace) -> dict[str, tuple[Path, str]] | None:
    values = [(getattr(args, f"font_{role}"), getattr(args, f"font_{role}_sha256")) for role in FONT_ROLES]
    if not any(path is not None or digest is not None for path, digest in values):
        return None
    if not all(path is not None and digest is not None for path, digest in values):
        raise ValidationFailure("all four document font paths and matching SHA-256 values are required together")
    return {role: (path, digest) for role, (path, digest) in zip(FONT_ROLES, values)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--without-integrity", action="store_true", help="validate source tree before generated integrity surfaces exist")
    parser.add_argument("--without-docs", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path)
    add_verification_arguments(parser)
    args = parser.parse_args(argv)
    try:
        report = validate_tree(
            args.root,
            require_integrity=not args.without_integrity,
            require_docs=not args.without_docs,
            install_mode=None if args.install_mode == "none" else args.install_mode,
            wheelhouse=args.wheelhouse,
            rebuild_docs=args.rebuild_docs,
            font_bindings=font_bindings_from_args(args),
        )
    except ValidationFailure as exc:
        report = ValidationReport(root=str(args.root), errors=[str(exc)])
    rendered = json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    sys.stdout.write(rendered)
    return 0 if report.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
