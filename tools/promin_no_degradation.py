#!/usr/bin/env python3
"""Run live promin structural and focused conformance checks without report inputs."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ElementTree
from pathlib import Path
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

from promin_package import verify_archive
from promin_validate import (
    INSTALL_MODES,
    ValidationFailure,
    _close_bounded_process_tree,
    _spawn_bounded_process,
    canonical_bytes,
    create_clean_installed_environment,
    sha256_file,
    validate_tree,
)
from promin.evidence import (
    release_evidence_invocation,
    release_evidence_producer,
    seal_release_evidence,
    validate_no_degradation_result,
)


CAPTURE_BYTES = 64 * 1024
RAW_TEST_ARTIFACT_BYTES = 16 * 1024 * 1024
VALIDATION_TIMEOUT_SECONDS = 900
TEST_TIMEOUT_SECONDS = 1_200
TOTAL_TIMEOUT_SECONDS = 2_400
SATURATION_TOOL = Path(__file__).with_name("promin_saturation.py")
OPTIONAL_TEST_NAMES = (
    "init_provider_fixture_preserves_posix_executable_mode",
    "strict_parser_rejects_symlink",
    "symlink_is_rejected_when_platform_allows_creation",
)
REQUIRED_POLICY_OWNERS = {
    "P-042": "continuation-authorization-and-completeness",
    "P-043": "candidate-snapshot-consistency",
    "P-044": "provider-adapter-dispatch",
    "P-045": "current-release-closure",
    "P-046": "finding-disposition-evidence",
    "P-047": "candidate-delta-scope",
    "P-048": "verified-state-checkpoint",
    "P-049": "profile-default-depth",
    "P-050": "canonical-distribution-archive",
    "P-051": "verified-inventory-provenance",
    "P-052": "supported-command-surface",
    "P-053": "profile-bound-scale",
    "P-054": "cross-platform-release-evidence",
    "P-055": "standard-release-separation",
    "P-056": "required-gates-fail-closed",
}
REQUIRED_ACCEPTANCE = {
    "continuation-v2-complete-page-union",
    "candidate-recipe-applied-once",
    "creditable-candidate-immutable-vcs-tree",
    "selected-provider-adapter-evidence",
    "team-signed-cli-end-to-end",
    "current-release-closure-revalidation",
    "finding-bound-resolution-and-waiver-evidence",
    "candidate-delta-within-task-and-grant-scope",
    "verified-head-checkpoint-delta-replay",
    "profile-default-with-core-depth-twelve",
    "candidate-evidence-decision-acyclic-chain",
    "evidence-manifest-physical-resolution",
    "signed-standard-decision-authority-proof",
    "semver-from-candidate-binding",
    "typed-human-document-verification",
    "explicit-scale-marker-selection",
    "authenticated-role-platform-evidence-attestations",
    "installed-platform-observation-closure",
    "handle-relative-evidence-root-safety",
    "raw-scale-summary-recomputation",
    "bounded-incremental-commit-and-compaction",
    "offline-installed-no-degradation",
    "offline-release-online-compatibility",
    "decision-after-evidence-with-bounded-skew",
    "single-derived-platform-closure-owner",
    "truthful-process-invocation-status",
    "product-public-approval-separation",
    "historical-decision-current-eligibility-separation",
}
REQUIRED_MUTATIONS = {
    "continuation-frontier-loss",
    "continuation-duplicate-emission",
    "candidate-recipe-bypass",
    "observational-candidate-pass-credit",
    "snapshot-provider-substitution",
    "unsupported-provider-adapter",
    "stale-release-closure-credit",
    "finding-evidence-target-mismatch",
    "candidate-delta-scope-escape",
    "checkpoint-head-mismatch",
    "checkpoint-corruption-credit",
    "normal-command-full-replay",
    "profile-default-depth-bypass",
    "candidate-decision-cycle",
    "fabricated-evidence-digest",
    "unsigned-standard-decision",
    "unconfigured-standard-decision-key",
    "standard-decision-version-replay",
    "pdf-header-only-credit",
    "scale-environment-skip-credit",
    "status-credit-contradiction",
    "symlink-product-entry",
    "clock-order-violation",
    "noncanonical-archive-layout",
    "unverified-signature-acceptance",
}


def _capture(value: str) -> dict[str, Any]:
    encoded = value.encode("utf-8")
    truncated = len(encoded) > CAPTURE_BYTES
    selected = encoded[-CAPTURE_BYTES:] if truncated else encoded
    return {
        "text": selected.decode("utf-8", errors="replace"),
        "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "truncated": truncated,
        "selection": "tail" if truncated else "complete",
    }


def _capture_file(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
        stream.seek(max(0, size - CAPTURE_BYTES))
        selected = stream.read(CAPTURE_BYTES)
    truncated = size > CAPTURE_BYTES
    return {
        "text": selected.decode("utf-8", errors="replace"),
        "bytes": size,
        "sha256": digest.hexdigest(),
        "truncated": truncated,
        "selection": "tail" if truncated else "complete",
    }


def _embedded_test_artifact(path: Path, *, role: str, media_type: str) -> dict[str, Any]:
    payload = path.read_bytes()
    if len(payload) > RAW_TEST_ARTIFACT_BYTES:
        raise RuntimeError(f"required-test artifact exceeds its bound: {role}")
    return {
        "role": role,
        "media_type": media_type,
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "encoding": "base64",
        "data": base64.b64encode(payload).decode("ascii"),
    }


def _run_bounded(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: int,
    stdout_path: Path,
    stderr_path: Path,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    effective_timeout = float(timeout_seconds)
    if deadline_monotonic is not None:
        remaining = deadline_monotonic - started
        if remaining <= 0:
            raise RuntimeError("total no-degradation deadline expired before subprocess start")
        effective_timeout = min(effective_timeout, remaining)
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process, job_handle = _spawn_bounded_process(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            creationflags=creationflags,
            start_new_session=os.name != "nt",
        )
        timed_out = False
        cleanup = "normal-exit"
        try:
            returncode = process.wait(timeout=effective_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _close_bounded_process_tree(process, job_handle, force=True)
            cleanup = "process-group-terminated"
            returncode = process.returncode if process.returncode is not None else -1
        else:
            if _close_bounded_process_tree(process, job_handle, force=False):
                cleanup = "process-group-terminated"
    return {
        "returncode": returncode,
        "timed_out": timed_out,
        "timeout_seconds": timeout_seconds,
        "elapsed_ms": round((time.monotonic() - started) * 1000),
        "process_group_cleanup": cleanup,
        "stdout": _capture_file(stdout_path),
        "stderr": _capture_file(stderr_path),
    }


def _progress(phases: list[dict[str, Any]], name: str, result: dict[str, Any]) -> None:
    row = {
        "phase": name,
        "status": (
            "timeout"
            if result.get("timed_out")
            else "pass"
            if result.get("returncode") == 0
            else "fail"
        ),
        "returncode": result.get("returncode"),
        "elapsed_ms": result.get("elapsed_ms"),
        "timeout_seconds": result.get("timeout_seconds"),
        "process_group_cleanup": result.get("process_group_cleanup"),
    }
    phases.append(row)
    print(json.dumps({"record_type": "NoDegradationProgress", **row}, sort_keys=True), file=sys.stderr, flush=True)


def _publish_output(path: Path, rendered: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError("no-degradation output symlink is forbidden")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".promin-no-degradation-",
        suffix=".tmp",
        dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _artifact_binding(
    root: Path,
    archive: Path | None,
    candidate_binding: Path | None = None,
) -> dict[str, Any]:
    if archive is None:
        raise RuntimeError("exact archive path is required for no-degradation evidence")
    try:
        canonical_archive = verify_archive(
            archive,
            install_mode=None,
            candidate_binding=candidate_binding,
        )
    except (ValidationFailure, ValueError) as exc:
        raise RuntimeError(f"exact archive canonical verification failed: {exc}") from exc
    spec = importlib.util.spec_from_file_location("promin_no_degradation_binding", SATURATION_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("physical saturation binding tool cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        binding = module.build_artifact_binding(root, archive)
    except module.SaturationError as exc:
        raise RuntimeError(str(exc)) from exc
    archive_sha256 = canonical_archive["archive_sha256"]
    if binding.get("archive", {}).get("sha256") != "sha256:" + archive_sha256:
        raise RuntimeError("canonical archive verification and exact folder binding disagree")
    if (
        binding.get("candidate_binding_digest")
        != canonical_archive["candidate_binding"]["candidate_binding_digest"]
    ):
        raise RuntimeError("no-degradation and package verification bind different candidates")
    binding.pop("binding_digest", None)
    binding["canonical_archive_verification"] = {
        "archive_sha256": archive_sha256,
        "file_entries": canonical_archive["file_entries"],
        "byte_deterministic": canonical_archive["byte_deterministic"],
        "second_build_sha256": canonical_archive["second_build_sha256"],
        "artifact_binding": canonical_archive["artifact_binding"],
        "candidate_binding": canonical_archive["candidate_binding"],
        "standard_distribution_status": canonical_archive["standard_distribution_status"],
    }
    binding["binding_digest"] = "sha256:" + hashlib.sha256(canonical_bytes(binding)).hexdigest()
    return binding


def _test_manifest(root: Path) -> dict[str, Any]:
    rows = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        }
        for path in sorted((root / "tests").glob("test_*.py"), key=lambda item: item.name.encode("utf-8"))
        if path.is_file() and not path.is_symlink()
    ]
    if not rows:
        raise RuntimeError("required executable test manifest is empty")
    return {
        "files": rows,
        "file_count": len(rows),
        "digest": hashlib.sha256(canonical_bytes(rows)).hexdigest(),
    }


def _junit_counts(path: Path) -> dict[str, int]:
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError) as exc:
        raise RuntimeError("required-test JUnit result is missing or malformed") from exc
    suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
    if not suites:
        raise RuntimeError("required-test JUnit result contains no suites")
    counts = {
        key: sum(int(suite.attrib.get(key, "0")) for suite in suites)
        for key in ("tests", "failures", "errors", "skipped")
    }
    return counts


def _required_test_passed(returncode: int, counts: dict[str, int]) -> bool:
    return (
        returncode == 0
        and counts.get("tests", 0) > 0
        and counts.get("failures", 0) == 0
        and counts.get("errors", 0) == 0
        and counts.get("skipped", 0) == 0
    )


def _focused_pytest_command(
    root: Path,
    junit: Path,
    expression: str,
    *,
    python: Path | None = None,
) -> list[str]:
    return [
        str(python or Path(sys.executable)),
        "-I",
        "-B",
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "--import-mode=importlib",
        "-m",
        "not scale",
        "--junitxml",
        str(junit),
        "-k",
        expression,
        str(root / "tests"),
    ]


def _physical_pytest_command(root: Path, *, python: Path | None = None) -> list[str]:
    return [
        str(python or Path(sys.executable)),
        "-I",
        "-B",
        "-m",
        "pytest",
        "-q",
        "-p",
        "no:cacheprovider",
        "--import-mode=importlib",
        "-m",
        "scale",
        str(root / "tests"),
    ]


def _run_required_tests(
    root: Path,
    *,
    install_mode: str,
    wheelhouse: Path | None,
    timeout_seconds: int,
    deadline_monotonic: float,
) -> dict[str, Any]:
    expression = " and ".join(f"not {name}" for name in OPTIONAL_TEST_NAMES)
    with tempfile.TemporaryDirectory(prefix="promin-required-tests-") as temporary_name:
        temporary = Path(temporary_name)
        clean = create_clean_installed_environment(
            root,
            temporary / "installed",
            mode=install_mode,
            wheelhouse=wheelhouse,
            include_test_dependencies=True,
            deadline_monotonic=deadline_monotonic,
        )
        clean_python = clean["python"].resolve(strict=True)
        clean_source = clean["source"].resolve(strict=True)
        if (
            root == clean_python
            or root in clean_python.parents
            or clean_source == clean_python
            or clean_source in clean_python.parents
        ):
            raise RuntimeError(
                "required tests must use a nested installed interpreter outside every source tree"
            )
        if "PYTHONPATH" in clean["environment"] or "PYTHONHOME" in clean["environment"]:
            raise RuntimeError("required installed-test environment retained source import overrides")
        origin_assertion = clean["evidence"].get("origin_assertion")
        if (
            not isinstance(origin_assertion, dict)
            or origin_assertion.get("isolated_mode") is not True
            or origin_assertion.get("safe_path") is not True
            or origin_assertion.get("inside_site_packages") is not True
            or origin_assertion.get("outside_install_source") is not True
            or origin_assertion.get("source_absent_from_sys_path") is not True
        ):
            raise RuntimeError("clean installation omitted its import-origin assertion")
        fixture = temporary / "test-fixture" / "promin"
        shutil.copytree(root, fixture)
        runner = temporary / "runner"
        runner.mkdir()
        junit = temporary / "required-tests.xml"
        stdout_path = temporary / "pytest.stdout"
        stderr_path = temporary / "pytest.stderr"
        command = _focused_pytest_command(
            fixture,
            junit,
            expression,
            python=clean["python"],
        )
        environment = dict(clean["environment"])
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONHOME", None)
        for name in (
            "PROMIN_EVIDENCE_PRIVATE_KEY",
            "PROMIN_EVIDENCE_TRUST_CONFIGURATION",
            "PROMIN_EVIDENCE_KEY_ID",
            "PROMIN_EVIDENCE_PRODUCER_ID",
        ):
            environment.pop(name, None)
        environment["PROMIN_INSTALLED_TEST_MODE"] = "1"
        environment["PROMIN_EXPECTED_INSTALLED_ROOT"] = clean["evidence"][
            "installed_environment_observation"
        ]["site_packages"]
        environment["PROMIN_EXPECTED_INSTALLED_INTERPRETER"] = str(clean_python)
        environment["PROMIN_EXPECTED_INSTALL_MODE"] = install_mode
        environment["PROMIN_EXPECTED_PLATFORM"] = clean["evidence"][
            "installed_environment_observation"
        ]["platform"]["system"]
        environment["PROMIN_SOURCE_FIXTURE_ROOT"] = str(fixture)
        environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        executed = _run_bounded(
            command,
            cwd=runner,
            environment=environment,
            timeout_seconds=timeout_seconds,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            deadline_monotonic=deadline_monotonic,
        )
        counts = (
            _junit_counts(junit)
            if junit.is_file()
            else {"tests": 0, "failures": 0, "errors": 1, "skipped": 0}
        )
        artifacts = []
        if junit.is_file():
            artifacts.append(
                _embedded_test_artifact(
                    junit,
                    role="required-junit",
                    media_type="application/xml",
                )
            )
        artifacts.extend(
            (
                _embedded_test_artifact(
                    stdout_path,
                    role="required-stdout",
                    media_type="text/plain; charset=utf-8",
                ),
                _embedded_test_artifact(
                    stderr_path,
                    role="required-stderr",
                    media_type="text/plain; charset=utf-8",
                ),
            )
        )
        junit_digest = sha256_file(junit) if junit.is_file() else None
        artifact_manifest_digest = hashlib.sha256(canonical_bytes(artifacts)).hexdigest()
        installed_environment = clean["evidence"]
    passed = not executed["timed_out"] and _required_test_passed(executed["returncode"], counts)
    return {
        "ran": True,
        "command": command,
        "returncode": executed["returncode"],
        "stdout": executed["stdout"],
        "stderr": executed["stderr"],
        "timed_out": executed["timed_out"],
        "timeout_seconds": executed["timeout_seconds"],
        "elapsed_ms": executed["elapsed_ms"],
        "process_group_cleanup": executed["process_group_cleanup"],
        "required_counts": counts,
        "required_skips_fail_closed": True,
        "optional_platform_tests_excluded": list(OPTIONAL_TEST_NAMES),
        "marker_expression": "not scale",
        "selection_expression": expression,
        "junit_sha256": junit_digest,
        "raw_artifacts": artifacts,
        "raw_artifact_manifest_digest": artifact_manifest_digest,
        "installed_environment": installed_environment,
        "source_tree_shadowing_disabled": True,
        "passed": passed,
    }


def _required_predicates(root: Path) -> dict[str, Any]:
    policy_path = root / "core" / "policy-set.json"
    conformance_path = root / "core" / "conformance.json"
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        conformance = json.loads(conformance_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"required Core owners cannot be read: {exc}") from exc
    policy_rows = policy.get("policies")
    if not isinstance(policy_rows, list):
        raise RuntimeError("Core policy owner omitted policies")
    policies_by_id = {
        row.get("id"): row.get("name")
        for row in policy_rows
        if isinstance(row, dict)
        and isinstance(row.get("id"), str)
        and isinstance(row.get("name"), str)
    }
    acceptance = set(conformance.get("required_acceptance", []))
    mutations = set(conformance.get("mutation_families", []))
    missing_policies = sorted(
        policy_id
        for policy_id, policy_name in REQUIRED_POLICY_OWNERS.items()
        if policies_by_id.get(policy_id) != policy_name
    )
    missing_acceptance = sorted(REQUIRED_ACCEPTANCE - acceptance)
    missing_mutations = sorted(REQUIRED_MUTATIONS - mutations)
    return {
        "policies": [
            {"id": policy_id, "name": policy_name}
            for policy_id, policy_name in REQUIRED_POLICY_OWNERS.items()
        ],
        "acceptance_predicates": sorted(REQUIRED_ACCEPTANCE),
        "mutation_families": sorted(REQUIRED_MUTATIONS),
        "missing_policies": missing_policies,
        "missing_acceptance_predicates": missing_acceptance,
        "missing_mutation_families": missing_mutations,
        "complete": not (missing_policies or missing_acceptance or missing_mutations),
    }


def _run_validation(
    root: Path,
    *,
    install_mode: str,
    wheelhouse: Path | None,
    timeout_seconds: int,
    deadline_monotonic: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    command = [
        sys.executable,
        "-B",
        str(root / "tools" / "promin_validate.py"),
        str(root),
        "--install-mode",
        install_mode,
    ]
    if wheelhouse is not None:
        command.extend(("--wheelhouse", str(wheelhouse)))
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    with tempfile.TemporaryDirectory(prefix="promin-validation-phase-") as temporary_name:
        temporary = Path(temporary_name)
        executed = _run_bounded(
            command,
            cwd=root,
            environment=environment,
            timeout_seconds=timeout_seconds,
            stdout_path=temporary / "validation.stdout",
            stderr_path=temporary / "validation.stderr",
            deadline_monotonic=deadline_monotonic,
        )
        stdout_path = temporary / "validation.stdout"
        if stdout_path.stat().st_size > 16 * 1024 * 1024:
            raise RuntimeError("validation JSON exceeds its bounded result size")
        try:
            report = json.loads(stdout_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("validation phase did not produce one JSON report") from exc
    if not isinstance(report, dict):
        raise RuntimeError("validation phase result must be an object")
    return report, executed
def run(
    root: Path,
    pattern: str,
    archive: Path | None = None,
    *,
    install_mode: str = "offline-wheelhouse",
    wheelhouse: Path | None = None,
    candidate_binding: Path | None = None,
    validation_timeout_seconds: int = VALIDATION_TIMEOUT_SECONDS,
    test_timeout_seconds: int = TEST_TIMEOUT_SECONDS,
    total_timeout_seconds: int = TOTAL_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
    started_monotonic = time.monotonic()
    root = root.resolve()
    if root != Path(__file__).resolve().parents[1]:
        raise RuntimeError("execute no-degradation from the exact package root under test")
    if pattern != "test_*.py":
        raise RuntimeError("custom no-degradation test selection is forbidden")
    if install_mode not in INSTALL_MODES:
        raise RuntimeError(f"unknown no-degradation install mode: {install_mode}")
    if install_mode != "offline-wheelhouse" or wheelhouse is None:
        raise RuntimeError(
            "creditable no-degradation requires an explicit hash-bound offline wheelhouse"
        )
    for label, value in (
        ("validation timeout", validation_timeout_seconds),
        ("test timeout", test_timeout_seconds),
        ("total timeout", total_timeout_seconds),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise RuntimeError(f"{label} must be a positive integer")
    if validation_timeout_seconds + test_timeout_seconds > total_timeout_seconds:
        raise RuntimeError("phase timeouts exceed the total no-degradation budget")
    deadline_monotonic = started_monotonic + total_timeout_seconds
    phases: list[dict[str, Any]] = []
    binding = _artifact_binding(
        root,
        archive,
        candidate_binding,
    )
    platform_name = (
        "windows"
        if os.name == "nt"
        else "linux"
        if sys.platform.startswith("linux")
        else sys.platform
    )
    if platform_name not in {"linux", "windows"}:
        raise RuntimeError("creditable no-degradation requires an exact Linux or Windows lane")
    if binding.get("platform", {}).get("system") != platform_name:
        raise RuntimeError("no-degradation controller and artifact platform bindings disagree")
    test_manifest = _test_manifest(root)
    bound_test_manifest = binding["canonical_archive_verification"]["artifact_binding"].get(
        "test_manifest_digest"
    )
    if bound_test_manifest != test_manifest["digest"]:
        raise RuntimeError("required-test manifest differs from the exact archive binding")
    predicates = _required_predicates(root)
    validation, validation_execution = _run_validation(
        root,
        install_mode=install_mode,
        wheelhouse=wheelhouse,
        timeout_seconds=validation_timeout_seconds,
        deadline_monotonic=deadline_monotonic,
    )
    _progress(phases, "validation", validation_execution)
    result: dict[str, Any] = {
        "record_type": "NoDegradationResult",
        "status": "fail",
        "platform": platform_name,
        "no_degradation": False,
        "source": "live_files_and_executable_tests",
        "root": str(root),
        "artifact_binding": binding,
        "candidate_binding_digest": binding["canonical_archive_verification"][
            "candidate_binding"
        ]["candidate_binding_digest"],
        "test_manifest": test_manifest,
        "install_mode": install_mode,
        "required_predicates": predicates,
        "validation": validation,
        "tests": {"ran": False, "returncode": None, "stdout": _capture(""), "stderr": _capture("")},
        "passed": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "product_public_approval": "not_approved",
        "artifact_binding_unchanged": False,
        "standard_distribution_gate_pass": False,
        "phases": phases,
        "scale_selection": {
            "command": _physical_pytest_command(root),
            "runs_separately": True,
            "missing_workspace_is_failure": True,
            "pass_credit": False,
        },
    }

    def finalize() -> dict[str, Any]:
        completed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )
        result["execution_budget"] = {
            "total_timeout_seconds": total_timeout_seconds,
            "validation_timeout_seconds": validation_timeout_seconds,
            "test_timeout_seconds": test_timeout_seconds,
            "elapsed_ms": round((time.monotonic() - started_monotonic) * 1000),
            "started_at": started_at,
            "completed_at": completed_at,
        }
        result["producer"] = release_evidence_producer(
            root,
            "tools/promin_no_degradation.py",
            version=binding["standard_candidate_binding"]["version"],
        )
        result["invocation"] = release_evidence_invocation(
            invocation_id=f"no-degradation:{uuid.uuid4().hex}",
            operation="no-degradation",
            arguments={
                "archive_sha256": binding["archive"]["sha256"],
                "candidate_binding_digest": result["candidate_binding_digest"],
                "install_mode": install_mode,
                "pattern": pattern,
                "test_manifest_digest": test_manifest["digest"],
                "total_timeout_seconds": total_timeout_seconds,
            },
            started_at=started_at,
            completed_at=completed_at,
            exit_code=0 if result["passed"] else 1,
            platform_binding=binding["platform"]["binding_digest"][7:],
        )
        sealed = seal_release_evidence(result)
        if sealed["passed"]:
            validated = validate_no_degradation_result(
                sealed,
                candidate_binding=binding["standard_candidate_binding"],
                expected_platform=result["platform"],
            )
            if canonical_bytes(validated) != canonical_bytes(sealed):
                raise RuntimeError("live no-degradation validation changed the sealed result")
        return sealed

    if validation_execution["timed_out"] or validation.get("valid") is not True or not predicates["complete"]:
        return finalize()
    tests = root / "tests"
    if not tests.is_dir():
        result["validation"]["errors"].append("missing executable tests directory")
        result["validation"]["valid"] = False
        return finalize()
    if time.monotonic() >= deadline_monotonic:
        return finalize()
    result["tests"] = _run_required_tests(
        root,
        install_mode=install_mode,
        wheelhouse=wheelhouse,
        timeout_seconds=test_timeout_seconds,
        deadline_monotonic=deadline_monotonic,
    )
    _progress(phases, "required-tests", result["tests"])
    result["tests"]["scale_environment_configured"] = bool(os.environ.get("PROMIN_SCALE_WORKSPACE"))
    if time.monotonic() >= deadline_monotonic:
        return finalize()
    final_binding = _artifact_binding(
        root,
        archive,
        candidate_binding,
    )
    result["artifact_binding_unchanged"] = (
        final_binding["binding_digest"] == binding["binding_digest"]
    )
    within_deadline = time.monotonic() <= deadline_monotonic
    result["passed"] = (
        result["tests"]["passed"]
        and result["artifact_binding_unchanged"]
        and within_deadline
    )
    result["status"] = "pass" if result["passed"] else "fail"
    result["no_degradation"] = result["passed"]
    return finalize()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("output_path", nargs="?", type=Path)
    parser.add_argument("--pattern", default="test_*.py")
    parser.add_argument("--archive", required=True, type=Path, help="exact promin ZIP under test")
    parser.add_argument("--install-mode", choices=INSTALL_MODES, default="offline-wheelhouse")
    parser.add_argument("--wheelhouse", type=Path)
    parser.add_argument(
        "--validation-timeout-seconds",
        type=int,
        default=VALIDATION_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--test-timeout-seconds",
        type=int,
        default=TEST_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--total-timeout-seconds",
        type=int,
        default=TOTAL_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--candidate-binding",
        type=Path,
        help="external StandardReleaseCandidateBinding for the exact candidate bytes",
    )
    parser.add_argument("--output", dest="output_option", type=Path, help="optional external evidence destination")
    args = parser.parse_args(argv)
    if args.output_path is not None and args.output_option is not None:
        parser.error("choose either positional output_path or --output")
    output = args.output_option or args.output_path
    if output:
        root_resolved = args.root.resolve()
        output_resolved = output.resolve()
        try:
            output_resolved.relative_to(root_resolved)
        except ValueError:
            pass
        else:
            parser.error("no-degradation evidence output must be outside the canonical package")
        if output.is_symlink():
            parser.error("no-degradation evidence output must not be a symlink")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.unlink(missing_ok=True)
    try:
        result = run(
            args.root,
            args.pattern,
            args.archive,
            install_mode=args.install_mode,
            wheelhouse=args.wheelhouse,
            candidate_binding=args.candidate_binding,
            validation_timeout_seconds=args.validation_timeout_seconds,
            test_timeout_seconds=args.test_timeout_seconds,
            total_timeout_seconds=args.total_timeout_seconds,
        )
    except (OSError, ValueError, RuntimeError) as exc:
        rendered = json.dumps(
            {
                "record_type": "NoDegradationResult",
                "passed": False,
                "pass_credit": False,
                "acceptance_pass": False,
                "product_acceptance_pass": False,
                "product_public_approval": "not_approved",
                "status": "rejected",
                "reason": str(exc),
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        ) + "\n"
        if output:
            _publish_output(output, rendered)
        sys.stdout.write(rendered)
        return 2
    rendered = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if output:
        _publish_output(output, rendered)
    sys.stdout.write(rendered)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
