from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
TOOLS = PACKAGE_ROOT / "tools"
sys.path.insert(0, str(TOOLS))
if os.environ.get("PROMIN_INSTALLED_TEST_MODE") != "1":
    sys.path.insert(0, str(PACKAGE_ROOT))

from promin_package import (  # noqa: E402
    ZIP_METHOD,
    build_archive,
    build_evidence_manifest,
    sync_version,
    verify_archive,
    verify_platform,
    write_integrity,
)
from promin_validate import (  # noqa: E402
    CANONICAL_PACKAGE_DIRECTORY_COUNT,
    CANONICAL_PACKAGE_DIRECTORIES,
    CANONICAL_PACKAGE_FILE_COUNT,
    CANONICAL_PACKAGE_FILES,
    CANONICAL_PAYLOAD_FILES,
    GENERATED_SURFACES,
    ValidationFailure,
    _create_clean_venv,
    _observe_installed_environment,
    _pip_install_arguments,
    _run_capture_with_deadline,
    canonical_bytes,
    distribution_identity,
    scan_distribution,
    sha256_file,
    validate_tree,
    verify_installability,
    verify_human_documents,
    verify_package_inventory,
    verify_package_integrity,
    verify_reconciliation_path_ownership,
)
from promin_no_degradation import (  # noqa: E402
    _run_required_tests,
    _required_predicates,
    _required_test_passed,
    _run_bounded,
    main as no_degradation_main,
)
from promin.evidence import EvidenceError, load_external_json_stable  # noqa: E402

sys.path.remove(str(TOOLS))
if os.environ.get("PROMIN_INSTALLED_TEST_MODE") != "1" and str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8", newline="\n")


def create_directory_link(link: Path, target: Path) -> None:
    if os.name != "nt":
        link.symlink_to(target, target_is_directory=True)
        return
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "& { param($link,$target) "
            "New-Item -ItemType Junction -Path $link -Target $target -ErrorAction Stop | Out-Null }",
            str(link),
            str(target),
        ],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("junction creation failed: " + completed.stderr[-2048:])


def process_is_running(process_id: int) -> bool:
    if os.name == "nt":
        listed = subprocess.run(
            ["tasklist", "/FI", f"PID eq {process_id}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            check=False,
        )
        return str(process_id) in listed.stdout
    try:
        os.kill(process_id, 0)
    except ProcessLookupError:
        return False
    return True


def remove_directory_link(link: Path) -> None:
    if os.name == "nt":
        link.rmdir()
    else:
        link.unlink()


def repair_core_manifest(root: Path) -> None:
    path = root / "core" / "promin.manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    manifest["core_components"] = [
        {"path": name, "sha256": sha256_file(root / "core" / name)}
        for name in (
            "semantic-model.json",
            "authority-model.json",
            "policy-set.json",
            "contracts.schema.json",
            "conformance.json",
        )
    ]
    identity = dict(manifest)
    identity.pop("bundle_digest", None)
    manifest["bundle_digest"] = hashlib.sha256(canonical_bytes(identity)).hexdigest()
    write_json(path, manifest)


def copy_canonical_payload_tree(root: Path) -> None:
    """Materialize exactly the declared payload, excluding live worktree noise."""

    root.mkdir(parents=True)
    for relative in sorted(CANONICAL_PAYLOAD_FILES, key=lambda value: value.encode("utf-8")):
        source = PACKAGE_ROOT / relative
        if not source.is_file():
            raise AssertionError(f"canonical payload source is unavailable: {relative}")
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    repair_core_manifest(root)
    sync_version(root)


FABRICATED_EVIDENCE_ROLES = {
    "linux": "PlatformVerificationResult",
    "windows": "PlatformVerificationResult",
    "physical-scale": "SaturationEvidence",
    "saturation-audit": "SaturationAudit",
    "human-documents": "HumanDocumentVerification",
    "linux-no-degradation": "NoDegradationResult",
    "windows-no-degradation": "NoDegradationResult",
}


def create_fabricated_standard_evidence(
    base: Path,
    candidate_binding_path: Path,
) -> tuple[Path, Path]:
    candidate = json.loads(candidate_binding_path.read_text(encoding="utf-8"))
    evidence_root = base / "standard-evidence"
    evidence_root.mkdir()
    plan_entries: list[dict[str, object]] = []
    for index, (role, record_type) in enumerate(
        FABRICATED_EVIDENCE_ROLES.items(), start=1
    ):
        relative = f"evidence-{index:02d}.json"
        evidence: dict[str, object] = {
            "record_type": record_type,
            "status": "pass",
            "candidate_binding_digest": candidate[
                "candidate_binding_digest"
            ],
            "claimed_pass": True,
        }
        write_json(
            evidence_root / relative,
            evidence,
        )
        plan_entries.append(
            {
                "evidence_id": f"fixture-evidence-{index:02d}",
                "evidence_role": role,
                "path": relative,
                "predicates": [{"pointer": "/claimed_pass", "equals": True}],
            }
        )
    plan_path = base / "standard-evidence-plan.json"
    write_json(
        plan_path,
        {
            "record_type": "StandardReleaseEvidencePlan",
            "entries": plan_entries,
            "matrix_aggregate": {
                "path": "matrix-current/platform-no-degradation-matrix.json"
            },
            "supplemental_lanes": [
                {
                    "lane_id": "linux-cp314-offline",
                    "path": "no-degradation-current/linux-cp314-offline.json",
                },
                {
                    "lane_id": "linux-cp314-online",
                    "path": "platform-matrix-current/linux-cp314-online.json",
                },
                {
                    "lane_id": "windows-cp314-offline",
                    "path": "no-degradation-current/windows-cp314-offline.json",
                },
                {
                    "lane_id": "windows-cp314-online",
                    "path": "platform-matrix-current/windows-cp314-online.json",
                },
            ],
        },
    )
    return evidence_root, plan_path


class PackageValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.template_temporary = tempfile.TemporaryDirectory(prefix="promin-package-template-")
        cls.template = Path(cls.template_temporary.name) / "promin"
        shutil.copytree(
            PACKAGE_ROOT,
            cls.template,
            ignore=shutil.ignore_patterns(
                "MANIFEST.json",
                "SHA256SUMS.txt",
                ".git",
                "__pycache__",
                "*.pyc",
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
                "*.egg-info",
            ),
        )
        repair_core_manifest(cls.template)
        sync_version(cls.template)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.template_temporary.cleanup()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="promin-package-test-")
        self.base = Path(self.temporary.name)
        self.root = self.base / "promin"
        shutil.copytree(self.template, self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_manifest_and_checksum_close_over_exact_tree(self) -> None:
        write_integrity(self.root)
        result = verify_package_integrity(self.root)
        self.assertTrue(result["closure"])
        self.assertEqual(result["inventory"]["files"], CANONICAL_PACKAGE_FILE_COUNT)
        self.assertEqual(result["inventory"]["directories"], CANONICAL_PACKAGE_DIRECTORY_COUNT)
        manifest = json.loads((self.root / "MANIFEST.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["builder"], "tools/promin_package.py")
        (self.root / "unowned.txt").write_text("unowned\n", encoding="utf-8")
        with self.assertRaises(ValidationFailure):
            verify_package_integrity(self.root)

    def test_root_git_worktree_file_is_host_metadata_but_nested_git_is_rejected(self) -> None:
        root = self.base / "linked-worktree"
        copy_canonical_payload_tree(root)
        write_integrity(root)

        # Linked Git worktrees use this root-level regular file instead of a
        # `.git` directory.  It is host metadata and cannot alter payload
        # manifest/checksum closure after baseline integrity was generated.
        (root / ".git").write_text(
            "gitdir: C:/host/worktrees/promin/.git/worktrees/linked\n",
            encoding="utf-8",
            newline="\n",
        )
        inventory = verify_package_inventory(root)
        integrity = verify_package_integrity(root)
        self.assertTrue(inventory["exact"])
        self.assertTrue(integrity["closure"])

        write_integrity(root)
        manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
        self.assertNotIn(".git", {entry["path"] for entry in manifest["files"]})

        # This is nested package content, not worktree metadata.  It remains
        # subject to the normal exact-inventory rejection path.
        nested = root / "docs" / ".git"
        nested.write_text("must remain package-visible\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ValidationFailure,
            r"canonical package file inventory mismatch: .*docs/\.git",
        ):
            verify_package_inventory(root)

    def test_canonical_inventory_declares_exact_v1_tree(self) -> None:
        self.assertEqual(CANONICAL_PACKAGE_FILE_COUNT, 262)
        self.assertEqual(CANONICAL_PACKAGE_DIRECTORY_COUNT, 17)
        self.assertEqual(len(CANONICAL_PACKAGE_FILES), CANONICAL_PACKAGE_FILE_COUNT)
        self.assertEqual(
            len(CANONICAL_PACKAGE_DIRECTORIES),
            CANONICAL_PACKAGE_DIRECTORY_COUNT,
        )
        self.assertEqual(
            CANONICAL_PACKAGE_DIRECTORIES,
            {".github", ".github/workflows", "capability_profiles", "core", "docs", "docs/audit", "examples", "human", "language_profiles", "presets", "profiles", "promin", "prompts", "skills", "skills/example", "tests", "tools"},
        )
        self.assertEqual(CANONICAL_PACKAGE_FILES - CANONICAL_PAYLOAD_FILES, GENERATED_SURFACES)
        for required in (
            "LICENSE",
            "MACHINE_README.md",
            "THIRD_PARTY_NOTICES.md",
            "human/promin_appendices_en.pdf",
            "human/promin_appendices_ua.pdf",
            "human/promin_main_en.pdf",
            "human/promin_main_ua.pdf",
            "core/authority-model.json",
            "core/conformance.json",
            "core/contracts.schema.json",
            "core/policy-set.json",
            "core/promin.manifest.json",
            "core/semantic-model.json",
            "docs/audit/ALPHA4_HEAVY_HARDENING_WAVE_UA.md",
            "presets/semantic-standard.json",
        ):
            self.assertIn(required, CANONICAL_PACKAGE_FILES)
        self.assertTrue({
            "promin/__init__.py",
            "promin/__main__.py",
            "promin/audit.py",
            "promin/context_index.py",
            "promin/documentation.py",
            "promin/experience.py",
            "promin/host_integration.py",
            "promin/initial_project_work.py",
            "promin/portability.py",
            "promin/revalidation_workflow.py",
            "promin/refresh.py",
            "promin/skills.py",
            "promin/system_check.py",
            "promin/weak_model_workflow.py",
            "promin/windows_event_history.py",
        }.issubset(CANONICAL_PACKAGE_FILES))
        self.assertTrue({
            "tools/compile_schema.py",
            "tools/generate_human.py",
            "tools/promin_alpha_check.py",
            "tools/promin_checkpoint_profile.py",
            "tools/promin_package.py",
            "tools/promin_performance_model.py",
            "tools/promin_projection_profile.py",
            "tools/promin_validate.py",
        }.issubset(CANONICAL_PACKAGE_FILES))
        self.assertTrue({
            "tests/test_alpha_deployable.py",
            "tests/test_alpha4_bundled_language_catalog.py",
            "tests/test_alpha4_init_evidence_first_profiles.py",
            "tests/test_alpha_experience.py",
            "tests/test_alpha_host_pickup.py",
            "tests/test_alpha_portability.py",
            "tests/test_alpha_skills.py",
            "tests/test_alpha_skills_checklist.py",
            "tests/test_expert_init_bundle_roundtrip.py",
            "tests/test_initial_project_work.py",
            "tests/test_public_workflows_cli.py",
            "tests/test_revalidation_workflow.py",
        }.issubset(CANONICAL_PACKAGE_FILES))
        self.assertTrue({
            "tests/test_heavy_checkpoint_profile.py",
            "tests/test_heavy_derived_storage.py",
            "tests/test_heavy_event_batching.py",
            "tests/test_heavy_eventstore_commit_io_profile.py",
            "tests/test_heavy_eventstore_lifecycle.py",
            "tests/test_heavy_eventstore_postcommit_index_failure.py",
            "tests/test_heavy_eventstore_validator_cache.py",
            "tests/test_heavy_performance_model.py",
            "tests/test_heavy_projection_bulk_rebuild.py",
            "tests/test_heavy_projection_incremental_shards.py",
            "tests/test_heavy_projection_profile.py",
            "tests/test_heavy_query_tail_scale.py",
            "tests/test_heavy_saturation_continuation_sqlite.py",
            "tests/test_heavy_saturation_storage_budget.py",
            "tests/test_heavy_state_binding_batch_union.py",
            "tests/test_heavy_state_binding_batching.py",
            "tests/test_heavy_state_binding_storage.py",
            "tests/test_heavy_state_binding_storage_retention.py",
            "tests/test_heavy_runtime_checkpoint_incremental.py",
            "tests/test_heavy_weak_model_workflow.py",
            "tests/test_heavy_windows_event_history.py",
            "tests/test_heavy_windows_seal_scaling.py",
            "tests/test_retrieval_continuation_service.py",
            "tests/test_saturation_archive_binding.py",
            "tests/test_saturation_raw_artifact_cardinality.py",
            "tests/test_projection_profile_cleanup.py",
        }.issubset(CANONICAL_PACKAGE_FILES))

    def test_every_canonical_payload_file_is_mandatory(self) -> None:
        for rel in sorted(CANONICAL_PAYLOAD_FILES, key=lambda value: value.encode("utf-8")):
            with self.subTest(path=rel):
                target = self.root / rel
                content = target.read_bytes()
                target.unlink()
                try:
                    with self.assertRaisesRegex(
                        ValidationFailure,
                        rf"canonical package file inventory mismatch: .*{re.escape(rel)}",
                    ):
                        verify_package_inventory(self.root, require_generated=False)
                finally:
                    target.write_bytes(content)

    def test_generated_integrity_surfaces_are_mandatory_in_final_tree(self) -> None:
        write_integrity(self.root)
        for rel in sorted(GENERATED_SURFACES):
            with self.subTest(path=rel):
                target = self.root / rel
                content = target.read_bytes()
                target.unlink()
                try:
                    with self.assertRaisesRegex(
                        ValidationFailure,
                        rf"canonical package file inventory mismatch: .*{re.escape(rel)}",
                    ):
                        verify_package_inventory(self.root)
                finally:
                    target.write_bytes(content)

    def test_canonical_inventory_rejects_extra_file(self) -> None:
        write_integrity(self.root)
        (self.root / "draft.tmp").write_text("intermediate\n", encoding="utf-8")
        with self.assertRaisesRegex(
            ValidationFailure,
            r"canonical package file inventory mismatch: .*draft\.tmp",
        ):
            verify_package_inventory(self.root)

    def test_canonical_inventory_rejects_extra_directories(self) -> None:
        write_integrity(self.root)
        for rel in ("draft", "tools/intermediate"):
            with self.subTest(path=rel):
                target = self.root / rel
                target.mkdir(parents=True)
                try:
                    with self.assertRaisesRegex(
                        ValidationFailure,
                        rf"canonical package directory inventory mismatch: .*{re.escape(rel)}",
                    ):
                        verify_package_inventory(self.root)
                finally:
                    target.rmdir()

    def test_integrity_writer_rejects_missing_payload_before_writing(self) -> None:
        target = self.root / "LICENSE"
        target.unlink()
        with self.assertRaisesRegex(
            ValidationFailure,
            r"canonical package file inventory mismatch: .*LICENSE",
        ):
            write_integrity(self.root)
        self.assertFalse((self.root / "MANIFEST.json").exists())
        self.assertFalse((self.root / "SHA256SUMS.txt").exists())

    def test_integrity_writer_rejects_extra_directory_before_writing(self) -> None:
        (self.root / "draft").mkdir()
        with self.assertRaisesRegex(
            ValidationFailure,
            r"canonical package directory inventory mismatch: .*draft",
        ):
            write_integrity(self.root)
        self.assertFalse((self.root / "MANIFEST.json").exists())
        self.assertFalse((self.root / "SHA256SUMS.txt").exists())

    def test_full_tree_validates_with_false_acceptance(self) -> None:
        write_integrity(self.root)
        report = validate_tree(self.root)
        self.assertTrue(report.valid, report.errors)
        distribution = distribution_identity(self.root)
        self.assertEqual(report.checks["version"]["version"], distribution["version"])
        self.assertEqual(
            set(report.checks["version"]),
            {
                "record_type",
                "canonical_name",
                "version",
                "core_bundle_digest",
                "selected_preset",
                "integrity",
            },
        )
        self.assertNotIn("acceptance", report.checks["version"])
        self.assertNotIn("distribution_status", report.checks["version"])
        self.assertEqual(report.checks["path_ownership"]["status"], "pass")

    def test_reconciliation_path_ownership_gate_is_reported_and_passes(self) -> None:
        result = verify_reconciliation_path_ownership(self.root)

        self.assertEqual(result["gate_id"], "REC-006")
        self.assertEqual(result["status"], "pass", result["violations"])
        self.assertFalse(result["pass_credit"])
        self.assertEqual(
            result["identity"]["definitions"], ["promin/platform_paths.py"]
        )
        self.assertEqual(result["process_transport"]["provider_subprocess_run_count"], 1)
        self.assertTrue(result["temporary_boundaries"]["all_routed_through_platform_owner"])

    def test_reconciliation_path_ownership_gate_fails_closed(self) -> None:
        init_source = self.root / "promin" / "init.py"
        init_source.write_text(
            init_source.read_text(encoding="utf-8")
            + "\n\ndef _provider_path():\n    return None\n",
            encoding="utf-8",
        )

        report = verify_reconciliation_path_ownership(self.root)

        self.assertEqual(report["status"], "fail")
        self.assertFalse(report["pass_credit"])
        self.assertIn("forbidden provider identity helper", report["violations"][0])

    def test_no_degradation_required_owners_match_core(self) -> None:
        result = _required_predicates(self.root)
        self.assertTrue(result["complete"], result)
        self.assertEqual(result["missing_policies"], [])
        self.assertEqual(result["missing_acceptance_predicates"], [])
        self.assertEqual(result["missing_mutation_families"], [])

    def test_compiled_installed_observation_requires_base_runtime_and_sqlite(self) -> None:
        schema = json.loads(
            (self.root / "core" / "contracts.schema.json").read_text(encoding="utf-8")
        )
        matching: list[dict[str, object]] = []

        def visit(value: object) -> None:
            if isinstance(value, dict):
                required = value.get("required")
                properties = value.get("properties")
                if (
                    isinstance(required, list)
                    and isinstance(properties, dict)
                    and "observation_digest" in required
                    and "python" in required
                    and "platform" in required
                ):
                    matching.append(value)
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(schema)
        self.assertTrue(matching)
        for observation_schema in matching:
            required = observation_schema["required"]
            properties = observation_schema["properties"]
            self.assertIn("sqlite_version", required)
            python_schema = properties["python"]
            self.assertIn("base_executable", python_schema["required"])
            self.assertIn("base_executable_sha256", python_schema["required"])

    def test_compiled_retrieval_page_accepts_zero_effective_top_k_only_for_integer_boundary(
        self,
    ) -> None:
        schema = json.loads(
            (self.root / "core" / "contracts.schema.json").read_text(encoding="utf-8")
        )
        retrieval_schema = schema["$defs"]["RetrievalPage"]
        effective_top_k_schema = retrieval_schema["properties"]["effective_top_k"]
        validator = Draft202012Validator(
            {
                "$schema": schema["$schema"],
                "$defs": schema["$defs"],
                "$ref": "#/$defs/RetrievalPage",
            }
        )
        empty_miss = {
            "record_type": "RetrievalPage",
            "query": "no matching entity",
            "activation_digest": "a" * 64,
            "depth": 1,
            "ranking": "bm25-v1",
            "budget": {
                "max_bytes": 1024,
                "max_entities": 1,
                "max_relations": 0,
                "max_fanout_per_entity": 1,
                "top_k": 1,
            },
            "head_digest": None,
            "projection_digest": "b" * 64,
            "entities": [],
            "relations": [],
            "evidence": [],
            "truncated": False,
            "continuation": None,
            "continuation_version": 2,
            "stream_cursor": 0,
            "next_stream_cursor": 0,
            "effective_top_k": 0,
            "selected_seed_count": 0,
            "refinement_required": False,
            "refinement_hints": [],
            "unselected_matches_traversable": False,
            "selected_closure_complete": True,
            "silent_truncation": False,
            "projection_authoritative": False,
        }

        self.assertEqual(effective_top_k_schema["minimum"], 0)
        self.assertEqual(effective_top_k_schema["maximum"], 12)
        self.assertEqual(effective_top_k_schema["type"], "integer")
        validator.validate(empty_miss)
        for invalid in (-1, True, 13):
            with self.subTest(effective_top_k=invalid):
                candidate = dict(empty_miss, effective_top_k=invalid)
                self.assertFalse(validator.is_valid(candidate))

    def test_compiled_saturation_audit_accepts_only_current_fresh_state_shape(
        self,
    ) -> None:
        schema = json.loads(
            (self.root / "core" / "contracts.schema.json").read_text(encoding="utf-8")
        )
        audit_schema = schema["$defs"]["SaturationAudit"]
        validator = Draft202012Validator(
            {
                "$schema": schema["$schema"],
                "$defs": schema["$defs"],
                "$ref": "#/$defs/SaturationAudit",
            }
        )
        fresh_state = {
            "status": "created",
            "product_tree_scans": 0,
            "init_record_count": 5,
            "activation_digest": "a" * 64,
            "implementation_closure_digest": "b" * 64,
            "core_bundle_digest": "c" * 64,
            "preset_digest": "d" * 64,
            "semantic_state_reused": False,
            "product_tree_reused": True,
            "physical_corpus_recipe": {
                "sha256": "e" * 64,
                "bytes": 512,
                "file_count": 100_000,
            },
        }
        iteration_schema = audit_schema["properties"]["iterations"]["items"]
        focused_schema = iteration_schema["properties"][
            "focused_and_integration_tests"
        ]
        physical_schema = iteration_schema["properties"][
            "physical_runtime_saturation"
        ]
        focused = {field: None for field in focused_schema["required"]}
        physical = {field: None for field in physical_schema["required"]}
        physical["fresh_control_state"] = fresh_state
        physical["record_bytes"] = 1
        iteration = {field: None for field in iteration_schema["required"]}
        iteration["focused_and_integration_tests"] = focused
        iteration["physical_runtime_saturation"] = physical
        requirements_schema = audit_schema["properties"]["requirements"]
        requirements = {field: None for field in requirements_schema["required"]}
        requirements.update(
            {
                "fresh_control_state_per_iteration": True,
                "semantic_state_reused": False,
                "init_product_tree_scans": 0,
            }
        )
        digest = "f" * 64
        attestation_schema = schema["$defs"]["EvidenceProducerAttestation"]
        audit = {
            "record_type": "SaturationAudit",
            "status": "pass",
            "candidate_binding_digest": digest,
            "zero_new_iterations": 3,
            "new_findings": 0,
            "pass_credit": False,
            "artifact_binding": {},
            "families": ["fixture-family"],
            "collection": {
                "catalogue_digest": digest,
                "families_discovered": 1,
                "production_probes_discovered": 1,
            },
            "iterations": [
                json.loads(json.dumps(iteration)) for _index in range(3)
            ],
            "consecutive_full_zero_new": 3,
            "requirements": requirements,
            "predeclared_zero_new": False,
            "acceptance_pass": False,
            "product_acceptance_pass": False,
            "producer": {
                "tool_path": "tools/promin_saturation_audit.py",
                "tool_sha256": digest,
                "tool_version": "1.0.0",
            },
            "invocation": {
                "invocation_id": "saturation-audit:fixture",
                "operation": "saturation-audit",
                "arguments_digest": digest,
                "started_at": "2026-07-22T10:00:00Z",
                "completed_at": "2026-07-22T10:00:01Z",
                "exit_code": 0,
                "platform_binding_digest": digest,
            },
            "raw_artifact_manifest_digest": digest,
            "producer_attestation": {
                "record_type": "EvidenceProducerAttestation",
                "claim_domain": attestation_schema["properties"]["claim_domain"][
                    "const"
                ],
                "candidate_binding_digest": digest,
                "evidence_role": "saturation-audit",
                "evidence_record_type": "SaturationAudit",
                "platform": "windows",
                "invocation_id": "saturation-audit:fixture",
                "payload_digest": digest,
                "raw_artifact_manifest_digest": digest,
                "producer_id": "fixture-producer",
                "trust_root_id": "fixture-trust-root",
                "signature_provider_id": "cryptography-ed25519-v1",
                "key_id": "fixture-key",
                "public_key": "A" * 43 + "=",
                "nonce": "n" * 24,
                "signed_at": "2026-07-22T10:00:01Z",
                "signed_claim_digest": digest,
                "signature": "A" * 80,
            },
            "result_digest": digest,
        }
        errors = list(validator.iter_errors(audit))
        self.assertEqual(errors, [], [error.message for error in errors])

        missing_state = json.loads(json.dumps(audit))
        del missing_state["iterations"][0]["physical_runtime_saturation"][
            "fresh_control_state"
        ]
        self.assertTrue(list(validator.iter_errors(missing_state)))

        mutated_requirement = json.loads(json.dumps(audit))
        mutated_requirement["requirements"]["semantic_state_reused"] = True
        self.assertTrue(list(validator.iter_errors(mutated_requirement)))

    def test_compiled_saturation_evidence_rejects_semantic_corpus_reuse(
        self,
    ) -> None:
        schema = json.loads(
            (self.root / "core" / "contracts.schema.json").read_text(encoding="utf-8")
        )
        evidence_schema = schema["$defs"]["SaturationEvidence"]
        corpus_schema = evidence_schema["properties"]["physical"]["properties"][
            "explicit_semantic_corpus"
        ]
        validator = Draft202012Validator(corpus_schema)
        corpus = {field: None for field in corpus_schema["required"]}
        corpus.update(
            {
                "record_type": "SaturationSemanticCorpus",
                "harness_generated": True,
                "product_acceptance_credit": False,
                "reused": False,
                "search_fixture_reused": False,
                "physical_relation_fixture_reused": False,
                "search_fixture": {
                    field: None
                    for field in corpus_schema["properties"]["search_fixture"][
                        "required"
                    ]
                },
                "physical_relation_fixture": {
                    field: None
                    for field in corpus_schema["properties"][
                        "physical_relation_fixture"
                    ]["required"]
                },
            }
        )
        self.assertEqual(list(validator.iter_errors(corpus)), [])
        for field in (
            "reused",
            "search_fixture_reused",
            "physical_relation_fixture_reused",
        ):
            reused = json.loads(json.dumps(corpus))
            reused[field] = True
            self.assertTrue(list(validator.iter_errors(reused)), field)

    def test_compiled_saturation_projection_requires_exact_entity_contour(
        self,
    ) -> None:
        schema = json.loads(
            (self.root / "core" / "contracts.schema.json").read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(
            {
                "$schema": schema["$schema"],
                "$defs": schema["$defs"],
                "$ref": "#/$defs/SaturationEvidence/properties/projection",
            }
        )
        projection = {
            "database_bytes": 8_192,
            "elapsed_ms": 250.0,
            "entity_count": 101_604,
            "entity_type_counts": {
                "Artifact": 100_000,
                "Candidate": 1,
                "Grant": 4,
                "Task": 1_599,
            },
            "equal_semantic_digest": True,
            "implementation_closure_digest": "a" * 64,
            "initial_inventory_passes": 1,
            "initial_product_passes": 0,
            "inventory_integrity": True,
            "inventory_projection_amplification": 1.0,
            "projection_amplification": 2.0,
            "rebuild_inventory_passes": 1,
            "rebuild_product_passes": 0,
            "relation_count": 198_999,
            "semantic_digest": "b" * 64,
            "semantic_inflation": 3.0,
        }
        self.assertEqual(list(validator.iter_errors(projection)), [])

        missing_candidate = json.loads(json.dumps(projection))
        del missing_candidate["entity_type_counts"]["Candidate"]
        self.assertTrue(list(validator.iter_errors(missing_candidate)))

        extra_entity_type = json.loads(json.dumps(projection))
        extra_entity_type["entity_type_counts"]["Document"] = 1
        self.assertTrue(list(validator.iter_errors(extra_entity_type)))

        zero_candidate = json.loads(json.dumps(projection))
        zero_candidate["entity_type_counts"]["Candidate"] = 0
        self.assertTrue(list(validator.iter_errors(zero_candidate)))

        wrong_total = json.loads(json.dumps(projection))
        wrong_total["entity_count"] = 101_603
        self.assertTrue(list(validator.iter_errors(wrong_total)))

        wrong_relation_total = json.loads(json.dumps(projection))
        wrong_relation_total["relation_count"] = 198_998
        self.assertTrue(list(validator.iter_errors(wrong_relation_total)))

    def test_existing_pdf_verification_does_not_invoke_generator(self) -> None:
        (self.root / "tools" / "generate_human.py").write_text("raise RuntimeError('must not run')\n", encoding="utf-8")
        result = verify_human_documents(self.root)
        self.assertTrue(result["existing_pdf_verification"])
        self.assertFalse(result["rebuild_performed"])

    def test_existing_pdf_verification_reuses_only_freshly_hashed_pdf_summaries(self) -> None:
        from pypdf import PdfReader

        document = self.root / "human" / "promin_main_en.pdf"
        document.write_bytes(document.read_bytes() + b"\n")
        with mock.patch("pypdf.PdfReader", wraps=PdfReader) as reader:
            first = verify_human_documents(self.root)
            first_parse_count = reader.call_count
            second = verify_human_documents(self.root)

        self.assertGreaterEqual(first_parse_count, 1)
        self.assertEqual(reader.call_count, first_parse_count)
        self.assertEqual(first, second)

    def test_document_rebuild_requires_all_explicit_font_bindings(self) -> None:
        with self.assertRaises(ValidationFailure):
            verify_human_documents(self.root, rebuild=True)

    def test_core_drift_is_rejected(self) -> None:
        write_integrity(self.root)
        target = self.root / "core" / "semantic-model.json"
        target.write_bytes(target.read_bytes() + b" ")
        report = validate_tree(self.root)
        self.assertFalse(report.valid)
        self.assertIn("Core digest mismatch", report.errors[0])

    def test_forbidden_identity_in_content_is_rejected(self) -> None:
        forbidden = "agent" + "doc"
        (self.root / "bad.txt").write_text(forbidden, encoding="utf-8")
        with self.assertRaises(ValidationFailure):
            scan_distribution(self.root)

    def test_secret_bearing_filename_is_rejected(self) -> None:
        (self.root / ".env").write_text("TOKEN=not-a-real-value\n", encoding="utf-8")
        with self.assertRaises(ValidationFailure):
            scan_distribution(self.root)

    def test_external_standard_release_decision_is_rejected_from_package(self) -> None:
        (self.root / "standard-release-decision.json").write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValidationFailure, "must not be packaged"):
            scan_distribution(self.root)

    def test_deterministic_archive_and_clean_self_verification(self) -> None:
        first = self.base / "one.zip"
        second = self.base / "two.zip"
        first_result = build_archive(self.root, first, install_mode=None)
        second_result = build_archive(self.root, second, install_mode=None)
        self.assertTrue(first_result["candidate_only"])
        self.assertFalse(first_result["current_distribution_eligible"])
        self.assertFalse(first_result["product_acceptance_pass"])
        self.assertEqual(first_result["archive_sha256"], second_result["archive_sha256"])
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with zipfile.ZipFile(first) as archive:
            infos = archive.infolist()
            self.assertTrue(all(not info.is_dir() for info in infos))
            self.assertTrue(all(info.compress_type == ZIP_METHOD for info in infos))
            self.assertEqual(
                [info.filename for info in infos],
                sorted((info.filename for info in infos), key=lambda value: value.encode("utf-8")),
            )
            self.assertFalse(
                any(
                    part.casefold() in {"_work", "cache", ".cache", "__pycache__", ".pytest_cache"}
                    for info in infos
                    for part in Path(info.filename).parts
                )
            )
        result = verify_archive(
            first,
            install_mode="current-environment",
        )
        self.assertTrue(result["clean_extraction"])
        self.assertTrue(result["byte_deterministic"])
        self.assertEqual(result["archive_sha256"], result["second_build_sha256"])
        installability = result["tree"]["checks"]["installability"]
        distribution = distribution_identity(self.root)
        self.assertTrue(installability["verified"])
        self.assertEqual(installability["mode"], "current-environment")
        self.assertEqual(installability["runtime_dependency_source"], "current-environment")
        self.assertEqual(installability["environment"], "current-interpreter")
        self.assertFalse(installability["installation_performed"])
        self.assertFalse(installability["nested_venv_created"])
        self.assertFalse(installability["interpreter"]["nested_venv_created"])
        self.assertEqual(installability["python_distribution_version"], distribution["python_version"])
        self.assertTrue(
            {"cryptography", "jsonschema", "pypdf"}.issubset(
                {
                    name.casefold()
                    for name in installability["resolved_runtime_dependencies"]
                }
            )
        )
        self.assertTrue(installability["console_script"]["present"])
        self.assertFalse(installability["console_script"]["installed_wrapper_checked"])
        self.assertTrue(installability["console_script"]["source_module_invoked"])
        self.assertIsNone(installability["console_script"]["posix_execute_bits"])
        binding = result["artifact_binding"]
        self.assertEqual(binding["archive_sha256"], result["archive_sha256"])
        self.assertEqual(binding["version"], distribution["version"])
        self.assertEqual(binding["core_bundle_digest"], result["tree"]["checks"]["core"]["bundle_digest"])
        self.assertEqual(binding["selected_preset_sha256"], result["tree"]["checks"]["preset"]["sha256"])
        self.assertEqual(set(binding["tool_digests"]), {"tools/promin_package.py", "tools/promin_validate.py"})
        for field in (
            "archive_member_manifest_digest",
            "package_manifest_digest",
            "checksums_digest",
            "package_tool_digest",
            "validator_digest",
            "test_manifest_digest",
            "portable_implementation_closure_digest",
            "observed_environment_closure_digest",
        ):
            self.assertRegex(binding[field], r"^[0-9a-f]{64}$")
        candidate = result["candidate_binding"]
        self.assertEqual(candidate["record_type"], "StandardReleaseCandidateBinding")
        self.assertEqual(candidate["archive_sha256"], result["archive_sha256"])
        self.assertEqual(candidate["archive_bytes"], first.stat().st_size)
        self.assertRegex(candidate["candidate_binding_digest"], r"^[0-9a-f]{64}$")
        self.assertIsNone(result["evidence_manifest"])
        self.assertIsNone(result["standard_release_decision"])
        self.assertEqual(
            result["standard_distribution_status"]["distribution_status"],
            "candidate",
        )
        self.assertFalse(result["product_acceptance_pass"])

    def test_package_cli_does_not_create_transient_bytecode(self) -> None:
        archive = self.base / "cli.zip"
        candidate_binding = self.base / "cli-candidate-binding.json"
        environment = os.environ.copy()
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        if environment.get("PROMIN_INSTALLED_TEST_MODE") == "1":
            environment.pop("PYTHONPATH", None)
        else:
            environment["PYTHONPATH"] = str(self.root)
        result = subprocess.run(
            [
                sys.executable,
                str(self.root / "tools" / "promin_package.py"),
                "build",
                str(self.root),
                str(archive),
                "--candidate-binding-output",
                str(candidate_binding),
                "--install-mode",
                "none",
            ],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(candidate_binding.is_file())
        cli_result = json.loads(result.stdout)
        self.assertTrue(cli_result["candidate_only"])
        self.assertFalse(cli_result["current_distribution_eligible"])
        self.assertFalse(cli_result["product_acceptance_pass"])
        transient = [
            path
            for path in self.root.rglob("*")
            if path.name in {"__pycache__", ".pytest_cache"} or path.suffix in {".pyc", ".pyo"}
        ]
        self.assertEqual(transient, [])

    def test_evidence_cli_help_does_not_create_transient_bytecode(self) -> None:
        environment = os.environ.copy()
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        if environment.get("PROMIN_INSTALLED_TEST_MODE") == "1":
            environment.pop("PYTHONPATH", None)
        else:
            environment["PYTHONPATH"] = str(self.root)
        for name in (
            "promin_no_degradation.py",
            "promin_saturation.py",
            "promin_saturation_audit.py",
        ):
            result = subprocess.run(
                [sys.executable, str(self.root / "tools" / name), "--help"],
                cwd=self.root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        transient = [
            path
            for path in self.root.rglob("*")
            if path.name in {"__pycache__", ".pytest_cache"} or path.suffix in {".pyc", ".pyo"}
        ]
        self.assertEqual(transient, [])

    def test_dependency_modes_build_truthful_pip_arguments(self) -> None:
        source = self.base / "source"
        wheelhouse = self.base / "wheelhouse"
        wheelhouse.mkdir()
        (wheelhouse / "dependency.whl").write_bytes(b"fixture")
        current, current_details = _pip_install_arguments(source, "current-environment", None)
        self.assertEqual(current, [])
        self.assertEqual(current_details["environment"], "current-interpreter")
        self.assertFalse(current_details["installation_performed"])
        self.assertFalse(current_details["nested_venv_created"])
        self.assertEqual(current_details["runtime_dependency_source"], "current-environment")
        offline, offline_details = _pip_install_arguments(source, "offline-wheelhouse", wheelhouse)
        self.assertIn("--no-index", offline)
        self.assertIn("--find-links", offline)
        self.assertNotIn("--no-deps", offline)
        self.assertTrue(offline_details["network_disabled"])
        self.assertEqual(offline_details["wheelhouse_binding"]["file_count"], 1)
        online, online_details = _pip_install_arguments(source, "online-clean", None)
        self.assertNotIn("--no-deps", online)
        self.assertNotIn("--no-index", online)
        self.assertEqual(online_details["environment"], "clean-venv")

    def test_current_environment_does_not_create_a_nested_venv(self) -> None:
        write_integrity(self.root)
        with mock.patch("promin_validate._create_clean_venv", side_effect=AssertionError("nested venv")):
            result = verify_installability(self.root, mode="current-environment")
        self.assertTrue(result["verified"])
        self.assertEqual(result["environment"], "current-interpreter")
        self.assertFalse(result["interpreter"]["nested_venv_created"])

    def test_required_test_skip_is_fail_closed(self) -> None:
        clean = {"tests": 10, "failures": 0, "errors": 0, "skipped": 0}
        skipped = {**clean, "skipped": 1}
        self.assertTrue(_required_test_passed(0, clean))
        self.assertFalse(_required_test_passed(0, skipped))
        self.assertFalse(_required_test_passed(5, clean))
        self.assertFalse(_required_test_passed(0, {**clean, "tests": 0}))

    def test_no_degradation_subprocess_is_bounded_and_timeout_killed(self) -> None:
        environment = os.environ.copy()
        stdout_path = self.base / "bounded.stdout"
        stderr_path = self.base / "bounded.stderr"
        captured = _run_bounded(
            [sys.executable, "-c", "import sys;sys.stdout.write('x'*100000)"],
            cwd=self.root,
            environment=environment,
            timeout_seconds=10,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )
        self.assertEqual(captured["returncode"], 0)
        self.assertFalse(captured["timed_out"])
        self.assertEqual(captured["process_group_cleanup"], "normal-exit")
        self.assertEqual(captured["stdout"]["bytes"], 100000)
        self.assertTrue(captured["stdout"]["truncated"])
        self.assertEqual(captured["stdout"]["selection"], "tail")
        self.assertLessEqual(len(captured["stdout"]["text"].encode("utf-8")), 64 * 1024)

        timed_out = _run_bounded(
            [sys.executable, "-c", "import time;time.sleep(30)"],
            cwd=self.root,
            environment=environment,
            timeout_seconds=1,
            stdout_path=self.base / "timeout.stdout",
            stderr_path=self.base / "timeout.stderr",
        )
        self.assertTrue(timed_out["timed_out"])
        self.assertEqual(timed_out["process_group_cleanup"], "process-group-terminated")
        self.assertNotEqual(timed_out["returncode"], 0)

    def test_clean_install_deadline_bounds_creation_and_descendant_processes(self) -> None:
        deadline = time.monotonic() + 30
        completed = subprocess.CompletedProcess(["python", "-m", "venv"], 0, "", "")
        bounded = mock.Mock(return_value=completed)
        with mock.patch.dict(
            _create_clean_venv.__globals__,
            {"_run_capture_with_deadline": bounded},
        ):
            _create_clean_venv(
                self.base / "deadline-venv",
                os.environ.copy(),
                deadline_monotonic=deadline,
            )
        self.assertEqual(bounded.call_args.kwargs["deadline_monotonic"], deadline)
        self.assertEqual(bounded.call_args.kwargs["phase"], "clean environment creation")

        pid_path = self.base / "deadline-child.pid"
        child_code = "import time;time.sleep(30)"
        parent_code = (
            "import pathlib,subprocess,sys,time;"
            f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]);"
            f"pathlib.Path({str(pid_path)!r}).write_text(str(p.pid));"
            "time.sleep(30)"
        )
        started = time.monotonic()
        with self.assertRaisesRegex(ValidationFailure, "total execution deadline"):
            _run_capture_with_deadline(
                [sys.executable, "-c", parent_code],
                cwd=self.base,
                environment=os.environ.copy(),
                deadline_monotonic=time.monotonic() + 1,
                phase="deadline process-tree fixture",
            )
        self.assertLess(time.monotonic() - started, 15)
        self.assertTrue(pid_path.is_file())
        child_pid = int(pid_path.read_text(encoding="utf-8"))

        for _ in range(50):
            if not process_is_running(child_pid):
                break
            time.sleep(0.1)
        self.assertFalse(process_is_running(child_pid))

    def test_parent_exit_cannot_leave_an_uncontained_descendant(self) -> None:
        def parent_command(pid_path: Path) -> list[str]:
            child_code = "import time;time.sleep(30)"
            parent_code = (
                "import pathlib,subprocess,sys;"
                "p=subprocess.Popen([sys.executable,'-c',"
                f"{child_code!r}],stdin=subprocess.DEVNULL,"
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
                f"pathlib.Path({str(pid_path)!r}).write_text(str(p.pid))"
            )
            return [sys.executable, "-c", parent_code]

        validation_pid = self.base / "validation-orphan.pid"
        completed = _run_capture_with_deadline(
            parent_command(validation_pid),
            cwd=self.base,
            environment=os.environ.copy(),
            deadline_monotonic=time.monotonic() + 10,
            phase="parent-exit containment fixture",
        )
        self.assertEqual(completed.returncode, 0)
        validation_child = int(validation_pid.read_text(encoding="utf-8"))

        no_degradation_pid = self.base / "no-degradation-orphan.pid"
        bounded = _run_bounded(
            parent_command(no_degradation_pid),
            cwd=self.base,
            environment=os.environ.copy(),
            timeout_seconds=10,
            stdout_path=self.base / "parent-exit.stdout",
            stderr_path=self.base / "parent-exit.stderr",
        )
        self.assertEqual(bounded["returncode"], 0)
        self.assertFalse(bounded["timed_out"])
        self.assertEqual(
            bounded["process_group_cleanup"],
            "process-group-terminated",
        )
        no_degradation_child = int(no_degradation_pid.read_text(encoding="utf-8"))

        for child_pid in (validation_child, no_degradation_child):
            for _ in range(50):
                if not process_is_running(child_pid):
                    break
                time.sleep(0.1)
            self.assertFalse(process_is_running(child_pid))

    def test_required_test_install_receives_the_total_deadline(self) -> None:
        deadline = time.monotonic() + 10
        with mock.patch(
            "promin_no_degradation.create_clean_installed_environment",
            side_effect=ValidationFailure("fixture install deadline"),
        ) as installed:
            with self.assertRaisesRegex(ValidationFailure, "fixture install deadline"):
                _run_required_tests(
                    self.root,
                    install_mode="offline-wheelhouse",
                    wheelhouse=self.base / "wheelhouse",
                    timeout_seconds=5,
                    deadline_monotonic=deadline,
                )
        self.assertEqual(installed.call_args.kwargs["deadline_monotonic"], deadline)

    def test_no_degradation_failure_replaces_stale_pass_output(self) -> None:
        output = self.base / "no-degradation-current.json"
        write_json(output, {"status": "pass", "passed": True})
        with mock.patch(
            "promin_no_degradation.run",
            side_effect=RuntimeError("fixture total deadline"),
        ):
            returncode = no_degradation_main(
                [
                    str(self.root),
                    "--archive",
                    str(self.base / "candidate.zip"),
                    "--wheelhouse",
                    str(self.base / "wheelhouse"),
                    "--output",
                    str(output),
                ]
            )
        self.assertEqual(returncode, 2)
        published = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(published["status"], "rejected")
        self.assertFalse(published["passed"])
        self.assertFalse(published["pass_credit"])

    def test_external_evidence_ingress_rejects_unicode_depth_and_numeric_attacks(self) -> None:
        collision = self.base / "nfc-collision.json"
        collision.write_bytes(b'{"\\u00e9":1,"e\\u0301":2}')
        with self.assertRaisesRegex(EvidenceError, "NFC"):
            load_external_json_stable(collision)

        casefold = self.base / "casefold-collision.json"
        casefold.write_bytes(b'{"Alpha":1,"alpha":2}')
        with self.assertRaisesRegex(EvidenceError, "casefold"):
            load_external_json_stable(casefold)

        deep = self.base / "deep.json"
        deep.write_text('{"v":' * 65 + "0" + "}" * 65, encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "nesting"):
            load_external_json_stable(deep)

        numeric = self.base / "numeric.json"
        numeric.write_text('{"v":' + "9" * 257 + "}", encoding="utf-8")
        with self.assertRaisesRegex(EvidenceError, "numeric"):
            load_external_json_stable(numeric)

        oversized = self.base / "oversized.json"
        with oversized.open("wb") as handle:
            handle.truncate(16 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(EvidenceError, "bounded regular file"):
            load_external_json_stable(oversized)

    def test_external_evidence_hash_and_parse_share_one_stable_read(self) -> None:
        path = self.base / "changing.json"
        path.write_bytes(b'{"status":"pass"}')
        original_read = os.read
        changed = False

        def mutate_after_read(descriptor: int, size: int) -> bytes:
            nonlocal changed
            payload = original_read(descriptor, size)
            if payload and not changed:
                changed = True
                with path.open("ab") as handle:
                    handle.write(b" ")
                    handle.flush()
                    os.fsync(handle.fileno())
            return payload

        with mock.patch("promin.evidence.os.read", side_effect=mutate_after_read):
            with self.assertRaisesRegex(EvidenceError, "changed during"):
                load_external_json_stable(path)

    def test_external_evidence_root_handle_rejects_parent_and_root_links(self) -> None:
        evidence_root = self.base / "handle-evidence-root"
        evidence_root.mkdir()
        outside = self.base / "handle-evidence-outside"
        outside.mkdir()
        write_json(outside / "evidence.json", {"source": "outside"})

        parent_link = evidence_root / "linked-parent"
        create_directory_link(parent_link, outside)
        try:
            with self.assertRaisesRegex(EvidenceError, "reparse|descriptor walk"):
                load_external_json_stable(
                    parent_link / "evidence.json",
                    root=evidence_root,
                )
        finally:
            remove_directory_link(parent_link)

        substituted_root = self.base / "handle-substituted-root"
        create_directory_link(substituted_root, outside)
        try:
            with self.assertRaisesRegex(EvidenceError, "reparse|descriptor walk"):
                load_external_json_stable(
                    substituted_root / "evidence.json",
                    root=substituted_root,
                )
        finally:
            remove_directory_link(substituted_root)

    def test_fabricated_release_evidence_is_rejected_before_manifest_creation(self) -> None:
        archive = self.base / "candidate.zip"
        candidate_binding_path = self.base / "candidate-binding.json"
        built = build_archive(
            self.root,
            archive,
            install_mode=None,
            candidate_binding_output=candidate_binding_path,
        )
        candidate_bytes = archive.read_bytes()
        self.assertTrue(built["candidate_only"])
        self.assertFalse(built["current_distribution_eligible"])
        self.assertFalse(built["product_acceptance_pass"])
        self.assertNotIn("published", built)
        self.assertNotIn("implementation_closure_manifest", built)
        self.assertEqual(
            built["archive_sha256"],
            json.loads(candidate_binding_path.read_text(encoding="utf-8"))[
                "archive_sha256"
            ],
        )

        evidence_root, evidence_plan_path = create_fabricated_standard_evidence(
            self.base,
            candidate_binding_path,
        )
        trust_path = self.base / "fabricated-evidence-trust.json"
        write_json(
            trust_path,
            {
                "record_type": "StandardReleaseTrustConfiguration",
                "trust_root_id": "fixture-trust-root",
                "signature_provider_id": "cryptography-ed25519-v1",
                "algorithm": "Ed25519",
                "keys": [
                    {
                        "key_id": "fixture-evidence-key",
                        "subject_id": "fixture-evidence-producer",
                        "capabilities": ["evidence.produce"],
                        "evidence_roles": sorted(FABRICATED_EVIDENCE_ROLES),
                        "platforms": ["linux", "windows"],
                        "public_key": base64.b64encode(bytes(32)).decode("ascii"),
                        "not_before": "2026-01-01T00:00:00Z",
                        "not_after": "2027-01-01T00:00:00Z",
                        "revoked": False,
                    }
                ],
            },
        )
        manifest_path = self.base / "fabricated-evidence-manifest.json"
        with self.assertRaisesRegex(
            ValidationFailure,
            "pinned SHA-256",
        ):
            build_evidence_manifest(
                archive,
                candidate_binding_path,
                evidence_root,
                evidence_plan_path,
                trust_path,
                manifest_path,
                expected_trust_root_sha256="0" * 64,
            )
        with self.assertRaisesRegex(
            EvidenceError,
            "exact PlatformVerificationResult schema|release evidence",
        ):
            build_evidence_manifest(
                archive,
                candidate_binding_path,
                evidence_root,
                evidence_plan_path,
                trust_path,
                manifest_path,
                expected_trust_root_sha256=hashlib.sha256(
                    trust_path.read_bytes()
                ).hexdigest(),
            )
        self.assertFalse(manifest_path.exists())
        self.assertEqual(archive.read_bytes(), candidate_bytes)

    def test_offline_mode_requires_real_wheelhouse(self) -> None:
        with self.assertRaises(ValidationFailure):
            _pip_install_arguments(self.base / "source", "offline-wheelhouse", None)

    def test_platform_evidence_uses_only_online_clean_compatibility_lane(self) -> None:
        for mode, wheelhouse in (
            ("current-environment", None),
            ("offline-wheelhouse", self.base),
        ):
            with self.subTest(mode=mode), self.assertRaisesRegex(
                ValidationFailure, "online-clean compatibility lane"
            ):
                verify_platform(
                    self.base / "missing.zip",
                    candidate_binding=self.base / "missing-binding.json",
                    install_mode=mode,
                    wheelhouse=wheelhouse,
                )

    def test_installed_observation_reads_version_from_canonical_source_root(self) -> None:
        """The isolated installation cwd intentionally has no canonical source tree."""

        observation = {"promin": {"version": "1.0.0-alpha.4"}}
        isolated_cwd = self.base / "isolated-install-cwd"
        isolated_cwd.mkdir()
        self.assertNotEqual(isolated_cwd.resolve(), self.root.resolve())
        self.assertNotIn(self.root.resolve(), isolated_cwd.resolve().parents)
        python = self.base / "venv" / "python.exe"
        executable = self.base / "venv" / "promin.exe"
        capture = mock.create_autospec(
            _observe_installed_environment.__globals__["_run_capture_with_deadline"],
            return_value=subprocess.CompletedProcess([], 0, json.dumps(observation), ""),
        )
        canonical_version = mock.create_autospec(
            _observe_installed_environment.__globals__["_canonical_standard_version"],
            return_value="1.0.0-alpha.4",
        )
        # Mutation fixtures may replace sys.modules['promin_validate'] with a
        # package-local module. Patch this function's lexical globals instead
        # of that mutable registry entry so no nested process can escape.
        with mock.patch.dict(
            _observe_installed_environment.__globals__,
            {
                "_run_capture_with_deadline": capture,
                "_canonical_standard_version": canonical_version,
            },
        ):
            result = _observe_installed_environment(
                python=python,
                executable=executable,
                cwd=isolated_cwd,
                canonical_root=self.root,
                environment={},
                pip_report_paths=(),
            )

        self.assertEqual(result["observation"], observation)
        self.assertEqual(
            result["pip_report"],
            {
                "reports": [],
                "report_count": 0,
                "artifact_digest": hashlib.sha256(canonical_bytes([])).hexdigest(),
            },
        )
        capture.assert_called_once_with(
            [
                str(python),
                "-I",
                "-B",
                "-c",
                _observe_installed_environment.__globals__["_INSTALLED_ENVIRONMENT_PROBE"],
                str(executable),
            ],
            cwd=isolated_cwd,
            environment={},
            deadline_monotonic=None,
            phase="installed environment observation",
        )
        canonical_version.assert_called_once_with(self.root)

    def test_archive_traversal_is_rejected(self) -> None:
        archive_path = self.base / "traversal.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            info = zipfile.ZipInfo("promin/../escape.txt", (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = ZIP_METHOD
            archive.writestr(info, b"x")
        with self.assertRaises(ValidationFailure):
            verify_archive(archive_path)

    def test_archive_directory_entry_is_rejected(self) -> None:
        archive_path = self.base / "directory-entry.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            info = zipfile.ZipInfo("promin/", (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFDIR | 0o755) << 16
            info.compress_type = ZIP_METHOD
            archive.writestr(info, b"")
        with self.assertRaisesRegex(ValidationFailure, "directory ZIP entries"):
            verify_archive(archive_path)

    def test_archive_noncanonical_compression_is_rejected(self) -> None:
        archive_path = self.base / "noncanonical-compression.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            info = zipfile.ZipInfo("promin/README.md", (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, b"x")
        with self.assertRaisesRegex(ValidationFailure, "metadata is not deterministic"):
            verify_archive(archive_path)

    def test_archive_unmanifested_payload_is_rejected(self) -> None:
        archive_path = self.base / "unmanifested.zip"
        build_archive(
            self.root,
            archive_path,
            install_mode=None,
        )
        with zipfile.ZipFile(archive_path, "a") as archive:
            info = zipfile.ZipInfo("promin/zz-unmanifested.txt", (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = ZIP_METHOD
            archive.writestr(info, b"unmanifested\n")
        with self.assertRaisesRegex(
            ValidationFailure,
            "canonical archive member inventory mismatch",
        ):
            verify_archive(
                archive_path,
                install_mode=None,
            )

    def test_archive_missing_canonical_member_is_rejected(self) -> None:
        archive_path = self.base / "complete.zip"
        incomplete_path = self.base / "missing-member.zip"
        build_archive(
            self.root,
            archive_path,
            install_mode=None,
        )
        with zipfile.ZipFile(archive_path, "r") as source, zipfile.ZipFile(
            incomplete_path,
            "w",
        ) as destination:
            for info in source.infolist():
                if info.filename != "promin/LICENSE":
                    destination.writestr(
                        info,
                        source.read(info),
                        compress_type=info.compress_type,
                    )
        with self.assertRaisesRegex(
            ValidationFailure,
            r"canonical archive member inventory mismatch: .*promin/LICENSE",
        ):
            verify_archive(
                incomplete_path,
                install_mode=None,
            )

    def test_work_and_cache_directories_are_rejected(self) -> None:
        for name in ("_work", "cache", ".cache", "build", "dist"):
            with self.subTest(name=name):
                candidate = self.base / name.replace(".", "dot") / "promin"
                shutil.copytree(self.template, candidate)
                transient = candidate / name
                transient.mkdir()
                (transient / "payload.txt").write_text("generated\n", encoding="utf-8")
                with self.assertRaisesRegex(ValidationFailure, "transient directory"):
                    scan_distribution(candidate)

    def test_archive_casefold_collision_is_rejected(self) -> None:
        archive_path = self.base / "collision.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            for name in ("promin/A.txt", "promin/a.txt"):
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                info.compress_type = ZIP_METHOD
                archive.writestr(info, b"x")
        with self.assertRaises(ValidationFailure):
            verify_archive(archive_path)

    def test_archive_symlink_metadata_is_rejected(self) -> None:
        archive_path = self.base / "symlink.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            info = zipfile.ZipInfo("promin/link", (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            info.compress_type = ZIP_METHOD
            archive.writestr(info, b"README.md")
        with self.assertRaises(ValidationFailure):
            verify_archive(archive_path)

    def test_archive_uppercase_root_is_rejected(self) -> None:
        archive_path = self.base / "uppercase.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            info = zipfile.ZipInfo("Promin/README.md", (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = ZIP_METHOD
            archive.writestr(info, b"x")
        with self.assertRaises(ValidationFailure):
            verify_archive(archive_path)

    def test_symlink_or_windows_junction_is_rejected_without_skip(self) -> None:
        target = self.base / "reparse-target"
        target.mkdir()
        (target / "payload.txt").write_text("outside package\n", encoding="utf-8")
        link = self.root / "linked-directory"
        if os.name == "nt":
            created = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                created.returncode,
                0,
                msg=f"junction creation failed: {created.stdout}{created.stderr}",
            )
        else:
            os.symlink(target, link, target_is_directory=True)
        try:
            with self.assertRaisesRegex(ValidationFailure, "symlink|reparse"):
                scan_distribution(self.root)
        finally:
            if link.exists() or link.is_symlink():
                os.rmdir(link) if os.name == "nt" else link.unlink()


if __name__ == "__main__":
    unittest.main()
