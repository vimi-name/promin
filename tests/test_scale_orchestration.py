from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
TOOLS = PACKAGE_ROOT / "tools"
for entry in (str(PACKAGE_ROOT), str(TOOLS)):
    if entry in sys.path:
        sys.path.remove(entry)
if os.environ.get("PROMIN_INSTALLED_TEST_MODE") != "1":
    sys.path.insert(0, str(PACKAGE_ROOT))
sys.path.insert(1, str(TOOLS))

from promin.authority import canonical_digest
from promin.canonical import canonical_bytes
from promin.evidence import (
    EvidenceError,
    _SATURATION_EVIDENCE_FIELDS,
    _validate_release_platform_binding,
    _validate_saturation_audit_fresh_control_state,
    _validate_saturation_audit_fresh_requirements,
    _validate_saturation_fresh_semantic_corpus,
    _validate_saturation_operation_metrics,
    _validate_saturation_runtime_bindings,
    release_evidence_invocation,
    validate_saturation_evidence,
)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


no_degradation = _load(
    "promin_scale_no_degradation",
    TOOLS / "promin_no_degradation.py",
)
saturation_audit = _load(
    "promin_scale_saturation_audit",
    TOOLS / "promin_saturation_audit.py",
)
saturation = _load(
    "promin_scale_runtime",
    TOOLS / "promin_saturation.py",
)


class ScaleOrchestrationTests(unittest.TestCase):
    @staticmethod
    def _exact_saturation_evidence_fixture() -> tuple[dict, dict]:
        corpus = {
            "record_type": "SaturationSemanticCorpus",
            "generation": "explicit-authorized-command-events",
            "harness_generated": True,
            "product_acceptance_credit": False,
            "task_count": 1_599,
            "relation_count": 198_999,
            "depths": list(range(1, 13)),
            "high_fanout": 16,
            "conflicting_exact_id_text": True,
            "search_fixture": {
                "task_count": 32,
                "relation_count": 28,
                "depths": list(range(1, 13)),
                "high_fanout": 16,
            },
            "physical_relation_fixture": {
                "task_count": 1_567,
                "relation_count": 198_971,
                "relation_kind": "READS",
                "target_type": "Artifact",
                "artifact_target_count": 100_000,
                "artifact_target_coverage": 1.0,
                "relations_per_atomic_batch_max": 127,
            },
            "reused": False,
            "search_fixture_reused": False,
            "physical_relation_fixture_reused": False,
        }
        semantic_ingestion = {
            "commit_count": 1_604,
            "p95_ms": 2.0,
            "p99_ms": 3.0,
            "bytes_per_changed_record": 4.0,
            "checkpoint_count": 5,
            "checkpoint_writes": 2,
            "elapsed_seconds": 6.0,
        }
        query_mix = {
            "broad": 60,
            "content-high-cardinality": 60,
            "content-probe": 60,
            "exact-artifact": 60,
            "exact-semantic": 60,
            "forced-continuation": 120,
            "hostile-content": 60,
            "hostile-exact": 60,
            "miss": 60,
        }
        search = {
            "actual_runtime_queries": 600,
            "query_mix": query_mix,
            "depth_counts": {str(depth): 1 for depth in range(1, 13)},
            "depth_min": 1,
            "depth_max": 12,
            "silent_truncations": 0,
            "continuation_union_completeness": 1.0,
            "selected_closure_union_completeness": 1.0,
            "maximum_continuation_token_bytes": 256,
            "continuation_state": {"maximum_bytes": 16_384},
            "continuation_token_overhead_at_most_10_percent": True,
            "broad_query_refinement_required": True,
            "high_cardinality_terms_verified": True,
            "content_search_verified": True,
            "miss_behavior_verified": True,
            "hostile_proxy_content_verified": True,
            "exact_artifact_search_verified": True,
            "forced_union_matches": 1,
            "forced_continuation_chains": 1,
            "runtime_query_budget": {"queries": 600},
        }
        observed = {
            "p50_ms": 1.0,
            "p95_ms": 2.0,
            "p99_ms": 3.0,
            "peak_rss_bytes": 4_096,
            "database_bytes": 8_192,
            "projection_amplification": 2.0,
            "semantic_inflation": 3.0,
            "commit_p95_ms": 2.0,
            "commit_p99_ms": 3.0,
            "commit_bytes_per_changed_record": 4.0,
            "runtime_checkpoint_count": 5,
            "runtime_checkpoint_writes": 2,
            "semantic_ingestion_seconds": 6.0,
        }
        thresholds = {
            "p50_ms_max": 1.0,
            "p95_ms_max": 2.0,
            "p99_ms_max": 3.0,
            "peak_rss_bytes_max": 4_096,
            "database_bytes_max": 8_192,
            "projection_amplification_max": 2.0,
            "semantic_inflation_max": 3.0,
            "commit_p95_ms_max": 2.0,
            "commit_p99_ms_max": 3.0,
            "commit_bytes_per_changed_record_max": 4.0,
            "runtime_checkpoint_count_max": 5,
            "semantic_ingestion_seconds_max": 6.0,
        }
        performance_predicates = {
            "p50_within_profile": True,
            "p95_within_profile": True,
            "p99_within_profile": True,
            "peak_rss_within_profile": True,
            "database_within_profile": True,
            "projection_amplification_within_profile": True,
            "semantic_inflation_within_profile": True,
            "commit_p95_within_profile": True,
            "commit_p99_within_profile": True,
            "commit_bytes_per_changed_record_within_profile": True,
            "runtime_checkpoint_count_within_profile": True,
            "semantic_ingestion_within_profile": True,
        }
        contract_predicates = {
            "broad_query_refinement_required": True,
            "content_search_verified": True,
            "continuation_state_bytes_at_most_16384": True,
            "continuation_token_bytes_at_most_256": True,
            "continuation_token_overhead_at_most_10_percent": True,
            "continuation_union_complete": True,
            "core_valid_relations_exact": True,
            "exact_artifact_binding_unchanged": True,
            "exact_artifact_search_verified": True,
            "high_cardinality_terms_verified": True,
            "hostile_proxy_content_verified": True,
            "inventory_incremental_memory_amplification_at_most_32": True,
            "inventory_passes_exact": True,
            "miss_behavior_verified": True,
            "mixed_query_classes_complete": True,
            "physical_relation_artifact_coverage_complete": True,
            "raw_file_proxy_ratio_exact": True,
            "rebuild_digest_equal": True,
            "rebuild_product_passes_zero": True,
            "runtime_depths_1_through_12": True,
            "runtime_queries_exact": True,
            "runtime_query_budget_bounded": True,
            "selected_closure_union_complete": True,
            "semantic_commit_count_exact": True,
            "silent_truncations_zero": True,
            "synthetic_task_ratio_zero": True,
        }
        verification = {field: None for field in _SATURATION_EVIDENCE_FIELDS}
        verification.update(
            {
                "record_type": "SaturationEvidence",
                "status": "pass",
                "candidate_binding_digest": "c" * 64,
                "artifact_binding": {
                    "platform": {"binding_digest": "sha256:" + "a" * 64}
                },
                "invocation": {"platform_binding_digest": "a" * 64},
                "artifact_binding_unchanged": True,
                "physical_files": 100_000,
                "core_valid_relations": 198_999,
                "runtime_queries": 600,
                "silent_truncations": 0,
                "selected_closure_union_completeness": 1.0,
                "memory_amplification_at_most_32": True,
                "core_valid_relations_exact_198999": True,
                "broad_query_refinement_required": True,
                "high_cardinality_terms_verified": True,
                "content_search_verified": True,
                "miss_behavior_verified": True,
                "hostile_proxy_content_verified": True,
                "exact_artifact_search_verified": True,
                "mixed_query_classes_complete": True,
                "continuation_token_bytes_at_most_256": True,
                "continuation_state_bytes_at_most_16384": True,
                "continuation_token_overhead_at_most_10_percent": True,
                "pass_credit": False,
                "acceptance_pass": False,
                "product_acceptance_pass": False,
                "public_release_approved": False,
                "physical": {
                    "files": 100_000,
                    "raw_files": 100_000,
                    "raw_file_proxies": 100_000,
                    "semantic_proxies": 100_000,
                    "raw_file_proxy_ratio": 1.0,
                    "synthetic_task_count": 0,
                    "synthetic_task_ratio": 0.0,
                    "relations": 198_999,
                    "vcs_tree_files": 100_000,
                    "explicit_semantic_corpus": corpus,
                },
                "inventory": {"entries": 100_000, "passes": 1},
                "projection": {
                    "entity_count": 101_604,
                    "entity_type_counts": {
                        "Artifact": 100_000,
                        "Task": 1_599,
                        "Grant": 4,
                        "Candidate": 1,
                    },
                    "relation_count": 198_999,
                    "initial_inventory_passes": 1,
                    "initial_product_passes": 0,
                    "rebuild_inventory_passes": 1,
                    "rebuild_product_passes": 0,
                    "equal_semantic_digest": True,
                },
                "search": search,
                "resources": {"peak_rss_bytes": 4_096},
                "performance": {
                    "observed": observed,
                    "thresholds": thresholds,
                    "predicates": performance_predicates,
                    "all_within_profile": True,
                },
                "contract_predicates": contract_predicates,
            }
        )
        raw = {
            "operation": {"semantic_ingestion": semantic_ingestion},
            "memory_within_threshold": True,
        }
        return verification, raw

    @staticmethod
    def _validate_exact_saturation_fixture(
        verification: dict,
        raw: dict,
        *,
        require_pass: bool = True,
    ) -> dict:
        candidate = {"candidate_binding_digest": "c" * 64}
        with (
            mock.patch(
                "promin.evidence.validate_standard_release_candidate_binding",
                return_value=candidate,
            ),
            mock.patch("promin.evidence._validate_release_evidence_schema"),
            mock.patch("promin.evidence._validate_exact_artifact_binding"),
            mock.patch("promin.evidence._validate_release_evidence_envelope"),
            mock.patch(
                "promin.evidence._validate_saturation_raw_artifacts",
                return_value=raw,
            ),
            mock.patch("promin.evidence._validate_saturation_runtime_bindings"),
        ):
            return validate_saturation_evidence(
                verification,
                candidate_binding={},
                source_path=Path("saturation-result.json"),
                evidence_root=Path("evidence"),
                require_pass=require_pass,
            )

    @staticmethod
    def _fresh_state_fixture():
        class FakeSaturationTool:
            class SaturationError(RuntimeError):
                pass

            _PHYSICAL_CORPUS_RECIPE = "representative-operational-text-v3"
            _REPRESENTATIVE_PHRASES = tuple(str(index) for index in range(8))

            @staticmethod
            def _make_saturation_init_plan(workspace: Path):
                return {"project_root": str(workspace)}

            @staticmethod
            def _validate_saturation_workspace(workspace: Path, *, status: str):
                assert (workspace / ".promin" / "init-generation.txt").is_file()
                return {
                    "status": status,
                    "product_tree_scans": 0,
                    "init_record_count": 5,
                    "activation_digest": "a" * 64,
                    "implementation_closure_digest": "b" * 64,
                }

            @staticmethod
            def _verify_physical_product_recipe(workspace: Path, files: int):
                value = json.loads(
                    (workspace / ".promin" / "state" / "physical-corpus.json").read_text(
                        encoding="utf-8"
                    )
                )
                if value.get("record_type") != "PhysicalCorpusRecipe" or value.get(
                    "file_count"
                ) != files:
                    raise FakeSaturationTool.SaturationError("invalid recipe")

        return FakeSaturationTool()

    def test_focused_commands_exclude_scale_by_marker(self) -> None:
        focused = saturation_audit._pytest_command()
        marker_index = focused.index("-m", 3) + 1
        self.assertEqual(focused[marker_index], "not scale")

        root = Path("package")
        no_degradation_focused = no_degradation._focused_pytest_command(
            root,
            Path("focused.xml"),
            "not platform_optional",
        )
        marker_index = no_degradation_focused.index("-m", 4) + 1
        self.assertEqual(no_degradation_focused[marker_index], "not scale")

    def test_creditable_no_degradation_is_exactly_offline_and_hash_bound(self) -> None:
        for install_mode, wheelhouse in (
            ("online-clean", None),
            ("offline-wheelhouse", None),
        ):
            with self.subTest(install_mode=install_mode):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "explicit hash-bound offline wheelhouse",
                ):
                    no_degradation.run(
                        PACKAGE_ROOT,
                        "test_*.py",
                        archive=Path("unused.zip"),
                        install_mode=install_mode,
                        wheelhouse=wheelhouse,
                    )

    def test_saturation_init_is_explicit_and_project_bound(self) -> None:
        authority = saturation._saturation_authority_plan()
        self.assertEqual(
            authority["roots"][0]["scope"],
            [
                {
                    "kind": "project",
                    "value": "promin-physical-saturation",
                }
            ],
        )
        source = inspect.getsource(saturation._make_saturation_init_plan)
        for explicit_input in (
            "standard_bundle=",
            "preset_path=",
            "project_root=",
            "project_plan=",
            "standards_plan=",
            "technologies_plan=",
            "licenses_plan=",
            "authority_plan=",
        ):
            self.assertIn(explicit_input, source)
        self.assertNotIn('plan["plans"]', source)

    def test_raw_operation_metrics_require_valid_semantic_ingestion(self) -> None:
        observation = {
            "sequence": 1,
            "phase": "semantic-corpus",
            "command_id": "command:semantic:1",
            "batch_digest": "a" * 64,
            "duration_ms": 10.0,
            "changed_records": 2,
            "physical_payload_bytes": 20,
            "bytes_per_changed_record": 10.0,
            "checkpoint_written": False,
            "checkpoint_count": 1,
            "checkpoint_bytes": 0,
            "checkpoint_tail_batches": 1,
            "checkpoint_tail_bytes": 20,
        }
        second_observation = {
            "sequence": 2,
            "phase": "physical-relation-corpus",
            "command_id": "command:semantic:2",
            "batch_digest": "b" * 64,
            "duration_ms": 5.0,
            "changed_records": 1,
            "physical_payload_bytes": 12,
            "bytes_per_changed_record": 12.0,
            "checkpoint_written": False,
            "checkpoint_count": 1,
            "checkpoint_bytes": 0,
            "checkpoint_tail_batches": 2,
            "checkpoint_tail_bytes": 32,
        }
        third_observation = {
            "sequence": 3,
            "phase": "physical-relation-corpus",
            "command_id": "command:semantic:3",
            "batch_digest": "c" * 64,
            "duration_ms": 3.0,
            "changed_records": 1,
            "physical_payload_bytes": 16,
            "bytes_per_changed_record": 16.0,
            "checkpoint_written": True,
            "checkpoint_count": 2,
            "checkpoint_bytes": 64,
            "checkpoint_tail_batches": 0,
            "checkpoint_tail_bytes": 0,
        }
        observations = [observation, second_observation, third_observation]
        semantic_ingestion = {
            "record_type": "SemanticIngestionMetrics",
            "elapsed_seconds": 0.02,
            "commit_count": 3,
            "changed_records": 4,
            "physical_payload_bytes": 48,
            "bytes_per_changed_record": 12.0,
            "p95_ms": 10.0,
            "p99_ms": 10.0,
            "checkpoint_count": 2,
            "checkpoint_writes": 1,
            "observations": observations,
            "result_digest": canonical_digest(observations),
        }
        verification = {
            "status": "pass",
            "physical": {},
            "inventory": {},
            "projection": {},
            "search": {},
            "resources": {},
            "performance": {},
            "contract_predicates": {},
        }
        operation = {
            "record_type": "SaturationOperationMetrics",
            "evidence_class": "harness_generated",
            "product_acceptance_credit": False,
            "status": "pass",
            "process_exit_code": 0,
            "invocation_exit_code": 0,
            "physical": {},
            "inventory": {},
            "projection": {},
            "search": {},
            "resources": {},
            "performance": {},
            "contract_predicates": {},
            "semantic_ingestion": semantic_ingestion,
        }

        validated = _validate_saturation_operation_metrics(
            canonical_bytes(operation),
            records=1,
            verification=verification,
        )
        self.assertNotIn("semantic_ingestion", verification)
        self.assertNotIn("semantic_ingestion", _SATURATION_EVIDENCE_FIELDS)
        self.assertEqual(validated["semantic_ingestion"], semantic_ingestion)

        omitted = json.loads(json.dumps(operation))
        del omitted["semantic_ingestion"]
        with self.assertRaisesRegex(EvidenceError, "operation metrics shape is invalid"):
            _validate_saturation_operation_metrics(
                canonical_bytes(omitted),
                records=1,
                verification=verification,
            )

        mutated = json.loads(json.dumps(operation))
        mutated["semantic_ingestion"]["result_digest"] = "f" * 64
        with self.assertRaisesRegex(EvidenceError, "summary cannot be recomputed"):
            _validate_saturation_operation_metrics(
                canonical_bytes(mutated),
                records=1,
                verification=verification,
            )

        written_without_increment = json.loads(json.dumps(operation))
        written_observation = written_without_increment["semantic_ingestion"][
            "observations"
        ][2]
        written_observation["checkpoint_count"] = 1
        with self.assertRaisesRegex(EvidenceError, "observation is invalid"):
            _validate_saturation_operation_metrics(
                canonical_bytes(written_without_increment),
                records=1,
                verification=verification,
            )

        increment_without_write = json.loads(json.dumps(operation))
        increment_without_write["semantic_ingestion"]["observations"][1][
            "checkpoint_count"
        ] = 2
        with self.assertRaisesRegex(EvidenceError, "observation is invalid"):
            _validate_saturation_operation_metrics(
                canonical_bytes(increment_without_write),
                records=1,
                verification=verification,
            )

    def test_saturation_evidence_requires_exact_candidate_in_projection_contour(
        self,
    ) -> None:
        verification, raw = self._exact_saturation_evidence_fixture()
        validated = self._validate_exact_saturation_fixture(verification, raw)
        self.assertEqual(validated["projection"]["entity_count"], 101_604)
        self.assertEqual(
            validated["projection"]["entity_type_counts"],
            {
                "Artifact": 100_000,
                "Task": 1_599,
                "Grant": 4,
                "Candidate": 1,
            },
        )
        self.assertEqual(raw["operation"]["semantic_ingestion"]["commit_count"], 1_604)

        missing_candidate = json.loads(json.dumps(verification))
        del missing_candidate["projection"]["entity_type_counts"]["Candidate"]
        missing_candidate["projection"]["entity_count"] = 101_603
        with self.assertRaisesRegex(EvidenceError, "entity contour shape is invalid"):
            self._validate_exact_saturation_fixture(missing_candidate, raw)

        tampered_candidate = json.loads(json.dumps(verification))
        tampered_candidate["projection"]["entity_type_counts"]["Candidate"] = 0
        tampered_candidate["projection"]["entity_count"] = 101_603
        with self.assertRaisesRegex(EvidenceError, "entity contour is not exact"):
            self._validate_exact_saturation_fixture(tampered_candidate, raw)

        stale_commit_count = json.loads(json.dumps(raw))
        stale_commit_count["operation"]["semantic_ingestion"]["commit_count"] = 1_603
        with self.assertRaisesRegex(
            EvidenceError,
            "contract predicates cannot be recomputed",
        ):
            self._validate_exact_saturation_fixture(verification, stale_commit_count)

    def test_completed_performance_failure_is_structurally_published(self) -> None:
        failed, failed_raw = self._exact_saturation_evidence_fixture()
        failed["status"] = "fail"
        failed["performance"]["observed"]["semantic_ingestion_seconds"] = 6.000001
        failed["performance"]["predicates"][
            "semantic_ingestion_within_profile"
        ] = False
        failed["performance"]["all_within_profile"] = False
        failed_raw["operation"]["semantic_ingestion"]["elapsed_seconds"] = 6.000001

        candidate_binding = {"candidate_binding_digest": "c" * 64}
        validation_calls: list[dict] = []

        def structural_validator(raw: dict):
            def validate(document: dict, **kwargs):
                validation_calls.append(kwargs)
                return self._validate_exact_saturation_fixture(
                    document,
                    raw,
                    require_pass=kwargs["require_pass"],
                )

            return validate

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            failed_output = root / "failed"
            with mock.patch.object(
                saturation,
                "validate_saturation_evidence",
                side_effect=structural_validator(failed_raw),
            ):
                published = saturation._publish_completed_saturation_result(
                    failed_output,
                    failed,
                    candidate_binding=candidate_binding,
                )
            self.assertEqual(published, failed)
            self.assertEqual(
                json.loads(
                    (failed_output / "saturation-result.json").read_text(
                        encoding="utf-8"
                    )
                ),
                failed,
            )
            self.assertEqual(published["status"], "fail")
            for field in (
                "pass_credit",
                "acceptance_pass",
                "product_acceptance_pass",
                "public_release_approved",
            ):
                self.assertIs(published[field], False)

            passed, passed_raw = self._exact_saturation_evidence_fixture()
            passed_output = root / "passed"
            with mock.patch.object(
                saturation,
                "validate_saturation_evidence",
                side_effect=structural_validator(passed_raw),
            ):
                published_pass = saturation._publish_completed_saturation_result(
                    passed_output,
                    passed,
                    candidate_binding=candidate_binding,
                )
            self.assertEqual(published_pass, passed)
            self.assertEqual(
                json.loads(
                    (passed_output / "saturation-result.json").read_text(
                        encoding="utf-8"
                    )
                ),
                passed,
            )

            malformed = json.loads(json.dumps(failed))
            malformed["performance"]["predicates"][
                "semantic_ingestion_within_profile"
            ] = True
            malformed_output = root / "malformed"
            with (
                mock.patch.object(
                    saturation,
                    "validate_saturation_evidence",
                    side_effect=structural_validator(failed_raw),
                ),
                self.assertRaisesRegex(
                    EvidenceError,
                    "performance predicates cannot be recomputed",
                ),
            ):
                saturation._publish_completed_saturation_result(
                    malformed_output,
                    malformed,
                    candidate_binding=candidate_binding,
                )
            self.assertFalse((malformed_output / "saturation-result.json").exists())

        self.assertEqual(len(validation_calls), 3)
        for call in validation_calls:
            self.assertIs(call["require_pass"], False)
            self.assertEqual(call["candidate_binding"], candidate_binding)
            self.assertEqual(call["source_path"].name, "saturation-result.json")
            self.assertEqual(call["evidence_root"], call["source_path"].parent)

    def test_completed_result_refuses_existing_terminal_file(self) -> None:
        evidence, raw = self._exact_saturation_evidence_fixture()
        candidate_binding = {"candidate_binding_digest": "c" * 64}
        sentinel = b"external terminal owner\n"

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "evidence"
            output.mkdir()
            result_path = output / "saturation-result.json"
            result_path.write_bytes(sentinel)

            def validate(document: dict, **kwargs):
                return self._validate_exact_saturation_fixture(
                    document,
                    raw,
                    require_pass=kwargs["require_pass"],
                )

            with (
                mock.patch.object(
                    saturation,
                    "validate_saturation_evidence",
                    side_effect=validate,
                ),
                self.assertRaisesRegex(
                    saturation.TerminalPublicationError,
                    "terminal result already exists",
                ),
            ):
                saturation._publish_completed_saturation_result(
                    output,
                    evidence,
                    candidate_binding=candidate_binding,
                )

            self.assertEqual(result_path.read_bytes(), sentinel)
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                ["saturation-result.json"],
            )

    def test_fresh_semantic_corpus_rejects_every_reuse_signal(self) -> None:
        corpus = {
            "record_type": "SaturationSemanticCorpus",
            "generation": "explicit-authorized-command-events",
            "harness_generated": True,
            "product_acceptance_credit": False,
            "task_count": 1_599,
            "relation_count": 198_999,
            "depths": list(range(1, 13)),
            "high_fanout": 16,
            "conflicting_exact_id_text": True,
            "search_fixture": {
                "task_count": 32,
                "relation_count": 28,
                "depths": list(range(1, 13)),
                "high_fanout": 16,
            },
            "physical_relation_fixture": {
                "task_count": 1_567,
                "relation_count": 198_971,
                "relation_kind": "READS",
                "target_type": "Artifact",
                "artifact_target_count": 100_000,
                "artifact_target_coverage": 1.0,
                "relations_per_atomic_batch_max": 127,
            },
            "reused": False,
            "search_fixture_reused": False,
            "physical_relation_fixture_reused": False,
        }
        self.assertEqual(
            _validate_saturation_fresh_semantic_corpus(corpus),
            corpus,
        )
        for field in (
            "reused",
            "search_fixture_reused",
            "physical_relation_fixture_reused",
        ):
            with self.subTest(field=field):
                reused = dict(corpus)
                reused[field] = True
                with self.assertRaisesRegex(
                    EvidenceError,
                    "cannot reuse semantic corpus state",
                ):
                    _validate_saturation_fresh_semantic_corpus(reused)
                with self.assertRaisesRegex(
                    ValueError,
                    "reused semantic state in a fresh audit iteration",
                ):
                    saturation_audit._validate_iteration_semantic_freshness(
                        reused
                    )

                missing = dict(corpus)
                del missing[field]
                with self.assertRaisesRegex(
                    EvidenceError,
                    "cannot reuse semantic corpus state",
                ):
                    _validate_saturation_fresh_semantic_corpus(missing)

    def test_saturation_audit_fresh_state_is_exact_and_bound_to_physical_run(
        self,
    ) -> None:
        candidate = {
            "core_bundle_digest": "c" * 64,
            "preset_digest": "d" * 64,
        }
        requirements = {
            "fresh_control_state_per_iteration": True,
            "semantic_state_reused": False,
            "init_product_tree_scans": 0,
        }
        audit = {
            "requirements": requirements,
            "invocation": release_evidence_invocation(
                invocation_id="saturation-audit:fresh-fixture",
                operation="saturation-audit",
                arguments={
                    "fresh_control_state_per_iteration": True,
                    "semantic_state_reused": False,
                },
                started_at="2026-07-22T10:00:00Z",
                completed_at="2026-07-22T10:00:01Z",
                exit_code=0,
                platform_binding="f" * 64,
            ),
        }
        self.assertNotIn("arguments", audit["invocation"])
        _validate_saturation_audit_fresh_requirements(audit)

        state = {
            "status": "created",
            "product_tree_scans": 0,
            "init_record_count": 5,
            "activation_digest": "a" * 64,
            "implementation_closure_digest": "b" * 64,
            "core_bundle_digest": candidate["core_bundle_digest"],
            "preset_digest": candidate["preset_digest"],
            "semantic_state_reused": False,
            "product_tree_reused": True,
            "physical_corpus_recipe": {
                "sha256": "e" * 64,
                "bytes": 512,
                "file_count": 100_000,
            },
        }
        platform_digest = "sha256:" + "f" * 64
        run = {
            "artifact_binding": {
                "core_bundle_digest": "sha256:" + candidate["core_bundle_digest"],
                "preset": {"sha256": "sha256:" + candidate["preset_digest"]},
                "platform": {"binding_digest": platform_digest},
            },
            "runtime_binding": {
                "activation_digest": state["activation_digest"],
                "implementation_closure_digest": state[
                    "implementation_closure_digest"
                ],
                "platform_binding_digest": platform_digest,
            },
            "workspace_initialization": {
                "record_type": "SaturationWorkspaceInitialization",
                "status": "reused",
                "project_id": "promin-physical-saturation",
                "activation_digest": state["activation_digest"],
                "implementation_closure_digest": state[
                    "implementation_closure_digest"
                ],
                "product_tree_scans": 0,
                "init_record_count": 5,
                "init_records": [
                    "activation.json",
                    "authority.json",
                    "project.json",
                    "standards.json",
                    "technologies.json",
                ],
                "snapshot_provider_id": "git-filesystem-inventory",
                "snapshot_provider_version": "2.45.1",
            },
            "physical": {"reused_product": True},
            "invocation": release_evidence_invocation(
                invocation_id="saturation:fresh-fixture",
                operation="physical-saturation",
                arguments={
                    "reuse_product": True,
                    "workspace_recipe": "representative-operational-text-v3",
                },
                started_at="2026-07-22T10:00:00Z",
                completed_at="2026-07-22T10:00:01Z",
                exit_code=0,
                platform_binding="f" * 64,
            ),
        }
        self.assertNotIn("arguments", run["invocation"])
        self.assertEqual(
            _validate_saturation_audit_fresh_control_state(
                state,
                candidate=candidate,
                run=run,
            ),
            state,
        )

        missing_requirement = json.loads(json.dumps(audit))
        del missing_requirement["requirements"]["fresh_control_state_per_iteration"]
        with self.assertRaisesRegex(EvidenceError, "fresh-control requirements"):
            _validate_saturation_audit_fresh_requirements(missing_requirement)

        missing_state_field = json.loads(json.dumps(state))
        del missing_state_field["init_record_count"]
        with self.assertRaisesRegex(EvidenceError, "fresh control state is invalid"):
            _validate_saturation_audit_fresh_control_state(
                missing_state_field,
                candidate=candidate,
                run=run,
            )

        mutated_run = json.loads(json.dumps(run))
        mutated_run["runtime_binding"]["activation_digest"] = "0" * 64
        with self.assertRaisesRegex(EvidenceError, "differs from nested physical evidence"):
            _validate_saturation_audit_fresh_control_state(
                state,
                candidate=candidate,
                run=mutated_run,
            )

    def test_physical_platform_binding_uses_base_python_not_driver_launcher(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            driver = root / "driver-python.exe"
            base = root / "base-python.exe"
            driver.write_bytes(b"driver launcher")
            base.write_bytes(b"base runtime")

            with mock.patch.object(saturation.sys, "executable", str(driver)), mock.patch.object(
                saturation.sys,
                "_base_executable",
                str(base),
                create=True,
            ):
                binding = saturation._platform_binding()

            self.assertEqual(
                binding["python_executable_sha256"],
                "sha256:" + hashlib.sha256(base.read_bytes()).hexdigest(),
            )
            self.assertNotEqual(
                binding["python_executable_sha256"],
                "sha256:" + hashlib.sha256(driver.read_bytes()).hexdigest(),
            )

    def test_standalone_saturation_runtime_bindings_are_cross_checked(self) -> None:
        platform_binding = saturation._platform_binding()
        _validate_release_platform_binding(platform_binding)
        activation_digest = "a" * 64
        implementation_digest = "b" * 64
        verification = {
            "workspace_initialization": {
                "record_type": "SaturationWorkspaceInitialization",
                "status": "created",
                "project_id": "promin-physical-saturation",
                "activation_digest": activation_digest,
                "implementation_closure_digest": implementation_digest,
                "product_tree_scans": 0,
                "init_record_count": 5,
                "init_records": [
                    "activation.json",
                    "authority.json",
                    "project.json",
                    "standards.json",
                    "technologies.json",
                ],
                "snapshot_provider_id": "git-filesystem-inventory",
                "snapshot_provider_version": "2.45.1",
            },
            "runtime_binding": {
                "activation_digest": activation_digest,
                "implementation_closure_digest": implementation_digest,
                "platform_binding_digest": platform_binding["binding_digest"],
            },
        }
        projection = {
            "implementation_closure_digest": implementation_digest,
            "database_bytes": 1024,
            "projection_amplification": 2.0,
            "semantic_inflation": 3.0,
        }
        query_authorization = {
            "subject_id": "fixture-reader",
            "grant_id": "grant:fixture-reader",
            "claim_digest": "c" * 64,
            "capability_id": "projection.read",
            "scope": [{"kind": "all", "value": "*"}],
            "activation_digest": activation_digest,
            "expires_at": "2026-07-23T10:00:00Z",
        }
        search = {"p50_ms": 1.0, "p95_ms": 2.0, "p99_ms": 3.0}
        resources = {"peak_rss_bytes": 4096}
        performance = {
            "profile_id": "portable-local-v1",
            "platform_binding": platform_binding,
            "compatible_platforms": ["linux", "windows"],
            "requires_same_runner_no_degradation": True,
            "observed": {
                "p50_ms": 1.0,
                "p95_ms": 2.0,
                "p99_ms": 3.0,
                "peak_rss_bytes": 4096,
                "database_bytes": 1024,
                "projection_amplification": 2.0,
                "semantic_inflation": 3.0,
            },
        }
        arguments = {
            "verification": verification,
            "binding": {"platform": platform_binding},
            "projection": projection,
            "query_authorization": query_authorization,
            "search": search,
            "resources": resources,
            "performance": performance,
        }
        _validate_saturation_runtime_bindings(**arguments)

        extra_field_platform = json.loads(json.dumps(platform_binding))
        extra_field_platform["launcher_path"] = "ignored.exe"
        platform_identity = {
            key: value
            for key, value in extra_field_platform.items()
            if key != "binding_digest"
        }
        extra_field_platform["binding_digest"] = (
            "sha256:" + canonical_digest(platform_identity)
        )
        with self.assertRaisesRegex(EvidenceError, "platform binding shape"):
            _validate_release_platform_binding(extra_field_platform)

        drifted_runtime = json.loads(json.dumps(verification))
        drifted_runtime["runtime_binding"]["activation_digest"] = "d" * 64
        with self.assertRaisesRegex(EvidenceError, "generation bindings disagree"):
            _validate_saturation_runtime_bindings(
                **{**arguments, "verification": drifted_runtime}
            )

        drifted_observed = json.loads(json.dumps(performance))
        drifted_observed["observed"]["p95_ms"] = 1.0
        with self.assertRaisesRegex(EvidenceError, "performance profile binding"):
            _validate_saturation_runtime_bindings(
                **{**arguments, "performance": drifted_observed}
            )

    def test_semantic_ingestion_rounding_has_one_raw_and_phase_value(self) -> None:
        elapsed = saturation._semantic_ingestion_elapsed_seconds(0.0, 0.0014996)
        self.assertEqual(elapsed, 0.0015)
        self.assertEqual(round(elapsed * 1000), 2)

    def test_physical_scale_counts_are_exact_and_cannot_be_weakened(self) -> None:
        self.assertEqual(saturation._EXACT_PHYSICAL_FILES, 100_000)
        self.assertEqual(saturation._EXACT_CORE_VALID_RELATIONS, 198_999)
        self.assertEqual(saturation._EXACT_RUNTIME_QUERIES, 600)
        self.assertEqual(
            saturation._PHYSICAL_RELATION_COUNT
            + saturation._SEARCH_FIXTURE_RELATION_COUNT,
            saturation._EXACT_CORE_VALID_RELATIONS,
        )
        saturation_source = inspect.getsource(saturation.run)
        self.assertIn('"core_valid_relations_exact_198999"', saturation_source)
        self.assertIn('"core_valid_relations_exact"', saturation_source)
        self.assertIn('"runtime_queries_exact"', saturation_source)
        performance_source = inspect.getsource(saturation._load_performance_contract)
        self.assertIn('"core_valid_relation_count"', performance_source)
        self.assertIn('"query_count"', performance_source)
        for files, queries in (
            (99_999, 600),
            (100_001, 600),
            (100_000, 599),
            (100_000, 601),
        ):
            with self.subTest(tool="physical", files=files, queries=queries):
                with self.assertRaisesRegex(saturation.SaturationError, "exactly"):
                    saturation.run(
                        Path("unused-workspace"),
                        Path("unused-output"),
                        files=files,
                        queries=queries,
                    )
            with self.subTest(tool="audit", files=files, queries=queries):
                with self.assertRaisesRegex(saturation_audit.AuditError, "exactly"):
                    saturation_audit.run(
                        Path("unused-package"),
                        Path("unused-output"),
                        Path("unused-workspace"),
                        files=files,
                        queries=queries,
                    )

    def test_audit_reads_semantic_metrics_only_through_raw_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "raw"
            raw.mkdir()
            operation_path = raw / "operation-metrics.json"
            operation = {
                "record_type": "SaturationOperationMetrics",
                "semantic_ingestion": {"commit_count": 1},
            }
            payload = canonical_bytes(operation)
            operation_path.write_bytes(payload)
            verification = {
                "raw_artifact_manifest": {
                    "artifacts": [
                        {
                            "role": "operation-metrics",
                            "path": "raw/operation-metrics.json",
                            "media_type": "application/json",
                            "sha256": hashlib.sha256(payload).hexdigest(),
                            "bytes": len(payload),
                            "records": 1,
                        }
                    ]
                }
            }
            self.assertEqual(
                saturation_audit._read_bound_raw_json(
                    verification,
                    record_path=root / "saturation-result.json",
                    role="operation-metrics",
                    expected_path="raw/operation-metrics.json",
                    max_bytes=4096,
                ),
                operation,
            )
            operation_path.write_bytes(canonical_bytes({**operation, "status": "tampered"}))
            with self.assertRaisesRegex(ValueError, "binding mismatch"):
                saturation_audit._read_bound_raw_json(
                    verification,
                    record_path=root / "saturation-result.json",
                    role="operation-metrics",
                    expected_path="raw/operation-metrics.json",
                    max_bytes=4096,
                )

    def test_scale_producers_validate_sealed_evidence_before_publication(self) -> None:
        saturation_source = inspect.getsource(saturation.run)
        sealed = saturation_source.index("evidence = seal_release_evidence(evidence)")
        publication = saturation_source.index(
            "return _publish_completed_saturation_result("
        )
        self.assertLess(sealed, publication)

        publication_source = inspect.getsource(
            saturation._publish_completed_saturation_result
        )
        validated = publication_source.index(
            "validated = validate_saturation_evidence("
        )
        published = publication_source.index(
            "_write_json_create_only(result_path, evidence)"
        )
        self.assertLess(validated, published)

        no_degradation_source = inspect.getsource(no_degradation.run)
        self.assertIn("validate_no_degradation_result(", no_degradation_source)

    def test_zero_new_orchestration_closes_on_exactly_three_full_runs(self) -> None:
        streak = 0
        for expected in (1, 2, 3):
            streak, reason = saturation_audit._advance_zero_new_streak(
                streak,
                passed=True,
                new_findings=[],
            )
            self.assertEqual(streak, expected)
            self.assertIsNone(reason)
        source = inspect.getsource(saturation_audit.run)
        self.assertIn("if zero_new_streak == 3:", source)
        self.assertIn("zero_new_streak == 3", source)

    def test_physical_commands_select_only_scale(self) -> None:
        for command in (
            saturation_audit._physical_pytest_command(),
            no_degradation._physical_pytest_command(Path("package")),
        ):
            marker_index = command.index("-m", 4) + 1
            self.assertEqual(command[marker_index], "scale")

    def test_missing_scale_workspace_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            saturation_audit.AuditError,
            "PROMIN_SCALE_WORKSPACE is required",
        ):
            saturation_audit._require_scale_workspace({})

    def test_scale_workspace_must_be_initialized_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            workspace.mkdir()
            environment = {"PROMIN_SCALE_WORKSPACE": str(workspace)}
            with self.assertRaisesRegex(
                saturation_audit.AuditError,
                "production-initialized workspace",
            ):
                saturation_audit._require_scale_workspace(environment)
            (workspace / ".promin").mkdir()
            self.assertEqual(
                saturation_audit._require_scale_workspace(
                    environment,
                    expected=workspace,
                ),
                workspace.resolve(),
            )

    def test_audit_roots_are_real_and_strictly_disjoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            workspace = root / "workspace"
            package.mkdir()
            (workspace / ".promin").mkdir(parents=True)
            valid = saturation_audit._validate_run_roots(
                package,
                root / "audit-output",
                workspace,
            )
            self.assertEqual(valid["package"], package)
            for output in (
                package / "evidence",
                workspace / "evidence",
                workspace / ".promin" / "state" / "evidence",
                workspace / ".promin-saturation-audit-state" / "evidence",
                saturation_audit._operational_state_parent(workspace) / "evidence",
            ):
                with self.subTest(output=output), self.assertRaisesRegex(
                    saturation_audit.AuditError,
                    "disjoint",
                ):
                    saturation_audit._validate_run_roots(package, output, workspace)

            nested_workspace = package / "nested-workspace"
            (nested_workspace / ".promin").mkdir(parents=True)
            with self.assertRaisesRegex(saturation_audit.AuditError, "strictly disjoint"):
                saturation_audit._validate_run_roots(
                    package,
                    root / "other-output",
                    nested_workspace,
                )

    def test_symlink_or_reparse_ancestor_is_rejected_where_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            workspace_target = root / "workspace-target"
            package.mkdir()
            (workspace_target / ".promin").mkdir(parents=True)
            workspace_link = root / "workspace-link"
            try:
                workspace_link.symlink_to(workspace_target, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlink/reparse fixture unavailable: {exc}")
            with self.assertRaisesRegex(
                saturation_audit.AuditError,
                "symbolic link, junction, or reparse",
            ):
                saturation_audit._validate_run_roots(
                    package,
                    root / "audit-output",
                    workspace_link,
                )

    def test_audit_scrubs_tests_and_routes_only_physical_credentials_to_child(self) -> None:
        outer = {
            "PROMIN_EVIDENCE_PRIVATE_KEY": "audit.key",
            "PROMIN_EVIDENCE_TRUST_CONFIGURATION": "trust.json",
            "PROMIN_EVIDENCE_KEY_ID": "audit-key",
            "PROMIN_EVIDENCE_PRODUCER_ID": "audit-producer",
            "PROMIN_MUTATION_SEED": "seed",
        }
        boundary = {
            "physical_environment": {
                "PROMIN_EVIDENCE_PRIVATE_KEY": "physical.key",
                "PROMIN_EVIDENCE_TRUST_CONFIGURATION": "trust.json",
                "PROMIN_EVIDENCE_KEY_ID": "physical-key",
                "PROMIN_EVIDENCE_PRODUCER_ID": "physical-producer",
            }
        }

        focused = saturation_audit._without_evidence_configuration(outer)
        physical = saturation_audit._physical_evidence_environment(outer, boundary)

        self.assertEqual(focused, {"PROMIN_MUTATION_SEED": "seed"})
        self.assertEqual(physical["PROMIN_EVIDENCE_PRIVATE_KEY"], "physical.key")
        self.assertEqual(physical["PROMIN_EVIDENCE_KEY_ID"], "physical-key")
        self.assertEqual(physical["PROMIN_EVIDENCE_PRODUCER_ID"], "physical-producer")
        self.assertEqual(physical["PROMIN_MUTATION_SEED"], "seed")
        self.assertEqual(outer["PROMIN_EVIDENCE_KEY_ID"], "audit-key")

    def test_audit_rejects_partial_or_mixed_producer_configuration_before_work(self) -> None:
        with self.assertRaisesRegex(
            saturation_audit.AuditError,
            "outer saturation-audit producer configuration is partial",
        ):
            saturation_audit._producer_boundary(
                {"PROMIN_EVIDENCE_PRIVATE_KEY": "audit.key"},
                platform_name="windows",
                physical_private_key=None,
                physical_trust_configuration=None,
                physical_key_id=None,
                physical_producer_id=None,
            )
        with self.assertRaisesRegex(
            saturation_audit.AuditError,
            "outer saturation-audit producer configuration is partial",
        ):
            saturation_audit._producer_boundary(
                {"PROMIN_EVIDENCE_PRODUCER_ID": "producer-only"},
                platform_name="windows",
                physical_private_key=None,
                physical_trust_configuration=None,
                physical_key_id=None,
                physical_producer_id=None,
            )
        outer = {
            "PROMIN_EVIDENCE_PRIVATE_KEY": "audit.key",
            "PROMIN_EVIDENCE_TRUST_CONFIGURATION": "trust.json",
            "PROMIN_EVIDENCE_KEY_ID": "audit-key",
            "PROMIN_EVIDENCE_PRODUCER_ID": "audit-producer",
        }
        with self.assertRaisesRegex(
            saturation_audit.AuditError,
            "requires both outer and nested producer configurations",
        ):
            saturation_audit._producer_boundary(
                outer,
                platform_name="windows",
                physical_private_key=None,
                physical_trust_configuration=None,
                physical_key_id=None,
                physical_producer_id=None,
            )
        with self.assertRaisesRegex(
            saturation_audit.AuditError,
            "nested physical-scale producer configuration is partial",
        ):
            saturation_audit._producer_boundary(
                {},
                platform_name="windows",
                physical_private_key=Path("physical.key"),
                physical_trust_configuration=None,
                physical_key_id=None,
                physical_producer_id=None,
            )

        source = inspect.getsource(saturation_audit.run)
        preflight = source.index("producer_boundary = _producer_boundary(")
        self.assertLess(preflight, source.index("_collect_mutations("))
        self.assertLess(preflight, source.index("_durable_mkdir(output"))
        self.assertLess(preflight, source.index("for iteration in range("))

    def test_outer_producer_id_defaults_to_the_trusted_subject(self) -> None:
        outer = {
            "PROMIN_EVIDENCE_PRIVATE_KEY": "audit.key",
            "PROMIN_EVIDENCE_TRUST_CONFIGURATION": "trust.json",
            "PROMIN_EVIDENCE_KEY_ID": "audit-key",
        }

        def preflight(**arguments):
            role = arguments["role"]
            return {
                "producer_id": arguments.get("producer_id")
                or ("audit-subject" if role == "saturation-audit" else "physical-subject"),
                "trust_root_id": "trust-root",
                "key_id": arguments["key_id"],
                "configured_public_key": (
                    "audit-public" if role == "saturation-audit" else "physical-public"
                ),
                "trust_configuration_sha256": "a" * 64,
                "evidence_role": role,
                "platform": arguments["platform_name"],
            }

        with mock.patch.object(
            saturation_audit,
            "validate_release_evidence_producer_configuration",
            side_effect=preflight,
        ):
            boundary = saturation_audit._producer_boundary(
                outer,
                platform_name="windows",
                physical_private_key=Path("physical.key"),
                physical_trust_configuration=Path("trust.json"),
                physical_key_id="physical-key",
                physical_producer_id="physical-subject",
            )

        self.assertIsNotNone(boundary)
        self.assertEqual(boundary["outer"]["producer_id"], "audit-subject")
        self.assertNotIn("PROMIN_EVIDENCE_PRODUCER_ID", outer)

    def test_audit_cli_exposes_all_nested_physical_producer_arguments(self) -> None:
        source = inspect.getsource(saturation_audit.main)
        for option in (
            "--physical-evidence-private-key",
            "--physical-evidence-trust-configuration",
            "--physical-evidence-key-id",
            "--physical-evidence-producer-id",
        ):
            self.assertIn(option, source)

    def test_three_physical_iterations_use_fresh_semantic_states_and_same_product(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            output = Path(temporary) / "evidence" / "saturation-audit"
            (workspace / "product").mkdir(parents=True)
            product = workspace / "product" / "representative.txt"
            product.write_bytes(b"same physical product\n")
            state = workspace / ".promin" / "state"
            state.mkdir(parents=True)
            recipe_value = {
                "record_type": "PhysicalCorpusRecipe",
                "recipe": "representative-operational-text-v3",
                "file_count": 100_000,
                "representative_classes": [str(index) for index in range(8)],
                "content_probe_stride": 257,
                "hostile_probe_stride": 509,
            }
            recipe_path = state / "physical-corpus.json"
            recipe_path.write_bytes(
                (json.dumps(recipe_value, sort_keys=True, separators=(",", ":")) + "\n").encode(
                    "utf-8"
                )
            )
            (state / "baseline-semantic-state.json").write_text(
                '["must-not-enter-a-fresh-iteration"]',
                encoding="utf-8",
            )
            tool = self._fresh_state_fixture()
            recipe = saturation_audit._capture_physical_recipe(
                workspace,
                tool,
                files=100_000,
            )
            artifact_binding = {
                "binding_digest": "sha256:" + "c" * 64,
                "candidate_binding_digest": "d" * 64,
                "standard_candidate_binding": {
                    "core_bundle_digest": "e" * 64,
                    "preset_digest": "f" * 64,
                },
            }
            coordinator = saturation_audit._begin_operational_state(
                workspace,
                output,
                artifact_binding,
                recipe=recipe,
            )
            generations: list[str] = []

            def apply_plan(target: Path, _plan):
                self.assertFalse((target / ".promin").exists())
                generation = f"generation-{len(generations) + 1}"
                generations.append(generation)
                control = target / ".promin"
                (control / "state").mkdir(parents=True)
                (control / "init-generation.txt").write_text(generation, encoding="utf-8")
                return {
                    "status": "created",
                    "product_tree_scans": 0,
                    "core_bundle_digest": "e" * 64,
                    "preset_digest": "f" * 64,
                }

            with mock.patch("promin_init.apply_plan", side_effect=apply_plan):
                for iteration in range(1, 4):
                    initialized = saturation_audit._fresh_iteration_control_state(
                        coordinator,
                        tool,
                        artifact_binding,
                        iteration=iteration,
                    )
                    current_state = workspace / ".promin" / "state"
                    self.assertFalse((current_state / "baseline-semantic-state.json").exists())
                    self.assertEqual(initialized["product_tree_scans"], 0)
                    self.assertFalse(initialized["semantic_state_reused"])
                    self.assertTrue(initialized["product_tree_reused"])
                    (current_state / "semantic-commits.json").write_text(
                        json.dumps([f"commit-{iteration}"]),
                        encoding="utf-8",
                    )
                    saturation_audit._preserve_iteration_control_state(
                        coordinator,
                        iteration=iteration,
                        status="zero-new",
                        semantic_commit_count=1,
                    )

            saturation_audit._restore_baseline_control_state(coordinator)

            self.assertEqual(generations, ["generation-1", "generation-2", "generation-3"])
            self.assertEqual(product.read_bytes(), b"same physical product\n")
            self.assertEqual(recipe_path.read_bytes(), recipe["payload"])
            self.assertTrue((state / "baseline-semantic-state.json").is_file())
            for iteration in range(1, 4):
                preserved = coordinator["root"] / f"iteration-{iteration:02d}.promin"
                self.assertEqual(
                    json.loads((preserved / "state" / "semantic-commits.json").read_text()),
                    [f"commit-{iteration}"],
                )
                self.assertEqual(
                    (preserved / "init-generation.txt").read_text(encoding="utf-8"),
                    f"generation-{iteration}",
                )
            operational = json.loads(
                (coordinator["root"] / "operational-state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(operational["phase"], "complete")
            self.assertTrue(operational["baseline_restored"])
            self.assertEqual(
                operational["baseline_identity_before"],
                operational["baseline_identity_after"],
            )
            self.assertEqual(
                [row["semantic_commit_count"] for row in operational["iterations"]],
                [1, 1, 1],
            )
            source = inspect.getsource(saturation_audit.run)
            loop = source.index("for iteration in range(")
            fresh = source.index("_fresh_iteration_control_state(", loop)
            child = source.index("saturation_code, saturation_log", fresh)
            preserve = source.index("_preserve_iteration_control_state(", child)
            restore = source.index("_restore_baseline_control_state(", preserve)
            publish = source.index('"record_type": "SaturationAudit"', restore)
            self.assertLess(loop, fresh)
            self.assertLess(fresh, child)
            self.assertLess(child, preserve)
            self.assertLess(preserve, restore)
            self.assertLess(restore, publish)
            self.assertIn("if reuse_existing_product or iteration > 1:", source)

    def test_fresh_iteration_rejects_wrong_candidate_before_physical_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            output = Path(temporary) / "audit-output"
            (workspace / ".promin" / "state").mkdir(parents=True)
            artifact_binding = {
                "binding_digest": "sha256:" + "5" * 64,
                "candidate_binding_digest": "6" * 64,
                "standard_candidate_binding": {
                    "core_bundle_digest": "7" * 64,
                    "preset_digest": "8" * 64,
                },
            }
            coordinator = saturation_audit._begin_operational_state(
                workspace,
                output,
                artifact_binding,
                recipe=None,
            )
            tool = self._fresh_state_fixture()

            def wrong_apply(target: Path, _plan):
                control = target / ".promin"
                (control / "state").mkdir(parents=True)
                (control / "init-generation.txt").write_text("wrong", encoding="utf-8")
                return {
                    "status": "created",
                    "product_tree_scans": 0,
                    "core_bundle_digest": "9" * 64,
                    "preset_digest": "8" * 64,
                }

            with mock.patch("promin_init.apply_plan", side_effect=wrong_apply):
                with self.assertRaisesRegex(
                    saturation_audit.AuditError,
                    "exact candidate",
                ):
                    saturation_audit._fresh_iteration_control_state(
                        coordinator,
                        tool,
                        artifact_binding,
                        iteration=1,
                    )
            marker = json.loads(
                (coordinator["root"] / "operational-state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(marker["phase"], "iteration-initialization-failed")
            self.assertFalse((output / "saturation-audit.json").exists())
            saturation_audit._preserve_iteration_control_state(
                coordinator,
                iteration=1,
                status="rejected-wrong-candidate",
                semantic_commit_count=0,
            )
            saturation_audit._restore_baseline_control_state(coordinator)

    def test_recovery_reconciles_moves_that_cross_marker_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            output = Path(temporary) / "audit-output"
            (workspace / ".promin" / "state").mkdir(parents=True)
            (workspace / ".promin" / "state" / "baseline.json").write_text(
                '{"baseline":true}',
                encoding="utf-8",
            )
            artifact_binding = {
                "binding_digest": "sha256:" + "a" * 64,
                "candidate_binding_digest": "b" * 64,
                "standard_candidate_binding": {
                    "core_bundle_digest": "c" * 64,
                    "preset_digest": "d" * 64,
                },
            }
            coordinator = saturation_audit._begin_operational_state(
                workspace,
                output,
                artifact_binding,
                recipe=None,
            )
            marker_path = coordinator["root"] / "operational-state.json"
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            marker["phase"] = "baseline-preservation-pending"
            saturation_audit._write(marker_path, marker)
            reconciled = saturation_audit._reconcile_operational_state(
                coordinator["root"],
                workspace,
                candidate_binding_digest=artifact_binding["candidate_binding_digest"],
                output_identity_digest=coordinator["output_identity_digest"],
            )
            self.assertEqual(reconciled["phase"], "iteration-preserved-recovered")

            tool = self._fresh_state_fixture()

            def apply_plan(target: Path, _plan):
                control = target / ".promin"
                (control / "state").mkdir(parents=True)
                (control / "init-generation.txt").write_text("crash-boundary", encoding="utf-8")
                return {
                    "status": "created",
                    "product_tree_scans": 0,
                    "core_bundle_digest": "c" * 64,
                    "preset_digest": "d" * 64,
                }

            with mock.patch("promin_init.apply_plan", side_effect=apply_plan):
                saturation_audit._fresh_iteration_control_state(
                    reconciled,
                    tool,
                    artifact_binding,
                    iteration=1,
                )
            saturation_audit._move_control_state(
                workspace / ".promin",
                reconciled["root"] / "iteration-01.promin",
            )
            after_iteration_move = saturation_audit._reconcile_operational_state(
                reconciled["root"],
                workspace,
                candidate_binding_digest=artifact_binding["candidate_binding_digest"],
                output_identity_digest=reconciled["output_identity_digest"],
            )
            self.assertEqual(
                after_iteration_move["iterations"][0]["status"],
                "recovered-uncredited",
            )
            self.assertEqual(after_iteration_move["phase"], "iteration-preserved-recovered")

            saturation_audit._move_control_state(
                after_iteration_move["root"] / "baseline.promin",
                workspace / ".promin",
            )
            after_restore_move = saturation_audit._reconcile_operational_state(
                after_iteration_move["root"],
                workspace,
                candidate_binding_digest=artifact_binding["candidate_binding_digest"],
                output_identity_digest=after_iteration_move["output_identity_digest"],
            )
            self.assertEqual(after_restore_move["phase"], "complete-recovered")
            self.assertTrue(after_restore_move["baseline_restored"])
            self.assertEqual(
                after_restore_move["baseline_identity_before"],
                after_restore_move["baseline_identity_after"],
            )
            self.assertFalse((output / "saturation-audit.json").exists())

    def test_alternate_output_cannot_bypass_active_workspace_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            output_a = Path(temporary) / "audit-output-a"
            output_b = Path(temporary) / "audit-output-b"
            (workspace / ".promin" / "state").mkdir(parents=True)
            (workspace / ".promin" / "state" / "baseline.json").write_text(
                '{"baseline":true}',
                encoding="utf-8",
            )
            artifact_a = {
                "binding_digest": "sha256:" + "1" * 64,
                "candidate_binding_digest": "2" * 64,
                "standard_candidate_binding": {
                    "core_bundle_digest": "3" * 64,
                    "preset_digest": "4" * 64,
                },
            }
            artifact_b = {
                "binding_digest": "sha256:" + "5" * 64,
                "candidate_binding_digest": "6" * 64,
                "standard_candidate_binding": {
                    "core_bundle_digest": "7" * 64,
                    "preset_digest": "8" * 64,
                },
            }
            coordinator = saturation_audit._begin_operational_state(
                workspace,
                output_a,
                artifact_a,
                recipe=None,
            )
            baseline_identity = coordinator["baseline_identity_before"]
            tool = self._fresh_state_fixture()

            def apply_plan(target: Path, _plan):
                control = target / ".promin"
                (control / "state").mkdir(parents=True)
                (control / "init-generation.txt").write_text(
                    "output-a-active",
                    encoding="utf-8",
                )
                return {
                    "status": "created",
                    "product_tree_scans": 0,
                    "core_bundle_digest": "3" * 64,
                    "preset_digest": "4" * 64,
                }

            with mock.patch("promin_init.apply_plan", side_effect=apply_plan):
                saturation_audit._fresh_iteration_control_state(
                    coordinator,
                    tool,
                    artifact_a,
                    iteration=1,
                )

            root_a, identity_a = saturation_audit._operational_state_location(
                workspace,
                output_a,
                artifact_a,
            )
            root_b, identity_b = saturation_audit._operational_state_location(
                workspace,
                output_b,
                artifact_b,
            )
            self.assertEqual(root_a, root_b)
            self.assertNotEqual(identity_a, identity_b)
            self.assertNotEqual(
                saturation_audit._control_state_identity(workspace / ".promin"),
                baseline_identity,
            )

            with self.assertRaisesRegex(
                saturation_audit.AuditError,
                "workspace-exclusive.*iteration-active-recovered",
            ):
                saturation_audit._guard_workspace_operational_state(workspace)

            marker = json.loads(
                (coordinator["root"] / "operational-state.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(marker["output_identity_digest"], identity_a)
            self.assertEqual(marker["phase"], "iteration-active-recovered")
            self.assertFalse(marker["baseline_restored"])
            self.assertEqual(
                saturation_audit._control_state_identity(
                    coordinator["root"] / "baseline.promin"
                ),
                baseline_identity,
            )
            self.assertFalse((output_b / "saturation-audit.json").exists())

            source = inspect.getsource(saturation_audit.run)
            guard = source.index("_guard_workspace_operational_state(")
            artifact_load = source.index("saturation_tool = _load_saturation_tool()")
            output_check = source.index("if output.exists() or output.is_symlink():")
            self.assertLess(guard, artifact_load)
            self.assertLess(guard, output_check)

            saturation_audit._preserve_iteration_control_state(
                coordinator,
                iteration=1,
                status="interrupted",
                semantic_commit_count=0,
            )
            saturation_audit._restore_baseline_control_state(coordinator)

    def test_control_state_move_fsyncs_destination_parent_before_source_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_parent = root / "source-parent"
            destination_parent = root / "destination-parent"
            source = source_parent / "active.promin"
            destination = destination_parent / "preserved.promin"
            (source / "state").mkdir(parents=True)
            destination_parent.mkdir()
            (source / "state" / "record.json").write_text("{}", encoding="utf-8")

            with mock.patch.object(saturation_audit, "_fsync_directory") as fsync:
                saturation_audit._move_control_state(source, destination)

            self.assertEqual(
                fsync.call_args_list,
                [mock.call(destination_parent), mock.call(source_parent)],
            )
            self.assertFalse(source.exists())
            self.assertTrue((destination / "state" / "record.json").is_file())

    def test_cross_iteration_replay_identities_are_rejected_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)

            def make_record(index: int):
                return {
                    "result_digest": f"{index + 1:064x}",
                    "invocation": {"invocation_id": f"physical:{index}"},
                    "producer_attestation": {
                        "key_id": "physical-key",
                        "nonce": f"nonce-{index}",
                        "signed_claim_digest": f"{index + 101:064x}",
                    },
                }

            records = [make_record(index) for index in range(3)]

            def write_rows():
                rows = []
                for index, record in enumerate(records, start=1):
                    path = output / f"iteration-{index:02d}-physical" / "saturation-result.json"
                    saturation_audit._write(path, record)
                    rows.append(
                        {
                            "physical_runtime_saturation": {
                                "record_path": f"iteration-{index:02d}-physical/saturation-result.json",
                                "record_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                "record_bytes": path.stat().st_size,
                            }
                        }
                    )
                return rows

            rows = write_rows()
            self.assertEqual(
                len(saturation_audit._assert_unique_physical_evidence_identities(output, rows)),
                3,
            )
            wrong_size = write_rows()
            wrong_size[0]["physical_runtime_saturation"]["record_bytes"] += 1
            with self.assertRaisesRegex(
                saturation_audit.AuditError,
                "identity is incomplete or drifted",
            ):
                saturation_audit._assert_unique_physical_evidence_identities(
                    output,
                    wrong_size,
                )
            duplicate_cases = {
                "result": ("result_digest", records[0]["result_digest"]),
                "invocation": (
                    "invocation.invocation_id",
                    records[0]["invocation"]["invocation_id"],
                ),
                "nonce": (
                    "producer_attestation.nonce",
                    records[0]["producer_attestation"]["nonce"],
                ),
                "claim": (
                    "producer_attestation.signed_claim_digest",
                    records[0]["producer_attestation"]["signed_claim_digest"],
                ),
            }
            for name, (field, duplicate) in duplicate_cases.items():
                records[1] = make_record(1)
                target = records[1]
                parts = field.split(".")
                for part in parts[:-1]:
                    target = target[part]
                target[parts[-1]] = duplicate
                with self.subTest(name=name), self.assertRaisesRegex(
                    saturation_audit.AuditError,
                    "cross-iteration replay",
                ):
                    saturation_audit._assert_unique_physical_evidence_identities(
                        output,
                        write_rows(),
                    )

    def test_final_audit_is_atomically_published_only_after_full_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "accepted"
            output.mkdir()
            result = {"record_type": "SaturationAudit", "result_digest": "a" * 64}

            def validate(value, **arguments):
                self.assertTrue(arguments["source_path"].is_file())
                self.assertFalse((output / "saturation-audit.json").exists())
                arguments["attestation_graph"].extend([{}, {}, {}])
                return value

            with mock.patch.object(
                saturation_audit,
                "validate_saturation_audit",
                side_effect=validate,
            ) as validator:
                saturation_audit._publish_validated_saturation_audit(
                    output,
                    result,
                    candidate_binding={"candidate_binding_digest": "b" * 64},
                    trust_configuration={"record_type": "trust"},
                )
            validator.assert_called_once()
            self.assertTrue((output / "saturation-audit.json").is_file())
            self.assertFalse((output / ".saturation-audit.json.staged").exists())

            rejected = Path(temporary) / "rejected"
            rejected.mkdir()
            with mock.patch.object(
                saturation_audit,
                "validate_saturation_audit",
                side_effect=saturation_audit.EvidenceError("replay"),
            ):
                with self.assertRaisesRegex(saturation_audit.AuditError, "full validation"):
                    saturation_audit._publish_validated_saturation_audit(
                        rejected,
                        result,
                        candidate_binding={"candidate_binding_digest": "b" * 64},
                        trust_configuration={"record_type": "trust"},
                    )
            self.assertFalse((rejected / "saturation-audit.json").exists())
            self.assertTrue((rejected / ".saturation-audit.json.staged").is_file())

    def test_interrupted_fresh_iteration_leaves_recoverable_state_without_final_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            output = Path(temporary) / "evidence" / "saturation-audit"
            (workspace / ".promin" / "state").mkdir(parents=True)
            artifact_binding = {
                "binding_digest": "sha256:" + "1" * 64,
                "candidate_binding_digest": "2" * 64,
                "standard_candidate_binding": {
                    "core_bundle_digest": "3" * 64,
                    "preset_digest": "4" * 64,
                },
            }
            coordinator = saturation_audit._begin_operational_state(
                workspace,
                output,
                artifact_binding,
                recipe=None,
            )
            tool = self._fresh_state_fixture()

            def apply_plan(target: Path, _plan):
                control = target / ".promin"
                (control / "state").mkdir(parents=True)
                (control / "init-generation.txt").write_text("interrupted", encoding="utf-8")
                return {
                    "status": "created",
                    "product_tree_scans": 0,
                    "core_bundle_digest": "3" * 64,
                    "preset_digest": "4" * 64,
                }

            with mock.patch("promin_init.apply_plan", side_effect=apply_plan):
                saturation_audit._fresh_iteration_control_state(
                    coordinator,
                    tool,
                    artifact_binding,
                    iteration=1,
                )

            operational_path = coordinator["root"] / "operational-state.json"
            operational = json.loads(operational_path.read_text(encoding="utf-8"))
            self.assertEqual(operational["phase"], "iteration-active")
            self.assertEqual(operational["active_iteration"], 1)
            self.assertTrue((coordinator["root"] / "baseline.promin").is_dir())
            self.assertTrue((workspace / ".promin").is_dir())
            self.assertFalse((output / "saturation-audit.json").exists())

            with self.assertRaisesRegex(
                saturation_audit.AuditError,
                "independent nonempty semantic commits",
            ):
                saturation_audit._preserve_iteration_control_state(
                    coordinator,
                    iteration=1,
                    status="zero-new",
                    semantic_commit_count=0,
                )

            saturation_audit._preserve_iteration_control_state(
                coordinator,
                iteration=1,
                status="interrupted",
                semantic_commit_count=0,
            )
            saturation_audit._restore_baseline_control_state(coordinator)
            self.assertTrue((workspace / ".promin" / "state").is_dir())

    def test_no_degradation_uses_candidate_binding_without_legacy_closure(self) -> None:
        artifact_parameters = inspect.signature(no_degradation._artifact_binding).parameters
        run_parameters = inspect.signature(no_degradation.run).parameters
        self.assertIn("candidate_binding", artifact_parameters)
        self.assertIn("candidate_binding", run_parameters)
        self.assertNotIn("implementation_closure_manifest", artifact_parameters)
        self.assertNotIn("implementation_closure_manifest", run_parameters)

    def test_physical_test_is_marked_and_never_skip_guarded(self) -> None:
        source = (PACKAGE_ROOT / "tests" / "test_search_scale.py").read_text(encoding="utf-8")
        physical = source[source.index("class SearchScalePhysicalTests") - 160 :]
        self.assertIn("@pytest.mark.scale", physical)
        self.assertNotIn("skipUnless", physical)

    def test_memory_and_storage_amplification_are_not_conflated(self) -> None:
        payload, measurement, samples = saturation._measure_rss(
            lambda: bytearray(1024 * 1024)
        )
        self.assertEqual(len(payload), 1024 * 1024)
        self.assertGreater(measurement["baseline_bytes"], 0)
        self.assertGreaterEqual(measurement["peak_bytes"], measurement["baseline_bytes"])
        self.assertGreaterEqual(len(samples), 2)
        self.assertEqual(samples[0]["rss_bytes"], measurement["baseline_bytes"])
        self.assertEqual(
            max(sample["rss_bytes"] for sample in samples),
            measurement["peak_bytes"],
        )
        self.assertTrue(
            all(sample["elapsed_ns"] >= 0 for sample in samples)
        )
        source = (TOOLS / "promin_saturation.py").read_text(encoding="utf-8")
        self.assertIn(
            '_field(first_rebuild, "inventory_projection_amplification", -1.0)',
            source,
        )
        self.assertNotIn(
            '_field(first_rebuild, "inventory_memory_amplification", -1.0)',
            source,
        )

    def test_physical_recipe_requires_bounded_canonical_real_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            state = workspace / ".promin" / "state"
            state.mkdir(parents=True)
            tool = self._fresh_state_fixture()
            value = {
                "record_type": "PhysicalCorpusRecipe",
                "recipe": tool._PHYSICAL_CORPUS_RECIPE,
                "file_count": 100_000,
                "representative_classes": list(tool._REPRESENTATIVE_PHRASES),
                "content_probe_stride": 257,
                "hostile_probe_stride": 509,
            }
            recipe = state / "physical-corpus.json"
            recipe.write_text(json.dumps(value, indent=2), encoding="utf-8")
            with self.assertRaisesRegex(saturation_audit.AuditError, "not canonical"):
                saturation_audit._capture_physical_recipe(
                    workspace,
                    tool,
                    files=100_000,
                )

            external = Path(temporary) / "external-recipe.json"
            external.write_bytes(
                (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
                    "utf-8"
                )
            )
            recipe.unlink()
            try:
                recipe.symlink_to(external)
            except OSError:
                return
            with self.assertRaisesRegex(
                saturation_audit.AuditError,
                "recipe cannot be captured",
            ):
                saturation_audit._capture_physical_recipe(
                    workspace,
                    tool,
                    files=100_000,
                )

    def test_continuation_evidence_reads_runtime_paths_after_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / ".promin" / "state" / "continuations"
            root.mkdir(parents=True)
            (root / "baseline.json").write_bytes(b"baseline")
            baseline = set(saturation._continuation_state_files(workspace))
            payload = b'{"cursor":1}'
            (root / "current.json").write_bytes(payload)

            rows = saturation._continuation_state_rows(
                workspace,
                baseline_files=baseline,
            )

            self.assertEqual(
                rows,
                [
                    {
                        "path": "current.json",
                        "sha256": saturation._sha256_bytes(payload),
                        "bytes": len(payload),
                    }
                ],
            )


if __name__ == "__main__":
    unittest.main()
