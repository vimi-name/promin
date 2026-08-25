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
    _validate_saturation_raw_artifacts,
    _validate_saturation_runtime_bindings,
    release_evidence_invocation,
    validate_saturation_evidence,
)
import promin.evidence as evidence


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
    def test_exact_temporary_fixture_reaches_real_release_evidence_validator(self) -> None:
        """A canonical exact physical fixture must cross the real release boundary."""
        verification, temporary = self._build_exact_release_fixture()
        fixture_root = Path(temporary.name)
        try:
            with mock.patch(
                "promin.evidence.validate_standard_release_candidate_binding",
                return_value=verification["artifact_binding"]["standard_candidate_binding"],
            ):
                validated = validate_saturation_evidence(
                    verification,
                    candidate_binding={},
                    source_path=fixture_root / "saturation-result" / "saturation-result.json",
                    evidence_root=fixture_root / "saturation-result",
                    require_pass=True,
                )
            self.assertEqual(validated["status"], "pass")
            for field in (
                "acceptance_pass",
                "product_acceptance_pass",
                "pass_credit",
                "public_release_approved",
            ):
                self.assertIs(validated[field], False)
        finally:
            temporary.cleanup()

    @staticmethod
    def _build_exact_release_fixture(
        query_rows: list[dict] | None = None,
    ) -> tuple[dict, tempfile.TemporaryDirectory[str]]:
        """Build exact raw evidence while retaining the real verifier boundary.

        ``query_rows`` deliberately accepts the producer observation shape.  This
        keeps this expensive physical fixture reusable by the rich continuation
        trace regression without replacing any raw parser or recomputation path.
        """
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        output = root / "saturation-result"
        raw_dir = output / "raw"
        raw_dir.mkdir(parents=True)
        candidate_digest = "c" * 64
        activation_digest = "a" * 64
        implementation_digest = "b" * 64

        inventory_digest = hashlib.sha256()
        bucket_hashes = [hashlib.sha256() for _ in range(100)]
        inventory_path = raw_dir / "inventory-stream.jsonl"
        with inventory_path.open("wb") as stream:
            for index in range(100_000):
                bucket = index // 1_000
                row = {
                    "path": f"product/bucket-{bucket:03d}/record-{index:06d}.txt",
                    "digest": "0" * 64,
                    "size": 1,
                    "search_text": "",
                }
                stream.write(canonical_bytes(row))
                identity = canonical_bytes(
                    {key: row[key] for key in ("path", "digest", "size")}
                )
                inventory_digest.update(identity)
                bucket_hashes[bucket].update(identity)
        inventory_identity_digest = inventory_digest.hexdigest()
        aggregates = [
            {
                "bucket_id": f"bucket-{bucket:03d}",
                "relative_prefix": f"product/bucket-{bucket:03d}/",
                "file_count": 1_000,
                "total_bytes": 1_000,
                "identity_digest": bucket_hashes[bucket].hexdigest(),
                "first_path": f"product/bucket-{bucket:03d}/record-{bucket * 1_000:06d}.txt",
                "last_path": f"product/bucket-{bucket:03d}/record-{bucket * 1_000 + 999:06d}.txt",
            }
            for bucket in range(100)
        ]
        aggregate_digest = canonical_digest(aggregates)
        inventory_payload = inventory_path.read_bytes()

        relation_path = raw_dir / "physical-relation-evidence.jsonl"
        with relation_path.open("wb") as stream:
            for relation_index in range(198_999):
                target_index = relation_index % 100_000
                bucket = target_index // 1_000
                target_path = f"product/bucket-{bucket:03d}/record-{target_index:06d}.txt"
                stream.write(
                    canonical_bytes(
                        {
                            "record_type": "PhysicalRelationEvidence",
                            "relation_id": f"physical-relation:{relation_index:06d}",
                            "kind": "READS",
                            "source_type": "PhysicalBucket",
                            "source_id": f"bucket-{bucket:03d}",
                            "target_type": "PhysicalInventoryRecord",
                            "target_id": "artifact:file:"
                            + hashlib.sha256(target_path.encode("utf-8")).hexdigest()[:48],
                            "target_path": target_path,
                            "target_digest": "0" * 64,
                            "target_size": 1,
                            "bucket": bucket,
                            "activation_digest": activation_digest,
                            "candidate_digest": candidate_digest,
                            "inventory_identity_digest": inventory_identity_digest,
                            "physical_evidence": True,
                            "semantic_record": False,
                        }
                    )
                )
        relation_payload = relation_path.read_bytes()
        relation_sha256 = hashlib.sha256(relation_payload).hexdigest()
        relation_summary = {
            "record_type": "PhysicalRelationEvidenceSummary",
            "evidence_class": "harness_generated_physical",
            "product_acceptance_credit": False,
            "relation_count": 198_999,
            "relation_id_first": "physical-relation:000000",
            "relation_id_last": "physical-relation:198998",
            "physical_target_cardinality": 100_000,
            "inventory_identity_digest": inventory_identity_digest,
            "candidate_digest": candidate_digest,
            "activation_digest": activation_digest,
            "bytes": len(relation_payload),
            "sha256": relation_sha256,
        }

        if query_rows is None:
            trace = saturation._raw_page_trace(
                {
                    "atoms": {"artifact:file:needle", "task:saturation:needle"},
                    "page_digests": ["1" * 64, "2" * 64],
                    "page_identity_digests": ["a" * 64, "b" * 64],
                    "pages": 2,
                    "continuation_pages": 1,
                    "first_truncated": True,
                    "initial_expiry": "2026-08-25T10:01:00Z",
                    "expiry_monotonic": True,
                    "renewals": [
                        {
                            "cursor": 1,
                            "old_expiry": "2026-08-25T10:01:00Z",
                            "new_expiry": "2026-08-25T10:02:00Z",
                            "renewed_at": "2026-08-25T10:00:30Z",
                        }
                    ],
                    "maximum_token_bytes": 32,
                    "identity_digests": {"a" * 64, "b" * 64},
                    "selected_closure_complete": True,
                }
            )
            first_pages = {
                "broad": {
                    "refinement_required": True,
                    "refinement_hints": ["narrow"],
                    "unselected_matches_traversable": False,
                },
                "content-high-cardinality": {
                    "refinement_required": True,
                    "selected_seed_count": 1,
                    "unselected_matches_traversable": False,
                    "entities": [{"id": "artifact:file:needle"}],
                },
                "content-probe": {"entities": [{"id": "artifact:file:needle"}]},
                "exact-artifact": {"entities": [{"id": "query:exact-artifact"}]},
                "exact-semantic": {"entities": [{"id": "query:exact-semantic"}]},
                "hostile-content": {"entities": [{"id": "artifact:file:needle"}]},
                "hostile-exact": {"entities": [{"id": "task:saturation:needle"}]},
                "miss": {
                    "entities": [],
                    "relations": [],
                    "evidence": [],
                    "selected_seed_count": 0,
                    "refinement_required": False,
                    "truncated": False,
                    "silent_truncation": False,
                },
                "forced-continuation": {"entities": [{"id": "artifact:file:needle"}]},
            }
            query_rows = []
            query_classes = [
                name
                for name, count in {
                    "broad": 60,
                    "content-high-cardinality": 60,
                    "content-probe": 60,
                    "exact-artifact": 60,
                    "exact-semantic": 60,
                    "forced-continuation": 120,
                    "hostile-content": 60,
                    "hostile-exact": 60,
                    "miss": 60,
                }.items()
                for _ in range(count)
            ]
            for index, query_class in enumerate(query_classes):
                query = (
                    "query:exact-artifact"
                    if query_class == "exact-artifact"
                    else "query:exact-semantic"
                    if query_class == "exact-semantic"
                    else "query:miss"
                    if query_class == "miss"
                    else f"query:{query_class}"
                )
                page = first_pages[query_class]
                query_rows.append(
                    {
                        "record_type": "SaturationQueryObservation",
                        "index": index,
                        "query_class": query_class,
                        "query": query,
                        "depth": index % 12 + 1,
                        "elapsed_ms": 1.0,
                        "first_page": page,
                        "first_page_digest": canonical_digest(page),
                        "class_result_verified": True,
                        "reference": trace,
                        "forced": (
                            {**trace, "union_matches_reference": True}
                            if query_class == "forced-continuation"
                            else None
                        ),
                    }
                )
        else:
            query_rows = [dict(row) for row in query_rows]
        query_rows = list(query_rows)
        query_payload = b"".join(canonical_bytes(row) for row in query_rows)
        query_path = raw_dir / "query-results.jsonl"
        query_path.write_bytes(query_payload)
        recomputed = [
            evidence._recompute_raw_query_result(row, expected_index=index, top_k=1)
            for index, row in enumerate(query_rows)
        ]
        query_mix: dict[str, int] = {}
        depth_counts: dict[str, int] = {}
        class_depths: dict[str, set[int]] = {}
        class_latencies: dict[str, list[float]] = {}
        latencies: list[float] = []
        page_digests: list[str] = []
        total_pages = continuation_pages = explicit_truncations = 0
        maximum_token_bytes = selected_closure_chains = forced_chains = forced_union_matches = 0
        forced_depths: set[int] = set()
        class_checks: dict[str, list[bool]] = {}
        for row in recomputed:
            query_class = row["query_class"]
            depth = row["depth"]
            query_mix[query_class] = query_mix.get(query_class, 0) + 1
            depth_counts[str(depth)] = depth_counts.get(str(depth), 0) + 1
            class_depths.setdefault(query_class, set()).add(depth)
            class_latencies.setdefault(query_class, []).append(row["elapsed_ms"])
            class_checks.setdefault(query_class, []).append(row["class_verified"])
            latencies.append(row["elapsed_ms"])
            reference = row["reference"]
            page_digests.extend(reference["page_digests"])
            total_pages += reference["pages"]
            continuation_pages += reference["continuation_pages"]
            explicit_truncations += int(reference["first_truncated"])
            maximum_token_bytes = max(maximum_token_bytes, reference["maximum_token_bytes"])
            selected_closure_chains += 1
            if row["forced"] is not None:
                forced_chains += 1
                forced_union_matches += 1
                forced_depths.add(depth)
                forced = row["forced"]
                page_digests.extend(forced["page_digests"])
                total_pages += forced["pages"]
                continuation_pages += forced["continuation_pages"]
                explicit_truncations += int(forced["first_truncated"])
                maximum_token_bytes = max(maximum_token_bytes, forced["maximum_token_bytes"])
                selected_closure_chains += 1
        nearest = lambda values, quantile: sorted(values)[max(0, int(__import__("math").ceil(len(values) * quantile)) - 1)]
        query_mix = dict(sorted(query_mix.items()))
        depth_counts = dict(sorted(depth_counts.items(), key=lambda item: int(item[0])))
        query_summary = {
            "actual_runtime_queries": len(query_rows),
            "query_mix": query_mix,
            "depth_counts": depth_counts,
            "depth_min": min(int(depth) for depth in depth_counts),
            "depth_max": max(int(depth) for depth in depth_counts),
            "query_class_depths": {
                name: sorted(values) for name, values in sorted(class_depths.items())
            },
            "query_class_latency_ms": {
                name: {
                    "count": len(values),
                    "p50": nearest(values, 0.50),
                    "p95": nearest(values, 0.95),
                    "p99": nearest(values, 0.99),
                }
                for name, values in sorted(class_latencies.items())
            },
            "p50_ms": nearest(latencies, 0.50),
            "p95_ms": nearest(latencies, 0.95),
            "p99_ms": nearest(latencies, 0.99),
            "result_digest": canonical_digest(page_digests),
            "pages_observed": total_pages,
            "continuations_checked": continuation_pages,
            "explicit_truncations": explicit_truncations,
            "maximum_continuation_token_bytes": maximum_token_bytes,
            "selected_closure_chains": selected_closure_chains,
            "forced_continuation_chains": forced_chains,
            "forced_union_matches": forced_union_matches,
            "forced_depths": sorted(forced_depths),
            "runtime_query_budget": {"top_k": 1},
            "forced_query_budget": {"top_k": 1},
            "continuation_state": {
                "files": 0,
                "maximum_bytes": 0,
                "total_bytes": 0,
                "preexisting_files_excluded": 0,
            },
            "continuation_union_completeness": 1.0,
            "selected_closure_union_completeness": 1.0,
            "continuation_union_complete": True,
            "silent_truncations": 0,
            "continuation_token_overhead_at_most_10_percent": True,
            "broad_query_refinement_required": all(class_checks.get("broad", [])),
            "high_cardinality_terms_verified": all(class_checks.get("content-high-cardinality", [])),
            "content_search_verified": all(class_checks.get("content-probe", [])),
            "miss_behavior_verified": all(class_checks.get("miss", [])),
            "hostile_proxy_content_verified": all(class_checks.get("hostile-content", [])) and all(class_checks.get("hostile-exact", [])),
            "exact_artifact_search_verified": all(class_checks.get("exact-artifact", [])),
            "mixed_query_classes_complete": True,
            "promin_service_search_calls": len(query_rows),
            "promin_service_continuation_calls": continuation_pages,
            "runtime_ingress": "fixture",
            "immutable_query_phase": {
                "operation_budget": 12_240_612,
                "operations": 1,
                "within_budget": True,
                "close_elapsed_ms": 0.0,
                "product_acceptance_credit": False,
            },
        }

        process_samples = {
            "record_type": "SaturationProcessSamples",
            "sample_interval_ms": 50,
            "lifetime_peak_rss_bytes": 2,
            "phases": [
                {
                    "phase": phase,
                    "summary": {"baseline_bytes": 1, "peak_bytes": 2, "incremental_peak_bytes": 1},
                    "samples": [{"elapsed_ns": 0, "rss_bytes": 1}, {"elapsed_ns": 1, "rss_bytes": 2}],
                }
                for phase in ("inventory", "projection")
            ],
        }
        process_path = raw_dir / "process-samples.json"
        process_path.write_bytes(canonical_bytes(process_samples))
        phase_path = raw_dir / "phase-log.jsonl"
        phase_rows = [
            {"order": index, "phase": phase, "elapsed_ms": 1000 if phase == "semantic-ingestion" else 0, **({"status": "pass", "process_exit_code": 0, "invocation_exit_code": 0} if phase == "result" else {})}
            for index, phase in enumerate(("physical-generation", "inventory", "semantic-ingestion", "projection", "runtime-queries", "result"), start=1)
        ]
        phase_path.write_bytes(b"".join(canonical_bytes(row) for row in phase_rows))
        continuation_path = raw_dir / "continuation-state-manifest.jsonl"
        continuation_path.write_bytes(b"")

        semantic_ingestion = {
            "record_type": "SemanticIngestionMetrics",
            "elapsed_seconds": 1.0,
            "commit_count": 137,
            "changed_records": 137,
            "physical_payload_bytes": 274,
            "bytes_per_changed_record": 2.0,
            "p95_ms": 2.0,
            "p99_ms": 2.0,
            "checkpoint_count": 2,
            "checkpoint_writes": 1,
            "observations": [
                {
                    "sequence": sequence,
                    "phase": "semantic-corpus"
                    if sequence <= 132
                    else "physical-bucket-controls",
                    "command_id": f"fixture:commit:{sequence:03d}",
                    "batch_digest": f"{sequence:064x}",
                    "duration_ms": 1.0 if sequence == 1 else 2.0,
                    "changed_records": 1,
                    "physical_payload_bytes": 2,
                    "bytes_per_changed_record": 2.0,
                    "checkpoint_written": sequence == 2,
                    "checkpoint_count": 1 if sequence == 1 else 2,
                    "checkpoint_bytes": 1 if sequence == 2 else 0,
                    "checkpoint_tail_batches": 0,
                    "checkpoint_tail_bytes": 0,
                }
                for sequence in range(1, 138)
            ],
        }
        semantic_ingestion["result_digest"] = canonical_digest(semantic_ingestion["observations"])
        operation_resources = {
            "inventory_stage_rss": {"baseline_bytes": 1, "peak_bytes": 2, "incremental_peak_bytes": 1},
            "projection_stage_rss": {"baseline_bytes": 1, "peak_bytes": 2, "incremental_peak_bytes": 1},
            "inventory_pipeline_peak_rss_bytes": 2,
            "inventory_pipeline_incremental_peak_bytes": 1,
            "inventory_absolute_rss_amplification": round(2 / len(inventory_payload), 9),
            "inventory_incremental_memory_amplification": round(1 / len(inventory_payload), 9),
            "memory_amplification_metric": {
                "metric_id": "inventory-incremental-peak-over-stream-bytes", "numerator": "inventory_pipeline_incremental_peak_bytes",
                "denominator": "inventory_stream_bytes", "numerator_bytes": 1, "denominator_bytes": len(inventory_payload),
                "ratio": round(1 / len(inventory_payload), 9), "threshold_max": 32.0, "within_threshold": True,
            },
            "peak_rss_bytes": 2,
        }
        physical = {
            "files": 100_000, "raw_files": 100_000, "raw_file_proxies": 100_000, "semantic_proxies": 0,
            "physical_artifact_evidence": 100_000, "raw_file_proxy_ratio": 1.0, "synthetic_task_count": 0,
            "synthetic_task_ratio": 0.0, "inventory_relations": 0, "relations": 28,
            "physical_relation_evidence_count": 198_999, "semantic_control_records": 165,
            "semantic_control_envelopes": 137, "semantic_control_record_limit": 256, "vcs_tree_files": 100_000,
            "generation_elapsed_ms": 1, "reused_product": False, "synthetic_tasks": [],
            "vcs_commit": "d" * 40, "vcs_tree_digest": "e" * 64, "vcs_provider_version": "fixture-1",
            "physical_relation_evidence": relation_summary,
        }
        corpus = {
            "record_type": "SaturationSemanticCorpus", "generation": "explicit-authorized-command-events", "harness_generated": True,
            "product_acceptance_credit": False, "task_count": 132, "relation_count": 28, "depths": list(range(1, 13)), "high_fanout": 16,
            "conflicting_exact_id_text": True, "query_ids": ["query:fixture", "query:continuation"], "continuation_query_ids": ["query:continuation"],
            "search_fixture": {"task_count": 32, "relation_count": 28, "depths": list(range(1, 13)), "high_fanout": 16},
            "physical_bucket_control": {
                "record_type": "PhysicalBucketControlManifest", "generation": "streamed-inventory-aggregate", "candidate_digest": candidate_digest,
                "inventory_identity_digest": inventory_identity_digest, "bucket_count": 100, "files_per_bucket": 1_000, "file_count": 100_000,
                "aggregate_digest": aggregate_digest, "cardinality": {"minimum": 1_000, "maximum": 1_000, "distinct": 1},
                "semantic_control_record_count": 100, "semantic_control_envelope_count": 100, "semantic_control_record_limit": 256,
            },
            "reused": False, "search_fixture_reused": False, "physical_bucket_control_reused": False,
        }
        physical["explicit_semantic_corpus"] = corpus
        projection = {
            "entity_count": 137, "entity_type_counts": {"Task": 132, "Grant": 4, "Candidate": 1}, "relation_count": 28,
            "initial_inventory_passes": 1, "initial_product_passes": 0, "rebuild_inventory_passes": 1, "rebuild_product_passes": 0,
            "equal_semantic_digest": True, "implementation_closure_digest": implementation_digest, "database_bytes": 8192,
            "elapsed_ms": 1.0, "inventory_integrity": True, "inventory_projection_amplification": 2.0, "projection_amplification": 2.0,
            "semantic_digest": "f" * 64, "semantic_inflation": 3.0,
        }
        inventory = {"candidate_digest": candidate_digest, "elapsed_ms": 1.0, "entries": 100_000, "passes": 1, "snapshot": {"digest": "1" * 64}, "stream_bytes": len(inventory_payload)}
        platform_identity = {
            "system": "windows", "release": "10.0.0", "machine": "AMD64", "python_implementation": "CPython", "python_version": "3.14.0",
            "python_executable_sha256": "sha256:" + "1" * 64, "sqlite_version": "3.45.1", "profile_key": "windows-AMD64-cpython-3.14",
        }
        platform_binding = {**platform_identity, "binding_digest": "sha256:" + canonical_digest(platform_identity)}
        observed = {"p50_ms": query_summary["p50_ms"], "p95_ms": query_summary["p95_ms"], "p99_ms": query_summary["p99_ms"], "peak_rss_bytes": 2, "database_bytes": 8192, "projection_amplification": 2.0, "semantic_inflation": 3.0, "commit_p95_ms": 2.0, "commit_p99_ms": 2.0, "commit_bytes_per_changed_record": 2.0, "runtime_checkpoint_count": 2, "runtime_checkpoint_writes": 1, "semantic_ingestion_seconds": 1.0, "runtime_checkpoint_writes": 1}
        thresholds = {"p50_ms_max": 100, "p95_ms_max": 150, "p99_ms_max": 500, "peak_rss_bytes_max": 805306368, "database_bytes_max": 402653184, "projection_amplification_max": 20, "semantic_inflation_max": 3.25, "commit_p95_ms_max": 500, "commit_p99_ms_max": 1000, "commit_bytes_per_changed_record_max": 32768, "runtime_checkpoint_count_max": 24, "semantic_ingestion_seconds_max": 600}
        performance_predicates = {name: observed[key] <= thresholds[limit] for name, (key, limit) in {"p50_within_profile": ("p50_ms", "p50_ms_max"), "p95_within_profile": ("p95_ms", "p95_ms_max"), "p99_within_profile": ("p99_ms", "p99_ms_max"), "peak_rss_within_profile": ("peak_rss_bytes", "peak_rss_bytes_max"), "database_within_profile": ("database_bytes", "database_bytes_max"), "projection_amplification_within_profile": ("projection_amplification", "projection_amplification_max"), "semantic_inflation_within_profile": ("semantic_inflation", "semantic_inflation_max"), "commit_p95_within_profile": ("commit_p95_ms", "commit_p95_ms_max"), "commit_p99_within_profile": ("commit_p99_ms", "commit_p99_ms_max"), "commit_bytes_per_changed_record_within_profile": ("commit_bytes_per_changed_record", "commit_bytes_per_changed_record_max"), "runtime_checkpoint_count_within_profile": ("runtime_checkpoint_count", "runtime_checkpoint_count_max"), "semantic_ingestion_within_profile": ("semantic_ingestion_seconds", "semantic_ingestion_seconds_max")}.items()}
        performance = {"profile_id": "portable-local-v1", "platform_binding": platform_binding, "compatible_platforms": ["linux", "windows"], "requires_same_runner_no_degradation": True, "observed": observed, "thresholds": thresholds, "predicates": performance_predicates, "all_within_profile": all(performance_predicates.values())}
        contract_predicates = {"broad_query_refinement_required": True, "content_search_verified": True, "continuation_state_bytes_at_most_16384": True, "continuation_token_bytes_at_most_256": True, "continuation_token_overhead_at_most_10_percent": True, "continuation_union_complete": True, "exact_artifact_binding_unchanged": True, "exact_artifact_search_verified": True, "high_cardinality_terms_verified": True, "hostile_proxy_content_verified": True, "inventory_incremental_memory_amplification_at_most_32": True, "inventory_passes_exact": True, "miss_behavior_verified": True, "mixed_query_classes_complete": True, "physical_bucket_cardinality_exact": True, "physical_relation_evidence_count_exact": True, "physical_relation_evidence_exact": True, "raw_file_proxy_ratio_exact": True, "rebuild_digest_equal": True, "rebuild_product_passes_zero": True, "runtime_depths_1_through_12": True, "runtime_queries_exact": True, "runtime_query_budget_bounded": True, "semantic_control_envelopes_bounded": True, "semantic_control_records_bounded": True, "semantic_relation_count_bounded_exact": True, "selected_closure_union_complete": True, "semantic_commit_count_exact": True, "silent_truncations_zero": True, "synthetic_task_ratio_zero": True}

        raw_specs = {
            "inventory-stream": ("raw/inventory-stream.jsonl", "application/x-ndjson", inventory_payload, 100_000),
            "physical-relation-evidence": ("raw/physical-relation-evidence.jsonl", "application/x-ndjson", relation_payload, 198_999),
            "query-results": ("raw/query-results.jsonl", "application/x-ndjson", query_payload, len(query_rows)),
            "process-samples": ("raw/process-samples.json", "application/json", process_path.read_bytes(), 4),
            "continuation-state-manifest": ("raw/continuation-state-manifest.jsonl", "application/x-ndjson", b"", 0),
            "phase-log": ("raw/phase-log.jsonl", "application/x-ndjson", phase_path.read_bytes(), 6),
        }
        operation = {"record_type": "SaturationOperationMetrics", "evidence_class": "harness_generated", "product_acceptance_credit": False, "status": "pass", "process_exit_code": 0, "invocation_exit_code": 0, "physical": physical, "inventory": inventory, "projection": projection, "search": query_summary, "resources": operation_resources, "performance": performance, "contract_predicates": contract_predicates, "physical_relation_evidence": relation_summary, "semantic_ingestion": semantic_ingestion}
        operation_payload = canonical_bytes(operation)
        operation_path = raw_dir / "operation-metrics.json"
        operation_path.write_bytes(operation_payload)
        raw_specs["operation-metrics"] = ("raw/operation-metrics.json", "application/json", operation_payload, 1)
        artifacts = [{"role": role, "path": relative, "media_type": media, "sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload), "records": records} for role, (relative, media, payload, records) in raw_specs.items()]
        raw_manifest_identity = {"record_type": "SaturationRawArtifactManifest", "path_scope": "saturation-result-directory", "evidence_class": "harness_generated", "product_acceptance_credit": False, "artifacts": artifacts, "artifact_count": 7, "inventory_stream_digest": hashlib.sha256(inventory_payload).hexdigest(), "inventory_identity_digest": inventory_identity_digest}
        raw_manifest = {**raw_manifest_identity, "manifest_digest": canonical_digest(raw_manifest_identity)}
        verification = {"record_type": "SaturationEvidence", "status": "pass", "candidate_binding_digest": candidate_digest, "artifact_binding_unchanged": True, "workspace_initialization": {"record_type": "SaturationWorkspaceInitialization", "status": "reused", "project_id": "promin-physical-saturation", "activation_digest": activation_digest, "implementation_closure_digest": implementation_digest, "product_tree_scans": 0, "init_record_count": 5, "init_records": ["activation.json", "authority.json", "project.json", "standards.json", "technologies.json"], "snapshot_provider_id": "git-filesystem-inventory", "snapshot_provider_version": "2.45.1"}, "runtime_binding": {"activation_digest": activation_digest, "implementation_closure_digest": implementation_digest, "platform_binding_digest": platform_binding["binding_digest"]}, "physical_files": 100_000, "physical_relation_evidence": relation_summary, "core_valid_relations": 198_999, "runtime_queries": len(query_rows), "silent_truncations": 0, "selected_closure_union_completeness": 1.0, "memory_amplification_at_most_32": True, "core_valid_relations_exact_198999": True, "broad_query_refinement_required": True, "high_cardinality_terms_verified": True, "content_search_verified": True, "miss_behavior_verified": True, "hostile_proxy_content_verified": True, "exact_artifact_search_verified": True, "mixed_query_classes_complete": True, "continuation_token_bytes_at_most_256": True, "continuation_state_bytes_at_most_16384": True, "continuation_token_overhead_at_most_10_percent": True, "pass_credit": False, "physical": physical, "inventory": inventory, "projection": projection, "query_authorization": {"subject_id": "fixture-reader", "grant_id": "grant:fixture-reader", "claim_digest": "1" * 64, "capability_id": "projection.read", "scope": [{"resource": "promin-physical-saturation"}], "activation_digest": activation_digest, "expires_at": "2026-08-25T11:00:00Z"}, "search": query_summary, "resources": operation_resources, "performance": performance, "contract_predicates": contract_predicates, "raw_artifact_manifest": raw_manifest, "current_release_regression": {"before": {"eligibility": False}, "after": {"eligibility": False}, "eligibility_remained_false": True, "historical_decision_preserved": True}, "claim_scope": "diagnostic exact physical saturation fixture only", "acceptance_pass": False, "product_acceptance_pass": False, "public_release_approved": False}

        candidate = {"record_type": "StandardReleaseCandidateBinding", "standard_name": "promin", "version": "1.0.0-alpha.4", "archive_sha256": "d" * 64, "archive_bytes": 1, "archive_member_manifest_digest": "e" * 64, "package_manifest_digest": "f" * 64, "checksums_digest": "1" * 64, "core_bundle_digest": "2" * 64, "preset_digest": "3" * 64, "package_tool_digest": "4" * 64, "validator_digest": "5" * 64, "test_manifest_digest": "6" * 64, "portable_implementation_closure_digest": implementation_digest, "evidence_tool_digests": {path: "7" * 64 for path in ("tools/generate_human.py", "tools/promin_no_degradation.py", "tools/promin_package.py", "tools/promin_saturation.py", "tools/promin_saturation_audit.py", "tools/promin_validate.py")}}
        # The release fixture intentionally isolates only the standard binding
        # boundary; all downstream checks still consume this exact digest.
        candidate["candidate_binding_digest"] = candidate_digest
        artifact_tool_paths = {
            "tools/promin_no_degradation.py",
            "tools/promin_package.py",
            "tools/promin_saturation.py",
            "tools/promin_saturation_audit.py",
            "tools/promin_validate.py",
        }
        artifact_binding = {"record_type": "ExactArtifactBinding", "protocol_version": "promin-evidence-v1", "candidate_binding_digest": candidate_digest, "archive": {"bytes": 1, "sha256": "sha256:" + candidate["archive_sha256"], "manifest_member_bytes_match": True, "member_count": 1, "name": "promin-1.0.0-alpha.4.zip"}, "checksums_sha256": "sha256:" + candidate["checksums_digest"], "core_bundle_digest": "sha256:" + candidate["core_bundle_digest"], "package_manifest_sha256": "sha256:" + candidate["package_manifest_digest"], "preset": {"path": "presets/semantic-standard.json", "sha256": "sha256:" + candidate["preset_digest"]}, "platform": platform_binding, "standard_candidate_binding": candidate, "tools": [{"path": path, "sha256": "sha256:" + candidate["evidence_tool_digests"][path], "bytes": 1, "version": "1.0.0"} for path in sorted(artifact_tool_paths)]}
        artifact_binding["binding_digest"] = "sha256:" + canonical_digest({key: value for key, value in artifact_binding.items() if key != "binding_digest"})
        verification["artifact_binding"] = artifact_binding
        verification["producer"] = {"tool_path": "tools/promin_saturation.py", "tool_sha256": candidate["evidence_tool_digests"]["tools/promin_saturation.py"], "tool_version": candidate["version"]}
        verification["invocation"] = release_evidence_invocation(invocation_id="saturation:fixture", operation="physical-saturation", arguments={"files": 100_000, "queries": len(query_rows)}, started_at="2026-08-25T10:00:00Z", completed_at="2026-08-25T10:00:01Z", exit_code=0, platform_binding=platform_binding["binding_digest"][7:])
        verification = evidence.seal_release_evidence(verification)
        (output / "saturation-result.json").write_bytes(canonical_bytes(verification))
        return verification, temporary

    def test_real_rich_trace_survives_raw_release_recomputation(self) -> None:
        """Keep the release raw-query recomputation bound to producer-shaped traces."""
        internal_chain = {
            "atoms": {"artifact:file:needle", "task:saturation:needle"},
            "page_digests": ["1" * 64, "2" * 64],
            "page_identity_digests": ["a" * 64, "b" * 64],
            "pages": 2,
            "continuation_pages": 1,
            "first_truncated": True,
            "initial_expiry": "2026-08-25T10:01:00Z",
            "expiry_monotonic": True,
            "renewals": [
                {
                    "cursor": 1,
                    "old_expiry": "2026-08-25T10:01:00Z",
                    "new_expiry": "2026-08-25T10:02:00Z",
                    "renewed_at": "2026-08-25T10:00:30Z",
                }
            ],
            "maximum_token_bytes": 32,
            "identity_digests": {"a" * 64, "b" * 64},
            "selected_closure_complete": True,
        }
        producer_trace = saturation._raw_page_trace(internal_chain)
        forced_trace = dict(producer_trace)
        forced_trace["union_matches_reference"] = True

        first_pages = {
            "broad": {
                "refinement_required": True,
                "refinement_hints": ["narrow"],
                "unselected_matches_traversable": False,
            },
            "content-high-cardinality": {
                "refinement_required": True,
                "selected_seed_count": 1,
                "unselected_matches_traversable": False,
                "entities": [{"id": "artifact:file:needle"}],
            },
            "content-probe": {"entities": [{"id": "artifact:file:needle"}]},
            "exact-artifact": {"entities": [{"id": "query:exact-artifact"}]},
            "exact-semantic": {"entities": [{"id": "query:exact-semantic"}]},
            "hostile-content": {"entities": [{"id": "artifact:file:needle"}]},
            "hostile-exact": {"entities": [{"id": "task:saturation:needle"}]},
            "miss": {
                "entities": [],
                "relations": [],
                "evidence": [],
                "selected_seed_count": 0,
                "refinement_required": False,
                "truncated": False,
                "silent_truncation": False,
            },
            "forced-continuation": {"entities": [{"id": "artifact:file:needle"}]},
        }
        rows = []
        for index, query_class in enumerate(first_pages):
            query = f"query:{query_class}"
            page = first_pages[query_class]
            rows.append(
                {
                    "record_type": "SaturationQueryObservation",
                    "index": index,
                    "query_class": query_class,
                    "query": query,
                    "depth": 1,
                    "elapsed_ms": 1.0,
                    "first_page": page,
                    "first_page_digest": canonical_digest(page),
                    "class_result_verified": True,
                    "reference": producer_trace,
                    "forced": forced_trace if query_class == "forced-continuation" else None,
                }
            )

        payload = b"".join(canonical_bytes(row) for row in rows)
        with tempfile.TemporaryDirectory() as temporary:
            raw_path = Path(temporary) / "query-results.jsonl"
            raw_path.write_bytes(payload)
            parsed_rows = evidence._parse_raw_jsonl(
                payload, "query results", max_records=100_000
            )
            self.assertEqual(len(parsed_rows), len(rows))
            recomputed = [
                evidence._recompute_raw_query_result(
                    row, expected_index=index, top_k=1
                )
                for index, row in enumerate(parsed_rows)
            ]
            self.assertEqual(recomputed[-1]["reference"], producer_trace)
            self.assertEqual(recomputed[-1]["forced"], producer_trace)
            self.assertTrue(raw_path.exists())

        # Exercise the real release-evidence validator's flag gate. Candidate
        # binding is the only external boundary isolated here; raw parsing,
        # recomputation, and shared trace validation above remain unmocked.
        release_state, _ = self._exact_saturation_evidence_fixture()
        with mock.patch(
            "promin.evidence.validate_standard_release_candidate_binding",
            return_value={"candidate_binding_digest": "c" * 64},
        ):
            with self.assertRaises(EvidenceError):
                validate_saturation_evidence(
                    release_state,
                    candidate_binding={},
                    source_path=Path("saturation-result.json"),
                    evidence_root=Path("evidence"),
                    require_pass=False,
                )
        for field in (
            "acceptance_pass",
            "product_acceptance_pass",
            "pass_credit",
            "public_release_approved",
        ):
            self.assertIs(release_state[field], False)

    @staticmethod
    def _exact_saturation_evidence_fixture() -> tuple[dict, dict]:
        corpus = {
            "record_type": "SaturationSemanticCorpus",
            "generation": "explicit-authorized-command-events",
            "harness_generated": True,
            "product_acceptance_credit": False,
            "task_count": 132,
            "relation_count": 28,
            "depths": list(range(1, 13)),
            "high_fanout": 16,
            "conflicting_exact_id_text": True,
            "search_fixture": {
                "task_count": 32,
                "relation_count": 28,
                "depths": list(range(1, 13)),
                "high_fanout": 16,
            },
            "query_ids": ["query:fixture", "query:continuation"],
            "continuation_query_ids": ["query:continuation"],
            "physical_bucket_control": {
                "record_type": "PhysicalBucketControlManifest",
                "generation": "streamed-inventory-aggregate",
                "candidate_digest": "c" * 64,
                "inventory_identity_digest": "e" * 64,
                "bucket_count": 100,
                "files_per_bucket": 1_000,
                "file_count": 100_000,
                "aggregate_digest": "f" * 64,
                "cardinality": {"minimum": 1_000, "maximum": 1_000, "distinct": 1},
                "semantic_control_record_count": 100,
                "semantic_control_envelope_count": 100,
                "semantic_control_record_limit": 256,
            },
            "reused": False,
            "search_fixture_reused": False,
            "physical_bucket_control_reused": False,
        }
        semantic_ingestion = {
            "commit_count": 137,
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
            "continuation_state": {
                "files": 1,
                "maximum_bytes": 16_384,
                "total_bytes": 16_384,
                "preexisting_files_excluded": 0,
            },
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
            "exact_artifact_binding_unchanged": True,
            "exact_artifact_search_verified": True,
            "high_cardinality_terms_verified": True,
            "hostile_proxy_content_verified": True,
            "inventory_incremental_memory_amplification_at_most_32": True,
            "inventory_passes_exact": True,
            "miss_behavior_verified": True,
            "mixed_query_classes_complete": True,
            "physical_bucket_cardinality_exact": True,
            "physical_relation_evidence_count_exact": True,
            "physical_relation_evidence_exact": True,
            "raw_file_proxy_ratio_exact": True,
            "semantic_control_records_bounded": True,
            "semantic_control_envelopes_bounded": True,
            "semantic_relation_count_bounded_exact": True,
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
                "inventory": {
                    "candidate_digest": "c" * 64,
                    "entries": 100_000,
                    "passes": 1,
                },
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
                    "semantic_proxies": 0,
                    "physical_artifact_evidence": 100_000,
                    "raw_file_proxy_ratio": 1.0,
                    "synthetic_task_count": 0,
                    "synthetic_task_ratio": 0.0,
                    "inventory_relations": 0,
                    "relations": 28,
                    "physical_relation_evidence_count": 198_999,
                    "semantic_control_records": 165,
                    "semantic_control_envelopes": 137,
                    "semantic_control_record_limit": 256,
                    "vcs_tree_files": 100_000,
                    "explicit_semantic_corpus": corpus,
                },
                "projection": {
                    "entity_count": 137,
                    "entity_type_counts": {
                        "Task": 132,
                        "Grant": 4,
                        "Candidate": 1,
                    },
                    "relation_count": 28,
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
            "inventory_identity_digest": "e" * 64,
            "physical_bucket_aggregate_digest": "f" * 64,
            "physical_bucket_cardinality": {
                "minimum": 1_000,
                "maximum": 1_000,
                "distinct": 1,
            },
            "physical_relation_evidence": {
                "relation_count": 198_999,
                "target_cardinality": 100_000,
            },
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
            "phase": "physical-bucket-controls",
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
            "phase": "physical-bucket-controls",
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
            "physical": {"physical_relation_evidence": {}},
            "inventory": {},
            "projection": {},
            "search": {},
            "resources": {},
            "performance": {},
            "contract_predicates": {},
            "physical_relation_evidence": {},
        }
        operation = {
            "record_type": "SaturationOperationMetrics",
            "evidence_class": "harness_generated",
            "product_acceptance_credit": False,
            "status": "pass",
            "process_exit_code": 0,
            "invocation_exit_code": 0,
            "physical": {"physical_relation_evidence": {}},
            "inventory": {},
            "projection": {},
            "search": {},
            "resources": {},
            "performance": {},
            "contract_predicates": {},
            "physical_relation_evidence": {},
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

    def test_raw_artifacts_recount_exact_physical_bucket_stream(self) -> None:
        """Exercise the real raw validator over a deterministic 100k-row stream."""
        raw_roles = {
            "inventory-stream": ("raw/inventory-stream.jsonl", "application/x-ndjson"),
            "physical-relation-evidence": (
                "raw/physical-relation-evidence.jsonl",
                "application/x-ndjson",
            ),
            "query-results": ("raw/query-results.jsonl", "application/x-ndjson"),
            "process-samples": ("raw/process-samples.json", "application/json"),
            "continuation-state-manifest": (
                "raw/continuation-state-manifest.jsonl",
                "application/x-ndjson",
            ),
            "phase-log": ("raw/phase-log.jsonl", "application/x-ndjson"),
            "operation-metrics": ("raw/operation-metrics.json", "application/json"),
        }
        with tempfile.TemporaryDirectory() as temporary:
            evidence_root = Path(temporary)
            output = evidence_root / "result"
            (output / "raw").mkdir(parents=True)

            inventory_lines: list[bytes] = []
            inventory_digest = hashlib.sha256()
            bucket_hashes = [hashlib.sha256() for _ in range(100)]
            bucket_bytes = [0] * 100
            for index in range(100_000):
                bucket = index // 1_000
                row = {
                    "path": f"product/bucket-{bucket:03d}/record-{index:06d}.txt",
                    "digest": "0" * 64,
                    "size": 1,
                    "search_text": "",
                }
                payload = canonical_bytes(row)
                identity = canonical_bytes(
                    {key: row[key] for key in ("path", "digest", "size")}
                )
                inventory_lines.append(payload)
                inventory_digest.update(identity)
                bucket_hashes[bucket].update(identity)
                bucket_bytes[bucket] += row["size"]
            inventory_payload = b"".join(inventory_lines)
            aggregates = [
                {
                    "bucket_id": f"bucket-{index:03d}",
                    "relative_prefix": f"product/bucket-{index:03d}/",
                    "file_count": 1_000,
                    "total_bytes": bucket_bytes[index],
                    "identity_digest": bucket_hashes[index].hexdigest(),
                    "first_path": f"product/bucket-{index:03d}/record-{index * 1_000:06d}.txt",
                    "last_path": f"product/bucket-{index:03d}/record-{index * 1_000 + 999:06d}.txt",
                }
                for index in range(100)
            ]
            inventory_identity_digest = inventory_digest.hexdigest()
            aggregate_digest = canonical_digest(aggregates)
            relation_lines: list[bytes] = []
            for relation_index in range(198_999):
                target_index = relation_index % 100_000
                bucket = target_index // 1_000
                target_path = f"product/bucket-{bucket:03d}/record-{target_index:06d}.txt"
                relation_lines.append(
                    canonical_bytes(
                        {
                            "record_type": "PhysicalRelationEvidence",
                            "relation_id": f"physical-relation:{relation_index:06d}",
                            "kind": "READS",
                            "source_type": "PhysicalBucket",
                            "source_id": f"bucket-{bucket:03d}",
                            "target_type": "PhysicalInventoryRecord",
                            "target_id": "artifact:file:" + hashlib.sha256(
                                target_path.encode("utf-8")
                            ).hexdigest()[:48],
                            "target_path": target_path,
                            "target_digest": "0" * 64,
                            "target_size": 1,
                            "bucket": bucket,
                            "activation_digest": "a" * 64,
                            "candidate_digest": "c" * 64,
                            "inventory_identity_digest": inventory_identity_digest,
                            "physical_evidence": True,
                            "semantic_record": False,
                        }
                    )
                )
            relation_payload = b"".join(relation_lines)
            relation_summary = {
                "record_type": "PhysicalRelationEvidenceSummary",
                "evidence_class": "harness_generated_physical",
                "product_acceptance_credit": False,
                "relation_count": 198_999,
                "relation_id_first": "physical-relation:000000",
                "relation_id_last": "physical-relation:198998",
                "physical_target_cardinality": 100_000,
                "inventory_identity_digest": inventory_identity_digest,
                "candidate_digest": "c" * 64,
                "activation_digest": "a" * 64,
                "bytes": len(relation_payload),
                "sha256": hashlib.sha256(relation_payload).hexdigest(),
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
            query_rows: list[bytes] = []
            query_classes = [name for name, count in query_mix.items() for _ in range(count)]
            for index, query_class in enumerate(query_classes):
                query_rows.append(
                    canonical_bytes(
                        {
                            "record_type": "SaturationQueryObservation",
                            "index": index,
                            "query_class": query_class,
                            "query": f"query:{index}",
                            "depth": index % 12 + 1,
                            "elapsed_ms": 1.0,
                            "first_page": {},
                            "first_page_digest": "0" * 64,
                            "class_result_verified": True,
                            "reference": {},
                            "forced": None,
                        }
                    )
                )
            query_payload = b"".join(query_rows)
            query_depths = {str(depth): 50 for depth in range(1, 13)}
            query_summary = {
                "actual_runtime_queries": 600,
                "query_mix": query_mix,
                "depth_counts": query_depths,
                "query_class_depths": {
                    name: list(range(1, 13)) for name in query_mix
                },
                "query_class_latency_ms": {
                    name: {"count": count, "p50": 1, "p95": 1, "p99": 1}
                    for name, count in query_mix.items()
                },
                "p50_ms": 1,
                "p95_ms": 1,
                "p99_ms": 1,
                "result_digest": canonical_digest(["a" * 64] * 600),
                "pages_observed": 600,
                "continuations_checked": 0,
                "explicit_truncations": 0,
                "maximum_continuation_token_bytes": 0,
                "selected_closure_chains": 600,
                "forced_continuation_chains": 0,
                "forced_union_matches": 0,
                "forced_depths": [],
                "runtime_query_budget": {"top_k": 1},
                "continuation_state": {
                    "files": 0,
                    "maximum_bytes": 0,
                    "total_bytes": 0,
                    "preexisting_files_excluded": 0,
                },
                "broad_query_refinement_required": True,
                "high_cardinality_terms_verified": True,
                "content_search_verified": True,
                "miss_behavior_verified": True,
                "hostile_proxy_content_verified": True,
                "exact_artifact_search_verified": True,
            }
            operation = {
                "semantic_ingestion": {"elapsed_seconds": 1.0},
                "search": query_summary,
                "resources": {
                    "inventory_stage_rss": {
                        "baseline_bytes": 1,
                        "peak_bytes": 2,
                        "incremental_peak_bytes": 1,
                    },
                    "projection_stage_rss": {
                        "baseline_bytes": 1,
                        "peak_bytes": 2,
                        "incremental_peak_bytes": 1,
                    },
                    "inventory_pipeline_peak_rss_bytes": 2,
                    "inventory_pipeline_incremental_peak_bytes": 1,
                    "inventory_absolute_rss_amplification": round(2 / len(inventory_payload), 9),
                    "inventory_incremental_memory_amplification": round(1 / len(inventory_payload), 9),
                    "memory_amplification_metric": {
                        "metric_id": "inventory-incremental-peak-over-stream-bytes",
                        "numerator": "inventory_pipeline_incremental_peak_bytes",
                        "denominator": "inventory_stream_bytes",
                        "numerator_bytes": 1,
                        "denominator_bytes": len(inventory_payload),
                        "ratio": round(1 / len(inventory_payload), 9),
                        "threshold_max": 32.0,
                        "within_threshold": True,
                    },
                    "peak_rss_bytes": 2,
                },
            }
            operation.update(
                {
                    "status": "pass",
                    "process_exit_code": 0,
                    "invocation_exit_code": 0,
                }
            )
            process_samples = {
                "record_type": "SaturationProcessSamples",
                "sample_interval_ms": 50,
                "lifetime_peak_rss_bytes": 2,
                "phases": [
                    {
                        "phase": phase,
                        "summary": {
                            "baseline_bytes": 1,
                            "peak_bytes": 2,
                            "incremental_peak_bytes": 1,
                        },
                        "samples": [
                            {"elapsed_ns": 0, "rss_bytes": 1},
                            {"elapsed_ns": 1, "rss_bytes": 2},
                        ],
                    }
                    for phase in ("inventory", "projection")
                ],
            }
            phase_payload = b"".join(
                canonical_bytes(
                    {
                        "order": index,
                        "phase": phase,
                        "elapsed_ms": 1000 if phase == "semantic-ingestion" else 0,
                        **(
                            {
                                "status": "pass",
                                "process_exit_code": 0,
                                "invocation_exit_code": 0,
                            }
                            if phase == "result"
                            else {}
                        ),
                    }
                )
                for index, phase in enumerate(
                    (
                        "physical-generation",
                        "inventory",
                        "semantic-ingestion",
                        "projection",
                        "runtime-queries",
                        "result",
                    ),
                    start=1,
                )
            )
            payloads = {
                "inventory-stream": inventory_payload,
                "physical-relation-evidence": relation_payload,
                "query-results": query_payload,
                "process-samples": canonical_bytes(process_samples),
                "continuation-state-manifest": b"",
                "phase-log": phase_payload,
                "operation-metrics": b"{}",
            }
            artifacts = []
            for role, (relative, media_type) in raw_roles.items():
                path = output / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(payloads[role])
                artifacts.append(
                    {
                        "role": role,
                        "path": relative,
                        "media_type": media_type,
                        "sha256": hashlib.sha256(payloads[role]).hexdigest(),
                        "bytes": len(payloads[role]),
                        "records": 0 if role == "continuation-state-manifest" else (
                            100_000 if role == "inventory-stream" else 198_999 if role == "physical-relation-evidence" else 600 if role == "query-results" else 4 if role == "process-samples" else 6 if role == "phase-log" else 1
                        ),
                    }
                )
            manifest_identity = {
                "record_type": "SaturationRawArtifactManifest",
                "path_scope": "saturation-result-directory",
                "evidence_class": "harness_generated",
                "product_acceptance_credit": False,
                "artifacts": artifacts,
                "artifact_count": 7,
                "inventory_stream_digest": hashlib.sha256(inventory_payload).hexdigest(),
                "inventory_identity_digest": inventory_identity_digest,
            }
            verification = {
                "status": "pass",
                "invocation": {"exit_code": 0},
                "runtime_binding": {"activation_digest": "a" * 64},
                "inventory": {"candidate_digest": "c" * 64},
                "physical": {"physical_relation_evidence": relation_summary},
                "physical_relation_evidence": relation_summary,
                "search": query_summary,
                "resources": operation["resources"],
                "raw_artifact_manifest": {
                    **manifest_identity,
                    "manifest_digest": canonical_digest(manifest_identity),
                },
            }
            reference = {
                "atoms": ["atom"],
                "atoms_count": 1,
                "atoms_digest": canonical_digest(["atom"]),
                "page_digests": ["a" * 64],
                "pages": 1,
                "continuation_pages": 0,
                "maximum_token_bytes": 0,
                "first_truncated": False,
                "selected_closure_complete": True,
            }
            with (
                mock.patch(
                    "promin.evidence._validate_saturation_operation_metrics",
                    return_value=operation,
                ),
                mock.patch(
                    "promin.evidence._recompute_raw_query_result",
                    side_effect=lambda row, expected_index, top_k: {
                        "query_class": row["query_class"],
                        "depth": row["depth"],
                        "elapsed_ms": 1.0,
                        "class_verified": True,
                        "reference": reference,
                        "forced": None,
                    },
                ),
            ):
                raw = _validate_saturation_raw_artifacts(
                    verification,
                    source_path=output / "saturation-result.json",
                    evidence_root=evidence_root,
                )
            self.assertEqual(raw["inventory_entry_count"], 100_000)
            self.assertEqual(raw["inventory_identity_digest"], inventory_identity_digest)
            self.assertEqual(raw["physical_bucket_cardinality"], {"minimum": 1_000, "maximum": 1_000, "distinct": 1})
            self.assertEqual(raw["physical_bucket_aggregate_digest"], aggregate_digest)

    def test_physical_relation_evidence_stream_is_canonical_exact_and_bound(self) -> None:
        """Count the independently published 198999-link stream, not a scalar."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "result"
            raw_dir = root / "raw"
            raw_dir.mkdir(parents=True)
            inventory_path = raw_dir / "inventory-stream.jsonl"
            with inventory_path.open("wb") as stream:
                for index in range(100_000):
                    bucket = index // 1_000
                    stream.write(
                        canonical_bytes(
                            {
                                "path": f"product/bucket-{bucket:03d}/record-{index:06d}.txt",
                                "digest": "0" * 64,
                                "size": 1,
                                "search_text": "",
                            }
                        )
                    )
            inventory_payload = inventory_path.read_bytes()
            relation_path = raw_dir / "physical-relation-evidence.jsonl"
            activation_digest = "a" * 64
            candidate_digest = "c" * 64
            inventory_identity = hashlib.sha256()
            bucket_hashes = [hashlib.sha256() for _ in range(100)]
            inventory_rows: dict[str, tuple[str, int, int]] = {}
            for index in range(100_000):
                bucket = index // 1_000
                target_path = f"product/bucket-{bucket:03d}/record-{index:06d}.txt"
                identity_bytes = canonical_bytes(
                    {"path": target_path, "digest": "0" * 64, "size": 1}
                )
                inventory_identity.update(identity_bytes)
                bucket_hashes[bucket].update(identity_bytes)
                inventory_rows[target_path] = ("0" * 64, 1, bucket)
            inventory_identity_digest = inventory_identity.hexdigest()
            bucket_aggregates = [
                {
                    "bucket_id": f"bucket-{bucket:03d}",
                    "relative_prefix": f"product/bucket-{bucket:03d}/",
                    "file_count": 1_000,
                    "total_bytes": 1_000,
                    "identity_digest": bucket_hashes[bucket].hexdigest(),
                    "first_path": f"product/bucket-{bucket:03d}/record-{bucket * 1_000:06d}.txt",
                    "last_path": f"product/bucket-{bucket:03d}/record-{bucket * 1_000 + 999:06d}.txt",
                }
                for bucket in range(100)
            ]
            bucket_control = {
                "candidate_digest": candidate_digest,
                "inventory_identity_digest": inventory_identity_digest,
                "bucket_count": 100,
                "files_per_bucket": 1_000,
                "file_count": 100_000,
                "aggregate_digest": hashlib.sha256(
                    canonical_bytes(bucket_aggregates)
                ).hexdigest(),
                "cardinality": {"minimum": 1_000, "maximum": 1_000, "distinct": 1},
            }
            with relation_path.open("wb") as stream:
                for index in range(198_999):
                    target_index = index % 100_000
                    bucket = target_index // 1_000
                    target_path = (
                        f"product/bucket-{bucket:03d}/record-{target_index:06d}.txt"
                    )
                    target_id = "artifact:file:" + hashlib.sha256(
                        target_path.encode("utf-8")
                    ).hexdigest()[:48]
                    stream.write(
                        canonical_bytes(
                            {
                                "record_type": "PhysicalRelationEvidence",
                                "relation_id": f"physical-relation:{index:06d}",
                                "kind": "READS",
                                "source_type": "PhysicalBucket",
                                "source_id": f"bucket-{bucket:03d}",
                                "target_type": "PhysicalInventoryRecord",
                                "target_id": target_id,
                                "target_path": target_path,
                                "target_digest": "0" * 64,
                                "target_size": 1,
                                "bucket": bucket,
                                "activation_digest": activation_digest,
                                "candidate_digest": candidate_digest,
                                "inventory_identity_digest": inventory_identity_digest,
                                "physical_evidence": True,
                                "semantic_record": False,
                            }
                        )
                    )
            payload = relation_path.read_bytes()
            loaded = {
                "runtime_binding": {"activation_digest": activation_digest},
                "inventory": {
                    "candidate_digest": candidate_digest,
                    "stream_bytes": len(inventory_payload),
                },
                "physical": {
                    "physical_relation_evidence_count": 198_999,
                    "candidate_digest": candidate_digest,
                    "inventory_identity_digest": inventory_identity_digest,
                    "activation_digest": activation_digest,
                    "explicit_semantic_corpus": {
                        "physical_bucket_control": bucket_control,
                    },
                },
                "raw_artifact_manifest": {
                    "artifacts": [
                        {
                            "role": "inventory-stream",
                            "path": "raw/inventory-stream.jsonl",
                            "records": 100_000,
                            "bytes": len(inventory_payload),
                            "sha256": hashlib.sha256(inventory_payload).hexdigest(),
                        },
                        {
                            "role": "physical-relation-evidence",
                            "path": "raw/physical-relation-evidence.jsonl",
                            "records": 198_999,
                            "bytes": len(payload),
                            "sha256": hashlib.sha256(payload).hexdigest(),
                        }
                    ],
                    "inventory_stream_digest": hashlib.sha256(inventory_payload).hexdigest(),
                    "inventory_identity_digest": inventory_identity_digest,
                },
            }
            raw_inventory = saturation_audit._validate_raw_inventory_stream(
                loaded,
                record_path=root / "saturation-result.json",
                files=100_000,
            )
            inventory_rows = raw_inventory["rows"]
            inventory_identity_digest = raw_inventory["inventory_identity_digest"]
            summary = {
                "record_type": "PhysicalRelationEvidenceSummary",
                "evidence_class": "harness_generated_physical",
                "product_acceptance_credit": False,
                "relation_count": 198_999,
                "relation_id_first": "physical-relation:000000",
                "relation_id_last": "physical-relation:198998",
                "physical_target_cardinality": 100_000,
                "inventory_identity_digest": inventory_identity_digest,
                "candidate_digest": candidate_digest,
                "activation_digest": activation_digest,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            loaded["physical_relation_evidence"] = summary
            loaded["physical"]["physical_relation_evidence"] = summary
            result = saturation_audit._validate_raw_physical_relation_evidence(
                loaded,
                record_path=root / "saturation-result.json",
                inventory_rows=inventory_rows,
                inventory_identity_digest=inventory_identity_digest,
            )
            self.assertEqual(result["records"], 198_999)
            self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(result["evidence_digest"], hashlib.sha256(payload).hexdigest())

            artifact_binding = {
                "candidate_binding_digest": candidate_digest,
                "binding_digest": "b" * 64,
                "archive": {"sha256": "d" * 64},
                "platform": {"binding_digest": "p" * 64},
            }
            assembled = {
                **loaded,
                "status": "fail",
                "pass_credit": False,
                "acceptance_pass": False,
                "product_acceptance_pass": False,
                "public_release_approved": False,
                "candidate_binding_digest": candidate_digest,
                "artifact_binding": artifact_binding,
                "invocation": {
                    "exit_code": 1,
                    "arguments": {"archive_sha256": "d" * 64},
                },
                "physical_files": 100_000,
                "core_valid_relations": 198_999,
                "core_valid_relations_exact_198999": True,
                "runtime_queries": 600,
                "silent_truncations": 0,
                "selected_closure_union_completeness": 1.0,
                "memory_amplification_at_most_32": True,
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
                "runtime_binding": {
                    "activation_digest": activation_digest,
                    "implementation_closure_digest": "e" * 64,
                    "platform_binding_digest": "p" * 64,
                },
                "workspace_initialization": {
                    "status": "reused",
                    "product_tree_scans": 0,
                    "init_record_count": 5,
                    "activation_digest": activation_digest,
                    "implementation_closure_digest": "e" * 64,
                },
                "projection": {},
                "search": {},
                "performance": {},
                "contract_predicates": {},
                "resources": {},
            }
            with mock.patch.object(
                saturation_audit,
                "_validate_raw_physical_relation_evidence",
                wraps=saturation_audit._validate_raw_physical_relation_evidence,
            ) as relation_validator:
                with self.assertRaisesRegex(
                    ValueError,
                    "physical result violates the bounded stream/bucket semantic contour",
                ):
                    saturation_audit._validate_physical_result(
                        assembled,
                        record_path=root / "saturation-result.json",
                        artifact_binding=artifact_binding,
                        files=100_000,
                        queries=600,
                        performance_profile="portable-local-v1",
                    )
            relation_validator.assert_called_once()

            duplicate = payload.replace(
                b"physical-relation:000001",
                b"physical-relation:000000",
                1,
            )
            relation_path.write_bytes(duplicate)
            loaded["raw_artifact_manifest"]["artifacts"][1].update(
                {
                    "bytes": len(duplicate),
                    "sha256": hashlib.sha256(duplicate).hexdigest(),
                }
            )
            with self.assertRaisesRegex(ValueError, "raw physical relation evidence row"):
                saturation_audit._validate_raw_physical_relation_evidence(
                    loaded,
                    record_path=root / "saturation-result.json",
                    inventory_rows=inventory_rows,
                    inventory_identity_digest=inventory_identity_digest,
                )

            missing_root = root.parent / "missing-relation-result"
            (missing_root / "raw").mkdir(parents=True)
            missing_loaded = json.loads(json.dumps(loaded))
            with self.assertRaisesRegex(ValueError, "raw physical relation evidence cannot be read safely"):
                saturation_audit._validate_raw_physical_relation_evidence(
                    missing_loaded,
                    record_path=missing_root / "saturation-result.json",
                    inventory_rows=inventory_rows,
                    inventory_identity_digest=inventory_identity_digest,
                )

    def test_saturation_evidence_requires_exact_candidate_in_projection_contour(
        self,
    ) -> None:
        verification, raw = self._exact_saturation_evidence_fixture()
        validated = self._validate_exact_saturation_fixture(verification, raw)
        self.assertEqual(validated["projection"]["entity_count"], 137)
        self.assertEqual(
            validated["projection"]["entity_type_counts"],
            {
                "Task": 132,
                "Grant": 4,
                "Candidate": 1,
            },
        )
        self.assertEqual(raw["operation"]["semantic_ingestion"]["commit_count"], 137)

        missing_candidate = json.loads(json.dumps(verification))
        del missing_candidate["projection"]["entity_type_counts"]["Candidate"]
        missing_candidate["projection"]["entity_count"] = 136
        with self.assertRaisesRegex(EvidenceError, "entity contour shape is invalid"):
            self._validate_exact_saturation_fixture(missing_candidate, raw)

        tampered_candidate = json.loads(json.dumps(verification))
        tampered_candidate["projection"]["entity_type_counts"]["Candidate"] = 0
        tampered_candidate["projection"]["entity_count"] = 136
        with self.assertRaisesRegex(EvidenceError, "entity contour is not exact"):
            self._validate_exact_saturation_fixture(tampered_candidate, raw)

        stale_commit_count = json.loads(json.dumps(raw))
        stale_commit_count["operation"]["semantic_ingestion"]["commit_count"] = 136
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
            "task_count": 132,
            "relation_count": 28,
            "depths": list(range(1, 13)),
            "high_fanout": 16,
            "conflicting_exact_id_text": True,
            "search_fixture": {
                "task_count": 32,
                "relation_count": 28,
                "depths": list(range(1, 13)),
                "high_fanout": 16,
            },
            "query_ids": ["query:fixture", "query:continuation"],
            "continuation_query_ids": ["query:continuation"],
            "physical_bucket_control": {
                "record_type": "PhysicalBucketControlManifest",
                "generation": "streamed-inventory-aggregate",
                "candidate_digest": "c" * 64,
                "inventory_identity_digest": "e" * 64,
                "bucket_count": 100,
                "files_per_bucket": 1_000,
                "file_count": 100_000,
                "aggregate_digest": "f" * 64,
                "cardinality": {"minimum": 1_000, "maximum": 1_000, "distinct": 1},
                "semantic_control_record_count": 100,
                "semantic_control_envelope_count": 100,
                "semantic_control_record_limit": 256,
            },
            "reused": False,
            "search_fixture_reused": False,
            "physical_bucket_control_reused": False,
        }
        self.assertEqual(
            _validate_saturation_fresh_semantic_corpus(
                corpus,
                candidate_digest="c" * 64,
                inventory_identity_digest="e" * 64,
                aggregate_digest="f" * 64,
            ),
            corpus,
        )
        for field in (
            "reused",
            "search_fixture_reused",
            "physical_bucket_control_reused",
        ):
            with self.subTest(field=field):
                reused = dict(corpus)
                reused[field] = True
                with self.assertRaisesRegex(
                    EvidenceError,
                    "cannot reuse semantic corpus state",
                ):
                    _validate_saturation_fresh_semantic_corpus(
                        reused,
                        candidate_digest="c" * 64,
                        inventory_identity_digest="e" * 64,
                        aggregate_digest="f" * 64,
                    )
                with self.assertRaisesRegex(
                    ValueError,
                    "bounded semantic corpus is incomplete, stale, or creditable",
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
                    _validate_saturation_fresh_semantic_corpus(
                        missing,
                        candidate_digest="c" * 64,
                        inventory_identity_digest="e" * 64,
                        aggregate_digest="f" * 64,
                    )

    def test_fresh_semantic_corpus_rejects_legacy_relation_fixture(self) -> None:
        corpus = {
            "record_type": "SaturationSemanticCorpus",
            "generation": "explicit-authorized-command-events",
            "harness_generated": True,
            "product_acceptance_credit": False,
            "task_count": 132,
            "relation_count": 28,
            "depths": list(range(1, 13)),
            "high_fanout": 16,
            "conflicting_exact_id_text": True,
            "query_ids": ["query:fixture", "query:continuation"],
            "continuation_query_ids": ["query:continuation"],
            "search_fixture": {
                "task_count": 32,
                "relation_count": 28,
                "depths": list(range(1, 13)),
                "high_fanout": 16,
            },
            "physical_relation_fixture": {},
            "reused": False,
            "search_fixture_reused": False,
            "physical_bucket_control_reused": False,
        }
        with self.assertRaisesRegex(EvidenceError, "bounded semantic corpus shape"):
            _validate_saturation_fresh_semantic_corpus(
                corpus,
                candidate_digest="c" * 64,
                inventory_identity_digest="e" * 64,
                aggregate_digest="f" * 64,
            )
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
        self.assertIn(
            '"core_valid_relations": _EXACT_CORE_VALID_RELATIONS,',
            saturation_source,
        )
        self.assertIn('"core_valid_relations_exact_198999"', saturation_source)
        self.assertIn('"physical_relation_evidence_count_exact"', saturation_source)
        self.assertIn('"runtime_queries_exact"', saturation_source)
        audit_source = inspect.getsource(saturation_audit._validate_physical_result)
        self.assertIn(
            '"core_valid_relations": physical["physical_relation_evidence_count"],',
            audit_source,
        )
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
