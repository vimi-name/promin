from __future__ import annotations

import base64
import hashlib
import re
import sys
import unicodedata
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping

from .canonical import (
    CanonicalError,
    ParseLimits,
    canonical_bytes,
    digest_file,
    digest_value,
    ensure_exact_regular_files,
    load_json_strict,
    parse_json_strict,
)

if TYPE_CHECKING:
    from .contracts import ContractBundle


class ConformanceError(ValueError):
    """Raised when a concrete conformance check cannot prove its claim."""


Check = Callable[[Mapping[str, Any], "ContractBundle", Mapping[str, Any]], None]


_SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-((?:0|[1-9][0-9]*|[0-9A-Za-z-][0-9A-Za-z.-]*)))?"
    r"(?:\+([0-9A-Za-z-][0-9A-Za-z.-]*))?$"
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def validate_resolved_plan_budget(
    plan: Mapping[str, Any], budgets: Mapping[str, Any]
) -> None:
    """Fail closed when a user-facing resolved plan exceeds Core's bounds.

    The full inventory belongs to derived context/index state.  A resolved plan
    carries exact technology counts plus a bounded, deterministic diagnostic
    sample only.  This check is deliberately independent of schema ingress so
    guided and direct expert paths enforce the same Core-owned limits before
    compiling any ProjectInit record.
    """

    max_bytes = budgets.get("resolved_plan_bytes_max")
    max_samples = budgets.get("resolved_plan_source_samples_max")
    if (
        not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or max_bytes < 1024
        or not isinstance(max_samples, int)
        or isinstance(max_samples, bool)
        or max_samples < 1
    ):
        raise ConformanceError("resolved plan budget owner is invalid")

    technologies = plan.get("detected_technologies")
    if not isinstance(technologies, list):
        raise ConformanceError("resolved plan lacks detected technologies")

    previous_id: str | None = None
    sample_count = 0
    for item in technologies:
        if not isinstance(item, Mapping):
            raise ConformanceError("resolved plan technology fact is invalid")
        technology_id = item.get("technology")
        sources = item.get("sources")
        total_count = item.get("total_source_count")
        truncated = item.get("sources_truncated")
        count_complete = item.get("source_count_complete")
        if (
            not isinstance(technology_id, str)
            or not technology_id
            or (previous_id is not None and technology_id <= previous_id)
            or not isinstance(sources, list)
            or not isinstance(total_count, int)
            or isinstance(total_count, bool)
            or total_count < len(sources)
            or not isinstance(truncated, bool)
            or not isinstance(count_complete, bool)
        ):
            raise ConformanceError("resolved plan technology fact is inconsistent")
        previous_id = technology_id
        normalized_sources: list[str] = []
        for source in sources:
            if (
                not isinstance(source, str)
                or not source
                or "\\" in source
                or source.startswith("/")
                or any(part in {"", ".", ".."} for part in source.split("/"))
            ):
                raise ConformanceError("resolved plan contains a non-normalized source sample")
            normalized_sources.append(source)
        if normalized_sources != sorted(set(normalized_sources)):
            raise ConformanceError("resolved plan source samples are not deterministic")
        if not truncated and (not count_complete or len(sources) != total_count):
            raise ConformanceError("resolved plan falsely reports complete source samples")
        if not count_complete and not truncated:
            raise ConformanceError("resolved plan hides an incomplete source count")
        sample_count += len(sources)

    if sample_count > max_samples:
        raise ConformanceError(
            f"resolved plan source sample budget exceeded: {sample_count}>{max_samples}"
        )
    try:
        encoded = canonical_bytes(dict(plan))
    except Exception as exc:
        raise ConformanceError("resolved plan is not canonical JSON") from exc
    if len(encoded) > max_bytes:
        raise ConformanceError(
            f"resolved plan byte budget exceeded: {len(encoded)}>{max_bytes}"
        )


def _activation_context(context: Mapping[str, Any]):
    supplied = context.get("activation_context")
    if supplied is not None:
        return supplied
    project_root = context.get("project_root")
    if project_root is None:
        raise ConformanceError("concrete check requires installed project context")
    from .init import ActivationGuard

    return ActivationGuard(
        Path(project_root),
        provider_verifiers=context.get("provider_verifiers"),
        signature_verifier=context.get("signature_verifier"),
    ).verify()


def _require_evidence(
    check_id: str,
    value: Mapping[str, Any],
    bundle: "ContractBundle",
    context: Mapping[str, Any],
    *,
    purpose: str = "gate",
) -> None:
    store = context.get("evidence_store")
    bindings = context.get("evidence_bindings")
    if store is None or not isinstance(bindings, Mapping):
        raise ConformanceError(f"{check_id} requires immutable EvidenceStore context")
    artifact = bindings.get(check_id)
    if not isinstance(artifact, Mapping):
        raise ConformanceError(f"{check_id} has no candidate-bound evidence")
    from .contracts import validate_definition

    try:
        validate_definition(bundle.schema, "Artifact", artifact)
    except Exception as exc:
        raise ConformanceError(f"{check_id} evidence Artifact is not Core-valid") from exc
    if artifact.get("artifact_kind") != "evidence":
        raise ConformanceError(f"{check_id} does not cite an evidence Artifact")
    binding = artifact["evidence_binding"]
    if (
        artifact.get("outcome") != "pass"
        or artifact.get("stale") is not False
        or artifact.get("unresolved") is not False
    ):
        raise ConformanceError(f"{check_id} evidence is not a fresh resolved pass")
    if purpose == "product" and (
        artifact.get("evidence_class") != "product-execution"
        or artifact.get("product_credit_eligible") is not True
    ):
        raise ConformanceError(f"{check_id} lacks product-execution evidence")
    activation = context.get("activation_digest")
    activation_context = None
    if activation is None:
        try:
            activation_context = _activation_context(context)
            activation = activation_context.activation_digest
        except Exception as exc:
            raise ConformanceError(f"{check_id} lacks active Activation evidence") from exc
    if binding["activation_digest"] != activation:
        raise ConformanceError(f"{check_id} evidence binds a different Activation")
    implementation_closure = context.get("implementation_closure_digest")
    if implementation_closure is None:
        try:
            if activation_context is None:
                activation_context = _activation_context(context)
            implementation_closure = activation_context.implementation_closure_digest
        except Exception as exc:
            raise ConformanceError(
                f"{check_id} lacks implementation closure evidence"
            ) from exc
    if binding.get("implementation_closure_digest") != implementation_closure:
        raise ConformanceError(
            f"{check_id} evidence binds a different implementation closure"
        )
    expected_policy = None
    for policy in bundle.core["policy-set.json"]["policies"]:
        if policy["validator_id"] == check_id:
            expected_policy = digest_value(policy)
            break
    if check_id in bundle.core["conformance.json"]["required_acceptance"]:
        expected_policy = digest_value(
            {
                "acceptance_predicate": check_id,
                "conformance_digest": digest_value(bundle.core["conformance.json"]),
            }
        )
    if expected_policy is None or binding["policy_digest"] != expected_policy:
        raise ConformanceError(f"{check_id} evidence binds the wrong policy owner")
    if binding["candidate_digest"] != context.get("candidate_digest"):
        raise ConformanceError(f"{check_id} evidence binds the wrong Candidate")
    tool_paths = context.get("evidence_tools")
    input_paths = context.get("evidence_inputs")
    payload_paths = context.get("evidence_payloads")
    if (
        not isinstance(tool_paths, Mapping)
        or not isinstance(input_paths, Mapping)
        or not isinstance(payload_paths, Mapping)
    ):
        raise ConformanceError(f"{check_id} lacks actual tool/input artifacts")
    tool_path = tool_paths.get(check_id)
    selected_inputs = input_paths.get(check_id)
    if tool_path is None or not isinstance(selected_inputs, (list, tuple)):
        raise ConformanceError(f"{check_id} lacks actual tool/input artifacts")
    if digest_file(Path(tool_path)) != binding["tool_digest"]:
        raise ConformanceError(f"{check_id} tool digest differs from actual bytes")
    actual_inputs = [digest_file(Path(path)) for path in selected_inputs]
    if actual_inputs != binding["input_digests"]:
        raise ConformanceError(f"{check_id} input digests differ from actual bytes")
    payload_path = payload_paths.get(check_id)
    if payload_path is None or digest_file(Path(payload_path)) != artifact["digest"]:
        raise ConformanceError(f"{check_id} evidence payload differs from CAS identity")
    payload = load_json_strict(Path(payload_path))
    if (
        not isinstance(payload, dict)
        or set(payload) != {"record_type", "check_id", "status", "observed", "metrics"}
        or payload["record_type"] != "ConformanceEvidence"
        or payload["check_id"] != check_id
        or payload["status"] != "pass"
        or payload["observed"] is not True
        or not isinstance(payload["metrics"], dict)
    ):
        raise ConformanceError(f"{check_id} evidence payload is not an exact pass observation")
    _validate_evidence_metrics(check_id, payload["metrics"], bundle=bundle)
    try:
        reference = store.artifact_reference(artifact["artifact_id"])
        resolved_artifact = store.require_creditable(
            reference["artifact_id"],
            reference["artifact_record_digest"],
            candidate_digest=binding["candidate_digest"],
            policy_digest=binding["policy_digest"],
            tool_digest=binding["tool_digest"],
            input_digests=binding["input_digests"],
            provider_invocation_digests=[
                digest_value(invocation)
                for invocation in binding.get("provider_invocations", [])
            ],
            activation_digest=binding["activation_digest"],
            implementation_closure_digest=binding[
                "implementation_closure_digest"
            ],
            evidence_class=artifact["evidence_class"],
            purpose=purpose,
            finding_digest=binding.get("finding_digest"),
            require_product_credit=purpose == "product",
        )
        if resolved_artifact != dict(artifact):
            raise ConformanceError(f"{check_id} evidence metadata differs from CAS record")
    except Exception as exc:
        raise ConformanceError(
            f"{check_id} evidence is failed, blocked, stale, unresolved, or unbound"
        ) from exc


def _validate_evidence_metrics(
    check_id: str,
    metrics: Mapping[str, Any],
    *,
    bundle: "ContractBundle",
) -> None:
    if check_id in {
        "physical-100k-one-artifact-proxy-per-file",
        "profile-bound-physical-100k-performance",
    }:
        _validate_physical_scale_result(metrics, bundle=bundle, check_id=check_id)
    elif check_id == "rollback-and-recutover-equivalence":
        if (
            not metrics.get("rollback_executed")
            or not metrics.get("recutover_executed")
            or metrics.get("first_digest") != metrics.get("recutover_digest")
        ):
            raise ConformanceError(f"{check_id} semantic digest parity failed")
    elif check_id.startswith("zero-"):
        violation_keys = (
            "violations",
            "occurrences",
            "product_tree_passes",
            "compiled_cache_files",
            "unowned_facts",
            "provider_lock_in",
            "truncated_queries",
        )
        nonzero = [
            value
            for key, value in metrics.items()
            if key in violation_keys and isinstance(value, int) and value != 0
        ]
        if nonzero:
            raise ConformanceError(f"{check_id} contains non-zero violation metrics")


def _required_mapping(
    value: Mapping[str, Any], key: str, *, owner: str
) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ConformanceError(f"{owner} lacks mapping: {key}")
    return selected


def _required_exact_int(
    value: Mapping[str, Any], key: str, expected: int, *, owner: str
) -> None:
    selected = value.get(key)
    if not isinstance(selected, int) or isinstance(selected, bool) or selected != expected:
        raise ConformanceError(f"{owner} has non-exact metric: {key}")


def _required_nonnegative_int(
    value: Mapping[str, Any], key: str, *, owner: str
) -> int:
    selected = value.get(key)
    if not isinstance(selected, int) or isinstance(selected, bool) or selected < 0:
        raise ConformanceError(f"{owner} lacks nonnegative integer: {key}")
    return selected


def _required_nonnegative_number(
    value: Mapping[str, Any], key: str, *, owner: str
) -> float:
    selected = value.get(key)
    if (
        not isinstance(selected, (int, float))
        or isinstance(selected, bool)
        or selected < 0
    ):
        raise ConformanceError(f"{owner} lacks nonnegative metric: {key}")
    return float(selected)


def _validate_physical_scale_result(
    result: Mapping[str, Any], *, bundle: "ContractBundle", check_id: str
) -> None:
    conformance = _required_mapping(
        bundle.core, "conformance.json", owner="Core bundle"
    )
    reference = _required_mapping(
        conformance, "reference_benchmarks", owner="Core conformance"
    )
    scale_contracts = _required_mapping(
        conformance, "scale_contracts", owner="Core conformance"
    )
    semantic_reference = _required_mapping(
        reference, "semantic_corpus", owner="Core reference benchmarks"
    )
    physical_reference = _required_mapping(
        reference, "physical_relation_corpus", owner="Core reference benchmarks"
    )
    inventory_contract = _required_mapping(
        scale_contracts, "inventory", owner="Core scale contracts"
    )
    projection_contract = _required_mapping(
        scale_contracts, "projection", owner="Core scale contracts"
    )
    workcard_contract = _required_mapping(
        scale_contracts, "workcard", owner="Core scale contracts"
    )

    file_count = _required_nonnegative_int(
        reference, "file_count", owner="Core reference benchmarks"
    )
    core_valid_relation_count = _required_nonnegative_int(
        reference,
        "core_valid_relation_count",
        owner="Core reference benchmarks",
    )
    query_count = _required_nonnegative_int(
        reference, "query_count", owner="Core reference benchmarks"
    )
    inventory_passes = _required_nonnegative_int(
        reference, "inventory_passes", owner="Core reference benchmarks"
    )
    silent_truncations_max = _required_nonnegative_int(
        reference, "silent_truncations_max", owner="Core reference benchmarks"
    )
    semantic_task_count = _required_nonnegative_int(
        semantic_reference, "task_count", owner="Core semantic corpus"
    )
    semantic_relation_count = _required_nonnegative_int(
        semantic_reference, "relation_count", owner="Core semantic corpus"
    )
    physical_task_count = _required_nonnegative_int(
        physical_reference, "task_count", owner="Core physical relation corpus"
    )
    physical_relation_count = _required_nonnegative_int(
        physical_reference, "relation_count", owner="Core physical relation corpus"
    )
    total_relation_count = _required_nonnegative_int(
        physical_reference,
        "total_core_valid_relations",
        owner="Core physical relation corpus",
    )
    expected_relation_count = semantic_relation_count + physical_relation_count
    if (
        file_count != 100000
        or core_valid_relation_count != 198999
        or query_count != 600
        or inventory_passes <= 0
        or total_relation_count != expected_relation_count
        or total_relation_count != core_valid_relation_count
    ):
        raise ConformanceError("Core reference scale counts are internally inconsistent")

    depths = semantic_reference.get("depths")
    if (
        not isinstance(depths, list)
        or not depths
        or any(
            not isinstance(depth, int) or isinstance(depth, bool) or depth <= 0
            for depth in depths
        )
        or len(depths) != len(set(depths))
        or reference.get("depths_tested") != depths
    ):
        raise ConformanceError("Core reference depth corpus is internally inconsistent")

    proxies_per_file = _required_nonnegative_int(
        inventory_contract,
        "derived_artifact_proxies_per_raw_file",
        owner="Core inventory scale contract",
    )
    synthetic_tasks_per_file = _required_nonnegative_int(
        inventory_contract,
        "synthetic_tasks_per_raw_file",
        owner="Core inventory scale contract",
    )
    synthetic_relations_per_file = _required_nonnegative_int(
        inventory_contract,
        "synthetic_relations_per_raw_file",
        owner="Core inventory scale contract",
    )
    inventory_passes_max = _required_nonnegative_int(
        inventory_contract,
        "project_tree_passes_max",
        owner="Core inventory scale contract",
    )
    rebuild_product_passes = _required_nonnegative_int(
        projection_contract,
        "rebuild_product_tree_passes",
        owner="Core projection scale contract",
    )
    continuation_state_bytes_max = _required_nonnegative_int(
        workcard_contract,
        "continuation_state_bytes_max",
        owner="Core workcard scale contract",
    )
    continuation_token_bytes_max = _required_nonnegative_int(
        workcard_contract,
        "continuation_token_bytes_max",
        owner="Core workcard scale contract",
    )
    selected_closure_completeness = _required_nonnegative_number(
        workcard_contract,
        "selected_closure_union_completeness",
        owner="Core workcard scale contract",
    )
    expected_proxy_ratio = _required_nonnegative_number(
        reference, "raw_file_proxy_ratio", owner="Core reference benchmarks"
    )
    expected_synthetic_task_ratio = _required_nonnegative_number(
        reference, "synthetic_task_ratio", owner="Core reference benchmarks"
    )
    if (
        proxies_per_file != expected_proxy_ratio
        or synthetic_tasks_per_file != expected_synthetic_task_ratio
        or inventory_passes > inventory_passes_max
        or reference.get("rebuild_product_passes") != rebuild_product_passes
        or continuation_state_bytes_max <= 0
        or continuation_token_bytes_max <= 0
    ):
        raise ConformanceError("Core scale contracts disagree with reference benchmarks")

    physical = _required_mapping(result, "physical", owner=check_id)
    inventory = _required_mapping(result, "inventory", owner=check_id)
    projection = _required_mapping(result, "projection", owner=check_id)
    search = _required_mapping(result, "search", owner=check_id)
    resources = _required_mapping(result, "resources", owner=check_id)
    performance = _required_mapping(result, "performance", owner=check_id)

    expected_proxy_count = file_count * proxies_per_file
    expected_synthetic_task_count = file_count * synthetic_tasks_per_file
    expected_inventory_relation_count = file_count * synthetic_relations_per_file
    _required_exact_int(physical, "files", file_count, owner=check_id)
    _required_exact_int(physical, "raw_files", file_count, owner=check_id)
    _required_exact_int(
        physical, "semantic_proxies", expected_proxy_count, owner=check_id
    )
    _required_exact_int(
        physical, "raw_file_proxies", expected_proxy_count, owner=check_id
    )
    _required_exact_int(
        physical, "synthetic_tasks", expected_synthetic_task_count, owner=check_id
    )
    _required_exact_int(
        physical, "synthetic_task_count", expected_synthetic_task_count, owner=check_id
    )
    _required_exact_int(
        physical,
        "inventory_relations",
        expected_inventory_relation_count,
        owner=check_id,
    )
    _required_exact_int(physical, "relations", total_relation_count, owner=check_id)
    if (
        physical.get("raw_file_proxy_ratio") != expected_proxy_ratio
        or physical.get("synthetic_task_ratio") != expected_synthetic_task_ratio
    ):
        raise ConformanceError(f"{check_id} inventory ratios are not exact")
    corpus = _required_mapping(
        physical, "explicit_semantic_corpus", owner=check_id
    )
    depths = corpus.get("depths")
    physical_relations = _required_mapping(
        corpus, "physical_relation_fixture", owner=check_id
    )
    if (
        depths != semantic_reference["depths"]
        or corpus.get("task_count") != semantic_task_count + physical_task_count
        or corpus.get("relation_count") != total_relation_count
        or corpus.get("harness_generated") is not True
        or corpus.get("product_acceptance_credit") is not False
        or physical_relations.get("task_count") != physical_task_count
        or physical_relations.get("relation_count") != physical_relation_count
        or physical_relations.get("relation_kind")
        != physical_reference.get("relation_kind")
        or physical_relations.get("artifact_target_coverage")
        != physical_reference.get("artifact_target_coverage")
    ):
        raise ConformanceError(f"{check_id} semantic corpus differs from Core")

    _required_exact_int(inventory, "passes", inventory_passes, owner=check_id)
    _required_exact_int(inventory, "entries", file_count, owner=check_id)
    _required_exact_int(
        projection, "initial_inventory_passes", inventory_passes, owner=check_id
    )
    _required_exact_int(
        projection, "initial_product_passes", rebuild_product_passes, owner=check_id
    )
    _required_exact_int(
        projection, "rebuild_inventory_passes", inventory_passes, owner=check_id
    )
    _required_exact_int(
        projection, "rebuild_product_passes", rebuild_product_passes, owner=check_id
    )
    if projection.get("equal_semantic_digest") is not True:
        raise ConformanceError(f"{check_id} rebuild semantic digest differs")

    runtime_queries = search.get("actual_runtime_queries")
    if (
        not isinstance(runtime_queries, int)
        or isinstance(runtime_queries, bool)
        or runtime_queries != query_count
        or search.get("continuation_union_complete") is not True
        or search.get("continuation_union_completeness")
        != selected_closure_completeness
        or search.get("silent_truncations") != silent_truncations_max
        or search.get("broad_query_refinement_required") is not True
        or search.get("high_cardinality_terms_verified") is not True
        or search.get("content_search_verified") is not True
        or search.get("miss_behavior_verified") is not True
        or search.get("hostile_proxy_content_verified") is not True
        or search.get("exact_artifact_search_verified") is not True
        or search.get("mixed_query_classes_complete") is not True
    ):
        raise ConformanceError(f"{check_id} runtime query closure is incomplete")
    depth_counts = search.get("depth_counts")
    if (
        not isinstance(depth_counts, Mapping)
        or set(depth_counts) != {str(depth) for depth in depths}
        or any(
            not isinstance(count, int) or isinstance(count, bool) or count <= 0
            for count in depth_counts.values()
        )
        or sum(depth_counts.values()) != runtime_queries
        or search.get("depth_min") != min(depths)
        or search.get("depth_max") != max(depths)
        or search.get("forced_depths") != depths
    ):
        raise ConformanceError(f"{check_id} runtime depth coverage differs from Core")
    continuation_state = _required_mapping(
        search, "continuation_state", owner=check_id
    )
    maximum_state_bytes = continuation_state.get("maximum_bytes")
    maximum_token_bytes = search.get("maximum_continuation_token_bytes")
    if (
        not isinstance(maximum_state_bytes, int)
        or isinstance(maximum_state_bytes, bool)
        or not 0 < maximum_state_bytes <= continuation_state_bytes_max
        or not isinstance(maximum_token_bytes, int)
        or isinstance(maximum_token_bytes, bool)
        or not 0 < maximum_token_bytes <= continuation_token_bytes_max
        or search.get("continuation_token_overhead_at_most_10_percent") is not True
    ):
        raise ConformanceError(f"{check_id} continuation context bounds are incomplete")

    thresholds = _required_mapping(performance, "thresholds", owner=check_id)
    observed = _required_mapping(performance, "observed", owner=check_id)
    predicates = _required_mapping(performance, "predicates", owner=check_id)
    profile_id = performance.get("profile_id")
    profiles = _required_mapping(
        reference, "performance_profiles", owner="Core reference benchmarks"
    )
    profile = profiles.get(profile_id)
    if not isinstance(profile, Mapping):
        raise ConformanceError(f"{check_id} names an unknown Core performance profile")
    expected_thresholds = {
        key: selected for key, selected in profile.items() if key.endswith("_max")
    }
    if (
        thresholds != expected_thresholds
        or performance.get("compatible_platforms") != profile.get("compatible_platforms")
        or performance.get("requires_same_runner_no_degradation")
        != profile.get("requires_same_runner_no_degradation")
    ):
        raise ConformanceError(f"{check_id} performance profile differs from Core")
    bindings = {
        "p50_ms": ("p50_ms_max", "p50_within_profile"),
        "p95_ms": ("p95_ms_max", "p95_within_profile"),
        "p99_ms": ("p99_ms_max", "p99_within_profile"),
        "peak_rss_bytes": ("peak_rss_bytes_max", "peak_rss_within_profile"),
        "database_bytes": ("database_bytes_max", "database_within_profile"),
        "projection_amplification": (
            "projection_amplification_max",
            "projection_amplification_within_profile",
        ),
        "semantic_inflation": (
            "semantic_inflation_max",
            "semantic_inflation_within_profile",
        ),
    }
    actual_sources: dict[str, Mapping[str, Any]] = {
        "p50_ms": search,
        "p95_ms": search,
        "p99_ms": search,
        "peak_rss_bytes": resources,
        "database_bytes": projection,
        "projection_amplification": projection,
        "semantic_inflation": projection,
    }
    for observed_key, (threshold_key, predicate_key) in bindings.items():
        actual = _required_nonnegative_number(
            actual_sources[observed_key], observed_key, owner=check_id
        )
        cited = _required_nonnegative_number(
            observed, observed_key, owner=check_id
        )
        maximum = _required_nonnegative_number(
            thresholds, threshold_key, owner=check_id
        )
        if actual != cited or actual > maximum or predicates.get(predicate_key) is not True:
            raise ConformanceError(
                f"{check_id} exceeds or misstates profile threshold: {observed_key}"
            )
    if performance.get("all_within_profile") is not True:
        raise ConformanceError(f"{check_id} profile-bound performance did not pass")


def _canonical_identity(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    manifest = bundle.manifest
    version = manifest.get("version")
    valid_version = (
        isinstance(version, str)
        and len(version) <= 128
        and _SEMVER.fullmatch(version) is not None
    )
    if (
        manifest.get("canonical_name") != "promin"
        or manifest.get("canonical_name_only") is not True
        or manifest.get("aliases") != []
        or not valid_version
        or bundle.preset.get("version") != version
    ):
        raise ConformanceError("canonical Promin v1 identity is not exact")


def _core_layout(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import CORE_FILES, verify_core

    ensure_exact_regular_files(bundle.core_dir, CORE_FILES)
    verified = verify_core(bundle.core_dir)
    if verified["promin.manifest.json"]["bundle_digest"] != bundle.bundle_digest:
        raise ConformanceError("verified Core identity changed")


def _preset_separation(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    components = {item["path"] for item in bundle.manifest["core_components"]}
    if any("preset" in name.casefold() for name in components):
        raise ConformanceError("replaceable preset leaked into Core identity")
    forbidden = {
        "grants",
        "roots",
        "capability_ceiling",
        "authority",
        "trust_mode",
    }
    if forbidden & set(bundle.preset):
        raise ConformanceError("preset attempts to own action authority")


def _installed_preset_layout(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    activation = _activation_context(context)
    preset_dir = activation.installed_standard / "presets"
    ensure_exact_regular_files(
        preset_dir, (f"{activation.activation['preset_digest']}.json",)
    )


def _activation_integrity(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    activation = _activation_context(context)
    if (
        activation.bundle.bundle_digest != bundle.bundle_digest
        or activation.bundle.preset_digest != bundle.preset_digest
        or set(activation.plans)
        != {"project.json", "standards.json", "technologies.json", "authority.json"}
    ):
        raise ConformanceError("installed Activation does not bind exact bundle, preset, and init")
    if value and "activation_digest" in value:
        if value["activation_digest"] != activation.activation_digest:
            raise ConformanceError("record binds a stale Activation")


def _strict_record(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import validate_ingress

    operation = context.get("operation")
    if operation not in {"command", "import", "replay", "rebuild", "export"}:
        raise ConformanceError("strict record check requires a real ingress operation")
    validate_ingress(
        bundle,
        value,
        operation=operation,
        context={
            "activation_digest": context.get("activation_digest"),
            "operating_profile": context.get("operating_profile"),
        },
    )


def _normalization_rejection(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    rejected = 0
    for payload in (b'{"a":1,"a":2}', '{"é":1,"é":2}'.encode("utf-8")):
        try:
            parse_json_strict(payload)
        except CanonicalError:
            rejected += 1
    if rejected != 2:
        raise ConformanceError("production canonical parser accepted a key collision")


def _validate_gate_command_scope(
    command: Mapping[str, Any],
    definition: Mapping[str, Any],
    *,
    task_id: str,
    bundle: "ContractBundle",
) -> None:
    from .authority import AuthorityError, validate_gate_authorization_scope

    lease_bound_task_id = command.get("workcard_task_id")
    if lease_bound_task_id is not None and not isinstance(lease_bound_task_id, str):
        raise ConformanceError("gate command WorkCard Task binding is invalid")
    try:
        validate_gate_authorization_scope(
            command.get("requested_scope", ()),
            definition["target_scope"],
            task_id=task_id,
            scope_contract=bundle.core["authority-model.json"]["scope_contract"],
            gate_scope_contract=bundle.core["policy-set.json"][
                "gate_run_definition_contract"
            ]["authorization_scope_contract"],
            lease_bound_task_id=lease_bound_task_id,
        )
    except (AuthorityError, KeyError, TypeError) as exc:
        raise ConformanceError(str(exc)) from exc


def _gate_credit(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import validate_definition

    validate_definition(bundle.schema, "GateResult", value)
    task = context.get("gate_task")
    if not isinstance(task, Mapping):
        raise ConformanceError("GateResult requires its current Task owner")
    try:
        validate_definition(bundle.schema, "Task", task)
    except Exception as exc:
        raise ConformanceError("GateResult Task owner is not Core-valid") from exc
    if task["task_id"] != value["task_id"]:
        raise ConformanceError("GateResult binds another Task")
    matches = [
        binding["definition"]
        for binding in task["gate_run_definitions"]
        if binding["definition_digest"] == value["definition_digest"]
        and digest_value(binding["definition"]) == value["definition_digest"]
    ]
    if len(matches) != 1:
        raise ConformanceError(
            "GateResult definition does not resolve exactly once from its Task"
        )
    definition = matches[0]
    owner_identity = {
        field: nested
        for field, nested in task.items()
        if field not in {"state", "gate_run_definitions"}
    }
    if (
        definition["owner_kind"] != "Task"
        or definition["owner_digest"] != digest_value(owner_identity)
    ):
        raise ConformanceError("GateRunDefinition owner provenance differs from its Task")
    for field in ("gate_id", "candidate_digest", "policy_digest", "tool_digest"):
        if value[field] != definition[field]:
            raise ConformanceError(f"GateResult {field} differs from its definition")
    if value["evidence_class"] != definition["expected_evidence_class"]:
        raise ConformanceError("GateResult evidence class differs from its definition")
    gate_owner = bundle.core["policy-set.json"]["gate_run_definition_contract"]
    allowed_classes = gate_owner["evidence_class_purpose_pairs"].get(
        definition["expected_evidence_purpose"], []
    )
    if definition["expected_evidence_class"] not in allowed_classes:
        raise ConformanceError("GateRunDefinition evidence class-purpose pair is invalid")

    command = context.get("gate_command")
    if isinstance(command, Mapping):
        if (
            command.get("definition_digest") != value["definition_digest"]
            or not isinstance(command.get("payload"), Mapping)
            or command["payload"].get("definition_digest")
            != value["definition_digest"]
            or "gate_run_definition" in command
            or "gate_run_definition" in command["payload"]
        ):
            raise ConformanceError(
                "gate command does not bind the exact definition"
            )
        _validate_gate_command_scope(
            command, definition, task_id=value["task_id"], bundle=bundle
        )
    run = context.get("gate_run")
    if not isinstance(run, Mapping):
        raise ConformanceError("GateResult requires its exact Run")
    try:
        validate_definition(bundle.schema, "Run", run)
    except Exception as exc:
        raise ConformanceError("GateResult Run is not Core-valid") from exc
    if (
        run.get("run_id") != value["run_id"]
        or value.get("run_digest") != digest_value(run)
        or run.get("task_id") != value["task_id"]
        or run.get("definition_digest") != value["definition_digest"]
        or run.get("run_kind") != definition["run_kind"]
        or any(run.get(field) != definition[field] for field in (
            "candidate_digest",
            "policy_digest",
            "tool_digest",
            "implementation_closure_digest",
            "provider_binding_digest",
            "input_digests",
            "activation_digest",
        ))
    ):
        raise ConformanceError("GateResult Run differs from its definition")

    supplied_artifacts = context.get("gate_evidence_artifacts")
    if not isinstance(supplied_artifacts, Mapping):
        raise ConformanceError("GateResult requires exact Artifact-record bindings")
    artifacts: list[Mapping[str, Any]] = []
    for binding in value["evidence_artifacts"]:
        finalized_record = supplied_artifacts.get(binding["artifact_id"])
        if (
            not isinstance(finalized_record, Mapping)
            or set(finalized_record) != {"artifact", "commit_binding"}
            or not isinstance(finalized_record.get("artifact"), Mapping)
            or not isinstance(finalized_record.get("commit_binding"), Mapping)
            or set(finalized_record["commit_binding"])
            != {"command_digest", "batch_digest", "primary_event_id", "primary_event_digest"}
        ):
            raise ConformanceError("GateResult references an unresolved finalized Artifact")
        artifact = finalized_record["artifact"]
        try:
            validate_definition(bundle.schema, "Artifact", artifact)
        except Exception as exc:
            raise ConformanceError("GateResult references a non-Core Artifact") from exc
        if (
            artifact.get("artifact_id") != binding["artifact_id"]
            or digest_value(finalized_record) != binding["artifact_record_digest"]
            or binding.get("run_id") != run["run_id"]
            or binding.get("run_digest") != value["run_digest"]
            or any(
                not isinstance(finalized_record["commit_binding"].get(field), str)
                or re.fullmatch(
                    r"[0-9a-f]{64}", finalized_record["commit_binding"][field]
                )
                is None
                for field in ("command_digest", "batch_digest", "primary_event_digest")
            )
        ):
            raise ConformanceError(
                "GateResult Artifact binding is not the exact Artifact-record digest"
            )
        evidence_binding = artifact.get("evidence_binding")
        if (
            artifact.get("artifact_kind") != "evidence"
            or artifact.get("evidence_class") != value["evidence_class"]
            or artifact.get("evidence_purpose")
            != definition["expected_evidence_purpose"]
            or not isinstance(evidence_binding, Mapping)
            or evidence_binding.get("activation_digest") != definition["activation_digest"]
            or evidence_binding.get("candidate_digest") != definition["candidate_digest"]
            or evidence_binding.get("policy_digest") != definition["policy_digest"]
            or evidence_binding.get("tool_digest") != definition["tool_digest"]
            or evidence_binding.get("implementation_closure_digest")
            != definition["implementation_closure_digest"]
            or evidence_binding.get("input_digests") != definition["input_digests"]
            or digest_value(evidence_binding.get("provider_invocations", []))
            != definition["provider_binding_digest"]
            or (
                definition["target_kind"] == "finding"
                and evidence_binding.get("finding_digest")
                != definition["target_digest"]
            )
            or (
                definition["target_kind"] == "candidate"
                and definition["target_digest"] != definition["candidate_digest"]
            )
        ):
            raise ConformanceError("GateResult Artifact differs from definition expectations")
        artifacts.append(artifact)

    status = value["status"]
    if status == "pass":
        if any(
            artifact.get("outcome") != "pass"
            or artifact.get("stale") is not False
            or artifact.get("unresolved") is not False
            for artifact in artifacts
        ):
            raise ConformanceError("passing GateResult contains non-passing evidence")
        if value["pass_credit"] is True and (
            definition["product_credit_required"] is not True
            or any(
                artifact.get("evidence_class") != "product-execution"
                or artifact.get("evidence_purpose") != "product"
                or artifact.get("product_credit_eligible") is not True
                for artifact in artifacts
            )
        ):
            raise ConformanceError("GateResult claims product credit without eligible evidence")
    elif status == "fail" and not any(
        artifact.get("outcome") in {"fail", "error"} for artifact in artifacts
    ):
        raise ConformanceError("failed GateResult lacks failing evidence")
    elif status == "blocked" and not any(
        artifact.get("outcome") == "blocked" or artifact.get("unresolved") is True
        for artifact in artifacts
    ):
        raise ConformanceError("blocked GateResult lacks blocked evidence")


def _workcard_bounds(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import validate_definition

    validate_definition(bundle.schema, "WorkCard", value)
    profile_id = context.get("operating_profile")
    if profile_id is None:
        profile_id = _activation_context(context).operating_profile
    profile = bundle.preset["profiles"].get(profile_id)
    if profile is None:
        raise ConformanceError("WorkCard selects an unknown profile")
    profile_keys = {
        "max_bytes": "max_context_bytes",
        "max_entities": "max_entities",
        "max_relations": "max_relations",
        "max_fanout_per_entity": "max_fanout_per_entity",
        "top_k": "top_k",
    }
    ceiling = bundle.core["conformance.json"]["workcard_hard_ceiling"]
    for key, selected in value["budget"].items():
        if selected > ceiling[key] or selected > profile[profile_keys[key]]:
            raise ConformanceError(f"WorkCard exceeds {key} ceiling")
    if value["operation_mode"] == "mutate" and "lease_id" not in value:
        raise ConformanceError("mutation WorkCard lacks Lease")
    if value["operation_mode"] == "read" and "lease_id" in value:
        raise ConformanceError("read WorkCard carries mutation Lease")


def _relation_domain_range(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import validate_definition

    validate_definition(bundle.schema, "Relation", value)
    definitions = {
        relation["kind"]: relation
        for relation in bundle.core["semantic-model.json"]["relations"]
    }
    selected = definitions[value["kind"]]
    if (
        value["source_type"] not in selected["source"]
        or value["target_type"] not in selected["target"]
    ):
        raise ConformanceError("typed relation violates Core domain/range")


def _dependency_state(
    bundle: "ContractBundle", context: Mapping[str, Any]
) -> tuple[
    dict[str, Mapping[str, Any]],
    list[Mapping[str, Any]],
    list[Mapping[str, Any]],
    list[Mapping[str, Any]],
    dict[str, list[str]],
]:
    from .contracts import validate_definition

    tasks_value = context.get("current_tasks")
    relations_value = context.get("current_relations")
    gates_value = context.get("current_gate_results")
    findings_value = context.get("current_findings")
    if not all(
        isinstance(item, (list, tuple))
        for item in (tasks_value, relations_value, gates_value, findings_value)
    ):
        raise ConformanceError("dependency evaluation requires exact current records")
    tasks: dict[str, Mapping[str, Any]] = {}
    for task in tasks_value:
        validate_definition(bundle.schema, "Task", task)
        if task["task_id"] in tasks:
            raise ConformanceError("current Task identity is duplicated")
        tasks[task["task_id"]] = task
    relations = list(relations_value)
    gates = list(gates_value)
    findings = list(findings_value)
    for relation in relations:
        validate_definition(bundle.schema, "Relation", relation)
    for gate in gates:
        validate_definition(bundle.schema, "GateResult", gate)
    for finding in findings:
        validate_definition(bundle.schema, "Finding", finding)
    dependencies = {task_id: [] for task_id in tasks}
    for relation in relations:
        if relation["kind"] != "DEPENDS_ON":
            continue
        if relation["source_id"] not in tasks or relation["target_id"] not in tasks:
            raise ConformanceError("DEPENDS_ON references a non-current Task")
        dependencies[relation["source_id"]].append(relation["target_id"])
    for task_id in dependencies:
        dependencies[task_id] = sorted(set(dependencies[task_id]))
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(task_id: str) -> None:
        if task_id in visiting:
            raise ConformanceError("DEPENDS_ON graph contains a cycle")
        if task_id in visited:
            return
        visiting.add(task_id)
        for dependency_id in dependencies[task_id]:
            visit(dependency_id)
        visiting.remove(task_id)
        visited.add(task_id)

    for task_id in sorted(tasks):
        visit(task_id)
    return tasks, relations, gates, findings, dependencies


def _dependency_graph_acyclicity(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    _dependency_state(bundle, context)


def _ready_frontier_projection(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import validate_definition

    frontier = context.get("ready_frontier", value)
    if not isinstance(frontier, Mapping):
        raise ConformanceError("ready frontier policy requires ReadyFrontier")
    try:
        validate_definition(bundle.schema, "ReadyFrontier", frontier)
    except Exception as exc:
        raise ConformanceError("ReadyFrontier is not Core-valid") from exc
    tasks, relations, gates, findings, dependencies = _dependency_state(bundle, context)
    owner = bundle.core["policy-set.json"]["derived_result_contracts"][
        "ReadyFrontier"
    ]
    gate_index: dict[tuple[str, str], Mapping[str, Any]] = {}
    for gate in gates:
        key = (gate["task_id"], gate["definition_digest"])
        if key in gate_index:
            raise ConformanceError("current GateResult identity is duplicated")
        gate_index[key] = gate
    open_blockers = {
        relation["target_id"]
        for relation in relations
        if relation["kind"] == "BLOCKS"
        and relation["target_type"] == "Task"
        and any(
            finding["finding_id"] == relation["source_id"]
            and finding["status"] in owner["blocking_finding_statuses"]
            and finding["blocking"] is True
            for finding in findings
        )
    }

    def accepted(task: Mapping[str, Any]) -> tuple[bool, list[str]]:
        result_digests: list[str] = []
        if task["state"] != owner["required_dependency_state"]:
            return False, result_digests
        for binding in task["gate_run_definitions"]:
            gate = gate_index.get((task["task_id"], binding["definition_digest"]))
            if (
                gate is None
                or gate["status"] != owner["gate_outcome"]
                or gate["pass_credit"] is not owner["gate_pass_credit"]
                or gate["activation_digest"] != task["activation_digest"]
                or gate["candidate_digest"] != task["candidate_digest"]
            ):
                return False, []
            result_digests.append(digest_value(gate))
        return True, sorted(result_digests)

    expected: list[dict[str, Any]] = []
    blocked = 0
    ready_state_tasks = [
        task for task in tasks.values() if task["state"] == owner["eligible_task_state"]
    ]
    for task in ready_state_tasks:
        dependency_results = [accepted(tasks[item]) for item in dependencies[task["task_id"]]]
        if task["task_id"] in open_blockers or not all(
            result[0] for result in dependency_results
        ):
            blocked += 1
            continue
        gate_digests = sorted(
            digest
            for _accepted, digests in dependency_results
            for digest in digests
        )
        expected.append(
            {
                "task_id": task["task_id"],
                "task_digest": digest_value(task),
                "created_at": task["created_at"],
                "candidate_digest": task["candidate_digest"],
                "acceptance_predicate": task["acceptance_predicate"],
                "dependency_task_ids": dependencies[task["task_id"]],
                "gate_result_digests": gate_digests,
            }
        )
    expected.sort(key=lambda item: (item["created_at"], item["task_id"]))
    supplied = frontier["ready_tasks"]
    if (
        supplied != expected[: len(supplied)]
        or frontier["evaluated_task_count"] != len(ready_state_tasks)
        or frontier["blocked_task_count"] != blocked
        or frontier["cycle_count"] != 0
        or frontier["ordering"] != owner["ordering"]
        or frontier["truncated"] is not (len(supplied) < len(expected))
        or frontier["truncated"] is not (frontier["continuation"] is not None)
    ):
        raise ConformanceError("ReadyFrontier differs from current dependency state")


def _runtime_validate(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    project_root = context.get("project_root")
    if project_root is None:
        raise ConformanceError("runtime validation requires a project root")
    from .service import ProminService

    result = ProminService(project_root).validate(replay=True)
    if result.get("status") != "pass":
        raise ConformanceError("production runtime validation did not pass")


def _continuation_page_union(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    projection = context.get("continuation_projection")
    query = context.get("continuation_query")
    budget = context.get("continuation_budget")
    depth = context.get("continuation_depth")
    resume_binding = context.get("continuation_resume_binding")
    expected_entities = context.get("expected_entity_ids")
    expected_relations = context.get("expected_relation_ids")
    if (
        projection is None
        or not isinstance(query, str)
        or not isinstance(budget, Mapping)
        or not isinstance(depth, int)
        or isinstance(depth, bool)
        or not isinstance(resume_binding, Mapping)
        or not isinstance(expected_entities, (set, frozenset, list, tuple))
        or not isinstance(expected_relations, (set, frozenset, list, tuple))
    ):
        raise ConformanceError(
            "continuation closure check requires a production Projection and exact reference IDs"
        )
    now = context.get("continuation_now", "2026-07-17T12:00:00Z")
    ttl_seconds = context.get("continuation_ttl_seconds", 900)
    max_pages = context.get("continuation_max_pages", 10_000)
    if not isinstance(max_pages, int) or isinstance(max_pages, bool) or max_pages < 1:
        raise ConformanceError("continuation page limit is invalid")
    continuation_owner = bundle.core["authority-model.json"][
        "continuation_access_rule"
    ]
    if set(resume_binding) != set(
        continuation_owner["required_resume_binding_fields"]
    ):
        raise ConformanceError("continuation authorization binding fields are not exact")
    try:
        page = projection.search(
            query,
            depth=depth,
            budget=dict(budget),
            resume_binding=dict(resume_binding),
            now=now,
            ttl_seconds=ttl_seconds,
        )
    except Exception as exc:
        raise ConformanceError("production continuation search failed") from exc
    seen_entities: set[str] = set()
    seen_relations: set[str] = set()
    pages = 0
    while True:
        pages += 1
        if pages > max_pages:
            raise ConformanceError("continuation exceeded the bounded page limit")
        entity_ids = [item.get("id") for item in page.get("entities", ())]
        relation_ids = [item.get("relation_id") for item in page.get("relations", ())]
        if (
            any(not isinstance(item, str) or not item for item in entity_ids)
            or any(not isinstance(item, str) or not item for item in relation_ids)
            or seen_entities.intersection(entity_ids)
            or seen_relations.intersection(relation_ids)
        ):
            raise ConformanceError("continuation emitted an invalid or duplicate closure item")
        seen_entities.update(entity_ids)
        seen_relations.update(relation_ids)
        if page.get("truncated") is False:
            if page.get("continuation") is not None:
                raise ConformanceError("complete continuation page still carries a token")
            break
        continuation = page.get("continuation")
        if (
            not isinstance(continuation, Mapping)
            or continuation.get("version") != continuation_owner["token_version"]
            or continuation.get("traversal")
            != continuation_owner["traversal_algorithm_id"]
            or not isinstance(continuation.get("token"), str)
        ):
            raise ConformanceError("truncated page lacks a continuation v2 traversal token")
        cursor = page.get("stream_cursor")
        next_cursor = page.get("next_stream_cursor")
        if (
            not isinstance(cursor, int)
            or isinstance(cursor, bool)
            or not isinstance(next_cursor, int)
            or isinstance(next_cursor, bool)
            or next_cursor <= cursor
            or continuation.get("cursor") != next_cursor
        ):
            raise ConformanceError("continuation cursor did not advance monotonically")
        try:
            page = projection.continue_search(
                continuation["token"],
                resume_binding=dict(resume_binding),
                now=now,
            )
        except Exception as exc:
            raise ConformanceError("production continuation resume failed") from exc
    if seen_entities != set(expected_entities) or seen_relations != set(expected_relations):
        raise ConformanceError("continuation page union lost or added typed closure items")


def _candidate_recipe_applied_once(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    project_root = context.get("project_root")
    source_roots = context.get("inventory_source_roots")
    expected_paths = context.get("expected_inventory_paths")
    if (
        project_root is None
        or not isinstance(source_roots, (list, tuple))
        or not source_roots
        or not isinstance(expected_paths, (set, frozenset, list, tuple))
    ):
        raise ConformanceError(
            "candidate recipe check requires an isolated project, roots, and exact paths"
        )
    from .service import inventory_candidate

    try:
        result = inventory_candidate(Path(project_root), tuple(source_roots))
    except Exception as exc:
        raise ConformanceError("production Candidate inventory failed") from exc
    actual_paths = [item.get("path") for item in result.entries]
    inventory_contract = bundle.core["conformance.json"]["scale_contracts"][
        "inventory"
    ]
    expected_product_tree_passes = _required_nonnegative_int(
        inventory_contract,
        "project_tree_passes_max",
        owner="Core inventory scale contract",
    )
    if (
        expected_product_tree_passes <= 0
        or result.product_tree_passes != expected_product_tree_passes
        or any(not isinstance(path, str) or not path for path in actual_paths)
        or len(actual_paths) != len(set(actual_paths))
        or set(actual_paths) != set(expected_paths)
    ):
        raise ConformanceError("candidate recipe was not applied exactly once")


def _candidate_snapshot_policy(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    candidate = context.get("candidate")
    if not isinstance(candidate, Mapping):
        raise ConformanceError("candidate snapshot check requires a concrete Candidate")
    from .contracts import validate_candidate_consistency, validate_ingress

    try:
        validate_candidate_consistency(candidate)
        validate_ingress(
            bundle,
            candidate,
            operation="import",
            definition="Candidate",
            context={
                key: context[key]
                for key in (
                    "candidate_recipe_digest",
                    "candidate_consistency_mode",
                    "snapshot_provider_id",
                )
                if key in context
            },
        )
    except Exception as exc:
        raise ConformanceError("Candidate snapshot consistency is invalid") from exc


def _creditable_candidate_snapshot(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    _candidate_snapshot_policy(value, bundle, context)
    candidate = context["candidate"]
    if (
        candidate.get("creditable") is not True
        or candidate.get("consistency_mode") != "immutable-vcs-tree"
        or not isinstance(candidate.get("snapshot_provider_id"), str)
        or not isinstance(candidate.get("snapshot_digest"), str)
    ):
        raise ConformanceError(
            "credit-bearing Candidate lacks an immutable VCS provider binding"
        )


def _provider_adapter_dispatch(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    try:
        activation = _activation_context(context)
        dispatch = activation.provider_dispatch
        evidence = tuple(dispatch.runtime_evidence())
    except Exception as exc:
        raise ConformanceError("production provider dispatch is unavailable") from exc
    required = set(bundle.preset["required_provider_capabilities"])
    by_capability: dict[str, Mapping[str, Any]] = {}
    for item in evidence:
        if not isinstance(item, Mapping):
            raise ConformanceError("provider dispatch emitted non-object evidence")
        capability = item.get("capability_id")
        if not isinstance(capability, str) or capability in by_capability:
            raise ConformanceError("provider dispatch evidence is duplicate or unbound")
        if (
            not isinstance(item.get("provider_id"), str)
            or not isinstance(item.get("adapter_id"), str)
            or not isinstance(item.get("identity_digest"), str)
            or len(item["identity_digest"]) != 64
            or not isinstance(item.get("reconstructable"), bool)
            or not isinstance(item.get("persistence_scope"), str)
        ):
            raise ConformanceError("provider dispatch evidence lacks exact adapter identity")
        try:
            binding = dispatch.binding(capability)
        except Exception as exc:
            raise ConformanceError("provider dispatch cannot resolve its cited capability") from exc
        provider_id = (
            binding.get("provider_id")
            if isinstance(binding, Mapping)
            else getattr(binding, "provider_id", None)
        )
        if provider_id != item["provider_id"]:
            raise ConformanceError("provider dispatch evidence differs from invoked binding")
        by_capability[capability] = item
    if not required <= set(by_capability):
        raise ConformanceError("required provider capability has no invoked adapter evidence")


def _team_signed_runtime(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    project_root = context.get("project_root")
    command = context.get("team_signed_commit_command")
    if project_root is None or not isinstance(command, Mapping):
        raise ConformanceError(
            "team-signed runtime check requires an isolated project and commit command"
        )
    try:
        activation = _activation_context(context)
        authority = activation.plans["authority.json"]
        if authority.get("trust_mode") != "team-signed":
            raise ConformanceError("fixture is not team-signed")
        if activation.provider_dispatch.signature_verifier() is None:
            raise ConformanceError("team-signed Activation lacks its signature adapter")
        from .service import ProminService

        service = ProminService(Path(project_root))
        doctor = service.doctor(replay=True)
        status = service.status()
        validation = service.validate(replay=True)
        committed = service.commit(dict(command))
    except ConformanceError:
        raise
    except Exception as exc:
        raise ConformanceError("team-signed production workflow failed") from exc
    if (
        doctor.get("status") != "pass"
        or validation.get("status") != "pass"
        or status.get("activation_digest") != activation.activation_digest
        or not isinstance(committed, Mapping)
    ):
        raise ConformanceError("team-signed doctor/status/validate/commit is incomplete")


def _current_release_closure(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    domain = context.get("domain_state")
    candidate_digest = context.get("candidate_digest")
    status_kwargs = context.get("release_status_kwargs")
    if (
        domain is None
        or not isinstance(candidate_digest, str)
        or not isinstance(status_kwargs, Mapping)
    ):
        raise ConformanceError(
            "release closure check requires a concrete invalidated DomainState"
        )
    try:
        status = domain.approval_status(candidate_digest, **dict(status_kwargs))
    except Exception as exc:
        raise ConformanceError("current release closure evaluation failed") from exc
    reasons = status.get("invalidation_reasons")
    if (
        status.get("current_release_eligible") is not False
        or status.get("product_acceptance") is not False
        or status.get("public_release_approved") is not False
        or not isinstance(status.get("human_decision_id"), str)
        or not isinstance(reasons, list)
        or not reasons
    ):
        raise ConformanceError(
            "historical release Decision was not preserved and invalidated fail-closed"
        )


def _finding_disposition_binding(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    domain = context.get("domain_state")
    decision = context.get("finding_decision")
    authorization = context.get("finding_authorization")
    if (
        domain is None
        or not isinstance(decision, Mapping)
        or not isinstance(authorization, Mapping)
    ):
        raise ConformanceError(
            "Finding disposition check requires DomainState, Decision, and authorization"
        )
    try:
        stored = domain.record_decision(decision, authorization)
    except Exception as exc:
        raise ConformanceError("Finding disposition production path rejected its binding") from exc
    if (
        stored.get("decision_kind") not in {"resolve", "waive"}
        or stored.get("target_type") != "Finding"
        or not isinstance(stored.get("finding_digest"), str)
    ):
        raise ConformanceError("Finding disposition lacks exact target evidence binding")


def _candidate_delta_scope(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    domain = context.get("domain_state")
    artifact_digest = context.get("candidate_delta_artifact_digest")
    task_id = context.get("candidate_delta_task_id")
    workcard = context.get("candidate_delta_workcard")
    authorization = context.get("candidate_delta_authorization")
    if (
        domain is None
        or not isinstance(artifact_digest, str)
        or not isinstance(task_id, str)
        or not isinstance(workcard, Mapping)
        or not isinstance(authorization, Mapping)
    ):
        raise ConformanceError(
            "Candidate delta check requires exact Artifact, Task, WorkCard, and Grant"
        )
    try:
        result = domain.validate_candidate_delta(
            artifact_digest,
            task_id=task_id,
            workcard=workcard,
            authorization=authorization,
        )
    except Exception as exc:
        raise ConformanceError("Candidate delta production scope validation failed") from exc
    if result.get("artifact_kind") != "diff":
        raise ConformanceError("Candidate delta did not resolve an immutable diff Artifact")


def _verified_state_checkpoint(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    verified_store = context.get("verified_checkpoint_store")
    fallback_store = context.get("fallback_checkpoint_store")
    if verified_store is None or fallback_store is None:
        raise ConformanceError(
            "checkpoint check requires verified and corrupted-recovery EventStore fixtures"
        )
    try:
        verified = verified_store.checkpoint_status()
        fallback = fallback_store.checkpoint_status()
    except Exception as exc:
        raise ConformanceError("production checkpoint status failed") from exc
    if (
        verified.get("open_mode") != "verified-checkpoint"
        or verified.get("fallback_reason") is not None
        or fallback.get("open_mode") != "full-replay-fallback"
        or not fallback.get("fallback_reason")
        or verified.get("authoritative") is not False
        or fallback.get("authoritative") is not False
        or verified.get("head") != fallback.get("head")
        or verified.get("semantic_digest") != fallback.get("semantic_digest")
    ):
        raise ConformanceError(
            "checkpoint/delta replay and full-replay fallback are not equivalent"
        )


def _portable_distribution_policy(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    package_root = Path(context.get("package_root", bundle.source_root))
    install_mode = context.get("distribution_install_mode")
    wheelhouse = context.get("distribution_wheelhouse")
    rebuild_docs = context.get("distribution_rebuild_docs", False)
    font_bindings = context.get("distribution_font_bindings")
    if install_mode not in {
        "current-environment",
        "offline-wheelhouse",
        "online-clean",
    }:
        raise ConformanceError("distribution verification requires one explicit install mode")
    if not isinstance(rebuild_docs, bool) or (
        rebuild_docs and not isinstance(font_bindings, Mapping)
    ):
        raise ConformanceError("document rebuild requires explicit portable font bindings")
    from .mutation_suite import _load_tool

    try:
        validator = _load_tool(package_root, "promin_validate")
        report = validator.validate_tree(
            package_root,
            require_integrity=True,
            require_docs=True,
            install_mode=install_mode,
            wheelhouse=Path(wheelhouse) if wheelhouse is not None else None,
            rebuild_docs=rebuild_docs,
            font_bindings=font_bindings,
        )
    except Exception as exc:
        raise ConformanceError("production distribution folder verification failed") from exc
    if not report.valid:
        raise ConformanceError("distribution folder is invalid: " + "; ".join(report.errors))
    installability = report.checks.get("installability")
    identity = report.checks.get("identity_binding")
    documents = report.checks.get("documents")
    if (
        not isinstance(installability, Mapping)
        or installability.get("performed") is not True
        or installability.get("verified") is not True
        or installability.get("mode") != install_mode
        or installability.get("product_acceptance_pass") is not False
        or not isinstance(installability.get("runtime_dependency_source"), str)
        or not isinstance(installability.get("build_dependency_source"), str)
        or not isinstance(installability.get("declared_runtime_dependencies"), list)
        or not isinstance(installability.get("resolved_runtime_dependencies"), Mapping)
        or not isinstance(installability.get("console_script"), Mapping)
        or installability["console_script"].get("present") is not True
        or not isinstance(identity, Mapping)
        or identity.get("core_bundle_digest") != bundle.bundle_digest
        or identity.get("selected_preset_sha256") != bundle.preset_digest
        or not isinstance(identity.get("tool_digests"), Mapping)
        or not isinstance(identity.get("tool_versions"), Mapping)
        or not isinstance(documents, Mapping)
        or documents.get("existing_pdf_verification") is not True
    ):
        raise ConformanceError("distribution verification lacks portable bound signals")
    if install_mode == "current-environment":
        if (
            installability.get("environment") != "current-interpreter"
            or installability.get("installation_performed") is not False
            or installability.get("nested_venv_created") is not False
            or installability.get("network_access") != "not-used"
        ):
            raise ConformanceError("current-environment verification changed interpreter boundaries")
    elif not isinstance(installability.get("network_disabled"), bool):
        raise ConformanceError("clean install verification omitted network mode")
    if install_mode == "offline-wheelhouse" and not isinstance(
        installability.get("wheelhouse_binding"), Mapping
    ):
        raise ConformanceError("offline distribution lacks exact wheelhouse binding")
    if rebuild_docs and (
        documents.get("rebuild_performed") is not True
        or not isinstance(documents.get("build_evidence"), Mapping)
        or documents["build_evidence"].get("pass_credit") is not False
        or documents["build_evidence"].get("product_acceptance_pass") is not False
        or not isinstance(documents["build_evidence"].get("font_bindings"), Mapping)
    ):
        raise ConformanceError("portable document rebuild lacks explicit font evidence")
    platform_info = installability.get("platform")
    if not isinstance(platform_info, Mapping):
        raise ConformanceError("installability result lacks exact platform identity")
    if platform_info.get("os_name") != "nt" and installability["console_script"].get(
        "posix_execute_bits"
    ) is not True:
        raise ConformanceError("installed console script lacks POSIX execute bits")


def _portable_distribution_acceptance(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    _portable_distribution_policy(value, bundle, context)
    archive_path = context.get("distribution_archive")
    if archive_path is None:
        raise ConformanceError("exact distribution acceptance requires the ZIP artifact")
    package_root = Path(context.get("package_root", bundle.source_root))
    install_mode = context["distribution_install_mode"]
    wheelhouse = context.get("distribution_wheelhouse")
    rebuild_docs = context.get("distribution_rebuild_docs", False)
    font_bindings = context.get("distribution_font_bindings")
    from .mutation_suite import _load_tool

    try:
        verifier = _load_tool(package_root, "promin_package")
        result = verifier.verify_archive(
            Path(archive_path),
            install_mode=install_mode,
            wheelhouse=Path(wheelhouse) if wheelhouse is not None else None,
            rebuild_docs=rebuild_docs,
            font_bindings=font_bindings,
        )
    except Exception as exc:
        raise ConformanceError("production exact ZIP verification failed") from exc
    binding = result.get("artifact_binding")
    if (
        result.get("valid") is not True
        or result.get("clean_extraction") is not True
        or result.get("byte_deterministic") is not True
        or not isinstance(result.get("archive_sha256"), str)
        or not isinstance(binding, Mapping)
        or binding.get("archive_sha256") != result["archive_sha256"]
        or binding.get("core_bundle_digest") != bundle.bundle_digest
        or binding.get("selected_preset_sha256") != bundle.preset_digest
        or not isinstance(binding.get("tool_digests"), Mapping)
        or not isinstance(binding.get("tool_versions"), Mapping)
    ):
        raise ConformanceError("exact ZIP does not self-verify with complete artifact binding")


def _current_interpreter_and_clean_install_modes(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    package_root = Path(context.get("package_root", bundle.source_root))
    modes = context.get("install_modes")
    if not isinstance(modes, Mapping) or set(modes) != {
        "offline-wheelhouse",
        "online-clean",
    }:
        raise ConformanceError(
            "release install verification requires offline-wheelhouse and online-clean"
        )
    from .mutation_suite import _load_tool

    try:
        validator = _load_tool(package_root, "promin_validate")
        results = {
            mode: validator.verify_installability(
                package_root,
                mode=mode,
                wheelhouse=(
                    Path(wheelhouse) if wheelhouse is not None else None
                ),
            )
            for mode, wheelhouse in modes.items()
        }
    except Exception as exc:
        raise ConformanceError("production install verification failed") from exc
    offline = results["offline-wheelhouse"]
    online = results["online-clean"]
    offline_interpreter = offline.get("interpreter")
    online_interpreter = online.get("interpreter")
    if (
        offline.get("mode") != "offline-wheelhouse"
        or offline.get("environment") != "clean-venv"
        or offline.get("installation_performed") is not True
        or offline.get("nested_venv_created") is not True
        or offline.get("network_disabled") is not True
        or not isinstance(offline.get("wheelhouse_binding"), Mapping)
        or not isinstance(offline_interpreter, Mapping)
        or offline_interpreter.get("nested_venv_created") is not True
        or offline.get("verified") is not True
        or offline.get("product_acceptance_pass") is not False
        or offline.get("origin_assertion", {}).get("inside_site_packages") is not True
        or offline.get("origin_assertion", {}).get("source_absent_from_sys_path") is not True
        or offline.get("wheelhouse_lock", {}).get("source_unchanged") is not True
        or online.get("mode") != "online-clean"
        or online.get("environment") != "clean-venv"
        or online.get("installation_performed") is not True
        or online.get("nested_venv_created") is not True
        or online.get("network_disabled") is not False
        or not isinstance(online_interpreter, Mapping)
        or online_interpreter.get("nested_venv_created") is not True
        or online.get("verified") is not True
        or online.get("product_acceptance_pass") is not False
        or online.get("origin_assertion", {}).get("inside_site_packages") is not True
        or online.get("origin_assertion", {}).get("source_absent_from_sys_path") is not True
    ):
        raise ConformanceError("offline release and online compatibility lanes are incomplete")


def _required_no_degradation_tests_fail_closed(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    result = context.get("no_degradation_result")
    required = context.get("required_no_degradation_tests")
    if not isinstance(result, Mapping) or not isinstance(required, (set, list, tuple)):
        raise ConformanceError("no-degradation check requires an exact required-test result")
    tests = result.get("tests")
    if not isinstance(tests, Mapping) or set(tests) != set(required):
        raise ConformanceError("no-degradation result omits or adds required tests")
    for test_id, test_result in tests.items():
        if (
            not isinstance(test_result, Mapping)
            or test_result.get("status") != "pass"
            or test_result.get("skipped") is not False
            or test_result.get("executed") is not True
        ):
            raise ConformanceError(
                f"required no-degradation test did not execute and pass: {test_id}"
            )
    if result.get("status") != "pass" or result.get("fail_closed_on_skip") is not True:
        raise ConformanceError("no-degradation aggregate is not fail-closed")


def _forged_public_material_token(
    token: str, *, subject_id: str, grant_id: str
) -> str:
    del subject_id, grant_id
    if not isinstance(token, str) or len(token) < 8:
        raise ConformanceError("continuation fixture returned a malformed token")
    selected = len(token) - 1
    replacement = "A" if token[selected] != "A" else "B"
    return token[:selected] + replacement


def _continuation_secret_subject_grant_binding(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    service = context.get("continuation_service")
    subject_id = context.get("continuation_subject_id")
    grant_id = context.get("continuation_grant_id")
    query = context.get("continuation_query")
    budget = context.get("continuation_budget")
    depth = context.get("continuation_depth")
    if (
        service is None
        or not isinstance(subject_id, str)
        or not isinstance(grant_id, str)
        or not isinstance(query, str)
        or not isinstance(budget, Mapping)
        or not isinstance(depth, int)
        or isinstance(depth, bool)
    ):
        raise ConformanceError("continuation binding check lacks a production service fixture")
    now = context.get("continuation_now")
    try:
        first = service.search(
            query,
            depth,
            subject_id=subject_id,
            grant_id=grant_id,
            budget=dict(budget),
            now=now,
        )
        token = first.get("continuation", {}).get("token")
        if not isinstance(token, str):
            raise ConformanceError("continuation binding fixture did not truncate")
        resumed = service.continue_search(
            token,
            subject_id=subject_id,
            grant_id=grant_id,
            now=now,
        )
        if not isinstance(resumed, Mapping):
            raise ConformanceError("authorized continuation did not resume")
    except ConformanceError:
        raise
    except Exception as exc:
        raise ConformanceError("authorized continuation production path failed") from exc

    invalid_attempts = (
        (
            _forged_public_material_token(
                token, subject_id=subject_id, grant_id=grant_id
            ),
            subject_id,
            grant_id,
        ),
        (token, subject_id + ":other", grant_id),
        (token, subject_id, grant_id + ":other"),
    )
    for selected_token, selected_subject, selected_grant in invalid_attempts:
        try:
            service.continue_search(
                selected_token,
                subject_id=selected_subject,
                grant_id=selected_grant,
                now=now,
            )
        except Exception:
            continue
        raise ConformanceError("continuation accepted mismatched public or authority material")


def _implementation_closure_bound_and_current(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    try:
        activation = _activation_context(context)
    except Exception as exc:
        raise ConformanceError("implementation closure cannot verify Activation") from exc
    activation_value = getattr(activation, "activation", None)
    closure_digest = getattr(activation, "implementation_closure_digest", None)
    if closure_digest is None and isinstance(activation_value, Mapping):
        closure_digest = activation_value.get("implementation_closure_digest")
    if (
        not isinstance(closure_digest, str)
        or len(closure_digest) != 64
        or any(character not in "0123456789abcdef" for character in closure_digest)
    ):
        raise ConformanceError("Activation lacks a current implementation closure digest")
    expected = context.get("implementation_closure_digest")
    if expected is not None and expected != closure_digest:
        raise ConformanceError("implementation closure differs from the expected release binding")


def _verified_inventory_result_provenance(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    service = context.get("inventory_service")
    inventory = context.get("inventory_result")
    if service is None or inventory is None:
        raise ConformanceError("verified inventory check requires service and InventoryResult")
    try:
        from .service import InventoryResult

        if not isinstance(inventory, InventoryResult):
            raise ConformanceError("public rebuild input is not an InventoryResult")
        result = service.rebuild(inventory)
    except ConformanceError:
        raise
    except Exception as exc:
        raise ConformanceError("verified InventoryResult rebuild failed") from exc
    conformance = bundle.core["conformance.json"]
    reference = conformance["reference_benchmarks"]
    inventory_contract = conformance["scale_contracts"]["inventory"]
    projection_contract = conformance["scale_contracts"]["projection"]
    inventory_passes_max = _required_nonnegative_int(
        inventory_contract,
        "project_tree_passes_max",
        owner="Core inventory scale contract",
    )
    rebuild_product_passes = _required_nonnegative_int(
        projection_contract,
        "rebuild_product_tree_passes",
        owner="Core projection scale contract",
    )
    synthetic_tasks_per_file = _required_nonnegative_int(
        inventory_contract,
        "synthetic_tasks_per_raw_file",
        owner="Core inventory scale contract",
    )
    expected_synthetic_task_count = len(inventory.entries) * synthetic_tasks_per_file
    expected_proxy_ratio = _required_nonnegative_number(
        reference, "raw_file_proxy_ratio", owner="Core reference benchmarks"
    )
    inventory_passes = result.get("inventory_passes")
    if (
        result.get("product_passes") != rebuild_product_passes
        or not isinstance(inventory_passes, int)
        or isinstance(inventory_passes, bool)
        or inventory_passes != inventory.product_tree_passes
        or not 0 <= inventory_passes <= inventory_passes_max
        or result.get("synthetic_task_count") != expected_synthetic_task_count
        or result.get("raw_file_proxy_ratio") != expected_proxy_ratio
    ):
        raise ConformanceError("verified inventory rebuild inflated or rescanned the graph")


def _supported_command_surface(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    expected = ["init", "doctor", "status", "next", "validate", "static-admission", "continue", "audit", "refresh", "context", "skills"]
    preset = bundle.preset
    if (
        preset.get("base_user_commands") != expected
        or preset.get("optional_user_commands", []) != []
        or bundle.core["conformance.json"]["structural_budgets"].get(
            "base_user_commands_max"
        )
        != len(expected)
    ):
        raise ConformanceError("v1 exposes commands without an end-to-end implementation")


def _contains_value(value: Any, forbidden: str) -> bool:
    if isinstance(value, Mapping):
        return any(_contains_value(item, forbidden) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_value(item, forbidden) for item in value)
    return value == forbidden


def _supported_snapshot_modes(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    inventory = bundle.core["conformance.json"].get("scale_contracts", {}).get(
        "inventory", {}
    )
    if (
        inventory.get("creditable_consistency_modes") != ["immutable-vcs-tree"]
        or _contains_value(bundle.core, "immutable-filesystem-snapshot")
        or _contains_value(bundle.preset, "immutable-filesystem-snapshot")
    ):
        raise ConformanceError("v1 exposes an inventory mode without its full protocol")


def _contains_key(value: Any, forbidden: str) -> bool:
    if isinstance(value, Mapping):
        return forbidden in value or any(
            _contains_key(item, forbidden) for item in value.values()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_key(item, forbidden) for item in value)
    return False


def _zero_dead_evidence_budget_fields(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    if _contains_key(bundle.core, "max_evidence") or _contains_key(
        bundle.preset, "max_evidence"
    ):
        raise ConformanceError("dead max_evidence budget remains in canonical inputs")


def _profile_bound_physical_100k_performance(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    result = context.get("physical_100k_result")
    if not isinstance(result, Mapping):
        raise ConformanceError("physical 100k result is absent")
    _validate_physical_scale_result(
        result,
        bundle=bundle,
        check_id="profile-bound-physical-100k-performance",
    )


def _windows_linux_exact_zip_matrix(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    results = context.get("platform_results")
    archive_sha256 = context.get("archive_sha256")
    if not isinstance(results, Mapping) or set(results) != {"windows", "linux"}:
        raise ConformanceError("release matrix must contain exactly Windows and Linux")
    required_suites = {"clean-install", "package", "path", "crash"}
    for platform_id, result in results.items():
        if not isinstance(result, Mapping) or result.get("archive_sha256") != archive_sha256:
            raise ConformanceError(f"{platform_id} result is not bound to the exact ZIP")
        suites = result.get("suites")
        if not isinstance(suites, Mapping) or set(suites) != required_suites:
            raise ConformanceError(f"{platform_id} result has an incomplete suite set")
        if any(
            not isinstance(item, Mapping)
            or item.get("status") != "pass"
            or item.get("skipped") is not False
            for item in suites.values()
        ):
            raise ConformanceError(f"{platform_id} suite did not execute and pass")


def _three_zero_new_saturation_iterations(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    iterations = context.get("saturation_iterations")
    archive_sha256 = context.get("archive_sha256")
    if not isinstance(iterations, (list, tuple)) or len(iterations) != 3:
        raise ConformanceError("saturation requires exactly three complete iterations")
    for index, iteration in enumerate(iterations, 1):
        if (
            not isinstance(iteration, Mapping)
            or iteration.get("iteration") != index
            or iteration.get("archive_sha256") != archive_sha256
            or iteration.get("status") != "pass"
            or iteration.get("new_finding_classes") != []
            or iteration.get("complete") is not True
        ):
            raise ConformanceError(f"saturation iteration {index} is incomplete or nonzero")


def _standard_distribution_separate_from_product_acceptance(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    status = context.get("release_status", value)
    if (
        not isinstance(status, Mapping)
        or status.get("record_type") != "StandardDistributionStatus"
        or status.get("standard_name") != "promin"
        or status.get("version") != bundle.manifest.get("version")
        or status.get("distribution_status")
        not in {
            "candidate",
            "approved",
            "rejected",
            "invalidated",
            "signature_valid_under_supplied_root",
        }
        or status.get("current_distribution_eligible")
        is not (status.get("distribution_status") == "approved")
        or status.get("product_acceptance_pass") is not False
        or status.get("product_public_approval") != "not_approved"
        or "public_approval" in status
        or "product_acceptance" in status
        or "public_release_approved" in status
    ):
        raise ConformanceError("standard distribution state is mixed with product acceptance")


def _release_chain_context(
    value: Mapping[str, Any],
    context: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], Mapping[str, Any], Path]:
    candidate = context.get("standard_release_candidate_binding")
    evidence_manifest = context.get("standard_release_evidence_manifest")
    trust_configuration = context.get("standard_release_trust_configuration")
    decision = context.get("standard_release_decision", value)
    evidence_root = context.get("standard_release_evidence_root")
    if (
        not isinstance(candidate, Mapping)
        or not isinstance(evidence_manifest, Mapping)
        or not isinstance(trust_configuration, Mapping)
        or not isinstance(decision, Mapping)
        or evidence_root is None
    ):
        raise ConformanceError(
            "standard decision check requires candidate, physical evidence, trust, and decision"
        )
    return candidate, evidence_manifest, trust_configuration, decision, Path(evidence_root)


def _semver_from_candidate_binding(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    candidate = context.get("standard_release_candidate_binding", value)
    if not isinstance(candidate, Mapping):
        raise ConformanceError("candidate SemVer check lacks a candidate binding")
    try:
        from .evidence import validate_standard_release_candidate_binding

        validated = validate_standard_release_candidate_binding(candidate)
    except Exception as exc:
        raise ConformanceError("candidate binding is not structurally valid") from exc
    version = validated.get("version")
    owner_versions = {
        bundle.manifest.get("version"),
        bundle.preset.get("version"),
        *(owner.get("version") for owner in bundle.core.values()),
    }
    if (
        not isinstance(version, str)
        or _SEMVER.fullmatch(version) is None
        or owner_versions != {version}
    ):
        raise ConformanceError("candidate SemVer differs from canonical standard owners")


def _evidence_manifest_physical_resolution(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    candidate = context.get("standard_release_candidate_binding")
    evidence_manifest = context.get("standard_release_evidence_manifest", value)
    evidence_root = context.get("standard_release_evidence_root")
    trust_configuration = context.get("standard_release_trust_configuration")
    if (
        not isinstance(candidate, Mapping)
        or not isinstance(evidence_manifest, Mapping)
        or evidence_root is None
        or not isinstance(trust_configuration, Mapping)
    ):
        raise ConformanceError(
            "physical evidence check requires candidate, manifest, and configured root"
        )
    try:
        from .evidence import validate_standard_release_evidence_manifest

        resolved = validate_standard_release_evidence_manifest(
            evidence_manifest,
            candidate_binding=candidate,
            evidence_root=Path(evidence_root),
            trust_configuration=trust_configuration,
            candidate_document_members=context.get(
                "standard_candidate_document_members", ()
            ),
        )
    except Exception as exc:
        raise ConformanceError(
            "standard evidence manifest is not physically digest-resolved"
        ) from exc
    if resolved.get("all_required_roles_resolved") is not True:
        raise ConformanceError("standard evidence manifest lacks a required resolved role")


def _authenticated_role_platform_evidence_attestations(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    _evidence_manifest_physical_resolution(value, bundle, context)


def _installed_platform_observation_closure(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    candidate = context.get("standard_release_candidate_binding")
    manifest = context.get("standard_release_evidence_manifest")
    root = context.get("standard_release_evidence_root")
    trust = context.get("standard_release_trust_configuration")
    try:
        from .evidence import validate_standard_release_evidence_manifest

        resolved = validate_standard_release_evidence_manifest(
            manifest,
            candidate_binding=candidate,
            evidence_root=Path(root),
            trust_configuration=trust,
            candidate_document_members=context.get(
                "standard_candidate_document_members", ()
            ),
        )
    except Exception as exc:
        raise ConformanceError("installed platform observation closure is invalid") from exc
    closure = resolved.get("derived_multi_platform_implementation_closure")
    if (
        not isinstance(closure, Mapping)
        or closure.get("record_type")
        != "DerivedMultiPlatformImplementationClosure"
        or closure.get("platforms_complete") is not True
        or closure.get("portable_implementation_closed") is not True
        or closure.get("product_acceptance_pass") is not False
        or closure.get("product_public_approval") != "not_approved"
    ):
        raise ConformanceError("installed Windows/Linux closure is incomplete")


def _handle_relative_evidence_root_safety(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    results = context.get("external_read_race_results", value)
    required = {
        "posix_parent_component_swap": "rejected",
        "windows_junction_reparse": "rejected",
        "root_substitution": "rejected",
        "same_bytes_hash_and_parse": "pass",
    }
    if not isinstance(results, Mapping) or any(
        results.get(name) != expected for name, expected in required.items()
    ):
        raise ConformanceError("handle-relative evidence-root race matrix is incomplete")


def _raw_scale_summary_recomputation(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    result = context.get("physical_100k_result", value)
    candidate = context.get("standard_release_candidate_binding")
    source_path = context.get("physical_100k_result_path")
    evidence_root = context.get("standard_release_evidence_root")
    if not isinstance(result, Mapping) or not isinstance(candidate, Mapping):
        raise ConformanceError("raw scale recomputation lacks candidate-bound evidence")
    try:
        from .evidence import validate_saturation_evidence

        validate_saturation_evidence(
            result,
            candidate_binding=candidate,
            source_path=Path(source_path),
            evidence_root=Path(evidence_root),
        )
    except Exception as exc:
        raise ConformanceError("raw scale summaries do not recompute") from exc


def _bounded_incremental_commit_and_compaction(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    _profile_bound_physical_100k_performance(value, bundle, context)
    result = context.get("physical_100k_result", value)
    performance = result.get("performance") if isinstance(result, Mapping) else None
    if (
        not isinstance(performance, Mapping)
        or performance.get("semantic_commit_count", 0) < 1
        or performance.get("runtime_checkpoint_writes", 0)
        > performance.get("runtime_checkpoint_count", -1)
    ):
        raise ConformanceError("incremental commit/checkpoint evidence is incomplete")


def _offline_installed_no_degradation(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    candidate = context.get("standard_release_candidate_binding")
    results = context.get("no_degradation_results")
    if not isinstance(candidate, Mapping) or not isinstance(results, Mapping) or set(results) != {
        "linux",
        "windows",
    }:
        raise ConformanceError("offline no-degradation requires exact Linux and Windows results")
    try:
        from .evidence import validate_no_degradation_result

        for platform_name in ("linux", "windows"):
            validate_no_degradation_result(
                results[platform_name],
                candidate_binding=candidate,
                expected_platform=platform_name,
            )
    except Exception as exc:
        raise ConformanceError("offline installed no-degradation is invalid") from exc


def _decision_after_evidence_with_bounded_skew(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    _signed_standard_decision_authority_proof(value, bundle, context)


def _single_derived_platform_closure_owner(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    if context.get("supplied_platform_closure") is not None:
        raise ConformanceError("independently supplied platform closure is forbidden")
    _installed_platform_observation_closure(value, bundle, context)


def _truthful_process_invocation_status(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    result = context.get("physical_100k_result", value)
    if not isinstance(result, Mapping):
        raise ConformanceError("truthful process status lacks a physical result")
    expected_exit = 0 if result.get("status") == "pass" else 1
    invocation = result.get("invocation")
    process_exit = context.get("physical_process_exit_code", expected_exit)
    if (
        not isinstance(invocation, Mapping)
        or invocation.get("exit_code") != expected_exit
        or process_exit != expected_exit
    ):
        raise ConformanceError("process, invocation, and result status disagree")
    _raw_scale_summary_recomputation(value, bundle, context)


def _product_public_approval_separation(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    status = context.get("release_status", value)
    if (
        not isinstance(status, Mapping)
        or "public_approval" in status
        or status.get("product_public_approval") != "not_approved"
        or status.get("product_acceptance_pass") is not False
    ):
        raise ConformanceError("standard distribution is ambiguous with product/public approval")


def _historical_decision_current_eligibility_separation(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    status = context.get("release_status", value)
    if not isinstance(status, Mapping):
        raise ConformanceError("distribution status is absent")
    eligible = status.get("current_distribution_eligible")
    if (
        not isinstance(eligible, bool)
        or not isinstance(status.get("historical_decision_present"), bool)
        or (
            status["historical_decision_present"]
            and not isinstance(status.get("historical_decision_digest"), str)
        )
    ):
        raise ConformanceError("historical decision and current eligibility are conflated")


def _signed_standard_decision_authority_proof(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    candidate, evidence_manifest, trust_configuration, decision, _ = (
        _release_chain_context(value, context)
    )
    try:
        from .evidence import (
            standard_distribution_status,
            validate_standard_release_decision,
        )

        validated = validate_standard_release_decision(
            decision,
            candidate_binding=candidate,
            evidence_manifest=evidence_manifest,
            evidence_root=Path(context["standard_release_evidence_root"]),
            trust_configuration=trust_configuration,
            candidate_document_members=context.get(
                "standard_candidate_document_members", ()
            ),
        )
        status = standard_distribution_status(
            decision,
            candidate_binding=candidate,
            evidence_manifest=evidence_manifest,
            evidence_root=Path(context["standard_release_evidence_root"]),
            trust_configuration=trust_configuration,
            candidate_document_members=context.get(
                "standard_candidate_document_members", ()
            ),
            trust_configuration_sha256=context.get(
                "standard_trust_configuration_sha256"
            ),
            expected_trust_root_sha256=context.get(
                "expected_trust_root_sha256"
            ),
        )
    except Exception as exc:
        raise ConformanceError(
            "standard decision lacks configured Ed25519 authority proof"
        ) from exc
    expected_status = "approved" if validated.get("outcome") == "approve" else "rejected"
    if (
        status.get("distribution_status") != expected_status
        or status.get("current_distribution_eligible")
        is not (validated.get("outcome") == "approve")
        or status.get("product_acceptance_pass") is not False
        or status.get("product_public_approval") != "not_approved"
    ):
        raise ConformanceError("standard decision produced contradictory derived status")


def _candidate_evidence_decision_acyclic_chain(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    candidate, evidence_manifest, _, decision, _ = _release_chain_context(value, context)
    _semver_from_candidate_binding(candidate, bundle, context)
    _evidence_manifest_physical_resolution(value, bundle, context)
    _signed_standard_decision_authority_proof(value, bundle, context)
    reverse_link_names = {
        "decision_digest",
        "decision_id",
        "evidence_manifest_digest",
        "distribution_status",
        "current_distribution_eligible",
    }
    if reverse_link_names.intersection(candidate):
        raise ConformanceError("candidate identity contains a reverse decision/evidence link")
    if evidence_manifest.get("candidate_binding_digest") != candidate.get(
        "candidate_binding_digest"
    ):
        raise ConformanceError("evidence manifest does not bind the exact candidate")
    if decision.get("evidence_manifest_digest") != evidence_manifest.get(
        "evidence_manifest_digest"
    ):
        raise ConformanceError("decision does not bind the exact evidence manifest")


def _typed_human_document_verification(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    verification = context.get("human_document_verification", value)
    candidate = context.get("standard_release_candidate_binding")
    if not isinstance(verification, Mapping) or not isinstance(candidate, Mapping):
        raise ConformanceError("human document check lacks typed candidate-bound evidence")
    try:
        from .evidence import (
            validate_human_document_verification,
            validate_standard_release_candidate_binding,
        )

        validated_candidate = validate_standard_release_candidate_binding(candidate)
        validate_human_document_verification(
            verification,
            candidate_binding=validated_candidate,
            candidate_document_members=context.get(
                "standard_candidate_document_members", ()
            ),
            source_path=Path(context["human_document_verification_path"]),
            evidence_root=Path(context["standard_release_evidence_root"]),
        )
    except Exception as exc:
        raise ConformanceError("human document evidence is not exact and candidate-bound") from exc


def _external_standard_release_decision_exact_binding(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    decision = context.get("standard_release_decision", value)
    decision_path = context.get("standard_release_decision_path")
    candidate = context.get("standard_release_candidate_binding")
    if (
        not isinstance(decision, Mapping)
        or decision.get("record_type") != "StandardReleaseDecision"
        or decision.get("standard_name") != "promin"
        or decision.get("version") != bundle.manifest.get("version")
        or not isinstance(candidate, Mapping)
        or decision_path is None
    ):
        raise ConformanceError("external StandardReleaseDecision is absent or malformed")
    try:
        resolved_decision = Path(decision_path).resolve(strict=True)
        resolved_package = Path(bundle.source_root).resolve(strict=True)
        resolved_decision.relative_to(resolved_package)
    except ValueError:
        pass
    except Exception as exc:
        raise ConformanceError("external StandardReleaseDecision path is invalid") from exc
    else:
        raise ConformanceError("StandardReleaseDecision must remain outside the standard folder")
    try:
        _candidate_evidence_decision_acyclic_chain(value, bundle, context)
    except Exception as exc:
        raise ConformanceError(
            "StandardReleaseDecision does not exactly bind the release evidence"
        ) from exc


def _release_evidence_and_platform_gate(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    _portable_distribution_acceptance(value, bundle, context)
    _windows_linux_exact_zip_matrix(value, bundle, context)
    _three_zero_new_saturation_iterations(value, bundle, context)
    _external_standard_release_decision_exact_binding(value, bundle, context)


def integrity_requirement_catalogue() -> dict[str, Check]:
    """Executable owners for every requirement row in the 12 x 6 x 6 matrix."""

    return {
        "R1": _portable_distribution_acceptance,
        "R2": _current_interpreter_and_clean_install_modes,
        "R3": _continuation_secret_subject_grant_binding,
        "R4": _verified_inventory_result_provenance,
        "R5": _profile_bound_physical_100k_performance,
        "R6": _implementation_closure_bound_and_current,
        "R7": _supported_snapshot_modes,
        "R8": _verified_inventory_result_provenance,
        "R9": _supported_command_surface,
        "R10": _zero_dead_evidence_budget_fields,
        "R11": _standard_distribution_separate_from_product_acceptance,
        "R12": _release_evidence_and_platform_gate,
    }


def _profile_default_depth(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    service = context.get("profile_service")
    query = context.get("profile_query")
    subject_id = context.get("profile_subject_id")
    grant_id = context.get("profile_grant_id")
    if (
        service is None
        or not isinstance(query, str)
        or not isinstance(subject_id, str)
        or not isinstance(grant_id, str)
    ):
        raise ConformanceError("profile depth check requires a production service fixture")
    profile_id = context.get("operating_profile", bundle.preset["default_profile"])
    profile = bundle.preset["profiles"].get(profile_id)
    if profile is None or "default_dependency_depth" not in profile:
        raise ConformanceError("selected profile lacks one default dependency depth")
    maximum_depth = _required_nonnegative_int(
        bundle.core["conformance.json"],
        "dependency_depth_hard_max",
        owner="Core conformance",
    )
    if maximum_depth <= 0:
        raise ConformanceError("Core dependency depth ceiling is not positive")
    try:
        default_result = service.search(
            query, subject_id=subject_id, grant_id=grant_id
        )
        maximum_result = service.search(
            query,
            depth=maximum_depth,
            subject_id=subject_id,
            grant_id=grant_id,
        )
    except Exception as exc:
        raise ConformanceError("production profile depth search failed") from exc
    if (
        default_result.get("depth") != profile["default_dependency_depth"]
        or maximum_result.get("depth") != maximum_depth
    ):
        raise ConformanceError("profile default or Core hard depth maximum is not enforced")


def _broad_query_bounded_seed_refinement(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    result = context.get("broad_query_result", value)
    if not isinstance(result, Mapping):
        raise ConformanceError("broad-query check lacks a production search result")
    budget = result.get("budget")
    if not isinstance(budget, Mapping):
        budget = context.get("broad_query_budget")
    if not isinstance(budget, Mapping):
        raise ConformanceError("broad-query result lacks its exact budget")
    ceiling = _required_mapping(
        bundle.core["conformance.json"],
        "workcard_hard_ceiling",
        owner="Core conformance",
    )
    maximum_context_bytes = _required_nonnegative_int(
        ceiling, "max_bytes", owner="Core WorkCard hard ceiling"
    )
    maximum_top_k = _required_nonnegative_int(
        ceiling, "top_k", owner="Core WorkCard hard ceiling"
    )
    top_k = budget.get("top_k")
    max_bytes = budget.get("max_bytes")
    selected = result.get("selected_seed_count")
    hints = result.get("refinement_hints")
    continuation = result.get("continuation")
    selected_closure_complete = result.get("selected_closure_complete")
    selected_closure_union_complete = context.get(
        "selected_closure_union_complete", selected_closure_complete
    )
    try:
        result_bytes = len(canonical_bytes(dict(result)))
    except Exception as exc:
        raise ConformanceError("broad-query result is not canonical JSON") from exc
    if (
        not isinstance(top_k, int)
        or isinstance(top_k, bool)
        or top_k < 1
        or top_k > maximum_top_k
        or not isinstance(max_bytes, int)
        or isinstance(max_bytes, bool)
        or max_bytes <= 0
        or max_bytes > maximum_context_bytes
        or result_bytes > max_bytes
        or not isinstance(selected, int)
        or isinstance(selected, bool)
        or not 1 <= selected <= top_k
        or result.get("refinement_required") is not True
        or not isinstance(hints, list)
        or not hints
        or any(not isinstance(item, str) or not item for item in hints)
        or result.get("unselected_matches_traversable") is not False
        or result.get("corpus_pagination") is True
        or selected_closure_union_complete is not True
    ):
        raise ConformanceError("broad query is not bounded to selected seeds with refinement")
    if continuation is not None and not isinstance(continuation, Mapping):
        raise ConformanceError("broad query continuation metadata is malformed")


def _decode_opaque_digest(value: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, UnicodeError) as exc:
        raise ConformanceError("opaque continuation state digest is malformed") from exc
    if (
        len(decoded) != 32
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value
    ):
        raise ConformanceError("opaque continuation state digest is noncanonical")
    return decoded


def _continuation_token_bytes_at_most_256(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    token = context.get("continuation_token")
    state_path = context.get("continuation_state_path")
    workcard_path = context.get("continuation_workcard_path")
    if not isinstance(token, str) or state_path is None or workcard_path is None:
        raise ConformanceError("continuation size check requires token, state, and WorkCard files")
    scale_contracts = _required_mapping(
        bundle.core["conformance.json"],
        "scale_contracts",
        owner="Core conformance",
    )
    workcard_contract = _required_mapping(
        scale_contracts, "workcard", owner="Core scale contracts"
    )
    token_bytes_max = _required_nonnegative_int(
        workcard_contract,
        "continuation_token_bytes_max",
        owner="Core WorkCard scale contract",
    )
    state_bytes_max = _required_nonnegative_int(
        workcard_contract,
        "continuation_state_bytes_max",
        owner="Core WorkCard scale contract",
    )
    if token_bytes_max <= 0 or state_bytes_max <= 0:
        raise ConformanceError("Core continuation bounds are not positive")
    try:
        encoded = token.encode("ascii")
    except UnicodeError as exc:
        raise ConformanceError("continuation token is not ASCII") from exc
    parts = token.split(".")
    if len(parts) != 2 or len(encoded) > token_bytes_max:
        raise ConformanceError("continuation token is not a bounded opaque v2 reference")
    try:
        envelope_bytes = base64.urlsafe_b64decode(
            parts[0] + "=" * (-len(parts[0]) % 4)
        )
        envelope = parse_json_strict(envelope_bytes)
    except Exception as exc:
        raise ConformanceError("continuation token envelope is malformed") from exc
    if (
        not isinstance(envelope, Mapping)
        or set(envelope) != {"state_digest", "budgets"}
        or canonical_bytes(dict(envelope)) != envelope_bytes
        or not isinstance(envelope.get("state_digest"), str)
        or _DIGEST.fullmatch(envelope["state_digest"]) is None
        or not isinstance(envelope.get("budgets"), Mapping)
        or set(envelope["budgets"]) != {"max_entities"}
        or not isinstance(envelope["budgets"].get("max_entities"), int)
        or isinstance(envelope["budgets"].get("max_entities"), bool)
    ):
        raise ConformanceError("continuation token exposes unbounded context")
    _decode_opaque_digest(parts[1])
    expected_state_digest = envelope["state_digest"]
    selected_state = Path(state_path)
    selected_workcard = Path(workcard_path)
    if (
        selected_state.is_symlink()
        or not selected_state.is_file()
        or selected_workcard.is_symlink()
        or not selected_workcard.is_file()
    ):
        raise ConformanceError("continuation state or WorkCard is not a regular file")
    state_bytes = selected_state.stat().st_size
    try:
        workcard = load_json_strict(selected_workcard)
    except Exception as exc:
        raise ConformanceError("continuation WorkCard is not strict JSON") from exc
    budget = workcard.get("budget") if isinstance(workcard, Mapping) else None
    context_bytes = budget.get("max_bytes") if isinstance(budget, Mapping) else None
    if (
        state_bytes <= 0
        or state_bytes > state_bytes_max
        or not isinstance(context_bytes, int)
        or isinstance(context_bytes, bool)
        or context_bytes <= 0
        or len(encoded) * 10 > context_bytes
        or digest_file(selected_state) != expected_state_digest
    ):
        raise ConformanceError("continuation token/state exceeds its context budget")


def _inventory_stream_memory_amplification_at_most_32(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    result = context.get("inventory_stream_result", value)
    if not isinstance(result, Mapping):
        raise ConformanceError("inventory stream check lacks measured production evidence")
    conformance = bundle.core["conformance.json"]
    reference = _required_mapping(
        conformance, "reference_benchmarks", owner="Core conformance"
    )
    scale_contracts = _required_mapping(
        conformance, "scale_contracts", owner="Core conformance"
    )
    inventory_contract = _required_mapping(
        scale_contracts, "inventory", owner="Core scale contracts"
    )
    projection_contract = _required_mapping(
        scale_contracts, "projection", owner="Core scale contracts"
    )
    memory_amplification_max = _required_nonnegative_number(
        inventory_contract,
        "memory_amplification_max",
        owner="Core inventory scale contract",
    )
    inventory_passes = _required_nonnegative_int(
        reference, "inventory_passes", owner="Core reference benchmarks"
    )
    inventory_passes_max = _required_nonnegative_int(
        inventory_contract,
        "project_tree_passes_max",
        owner="Core inventory scale contract",
    )
    rebuild_product_passes = _required_nonnegative_int(
        projection_contract,
        "rebuild_product_tree_passes",
        owner="Core projection scale contract",
    )
    if (
        memory_amplification_max <= 0
        or inventory_passes <= 0
        or inventory_passes > inventory_passes_max
        or reference.get("rebuild_product_passes") != rebuild_product_passes
    ):
        raise ConformanceError("Core inventory scale owners are inconsistent")
    search_text_bytes_max = inventory_contract.get("search_text_bytes_max")
    manifest_path = result.get("manifest_path")
    stream_path = result.get("stream_path")
    if manifest_path is None or stream_path is None:
        raise ConformanceError("inventory stream check lacks physical manifest and JSONL")
    selected_manifest = Path(manifest_path)
    selected_stream = Path(stream_path)
    if (
        selected_manifest.is_symlink()
        or not selected_manifest.is_file()
        or selected_stream.is_symlink()
        or not selected_stream.is_file()
    ):
        raise ConformanceError("inventory manifest or JSONL is not a regular file")
    try:
        manifest = load_json_strict(selected_manifest)
    except Exception as exc:
        raise ConformanceError("inventory manifest is not strict JSON") from exc
    if not isinstance(manifest, Mapping):
        raise ConformanceError("inventory manifest is not an object")
    digest = hashlib.sha256()
    entry_count = 0
    stream_bytes = 0
    previous_path: str | None = None
    with selected_stream.open("rb") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.endswith(b"\n") or line == b"\n":
                raise ConformanceError("inventory JSONL contains a partial or blank record")
            try:
                row = parse_json_strict(line)
            except Exception as exc:
                raise ConformanceError(
                    f"inventory JSONL row {line_number} is not strict JSON"
                ) from exc
            if (
                not isinstance(row, Mapping)
                or set(row) not in (
                    {"path", "digest", "size"},
                    {"path", "digest", "size", "search_text"},
                )
                or canonical_bytes(dict(row)) != line
                or not isinstance(row.get("path"), str)
                or not row["path"]
                or (previous_path is not None and row["path"] <= previous_path)
                or not isinstance(row.get("digest"), str)
                or _DIGEST.fullmatch(row["digest"]) is None
                or not isinstance(row.get("size"), int)
                or isinstance(row.get("size"), bool)
                or row["size"] < 0
                or (
                    "search_text" in row
                    and (
                        not isinstance(search_text_bytes_max, int)
                        or isinstance(search_text_bytes_max, bool)
                        or search_text_bytes_max <= 0
                        or not isinstance(row["search_text"], str)
                        or len(row["search_text"].encode("utf-8"))
                        > search_text_bytes_max
                        or "\x00" in row["search_text"]
                    )
                )
            ):
                raise ConformanceError(
                    f"inventory JSONL row {line_number} violates its bounded shape"
                )
            previous_path = row["path"]
            digest.update(line)
            stream_bytes += len(line)
            entry_count += 1
    expected_digest = digest.hexdigest()
    peak_increment = result.get("peak_increment_bytes")
    amplification = result.get("memory_amplification")
    if (
        not isinstance(peak_increment, int)
        or isinstance(peak_increment, bool)
        or peak_increment < 0
        or not isinstance(amplification, (int, float))
        or isinstance(amplification, bool)
        or stream_bytes <= 0
        or abs(float(amplification) - peak_increment / stream_bytes) > 1e-9
        or float(amplification) > memory_amplification_max
        or manifest.get("stream_digest") != expected_digest
        or result.get("stream_digest") != expected_digest
        or manifest.get("stream_bytes") != stream_bytes
        or result.get("stream_bytes") != stream_bytes
        or manifest.get("entry_count") != entry_count
        or result.get("entry_count") != entry_count
        or result.get("manifest_digest") != digest_value(manifest)
        or result.get("manifest_verified_jsonl") is not True
        or result.get("atomic_publication") is not True
        or result.get("inventory_passes") != inventory_passes
        or result.get("rebuild_product_passes") != rebuild_product_passes
    ):
        raise ConformanceError("inventory stream is unverified, materialized, or over budget")


def _explicit_scale_marker_selection(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    result = context.get("scale_selection", value)
    if (
        not isinstance(result, Mapping)
        or result.get("focused_selector") != "not scale"
        or result.get("physical_selector") != "scale"
        or result.get("focused_scale_tests_collected") != 0
        or result.get("physical_scale_tests_collected", 0) < 1
        or result.get("missing_environment_status") != "fail"
        or result.get("physical_environment_status") != "pass"
        or result.get("physical_skipped") != 0
    ):
        raise ConformanceError("focused and physical scale selections are not fail-closed")


def validate_research_draft_intake(
    bundle: "ContractBundle",
    value: Mapping[str, Any],
    *,
    active_license_plan: Mapping[str, Any],
    active_license_plan_digest: str,
    source_receipts: Mapping[str, Mapping[str, Any]],
    evidence_receipts: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    """Validate the one non-persistent research-to-normative bridge."""

    from .contracts import validate_definition

    try:
        validate_definition(bundle.schema, "ResearchDraftIntake", value)
    except Exception as exc:
        raise ConformanceError("research draft intake is not Core-valid") from exc
    owner = bundle.core["policy-set.json"]["research_draft_sanitation"]
    if (
        value["migration_rule"] != owner["migration_rule"]
        or value["requested_flag_mutations"]
    ):
        raise ConformanceError("research draft attempts to bypass sanitation")
    if (
        not isinstance(active_license_plan, Mapping)
        or set(active_license_plan) != {"record_type", "bindings"}
        or active_license_plan.get("record_type") != "LicensesPlan"
        or not isinstance(active_license_plan.get("bindings"), list)
        or digest_value(active_license_plan) != active_license_plan_digest
        or value["license_plan_digest"] != active_license_plan_digest
    ):
        raise ConformanceError("research intake does not bind the verified active license plan")
    license_bindings: dict[str, Mapping[str, Any]] = {}
    for binding in active_license_plan["bindings"]:
        if (
            not isinstance(binding, Mapping)
            or set(binding) != {"provider_id", "license"}
            or not isinstance(binding.get("provider_id"), str)
            or binding["provider_id"] in license_bindings
            or not isinstance(binding.get("license"), Mapping)
        ):
            raise ConformanceError("active license plan contains an invalid binding")
        try:
            validate_definition(bundle.schema, "LicenseBinding", binding["license"])
        except Exception as exc:
            raise ConformanceError("active license plan contains a non-Core license") from exc
        license_bindings[binding["provider_id"]] = binding["license"]
    source_index: dict[str, Mapping[str, Any]] = {}
    sanitized_sources: list[dict[str, Any]] = []
    allowed_sources: set[str] = set()
    folded_sources: set[str] = set()
    total_source_bytes = 0
    captured_source_ids = {
        source["source_id"]
        for source in value["sources"]
        if source["source_mode"] == "captured-payload"
    }
    if set(source_receipts) != captured_source_ids:
        raise ConformanceError("research source receipts are missing or extraneous")
    for source in value["sources"]:
        folded = unicodedata.normalize("NFC", source["source_id"]).casefold()
        if folded in folded_sources:
            raise ConformanceError("research source IDs collide after normalization")
        folded_sources.add(folded)
        if source["license_plan_digest"] != value["license_plan_digest"]:
            raise ConformanceError("research source binds another license plan")
        if source["source_mode"] == "metadata-only":
            metadata_identity = {
                field: nested
                for field, nested in source.items()
                if field != "source_provenance_digest"
            }
            if digest_value(metadata_identity) != source["source_provenance_digest"]:
                raise ConformanceError("metadata-only source provenance digest drifted")
        else:
            receipt = source_receipts.get(source["source_id"])
            if (
                not isinstance(receipt, Mapping)
                or set(receipt) != {"artifact", "payload", "provenance"}
                or not isinstance(receipt.get("artifact"), Mapping)
                or not isinstance(receipt.get("payload"), bytes)
                or not isinstance(receipt.get("provenance"), Mapping)
            ):
                raise ConformanceError(
                    "research source receipt is not independently resolvable"
                )
            artifact = receipt["artifact"]
            payload = receipt["payload"]
            provenance = receipt["provenance"]
            if (
                set(provenance) != {"source_locator", "provider_id", "observed_at"}
                or not isinstance(provenance.get("source_locator"), str)
                or not provenance["source_locator"]
                or not isinstance(provenance.get("provider_id"), str)
                or not provenance["provider_id"]
            ):
                raise ConformanceError("research source provenance is not exact")
            try:
                validate_definition(bundle.schema, "Artifact", artifact)
                validate_definition(bundle.schema, "Timestamp", provenance["observed_at"])
            except Exception as exc:
                raise ConformanceError(
                    "research source Artifact or provenance is not Core-valid"
                ) from exc
            total_source_bytes += len(payload)
            if (
                len(payload) > owner["source_payload_bytes_max"]
                or total_source_bytes > owner["source_payload_total_bytes_max"]
                or artifact["artifact_id"] != source["artifact_id"]
                or digest_value(artifact) != source["artifact_record_digest"]
                or digest_value(provenance) != source["source_provenance_digest"]
                or provenance["source_locator"] != source["source_locator"]
                or hashlib.sha256(payload).hexdigest() != artifact["digest"]
                or artifact["digest"] != source["content_digest"]
                or artifact["size_bytes"] != len(payload)
                or source["size_bytes"] != len(payload)
                or artifact["media_type"] != source["media_type"]
            ):
                raise ConformanceError("research source bytes or Artifact receipt drifted")
        license_binding = license_bindings.get(source["license_provider_id"])
        if (
            license_binding is None
            or license_binding["expression"] != source["license_expression"]
        ):
            raise ConformanceError("research source license differs from the active plan")
        if (
            source["source_mode"] == "captured-payload"
            and license_binding["review_state"] in {"reviewed", "source-verified"}
        ):
            allowed_sources.add(source["source_id"])
        source_index[source["source_id"]] = source
        sanitized_sources.append(dict(source))
    expected_evidence: dict[str, str] = {}
    for claim in value["claims"]:
        for binding in claim["evidence_refs"]:
            previous = expected_evidence.setdefault(
                binding["artifact_id"], binding["artifact_record_digest"]
            )
            if previous != binding["artifact_record_digest"]:
                raise ConformanceError("research evidence ID binds multiple records")
    if set(evidence_receipts) != set(expected_evidence):
        raise ConformanceError("research evidence receipts are missing or extraneous")
    eligible_evidence: set[str] = set()
    for artifact_id, record_digest in expected_evidence.items():
        artifact = evidence_receipts.get(artifact_id)
        if not isinstance(artifact, Mapping):
            raise ConformanceError("research evidence Artifact is unresolved")
        try:
            validate_definition(bundle.schema, "Artifact", artifact)
        except Exception as exc:
            raise ConformanceError("research evidence Artifact is not Core-valid") from exc
        if (
            artifact["artifact_id"] != artifact_id
            or digest_value(artifact) != record_digest
        ):
            raise ConformanceError("research evidence Artifact record drifted")
        if (
            artifact["artifact_kind"] == "evidence"
            and artifact.get("outcome") == "pass"
            and artifact.get("stale") is False
            and artifact.get("unresolved") is False
        ):
            eligible_evidence.add(artifact_id)

    folded_claims: set[str] = set()
    normative_candidates: list[dict[str, Any]] = []
    excluded_claims: list[dict[str, Any]] = []
    for claim in value["claims"]:
        folded = unicodedata.normalize("NFC", claim["claim_id"]).casefold()
        if folded in folded_claims:
            raise ConformanceError("research claim IDs collide after normalization")
        folded_claims.add(folded)
        claim_identity = {
            field: nested
            for field, nested in claim.items()
            if field not in {"claim_digest", "normative_use_allowed"}
        }
        if digest_value(claim_identity) != claim["claim_digest"]:
            raise ConformanceError("research claim digest drifted")
        references: list[Mapping[str, Any]] = []
        for source_id in claim["citation_refs"]:
            source = source_index.get(source_id)
            if source is None:
                raise ConformanceError("research claim cites an unknown source")
            references.append(source)
        evidence_ids = [binding["artifact_id"] for binding in claim["evidence_refs"]]
        eligible = (
            claim["normative_candidate"] is True
            and claim["normative_use_allowed"] is False
            and claim["claim_kind"] == "evidence_claim"
            and claim["claim_class"] == "fact"
            and claim["verification_status"] in {"source-bound", "verified"}
            and claim["citation_required"] is True
            and bool(references)
            and bool(evidence_ids)
            and all(source["source_id"] in allowed_sources for source in references)
            and all(artifact_id in eligible_evidence for artifact_id in evidence_ids)
        )
        if eligible:
            normative_candidates.append(
                {
                    **{
                        field: claim[field]
                        for field in (
                            "claim_id",
                            "claim_kind",
                            "claim_class",
                            "claim_digest",
                            "text",
                            "citation_required",
                            "citation_refs",
                            "evidence_refs",
                            "verification_status",
                            "normative_candidate",
                        )
                    },
                    "normative_use_allowed": True,
                    "source_bindings": [
                        {
                            field: source[field]
                            for field in (
                                "source_id",
                                "source_mode",
                                "source_locator",
                                "source_provenance_digest",
                                "artifact_id",
                                "artifact_record_digest",
                                "content_digest",
                                "size_bytes",
                                "media_type",
                                "license_provider_id",
                                "license_expression",
                                "license_plan_digest",
                            )
                        }
                        for source in references
                    ],
                }
            )
            continue
        if claim["claim_class"] in owner["forbidden_normative_claim_classes"]:
            reason = "claim-class-is-nonnormative"
        elif claim["claim_kind"] == "blocked_claim" or claim["verification_status"] == "blocked":
            reason = f"blocked:{claim['blocked_reason']}"
        elif claim["normative_candidate"] is not True:
            reason = "not-requested-for-normative-migration"
        elif claim["claim_kind"] != "evidence_claim":
            reason = "claim-kind-is-not-evidence-claim"
        elif claim["citation_required"] is not True or not references:
            reason = "eligible-citation-is-missing"
        elif any(source["source_mode"] == "metadata-only" for source in references):
            reason = "metadata-only-source-cannot-authorize-normative-use"
        elif any(source["source_id"] not in allowed_sources for source in references):
            reason = "source-license-is-not-eligible"
        elif not evidence_ids or any(
            artifact_id not in eligible_evidence for artifact_id in evidence_ids
        ):
            reason = "evidence-reference-is-not-current-passing-evidence"
        else:
            reason = "claim-is-not-an-eligible-candidate-fact"
        excluded_claims.append({**dict(claim), "reason": reason})
    result = {
        "record_type": owner["result_record_type"],
        "migration_rule": owner["migration_rule"],
        "license_plan_digest": active_license_plan_digest,
        "sources": sanitized_sources,
        "normative_candidates": normative_candidates,
        "excluded_claims": excluded_claims,
        "requested_flag_mutations": [],
        **owner["result_flags"],
    }
    try:
        validate_definition(bundle.schema, "SanitizedResearchDraft", result)
    except Exception as exc:
        raise ConformanceError("sanitized research result is not Core-valid") from exc
    return result


def sanitize_research_draft_bytes(
    bundle: "ContractBundle",
    payload: bytes,
    *,
    active_license_plan: Mapping[str, Any],
    active_license_plan_digest: str,
    source_receipts: Mapping[str, Mapping[str, Any]],
    evidence_receipts: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    """Return the bounded, non-authoritative facts migrated from a research draft."""

    from .canonical import ParseLimits
    from .contracts import validate_ingress

    owner = bundle.core["policy-set.json"]["research_draft_sanitation"]
    try:
        value = parse_json_strict(
            payload,
            limits=ParseLimits(
                max_bytes=owner["canonical_bytes_max"],
                max_depth=32,
                max_items=4096,
                max_string_length=8192,
                max_number_length=64,
            ),
        )
    except Exception as exc:
        raise ConformanceError("research intake bytes are not strict bounded JSON") from exc
    if not isinstance(value, Mapping) or canonical_bytes(dict(value)) != payload:
        raise ConformanceError("research intake bytes are not canonical")
    try:
        validate_ingress(
            bundle,
            value,
            operation="transient",
            context={
                "active_license_plan": active_license_plan,
                "active_license_plan_digest": active_license_plan_digest,
                "source_receipts": source_receipts,
                "evidence_receipts": evidence_receipts,
            },
        )
    except Exception as exc:
        raise ConformanceError("research intake failed transient ingress") from exc
    return validate_research_draft_intake(
        bundle,
        value,
        active_license_plan=active_license_plan,
        active_license_plan_digest=active_license_plan_digest,
        source_receipts=source_receipts,
        evidence_receipts=evidence_receipts,
    )


def _research_draft_sanitation(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    intake = context.get("research_draft_intake", value)
    if not isinstance(intake, Mapping):
        raise ConformanceError("research sanitation requires a structured intake")
    plan = context.get("active_license_plan")
    plan_digest = context.get("active_license_plan_digest")
    receipts = context.get("source_receipts")
    evidence_receipts = context.get("evidence_receipts")
    if (
        not isinstance(plan, Mapping)
        or not isinstance(plan_digest, str)
        or not isinstance(receipts, Mapping)
        or not isinstance(evidence_receipts, Mapping)
    ):
        raise ConformanceError("research sanitation lacks verified sources or license plan")
    validate_research_draft_intake(
        bundle,
        intake,
        active_license_plan=plan,
        active_license_plan_digest=plan_digest,
        source_receipts=receipts,
        evidence_receipts=evidence_receipts,
    )


def _walk_mapping_keys(value: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(value, Mapping):
        for key, nested in value.items():
            keys.append(str(key))
            keys.extend(_walk_mapping_keys(nested))
    elif isinstance(value, (list, tuple)):
        for nested in value:
            keys.extend(_walk_mapping_keys(nested))
    return keys


def _doctor_result_non_authority(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import validate_definition

    result = context.get("doctor_result", value)
    if not isinstance(result, Mapping):
        raise ConformanceError("doctor policy requires a DoctorResult")
    try:
        validate_definition(bundle.schema, "DoctorResult", result)
    except Exception as exc:
        raise ConformanceError("DoctorResult is not Core-valid") from exc
    owner = bundle.core["policy-set.json"]["derived_result_contracts"]["DoctorResult"]
    for field in (
        "claim_scope",
        "source_scope",
        "report_authoritative",
        "pass_credit",
        "product_acceptance_pass",
        "product_public_approval",
        "product_tree_scans",
    ):
        if result[field] != owner[field]:
            raise ConformanceError(f"DoctorResult changes non-authority field {field}")
    if set(result["metrics"]) != set(owner["metrics"]):
        raise ConformanceError("DoctorResult metrics differ from the Core owner")
    forbidden_metrics = tuple(owner["forbidden_metric_families"])
    forbidden_scopes = tuple(owner["forbidden_allocation_scopes"])
    for key in _walk_mapping_keys(result["metrics"]):
        normalized = key.casefold().replace("_", "-")
        if any(item in normalized for item in forbidden_metrics + forbidden_scopes):
            raise ConformanceError("DoctorResult contains forbidden accounting metrics")
    if result["head"] != result["recovery"]:
        raise ConformanceError("DoctorResult recovery HEAD differs from current HEAD")
    replay = result["replay"]
    if replay is not None and replay["head"] != result["head"]:
        raise ConformanceError("DoctorResult replay HEAD differs from current HEAD")
    components = result["components"]
    if set(components) != set(owner["current_components"]):
        raise ConformanceError("DoctorResult component set differs from the Core owner")
    present_statuses = {component["status"] for component in components.values()}
    expected_rollup = next(
        status for status in owner["rollup_precedence"] if status in present_statuses
    )
    if result["status"] != expected_rollup:
        raise ConformanceError("DoctorResult status is not the exact component rollup")
    if replay is None and components["replay"]["status"] != "incomplete":
        raise ConformanceError("DoctorResult reports healthy replay without replaying")
    projection = result["projection"]
    if projection.get("status") == "missing":
        if components["projection"]["status"] != "incomplete":
            raise ConformanceError("DoctorResult hides a missing projection")
    elif (
        projection["head_digest"] != result["head"]["batch_digest"]
        or projection["head_sequence"] != result["head"]["sequence"]
    ):
        if components["projection"]["status"] not in {"failed", "incomplete"}:
            raise ConformanceError("DoctorResult hides a stale projection")
    elif components["projection"]["status"] in {"failed", "incomplete"}:
        raise ConformanceError("DoctorResult contradicts its current projection")
    protocols = {
        item["id"]: item["adapter_protocol"]
        for item in bundle.core["semantic-model.json"]["technology_capabilities"]
    }
    provider_receipts = context.get("doctor_provider_receipts")
    provider_bindings = context.get("doctor_provider_bindings")
    if not isinstance(provider_receipts, Mapping) or not isinstance(
        provider_bindings, Mapping
    ):
        raise ConformanceError("DoctorResult lacks resolved provider observations")
    if (
        {item["capability_id"] for item in result["provider_adapters"]}
        != set(protocols)
        or set(provider_receipts) != set(protocols)
        or set(provider_bindings) != set(protocols)
        or result["metrics"]["provider_healthchecks_executed"] != len(protocols)
    ):
        raise ConformanceError("DoctorResult omits a configured provider healthcheck")
    for adapter in result["provider_adapters"]:
        protocol = protocols[adapter["capability_id"]]
        allowed = protocol["supported_bindings"]
        receipt = provider_receipts[adapter["capability_id"]]
        binding = provider_bindings[adapter["capability_id"]]
        if (
            adapter["reconstructable"] is not True
            or adapter["persistence_scope"] != "content-addressed-receipt"
            or adapter["protocol_id"] != protocol["protocol_id"]
            or adapter["operation"] != "healthcheck"
            or adapter["operation_contract_digest"]
            != digest_value(protocol["operation_contracts"]["healthcheck"])
            or not isinstance(receipt, Mapping)
            or digest_value(receipt) != adapter["invocation_receipt_digest"]
            or receipt.get("capability_id") != adapter["capability_id"]
            or receipt.get("operation") != "healthcheck"
            or receipt.get("started_at") != adapter["started_at"]
            or receipt.get("completed_at") != adapter["completed_at"]
            or receipt.get("outcome") != adapter["outcome"]
            or receipt.get("exit_code") != adapter["exit_code"]
            or adapter["completed_at"] < adapter["started_at"]
            or not isinstance(binding, Mapping)
            or digest_value(binding.get("dependency_receipt"))
            != adapter["dependency_receipt_digest"]
            or not any(
                adapter["adapter_id"] == binding["adapter_id"]
                and adapter["invocation_kind"] == binding["invocation_kind"]
                and adapter["identity_kind"] == binding["identity_kind"]
                for binding in allowed
            )
        ):
            raise ConformanceError("DoctorResult contains an unsupported provider adapter")
    provider_outcomes = {adapter["outcome"] for adapter in result["provider_adapters"]}
    expected_provider_status = (
        "failed"
        if "failed" in provider_outcomes
        else "degraded"
        if "degraded" in provider_outcomes
        else "healthy"
    )
    if components["providers"]["status"] != expected_provider_status:
        raise ConformanceError("DoctorResult provider component hides healthcheck outcome")
    operation_metrics = result["operation_metrics"]
    if operation_metrics is not None:
        _operation_metrics_non_authority(operation_metrics, bundle, context)


def _operation_metrics_non_authority(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import validate_definition

    metrics = context.get("operation_metrics", value)
    if not isinstance(metrics, Mapping):
        raise ConformanceError("operation metrics policy requires OperationMetrics")
    try:
        validate_definition(bundle.schema, "OperationMetrics", metrics)
    except Exception as exc:
        raise ConformanceError("OperationMetrics is not Core-valid") from exc
    owner = bundle.core["policy-set.json"]["derived_result_contracts"][
        "OperationMetrics"
    ]
    if (
        metrics["claim_scope"] != owner["claim_scope"]
        or metrics["authoritative"] != owner["authoritative"]
        or set(metrics) != {"record_type", "claim_scope", "authoritative", *owner["metric_groups"]}
    ):
        raise ConformanceError("OperationMetrics differs from its Core owner")
    forbidden = tuple(
        owner["forbidden_metric_families"] + owner["forbidden_allocation_scopes"]
    )
    if any(
        token in key.casefold().replace("_", "-")
        for key in _walk_mapping_keys(metrics)
        for token in forbidden
    ):
        raise ConformanceError("OperationMetrics contains forbidden accounting data")
    event_write = metrics["event_write"]
    event_physical = sum(
        event_write[field]
        for field in (
            "journal_authority_bytes",
            "temporary_staging_bytes",
            "head_bytes",
            "derived_index_bytes",
            "journal_checkpoint_bytes",
        )
    )
    if (
        event_write["changed_records"] != metrics["changed_records"]
        or event_write["physical_payload_bytes"] != event_physical
    ):
        raise ConformanceError("OperationMetrics event-write accounting is inconsistent")
    projection = metrics["projection_update"]
    projection_expected_ratio = (
        projection["physical_payload_bytes"] / projection["changed_records"]
        if projection["changed_records"]
        else 0
    )
    if abs(projection["bytes_per_changed_record"] - projection_expected_ratio) > 1e-9:
        raise ConformanceError("OperationMetrics projection byte ratio is inconsistent")
    physical = (
        event_write["physical_payload_bytes"]
        + projection["physical_payload_bytes"]
        + metrics["runtime_checkpoint"]["checkpoint_bytes"]
    )
    expected_ratio = physical / metrics["changed_records"] if metrics["changed_records"] else 0
    if (
        metrics["physical_payload_bytes"] != physical
        or abs(metrics["bytes_per_changed_record"] - expected_ratio) > 1e-9
    ):
        raise ConformanceError("OperationMetrics total byte accounting is inconsistent")


def _workcard_projection_v2(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import validate_definition

    projection = context.get("retrieval_page", value)
    if not isinstance(projection, Mapping):
        raise ConformanceError("retrieval policy requires RetrievalPage")
    try:
        validate_definition(bundle.schema, "RetrievalPage", projection)
    except Exception as exc:
        raise ConformanceError("RetrievalPage is not Core-valid") from exc
    owner = bundle.core["policy-set.json"]["derived_result_contracts"][
        "RetrievalPage"
    ]
    if any(field in projection for field in owner["forbidden_compatibility_fields"]):
        raise ConformanceError("RetrievalPage carries a removed cursor alias")
    budget = projection["budget"]
    if (
        len(projection["entities"]) > budget["max_entities"]
        or len(projection["relations"]) > budget["max_relations"]
        or projection["effective_top_k"] > budget["top_k"]
        or projection["selected_seed_count"] > projection["effective_top_k"]
        or projection["next_stream_cursor"] < projection["stream_cursor"]
        or projection["truncated"] is not (projection["continuation"] is not None)
    ):
        raise ConformanceError("RetrievalPage violates its bounded v2 contract")
    continuation = projection["continuation"]
    if continuation is not None and (
        continuation["cursor"] != projection["next_stream_cursor"]
        or continuation["activation_digest"] != projection["activation_digest"]
        or continuation["head_digest"] != projection["head_digest"]
        or continuation["projection_digest"] != projection["projection_digest"]
        or continuation["depth"] != projection["depth"]
    ):
        raise ConformanceError("RetrievalPage continuation binds another result")
    internal = context.get("workcard_projection")
    if internal is not None:
        if not isinstance(internal, Mapping):
            raise ConformanceError("internal WorkCardProjection is not an object")
        try:
            validate_definition(bundle.schema, "WorkCardProjection", internal)
        except Exception as exc:
            raise ConformanceError("internal WorkCardProjection is not Core-valid") from exc
        if set(internal) != {
            "record_type",
            "activation_digest",
            "head_digest",
            "projection_digest",
            "task_id",
            "task_digest",
            "task",
            "budget",
            "projection_authoritative",
        }:
            raise ConformanceError("internal WorkCardProjection exposes retrieval state")
    for context_field, definition in (
        ("next_result", "NextResult"),
        ("continue_result", "ContinueResult"),
    ):
        envelope = context.get(context_field)
        if envelope is None:
            continue
        if not isinstance(envelope, Mapping) or set(envelope) != {
            "record_type",
            "status",
            "subject_id",
            "activation_digest",
            "work_card",
            "continuation",
        }:
            raise ConformanceError(f"{definition} fields are not exact")
        try:
            validate_definition(bundle.schema, definition, envelope)
        except Exception as exc:
            raise ConformanceError(f"{definition} is not Core-valid") from exc
        work_card = envelope["work_card"]
        if (
            (envelope["status"] == "ready") is not isinstance(work_card, Mapping)
            or (
                envelope["continuation"] is not None
                and (
                    not isinstance(work_card, Mapping)
                    or work_card.get("truncated") is not True
                )
            )
        ):
            raise ConformanceError(f"{definition} status or continuation is inconsistent")


def _event_store_policy_projection(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import validate_definition

    policy = context.get("event_store_policy", value)
    if not isinstance(policy, Mapping):
        raise ConformanceError("event store policy projection is missing")
    try:
        validate_definition(bundle.schema, "EventStorePolicy", policy)
    except Exception as exc:
        raise ConformanceError("EventStorePolicy is not Core-valid") from exc
    authority = bundle.core["authority-model.json"]
    mutation = authority["command_mutation_claim_rule"]
    event = authority["event_contract"]
    expected: dict[str, Any] = {
        "record_type": "EventStorePolicy",
        "authority_model_digest": digest_value(authority),
        "max_command_bytes": event["command_bytes_max"],
        "max_envelope_bytes": event["envelope_bytes_max"],
        "max_state_binding_bytes": event["state_binding_bytes_max"],
        "max_state_binding_updates_per_batch": event[
            "state_binding_updates_per_batch_max"
        ],
        "max_events_per_batch": event["events_per_batch_max"],
        "max_requested_scope_items": authority["scope_contract"][
            "requested_scope_items_max"
        ],
        "derived_tail_batch_threshold": event["derived_tail_batch_threshold"],
        "derived_tail_byte_threshold": event["derived_tail_byte_threshold"],
        "runtime_overlay_compaction_depth": event[
            "runtime_overlay_compaction_depth"
        ],
        "command_required_fields": event["command_required_fields"],
        "command_conditional_fields": event["command_conditional_fields"],
        "command_mutation_fields": mutation["required_command_fields"],
        "lease_bound_command_kinds": mutation["lease_bound_command_kinds"],
        "lease_bound_task_transition_states": mutation[
            "lease_bound_task_transition_states"
        ],
        "command_to_primary_event": [
            [command_kind, event_kind]
            for command_kind, event_kind in event["command_to_primary_event"].items()
        ],
        "allowed_state_binding_leaf_types": [
            "Activation",
            *[
                entity["kind"]
                for entity in bundle.core["semantic-model.json"][
                    "persistent_entities"
                ]
            ],
            "Relation",
        ],
        "state_binding_identity_rules": event["state_binding_identity_rules"],
        "state_binding_algorithm_contract": event[
            "state_binding_algorithm_contract"
        ],
        "state_binding_value_rules": event["state_binding_value_rules"],
        "canonical_timestamp_contract": authority["canonical_timestamp_contract"],
        "genesis_previous_authority_commitment": event[
            "genesis_previous_authority_commitment"
        ],
        "genesis_event_semantic_digest": event["genesis_event_semantic_digest"],
    }
    expected["policy_digest"] = digest_value(expected)
    if policy != expected:
        raise ConformanceError("EventStorePolicy differs from installed AuthorityModel")


def _semantic_inheritance(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import validate_definition

    semantic = bundle.core["semantic-model.json"]
    try:
        validate_definition(bundle.schema, "SemanticModel", semantic)
    except Exception as exc:
        raise ConformanceError("SemanticModel is not its compiled structural owner") from exc
    for field, owner_value in semantic.items():
        if field in {"schema_ref", "version"}:
            continue
        if bundle.schema["$defs"]["SemanticModel"]["properties"][field].get(
            "const"
        ) != owner_value:
            raise ConformanceError(f"compiled SemanticModel lost owner field {field}")


def _authority_owner(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import validate_definition

    authority = bundle.core["authority-model.json"]
    try:
        validate_definition(bundle.schema, "AuthorityModel", authority)
    except Exception as exc:
        raise ConformanceError("AuthorityModel is not its compiled structural owner") from exc
    schema_owner = bundle.schema["$defs"]["AuthorityModel"]["properties"]
    for field, owner_value in authority.items():
        if field in {"schema_ref", "version"}:
            continue
        if schema_owner[field].get("const") != owner_value:
            raise ConformanceError(f"compiled AuthorityModel lost owner field {field}")
    if len({rule["id"] for rule in authority["separation_of_duties"]}) != len(
        authority["separation_of_duties"]
    ):
        raise ConformanceError("AuthorityModel SOD owner contains duplicate identities")
    lease_bound_commands = authority["command_mutation_claim_rule"][
        "lease_bound_command_kinds"
    ]
    if lease_bound_commands != [
        "artifact.record",
        "run.record",
        "gate.record",
        "finding.record",
    ]:
        raise ConformanceError("AuthorityModel lease-bound command set is not exact")
    if "candidate.record" in lease_bound_commands:
        raise ConformanceError("immutable Candidate creation cannot require a Lease")


def _policy_state_machine_owner(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    owner = bundle.core["policy-set.json"]["state_machines"]
    definitions = bundle.schema["$defs"]
    if (
        definitions["TaskStateMachine"].get("const") != owner["task"]
        or definitions["LeaseStateMachine"].get("const") != owner["lease"]
        or definitions["StateMachines"].get("const") != owner
        or definitions["TaskState"].get("enum") != list(owner["task"])
        or definitions["LeaseState"].get("enum") != list(owner["lease"])
    ):
        raise ConformanceError("compiled state machines differ from the policy owner")


def _event_contract_owner(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    owner = bundle.core["authority-model.json"]["event_contract"]
    definitions = bundle.schema["$defs"]
    if (
        definitions["CommandRequest"].get("x-promin-max-canonical-bytes")
        != owner["command_bytes_max"]
        or definitions["CommandRequest"]["required"]
        != owner["command_required_fields"]
        or definitions["EventStorePolicy"]["properties"]["command_conditional_fields"]["const"]
        != ["definition_digest"]
        or definitions["EventBatch"]["required"]
        != owner["event_batch_required_fields"]
        or definitions["EventBatch"]["properties"]["events"]["maxItems"]
        != owner["events_per_batch_max"]
        or definitions["EventBatch"]["properties"]["state_binding_delta"][
            "maxItems"
        ]
        != owner["state_binding_updates_per_batch_max"]
        or definitions["EventStorePolicy"]["properties"]["max_events_per_batch"][
            "const"
        ]
        != owner["events_per_batch_max"]
        or definitions["EventStorePolicy"]["properties"][
            "max_state_binding_updates_per_batch"
        ]["const"]
        != owner["state_binding_updates_per_batch_max"]
        or owner["command_bytes_max"] != 1048576
        or owner["state_binding_bytes_max"] != 1048576
        or owner["envelope_bytes_max"] != 2097152
        or owner["events_per_batch_max"] != 128
        or owner["state_binding_updates_per_batch_max"] != 128
        or definitions["Event"]["required"] != owner["event_required_fields"]
        or set(definitions["Event"]["properties"]["event_kind"]["enum"])
        != set(owner["command_to_primary_event"].values())
        | set(owner["auxiliary_event_kinds"])
    ):
        raise ConformanceError("compiled event contracts differ from AuthorityModel")


def _gate_run_definition_integrity(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import validate_definition

    if value.get("record_type") == "GateResult":
        _gate_credit(value, bundle, context)
        return
    task = context.get("gate_task", value)
    if not isinstance(task, Mapping) or task.get("record_type") != "Task":
        raise ConformanceError("gate policy requires the owning Task")
    try:
        validate_definition(bundle.schema, "Task", task)
    except Exception as exc:
        raise ConformanceError("gate definition owner Task is not Core-valid") from exc
    definitions = {
        binding["definition_digest"]: binding["definition"]
        for binding in task["gate_run_definitions"]
    }
    if len(definitions) != len(task["gate_run_definitions"]):
        raise ConformanceError("Task contains duplicate gate definition digests")
    for definition_digest, definition in definitions.items():
        if digest_value(definition) != definition_digest:
            raise ConformanceError("Task gate definition digest drifted")
        scope = [(item["kind"], item["value"]) for item in definition["target_scope"]]
        if len(scope) != len(set(scope)):
            raise ConformanceError("GateRunDefinition target scope is not exact")
    command = context.get("gate_command")
    if isinstance(command, Mapping):
        selected = definitions.get(command.get("definition_digest"))
        if (
            selected is None
            or "gate_run_definition" in command
            or not isinstance(command.get("payload"), Mapping)
            or "gate_run_definition" in command["payload"]
        ):
            raise ConformanceError(
                "gate command submits or changes its definition inline"
            )
        _validate_gate_command_scope(
            command, selected, task_id=task["task_id"], bundle=bundle
        )


def _authority_runtime_policy_projection(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import validate_definition

    runtime_policy = context.get("authority_runtime_policy", value)
    if not isinstance(runtime_policy, Mapping):
        raise ConformanceError("authority runtime policy projection is missing")
    try:
        validate_definition(bundle.schema, "AuthorityRuntimePolicy", runtime_policy)
    except Exception as exc:
        raise ConformanceError("AuthorityRuntimePolicy is not Core-valid") from exc
    authority = bundle.core["authority-model.json"]
    identity = dict(runtime_policy)
    supplied_digest = identity.pop("policy_digest")
    if (
        runtime_policy["authority_model_digest"] != digest_value(authority)
        or runtime_policy["capability_ids"]
        != [item["id"] for item in authority["capabilities"]]
        or runtime_policy["separation_of_duties"]
        != authority["separation_of_duties"]
        or runtime_policy["separation_of_duties_capability_ids"]
        != [
            *[item["id"] for item in authority["capabilities"]],
            *authority["separation_of_duties_contract"][
                "external_capability_ids"
            ],
        ]
        or runtime_policy["separation_of_duties_contract"]
        != authority["separation_of_duties_contract"]
        or runtime_policy["delegation_depth_max"]
        != authority["delegation_depth_max"]
        or runtime_policy["scope_contract"] != authority["scope_contract"]
        or runtime_policy["grant_contract"] != authority["grant_contract"]
        or runtime_policy["canonical_timestamp_contract"]
        != authority["canonical_timestamp_contract"]
        or supplied_digest != digest_value(identity)
    ):
        raise ConformanceError("AuthorityRuntimePolicy differs from installed Core")


def _semantic_export_integrity(
    value: Mapping[str, Any], bundle: "ContractBundle", context: Mapping[str, Any]
) -> None:
    from .contracts import validate_definition

    exported = context.get("semantic_export", value)
    if not isinstance(exported, Mapping):
        raise ConformanceError("semantic export policy requires a SemanticExport")
    try:
        validate_definition(bundle.schema, "SemanticExport", exported)
    except Exception as exc:
        raise ConformanceError("SemanticExport is not Core-valid") from exc
    owner = bundle.core["policy-set.json"]["semantic_export_contract"]
    try:
        activation_context = _activation_context(context)
        provider_binding_digest = digest_value(
            list(activation_context.provider_dispatch.binding_evidence())
        )
    except Exception as exc:
        raise ConformanceError("SemanticExport lacks verified installed Activation") from exc
    head = context.get("semantic_export_head")
    records_value = context.get("semantic_export_records")
    finalized = context.get("semantic_export_artifact_record")
    payload_bytes = context.get("semantic_export_payload")
    if (
        not isinstance(head, Mapping)
        or set(head) != {"head_event_id", "head_sequence", "head_digest"}
        or not isinstance(records_value, (list, tuple))
        or not isinstance(finalized, Mapping)
        or set(finalized) != {"artifact", "commit_binding"}
        or not isinstance(payload_bytes, bytes)
    ):
        raise ConformanceError("SemanticExport requires replay, HEAD, and finalized CAS context")
    if (
        exported["core_bundle_digest"] != bundle.bundle_digest
        or exported["preset_digest"] != bundle.preset_digest
        or exported["activation_digest"] != activation_context.activation_digest
        or exported["implementation_closure_digest"]
        != activation_context.implementation_closure_digest
        or exported["provider_binding_digest"] != provider_binding_digest
        or any(exported[field] != head[field] for field in head)
        or (exported["head_sequence"] == 0)
        is not (exported["head_event_id"] is None and exported["head_digest"] is None)
    ):
        raise ConformanceError("SemanticExport binds stale installed or replay state")
    by_digest: dict[str, dict[str, Any]] = {}
    for record in records_value:
        if not isinstance(record, dict):
            raise ConformanceError("SemanticExport replay contains a non-record")
        definition = bundle.record_definitions.get(record.get("record_type"))
        if definition is None or definition not in {
            "Activation", "Task", "Candidate", "Artifact", "Run", "Finding",
            "Decision", "Grant", "Lease", "GateResult", "GrantRevocation", "Relation",
        }:
            raise ConformanceError("SemanticExport replay contains an unsupported record")
        validate_definition(bundle.schema, definition, record)
        by_digest[digest_value(record)] = dict(record)
    ordered_records = [by_digest[key] for key in sorted(by_digest)]
    input_digests = sorted(by_digest)
    if exported["input_digests"] != input_digests:
        raise ConformanceError("SemanticExport input digests are not replay-derived")
    payload_limits = ParseLimits(
        max_bytes=owner["output_bytes_max"],
        max_depth=64,
        max_items=max(owner["output_records_max"] * 32, 1),
        max_string_length=1048576,
        max_number_length=256,
    )
    try:
        parsed_payload = parse_json_strict(payload_bytes, limits=payload_limits)
        if canonical_bytes(parsed_payload, limits=payload_limits) != payload_bytes:
            raise ConformanceError("SemanticExport payload bytes are not canonical")
        validate_definition(bundle.schema, "SemanticStatePayload", parsed_payload)
    except (CanonicalError, Exception) as exc:
        if isinstance(exc, ConformanceError):
            raise
        raise ConformanceError("SemanticExport payload is not Core-valid canonical JSON") from exc
    expected_payload = {
        "record_type": owner["output_record_type"],
        "candidate_digest": exported["candidate_digest"],
        "activation_digest": exported["activation_digest"],
        "head_event_id": exported["head_event_id"],
        "head_sequence": exported["head_sequence"],
        "head_digest": exported["head_digest"],
        "records": ordered_records,
    }
    if parsed_payload != expected_payload:
        raise ConformanceError("SemanticExport payload differs from replay-derived state")
    artifact = finalized.get("artifact")
    commit_binding = finalized.get("commit_binding")
    if not isinstance(artifact, Mapping) or not isinstance(commit_binding, Mapping):
        raise ConformanceError("SemanticExport finalized Artifact is incomplete")
    validate_definition(bundle.schema, "Artifact", artifact)
    output_digest = hashlib.sha256(payload_bytes).hexdigest()
    if (
        set(commit_binding)
        != {"command_digest", "batch_digest", "primary_event_id", "primary_event_digest"}
        or artifact["artifact_id"] != exported["output_artifact_id"]
        or artifact["artifact_kind"] != owner["output_artifact_kind"]
        or artifact["digest"] != output_digest
        or artifact["size_bytes"] != len(payload_bytes)
        or artifact["media_type"] != owner["output_media_type"]
        or digest_value(finalized) != exported["output_artifact_record_digest"]
        or exported["output_digest"] != output_digest
        or exported["output_size_bytes"] != len(payload_bytes)
    ):
        raise ConformanceError("SemanticExport output is not its exact finalized CAS Artifact")


def _evidence_policy(
    check_id: str,
    value: Mapping[str, Any],
    bundle: "ContractBundle",
    context: Mapping[str, Any],
) -> None:
    _require_evidence(check_id, value, bundle, context, purpose="gate")


def _signed_role_acceptance(
    check_id: str,
    value: Mapping[str, Any],
    bundle: "ContractBundle",
    context: Mapping[str, Any],
) -> None:
    _require_evidence(check_id, value, bundle, context, purpose="gate")


def _migration_external_no_credit(
    check_id: str,
    value: Mapping[str, Any],
    bundle: "ContractBundle",
    context: Mapping[str, Any],
) -> None:
    _require_evidence(check_id, value, bundle, context, purpose="gate")
    evidence = context.get("evidence_bindings", {}).get(check_id)
    if (
        not isinstance(evidence, Mapping)
        or evidence.get("evidence_class") != "migration"
        or evidence.get("product_credit_eligible") is not False
    ):
        raise ConformanceError("migration parity evidence cannot receive product credit")


def _mutation_rejection(
    family: str,
    value: Mapping[str, Any],
    bundle: "ContractBundle",
    context: Mapping[str, Any],
) -> None:
    fixture_root = context.get("mutation_fixture_root")
    package_root = context.get("package_root", bundle.source_root)
    if fixture_root is None:
        raise ConformanceError(f"mutation {family} requires an isolated fixture root")
    from .mutation_suite import run_mutation

    try:
        result = run_mutation(family, fixture_root, package_root)
    except Exception as exc:
        raise ConformanceError(
            f"mutation {family} production runner failed: {exc}"
        ) from exc
    if result.family != family or not result.exception_type or not result.message:
        raise ConformanceError(f"mutation {family} produced incomplete rejection evidence")


_POLICY_DIRECT: dict[str, Check] = {
    "no_false_success": _gate_credit,
    "activation_binding": _activation_integrity,
    "bounded_workcard": _workcard_bounds,
    "canonical_name": _canonical_identity,
    "critical_fields": _strict_record,
    "preset_no_authority": _preset_separation,
    "core_preset_separation": _preset_separation,
    "normalization_collision": _normalization_rejection,
    "safe_export": _portable_distribution_policy,
    "exact_init_keyset": _activation_integrity,
    "exact_standard_files": _core_layout,
    "config_exact_idempotency": _activation_integrity,
    "lease_only_for_mutation": _workcard_bounds,
    "credit_requires_evidence": _gate_credit,
    "continuation_completeness": _continuation_page_union,
    "candidate_snapshot_consistency": _candidate_snapshot_policy,
    "provider_adapter_dispatch": _provider_adapter_dispatch,
    "current_release_closure": _current_release_closure,
    "finding_disposition_evidence": _finding_disposition_binding,
    "candidate_delta_scope": _candidate_delta_scope,
    "verified_state_checkpoint": _verified_state_checkpoint,
    "profile_default_depth": _profile_default_depth,
    "canonical_distribution_archive": _portable_distribution_acceptance,
    "verified_inventory_provenance": _verified_inventory_result_provenance,
    "supported_command_surface": _supported_command_surface,
    "profile_bound_scale": _profile_bound_physical_100k_performance,
    "cross_platform_release": _windows_linux_exact_zip_matrix,
    "standard_release_separation": _standard_distribution_separate_from_product_acceptance,
    "required_gates_fail_closed": _required_no_degradation_tests_fail_closed,
    "research_draft_sanitation": _research_draft_sanitation,
    "doctor_result_non_authority": _doctor_result_non_authority,
    "semantic_inheritance": _semantic_inheritance,
    "authority_owner": _authority_owner,
    "gate_run_definition_integrity": _gate_run_definition_integrity,
    "authority_runtime_policy_projection": _authority_runtime_policy_projection,
    "semantic_export_integrity": _semantic_export_integrity,
    "operation_metrics_non_authority": _operation_metrics_non_authority,
    "workcard_projection_v2": _workcard_projection_v2,
    "event_store_policy_projection": _event_store_policy_projection,
    "dependency_graph_acyclicity": _dependency_graph_acyclicity,
    "ready_frontier_projection": _ready_frontier_projection,
    "grant_validity": partial(_evidence_policy, "grant_validity"),
    "lease_fence": partial(_evidence_policy, "lease_fence"),
    "candidate_evidence_binding": partial(_evidence_policy, "candidate_evidence_binding"),
    "atomic_event_commit": partial(_evidence_policy, "atomic_event_commit"),
    "projection_derived": partial(_evidence_policy, "projection_derived"),
    "minimal_graph": partial(_evidence_policy, "minimal_graph"),
    "zero_scan_init": partial(_evidence_policy, "zero_scan_init"),
    "explicit_bindings": partial(_evidence_policy, "explicit_bindings"),
    "closed_ack": partial(_evidence_policy, "closed_ack"),
    "single_scan": partial(_evidence_policy, "single_scan"),
    "idempotent_commands": partial(_evidence_policy, "idempotent_commands"),
    "bootstrap_authority": partial(_evidence_policy, "bootstrap_authority"),
    "provider_substitution": partial(_evidence_policy, "provider_substitution"),
    "stale_projection": partial(_evidence_policy, "stale_projection"),
    "one_command_one_batch": partial(_evidence_policy, "one_command_one_batch"),
    "deterministic_retrieval": partial(_evidence_policy, "deterministic_retrieval"),
    "strict_time": partial(_evidence_policy, "strict_time"),
    "root_authorization_limit": partial(_evidence_policy, "root_authorization_limit"),
    "truthful_observability": partial(_evidence_policy, "truthful_observability"),
    "depth_aware_retrieval": partial(_evidence_policy, "depth_aware_retrieval"),
    "command_capability_scope": partial(_evidence_policy, "command_capability_scope"),
    "grant_issuance_chain": partial(_evidence_policy, "grant_issuance_chain"),
    "verified_team_signatures": partial(_evidence_policy, "verified_team_signatures"),
    "provider_preflight": partial(_evidence_policy, "provider_preflight"),
    "state_machine_transition": partial(_evidence_policy, "state_machine_transition"),
    "decision_target_binding": partial(_evidence_policy, "decision_target_binding"),
    "command_event_correspondence": partial(_evidence_policy, "command_event_correspondence"),
}

_POLICY_IDS = (
    "no_false_success", "activation_binding", "grant_validity", "lease_fence",
    "candidate_evidence_binding", "atomic_event_commit", "projection_derived",
    "minimal_graph", "bounded_workcard", "zero_scan_init", "explicit_bindings",
    "canonical_name", "safe_export", "closed_ack", "critical_fields",
    "preset_no_authority", "single_scan", "idempotent_commands",
    "core_preset_separation", "bootstrap_authority", "normalization_collision",
    "provider_substitution", "exact_init_keyset", "stale_projection",
    "one_command_one_batch", "deterministic_retrieval", "strict_time",
    "exact_standard_files", "root_authorization_limit", "config_exact_idempotency",
    "truthful_observability", "depth_aware_retrieval", "lease_only_for_mutation",
    "command_capability_scope", "grant_issuance_chain", "verified_team_signatures",
    "provider_preflight", "state_machine_transition", "decision_target_binding",
    "credit_requires_evidence", "command_event_correspondence",
    "continuation_completeness", "candidate_snapshot_consistency",
    "provider_adapter_dispatch", "current_release_closure",
    "finding_disposition_evidence", "candidate_delta_scope",
    "verified_state_checkpoint", "profile_default_depth",
    "canonical_distribution_archive", "verified_inventory_provenance",
    "supported_command_surface", "profile_bound_scale",
    "cross_platform_release", "standard_release_separation",
    "required_gates_fail_closed",
    "research_draft_sanitation", "doctor_result_non_authority",
    "semantic_inheritance", "authority_owner", "gate_run_definition_integrity",
    "authority_runtime_policy_projection", "semantic_export_integrity",
    "operation_metrics_non_authority", "workcard_projection_v2",
    "event_store_policy_projection", "dependency_graph_acyclicity",
    "ready_frontier_projection",
)


def policy_catalogue() -> dict[str, Check]:
    if set(_POLICY_DIRECT) != set(_POLICY_IDS) or len(_POLICY_IDS) != 68:
        raise RuntimeError("policy validator catalogue is not exact")
    return dict(_POLICY_DIRECT)


_ACCEPTANCE_DIRECT: dict[str, Check] = {
    "canonical-name-only": _canonical_identity,
    "exact-six-core-artifacts": _core_layout,
    "preset-outside-core-digest": _preset_separation,
    "exact-one-selected-preset": _installed_preset_layout,
    "exact-five-init-records": _activation_integrity,
    "no-false-success": _gate_credit,
    "strict-critical-fields": _strict_record,
    "activation-digest-binding": _activation_integrity,
    "normalization-collision-rejection": _normalization_rejection,
    "safe-recursive-export": _portable_distribution_acceptance,
    "bounded-workcard-through-depth-twelve": _workcard_bounds,
    "typed-reference-domain-range-closure": _relation_domain_range,
    "dependency-graph-acyclic-and-current-ready-frontier": _ready_frontier_projection,
    "read-workcard-without-lease": _workcard_bounds,
    "mutation-workcard-requires-current-lease": _workcard_bounds,
    "continuation-v2-complete-page-union": _continuation_page_union,
    "candidate-recipe-applied-once": _candidate_recipe_applied_once,
    "selected-provider-adapter-evidence": _provider_adapter_dispatch,
    "team-signed-cli-end-to-end": _team_signed_runtime,
    "current-release-closure-revalidation": _current_release_closure,
    "finding-bound-resolution-and-waiver-evidence": _finding_disposition_binding,
    "candidate-delta-within-task-and-grant-scope": _candidate_delta_scope,
    "verified-head-checkpoint-delta-replay": _verified_state_checkpoint,
    "profile-default-with-core-depth-twelve": _profile_default_depth,
    "lossless-continuation-in-reference-100k-scenario": _continuation_page_union,
    "canonical-exact-zip-distribution": _portable_distribution_acceptance,
    "current-interpreter-and-clean-install-modes": _current_interpreter_and_clean_install_modes,
    "required-no-degradation-tests-fail-closed": _required_no_degradation_tests_fail_closed,
    "continuation-secret-subject-grant-binding": _continuation_secret_subject_grant_binding,
    "implementation-closure-bound-and-current": _implementation_closure_bound_and_current,
    "verified-inventory-result-provenance": _verified_inventory_result_provenance,
    "exact-six-base-command-surface": _supported_command_surface,
    "zero-dead-evidence-budget-fields": _zero_dead_evidence_budget_fields,
    "physical-100k-one-artifact-proxy-per-file": _profile_bound_physical_100k_performance,
    "profile-bound-physical-100k-performance": _profile_bound_physical_100k_performance,
    "windows-linux-exact-zip-matrix": _windows_linux_exact_zip_matrix,
    "three-zero-new-saturation-iterations": _three_zero_new_saturation_iterations,
    "external-standard-release-decision-exact-binding": _external_standard_release_decision_exact_binding,
    "standard-distribution-separate-from-product-acceptance": _standard_distribution_separate_from_product_acceptance,
    "creditable-candidate-immutable-vcs-tree": _creditable_candidate_snapshot,
    "candidate-evidence-decision-acyclic-chain": _candidate_evidence_decision_acyclic_chain,
    "evidence-manifest-physical-resolution": _evidence_manifest_physical_resolution,
    "signed-standard-decision-authority-proof": _signed_standard_decision_authority_proof,
    "semver-from-candidate-binding": _semver_from_candidate_binding,
    "typed-human-document-verification": _typed_human_document_verification,
    "broad-query-bounded-seed-refinement": _broad_query_bounded_seed_refinement,
    "continuation-token-bytes-at-most-256": _continuation_token_bytes_at_most_256,
    "inventory-stream-memory-amplification-at-most-32": _inventory_stream_memory_amplification_at_most_32,
    "explicit-scale-marker-selection": _explicit_scale_marker_selection,
    "authenticated-role-platform-evidence-attestations": _authenticated_role_platform_evidence_attestations,
    "installed-platform-observation-closure": _installed_platform_observation_closure,
    "handle-relative-evidence-root-safety": _handle_relative_evidence_root_safety,
    "raw-scale-summary-recomputation": _raw_scale_summary_recomputation,
    "bounded-incremental-commit-and-compaction": _bounded_incremental_commit_and_compaction,
    "offline-installed-no-degradation": _offline_installed_no_degradation,
    "offline-release-online-compatibility": _current_interpreter_and_clean_install_modes,
    "decision-after-evidence-with-bounded-skew": _decision_after_evidence_with_bounded_skew,
    "single-derived-platform-closure-owner": _single_derived_platform_closure_owner,
    "truthful-process-invocation-status": _truthful_process_invocation_status,
    "product-public-approval-separation": _product_public_approval_separation,
    "historical-decision-current-eligibility-separation": _historical_decision_current_eligibility_separation,
}

_ACCEPTANCE_IDS = (
    "canonical-name-only", "exact-six-core-artifacts", "preset-outside-core-digest",
    "exact-one-selected-preset", "exact-five-init-records", "zero-product-scan-during-init",
    "single-pass-inventory", "no-false-success", "strict-critical-fields",
    "activation-digest-binding", "root-ceiling-without-bootstrap-grant-cycle",
    "grant-scope-expiry-nonce-proof", "lease-generation-fence-and-close-ack",
    "candidate-evidence-provider-binding", "one-command-one-atomic-batch",
    "deterministic-replay", "projection-disposable-and-current",
    "bounded-workcard-through-depth-twelve", "typed-reference-domain-range-closure",
    "dependency-graph-acyclic-and-current-ready-frontier",
    "safe-recursive-export", "idempotent-state-commands",
    "normalization-collision-rejection", "provider-substitution-invalidates-derived-state",
    "rollback-and-recutover-equivalence", "zero-forbidden-name-occurrences",
    "zero-unowned-normative-facts", "zero-core-provider-lock-in",
    "zero-compiled-cache-files", "physical-100k-one-artifact-proxy-per-file",
    "external-standard-release-decision-exact-binding", "root-bootstrap-command-limited",
    "deterministic-activation-identity", "configuration-exact-idempotency",
    "truthful-operation-reporting", "depth-aware-seed-budget",
    "lossless-continuation-in-reference-100k-scenario", "read-workcard-without-lease",
    "mutation-workcard-requires-current-lease", "command-capability-and-scope-resolution",
    "grant-issuance-chain-closure", "team-signatures-cryptographically-verified",
    "required-provider-preflight-before-commit", "policy-owned-task-and-lease-state-machines",
    "decision-kind-target-scope-binding", "non-skipped-credit-result-has-evidence",
    "exact-command-primary-event-correspondence", "conjunctive-scope-containment",
    "authorization-binds-exact-grant-claim", "command-effect-target-in-requested-scope",
    "lease-holder-has-task-execute-grant", "decision-grant-matches-command-authorization",
    "artifact-kind-resolves-correct-capability",
    "continuation-v2-complete-page-union", "candidate-recipe-applied-once",
    "creditable-candidate-immutable-vcs-tree", "selected-provider-adapter-evidence",
    "team-signed-cli-end-to-end", "current-release-closure-revalidation",
    "finding-bound-resolution-and-waiver-evidence",
    "candidate-delta-within-task-and-grant-scope",
    "verified-head-checkpoint-delta-replay", "profile-default-with-core-depth-twelve",
    "canonical-exact-zip-distribution", "current-interpreter-and-clean-install-modes",
    "required-no-degradation-tests-fail-closed",
    "continuation-secret-subject-grant-binding",
    "implementation-closure-bound-and-current",
    "verified-inventory-result-provenance", "exact-six-base-command-surface",
    "zero-dead-evidence-budget-fields", "profile-bound-physical-100k-performance",
    "windows-linux-exact-zip-matrix", "three-zero-new-saturation-iterations",
    "fresh-semantic-control-state-per-saturation-iteration",
    "standard-distribution-separate-from-product-acceptance",
    "candidate-evidence-decision-acyclic-chain",
    "evidence-manifest-physical-resolution",
    "evidence-manifest-exact-eight-lane-matrix-resolution",
    "evidence-manifest-four-cp314-supplemental-records",
    "evidence-manifest-path-digest-size-closure",
    "evidence-manifest-nested-and-supplemental-chronology",
    "seven-distinct-role-producer-scopes",
    "signed-standard-decision-authority-proof",
    "semver-from-candidate-binding", "typed-human-document-verification",
    "broad-query-bounded-seed-refinement",
    "continuation-token-bytes-at-most-256",
    "inventory-stream-memory-amplification-at-most-32",
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
)

_LOCAL_RUNTIME_REEXECUTE_ACCEPTANCE = (
    "zero-product-scan-during-init", "single-pass-inventory",
    "root-ceiling-without-bootstrap-grant-cycle", "grant-scope-expiry-nonce-proof",
    "lease-generation-fence-and-close-ack", "candidate-evidence-provider-binding",
    "one-command-one-atomic-batch", "deterministic-replay",
    "projection-disposable-and-current", "idempotent-state-commands",
    "provider-substitution-invalidates-derived-state", "root-bootstrap-command-limited",
    "deterministic-activation-identity", "configuration-exact-idempotency",
    "truthful-operation-reporting", "depth-aware-seed-budget",
    "command-capability-and-scope-resolution", "grant-issuance-chain-closure",
    "team-signatures-cryptographically-verified", "required-provider-preflight-before-commit",
    "policy-owned-task-and-lease-state-machines", "decision-kind-target-scope-binding",
    "non-skipped-credit-result-has-evidence", "exact-command-primary-event-correspondence",
    "conjunctive-scope-containment", "authorization-binds-exact-grant-claim",
    "command-effect-target-in-requested-scope", "lease-holder-has-task-execute-grant",
    "decision-grant-matches-command-authorization", "artifact-kind-resolves-correct-capability",
)
_PACKAGE_STATIC_ACCEPTANCE = (
    "zero-forbidden-name-occurrences", "zero-unowned-normative-facts",
    "zero-core-provider-lock-in", "zero-compiled-cache-files",
)
_MIGRATION_EXTERNAL_NO_CREDIT_ACCEPTANCE = ("rollback-and-recutover-equivalence",)
_SATURATION_SIGNED_ACCEPTANCE = (
    "fresh-semantic-control-state-per-saturation-iteration",
)
_STANDARD_RELEASE_SIGNED_MANIFEST_ACCEPTANCE = (
    "evidence-manifest-exact-eight-lane-matrix-resolution",
    "evidence-manifest-four-cp314-supplemental-records",
    "evidence-manifest-path-digest-size-closure",
    "evidence-manifest-nested-and-supplemental-chronology",
    "seven-distinct-role-producer-scopes",
)
_SIGNED_ROLE_ACCEPTANCE = (
    "physical-100k-one-artifact-proxy-per-file",
    "current-interpreter-and-clean-install-modes",
    "required-no-degradation-tests-fail-closed",
    "profile-bound-physical-100k-performance",
    "windows-linux-exact-zip-matrix", "three-zero-new-saturation-iterations",
    "evidence-manifest-physical-resolution", "typed-human-document-verification",
    "authenticated-role-platform-evidence-attestations",
    "installed-platform-observation-closure", "handle-relative-evidence-root-safety",
    "raw-scale-summary-recomputation", "bounded-incremental-commit-and-compaction",
    "offline-installed-no-degradation", "offline-release-online-compatibility",
    "single-derived-platform-closure-owner", "truthful-process-invocation-status",
)
_DECISION_ACCEPTANCE = (
    "current-release-closure-revalidation",
    "external-standard-release-decision-exact-binding",
    "standard-distribution-separate-from-product-acceptance",
    "candidate-evidence-decision-acyclic-chain",
    "signed-standard-decision-authority-proof", "semver-from-candidate-binding",
    "decision-after-evidence-with-bounded-skew", "product-public-approval-separation",
    "historical-decision-current-eligibility-separation",
)

_ACCEPTANCE_GROUP_VALIDATORS: dict[str, Check] = {
    **{
        check_id: _runtime_validate
        for check_id in _LOCAL_RUNTIME_REEXECUTE_ACCEPTANCE
    },
    **{
        check_id: _portable_distribution_acceptance
        for check_id in _PACKAGE_STATIC_ACCEPTANCE
    },
    **{
        check_id: partial(_migration_external_no_credit, check_id)
        for check_id in _MIGRATION_EXTERNAL_NO_CREDIT_ACCEPTANCE
    },
    **{
        check_id: _three_zero_new_saturation_iterations
        for check_id in _SATURATION_SIGNED_ACCEPTANCE
    },
    **{
        check_id: _evidence_manifest_physical_resolution
        for check_id in _STANDARD_RELEASE_SIGNED_MANIFEST_ACCEPTANCE
    },
    **{
        check_id: partial(_signed_role_acceptance, check_id)
        for check_id in _SIGNED_ROLE_ACCEPTANCE
    },
}
_ACCEPTANCE_DIRECT = {**_ACCEPTANCE_GROUP_VALIDATORS, **_ACCEPTANCE_DIRECT}


def acceptance_proof_classes(conformance_owner: Mapping[str, Any]) -> dict[str, str]:
    required = conformance_owner.get("required_acceptance")
    classes = conformance_owner.get("acceptance_proof_classes")
    if (
        not isinstance(required, list)
        or tuple(required) != _ACCEPTANCE_IDS
        or not isinstance(classes, Mapping)
        or set(classes) != set(required)
        or len(classes) != 102
    ):
        raise RuntimeError("Core acceptance proof-class map is not exact")
    counts = {
        proof_class: sum(value == proof_class for value in classes.values())
        for proof_class in set(classes.values())
    }
    owned_counts = conformance_owner.get("acceptance_proof_class_counts")
    if (
        not isinstance(owned_counts, Mapping)
        or any(
            not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
            for count in owned_counts.values()
        )
        or sum(owned_counts.values()) != len(required)
        or counts != owned_counts
    ):
        raise RuntimeError("Core acceptance proof-class distribution is not exact")
    return dict(classes)


def acceptance_catalogue() -> dict[str, Check]:
    if set(_ACCEPTANCE_DIRECT) != set(_ACCEPTANCE_IDS) or len(_ACCEPTANCE_IDS) != 102:
        raise RuntimeError("acceptance validator catalogue is not exact")
    return dict(_ACCEPTANCE_DIRECT)


_MUTATION_IDS = (
    "status-credit-contradiction", "missing-critical-field", "unknown-critical-field",
    "activation-drift", "grant-replay", "scope-escalation", "expired-grant",
    "revoked-grant", "stale-fence", "candidate-drift", "provider-substitution",
    "event-fork", "batch-command-mismatch", "duplicate-idempotency-key",
    "projection-corruption", "projection-staleness", "reference-break",
    "relation-domain-break", "context-flood", "symlink-core-input", "shadow-core-file",
    "symlink-product-entry", "secret-export", "archive-expansion",
    "preset-authority-escalation", "normalization-key-collision",
    "path-casefold-collision", "forbidden-name-reintroduction",
    "reinit-configuration-conflict", "clock-order-violation", "capability-confusion",
    "command-scope-escalation", "grant-issuer-chain-break",
    "unverified-signature-acceptance", "provider-declared-but-unavailable",
    "illegal-task-transition", "illegal-lease-transition", "decision-target-confusion",
    "credit-without-evidence", "command-primary-event-mismatch", "duplicate-event-id",
    "scope-selector-drop-broadening", "authorization-grant-claim-substitution",
    "command-effect-outside-requested-scope", "lease-holder-grant-mismatch",
    "decision-grant-provenance-mismatch", "artifact-kind-capability-confusion",
    "continuation-frontier-loss", "continuation-duplicate-emission",
    "candidate-recipe-bypass", "observational-candidate-pass-credit",
    "snapshot-provider-substitution", "unsupported-provider-adapter",
    "stale-release-closure-credit", "finding-evidence-target-mismatch",
    "candidate-delta-scope-escape", "checkpoint-head-mismatch",
    "checkpoint-corruption-credit", "normal-command-full-replay",
    "profile-default-depth-bypass",
    "continuation-public-material-mismatch", "inventory-provenance-override",
    "implementation-closure-drift", "noncanonical-archive-layout",
    "inventory-graph-inflation", "workcard-budget-bypass",
    "fabricated-evidence-digest", "unsigned-standard-decision",
    "unconfigured-standard-decision-key", "standard-decision-version-replay",
    "candidate-decision-cycle", "broad-query-corpus-pagination",
    "continuation-token-context-inflation", "inventory-stream-materialization",
    "pdf-header-only-credit", "scale-environment-skip-credit",
    "content-search-omission",
)


def mutation_catalogue() -> dict[str, Check]:
    if len(_MUTATION_IDS) != 77 or len(set(_MUTATION_IDS)) != 77:
        raise RuntimeError("mutation validator catalogue is not exact")
    return {check_id: partial(_mutation_rejection, check_id) for check_id in _MUTATION_IDS}
