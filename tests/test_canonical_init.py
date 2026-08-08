from __future__ import annotations

import hashlib
import json
import os
import runpy
import shutil
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

import pytest
import promin.init as init_runtime
import promin.service as service_runtime

from promin.__main__ import _parser as command_parser
from promin.canonical import (
    CanonicalError,
    ParseLimits,
    canonical_bytes,
    digest_file,
    digest_value,
    load_json_strict,
    parse_json_strict,
)
from promin.contracts import (
    ACCEPTANCE_VALIDATORS,
    MUTATION_PROBES,
    OBSERVATIONAL_CONSISTENCY,
    POLICY_VALIDATORS,
    ContractError,
    compile_candidate_recipe,
    load_contract_bundle,
    validate_candidate_consistency,
    validate_ingress,
    verify_core,
)
from promin.init import (
    ActivationGuard,
    InitError,
    InitRequest,
    bind_implementation_closures,
    build_explicit_init_plan,
    emit_canonical_init_plans,
    implementation_closure_digest,
    initialize_project,
    review_init_request,
    verify_before_mutation,
)
from promin.evidence import EvidenceStore
from promin.events import (
    CommitStateSnapshot,
    EventStore,
    PreparedCommit,
    command_intent_identity,
    state_binding_leaf_id,
    state_binding_value_digest,
)
from promin.experience import (
    PlanBudgetError,
    apply_plan,
    compile_core_plans,
    emit_expert_config,
    resolve_plan,
)


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
CORE = PACKAGE_ROOT / "core"
PRESET = PACKAGE_ROOT / "presets" / "semantic-standard.json"


def _provider_executable() -> Path:
    # A copied CPython launcher on Windows loses its adjacent DLL runtime and
    # therefore cannot truthfully serve as a materialized provider receipt.
    # Use a real system executable whose byte-exact copy remains runnable; the
    # fixture tests provider identity, not a Python-specific implementation.
    if os.name == "nt":
        candidate = Path(os.environ.get("SystemRoot", r"C:\\Windows")) / "System32" / "curl.exe"
        if candidate.is_file():
            return candidate.resolve()
    return Path(getattr(sys, "_base_executable", sys.executable)).resolve()


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _experience_preflight(paths: list[str]) -> dict[str, object]:
    return {
        "entries": [
            {
                "path": path,
                "kind": "file",
                "size_bytes": 1,
                "suffix": Path(path).suffix.casefold(),
            }
            for path in paths
        ],
        "manifest_samples": {},
        "truncated": False,
        "entry_count": len(paths),
        "bytes_read": 0,
        "max_files": 10_000,
        "max_bytes": 2 * 1024 * 1024,
        "max_depth": 8,
        "full_repository_scan": False,
        "git": {},
    }


def _with_plan_digest(plan: Mapping[str, Any]) -> dict[str, Any]:
    identity = {key: value for key, value in plan.items() if key != "plan_digest"}
    return {**identity, "plan_digest": digest_value(identity)}


def test_resolved_plan_uses_one_global_source_sample_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import promin.experience as experience_runtime

    suffixes = ["js", "ts", "py", "kt", "java", "cpp", "cs", "rs", "go", "swift"]
    paths = [
        f"apps/{suffix}/nested-segment/nested-segment/nested-segment/file-{index:04d}.{suffix}"
        for suffix in suffixes
        for index in range(500)
    ]
    preflight = _experience_preflight(paths)
    monkeypatch.setattr(experience_runtime, "bounded_preflight", lambda *_args, **_kwargs: preflight)

    first = resolve_plan(tmp_path, goal="Audit a mixed technology repository")
    reverse = dict(preflight)
    reverse["entries"] = list(reversed(preflight["entries"]))
    monkeypatch.setattr(experience_runtime, "bounded_preflight", lambda *_args, **_kwargs: reverse)
    second = resolve_plan(tmp_path, goal="Audit a mixed technology repository")

    technologies = first["detected_technologies"]
    assert len(paths) == 5000
    assert [item["technology"] for item in technologies] == sorted(
        item["technology"] for item in technologies
    )
    assert sum(len(item["sources"]) for item in technologies) <= 64
    assert {item["technology"]: item["total_source_count"] for item in technologies} == {
        "cpp": 500,
        "dotnet": 500,
        "go": 500,
        "java": 500,
        "javascript": 500,
        "kotlin": 500,
        "python": 500,
        "rust": 500,
        "swift": 500,
        "typescript": 500,
    }
    assert all(item["sources_truncated"] is True for item in technologies)
    assert all(item["source_count_complete"] is True for item in technologies)
    assert len(canonical_bytes(first)) <= 8192
    assert canonical_bytes(first) == canonical_bytes(second)
    assert first["plan_digest"] == second["plan_digest"]


def test_direct_expert_plan_ingress_cannot_bypass_global_source_budget(
    tmp_path: Path,
) -> None:
    plan = resolve_plan(tmp_path, goal="Create a bounded project")
    technologies = []
    for technology in ("alpha", "beta"):
        sources = [f"src/{technology}/file-{index:02d}.py" for index in range(33)]
        technologies.append(
            {
                "technology": technology,
                "sources": sources,
                "total_source_count": len(sources),
                "sources_truncated": False,
                "source_count_complete": True,
                "confidence": 1.0,
            }
        )
    direct_plan = _with_plan_digest({**plan, "detected_technologies": technologies})

    with pytest.raises(PlanBudgetError, match="source sample budget exceeded"):
        apply_plan(tmp_path, direct_plan)
    assert not (tmp_path / ".promin").exists()

    with pytest.raises(PlanBudgetError, match="source sample budget exceeded"):
        compile_core_plans(direct_plan, tmp_path)

    destination = tmp_path / "expert-config"
    with pytest.raises(PlanBudgetError, match="source sample budget exceeded"):
        emit_expert_config(destination, direct_plan, tmp_path)
    assert not destination.exists()


def _plans(tmp_path: Path) -> tuple[Path, dict[str, Path]]:
    project = tmp_path / "product"
    project.mkdir()
    provider_executable = _provider_executable()
    provider = project / provider_executable.name
    shutil.copy2(provider_executable, provider)
    if os.name != "nt":
        os.chmod(provider, provider.stat().st_mode | stat.S_IXUSR)
    provider_digest = digest_file(provider)
    plan_dir = tmp_path / "plans"
    project_plan = {
        "record_type": "ProjectInit",
        "project_id": "project-1",
        "roots": [{"path": ".", "kind": "product"}],
        "candidate_recipe": {
            "inventory_mode": "explicit",
            "include": ["src/**"],
            "exclude": [".promin/**"],
            "symlink_policy": "reject",
            "path_identity": "nfc-posix-relative",
            "collision_policy": "reject-nfc-and-casefold-collisions",
            "product_identity_excludes_control_state": True,
        },
        "preset_id": "semantic-standard",
        "operating_profile": "baseline",
    }
    standards_plan = {"record_type": "StandardsInit", "bindings": []}
    license_value = {
        "expression": "MIT",
        "source_uris": ["https://spdx.org/licenses/MIT.html"],
        "review_state": "source-verified",
    }
    required = [
        "control-runtime",
        "shape-validation",
        "content-identity",
        "local-serialization",
        "query-projection",
    ]
    bindings = [
        {
            "capability_id": capability,
            "provider_id": f"provider-{index}",
            "version": "1.0.0",
            "invocation": {"kind": "python-runtime", "value": str(provider)},
            "purpose": f"Provide {capability}",
            "required": True,
            "healthcheck": {
                "argv": [str(provider), "--version"],
                "timeout_ms": 1000,
                "expected_exit": 0,
            },
            "license": license_value,
            "identity": {
                "kind": "file-digest",
                "digest": provider_digest,
                "source": str(provider),
            },
        }
        for index, capability in enumerate(required, start=1)
    ]
    for binding in bindings:
        binding["dependency_receipt"] = init_runtime.build_provider_dependency_receipt(
            binding, project
        )
    technologies_plan = bind_implementation_closures(
        {"record_type": "TechnologiesInit", "bindings": bindings},
        project,
    )
    bindings = technologies_plan["bindings"]
    authority_plan = {
        "record_type": "AuthorityInit",
        "trust_mode": "local-owner",
        "subjects": [
            {"subject_id": "owner", "kind": "human", "display_name": "Owner"}
        ],
        "roots": [
            {
                "subject_id": "owner",
                "capability_ceiling": ["standard.activate", "task.plan", "task.execute"],
                "scope": [{"kind": "project", "value": "project-1"}],
            }
        ],
    }
    licenses_plan = {
        "record_type": "LicensesPlan",
        "bindings": [
            {"provider_id": item["provider_id"], "license": item["license"]}
            for item in bindings
        ],
    }
    paths = {
        "project_plan": _write(plan_dir / "project.json", project_plan),
        "standards_plan": _write(plan_dir / "standards.json", standards_plan),
        "technologies_plan": _write(plan_dir / "technologies.json", technologies_plan),
        "licenses_plan": _write(plan_dir / "licenses.json", licenses_plan),
        "authority_plan": _write(plan_dir / "authority.json", authority_plan),
    }
    return project, paths


def _request(project: Path, paths: dict[str, Path]) -> InitRequest:
    return InitRequest(
        project_root=project,
        standard_bundle=PACKAGE_ROOT,
        preset_path=PRESET,
        **paths,
    )


def _explicit_plan_objects(paths: Mapping[str, Path]) -> dict[str, dict[str, Any]]:
    return {
        "project_plan": load_json_strict(paths["project_plan"]),
        "standards_plan": load_json_strict(paths["standards_plan"]),
        "technologies_plan": load_json_strict(paths["technologies_plan"]),
        "licenses_plan": load_json_strict(paths["licenses_plan"]),
        "authority_plan": load_json_strict(paths["authority_plan"]),
    }


def test_emit_review_and_dry_run_are_non_mutating(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    plan_dir = tmp_path / "emitted-plans"
    emitted = emit_canonical_init_plans(
        plan_dir,
        project_root=project,
        standard_bundle=PACKAGE_ROOT,
        preset_path=PRESET,
        **_explicit_plan_objects(paths),
    )
    assert emitted["standard_version"] == "1.0.0-alpha.4"
    assert emitted["product_tree_scans"] == 0
    assert emitted["project_mutations"] == 0
    assert not (project / ".promin").exists()
    assert {item.name for item in plan_dir.iterdir()} == {
        "project.json",
        "standards.json",
        "technologies.json",
        "licenses.json",
        "authority.json",
    }
    request = InitRequest(
        project_root=project,
        standard_bundle=PACKAGE_ROOT,
        preset_path=PRESET,
        project_plan=plan_dir / "project.json",
        standards_plan=plan_dir / "standards.json",
        technologies_plan=plan_dir / "technologies.json",
        licenses_plan=plan_dir / "licenses.json",
        authority_plan=plan_dir / "authority.json",
    )
    review = review_init_request(request, run_preflight=False)
    dry_run = review_init_request(request, run_preflight=True)
    assert review["mode"] == "review"
    assert review["provider_preflight"] == "not_run"
    assert dry_run["mode"] == "dry-run"
    assert dry_run["provider_preflight"] == "pass"
    assert review["activation_digest"] == dry_run["activation_digest"]
    assert review["would_create_init_record_count"] == 5
    assert dry_run["mutations_performed"] == 0
    assert dry_run["product_tree_scans"] == 0
    assert dry_run["product_acceptance_pass"] is False
    assert not (project / ".promin").exists()


def test_emit_plan_rejects_existing_destination(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    destination = tmp_path / "existing-emission"
    destination.mkdir()
    with pytest.raises(InitError, match="already exists"):
        emit_canonical_init_plans(
            destination,
            project_root=project,
            standard_bundle=PACKAGE_ROOT,
            preset_path=PRESET,
            **_explicit_plan_objects(paths),
        )


def test_init_rejects_provider_byte_drift_before_project_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, paths = _plans(tmp_path)
    provider = project / _provider_executable().name
    original_identity = init_runtime._init_input_identity
    receipt_roots: list[Path | None] = []
    verified_identities: list[dict[str, Any]] = []

    def mutate_after_preflight(*args: object, **kwargs: object) -> dict[str, Any]:
        receipt_root = kwargs.get("provider_receipt_root")
        receipt_roots.append(
            receipt_root if isinstance(receipt_root, Path) else None
        )
        identity = original_identity(*args, **kwargs)
        if len(receipt_roots) == 1:
            verified_identities.append(identity)
            with provider.open("ab") as handle:
                handle.write(b"drift-after-preflight")
        return identity

    monkeypatch.setattr(init_runtime, "_init_input_identity", mutate_after_preflight)
    with pytest.raises(InitError, match="provider.*(?:drift|mismatch)"):
        initialize_project(_request(project, paths))
    assert len(receipt_roots) == 1
    assert receipt_roots[0] is not None
    assert receipt_roots[0] is not None and not receipt_roots[0].is_relative_to(project)
    assert len(verified_identities[0]["core_file_identities"]) == 6
    assert len(verified_identities[0]["init_plan_digests"]) == 5
    assert len(verified_identities[0]["init_record_digests"]) == 5
    assert verified_identities[0]["provider_identities"]
    assert verified_identities[0]["product_tree_scans"] == 0
    assert not (project / ".promin").exists()
    assert not list(project.glob(".p-*"))


def _standalone_provider_binding(
    project: Path, *, capability_id: str, timeout_ms: int
) -> dict[str, object]:
    provider = project / _provider_executable().name
    license_value = {
        "expression": "MIT",
        "source_uris": ["https://spdx.org/licenses/MIT.html"],
        "review_state": "source-verified",
    }
    binding = {
        "capability_id": capability_id,
        "provider_id": f"{capability_id}-provider",
        "version": "1.0.0",
        "invocation": {"kind": "executable", "value": str(provider)},
        "purpose": f"Provide {capability_id}",
        "required": False,
        "identity": {
            "kind": "file-digest",
            "digest": digest_file(provider),
            "source": str(provider),
        },
        "healthcheck": {
            "argv": [str(provider), "--version"],
            "timeout_ms": timeout_ms,
            "expected_exit": 0,
        },
        "license": license_value,
    }
    provider_tree = None
    if capability_id == "filesystem-inventory":
        provider_tree = project.parent / "standalone-git-provider-tree"
        provider_tree.mkdir(exist_ok=True)
        tree_file = provider_tree / provider.name
        if not tree_file.exists():
            shutil.copy2(provider, tree_file)
            if os.name != "nt":
                os.chmod(tree_file, tree_file.stat().st_mode | stat.S_IXUSR)
    binding["dependency_receipt"] = init_runtime.build_provider_dependency_receipt(
        binding,
        project,
        provider_tree=provider_tree,
    )
    return binding


def _select_immutable_inventory_provider(
    project: Path, paths: dict[str, Path], *, mode: str = "immutable-vcs-tree"
) -> None:
    project_plan = json.loads(paths["project_plan"].read_text(encoding="utf-8"))
    project_plan["candidate_recipe"].update(
        {
            "snapshot_consistency": mode,
            "snapshot_provider_id": "snapshot-provider",
        }
    )
    _write(paths["project_plan"], project_plan)

    provider_tree = project.parent / "snapshot-provider-tree"
    provider_tree.mkdir()
    provider = provider_tree / _provider_executable().name
    shutil.copy2(project / _provider_executable().name, provider)
    if os.name != "nt":
        os.chmod(provider, provider.stat().st_mode | stat.S_IXUSR)
    technologies = json.loads(paths["technologies_plan"].read_text(encoding="utf-8"))
    license_value = technologies["bindings"][0]["license"]
    snapshot_binding = {
        "capability_id": "filesystem-inventory",
        "provider_id": "snapshot-provider",
        "version": "1.0.0",
        "invocation": {"kind": "executable", "value": str(provider)},
        "purpose": "Provide immutable candidate inventory",
        "required": False,
        "healthcheck": {
            "argv": [str(provider), "--version"],
            "timeout_ms": 1000,
            "expected_exit": 0,
        },
        "license": license_value,
        "identity": {
            "kind": "file-digest",
            "digest": digest_file(provider),
            "source": str(provider),
        },
    }
    snapshot_binding["dependency_receipt"] = init_runtime.build_provider_dependency_receipt(
        snapshot_binding, project, provider_tree=provider_tree
    )
    technologies["bindings"].append(snapshot_binding)
    technologies = bind_implementation_closures(technologies, project)
    _write(paths["technologies_plan"], technologies)

    licenses = json.loads(paths["licenses_plan"].read_text(encoding="utf-8"))
    licenses["bindings"].append(
        {"provider_id": "snapshot-provider", "license": license_value}
    )
    _write(paths["licenses_plan"], licenses)


def test_strict_parser_rejects_duplicate_and_nfc_collisions(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"a":1,"a":2}', encoding="utf-8")
    with pytest.raises(CanonicalError, match="duplicate JSON key"):
        load_json_strict(duplicate)
    collision = '{"é":1,"é":2}'.encode("utf-8")
    with pytest.raises(CanonicalError, match="collision after NFC"):
        parse_json_strict(collision)


def test_strict_parser_enforces_size_depth_items_and_string_limits() -> None:
    with pytest.raises(CanonicalError, match="exceeds 8 bytes"):
        parse_json_strict(b'{"long":1}', limits=ParseLimits(max_bytes=8))
    with pytest.raises(CanonicalError, match="nesting exceeds"):
        parse_json_strict(b"[[[1]]]", limits=ParseLimits(max_depth=2))
    with pytest.raises(CanonicalError, match="item count exceeds"):
        parse_json_strict(b"[1,2,3]", limits=ParseLimits(max_items=3))
    with pytest.raises(CanonicalError, match="string exceeds"):
        parse_json_strict(b'"abcd"', limits=ParseLimits(max_string_length=3))


def test_strict_parser_rejects_symlink_or_windows_junction(tmp_path: Path) -> None:
    target_root = tmp_path / "target"
    target_root.mkdir()
    target = _write(target_root / "target.json", {"ok": True})
    if os.name == "nt":
        link = tmp_path / "linked-directory"
        created = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target_root)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert created.returncode == 0, created.stdout + created.stderr
        candidate = link / target.name
    else:
        link = tmp_path / "link.json"
        link.symlink_to(target)
        candidate = link
    try:
        with pytest.raises(CanonicalError, match="symbolic link or reparse point rejected"):
            load_json_strict(candidate, root=tmp_path)
    finally:
        if link.exists() or link.is_symlink():
            os.rmdir(link) if os.name == "nt" else link.unlink()


def _candidate_recipe(**updates: object) -> dict[str, object]:
    recipe: dict[str, object] = {
        "inventory_mode": "explicit",
        "include": ["src/**"],
        "exclude": [".promin/**", "build/**", "docs/**"],
        "symlink_policy": "reject",
        "path_identity": "nfc-posix-relative",
        "collision_policy": "reject-nfc-and-casefold-collisions",
        "product_identity_excludes_control_state": True,
    }
    recipe.update(updates)
    return recipe


def test_candidate_recipe_is_anchored_recursive_and_exclusion_wins() -> None:
    compiled = compile_candidate_recipe(_candidate_recipe())
    assert compiled.consistency_mode == OBSERVATIONAL_CONSISTENCY
    assert compiled.creditable is False
    assert compiled.includes("src/direct.txt")
    assert compiled.includes("src/nested/deep/file.txt")
    assert not compiled.includes("nested/src/not-anchored.txt")
    assert not compiled.includes("build/excluded.bin")
    assert not compiled.includes("docs/excluded.md")
    assert not compiled.includes(".promin/state/events/0001.json")


def test_candidate_recipe_selects_in_one_pass_and_rejects_path_collisions() -> None:
    compiled = compile_candidate_recipe(_candidate_recipe())
    seen: dict[str, str] = {}
    assert compiled.select("src/included.txt", seen) == "src/included.txt"
    assert compiled.select("build/excluded.bin", seen) is None
    assert compiled.select("docs/excluded.md", seen) is None
    assert compiled.select("src/\u00e9.txt", seen) == "src/\u00e9.txt"
    with pytest.raises(ContractError, match="NFC/casefold"):
        compiled.select("src/e\u0301.txt", seen)

    seen = {}
    assert compiled.select("src/Case.txt", seen) == "src/Case.txt"
    with pytest.raises(ContractError, match="NFC/casefold"):
        compiled.select("src/case.txt", seen)


@pytest.mark.parametrize(
    "path",
    ["/absolute", "C:/drive", "src\\windows", "src/../escape", "src//empty"],
)
def test_candidate_recipe_rejects_noncanonical_product_paths(path: str) -> None:
    compiled = compile_candidate_recipe(_candidate_recipe())
    with pytest.raises(ContractError, match="candidate path"):
        compiled.includes(path)


def test_candidate_recipe_symlink_policy_is_explicit_and_requires_nofollow() -> None:
    compiled = compile_candidate_recipe(_candidate_recipe())
    assert compiled.requires_descriptor_nofollow is True
    with pytest.raises(ContractError, match="symbolic link rejected"):
        compiled.select("src/link", {}, is_symlink=True)

    metadata = compile_candidate_recipe(
        _candidate_recipe(symlink_policy="hash-link-metadata")
    )
    assert metadata.select("src/link", {}, is_symlink=True) == "src/link"
    assert metadata.requires_descriptor_nofollow is True


def test_candidate_snapshot_consistency_fails_closed() -> None:
    observational = compile_candidate_recipe(_candidate_recipe())
    assert observational.snapshot_provider_id is None
    assert observational.digest == digest_value(_candidate_recipe())

    immutable = compile_candidate_recipe(
        _candidate_recipe(
            snapshot_consistency="immutable-vcs-tree",
            snapshot_provider_id="snapshot-provider",
        )
    )
    assert immutable.consistency_mode == "immutable-vcs-tree"
    assert immutable.creditable is True

    with pytest.raises(ContractError, match="requires snapshot_provider_id"):
        compile_candidate_recipe(
            _candidate_recipe(snapshot_consistency="immutable-vcs-tree")
        )
    with pytest.raises(ContractError, match="must not select"):
        compile_candidate_recipe(
            _candidate_recipe(snapshot_provider_id="snapshot-provider")
        )


def test_candidate_credit_requires_complete_immutable_snapshot_binding() -> None:
    observational = {
        "candidate_recipe_digest": "1" * 64,
        "consistency_mode": OBSERVATIONAL_CONSISTENCY,
        "creditable": False,
    }
    validate_candidate_consistency(observational)
    with pytest.raises(ContractError, match="cannot receive credit"):
        validate_candidate_consistency({**observational, "creditable": True})
    with pytest.raises(ContractError, match="must not claim"):
        validate_candidate_consistency(
            {**observational, "snapshot_provider_id": "snapshot-provider"}
        )

    immutable = {
        "candidate_recipe_digest": "1" * 64,
        "consistency_mode": "immutable-vcs-tree",
        "creditable": True,
        "snapshot_provider_id": "snapshot-provider",
        "snapshot_digest": "2" * 64,
    }
    validate_candidate_consistency(immutable)
    with pytest.raises(ContractError, match="snapshot_digest"):
        incomplete = dict(immutable)
        del incomplete["snapshot_digest"]
        validate_candidate_consistency(incomplete)


def test_init_provider_fixture_preserves_executable_identity(tmp_path: Path) -> None:
    project, _ = _plans(tmp_path)
    provider = project / _provider_executable().name
    assert os.access(provider, os.X_OK)
    assert digest_file(provider) == digest_file(_provider_executable())
    if os.name == "nt":
        assert provider.suffix.casefold() == ".exe"
    else:
        assert provider.stat().st_mode & stat.S_IXUSR


def test_v1_core_and_preset_verify() -> None:
    core = verify_core(CORE)
    manifest = core["promin.manifest.json"]
    assert manifest["canonical_name"] == "promin"
    assert str(manifest["version"]).startswith("1.0.0")
    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    assert bundle.bundle_digest == manifest["bundle_digest"]
    assert str(bundle.preset["version"]).startswith("1.0.0")
    expected_commands = (
        "init", "doctor", "status", "next", "validate", "static-admission",
        "continue", "audit", "refresh", "context", "skills",
    )
    assert tuple(bundle.preset["base_user_commands"]) == expected_commands
    workflows = next(
        action for action in command_parser()._actions if action.dest == "workflow"
    )
    assert tuple(workflows.choices) == expected_commands


def test_executable_contract_maps_exactly_cover_core_owners() -> None:
    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    assert set(POLICY_VALIDATORS) == {
        item["validator_id"] for item in bundle.core["policy-set.json"]["policies"]
    }
    assert set(ACCEPTANCE_VALIDATORS) == set(
        bundle.core["conformance.json"]["required_acceptance"]
    )
    assert set(MUTATION_PROBES) == set(
        bundle.core["conformance.json"]["mutation_families"]
    )
    manifest = bundle.manifest
    owner_counts = (
        len(bundle.schema["$defs"]),
        len(bundle.core["policy-set.json"]["policies"]),
        len(bundle.core["conformance.json"]["required_acceptance"]),
        len(bundle.core["conformance.json"]["mutation_families"]),
    )
    assert owner_counts == (
        manifest["schema_definition_count"],
        manifest["policy_count"],
        manifest["acceptance_predicate_count"],
        manifest["mutation_family_count"],
    )
    assert owner_counts[1:] == (
        len(POLICY_VALIDATORS),
        len(ACCEPTANCE_VALIDATORS),
        len(MUTATION_PROBES),
    )


def test_all_executable_contract_hooks_fail_closed_without_runtime_checks() -> None:
    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    with pytest.raises(ValueError, match="requires immutable EvidenceStore"):
        POLICY_VALIDATORS["grant_validity"]({}, bundle, {})
    with pytest.raises(ValueError, match="physical 100k result is absent"):
        ACCEPTANCE_VALIDATORS["profile-bound-physical-100k-performance"](
            {}, bundle, {}
        )
    with pytest.raises(ValueError, match="requires an isolated fixture root"):
        MUTATION_PROBES["grant-replay"]({}, bundle, {})


def test_direct_contract_hooks_execute_production_implementations() -> None:
    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    POLICY_VALIDATORS["canonical_name"]({}, bundle, {})
    POLICY_VALIDATORS["core_preset_separation"]({}, bundle, {})
    POLICY_VALIDATORS["normalization_collision"]({}, bundle, {})
    ACCEPTANCE_VALIDATORS["exact-six-core-artifacts"]({}, bundle, {})
    ACCEPTANCE_VALIDATORS["preset-outside-core-digest"]({}, bundle, {})


def test_legacy_workcard_grant_and_degraded_evidence_reject_at_every_ingress() -> None:
    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    workcard = {
        "record_type": "WorkCard",
        "task_id": "task:legacy",
        "operation_mode": "mutate",
        "operation": "task.transition",
        "acceptance_predicate": "reject legacy grant field",
        "allowed_paths": ["product/**"],
        "grant_id": "grant:legacy",
        "candidate_digest": "c" * 64,
        "activation_digest": "a" * 64,
        "context_digest": "d" * 64,
        "stop_conditions": ["legacy field rejected"],
        "budget": {
            "max_bytes": 1024,
            "max_entities": 1,
            "max_relations": 1,
            "max_fanout_per_entity": 1,
            "top_k": 1,
        },
        "truncated": False,
        "lease_id": "lease:legacy",
        "lease_generation": 1,
        "fencing_token": 1,
    }
    artifact = {
        "record_type": "Artifact",
        "artifact_id": "evidence:legacy",
        "artifact_kind": "evidence",
        "digest": "e" * 64,
        "media_type": "application/json",
        "size_bytes": 1,
        "retention_class": "audit",
        "created_at": "2026-07-17T00:00:00Z",
            "evidence_binding": {
                "activation_digest": "a" * 64,
                "implementation_closure_digest": "d" * 64,
                "candidate_digest": "c" * 64,
            "policy_digest": "1" * 64,
            "tool_digest": "2" * 64,
            "input_digests": [],
        },
        "outcome": "pass",
        "stale": False,
        "unresolved": False,
        "evidence_class": "validator",
        "evidence_purpose": "diagnostic",
        "product_credit_eligible": False,
        "degraded": False,
    }
    for operation in ("command", "import", "replay", "rebuild", "export"):
        with pytest.raises(ContractError, match="WorkCard validation failed"):
            validate_ingress(bundle, workcard, operation=operation)
        with pytest.raises(ContractError, match="Artifact validation failed"):
            validate_ingress(bundle, artifact, operation=operation)


def test_evidence_artifact_binds_the_active_activation() -> None:
    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    artifact = {
        "record_type": "Artifact",
        "artifact_id": "evidence:activation",
        "artifact_kind": "evidence",
        "digest": "e" * 64,
        "media_type": "application/json",
        "size_bytes": 1,
        "retention_class": "audit",
        "created_at": "2026-07-17T00:00:00Z",
        "evidence_binding": {
            "activation_digest": "a" * 64,
            "implementation_closure_digest": "d" * 64,
            "candidate_digest": "c" * 64,
            "policy_digest": "1" * 64,
            "tool_digest": "2" * 64,
            "input_digests": [],
        },
        "outcome": "pass",
        "stale": False,
        "unresolved": False,
        "evidence_class": "validator",
        "evidence_purpose": "diagnostic",
        "product_credit_eligible": False,
    }
    with pytest.raises(ContractError, match="Artifact Activation binding"):
        validate_ingress(
            bundle,
            artifact,
            operation="replay",
            context={
                "activation_digest": "b" * 64,
                "implementation_closure_digest": "d" * 64,
            },
        )


def test_mutation_command_requires_separate_holder_authorization() -> None:
    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    command = {
        "record_type": "CommandRequest",
        "command_id": "command:holder-binding",
        "command_kind": "task.transition",
        "subject_id": "worker",
        "activation_digest": "a" * 64,
        "idempotency_key": "holder-binding-0001",
        "requested_scope": [{"kind": "task", "value": "task:1"}],
        "expected_head_digest": None,
        "issued_at": "2026-07-17T00:00:00Z",
        "payload": {
            "task_id": "task:1",
            "from_state": "READY",
            "to_state": "LEASED",
            "reason": "begin execution",
        },
        "intent_digest": "1" * 64,
        "authorization": {
            "kind": "grant",
            "grant_id": "grant:planner",
            "grant_claim_digest": "2" * 64,
        },
        "holder_authorization": {
            "kind": "grant",
            "grant_id": "grant:worker",
            "grant_claim_digest": "3" * 64,
        },
        "workcard_task_id": "task:1",
        "lease_id": "lease:1",
        "lease_generation": 1,
        "fencing_token": 1,
        "workcard_digest": "4" * 64,
        "context_digest": "5" * 64,
    }
    validate_ingress(
        bundle,
        command,
        operation="command",
        context={"activation_digest": "a" * 64},
    )
    legacy = dict(command)
    legacy["holder_grant_id"] = legacy["holder_authorization"]["grant_id"]
    del legacy["holder_authorization"]
    with pytest.raises(ContractError, match="CommandRequest validation failed"):
        validate_ingress(bundle, legacy, operation="command")


def test_evidence_backed_policy_uses_real_cas_tool_and_input_bytes(tmp_path: Path) -> None:
    project, plan_paths = _plans(tmp_path)
    context = initialize_project(_request(project, plan_paths)).context
    bundle = context.bundle
    installed_activation = load_json_strict(
        context.control_root / "init" / "activation.json",
        root=context.control_root / "init",
    )
    assert installed_activation == context.activation
    activation_record_digest = digest_value(installed_activation)
    check_id = "grant_validity"
    policy = next(
        item
        for item in bundle.core["policy-set.json"]["policies"]
        if item["validator_id"] == check_id
    )
    payload = {
        "record_type": "ConformanceEvidence",
        "check_id": check_id,
        "status": "pass",
        "observed": True,
        "metrics": {},
    }
    payload_path = tmp_path / "grant-validity.json"
    payload_path.write_bytes(canonical_bytes(payload))
    tool_path = Path(__file__).resolve()
    input_path = CORE / "authority-model.json"
    candidate_digest = "c" * 64
    activation_digest = context.activation_digest
    implementation_closure_digest = context.implementation_closure_digest
    policy_digest = digest_value(policy)
    tool_digest = digest_file(tool_path)
    input_digests = [digest_file(input_path)]
    state_root = context.control_root / "state"
    store = EvidenceStore(state_root / "evidence")
    artifact = {
        "record_type": "Artifact",
        "artifact_id": "evidence:grant-validity",
        "artifact_kind": "evidence",
        "digest": digest_file(payload_path),
        "media_type": "application/json",
        "size_bytes": payload_path.stat().st_size,
        "retention_class": "audit",
        "created_at": "2026-07-17T00:00:00Z",
        "evidence_binding": {
            "activation_digest": activation_digest,
            "implementation_closure_digest": implementation_closure_digest,
            "candidate_digest": candidate_digest,
            "policy_digest": policy_digest,
            "tool_digest": tool_digest,
            "input_digests": input_digests,
        },
        "outcome": "pass",
        "stale": False,
        "unresolved": False,
        "evidence_class": "validator",
        "evidence_purpose": "gate",
        "product_credit_eligible": False,
    }
    command = {
        "record_type": "CommandRequest",
        "command_id": "command:grant-validity",
        "command_kind": "artifact.record",
        "subject_id": "worker",
        "activation_digest": activation_digest,
        "idempotency_key": "grant-validity-0001",
        "requested_scope": [{"kind": "all", "value": "*"}],
        "expected_head_digest": None,
        "issued_at": "2026-07-17T00:00:00Z",
        "payload": artifact,
        "intent_digest": "0" * 64,
        "authorization": {
            "kind": "grant",
            "grant_id": "grant:evidence-publisher",
            "grant_claim_digest": "3" * 64,
        },
        "holder_authorization": {
            "kind": "grant",
            "grant_id": "grant:task-holder",
            "grant_claim_digest": "4" * 64,
        },
        "workcard_task_id": "task:grant-validity",
        "lease_id": "lease:grant-validity",
        "lease_generation": 1,
        "fencing_token": 1,
        "workcard_digest": "5" * 64,
        "context_digest": "6" * 64,
    }
    command["intent_digest"] = digest_value(command_intent_identity(command))
    command_digest = digest_value(command)
    store.stage(artifact, payload_path.read_bytes(), command_digest=command_digest)
    event_policy = service_runtime._event_store_policy(context)
    event_validators = service_runtime._event_store_validators(context)

    def load_state(view: Any, _envelopes: Any) -> CommitStateSnapshot:
        return CommitStateSnapshot(
            (),
            view.head_sequence,
            view.head_digest,
            view.current_state_binding_digest,
        )

    def prepare_commit(
        _view: Any, prepared_command: Mapping[str, Any], relations: Any
    ) -> PreparedCommit:
        event_kind = event_policy.primary_events[prepared_command["command_kind"]]
        leaf_type = event_policy.state_binding_event_leaf_types[event_kind]
        payload_value = prepared_command["payload"]
        update = {
            "leaf_type": leaf_type,
            "leaf_id": state_binding_leaf_id(
                event_policy, leaf_type, payload_value
            ),
            "operation": "set",
            "value_digest": state_binding_value_digest(
                event_policy,
                leaf_type,
                payload_value,
                event_kind=event_kind,
            ),
        }
        return PreparedCommit(tuple(relations), (update,))

    events = EventStore(
        state_root / "events",
        activation_digest,
        activation_record_digest=activation_record_digest,
        implementation_closure_digest=implementation_closure_digest,
        policy=event_policy,
        **event_validators,
        commit_state_loader=load_state,
        commit_prepare_callback=prepare_commit,
    )
    events.commit(command, created_at="2026-07-17T00:00:00Z")
    envelope_path = next(events.journal.glob("*.json"))
    envelope = load_json_strict(envelope_path, root=events.journal)
    store.finalize(
        artifact,
        command_digest=command_digest,
        envelope=envelope,
    )
    store.reconcile(events.iter_envelopes())
    context = {
        "activation_digest": activation_digest,
        "implementation_closure_digest": implementation_closure_digest,
        "candidate_digest": candidate_digest,
        "evidence_store": store,
        "evidence_bindings": {check_id: artifact},
        "evidence_tools": {check_id: tool_path},
        "evidence_inputs": {check_id: [input_path]},
        "evidence_payloads": {check_id: payload_path},
    }
    POLICY_VALIDATORS[check_id]({}, bundle, context)
    payload_path.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="payload differs from CAS"):
        POLICY_VALIDATORS[check_id]({}, bundle, context)


def test_mutation_hook_executes_production_rejection(tmp_path: Path) -> None:
    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    MUTATION_PROBES["normalization-key-collision"](
        {},
        bundle,
        {
            "mutation_fixture_root": tmp_path / "mutations",
            "package_root": PACKAGE_ROOT,
        },
    )


def test_init_is_atomic_zero_scan_exact_and_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, paths = _plans(tmp_path)
    (project / "src").mkdir()
    for index in range(100):
        (project / "src" / f"product-{index}.txt").write_text("product", encoding="utf-8")
    original_iterdir = Path.iterdir

    def guarded_iterdir(path: Path):
        if path.resolve() == project.resolve():
            raise AssertionError("init attempted to enumerate the product root")
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", guarded_iterdir)
    result = initialize_project(_request(project, paths))
    assert result.created is True
    assert result.preflight_receipt.provider_count == len(
        result.context.plans["technologies.json"]["bindings"]
    )
    assert result.preflight_receipt.receipt_digest == digest_value(
        {
            "observation_digests": list(
                result.preflight_receipt.observation_digests
            )
        }
    )
    assert not (project / "core").exists()
    assert sorted(path.name for path in (project / ".promin" / "init").iterdir()) == [
        "activation.json",
        "authority.json",
        "project.json",
        "standards.json",
        "technologies.json",
    ]
    assert result.context.installed_standard == (
        project / ".promin" / "standard" / result.context.bundle.bundle_digest
    )
    secret_path = (
        project
        / ".promin"
        / "state"
        / "secrets"
        / f"{result.context.activation_digest}.continuation.key"
    )
    assert secret_path.read_bytes() == result.context.continuation_secret
    assert len(result.context.continuation_secret) == 32
    assert "continuation_secret" not in result.context.__dataclass_fields__
    assert "continuation_secret" not in repr(result.context)
    assert implementation_closure_digest(
        result.context.plans["technologies.json"]
    ) == result.context.implementation_closure_digest
    if os.name != "nt":
        assert stat.S_IMODE(secret_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(secret_path.parent.stat().st_mode) == 0o700
    for path in (project / ".promin" / "init").iterdir():
        assert result.context.continuation_secret not in path.read_bytes()
    second = initialize_project(_request(project, paths))
    assert second.idempotent is True
    assert second.preflight_receipt.provider_count == len(
        second.context.plans["technologies.json"]["bindings"]
    )
    assert second.context.activation_digest == result.context.activation_digest
    assert second.context.continuation_secret == result.context.continuation_secret


def test_init_tool_separates_standard_bundle_from_target_project(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    (project / "src").mkdir()
    tool = runpy.run_path(str(PACKAGE_ROOT / "tools" / "promin_init.py"))
    plan = tool["make_plan"](
        standard_bundle=PACKAGE_ROOT,
        preset_path=PRESET,
        project_root=project,
        project_plan=load_json_strict(paths["project_plan"]),
        standards_plan=load_json_strict(paths["standards_plan"]),
        technologies_plan=load_json_strict(paths["technologies_plan"]),
        licenses_plan=load_json_strict(paths["licenses_plan"]),
        authority_plan=load_json_strict(paths["authority_plan"]),
    )

    assert Path(plan["standard_bundle"]) == PACKAGE_ROOT
    assert Path(plan["project_root"]) == project
    assert plan["implementation_closure_digest"] == implementation_closure_digest(
        plan["plans"]["technologies.json"]
    )
    first = tool["apply_plan"](project, plan)
    second = tool["apply_plan"](project, plan)
    assert first["status"] == "created"
    assert second["status"] == "idempotent"
    assert (project / ".promin").is_dir()
    assert not (PACKAGE_ROOT / ".promin").exists()


def test_init_tool_is_a_zero_policy_thin_delegation() -> None:
    source = (PACKAGE_ROOT / "tools" / "promin_init.py").read_text(encoding="utf-8")
    assert "local-owner" not in source
    assert "all:*" not in source
    assert "semantic-standard.json" not in source
    assert "def make_plan" not in source
    assert "def apply_plan" not in source


def test_explicit_init_plan_rejects_non_project_authority_scope(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    authority = load_json_strict(paths["authority_plan"])
    authority["roots"][0]["scope"] = [{"kind": "all", "value": "*"}]
    with pytest.raises(InitError, match="exact project"):
        build_explicit_init_plan(
            standard_bundle=PACKAGE_ROOT,
            preset_path=PRESET,
            project_root=project,
            project_plan=load_json_strict(paths["project_plan"]),
            standards_plan=load_json_strict(paths["standards_plan"]),
            technologies_plan=load_json_strict(paths["technologies_plan"]),
            licenses_plan=load_json_strict(paths["licenses_plan"]),
            authority_plan=authority,
        )



def _materialized_provider_dispatch(
    project: Path, binding: Mapping[str, Any], bundle: ContractBundle
) -> init_runtime.ProviderDispatch:
    technologies = bind_implementation_closures(
        {"record_type": "TechnologiesInit", "bindings": [dict(binding)]},
        project,
        contract_bundle=bundle,
    )
    receipt_root = project.parent / "standalone-provider-receipts"
    init_runtime.materialize_provider_receipts(technologies, project, receipt_root)
    init_runtime.verify_provider_receipt_inventory(technologies, receipt_root, project)
    return init_runtime.resolve_provider_dispatch(
        technologies,
        project,
        contract_bundle=bundle,
        receipt_root=receipt_root,
    )

def test_provider_protocol_is_derived_and_rejects_an_unlisted_tuple(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    technologies = load_json_strict(paths["technologies_plan"])
    binding = technologies["bindings"][0]
    binding["invocation"]["kind"] = "executable"
    with pytest.raises(InitError, match="unsupported provider adapter"):
        init_runtime.resolve_provider_dispatch(
            technologies,
            project,
            contract_bundle=load_contract_bundle(PACKAGE_ROOT, PRESET),
            verify_implementation=False,
        )


def test_git_provider_helper_prepares_only_exact_core_operations(tmp_path: Path) -> None:
    project, _paths = _plans(tmp_path)
    binding = _standalone_provider_binding(
        project, capability_id="filesystem-inventory", timeout_ms=1000
    )
    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    dispatch = _materialized_provider_dispatch(project, binding, bundle)
    prepared = dispatch.prepare_invocation(
        "filesystem-inventory",
        "immutable-tree-object",
        {"repository": str(project)},
    )
    assert prepared.argv[1:] == ("rev-parse", "--verify", "HEAD^{tree}")
    assert prepared.stdin is None
    assert prepared.evidence["protocol_id"] == "promin.filesystem-inventory.v1"
    assert prepared.evidence["operation"] == "immutable-tree-object"
    with pytest.raises(InitError, match="executed verification"):
        dispatch.prepare_invocation(
            "filesystem-inventory",
            "immutable-tree-stream",
            {"repository": str(project), "tree_object": "a" * 40},
            output_size_ceiling_bytes=2 * 1024 * 1024,
        )
    assert dispatch.validate_tree_object_response(
        prepared,
        returncode=0,
        stdout=b"a" * 40 + b"\n",
        stderr=b"",
    ) == "a" * 40
    evidence = dispatch.complete_buffered_invocation_evidence(
        prepared,
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:01Z",
        outcome="success",
        exit_code=0,
        stdout=b"a" * 40 + b"\n",
        stderr=b"",
    )
    assert evidence["invoked"] is True
    assert evidence["outcome"] == "success"
    assert evidence["input_digest"] == hashlib.sha256(b"").hexdigest()
    assert evidence["output_digest"] == hashlib.sha256(
        b"a" * 40 + b"\n"
    ).hexdigest()
    assert evidence["pass_credit"] is False
    with pytest.raises(InitError, match="timestamp"):
        dispatch.complete_buffered_invocation_evidence(
            prepared,
            started_at="2026-02-31T00:00:00Z",
            completed_at="2026-03-01T00:00:00Z",
            outcome="success",
            exit_code=0,
            stdout=b"a" * 40 + b"\n",
            stderr=b"",
        )
    with pytest.raises(InitError, match="project root"):
        dispatch.prepare_invocation(
            "filesystem-inventory",
            "immutable-tree-object",
            {"repository": str(project), "treeish": "other"},
        )


def test_streamed_provider_evidence_separates_full_output_from_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, _paths = _plans(tmp_path)
    binding = _standalone_provider_binding(
        project, capability_id="filesystem-inventory", timeout_ms=1000
    )
    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    dispatch = _materialized_provider_dispatch(project, binding, bundle)

    def verified_tree(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 0, b"a" * 40 + b"\n", b"")

    monkeypatch.setattr(init_runtime.subprocess, "run", verified_tree)
    tree_object, _object_evidence = dispatch.invoke_tree_object(
        {"repository": str(project)}
    )
    selected_ceiling = 2 * 1024 * 1024
    plan = dispatch.prepare_invocation(
        "filesystem-inventory",
        "immutable-tree-stream",
        {"repository": str(project), "tree_object": tree_object},
        output_size_ceiling_bytes=selected_ceiling,
    )
    payload = b"x" * (1024 * 1024) + b"complete-stream-tail"
    capture = payload[: 1024 * 1024]
    evidence = dispatch.complete_streamed_invocation_evidence(
        plan,
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:00:01Z",
        outcome="success",
        exit_code=0,
        output_digest=hashlib.sha256(payload).hexdigest(),
        output_size_bytes=len(payload),
        stdout_capture_digest=hashlib.sha256(capture).hexdigest(),
        stdout_capture_size_bytes=len(capture),
        stdout_capture_truncated=True,
        stderr_capture_digest=hashlib.sha256(b"").hexdigest(),
        stderr_capture_size_bytes=0,
        stderr_capture_truncated=False,
    )
    assert evidence["output_digest"] == hashlib.sha256(payload).hexdigest()
    assert evidence["output_size_bytes"] == len(payload)
    assert evidence["output_size_ceiling_bytes"] == selected_ceiling
    assert evidence["stdout_capture_size_bytes"] == 1024 * 1024
    assert evidence["stdout_capture_truncated"] is True
    assert {
        "output_digest",
        "output_size_bytes",
        "output_size_ceiling_bytes",
    } <= set(evidence)
    assert {
        "stdout_capture_digest",
        "stdout_capture_size_bytes",
        "stdout_capture_truncated",
        "stderr_capture_digest",
        "stderr_capture_size_bytes",
        "stderr_capture_truncated",
    } <= set(evidence)
    assert "argv" not in evidence
    assert "argv_or_module_call" not in evidence
    request_receipt = dispatch.invocation_request_receipt(plan)
    assert evidence["invocation_request_digest"] == digest_value(request_receipt)
    receipt_digest = evidence["invocation_receipt_digest"]
    unsigned = dict(evidence)
    del unsigned["invocation_receipt_digest"]
    assert receipt_digest == digest_value(unsigned)


def test_streamed_provider_evidence_rejects_post_invocation_ceiling_and_false_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, _paths = _plans(tmp_path)
    binding = _standalone_provider_binding(
        project, capability_id="filesystem-inventory", timeout_ms=1000
    )
    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    dispatch = _materialized_provider_dispatch(project, binding, bundle)

    def verified_tree(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(argv, 0, b"b" * 40 + b"\n", b"")

    monkeypatch.setattr(init_runtime.subprocess, "run", verified_tree)
    tree_object, _object_evidence = dispatch.invoke_tree_object(
        {"repository": str(project)}
    )
    with pytest.raises(InitError, match="selected before invocation"):
        dispatch.prepare_invocation(
            "filesystem-inventory",
            "immutable-tree-stream",
            {"repository": str(project), "tree_object": tree_object},
        )
    plan = dispatch.prepare_invocation(
        "filesystem-inventory",
        "immutable-tree-stream",
        {"repository": str(project), "tree_object": tree_object},
        output_size_ceiling_bytes=1024,
    )
    with pytest.raises(InitError, match="identity is stale"):
        dispatch.invocation_request_receipt(
            replace(plan, output_size_ceiling_bytes=2048)
        )
    with pytest.raises(InitError, match="selected ceiling"):
        dispatch.complete_streamed_invocation_evidence(
            plan,
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:00:01Z",
            outcome="success",
            exit_code=0,
            output_digest="1" * 64,
            output_size_bytes=1025,
            stdout_capture_digest="1" * 64,
            stdout_capture_size_bytes=1024,
            stdout_capture_truncated=True,
            stderr_capture_digest=hashlib.sha256(b"").hexdigest(),
            stderr_capture_size_bytes=0,
            stderr_capture_truncated=False,
        )


def test_git_dependency_receipt_rejects_product_tree_as_provider_tree(
    tmp_path: Path,
) -> None:
    project, _paths = _plans(tmp_path)
    provider = project / _provider_executable().name
    license_value = {
        "expression": "MIT",
        "source_uris": ["https://spdx.org/licenses/MIT.html"],
        "review_state": "source-verified",
    }
    binding = {
        "capability_id": "filesystem-inventory",
        "provider_id": "overlapping-provider",
        "version": "1.0.0",
        "invocation": {"kind": "executable", "value": str(provider)},
        "purpose": "Reject a product-tree provider scan",
        "required": False,
        "healthcheck": {
            "argv": [str(provider), "--version"],
            "timeout_ms": 1000,
            "expected_exit": 0,
        },
        "license": license_value,
        "identity": {
            "kind": "file-digest",
            "digest": digest_file(provider),
            "source": str(provider),
        },
    }
    with pytest.raises(InitError, match="must not overlap"):
        init_runtime.build_provider_dependency_receipt(
            binding, project, provider_tree=project
        )


def test_process_local_signature_adapter_is_rejected_as_nonreconstructable(
    tmp_path: Path,
) -> None:
    project, _paths = _plans(tmp_path)
    binding = _standalone_provider_binding(
        project, capability_id="signature", timeout_ms=1000
    )
    binding["invocation"]["kind"] = "python-runtime"
    with pytest.raises(InitError, match="unsupported provider adapter|reconstructable"):
        init_runtime.resolve_provider_dispatch(
            {"record_type": "TechnologiesInit", "bindings": [binding]},
            project,
            contract_bundle=load_contract_bundle(PACKAGE_ROOT, PRESET),
            verify_implementation=False,
        )


def test_python_module_preflight_binds_exact_interpreter_module_and_callable(
    tmp_path: Path,
) -> None:
    project, _paths = _plans(tmp_path)
    module = project / "signature_provider.py"
    module.write_text("def verify_signature(proof, key):\n    return False\n", encoding="utf-8")
    license_value = {
        "expression": "MIT",
        "source_uris": ["https://spdx.org/licenses/MIT.html"],
        "review_state": "source-verified",
    }
    binding = {
        "capability_id": "signature",
        "provider_id": "module-signature",
        "version": "1.0.0",
        "invocation": {"kind": "python-module", "value": f"{module}#other"},
        "purpose": "Verify signatures",
        "required": False,
        "healthcheck": {
            "argv": [sys.executable, str(module), "--health"],
            "timeout_ms": 1000,
            "expected_exit": 0,
        },
        "license": license_value,
        "identity": {
            "kind": "module-file-digest",
            "digest": digest_file(module),
            "source": str(module),
        },
    }
    binding["dependency_receipt"] = init_runtime.build_provider_dependency_receipt(
        binding, project
    )
    technologies = {"record_type": "TechnologiesInit", "bindings": [binding]}
    with pytest.raises(InitError, match="verify_signature"):
        init_runtime.resolve_provider_dispatch(
            technologies,
            project,
            contract_bundle=load_contract_bundle(PACKAGE_ROOT, PRESET),
            verify_implementation=False,
        )
    binding["invocation"]["value"] = f"{module}#verify_signature"
    binding["healthcheck"]["argv"][0] = str(project / _provider_executable().name)
    with pytest.raises(InitError, match="interpreter is not exact"):
        init_runtime.verify_provider_preflight(
            technologies,
            project,
            contract_bundle=load_contract_bundle(PACKAGE_ROOT, PRESET),
        )


def test_implementation_closure_covers_runtime_dependencies_and_adapters(
    tmp_path: Path,
) -> None:
    project, paths = _plans(tmp_path)
    context = initialize_project(_request(project, paths)).context
    closures = context.implementation_closure

    assert set(closures) == {
        "control-runtime",
        "shape-validation",
        "content-identity",
        "local-serialization",
        "query-projection",
    }
    for capability_id, closure in closures.items():
        assert closure["runtime"]["name"] == "promin"
        assert closure["interpreter"]["name"] == sys.implementation.name
        assert closure["adapters"][0]["capability_id"] == capability_id
        identity = {key: value for key, value in closure.items() if key != "closure_digest"}
        assert closure["closure_digest"] == digest_value(identity)
    assert [
        component["component_id"]
        for component in closures["shape-validation"]["components"]
    ] == ["interpreter", "jsonschema"]
    assert [
        component["component_id"]
        for component in closures["query-projection"]["components"]
    ] == ["interpreter", "sqlite"]
    for binding in context.plans["technologies.json"]["bindings"]:
        closure_components = closures[binding["capability_id"]]["components"]
        assert closure_components
        assert closure_components == binding["dependency_receipt"]["components"]


def test_activation_guard_rejects_implementation_runtime_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, paths = _plans(tmp_path)
    initialize_project(_request(project, paths))
    original = init_runtime._promin_runtime_receipt

    def drifted_runtime() -> dict[str, str]:
        receipt = original()
        return {**receipt, "digest": "f" * 64}

    monkeypatch.setattr(init_runtime, "_promin_runtime_receipt", drifted_runtime)
    with pytest.raises(InitError, match="implementation closure drift"):
        ActivationGuard(project).verify()


def test_continuation_secret_creation_failure_leaves_no_control_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, paths = _plans(tmp_path)

    def fail_random(_size: int) -> bytes:
        raise RuntimeError("simulated local entropy failure")

    monkeypatch.setattr(init_runtime.os, "urandom", fail_random)
    with pytest.raises(RuntimeError, match="simulated local entropy failure"):
        initialize_project(_request(project, paths))
    assert not (project / ".promin").exists()
    assert not list(project.glob(".p-*"))


def test_activation_guard_rejects_continuation_secret_tamper(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    result = initialize_project(_request(project, paths))
    secret_path = (
        project
        / ".promin"
        / "state"
        / "secrets"
        / f"{result.context.activation_digest}.continuation.key"
    )
    secret_path.write_bytes(b"not-a-valid-activation-secret")
    with pytest.raises(InitError, match="invalid size"):
        ActivationGuard(project).verify()


def test_concurrent_identical_init_installs_one_activation_secret(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    request = _request(project, paths)

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(lambda _index: initialize_project(request), range(8)))

    assert sum(result.created for result in results) == 1
    activation_digests = {result.context.activation_digest for result in results}
    secrets = {result.context.continuation_secret for result in results}
    assert len(activation_digests) == 1
    assert len(secrets) == 1
    assert len(list((project / ".promin" / "state" / "secrets").iterdir())) == 1
    assert not list(project.glob(".p-*"))


def test_init_rejects_license_plan_mismatch(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    licenses = json.loads(paths["licenses_plan"].read_text(encoding="utf-8"))
    licenses["bindings"][0]["license"]["expression"] = "Apache-2.0"
    _write(paths["licenses_plan"], licenses)
    with pytest.raises(ContractError, match="exactly match"):
        initialize_project(_request(project, paths))
    assert not (project / ".promin").exists()


def test_init_rejects_unbound_immutable_snapshot_provider(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    project_plan = json.loads(paths["project_plan"].read_text(encoding="utf-8"))
    project_plan["candidate_recipe"].update(
        {
            "snapshot_consistency": "immutable-vcs-tree",
            "snapshot_provider_id": "missing-snapshot-provider",
        }
    )
    _write(paths["project_plan"], project_plan)
    with pytest.raises(ContractError, match="snapshot provider is not exactly bound"):
        initialize_project(_request(project, paths))
    assert not (project / ".promin").exists()


def test_init_persists_exact_immutable_snapshot_provider_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, paths = _plans(tmp_path)
    _select_immutable_inventory_provider(project, paths)
    execute = init_runtime.subprocess.run

    def exact_git_health(argv: list[str], **kwargs: object):
        if "git-provider-tree" in Path(argv[0]).parts and argv[1:] == ["--version"]:
            return init_runtime.subprocess.CompletedProcess(
                argv, 0, b"git version 2.45.1\n", b""
            )
        return execute(argv, **kwargs)

    monkeypatch.setattr(init_runtime.subprocess, "run", exact_git_health)
    result = initialize_project(_request(project, paths))
    installed = load_json_strict(
        project / ".promin" / "init" / "project.json",
        root=project / ".promin" / "init",
    )
    assert installed["candidate_recipe"]["snapshot_consistency"] == "immutable-vcs-tree"
    assert installed["candidate_recipe"]["snapshot_provider_id"] == "snapshot-provider"
    assert result.context.activation_digest


def test_init_rejects_provider_on_observational_recipe(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    project_plan = json.loads(paths["project_plan"].read_text(encoding="utf-8"))
    project_plan["candidate_recipe"]["snapshot_provider_id"] = "provider-1"
    _write(paths["project_plan"], project_plan)
    with pytest.raises(ContractError, match="snapshot_provider_id|must not select"):
        initialize_project(_request(project, paths))
    assert not (project / ".promin").exists()


def test_init_rejects_unavailable_required_provider_before_commit(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    technologies = json.loads(paths["technologies_plan"].read_text(encoding="utf-8"))
    technologies["bindings"][0]["healthcheck"]["argv"] = [
        str(project / "missing-provider.exe")
    ]
    _write(paths["technologies_plan"], technologies)
    with pytest.raises(InitError, match="provider path is unavailable"):
        initialize_project(_request(project, paths))
    assert not (project / ".promin").exists()


def test_signature_provider_short_timeout_uses_bounded_startup_allowance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, _ = _plans(tmp_path)
    binding = _standalone_provider_binding(
        project, capability_id="signature", timeout_ms=100
    )
    observed: list[float] = []

    def complete(argv: list[str], **kwargs: object):
        observed.append(float(kwargs["timeout"]))
        stdout = (
            canonical_bytes({"verified": True})
            if "--promin-signature-verify-v1" in argv
            else b""
        )
        return init_runtime.subprocess.CompletedProcess(argv, 0, stdout, b"")

    monkeypatch.setattr(init_runtime.subprocess, "run", complete)
    init_runtime.verify_provider_preflight({"bindings": [binding]}, project)
    verifier = init_runtime._executable_signature_verifier(binding, project)
    assert verifier({"claim_digest": "a" * 64}, {"key_id": "key-1"}) is True

    expected = 10.0 if os.name == "nt" else 5.0
    assert observed == [expected, expected]


def test_executable_signature_provider_uses_platform_subprocess_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, _ = _plans(tmp_path)
    binding = _standalone_provider_binding(
        project, capability_id="signature", timeout_ms=100
    )
    observed: list[tuple[list[str], str | None]] = []

    monkeypatch.setattr(
        init_runtime,
        "subprocess_path",
        lambda value: "EXTENDED::" + str(value),
    )

    def complete(argv: list[str], **kwargs: object):
        observed.append((list(argv), kwargs.get("executable")))
        return init_runtime.subprocess.CompletedProcess(
            argv, 0, canonical_bytes({"verified": True}), b""
        )

    monkeypatch.setattr(init_runtime.subprocess, "run", complete)
    verifier = init_runtime._executable_signature_verifier(binding, project)
    assert verifier({"claim_digest": "a" * 64}, {"key_id": "key-1"}) is True
    argv, executable = observed[0]
    assert not argv[0].startswith("EXTENDED::")
    assert isinstance(executable, str) and executable.startswith("EXTENDED::")


def test_signature_provider_timeout_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, _ = _plans(tmp_path)
    binding = _standalone_provider_binding(
        project, capability_id="signature", timeout_ms=100
    )

    def expire(argv: list[str], **kwargs: object):
        raise init_runtime.subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(init_runtime.subprocess, "run", expire)
    with pytest.raises(InitError, match="provider healthcheck unavailable"):
        init_runtime.verify_provider_preflight({"bindings": [binding]}, project)
    verifier = init_runtime._executable_signature_verifier(binding, project)
    with pytest.raises(InitError, match="signature provider invocation unavailable"):
        verifier({"claim_digest": "a" * 64}, {"key_id": "key-1"})


def test_non_signature_provider_keeps_declared_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, _ = _plans(tmp_path)
    binding = _standalone_provider_binding(
        project, capability_id="filesystem-inventory", timeout_ms=1375
    )
    observed: list[float] = []

    def complete(argv: list[str], **kwargs: object):
        observed.append(float(kwargs["timeout"]))
        return init_runtime.subprocess.CompletedProcess(
            argv, 0, b"git version 2.45.1\n", b""
        )

    monkeypatch.setattr(init_runtime.subprocess, "run", complete)
    init_runtime.verify_provider_preflight({"bindings": [binding]}, project)
    assert observed == [1.375]


def test_signature_provider_declared_timeout_and_ceiling_are_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, _ = _plans(tmp_path)
    binding = _standalone_provider_binding(
        project, capability_id="signature", timeout_ms=12_000
    )
    observed: list[float] = []

    def complete(argv: list[str], **kwargs: object):
        observed.append(float(kwargs["timeout"]))
        return init_runtime.subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(init_runtime.subprocess, "run", complete)
    init_runtime.verify_provider_preflight({"bindings": [binding]}, project)
    assert observed == [12.0]

    binding["healthcheck"]["timeout_ms"] = 60_001  # type: ignore[index]
    with pytest.raises(InitError, match="outside the bounded range"):
        init_runtime.verify_provider_preflight({"bindings": [binding]}, project)


def test_short_signature_healthcheck_executes_bound_runtime_cross_platform(
    tmp_path: Path,
) -> None:
    project, _ = _plans(tmp_path)
    binding = _standalone_provider_binding(
        project, capability_id="signature", timeout_ms=100
    )
    init_runtime.verify_provider_preflight({"bindings": [binding]}, project)


def test_concurrent_conflicting_init_rejects_one_plan(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    alternate = json.loads(paths["project_plan"].read_text(encoding="utf-8"))
    alternate["project_id"] = "project-conflict"
    alternate_path = _write(paths["project_plan"].parent / "project-conflict.json", alternate)
    alternate_authority = load_json_strict(paths["authority_plan"])
    for root in alternate_authority["roots"]:
        root["scope"] = [{"kind": "project", "value": "project-conflict"}]
    alternate_authority_path = _write(
        paths["authority_plan"].parent / "authority-conflict.json",
        alternate_authority,
    )
    first = _request(project, paths)
    second = replace(
        first,
        project_plan=alternate_path,
        authority_plan=alternate_authority_path,
    )

    def execute(request: InitRequest):
        try:
            return initialize_project(request)
        except InitError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(execute, (first, second)))
    successes = [outcome for outcome in outcomes if not isinstance(outcome, Exception)]
    failures = [outcome for outcome in outcomes if isinstance(outcome, Exception)]
    assert len(successes) == 1
    assert len(failures) == 1
    assert "differs from the requested content" in str(failures[0])
    assert not list(project.glob(".p-*"))


def test_init_bounds_atomic_staging_component(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, paths = _plans(tmp_path)
    observed: list[str] = []
    rename = os.rename

    def capture(source: str | os.PathLike[str], destination: str | os.PathLike[str]) -> None:
        observed.append(Path(source).name)
        rename(source, destination)

    monkeypatch.setattr(init_runtime.os, "rename", capture)
    initialize_project(_request(project, paths))

    assert len(observed) == 1
    assert observed[0].startswith(".p-")
    assert len(observed[0]) == 15
    assert not list(project.glob(".p-*"))


def test_activation_guard_rejects_init_tamper(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    initialize_project(_request(project, paths))
    project_init = project / ".promin" / "init" / "project.json"
    record = json.loads(project_init.read_text(encoding="utf-8"))
    record["project_id"] = "tampered"
    _write(project_init, record)
    with pytest.raises(InitError, match="Activation binding mismatch"):
        ActivationGuard(project).verify()


def test_activation_guard_rejects_core_tamper(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    result = initialize_project(_request(project, paths))
    semantic = result.context.installed_standard / "core" / "semantic-model.json"
    os.chmod(semantic, stat.S_IWRITE | stat.S_IREAD)
    with semantic.open("ab") as handle:
        handle.write(b" ")
    with pytest.raises(ContractError, match="Core digest mismatch"):
        ActivationGuard(project).verify()


def test_activation_guard_restarts_without_mutable_provider_source(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    initialized = initialize_project(_request(project, paths)).context
    receipt = Path(
        initialized.provider_dispatch.binding("control-runtime")["invocation"]["value"]
    )
    provider = project / _provider_executable().name
    provider.unlink()

    restarted = ActivationGuard(project).verify()
    assert Path(
        restarted.provider_dispatch.binding("control-runtime")["invocation"]["value"]
    ) == receipt
    assert digest_file(receipt) == restarted.provider_dispatch.binding(
        "control-runtime"
    )["identity"]["digest"]
    with pytest.raises(InitError, match="requires executed preflight"):
        restarted.provider_dispatch.runtime_evidence()
    observations = init_runtime.verify_provider_preflight(
        restarted.plans["technologies.json"],
        project,
        contract_bundle=restarted.bundle,
        provider_dispatch=restarted.provider_dispatch,
        receipt_root=restarted.control_root / "providers",
    )
    assert len(observations) == len(restarted.plans["technologies.json"]["bindings"])
    assert all(item["invoked"] is True for item in observations)
    assert all(item["outcome"] == "healthy" for item in observations)


def test_verified_provider_dispatch_uses_content_addressed_receipt(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    context = initialize_project(_request(project, paths)).context
    binding = context.provider_dispatch.binding("control-runtime")
    receipt = Path(binding["invocation"]["value"])
    original = project / _provider_executable().name
    assert receipt.is_relative_to(project / ".promin" / "providers")
    assert receipt != original
    assert digest_file(receipt) == binding["identity"]["digest"]
    runtime_evidence = next(
        item
        for item in context.provider_dispatch.runtime_evidence()
        if item["capability_id"] == "control-runtime"
    )
    assert runtime_evidence["protocol_id"] == "promin.control-runtime.v1"
    assert runtime_evidence["operation"] == "healthcheck"
    assert runtime_evidence["persistence_scope"] == "content-addressed-receipt"
    assert runtime_evidence["invoked"] is True
    assert runtime_evidence["outcome"] == "healthy"
    assert runtime_evidence["pass_credit"] is False

    with original.open("ab") as handle:
        handle.write(b"substitution")
    assert digest_file(receipt) == binding["identity"]["digest"]
    assert Path(context.provider_dispatch.binding("control-runtime")["invocation"]["value"]) == receipt


def test_provider_receipt_survives_restart_and_tamper_fails_closed(tmp_path: Path) -> None:
    project, paths = _plans(tmp_path)
    initialized = initialize_project(_request(project, paths)).context
    receipt = Path(
        initialized.provider_dispatch.binding("control-runtime")["invocation"]["value"]
    )
    restarted = ActivationGuard(project).verify()
    assert Path(
        restarted.provider_dispatch.binding("control-runtime")["invocation"]["value"]
    ) == receipt

    os.chmod(receipt, stat.S_IWRITE | stat.S_IREAD)
    # Windows may retain the just-invoked provider executable for a short
    # interval after its health-check child exits.  The assertion is about the
    # next Activation verification rejecting a real byte mutation, not about
    # an arbitrary file-sharing race at process teardown.
    deadline = time.monotonic() + 5.0
    while True:
        try:
            with receipt.open("ab") as handle:
                handle.write(b"tampered-receipt")
            break
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)
    with pytest.raises(InitError, match="provider receipt digest mismatch"):
        ActivationGuard(project).verify()


def test_authoritative_mutation_verification_never_uses_metadata_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, paths = _plans(tmp_path)
    context = initialize_project(_request(project, paths)).context
    verified = verify_before_mutation(project)
    assert verified.authoritative_byte_digest
    assert verified.activation_digest == context.activation_digest

    semantic = context.installed_standard / "core" / "semantic-model.json"
    os.chmod(semantic, stat.S_IWRITE | stat.S_IREAD)
    payload = semantic.read_bytes()
    semantic.write_bytes(payload[:-1] + (b" " if payload[-1:] != b" " else b"\n"))
    monkeypatch.setattr(init_runtime, "activation_read_fingerprint", lambda *_args: "cached")
    with pytest.raises(ContractError, match="Core digest mismatch"):
        verify_before_mutation(project)


def test_semantic_registry_rejects_relation_domain_mismatch() -> None:
    bundle = load_contract_bundle(PACKAGE_ROOT, PRESET)
    relation = {
        "record_type": "Relation",
        "relation_id": "relation-1",
        "kind": "READS",
        "source_type": "Decision",
        "source_id": "decision-1",
        "target_type": "Task",
        "target_id": "task-1",
        "activation_digest": "a" * 64,
        "created_at": "2026-07-17T00:00:00Z",
    }
    with pytest.raises(ContractError, match="domain or range"):
        validate_ingress(
            bundle,
            relation,
            operation="import",
            context={"activation_digest": "a" * 64},
        )


def _select_bounded_git_inventory_provider(
    project: Path, paths: dict[str, Path]
) -> None:
    git_path_value = shutil.which("git")
    if git_path_value is None:
        pytest.skip("Git executable is required for provider receipt guard tests")
    git_path = Path(git_path_value).resolve(strict=True)
    project_plan = json.loads(paths["project_plan"].read_text(encoding="utf-8"))
    project_plan["candidate_recipe"].update(
        {
            "snapshot_consistency": "immutable-vcs-tree",
            "snapshot_provider_id": "snapshot-provider",
        }
    )
    _write(paths["project_plan"], project_plan)

    provider_tree = project.parent / "bounded-git-provider-tree"
    provider_tree.mkdir()
    helper = provider_tree / "git-helper-placeholder"
    helper.write_bytes(b"bounded helper receipt")

    technologies = json.loads(paths["technologies_plan"].read_text(encoding="utf-8"))
    license_value = technologies["bindings"][0]["license"]
    snapshot_binding = {
        "capability_id": "filesystem-inventory",
        "provider_id": "snapshot-provider",
        "version": "1.0.0",
        "invocation": {"kind": "executable", "value": str(git_path)},
        "purpose": "Provide immutable candidate inventory",
        "required": False,
        "healthcheck": {
            "argv": [str(git_path), "--version"],
            "timeout_ms": 1000,
            "expected_exit": 0,
        },
        "license": license_value,
        "identity": {
            "kind": "file-digest",
            "digest": digest_file(git_path),
            "source": str(git_path),
        },
    }
    snapshot_binding["dependency_receipt"] = init_runtime.build_provider_dependency_receipt(
        snapshot_binding, project, provider_tree=provider_tree
    )
    technologies["bindings"].append(snapshot_binding)
    technologies = bind_implementation_closures(technologies, project)
    _write(paths["technologies_plan"], technologies)

    licenses = json.loads(paths["licenses_plan"].read_text(encoding="utf-8"))
    licenses["bindings"].append(
        {"provider_id": "snapshot-provider", "license": license_value}
    )
    _write(paths["licenses_plan"], licenses)


def test_verified_mutation_context_reuses_directory_provider_receipt_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, paths = _plans(tmp_path)
    _select_bounded_git_inventory_provider(project, paths)
    initialize_project(_request(project, paths))
    service = service_runtime.ProminService(project)
    expected = service._context()
    original = service_runtime.verify_before_mutation
    calls = 0

    def counted(root: Path | str) -> init_runtime.ActivationContext:
        nonlocal calls
        calls += 1
        return original(root)

    monkeypatch.setattr(service_runtime, "verify_before_mutation", counted)
    first = service._verified_mutation_context(expected)
    second = service._verified_mutation_context(expected)

    assert first.activation_digest == second.activation_digest
    assert calls == 1


def test_verified_mutation_context_invalidates_directory_provider_receipt_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, paths = _plans(tmp_path)
    _select_bounded_git_inventory_provider(project, paths)
    initialize_project(_request(project, paths))
    service = service_runtime.ProminService(project)
    expected = service._context()
    original = service_runtime.verify_before_mutation
    calls = 0

    def counted(root: Path | str) -> init_runtime.ActivationContext:
        nonlocal calls
        calls += 1
        return original(root)

    monkeypatch.setattr(service_runtime, "verify_before_mutation", counted)
    service._verified_mutation_context(expected)

    binding = next(
        item
        for item in expected.plans["technologies.json"]["bindings"]
        if item["capability_id"] == "filesystem-inventory"
    )
    component = next(
        item
        for item in binding["dependency_receipt"]["components"]
        if item["component_id"] == "git-provider-tree"
    )
    component_root = init_runtime._component_receipt_path(
        project / ".promin" / "providers", binding, component
    )
    (component_root / "unexpected-helper").write_bytes(b"unexpected")

    with pytest.raises(InitError, match="provider dependency receipt drift|provider receipt inventory"):
        service._verified_mutation_context(expected)
    assert calls == 2


def test_read_context_skips_repeated_schema_meta_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, paths = _plans(tmp_path)
    initialize_project(_request(project, paths))

    import promin.contracts as contract_runtime
    from promin.service import ProminService

    contract_runtime._bundle_cache.clear()

    def forbidden(_schema: object) -> None:
        raise AssertionError("read context repeated Draft meta-validation")

    monkeypatch.setattr(
        contract_runtime.Draft202012Validator,
        "check_schema",
        forbidden,
    )
    result = ProminService(project).status()
    assert result["record_type"] == "StatusResult"


def test_canonical_runtime_bundle_uses_resource_resolver(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Installed runtimes must load Core from the resolved bundle, not site-packages."""

    import promin.init as init_module

    bundle = tmp_path / "share" / "promin"
    shutil.copytree(PACKAGE_ROOT / "core", bundle / "core")
    shutil.copytree(PACKAGE_ROOT / "presets", bundle / "presets")
    monkeypatch.setattr(init_module, "bundle_root", lambda: bundle)
    loaded = init_module._canonical_runtime_bundle()
    assert loaded.manifest["bundle_digest"] == json.loads(
        (bundle / "core" / "promin.manifest.json").read_text(encoding="utf-8")
    )["bundle_digest"]
