"""Bounded whole-system readiness checklist for promin alpha.

The checklist verifies one deployed project without running expensive scale or
release campaigns.  It intentionally reports deferred heavy tests instead of
turning them into implicit passes.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping

from . import __version__
from .canonical import canonical_bytes
from .context_index import context_index_status
from .documentation import documentation_status
from .experience import DEFAULT_PRESET, PACKAGE_ROOT, compile_core_plans, experience_status, load_bootstrap_state, load_resolved_plan, resolve_plan
from .gitpolicy import commit_footprint, git_tracking_status
from .host_integration import host_surface_status
from .portability import doctor_with_portability
from .init import InitRequest
from .service import ProminService
from .resources import bundle_root
from .skills import SkillError, skill_catalog
from .telemetry import heartbeat


class SystemCheckError(RuntimeError):
    pass


def _check(
    check_id: str,
    surface: str,
    status: str,
    summary: str,
    evidence: Mapping[str, Any] | None = None,
    remediation: str | None = None,
) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "surface": surface,
        "status": status,
        "summary": summary,
        "evidence": dict(evidence or {}),
        "remediation": remediation,
    }


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file() or path.is_symlink():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None




_REMEDIATION_COMMANDS = (
    "promin init",
    "promin doctor --repair",
    "promin doctor --apply-repair",
    "promin refresh",
    "promin refresh --reset-derived",
    "promin audit",
    "promin skills list",
)

def remediation_commands() -> tuple[str, ...]:
    return _REMEDIATION_COMMANDS

def _sandbox_init_check() -> dict[str, Any]:
    """Exercise the real canonical init boundary without bootstrapping work state.

    This catches path, schema, provider-health and atomic-install failures while
    keeping the whole-system checklist bounded.  Operational bootstrap is
    covered by the deployed-project checks below.
    """

    previous = os.environ.get("PROMIN_NO_TELEMETRY")
    os.environ["PROMIN_NO_TELEMETRY"] = "1"
    try:
        with tempfile.TemporaryDirectory(prefix="promin-check-init-") as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            for index in range(10):
                (root / "src" / f"f{index}.py").write_text("value = 1\n", encoding="utf-8")
            plan = resolve_plan(root, goal="Bounded self-check initialization")
            plans = compile_core_plans(plan, root)
            staging = root / ".promin-check-plans"
            staging.mkdir()
            for name, value in plans.items():
                (staging / name).write_text(
                    json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )
            request = InitRequest(
                project_root=root,
                standard_bundle=PACKAGE_ROOT,
                preset_path=DEFAULT_PRESET,
                project_plan=staging / "project.json",
                standards_plan=staging / "standards.json",
                technologies_plan=staging / "technologies.json",
                licenses_plan=staging / "licenses.json",
                authority_plan=staging / "authority.json",
            )
            result = ProminService(root).initialize(request)
            return {
                "record_type": result.get("record_type"),
                "status": result.get("status"),
                "question_count_before_plan": plan.get("question_count_before_plan"),
                "product_tree_scans_before_plan": 0,
            }
    finally:
        if previous is None:
            os.environ.pop("PROMIN_NO_TELEMETRY", None)
        else:
            os.environ["PROMIN_NO_TELEMETRY"] = previous


def run_system_check(project_root: Path | str) -> dict[str, Any]:
    root = Path(project_root).resolve()
    if not root.is_dir() or root.is_symlink():
        raise SystemCheckError("project root must be a real directory")

    checks: list[dict[str, Any]] = []
    package = bundle_root()
    manifest = _load_json(package / "core" / "promin.manifest.json") or {}
    version_ok = manifest.get("canonical_name") == "promin" and manifest.get("version") == __version__
    checks.append(_check(
        "SYS-ID-001", "identity", "pass" if version_ok else "fail",
        "Canonical name and single version owner are consistent." if version_ok else "Canonical identity or version is inconsistent.",
        {"runtime_version": __version__, "manifest_version": manifest.get("version"), "canonical_name": manifest.get("canonical_name")},
        "Regenerate package/version projections from core/promin.manifest.json.",
    ))

    core_files = {
        "promin.manifest.json", "semantic-model.json", "authority-model.json",
        "policy-set.json", "contracts.schema.json", "conformance.json",
    }
    actual_core = {
        path.name for path in (package / "core").iterdir()
        if path.is_file() and not path.is_symlink()
    } if (package / "core").is_dir() else set()
    checks.append(_check(
        "SYS-CORE-001", "core", "pass" if actual_core == core_files else "fail",
        "Exactly six Core artifacts are present." if actual_core == core_files else "Core artifact inventory differs from the minimal contract.",
        {"actual": sorted(actual_core), "expected": sorted(core_files)},
        "Restore the exact six-artifact Core and regenerate derived schema/docs.",
    ))

    try:
        sandbox = _sandbox_init_check()
        sandbox_ok = sandbox.get("record_type") in {"InitializationResult", "InitResult"} and sandbox.get("status") in {"created", "idempotent"}
    except Exception as exc:
        sandbox = {"record_type": "SandboxInitCheck", "status": "failed", "reason": f"{type(exc).__name__}: {str(exc)[:256]}"}
        sandbox_ok = False
    checks.append(_check(
        "SYS-INIT-PATH-001", "initialization-path", "pass" if sandbox_ok else "fail",
        "A bounded clean initialization path succeeds on this host." if sandbox_ok else "The host cannot complete a bounded clean initialization path.",
        sandbox,
        "Fix the initialization path before trusting persisted-state checks.",
    ))

    plan = load_resolved_plan(root)
    initialized = (root / ".promin" / "init" / "activation.json").is_file()
    checks.append(_check(
        "SYS-INIT-001", "initialization", "pass" if initialized and plan else "fail",
        "Canonical initialization and resolved plan exist." if initialized and plan else "Project is not fully initialized.",
        {"initialized": initialized, "plan_present": plan is not None},
        "Run `promin init`, review the resolved plan, then apply it.",
    ))

    if plan is not None:
        no_questions = int(plan.get("question_count_before_plan", -1)) == 0
        preflight = plan.get("preflight", {}) if isinstance(plan.get("preflight"), Mapping) else {}
        no_hidden_scan = preflight.get("full_repository_scan") is False
        checks.append(_check(
            "SYS-UX-001", "guided-init", "pass" if no_questions and no_hidden_scan else "fail",
            "No-question-first plan resolution and zero hidden full scan are enforced." if no_questions and no_hidden_scan else "Guided init violates the simplicity contract.",
            {"question_count_before_plan": plan.get("question_count_before_plan"), "full_repository_scan": preflight.get("full_repository_scan")},
            "Resolve inferable values automatically and keep inventory as an explicit operation.",
        ))
        mode = plan.get("project_mode")
        workspace = plan.get("workspace_map", {}) if isinstance(plan.get("workspace_map"), Mapping) else {}
        units = workspace.get("units", []) if isinstance(workspace.get("units"), list) else []
        checks.append(_check(
            "SYS-WORKSPACE-001", "workspace", "pass" if mode in {"greenfield", "existing-code", "hybrid"} and units else "warn",
            "Project mode and top-level semantic units are resolved." if units else "Workspace units are not yet resolved or the project is empty.",
            {"project_mode": mode, "unit_count": len(units), "unit_ids": [item.get("unit_id") for item in units[:32] if isinstance(item, Mapping)]},
            "Run `promin refresh` after project files appear; one top-level control layer must own all units.",
        ))
        profiles = plan.get("profile_layers", []) if isinstance(plan.get("profile_layers"), list) else []
        checks.append(_check(
            "SYS-PROFILE-001", "profiles", "pass" if "general-development" in profiles and any(item in profiles for item in ("morok-tower-studio", "web-application", "android-application", "windows-development")) else "warn",
            "A general layer and at least one domain/fallback profile are active.",
            {"profile_layers": profiles, "autonomy": plan.get("autonomy"), "reporting_language": plan.get("reporting_language")},
            "Review detected facts or explicitly select a trusted profile; profile changes must not expand authority.",
        ))

    bootstrap = load_bootstrap_state(root)
    first_card = None if bootstrap is None else bootstrap.get("first_work_card")
    grants = {} if bootstrap is None else bootstrap.get("grants", {})
    orchestration_ok = (
        isinstance(first_card, Mapping)
        and first_card.get("record_type") == "WorkCard"
        and first_card.get("orchestration_required") is True
        and isinstance(grants, Mapping)
        and bool(grants)
    )
    checks.append(_check(
        "SYS-ORCH-001", "orchestration", "pass" if orchestration_ok else "fail",
        "The first Task, scoped Grants and bounded WorkCard are operational." if orchestration_ok else "Orchestration exists only partially or no real WorkCard is available.",
        {
            "bootstrap_present": bootstrap is not None,
            "grant_count": len(grants) if isinstance(grants, Mapping) else 0,
            "work_card_type": first_card.get("record_type") if isinstance(first_card, Mapping) else None,
            "operation_profile_id": first_card.get("operation_profile_id") if isinstance(first_card, Mapping) else None,
            "recommended_model_tier": first_card.get("recommended_model_tier") if isinstance(first_card, Mapping) else None,
        },
        "Run `promin doctor --repair`; authoritative agent work must enter through Task/Candidate/Grant/WorkCard contracts.",
    ))

    model_tiers = {"tool-only", "micro", "standard", "strong", "critical-review", "weak-local", "capable"}
    card_bytes = len(canonical_bytes(first_card)) if isinstance(first_card, Mapping) else 0
    model_route_ok = (
        isinstance(first_card, Mapping)
        and isinstance(first_card.get("operation_profile_id"), str)
        and first_card.get("recommended_model_tier") in model_tiers
        and card_bytes <= 16 * 1024
    )
    checks.append(_check(
        "SYS-MODEL-001", "model-routing", "pass" if model_route_ok else "fail",
        "The first operation is routed to a declared minimal model tier inside a bounded WorkCard." if model_route_ok else "The first operation lacks a valid model route or exceeds the WorkCard byte budget.",
        {
            "operation_profile_id": first_card.get("operation_profile_id") if isinstance(first_card, Mapping) else None,
            "recommended_model_tier": first_card.get("recommended_model_tier") if isinstance(first_card, Mapping) else None,
            "work_card_bytes": card_bytes,
            "work_card_bytes_max": 16 * 1024,
        },
        "Resolve an operation profile and route deterministic/mechanical work to the cheapest adequate tier.",
    ))

    diagnosis: dict[str, Any]
    try:
        diagnosis = doctor_with_portability(root, replay=False)
    except Exception as exc:
        diagnosis = {"status": "failed", "reason": f"{type(exc).__name__}: {str(exc)[:512]}"}
    canonical_paths = diagnosis.get("canonical_absolute_path_issues", []) if isinstance(diagnosis, Mapping) else []
    portability_ok = not canonical_paths and diagnosis.get("host_changed") is not True
    checks.append(_check(
        "SYS-PORT-001", "portability", "pass" if portability_ok else "fail",
        "Canonical state is host-neutral and the current host binding is valid." if portability_ok else "Canonical host paths or a stale host binding block portability.",
        {"canonical_absolute_path_issues": len(canonical_paths), "host_changed": diagnosis.get("host_changed"), "host_binding_missing": diagnosis.get("host_binding_missing")},
        "Move host-specific values to derived state and run `promin doctor --repair`.",
    ))

    docs = documentation_status(root, plan)
    context = context_index_status(root, plan)
    hosts = host_surface_status(root, language=str((plan or {}).get("reporting_language") or "en"))
    checks.append(_check(
        "SYS-DOC-001", "documentation", "pass" if docs.get("status") == "current" else "warn",
        "Hash-bound short documentation is current." if docs.get("status") == "current" else "Documentation is missing or stale.",
        {"status": docs.get("status"), "changed_units": docs.get("changed_units")},
        "Run `promin refresh`; only invalidated semantic units should update.",
    ))
    checks.append(_check(
        "SYS-CTX-001", "context", "pass" if context.get("status") == "current" and int(context.get("bytes", 0)) <= 32 * 1024 * 1024 else "warn",
        "The local bounded context index is current and within its alpha size budget." if context.get("status") == "current" else "The local context index is stale or absent.",
        {"status": context.get("status"), "backend": context.get("backend"), "record_count": context.get("record_count"), "bytes": context.get("bytes")},
        "Run `promin refresh --reset-derived`; do not commit the rebuildable database.",
    ))
    checks.append(_check(
        "SYS-HOST-001", "agent-hosts", "pass" if hosts.get("status") == "healthy" else "warn" if hosts.get("status") == "stale" else "fail",
        "Codex, Claude and Cursor discovery surfaces are synchronized." if hosts.get("status") == "healthy" else "Agent-host pickup surfaces need synchronization or contain conflicts.",
        {"status": hosts.get("status"), "startup_token_estimate": hosts.get("startup_token_estimate"), "conflicts": hosts.get("conflicts", [])},
        "Run `promin refresh` or resolve files that Promin does not own.",
    ))

    try:
        catalog = skill_catalog(root)
        skill_status = "fail" if catalog.get("host_conflicting_skill_ids") else "pass"
    except SkillError as exc:
        catalog = {"status": "blocked", "reason": str(exc), "skills": [], "host_skills": []}
        skill_status = "fail"
    checks.append(_check(
        "SYS-SKILL-001", "skills", skill_status,
        "Managed and host-provided skills are discoverable without granting authority." if skill_status == "pass" else "Skill identities conflict or a managed skill is invalid.",
        {"managed_count": len(catalog.get("skills", [])), "host_count": len(catalog.get("host_skills", [])), "host_conflicts": catalog.get("host_conflicting_skill_ids", []), "host_scan_truncated": catalog.get("host_scan_truncated")},
        "Resolve duplicate skill IDs, or explicitly adopt/create/install a digest- and license-bound skill.",
    ))

    try:
        footprint = commit_footprint(root)
        tracking = git_tracking_status(root)
        git_ok = footprint.get("within_budget") is True and tracking.get("status") == "healthy"
    except Exception as exc:
        footprint = {"error": type(exc).__name__, "reason": str(exc)[:512]}
        tracking = {}
        git_ok = False
    checks.append(_check(
        "SYS-GIT-001", "git-handoff", "pass" if git_ok else "fail",
        "Only the compact portable handoff is intended for Git." if git_ok else "Git tracking or portable footprint violates the handoff budget.",
        {"total_bytes": footprint.get("total_bytes"), "estimated_text_tokens": footprint.get("estimated_text_tokens"), "startup_instruction_tokens": footprint.get("startup_instruction_tokens"), "tracking_status": tracking.get("status")},
        "Run `promin refresh`; keep events, databases, caches, evidence and host paths ignored.",
    ))

    host_tokens = int(hosts.get("startup_token_estimate", 0) or 0)
    portable_bytes = int(footprint.get("total_bytes", 0) or 0)
    context_bytes = int(context.get("bytes", 0) or 0)
    cost_ok = (
        host_tokens <= 1_400
        and portable_bytes <= 2 * 1024 * 1024
        and context_bytes <= 32 * 1024 * 1024
        and card_bytes <= 16 * 1024
    )
    checks.append(_check(
        "SYS-COST-001", "cost-and-context", "pass" if cost_ok else "fail",
        "Startup, portable Git, WorkCard, and local index stay inside explicit alpha budgets." if cost_ok else "One or more context/resource surfaces exceed the explicit alpha budgets.",
        {
            "startup_instruction_tokens": host_tokens,
            "startup_instruction_tokens_max": 1_400,
            "portable_bytes": portable_bytes,
            "portable_bytes_max": 2 * 1024 * 1024,
            "work_card_bytes": card_bytes,
            "work_card_bytes_max": 16 * 1024,
            "context_index_bytes": context_bytes,
            "context_index_bytes_max": 32 * 1024 * 1024,
            "token_estimate_kind": "modeled-conservative",
        },
        "Reduce always-loaded instructions or portable/index payloads; keep detail behind bounded context queries.",
    ))

    license_path = package / "LICENSE"
    notices_path = package / "THIRD_PARTY_NOTICES.md"
    open_ok = license_path.is_file() and notices_path.is_file() and "Apache License" in license_path.read_text(encoding="utf-8", errors="replace")
    checks.append(_check(
        "SYS-OPEN-001", "open-technology", "pass" if open_ok else "fail",
        "The distribution declares an open commercial-use license and third-party notice surface." if open_ok else "License or third-party notice surface is missing or inconsistent.",
        {"license_present": license_path.is_file(), "third_party_notices_present": notices_path.is_file(), "declared_license": "Apache-2.0" if open_ok else None},
        "Restore LICENSE and THIRD_PARTY_NOTICES.md; reject skills/providers with unknown licenses.",
    ))

    hb = heartbeat(root)
    telemetry_ok = hb.get("record_type") == "ProminHeartbeat" and hb.get("authority") is False
    checks.append(_check(
        "SYS-AUDIT-001", "self-audit", "pass" if telemetry_ok else "warn",
        "Heartbeat and local self-observation are available without authority." if telemetry_ok else "Heartbeat/self-audit state is unavailable.",
        {"heartbeat_status": hb.get("status"), "active_fingerprints": hb.get("active_fingerprints"), "human_decision_required": hb.get("human_decision_required")},
        "Run `promin audit`; telemetry must remain local, bounded and redacted by default.",
    ))

    checks.append(_check(
        "SYS-TEST-001", "alpha-testing", "deferred",
        "Expensive repeated 100k/A-B/saturation campaigns are explicitly deferred for this alpha.",
        {"status": "alpha_deferred", "acceptance_credit": False},
        "Run focused/static/scenario/portability lanes now; execute heavy closure before stable release.",
    ))

    failures = [item for item in checks if item["status"] == "fail"]
    warnings = [item for item in checks if item["status"] == "warn"]
    result_status = "fail" if failures else "degraded" if warnings else "pass"
    return {
        "record_type": "ProminSystemChecklist",
        "status": result_status,
        "project_root": str(root),
        "check_count": len(checks),
        "pass_count": sum(1 for item in checks if item["status"] == "pass"),
        "warn_count": len(warnings),
        "fail_count": len(failures),
        "deferred_count": sum(1 for item in checks if item["status"] == "deferred"),
        "checks": checks,
        "next_action": (
            failures[0].get("remediation") if failures else warnings[0].get("remediation") if warnings else "promin next"
        ),
        "authority": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
        "public_release_approved": False,
    }
