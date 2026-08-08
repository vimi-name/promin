#!/usr/bin/env python3
"""Bounded deployable-alpha checklist for promin.

This lane is intentionally small.  It verifies the first useful real-repository
workflow without running physical 100k, A/B, repeated saturation, or public
release closure.  Deferred work is reported explicitly and receives no credit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
# Executing a script from tools/ otherwise shadows the package with tools/promin.py.
sys.path = [item for item in sys.path if Path(item or ".").resolve() != Path(__file__).resolve().parent]
sys.path.insert(0, str(PACKAGE_ROOT))

from promin.audit import audit_project
from promin.context_index import query_context
from promin.experience import apply_plan, next_proposal, resolve_plan
from promin.gitpolicy import commit_footprint, git_tracking_status
from promin.host_integration import host_surface_status
from promin.portability import doctor_with_portability
from promin.refresh import refresh_project
from promin.skills import create_skill, skill_catalog
from promin.version import standard_version


class CheckFailure(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        check=False,
    )
    if completed.returncode != 0:
        raise CheckFailure(f"git {' '.join(args)} failed: {completed.stderr[:300]}")
    return completed.stdout.strip()


def _record(
    records: list[dict[str, Any]],
    *,
    check_id: str,
    category: str,
    description: str,
    required: bool,
    action: Callable[[], Any],
) -> Any:
    started = time.perf_counter()
    try:
        evidence = action()
        status = "pass"
        reason = None
    except Exception as exc:  # checklist must continue and report the full surface
        evidence = None
        status = "fail" if required else "deferred"
        reason = f"{type(exc).__name__}: {str(exc)[:1000]}"
    records.append(
        {
            "check_id": check_id,
            "category": category,
            "description": description,
            "required": required,
            "status": status,
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            "reason": reason,
            "evidence": evidence,
        }
    )
    if status == "fail":
        return None
    return evidence


def _write_fixture(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "mobile" / "app" / "src" / "main").mkdir(parents=True)
    (root / "package.json").write_text(
        json.dumps(
            {
                "name": "alpha-check",
                "dependencies": {
                    "react": "1.0.0",
                    "@supabase/supabase-js": "1.0.0",
                },
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "src" / "app.tsx").write_text("export const App = () => null;\n", encoding="utf-8")
    (root / "mobile" / "settings.gradle.kts").write_text('rootProject.name = "mobile"\n', encoding="utf-8")
    (root / "mobile" / "build.gradle.kts").write_text("plugins {}\n", encoding="utf-8")
    (root / "mobile" / "app" / "build.gradle.kts").write_text("plugins {}\n", encoding="utf-8")
    (root / "mobile" / "app" / "src" / "main" / "AndroidManifest.xml").write_text(
        "<manifest/>\n", encoding="utf-8"
    )
    (root / "README.md").write_text("# Alpha check fixture\n", encoding="utf-8")


def _product_hashes(root: Path) -> dict[str, str]:
    excluded = {".git", ".promin", ".promin-host", ".agents", ".claude", ".cursor"}
    excluded_files = {"AGENTS.md", "CLAUDE.md", ".gitignore"}
    values: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] in excluded:
            continue
        if relative.as_posix() in excluded_files:
            continue
        values[relative.as_posix()] = _sha256(path)
    return values


def _manifest_check() -> dict[str, Any]:
    manifest = json.loads((PACKAGE_ROOT / "core" / "promin.manifest.json").read_text(encoding="utf-8"))
    version = manifest.get("version")
    if version != standard_version():
        raise CheckFailure("manifest version and runtime standard version differ")
    normative_owners: list[str] = []
    generated_views: list[str] = []
    for path in PACKAGE_ROOT.rglob("*.json"):
        if any(part in {".git", "__pycache__", ".pytest_cache"} for part in path.parts):
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("version") == version:
            relative = path.relative_to(PACKAGE_ROOT).as_posix()
            if relative == "core/promin.manifest.json":
                normative_owners.append(relative)
            elif relative == "VERSION.json":
                generated_views.append(relative)
            elif value.get("record_type") in {"StandardManifest", "StandardVersion"}:
                raise CheckFailure(f"a second version owner/view is not classified: {relative}")
    if normative_owners != ["core/promin.manifest.json"]:
        raise CheckFailure("canonical version owner is missing or duplicated")
    return {"version": version, "owner": normative_owners[0], "generated_views": generated_views}


def run_checklist(*, skip_clone: bool = False) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    _record(
        records,
        check_id="ADG-001",
        category="identity",
        description="One canonical alpha version owner and consistent runtime view",
        required=True,
        action=_manifest_check,
    )

    with tempfile.TemporaryDirectory(prefix="promin-alpha-check-") as temporary:
        workspace = Path(temporary)
        source = workspace / "source"
        clone = workspace / "clone"
        source.mkdir()
        _write_fixture(source)
        _git(source, "init", "-q")
        _git(source, "config", "user.email", "promin-check@example.invalid")
        _git(source, "config", "user.name", "Promin Alpha Check")
        _git(source, "add", ".")
        _git(source, "commit", "-qm", "fixture baseline")
        product_before = _product_hashes(source)

        plan_holder: dict[str, Any] = {}

        def check_plan() -> dict[str, Any]:
            plan = resolve_plan(source, goal="Audit and evolve the combined web and mobile product", language="en")
            plan_holder["plan"] = plan
            if plan.get("question_count_before_plan") != 0:
                raise CheckFailure("guided init asked questions before the plan")
            if plan.get("preflight", {}).get("full_repository_scan") is not False:
                raise CheckFailure("guided init performed or declared a hidden full scan")
            kinds = {(unit["path"], unit["kind"]) for unit in plan["workspace_map"]["units"]}
            if (".", "web-application") not in kinds or ("mobile", "android-application") not in kinds:
                raise CheckFailure("mixed repository units were not resolved")
            return {
                "project_mode": plan["project_mode"],
                "profile_layers": plan["profile_layers"],
                "workspace_units": sorted([f"{path}:{kind}" for path, kind in kinds]),
                "question_count_before_plan": plan["question_count_before_plan"],
                "full_repository_scan": plan["preflight"]["full_repository_scan"],
            }

        _record(records, check_id="ADG-010", category="init", description="No-question-first plan and mixed-repository detection", required=True, action=check_plan)

        applied_holder: dict[str, Any] = {}

        def check_apply() -> dict[str, Any]:
            plan = plan_holder.get("plan")
            if not isinstance(plan, dict):
                raise CheckFailure("resolved plan unavailable")
            result = apply_plan(source, plan)
            applied_holder["result"] = result
            card = result.get("first_work_card")
            if not isinstance(card, dict) or card.get("record_type") != "WorkCard":
                raise CheckFailure("first bounded WorkCard was not created")
            if card.get("orchestration_required") is not True:
                raise CheckFailure("orchestration is not enforced on the first WorkCard")
            return {
                "status": result.get("status"),
                "activation_digest": result.get("activation_digest"),
                "work_card_bytes": len(json.dumps(card, ensure_ascii=False).encode("utf-8")),
                "operation_profile_id": card.get("operation_profile_id"),
                "recommended_model_tier": card.get("recommended_model_tier"),
            }

        _record(records, check_id="ADG-020", category="init", description="Atomic apply produces operational state and first WorkCard", required=True, action=check_apply)

        def check_idempotent() -> dict[str, Any]:
            result = apply_plan(source, plan_holder["plan"])
            if result.get("status") != "idempotent":
                raise CheckFailure("exact guided re-init is not idempotent")
            return {"status": result.get("status"), "plan_digest": result.get("plan_digest")}

        _record(records, check_id="ADG-021", category="init", description="Exact re-init is idempotent", required=True, action=check_idempotent)

        def check_refresh() -> dict[str, Any]:
            first = refresh_project(source)
            second = refresh_project(source)
            if second.get("status") != "current" or second.get("changed_operations") != 0:
                raise CheckFailure("hash-driven refresh is not self-stable")
            return {
                "first_status": first.get("status"),
                "second_status": second.get("status"),
                "changed_operations_second": second.get("changed_operations"),
                "changed_units_first": first.get("documentation", {}).get("changed_units", []),
            }

        _record(records, check_id="ADG-030", category="documentation", description="Hash-driven documentation refresh is incremental and stable", required=True, action=check_refresh)

        def check_context() -> dict[str, Any]:
            result = query_context(source, "Android Gradle Supabase", limit=12, max_bytes=8192)
            if result.get("result_bytes", 0) > 8192 or result.get("estimated_tokens", 0) <= 0:
                raise CheckFailure("bounded context budget is not enforced")
            return {
                "result_count": result.get("result_count"),
                "result_bytes": result.get("result_bytes"),
                "estimated_tokens": result.get("estimated_tokens"),
                "backend": result.get("backend"),
                "truncated": result.get("truncated"),
            }

        _record(records, check_id="ADG-040", category="context", description="Python context bridge returns bounded direct search results", required=True, action=check_context)

        def check_skill() -> dict[str, Any]:
            created = create_skill(
                source,
                name="alpha-review",
                description="Review the assigned alpha change",
                body="Inspect only the assigned paths and return evidence-backed findings.",
                capabilities=("review.alpha",),
            )
            refreshed = refresh_project(source)
            catalog = skill_catalog(source)
            if [item["skill_id"] for item in catalog["skills"]] != ["alpha-review"]:
                raise CheckFailure("created project skill is not discoverable")
            wrappers = [
                source / ".agents/skills/promin-alpha-review/SKILL.md",
                source / ".claude/skills/promin-alpha-review/SKILL.md",
                source / ".cursor/skills/promin-alpha-review/SKILL.md",
            ]
            if not all(path.is_file() for path in wrappers):
                raise CheckFailure("native host wrappers were not generated")
            return {
                "content_digest": created["skill"]["content_digest"],
                "catalog_count": catalog["skill_count"],
                "host_sync_status": refreshed["host_integration"]["status"],
                "authority": created["skill"]["authority"],
            }

        _record(records, check_id="ADG-050", category="skills", description="Portable skills can be created, discovered, and exposed to hosts without authority", required=True, action=check_skill)

        def check_commit() -> dict[str, Any]:
            footprint = commit_footprint(source)
            tracking = git_tracking_status(source)
            if not footprint.get("within_budget") or tracking.get("status") != "healthy":
                raise CheckFailure("portable commit surface is oversized or local state is exposed")
            return {
                "file_count": footprint["file_count"],
                "total_bytes": footprint["total_bytes"],
                "estimated_text_tokens": footprint["estimated_text_tokens"],
                "startup_instruction_tokens": footprint["startup_instruction_tokens"],
                "tracking_status": tracking["status"],
            }

        _record(records, check_id="ADG-060", category="git", description="Committed control surface is small and local databases/state are ignored", required=True, action=check_commit)

        def check_doctor_audit() -> dict[str, Any]:
            doctor = doctor_with_portability(source, replay=False)
            audit = audit_project(source, max_files=10_000, max_total_bytes=64 * 1024 * 1024)
            if doctor.get("canonical_absolute_path_issues"):
                raise CheckFailure("canonical state contains host absolute paths")
            if audit.get("pass_credit") is not False or audit.get("authority") is not False:
                raise CheckFailure("runtime audit incorrectly grants authority or pass credit")
            return {
                "doctor_status": doctor.get("status"),
                "host_specific_provider_path_count": doctor.get("host_specific_provider_path_count"),
                "audit_status": audit.get("status"),
                "finding_count": audit.get("finding_count"),
                "pass_credit": audit.get("pass_credit"),
            }

        _record(records, check_id="ADG-070", category="self-maintenance", description="Doctor and runtime audit are useful but non-authoritative", required=True, action=check_doctor_audit)

        def check_product_unchanged() -> dict[str, Any]:
            after = _product_hashes(source)
            if after != product_before:
                changed = sorted(set(product_before) ^ set(after) | {key for key in product_before.keys() & after.keys() if product_before[key] != after[key]})
                raise CheckFailure(f"product files changed during the shadow deployment: {changed[:10]}")
            return {"product_file_count": len(after), "modified": False}

        _record(records, check_id="ADG-080", category="safety", description="Shadow initialization does not mutate product files", required=True, action=check_product_unchanged)

        records.append(
            {
                "check_id": "ADG-090",
                "category": "portability",
                "description": "Owner-confirmed clean reinitialization is deliberately outside the diagnostic checklist",
                "required": False,
                "status": "deferred",
                "duration_ms": 0.0,
                "reason": (
                    "alpha.4 forbids clone rehydration/replay; clean reinitialization "
                    "requires a separately verified project package and owner confirmation"
                ),
                "evidence": {"acceptance_credit": False, "pass_credit": False},
            }
        )

        def check_hosts() -> dict[str, Any]:
            status = host_surface_status(source, language="en")
            if status.get("status") != "healthy" or not status.get("within_token_budget"):
                raise CheckFailure("native host discovery surfaces are stale or over budget")
            return {
                "status": status["status"],
                "startup_tokens": status["startup_token_estimate"],
                "skill_metadata_tokens": status["skill_metadata_token_estimate"],
                "project_skill_count": status["project_skill_count"],
            }

        _record(records, check_id="ADG-100", category="hosts", description="Codex, Claude, Cursor, and generic agent pickup stays token-bounded", required=True, action=check_hosts)

        def check_next() -> dict[str, Any]:
            result = next_proposal(source)
            card = result.get("work_card")
            if result.get("status") != "ready" or not isinstance(card, dict):
                raise CheckFailure("next did not return a ready WorkCard")
            return {
                "task_id": card.get("task_id"),
                "operation_profile_id": card.get("operation_profile_id"),
                "recommended_model_tier": card.get("recommended_model_tier"),
                "orchestration_required": card.get("orchestration_required"),
            }

        _record(records, check_id="ADG-110", category="workflow", description="The layer still returns a useful next WorkCard after maintenance", required=True, action=check_next)

    for check_id, description in (
        ("DEFER-100K", "Repeated physical 100k saturation"),
        ("DEFER-AB", "Long A/B comparison campaigns"),
        ("DEFER-MATRIX", "Full Windows/macOS/Linux performance matrix"),
        ("DEFER-RELEASE", "Stable public release evidence closure"),
    ):
        records.append(
            {
                "check_id": check_id,
                "category": "alpha-deferred",
                "description": description,
                "required": False,
                "status": "deferred",
                "duration_ms": 0.0,
                "reason": "alpha policy: not executed and no acceptance credit",
                "evidence": {"acceptance_credit": False},
            }
        )

    required = [item for item in records if item["required"]]
    failures = [item for item in required if item["status"] != "pass"]
    result = {
        "record_type": "ProminAlphaDeployableChecklistResult",
        "standard_version": standard_version(),
        "status": "pass" if not failures else "fail",
        "gate": "ADG-0",
        "required_checks": len(required),
        "required_passed": len(required) - len(failures),
        "required_failed": len(failures),
        "deferred_checks": sum(1 for item in records if item["status"] == "deferred"),
        "checks": records,
        "heavy_tests_executed": False,
        "heavy_tests_acceptance_credit": False,
        "authority": False,
        "product_acceptance_pass": False,
        "public_release_approved": False,
    }
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--skip-clone", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = run_checklist(skip_clone=bool(args.skip_clone))
    payload = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    sys.stdout.write(payload)
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
