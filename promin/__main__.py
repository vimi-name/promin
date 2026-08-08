from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Mapping

from . import __version__
from .audit import audit_project
from .canonical import canonical_bytes, load_json_strict
from .context_index import query_context
from .experience import (
    apply_plan,
    bind_init_capability_selection,
    emit_expert_config,
    experience_status,
    next_proposal,
    resolve_plan,
    write_plan,
)
from .init_profiles import (
    InitProfileError,
    load_init_profile,
    negotiate_language_capabilities,
    resolve_init_profile,
)
from .resources import bundle_root
from .init import InitRequest, emit_canonical_init_plans, review_init_request
from .limits import PREFLIGHT_FILE_ITEMS_MAX
from .portability import doctor_with_portability, repair_project
from .refresh import refresh_project
from .service import ProminService, ServiceError, continue_work, next_work
from .system_check import run_system_check
from .skills import (
    create_skill,
    install_skill,
    remove_skill,
    request_skill,
    skill_catalog,
)
from .telemetry import OperationTimer, heartbeat, record_observation, telemetry_enabled_for_command


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="promin")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="project root")
    parser.add_argument("--version", action="version", version=f"promin {__version__}")
    parser.add_argument("--no-telemetry", action="store_true", help="do not persist local operational observations")
    sub = parser.add_subparsers(dest="workflow", required=True)

    init = sub.add_parser("init", help="resolve and optionally apply a guided initialization plan")
    init.add_argument("--goal")
    init.add_argument("--brief", type=Path, help="optional simple JSON project brief")
    init.add_argument("--autonomy", choices=("ask", "standing-reversible"))
    init.add_argument("--language", choices=("auto", "uk", "en"))
    init.add_argument("--profile", action="append", default=[], help="additional installed profile layer")
    init.add_argument("--documentation", choices=("accept", "decline", "custom"))
    init.add_argument("--verification", choices=("accept", "decline", "custom"))
    init.add_argument("--documentation-tool", action="append", default=[])
    init.add_argument("--verification-tool", action="append", default=[])
    init.add_argument("--max-preflight-files", type=int, default=PREFLIGHT_FILE_ITEMS_MAX)
    init.add_argument("--apply", "--yes", dest="apply", action="store_true", help="apply the resolved plan")
    init.add_argument("--plan-only", action="store_true", help="never apply the resolved plan")
    init.add_argument("--plan-out", type=Path)
    init.add_argument("--emit-expert-config", type=Path)

    # Strict expert/compatibility path. These options are intentionally hidden
    # from the ordinary workflow but preserve full explicit configuration.
    init.add_argument("--standard-bundle", type=Path)
    init.add_argument("--preset", type=Path)
    init.add_argument("--project-plan", type=Path)
    init.add_argument("--standards-plan", type=Path)
    init.add_argument("--technologies-plan", type=Path)
    init.add_argument("--licenses-plan", type=Path)
    init.add_argument("--authority-plan", type=Path)
    init.add_argument("--activation-proofs", type=Path)
    init.add_argument("--emit-plan", type=Path, metavar="DIRECTORY")
    init.add_argument("--review-plan", action="store_true")
    init.add_argument("--dry-run", action="store_true")

    doctor = sub.add_parser("doctor", help="diagnose Core and host portability")
    doctor.add_argument("--no-replay", action="store_true")
    doctor_mode = doctor.add_mutually_exclusive_group()
    doctor_mode.add_argument("--repair", action="store_true", help="plan reversible portability repair")
    doctor_mode.add_argument("--apply-repair", action="store_true", help="apply reversible repair")
    doctor_mode.add_argument("--checklist", action="store_true", help="run the bounded whole-system alpha checklist")

    status = sub.add_parser("status", help="show operational and experience state")
    status.add_argument("--watch", action="store_true")
    status.add_argument("--interval", type=float, default=2.0)
    status.add_argument("--count", type=int, default=1, help="bounded snapshots for --watch")

    next_cmd = sub.add_parser("next", help="return strict Core work or a proposal-only first card")
    next_cmd.add_argument("--subject")
    next_cmd.add_argument("--grant")
    next_cmd.add_argument("--query-grant")
    next_cmd.add_argument("--depth", type=int, choices=range(1, 13))

    validate = sub.add_parser("validate", help="validate Core and current operational state")
    validate.add_argument("--no-replay", action="store_true")

    static_admission = sub.add_parser(
        "static-admission",
        help="run bounded source/docs/portability checks without provider, build, runtime, or SQLite effects",
    )
    static_admission.add_argument("--profile", choices=("minimal", "diagnostic-host-local"), default="minimal")
    static_admission.add_argument("--handoff", type=Path)

    continuation = sub.add_parser("continue", help="continue a bounded WorkCard context")
    continuation.add_argument("token")
    continuation.add_argument("--subject")
    continuation.add_argument("--grant")

    audit = sub.add_parser("audit", help="audit promin operation and repository health")
    audit.add_argument("--since", default=None, help="period such as 24h, 30m, 7d")
    audit.add_argument("--plan", action="store_true", help="include a non-authoritative repair PlanProposal")
    audit.add_argument("--live", action="store_true", help="emit one bounded live audit and heartbeat")
    audit.add_argument("--record", action="store_true", help="persist the bounded audit result and telemetry")
    audit.add_argument("--max-files", type=int, default=10_000)
    audit.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024)

    refresh = sub.add_parser("refresh", help="refresh tracked documentation, context, and host surfaces")
    refresh.add_argument("--deep-context", action="store_true")
    refresh.add_argument("--plan-only", action="store_true", help="show the refresh plan without writing")
    refresh.add_argument("--reset-derived", action="store_true", help="rebuild ignored projections and caches before refresh")

    context = sub.add_parser("context", help="query the bounded local project context index")
    context.add_argument("query", nargs="?", default="")
    context.add_argument("--unit")
    context.add_argument("--limit", type=int, default=12)
    context.add_argument("--max-bytes", type=int, default=8192)

    skills = sub.add_parser("skills", help="discover, request, create, install, remove, or sync skills")
    skill_commands = skills.add_subparsers(dest="skills_action", required=True)
    skill_commands.add_parser("list", help="list managed and host-provided skills")
    skill_request = skill_commands.add_parser("request", help="match a requirement to installed skills")
    skill_request.add_argument("requirement")
    skill_create = skill_commands.add_parser("create", help="create a project skill")
    skill_create.add_argument("name")
    skill_create.add_argument("--description", required=True)
    skill_create.add_argument("--instructions-file", type=Path, required=True)
    skill_create.add_argument("--version", default="0.1.0")
    skill_create.add_argument("--license", dest="license_id", default="Apache-2.0")
    skill_create.add_argument("--capability", action="append", default=[])
    skill_create.add_argument("--host", action="append", default=[])
    skill_create.add_argument("--platform", action="append", default=[])
    skill_create.add_argument("--required-tool", action="append", default=[])
    skill_create.add_argument("--security-scope", choices=("read-only", "project-write", "host-local"), default="read-only")
    skill_create.add_argument("--local", action="store_true", help="store under host-local .promin/skills")
    skill_install = skill_commands.add_parser("install", help="install a local or explicit hash-pinned HTTPS skill")
    skill_install.add_argument("source")
    skill_install.add_argument("--sha256")
    skill_install.add_argument("--allow-network", action="store_true")
    skill_install.add_argument("--license", dest="expected_license")
    skill_install.add_argument("--local", action="store_true")
    skill_remove = skill_commands.add_parser("remove", help="remove one managed skill")
    skill_remove.add_argument("name")
    skill_remove.add_argument("--local", action="store_true")
    skill_commands.add_parser("sync", help="refresh native host wrappers and context surfaces")
    return parser


def _period_seconds(value: str | None) -> int | None:
    if value is None:
        return None
    text = value.strip().casefold()
    if not text:
        return None
    unit = text[-1]
    try:
        amount = int(text[:-1]) if unit in "smhd" else int(text)
    except ValueError as exc:
        raise ServiceError("--since must be an integer optionally followed by s/m/h/d") from exc
    if amount < 0:
        raise ServiceError("--since must be non-negative")
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(unit, 1)
    return amount * multiplier


def _expert_init_requested(args: argparse.Namespace) -> bool:
    values = (
        args.standard_bundle,
        args.preset,
        args.project_plan,
        args.standards_plan,
        args.technologies_plan,
        args.licenses_plan,
        args.authority_plan,
    )
    present = [value is not None for value in values]
    if any(present) and not all(present):
        raise ServiceError("expert init requires all standard/preset/project/standards/technologies/licenses/authority paths")
    return all(present)


def _run_expert_init(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    if args.emit_plan is not None:
        if args.activation_proofs is not None:
            raise ServiceError("--emit-plan does not emit Activation proofs")
        explicit_records = {
            "project_plan": load_json_strict(args.project_plan, root=args.project_plan.parent),
            "standards_plan": load_json_strict(args.standards_plan, root=args.standards_plan.parent),
            "technologies_plan": load_json_strict(args.technologies_plan, root=args.technologies_plan.parent),
            "licenses_plan": load_json_strict(args.licenses_plan, root=args.licenses_plan.parent),
            "authority_plan": load_json_strict(args.authority_plan, root=args.authority_plan.parent),
        }
        return emit_canonical_init_plans(
            args.emit_plan.resolve(),
            project_root=root,
            standard_bundle=args.standard_bundle.resolve(),
            preset_path=args.preset.resolve(),
            **explicit_records,
        )
    proofs = None
    if args.activation_proofs:
        proofs = load_json_strict(args.activation_proofs, root=args.activation_proofs.parent)
        if not isinstance(proofs, list):
            raise ServiceError("activation proofs file must contain a JSON array")
    request = InitRequest(
        project_root=root,
        standard_bundle=args.standard_bundle.resolve(),
        preset_path=args.preset.resolve(),
        project_plan=args.project_plan.resolve(),
        standards_plan=args.standards_plan.resolve(),
        technologies_plan=args.technologies_plan.resolve(),
        licenses_plan=args.licenses_plan.resolve(),
        authority_plan=args.authority_plan.resolve(),
        activation_proofs=proofs,
    )
    if args.review_plan or args.dry_run:
        return review_init_request(request, run_preflight=args.dry_run)
    return ProminService(root).initialize(request)


def _guided_init(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    brief = None
    if args.brief is not None:
        loaded = load_json_strict(args.brief, root=args.brief.parent)
        if not isinstance(loaded, dict):
            raise ServiceError("--brief must contain one JSON object")
        brief = loaded
    plan = resolve_plan(
        root,
        goal=args.goal,
        autonomy=args.autonomy,
        language=args.language,
        explicit_profiles=tuple(args.profile),
        brief=brief,
        max_preflight_files=args.max_preflight_files,
    )
    try:
        profile = load_init_profile(bundle_root() / "capability_profiles" / "standard-init.json")
        cli_override: dict[str, Any] = {}
        if args.autonomy is not None:
            cli_override["autonomy"] = args.autonomy
        requested_documentation = args.documentation or "ask"
        requested_verification = args.verification or "ask"
        if args.documentation is not None or args.verification is not None:
            cli_override["selection"] = {
                "documentationChoice": requested_documentation,
                "verificationChoice": requested_verification,
                "customProfile": "cli-custom" if "custom" in {requested_documentation, requested_verification} else None,
            }
        resolved_init_profile = resolve_init_profile(
            profile,
            cli_override=cli_override or None,
        )
        tech_ids = {str(item.get("technology", "")) for item in plan.get("detected_technologies", []) if isinstance(item, Mapping)}
        languages = [language for language in ("c", "cpp") if {"cpp", "cmake"} & tech_ids]
        selection = resolved_init_profile["effective"]["selection"]
        if selection["documentationChoice"] == "ask" or selection["verificationChoice"] == "ask":
            compact_selection: dict[str, Any] = {
                "status": "PENDING_OWNER_SELECTION",
                "selection_source": resolved_init_profile["selection_source"],
                "profile_digest": resolved_init_profile["profile_digest"],
                "documentation_choice": selection["documentationChoice"],
                "verification_choice": selection["verificationChoice"],
                "authority_granted": False,
                "pass_credit": False,
                "acceptance_pass": False,
            }
        else:
            language_selection = negotiate_language_capabilities(
                profile["language_capability_profiles"],
                languages=languages,
                documentation_choice=selection["documentationChoice"],
                verification_choice=selection["verificationChoice"],
                selection_source=resolved_init_profile["selection_source"],
                custom_documentation=tuple(args.documentation_tool),
                custom_verification=tuple(args.verification_tool),
            )
            compact_selection = {
                "status": language_selection["status"],
                "selection_source": resolved_init_profile["selection_source"],
                "profile_digest": resolved_init_profile["profile_digest"],
                "selection_digest": language_selection["selection_digest"],
                "documentation_choice": selection["documentationChoice"],
                "verification_choice": selection["verificationChoice"],
                "authority_granted": False,
                "pass_credit": False,
                "acceptance_pass": False,
            }
        plan = bind_init_capability_selection(plan, compact_selection)
    except InitProfileError as exc:
        raise ServiceError(f"init capability selection is invalid: {exc}") from exc
    if args.plan_out:
        write_plan(args.plan_out.resolve(), plan)
    if args.emit_expert_config:
        emitted = emit_expert_config(args.emit_expert_config.resolve(), plan, root)
    else:
        emitted = None
    should_apply = args.apply and not args.plan_only
    if should_apply:
        selection_status = plan["init_capability_selection"]["status"]
        if selection_status == "PENDING_OWNER_SELECTION":
            raise ServiceError(
                "--yes requires explicit --documentation and --verification choices; unresolved ask is fail-closed"
            )
        result = apply_plan(root, plan)
        if emitted is not None:
            result["expert_config"] = emitted
        return result
    return {
        "record_type": "GuidedInitReview",
        "status": "review-required",
        "resolved_plan": plan,
        "apply_command": "promin init --yes",
        "clarification": "Repeat init with --goal, --profile, --autonomy or edit emitted expert config.",
        "expert_config": emitted,
        "authority": False,
        "pass_credit": False,
    }


def _is_initialized(root: Path) -> bool:
    return (root / ".promin" / "init" / "activation.json").is_file()


def _require_initialized(root: Path) -> None:
    if not _is_initialized(root):
        raise ServiceError("project is not initialized; run promin init")


def _status(root: Path) -> dict[str, Any]:
    experience = experience_status(root)
    try:
        diagnosis = doctor_with_portability(root, replay=False)
        core = diagnosis.get("core", diagnosis)
        core_status = str(core.get("status", "unknown"))
    except Exception as exc:
        diagnosis = {"record_type": "PortableDoctorResult", "status": "failed", "reason": str(exc)[:512]}
        core = diagnosis
        core_status = "failed"
    initialized = bool(experience.get("initialized"))
    if initialized and core_status in {"healthy", "incomplete"} and not diagnosis.get("host_changed"):
        status = "ready" if core_status == "healthy" else "ready-for-inventory"
    else:
        status = "degraded" if initialized else "not-initialized"
    return {
        "record_type": "ProminStatus",
        "status": status,
        "experience": experience,
        "core": core,
        "portability": {
            "status": diagnosis.get("status"),
            "host_changed": diagnosis.get("host_changed", False),
            "repair_available": diagnosis.get("repair_available", False),
        },
        "heartbeat": heartbeat(root),
        "authority": False,
        "pass_credit": False,
    }


def _command_mutates(args: argparse.Namespace, result: Mapping[str, Any] | None = None) -> bool:
    """Return whether this invocation may intentionally persist project-local state."""

    workflow = args.workflow
    if workflow in {"status", "context", "validate", "audit", "static-admission"}:
        return False
    if workflow == "doctor":
        return bool(getattr(args, "apply_repair", False))
    if workflow == "init":
        return isinstance(result, Mapping) and result.get("record_type") in {"InitializationResult", "InitResult"}
    if workflow == "refresh":
        return not bool(getattr(args, "plan_only", False))
    if workflow == "skills":
        return getattr(args, "skills_action", None) in {"create", "install", "remove", "sync"}
    return True


def _safe_public_reason(exc: Exception, root: Path | None = None) -> str:
    text = str(exc) or type(exc).__name__
    candidates = [Path.cwd(), Path.home()]
    if root is not None:
        candidates.insert(0, root)
    for candidate in candidates:
        for spelling in {str(candidate), str(candidate).replace("\\", "/")}:
            if spelling:
                text = text.replace(spelling, "<project>")
    return text[:2048]


def _run(args: argparse.Namespace) -> dict[str, Any]:
    root = args.root.resolve()
    timer = OperationTimer()
    try:
        if args.workflow == "init":
            result = _run_expert_init(args, root) if _expert_init_requested(args) else _guided_init(args, root)
        elif args.workflow == "doctor":
            if args.checklist:
                result = run_system_check(root)
            elif args.apply_repair:
                result = repair_project(root, apply=True)
            elif args.repair:
                result = repair_project(root, apply=False)
            else:
                result = doctor_with_portability(root, replay=not args.no_replay)
        elif args.workflow == "status":
            if not _is_initialized(root):
                result = {
                    "record_type": "ProminStatus",
                    "status": "not-initialized",
                    "remedy": "run promin init",
                    "authority": False,
                    "pass_credit": False,
                }
                snapshots = None
            else:
                snapshots = []
            if snapshots is not None:
                count = max(1, min(args.count, 100)) if args.watch else 1
                for index in range(count):
                    snapshots.append(_status(root))
                    if index + 1 < count:
                        time.sleep(max(0.1, min(args.interval, 60.0)))
                result = snapshots[0] if len(snapshots) == 1 else {"record_type": "StatusWatch", "snapshots": snapshots}
        elif args.workflow == "next":
            strict_values = (args.subject, args.grant, args.query_grant)
            if any(strict_values) and not all(strict_values):
                raise ServiceError("strict next requires --subject, --grant and --query-grant together")
            result = (
                next_work(root, subject_id=args.subject, grant_id=args.grant, query_grant_id=args.query_grant, depth=args.depth)
                if all(strict_values)
                else next_proposal(root)
            )
        elif args.workflow == "validate":
            _require_initialized(root)
            result = ProminService(root).validate(replay=not args.no_replay)
        elif args.workflow == "continue":
            if (args.subject is None) != (args.grant is None):
                raise ServiceError("continue requires --subject and --grant together")
            subject = args.subject
            grant = args.grant
            if not isinstance(subject, str) or not isinstance(grant, str):
                raise ServiceError("continue requires an explicit current Grant; alpha.4 has no guided bootstrap grant")
            result = continue_work(root, args.token, subject_id=subject, grant_id=grant)
        elif args.workflow == "audit":
            result = audit_project(
                root,
                since_seconds=_period_seconds(args.since),
                build_plan=args.plan,
                max_files=max(1, min(args.max_files, 1_000_000)),
                max_total_bytes=max(1, min(args.max_bytes, 8 * 1024 * 1024 * 1024)),
                persist=args.record,
            )
            if args.live:
                result["heartbeat"] = heartbeat(root)
        elif args.workflow == "refresh":
            result = refresh_project(
                root,
                deep_context=args.deep_context,
                apply=not args.plan_only,
                reset_derived=args.reset_derived,
            )
        elif args.workflow == "context":
            _require_initialized(root)
            result = query_context(
                root,
                args.query,
                unit_id=args.unit,
                limit=args.limit,
                max_bytes=args.max_bytes,
            )
        elif args.workflow == "static-admission":
            handoff = None
            if args.handoff is not None:
                loaded_handoff = load_json_strict(args.handoff, root=args.handoff.parent)
                if not isinstance(loaded_handoff, dict):
                    raise ServiceError("--handoff must contain one JSON object")
                handoff = loaded_handoff
            # Import only at the explicit command boundary.  The implementation
            # is source-only and its focused tests spy on provider/build/runtime
            # and SQLite surfaces to keep this operation side-effect free.
            from .static_admission import run_static_admission

            result = run_static_admission(root, profile=args.profile, handoff=handoff)
        elif args.workflow == "skills":
            if args.skills_action == "list":
                result = skill_catalog(root)
            elif args.skills_action == "request":
                result = request_skill(root, requirement=args.requirement)
            elif args.skills_action == "create":
                body = args.instructions_file.read_text(encoding="utf-8")
                result = create_skill(
                    root,
                    name=args.name,
                    description=args.description,
                    body=body,
                    version=args.version,
                    license_id=args.license_id,
                    capabilities=tuple(args.capability),
                    hosts=tuple(args.host) or ("generic", "codex", "claude", "cursor", "local"),
                    platforms=tuple(args.platform) or ("windows", "macos", "linux"),
                    required_tools=tuple(args.required_tool),
                    security_scope=args.security_scope,
                    portable=not args.local,
                )
            elif args.skills_action == "install":
                result = install_skill(
                    root,
                    source=args.source,
                    expected_sha256=args.sha256,
                    allow_network=args.allow_network,
                    portable=not args.local,
                    expected_license=args.expected_license,
                )
            elif args.skills_action == "remove":
                result = remove_skill(root, name=args.name, portable=not args.local)
            elif args.skills_action == "sync":
                result = refresh_project(root, apply=True)
            else:  # pragma: no cover - argparse enforces the action set
                raise ServiceError(f"unsupported skills action: {args.skills_action}")
        else:
            raise ServiceError(f"unsupported base workflow: {args.workflow}")
        initialized = _is_initialized(root)
        if telemetry_enabled_for_command(
            args.workflow,
            initialized=initialized,
            plan_only=not _command_mutates(args, result),
            explicit_disabled=bool(getattr(args, "no_telemetry", False)),
        ):
            record_observation(root, kind=f"command:{args.workflow}", status="pass", duration_ms=timer.duration_ms, details={"component": "cli"})
        return result
    except Exception as exc:
        initialized = _is_initialized(root)
        if telemetry_enabled_for_command(
            args.workflow,
            initialized=initialized,
            plan_only=not _command_mutates(args),
            explicit_disabled=bool(getattr(args, "no_telemetry", False)),
        ):
            record_observation(root, kind=f"command:{args.workflow}", status="failed", duration_ms=timer.duration_ms, details={"component": "cli", "reason": type(exc).__name__})
        raise


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    parsed: argparse.Namespace | None = None
    try:
        parsed = parser.parse_args(argv)
        result = _run(parsed)
        sys.stdout.buffer.write(canonical_bytes(result))
        return 0
    except Exception as exc:
        root = None if parsed is None else Path(parsed.root).resolve()
        payload = {"record_type": "CommandFailure", "status": "rejected", "reason": _safe_public_reason(exc, root)}
        sys.stderr.buffer.write(canonical_bytes(payload))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
