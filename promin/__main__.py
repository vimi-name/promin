from __future__ import annotations

import argparse
import base64
from dataclasses import replace
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping

from . import __version__
from .audit import audit_project
from .canonical import CanonicalError, ParseLimits, canonical_bytes, digest_bytes
from .canonical import load_json_strict, parse_json_strict
from .context_index import query_context
from .client_report import ClientReportError, report_from_inspection
from .product_inspection import inspect_product, serialize_product_inspection
from .experience import (
    apply_plan,
    bind_init_capability_selection,
    emit_expert_config,
    experience_status,
    load_resolved_plan,
    next_proposal,
    resolve_plan,
    write_plan,
)
from .init_profiles import (
    InitProfileError,
    import_expert_init_bundle,
    load_init_profile,
    negotiate_language_capabilities,
    resolve_init_experience,
    resolve_init_profile,
)
from .language_catalog import languages_for_detected_technologies
from .language_catalog import load_bundled_language_catalog
from .language_tooling import (
    LanguageToolingError,
    plan_language_tool,
    probe_language_tool,
    run_language_tool,
)
from .resources import bundle_root
from .init import InitRequest, emit_canonical_init_plans, review_init_request
from .initial_project_work import (
    prepare_initial_project_work,
    preview_initial_project_work,
)
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


def _parser(*, include_public: bool = False) -> argparse.ArgumentParser:
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
    init.add_argument(
        "--init-experience",
        choices=("minimal", "expert"),
        help="guided capability UX; omitted defaults to deterministic minimal unless legacy selection flags are supplied",
    )
    init.add_argument(
        "--capability-language",
        action="append",
        default=[],
        metavar="LANGUAGE_ID",
        help="repeat one registered generic language ID for --init-experience expert",
    )
    init.add_argument(
        "--capability-selections",
        "--capability-selection-json",
        dest="capability_selections",
        type=Path,
        metavar="PATH",
        help="strict JSON object of complete registered selections for --init-experience expert",
    )
    init.add_argument("--max-preflight-files", type=int)
    init.add_argument("--apply", "--yes", dest="apply", action="store_true", help="apply the resolved plan")
    init.add_argument("--plan-only", action="store_true", help="never apply the resolved plan")
    init.add_argument("--plan-out", type=Path)
    init.add_argument(
        "--initial-work",
        choices=("none", "plan", "prepare"),
        default=None,
        help="bind bounded first-work proposal generation to this init request",
    )
    init.add_argument("--emit-expert-config", type=Path)
    init.add_argument("--expert-bundle", type=Path, help="exact expert bundle")

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
    doctor_mode.add_argument("--revalidate", type=Path, metavar="INPUT")
    doctor.add_argument("--execute-revalidation", action="store_true")

    revalidate = sub.add_parser(
        "revalidate",
        help="plan or execute a bounded evidence-first revalidation workflow",
    )
    revalidate.add_argument("--input", type=Path, required=True)
    revalidate.add_argument("--execute", action="store_true")

    status = sub.add_parser("status", help="show operational and experience state")
    status.add_argument("--watch", action="store_true")
    status.add_argument("--interval", type=float, default=2.0)
    status.add_argument("--count", type=int, default=1, help="bounded snapshots for --watch")

    next_cmd = sub.add_parser("next", help="return strict Core work or a proposal-only first card")
    next_cmd.add_argument("--subject")
    next_cmd.add_argument("--grant")
    next_cmd.add_argument("--query-grant")
    next_cmd.add_argument("--depth", type=int, choices=range(1, 13))
    next_cmd.add_argument(
        "--weak-work",
        choices=(
            "prepare",
            "review",
            "resume",
            "record",
            "pause",
            "resume-task",
            "cancel",
            "owner-decision",
            "recover-interrupted",
        ),
        help="manage a deterministic weak-worker workflow; never invokes a model",
    )
    next_cmd.add_argument("--weak-input", type=Path)
    next_cmd.add_argument("--weak-receipts", type=Path)
    next_cmd.add_argument("--weak-task-id")
    next_cmd.add_argument("--weak-outcome", type=Path)
    next_cmd.add_argument("--weak-authorize-current", action="store_true")
    next_cmd.add_argument("--weak-decision", choices=("APPROVED", "DECLINED"))
    next_cmd.add_argument("--weak-confirm-stopped", action="store_true")
    next_cmd.add_argument("--initial-work", choices=("plan", "execute"))

    validate = sub.add_parser("validate", help="validate Core and current operational state")
    validate.add_argument("--no-replay", action="store_true")

    static_admission = sub.add_parser(
        "static-admission",
        help="run bounded source/docs/portability checks without provider, build, runtime, or SQLite effects",
    )
    static_admission.add_argument("--profile", choices=("minimal", "diagnostic-host-local"), default="minimal")
    static_admission.add_argument("--handoff", type=Path)

    tooling = sub.add_parser("tooling", help="plan, probe, or run one declared language tool")
    tooling_commands = tooling.add_subparsers(dest="tooling_action", required=True)
    for action in ("plan", "probe", "run"):
        command = tooling_commands.add_parser(action)
        command.add_argument("--language", required=True)
        command.add_argument("--tool", required=True)
        command.add_argument("--action", dest="action_id", required=True)
        command.add_argument("--argument")
        if action in {"probe", "run"}:
            command.add_argument("--executable", type=Path)
            command.add_argument("--timeout-seconds", type=int, default=30)
        if action == "run":
            command.add_argument("--output-root")

    selector_shards = sub.add_parser("selector-shards", help="run or validate bounded Windows selector evidence")
    selector_commands = selector_shards.add_subparsers(dest="selector_shards_action", required=True)
    aggregate = selector_commands.add_parser("aggregate", help="execute one sequential selector aggregate")
    aggregate.add_argument("--manifest", type=Path, required=True)
    aggregate.add_argument("--candidate-binding", type=Path, required=True)
    aggregate.add_argument("--output", type=Path, required=True, metavar="EVIDENCE_ROOT")
    validate_selector = selector_commands.add_parser("validate", help="independently validate selector evidence")
    validate_selector.add_argument("--manifest", type=Path, required=True)
    validate_selector.add_argument("--candidate-binding", type=Path, required=True)
    validate_selector.add_argument("--evidence-root", type=Path, required=True)

    inspect = sub.add_parser("inspect", help="inspect product sources without operational effects")
    inspect.add_argument("--audience", choices=("client", "machine"), default="client")
    inspect.add_argument("--output", type=Path)

    report = sub.add_parser("report", help="derive a canonical client report from an inspection")
    report.add_argument("--inspection", type=Path, required=True)
    report.add_argument("--output", type=Path)

    recover = sub.add_parser("recover", help="run bounded recovery workflows")
    recover_commands = recover.add_subparsers(dest="recover_action", required=True)
    clean = recover_commands.add_parser("clean", help="prepare or apply clean recovery")
    clean.add_argument("--request", type=Path, required=True)
    clean.add_argument("--apply", action="store_true")

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


_PUBLIC_INPUT_LIMITS = ParseLimits(max_bytes=4 * 1024 * 1024, max_items=100_000)
_PUBLIC_PREFLIGHT_FILES_MAX = 1_000_000


def _load_canonical_object(path: Path, label: str) -> dict[str, Any]:
    """Load one ordinary, bounded, byte-canonical JSON object."""

    try:
        value = load_json_strict(path, root=path.parent, limits=_PUBLIC_INPUT_LIMITS)
        with path.open("rb") as stream:
            encoded = stream.read(_PUBLIC_INPUT_LIMITS.max_bytes + 1)
        if not isinstance(value, dict) or canonical_bytes(
            value, limits=_PUBLIC_INPUT_LIMITS
        ) != encoded:
            raise ServiceError(f"{label} must be one exact canonical JSON object")
        return value
    except ServiceError:
        raise
    except (CanonicalError, OSError) as exc:
        raise ServiceError(f"{label} cannot be loaded as canonical JSON") from exc


def _input_path(value: object, base: Path, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ServiceError(f"{label} must be a non-empty path")
    selected = Path(value)
    return (selected if selected.is_absolute() else base / selected).absolute()


def _require_false_claims(value: Mapping[str, Any], label: str) -> None:
    for field in ("authority_granted", "pass_credit", "acceptance_pass", "product_acceptance_pass"):
        if value.get(field) is not False:
            raise ServiceError(f"{label} {field} must remain false")


def _bounded_preflight_files(value: object, label: str) -> int:
    if type(value) is not int or not 1 <= value <= _PUBLIC_PREFLIGHT_FILES_MAX:
        raise ServiceError(f"{label} is outside 1..{_PUBLIC_PREFLIGHT_FILES_MAX}")
    return value


def _write_create_only(path: Path, payload: bytes) -> None:
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary_name, path)
    except Exception:
        raise
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass


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
    complete = all(present)
    if any(present) and not complete:
        raise ServiceError(
            "expert init requires all standard/preset/project/standards/technologies/licenses/authority paths"
        )
    if not complete and any(
        (
            args.activation_proofs is not None,
            args.emit_plan is not None,
            args.review_plan,
            args.dry_run,
        )
    ):
        raise ServiceError(
            "--activation-proofs, --emit-plan, --review-plan, and --dry-run require complete hidden expert plan inputs"
        )
    return complete


def _reject_competing_expert_bundle_options(args: argparse.Namespace) -> None:
    excluded = (
        "goal", "brief", "autonomy", "language", "profile", "documentation",
        "verification", "documentation_tool", "verification_tool",
        "init_experience", "capability_language", "capability_selections",
        "max_preflight_files", "standard_bundle", "preset", "project_plan",
        "standards_plan", "technologies_plan", "licenses_plan", "authority_plan",
        "activation_proofs", "emit_plan", "review_plan", "dry_run",
    )
    if any(getattr(args, name) not in (None, False, []) for name in excluded):
        raise ServiceError("--expert-bundle cannot be combined with configuration inputs")


def _next_initial_project_work(root: Path, *, execute: bool) -> dict[str, Any]:
    _require_initialized(root)
    plan = load_resolved_plan(root)
    if plan is None:
        raise ServiceError(
            "initialized project has no resolved plan; run promin doctor --repair"
        )
    # Resolve through the owner module so test and host integrations can bind
    # the same public owner without replacing this CLI adapter.
    from . import initial_project_work

    return initial_project_work.prepare_initial_project_work(root, plan, execute=execute)


def _initial_work_after_init(
    root: Path, plan: Mapping[str, Any], mode: str
) -> dict[str, Any] | None:
    if mode == "none":
        return None
    from . import initial_project_work

    return initial_project_work.prepare_initial_project_work(
        root, plan, execute=(mode == "prepare")
    )


def _run_expert_bundle_init(
    args: argparse.Namespace, root: Path
) -> dict[str, Any]:
    _reject_competing_expert_bundle_options(args)
    try:
        imported = import_expert_init_bundle(args.expert_bundle.absolute())
        inputs = imported["plan_inputs"]
        plan = resolve_plan(
            root,
            goal=inputs["goal"],
            autonomy=inputs["autonomy"],
            language=inputs["reporting_language"],
            explicit_profiles=tuple(inputs["profile_layers"]),
            brief=dict(inputs["brief"]),
            max_preflight_files=_bounded_preflight_files(
                inputs["max_preflight_files"], "expert bundle max_preflight_files"
            ),
        )
        if plan["profile_layers"] != inputs["profile_layers"]:
            raise ServiceError("expert bundle resolved a different profile order")
        resolved_experience = imported["resolved_experience"]
        plan = bind_init_capability_selection(
            plan, _compact_experience_capability_selection(resolved_experience)
        )
    except (InitProfileError, KeyError, TypeError, ValueError) as exc:
        raise ServiceError(f"expert init bundle is invalid: {exc}") from exc

    if args.plan_out is not None:
        write_plan(args.plan_out.resolve(), plan)
    emitted = (
        None
        if args.emit_expert_config is None
        else emit_expert_config(args.emit_expert_config.resolve(), plan, root)
    )
    bundle_record = {
        "record_type": "ImportedExpertInitBundle",
        "bundle_digest": imported["bundle_digest"],
        "plan_inputs": inputs,
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }
    if args.apply and not args.plan_only:
        result = apply_plan(root, plan)
        result["expert_init_bundle"] = bundle_record
        result["init_experience"] = resolved_experience
        if emitted is not None:
            result["expert_config"] = emitted
        return result
    return {
        "record_type": "GuidedInitReview",
        "status": "review-required",
        "resolved_plan": plan,
        "apply_command": "promin init --expert-bundle PATH --yes",
        "clarification": "Review the exact imported bundle and resolved plan before applying.",
        "expert_config": emitted,
        "expert_init_bundle": bundle_record,
        "init_experience": resolved_experience,
        "authority": False,
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }


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


def _legacy_capability_flags_present(args: argparse.Namespace) -> bool:
    return any(
        (
            args.documentation is not None,
            args.verification is not None,
            bool(args.documentation_tool),
            bool(args.verification_tool),
        )
    )


def _validate_legacy_capability_flags(args: argparse.Namespace) -> None:
    """Reject legacy tool flags that would otherwise be silently ignored."""

    if args.documentation_tool and args.documentation != "custom":
        raise ServiceError("--documentation-tool requires --documentation custom")
    if args.verification_tool and args.verification != "custom":
        raise ServiceError("--verification-tool requires --verification custom")
    if args.documentation == "custom" and not args.documentation_tool:
        raise ServiceError("--documentation custom requires at least one --documentation-tool")
    if args.verification == "custom" and not args.verification_tool:
        raise ServiceError("--verification custom requires at least one --verification-tool")


def _guided_capability_mode(args: argparse.Namespace) -> str:
    """Choose one public selection route with no implicit cross-route merge."""

    legacy_flags = _legacy_capability_flags_present(args)
    expert_controls = bool(args.capability_language) or args.capability_selections is not None
    if legacy_flags:
        _validate_legacy_capability_flags(args)

    if args.init_experience == "expert":
        if legacy_flags:
            raise ServiceError(
                "--init-experience expert cannot be combined with legacy --documentation/--verification selections"
            )
        if not args.capability_language:
            raise ServiceError("--init-experience expert requires at least one --capability-language")
        if args.capability_selections is None:
            raise ServiceError("--init-experience expert requires --capability-selections PATH")
        return "expert"

    if expert_controls:
        raise ServiceError(
            "--capability-language and --capability-selections require --init-experience expert"
        )
    if args.init_experience == "minimal":
        if legacy_flags:
            raise ServiceError(
                "--init-experience minimal cannot be combined with legacy --documentation/--verification selections"
            )
        return "minimal"
    return "legacy" if legacy_flags else "minimal"


def _registered_languages_from_detected_technologies(
    plan: Mapping[str, Any],
) -> tuple[str, ...]:
    """Delegate deterministic technology resolution to bundled catalog truth."""

    return languages_for_detected_technologies(
        str(item.get("technology", "")).casefold()
        for item in plan.get("detected_technologies", [])
        if isinstance(item, Mapping)
    )


def _load_expert_capability_selections(path: Path) -> dict[str, Any]:
    loaded = load_json_strict(path, root=path.parent)
    if not isinstance(loaded, Mapping):
        raise ServiceError("--capability-selections must contain one JSON object keyed by language ID")
    return dict(loaded)


def _compact_experience_capability_selection(
    resolved_experience: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind an H1 digest through the existing strict Core selection shape.

    The canonical ProjectInit schema intentionally owns only the compact
    selection record.  The richer public experience result remains available
    to the caller, while its digest binds every registered reference selected
    before ``apply_plan``.  Its status remains ``UNAVAILABLE`` until a separate
    host observation; generic reference selection is not tool availability.
    """

    profile = resolved_experience["profile"]
    if not isinstance(profile, Mapping):  # pragma: no cover - resolver owns this invariant
        raise InitProfileError("resolved init experience profile is invalid")
    experience = resolved_experience["experience"]
    return {
        "status": "UNAVAILABLE",
        "selection_source": "cli" if experience == "expert" else "default",
        "profile_digest": profile["profile_digest"],
        "selection_digest": resolved_experience["experience_digest"],
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
    }


def _legacy_capability_selection(
    args: argparse.Namespace,
    profile: Mapping[str, Any],
    resolved_init_profile: Mapping[str, Any],
    languages: tuple[str, ...],
) -> dict[str, Any]:
    selection = resolved_init_profile["effective"]["selection"]
    if (
        selection["documentationChoice"] == "ask"
        or selection["verificationChoice"] == "ask"
    ):
        return {
            "status": "PENDING_OWNER_SELECTION",
            "selection_source": resolved_init_profile["selection_source"],
            "profile_digest": resolved_init_profile["profile_digest"],
            "documentation_choice": selection["documentationChoice"],
            "verification_choice": selection["verificationChoice"],
            "authority_granted": False,
            "pass_credit": False,
            "acceptance_pass": False,
        }
    language_selection = negotiate_language_capabilities(
        profile["language_capability_profiles"],
        languages=languages,
        documentation_choice=selection["documentationChoice"],
        verification_choice=selection["verificationChoice"],
        selection_source=resolved_init_profile["selection_source"],
        custom_documentation=tuple(args.documentation_tool),
        custom_verification=tuple(args.verification_tool),
    )
    return {
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


def _guided_init(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    capability_mode = _guided_capability_mode(args)
    resolved_experience: dict[str, Any] | None = None
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
        max_preflight_files=_bounded_preflight_files(
            PREFLIGHT_FILE_ITEMS_MAX
            if args.max_preflight_files is None
            else args.max_preflight_files,
            "--max-preflight-files",
        ),
    )
    try:
        profile = load_init_profile(bundle_root() / "capability_profiles" / "standard-init.json")
        cli_override: dict[str, Any] = {}
        if args.autonomy is not None:
            cli_override["autonomy"] = args.autonomy
        if capability_mode == "legacy":
            requested_documentation = args.documentation or "ask"
            requested_verification = args.verification or "ask"
            cli_override["selection"] = {
                "documentationChoice": requested_documentation,
                "verificationChoice": requested_verification,
                "customProfile": "cli-custom" if "custom" in {requested_documentation, requested_verification} else None,
            }
        if capability_mode in {"minimal", "expert"}:
            languages = (
                _registered_languages_from_detected_technologies(plan)
                if capability_mode == "minimal"
                else tuple(args.capability_language)
            )
            resolved_experience = resolve_init_experience(
                profile,
                experience=capability_mode,
                languages=languages,
                cli_override=cli_override or None,
                expert_selections=(
                    _load_expert_capability_selections(args.capability_selections)
                    if capability_mode == "expert"
                    else None
                ),
                expert_source="cli" if capability_mode == "expert" else None,
            )
            compact_selection = _compact_experience_capability_selection(
                resolved_experience
            )
        else:
            resolved_init_profile = resolve_init_profile(
                profile,
                cli_override=cli_override or None,
            )
            compact_selection = _legacy_capability_selection(
                args,
                profile,
                resolved_init_profile,
                _registered_languages_from_detected_technologies(plan),
            )
        plan = bind_init_capability_selection(plan, compact_selection)
    except InitProfileError as exc:
        raise ServiceError(f"init capability selection is invalid: {exc}") from exc
    if args.plan_out:
        write_plan(args.plan_out.resolve(), plan)
    if args.emit_expert_config:
        emitted = emit_expert_config(args.emit_expert_config.resolve(), plan, root)
    else:
        emitted = None
    initial_work_mode = args.initial_work
    should_apply = (
        args.apply
        and not args.plan_only
        and initial_work_mode != "plan"
    )
    if (
        initial_work_mode is None
        and should_apply
        and args.init_experience == "minimal"
        and capability_mode == "minimal"
    ):
        initial_work_mode = "prepare"
    if should_apply:
        selection_status = plan["init_capability_selection"]["status"]
        if selection_status == "PENDING_OWNER_SELECTION":
            raise ServiceError(
                "--yes requires explicit --documentation and --verification choices; unresolved ask is fail-closed"
            )
        result = apply_plan(root, plan)
        for claim in (
            "authority",
            "authority_granted",
            "pass_credit",
            "acceptance_pass",
            "product_acceptance_pass",
        ):
            result.setdefault(claim, False)
        if emitted is not None:
            result["expert_config"] = emitted
        if resolved_experience is not None:
            result["init_experience"] = resolved_experience
        initial_work = _initial_work_after_init(root, plan, initial_work_mode or "none")
        if initial_work is not None:
            result["initial_work"] = initial_work
        return result
    if initial_work_mode == "plan":
        if _is_initialized(root):
            initial_work = _initial_work_after_init(root, plan, "plan")
        else:
            initial_work = preview_initial_project_work(root, plan)
    else:
        initial_work = None
    result = {
        "record_type": "GuidedInitReview",
        "status": "review-required",
        "resolved_plan": plan,
        "apply_command": "promin init --yes",
        "clarification": "Repeat init with --goal, --profile, --autonomy or edit emitted expert config.",
        "expert_config": emitted,
        "init_experience": resolved_experience,
        "authority": False,
        "authority_granted": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }
    if initial_work is not None:
        result["initial_work"] = initial_work
    return result


def _run_weak_work(args: argparse.Namespace) -> dict[str, Any]:
    from .weak_model_workflow import (
        WeakModelExecutionOutcome,
        cancel,
        execute,
        pause,
        prepare,
        recover_interrupted,
        resolve_owner_decision,
        resume,
        resume_task,
        review,
    )

    action = args.weak_work
    if args.weak_input is None:
        raise ServiceError("--weak-work requires --weak-input")
    record_inputs = (args.weak_task_id, args.weak_outcome)
    controls = {
        "pause": pause,
        "resume-task": resume_task,
        "cancel": cancel,
    }
    if action == "prepare" and (
        args.weak_receipts is not None
        or any(item is not None for item in record_inputs)
        or args.weak_authorize_current
        or args.weak_decision is not None
        or args.weak_confirm_stopped
    ):
        raise ServiceError("weak-work prepare accepts only --weak-input")
    if action != "prepare" and args.weak_receipts is None:
        raise ServiceError(f"weak-work {action} requires --weak-receipts")
    if action in {"review", "resume"} and (
        any(item is not None for item in record_inputs)
        or args.weak_authorize_current
        or args.weak_decision is not None
        or args.weak_confirm_stopped
    ):
        raise ServiceError(f"weak-work {action} rejects record-only inputs")
    if action == "record" and (
        any(item is None for item in record_inputs)
        or args.weak_decision is not None
        or args.weak_confirm_stopped
    ):
        raise ServiceError("weak-work record requires --weak-task-id and --weak-outcome")
    if action in controls and (
        args.weak_task_id is None
        or args.weak_outcome is not None
        or args.weak_authorize_current
        or args.weak_decision is not None
        or args.weak_confirm_stopped
    ):
        raise ServiceError(f"weak-work {action} requires only --weak-task-id")
    if action == "owner-decision" and (
        args.weak_task_id is None
        or args.weak_decision is None
        or args.weak_outcome is not None
        or args.weak_authorize_current
        or args.weak_confirm_stopped
    ):
        raise ServiceError(
            "weak-work owner-decision requires --weak-task-id and --weak-decision"
        )
    if action == "recover-interrupted" and (
        args.weak_task_id is None
        or not args.weak_confirm_stopped
        or args.weak_outcome is not None
        or args.weak_authorize_current
        or args.weak_decision is not None
    ):
        raise ServiceError(
            "weak-work recover-interrupted requires --weak-task-id and "
            "--weak-confirm-stopped"
        )

    workflow = prepare(_load_canonical_object(args.weak_input, "weak-work input"))
    if action == "prepare":
        return workflow.execution_plan_document()
    if action == "review":
        return parse_json_strict(review(workflow, args.weak_receipts).record_json)
    if action == "resume":
        return parse_json_strict(resume(workflow, args.weak_receipts).record_json)
    if action in controls:
        return controls[action](
            workflow, args.weak_receipts, task_id=args.weak_task_id
        )
    if action == "owner-decision":
        return resolve_owner_decision(
            workflow,
            args.weak_receipts,
            task_id=args.weak_task_id,
            decision=args.weak_decision,
        )
    if action == "recover-interrupted":
        return recover_interrupted(
            workflow,
            args.weak_receipts,
            task_id=args.weak_task_id,
            caller_confirms_stopped=True,
        ).record_document()

    record = _load_canonical_object(args.weak_outcome, "weak-work recorded outcome")
    _require_false_claims(record, "weak-work recorded outcome")
    if (
        record.get("schema") != "promin.weak-model-recorded-outcome.v1"
        or record.get("record_type") != "WeakModelRecordedOutcome"
        or record.get("current_authorization_confirmed") is not False
    ):
        raise ServiceError("weak-work recorded outcome identity is invalid")
    try:
        output = base64.b64decode(record["output_base64"], validate=True)
        if (
            base64.b64encode(output).decode("ascii") != record["output_base64"]
            or record["output_bytes"] != len(output)
            or record["output_sha256"] != digest_bytes(output)
        ):
            raise ValueError("output identity differs")
    except (KeyError, TypeError, ValueError) as exc:
        raise ServiceError("weak-work recorded output is invalid") from exc

    def recorded_executor(request):
        bound = (request.workflow_digest, request.receipt_set_digest, request.card.task_id, request.attempt)
        fields = ("workflow_digest", "receipt_set_digest", "task_id", "attempt")
        if tuple(record.get(field) for field in fields) != bound:
            raise ServiceError("weak-work recorded outcome is not current")
        return WeakModelExecutionOutcome(record.get("status"), output, record.get("observation"))

    receipt = execute(
        workflow,
        args.weak_receipts,
        task_id=args.weak_task_id,
        executor=recorded_executor,
        authorization_check=(lambda _request: True) if args.weak_authorize_current else None,
    )
    return receipt.record_document()


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ServiceError(f"{label} must be one JSON object")
    return dict(value)


def _revalidation_receipt(path: Path):
    from .revalidation import RevalidationReceipt
    from .revalidation_workflow import RevalidationWorkflowReceipt

    record = _load_canonical_object(path, "revalidation receipt")
    if record.get("record_type") == "RevalidationWorkflowReceipt":
        workflow_receipt = RevalidationWorkflowReceipt.from_record(record)
        if workflow_receipt.result_kind != "RevalidationReceipt":
            raise ServiceError("workflow receipt has no revalidation result")
        record = dict(workflow_receipt.result)
    return RevalidationReceipt.from_record(record)


def _revalidation_route(value: object, base: Path) -> dict[str, Any]:
    from .revalidation import RevalidationPhase, RevalidationPlan

    record = _mapping(value, "revalidation route")
    phase_values = record.get("phases")
    prior_values = record.get("prior_receipts", [])
    if not isinstance(phase_values, list):
        raise ServiceError("revalidation phases must be an array")
    if not isinstance(prior_values, list) or len(prior_values) > 16:
        raise ServiceError("prior receipts must be an array of at most 16 paths")
    return {
        "revalidation_plan": RevalidationPlan(
            plan_id=record.get("plan_id"),
            input_identity=record.get("input_identity"),
            phases=tuple(
                RevalidationPhase(**_mapping(item, "revalidation phase"))
                for item in phase_values
            ),
            total_budget_seconds=record.get("total_budget_seconds"),
        ),
        "prior_receipts": tuple(
            _revalidation_receipt(_input_path(item, base, "prior receipt"))
            for item in prior_values
        ),
        "max_phases": record.get("max_phases"),
    }


def _recorded_revalidation_callbacks(value: object, plan):
    from .revalidation import (
        ReadOnlyRevalidationCallback,
        RevalidationObservation,
        RevalidationStatus,
    )

    execution = _mapping(value, "revalidation execution")
    raw_observations = execution.get("observations")
    if (
        execution.get("kind") != "recorded-read-only-observations"
        or not isinstance(raw_observations, list)
    ):
        raise ServiceError("revalidation execution input is invalid")
    observations = {}
    for item in raw_observations:
        record = _mapping(item, "recorded revalidation observation")
        phase_id = record.get("phase_id")
        try:
            status = RevalidationStatus(record.get("status"))
        except (TypeError, ValueError) as exc:
            raise ServiceError("recorded revalidation observation is invalid") from exc
        if status is RevalidationStatus.PASS:
            raise ServiceError("recorded CLI observations cannot assert PASS")
        if not isinstance(phase_id, str) or phase_id in observations:
            raise ServiceError("recorded phase identifiers must be unique")
        observations[phase_id] = RevalidationObservation(
            status=status,
            observed_input_digest=record.get("observed_input_digest"),
            output_identity=record.get("output_identity"),
            reason=record.get("reason"),
        )
    if set(observations) != set(plan.required_phase_ids):
        raise ServiceError("recorded observations must exactly cover required phases")

    return tuple(
        ReadOnlyRevalidationCallback(
            phase_id, lambda _context, item=observations[phase_id]: item
        )
        for phase_id in plan.required_phase_ids
    )


def _run_revalidation(args: argparse.Namespace) -> dict[str, Any]:
    from .revalidation_workflow import (
        RevalidationWorkflowAuthority,
        RevalidationWorkflowMode,
        RevalidationWorkflowPlan,
        RevalidationWorkflowReceipt,
        execute_revalidation_workflow,
        plan_revalidation_workflow,
    )

    request = _load_canonical_object(args.revalidate, "revalidation input")
    _require_false_claims(request, "revalidation input")
    if (
        request.get("schema") != "promin.revalidation-cli-input.v1"
        or request.get("record_type") != "RevalidationCliInput"
    ):
        raise ServiceError("revalidation input identity is invalid")
    if not args.execute_revalidation and request.get("execution") is not None:
        raise ServiceError("plan-only revalidation cannot carry execution data")

    mode = RevalidationWorkflowMode(request.get("mode"))
    if mode is RevalidationWorkflowMode.REPAIR:
        raise ServiceError("repair execution requires the explicit public workflow API")
    route_name = "report_receipt" if mode is RevalidationWorkflowMode.REPORT else "revalidation"
    route_names = ("revalidation", "report_receipt", "repair")
    if request.get(route_name) is None or any(
        request.get(name) is not None for name in route_names if name != route_name
    ):
        raise ServiceError(f"{mode.value} carries incompatible route inputs")

    base = args.revalidate.absolute().parent
    predecessor_value = request.get("predecessor_receipt")
    predecessor = (
        None
        if predecessor_value is None
        else RevalidationWorkflowReceipt.from_record(
            _load_canonical_object(
                _input_path(predecessor_value, base, "predecessor receipt"),
                "predecessor receipt",
            )
        )
    )
    plan_values: dict[str, Any] = {
        "workflow_id": request.get("workflow_id"),
        "mode": mode,
        "authority": RevalidationWorkflowAuthority(
            **_mapping(request.get("authority"), "revalidation authority")
        ),
        "receipt_root": _input_path(
            request.get("receipt_root"), base, "revalidation receipt root"
        ),
        "receipt_name": request.get("receipt_name"),
        "retry_ordinal": request.get("retry_ordinal"),
        "predecessor_receipt": predecessor,
        "predecessor_receipt_digest": (
            None if predecessor is None else predecessor.receipt_digest
        ),
    }
    if route_name == "revalidation":
        plan_values.update(_revalidation_route(request[route_name], base))
    elif route_name == "report_receipt":
        plan_values["report_receipt"] = _revalidation_receipt(
            _input_path(request[route_name], base, "report receipt")
        )
    plan = RevalidationWorkflowPlan(**plan_values)
    if not args.execute_revalidation:
        return plan_revalidation_workflow(plan)

    execution = _mapping(request.get("execution"), "revalidation execution")
    if mode is RevalidationWorkflowMode.REVALIDATE:
        receipt = execute_revalidation_workflow(
            plan,
            callbacks=_recorded_revalidation_callbacks(execution, plan),
        )
    else:
        if execution.get("kind") != "no-callbacks":
            raise ServiceError("read-only execution input is invalid")
        receipt = execute_revalidation_workflow(plan)
    return receipt.to_record()


def _is_initialized(root: Path) -> bool:
    return (root / ".promin" / "init" / "activation.json").is_file()


def _reject_guided_options_for_full_expert_plan(args: argparse.Namespace) -> None:
    """Keep the hidden complete-plan route exclusive instead of ignoring input."""

    conflicting_options = [
        option
        for option, present in (
            ("--goal", args.goal is not None),
            ("--brief", args.brief is not None),
            ("--autonomy", args.autonomy is not None),
            ("--language", args.language is not None),
            ("--profile", bool(args.profile)),
            ("--documentation", args.documentation is not None),
            ("--verification", args.verification is not None),
            ("--documentation-tool", bool(args.documentation_tool)),
            ("--verification-tool", bool(args.verification_tool)),
            ("--init-experience", args.init_experience is not None),
            ("--capability-language", bool(args.capability_language)),
            ("--capability-selections", args.capability_selections is not None),
            ("--max-preflight-files", args.max_preflight_files is not None),
            ("--apply/--yes", args.apply),
            ("--plan-only", args.plan_only),
            ("--plan-out", args.plan_out is not None),
            ("--emit-expert-config", args.emit_expert_config is not None),
        )
        if present
    ]
    if conflicting_options:
        raise ServiceError(
            "complete expert plan input cannot be combined with guided init options: "
            + ", ".join(conflicting_options)
        )


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
    if workflow in {"status", "context", "validate", "audit", "static-admission", "tooling"}:
        return False
    if workflow == "selector-shards":
        return getattr(args, "selector_shards_action", None) == "aggregate"
    if workflow == "inspect":
        return getattr(args, "output", None) is not None
    if workflow == "report":
        return getattr(args, "output", None) is not None
    if workflow == "doctor":
        return bool(
            getattr(args, "apply_repair", False)
            or (
                getattr(args, "revalidate", None) is not None
                and getattr(args, "execute_revalidation", False)
            )
        )
    if workflow == "revalidate":
        return bool(getattr(args, "execute", False))
    if workflow == "init":
        return isinstance(result, Mapping) and result.get("record_type") in {"InitializationResult", "InitResult"}
    if workflow == "recover":
        return bool(getattr(args, "apply", False))
    if workflow == "refresh":
        return not bool(getattr(args, "plan_only", False))
    if workflow == "skills":
        return getattr(args, "skills_action", None) in {"create", "install", "remove", "sync"}
    if workflow == "next" and getattr(args, "weak_work", None) is not None:
        return getattr(args, "weak_work", None) in {
            "record",
            "pause",
            "resume-task",
            "cancel",
            "owner-decision",
            "recover-interrupted",
        }
    if workflow == "next" and getattr(args, "initial_work", None) is not None:
        return getattr(args, "initial_work", None) == "execute"
    return True


def _public_plan_boundary_disables_telemetry(args: argparse.Namespace) -> bool:
    """Keep explicit plan/read-only public routes free of hidden project writes."""

    if args.workflow in {"inspect", "report"}:
        return True
    if args.workflow == "tooling":
        return True
    if args.workflow == "selector-shards":
        return True
    if args.workflow == "recover" and getattr(args, "recover_action", None) == "clean":
        return not bool(getattr(args, "apply", False))
    if args.workflow == "doctor" and getattr(args, "revalidate", None) is not None:
        return not bool(getattr(args, "execute_revalidation", False))
    if args.workflow == "revalidate":
        return not bool(getattr(args, "execute", False))
    if args.workflow == "next" and getattr(args, "weak_work", None) is not None:
        return getattr(args, "weak_work", None) in {"prepare", "review", "resume"}
    if args.workflow == "next" and getattr(args, "initial_work", None) is not None:
        return getattr(args, "initial_work", None) == "plan"
    return False


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


def _run_public_revalidate(args: argparse.Namespace) -> dict[str, Any]:
    """Adapt the public revalidate alias to the canonical workflow runner."""

    args.revalidate = args.input
    args.execute_revalidation = bool(args.execute)
    return _run_revalidation(args)


def _strict_tool_executable(value: Path, *, root: Path, declared: str) -> Path:
    """Resolve one explicit local executable without accepting aliases or drift."""

    candidate = value if value.is_absolute() else root / value
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise ServiceError("--executable must identify an existing local file") from exc
    if not resolved.is_file() or resolved.name.casefold() != Path(declared).name.casefold():
        raise ServiceError("--executable does not match the declared tool mapping")
    if candidate.absolute() != resolved:
        raise ServiceError("--executable must be a canonical local path")
    return resolved


def _run_tooling(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    """Run one explicitly selected catalog-bound language tooling action."""

    from .language_tooling import LanguageToolPlan

    try:
        catalog = load_bundled_language_catalog(bundle_root() / "language_profiles")
        arguments = () if args.argument is None else (args.argument,)
        plan = plan_language_tool(
            catalog,
            language_id=args.language,
            tool_id=args.tool,
            action_id=args.action_id,
            root=root,
            arguments=arguments,
        )
        if args.tooling_action == "plan":
            return plan.to_record()
        if args.executable is not None:
            executable = _strict_tool_executable(args.executable, root=root, declared=plan.executable)
            plan = replace(plan, executable=str(executable), argv=(str(executable), *plan.argv[1:]))
        if not isinstance(plan, LanguageToolPlan):  # pragma: no cover
            raise ServiceError("language tooling plan is invalid")
        if args.tooling_action == "probe":
            receipt = probe_language_tool(plan, timeout_seconds=args.timeout_seconds)
        else:
            if args.output_root is not None:
                if args.tool in {"typedoc", "sphinx"}:
                    raise ServiceError(
                        f"--output-root cannot override the source-owned output root for {args.tool}"
                    )
                output_root = Path(args.output_root)
                if output_root.is_absolute() or any(part in {"", ".", ".."} for part in output_root.parts):
                    raise ServiceError("--output-root must be a bounded relative path")
                plan = replace(plan, output_roots=(str(output_root).replace("\\", "/"),))
            receipt = run_language_tool(plan, timeout_seconds=args.timeout_seconds)
        return {
            "record_type": f"LanguageTool{args.tooling_action.title()}",
            "plan": plan.to_record(),
            "receipt": receipt.to_record(),
            "claims": {
                "acceptance_pass": False,
                "pass_credit": False,
                "product_acceptance_pass": False,
                "release_approved": False,
            },
            "acceptance_pass": False,
            "pass_credit": False,
            "product_acceptance_pass": False,
            "release_approved": False,
        }
    except LanguageToolingError as exc:
        raise ServiceError(str(exc)) from exc


def _run_selector_shards(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    from .selector_shards import (
        SelectorShardError,
        load_selector_shard_manifest,
        run_selector_aggregate,
        validate_selector_aggregate_evidence,
    )

    def input_path(value: Path) -> Path:
        return (value if value.is_absolute() else root / value).absolute()

    try:
        manifest = load_selector_shard_manifest(input_path(args.manifest))
        candidate = _load_canonical_object(input_path(args.candidate_binding), "candidate binding")
        if args.selector_shards_action == "aggregate":
            result = run_selector_aggregate(
                manifest,
                project_root=root,
                evidence_root=input_path(args.output),
                candidate_binding=candidate,
            )
        else:
            result = validate_selector_aggregate_evidence(
                manifest,
                project_root=root,
                evidence_root=input_path(args.evidence_root),
                candidate_binding=candidate,
            )
        return result
    except SelectorShardError as exc:
        raise ServiceError(str(exc)) from exc


def _run(args: argparse.Namespace) -> dict[str, Any]:
    root = args.root.resolve()
    timer = OperationTimer()
    try:
        if args.workflow == "init":
            if args.apply and args.plan_only:
                raise ServiceError("--yes cannot be combined with --plan-only")
            if args.expert_bundle is not None:
                result = _run_expert_bundle_init(args, root)
            elif _expert_init_requested(args):
                _reject_guided_options_for_full_expert_plan(args)
                result = _run_expert_init(args, root)
            else:
                result = _guided_init(args, root)
        elif args.workflow == "recover":
            from .public_recovery import apply_clean_recovery, load_clean_recovery_request, plan_clean_recovery
            request_path = args.request if args.request.is_absolute() else root / args.request
            request = load_clean_recovery_request(request_path.resolve(), project_root=root)
            result = apply_clean_recovery(request, project_root=root) if args.apply else plan_clean_recovery(request, project_root=root)
        elif args.workflow == "doctor":
            if args.execute_revalidation and args.revalidate is None:
                raise ServiceError("--execute-revalidation requires --revalidate INPUT")
            if args.revalidate is not None:
                if args.no_replay:
                    raise ServiceError(
                        "--no-replay is not applicable to canonical revalidation input"
                    )
                result = _run_revalidation(args)
            elif args.checklist:
                result = run_system_check(root)
            elif args.apply_repair:
                result = repair_project(root, apply=True)
            elif args.repair:
                result = repair_project(root, apply=False)
            else:
                result = doctor_with_portability(root, replay=not args.no_replay)
        elif args.workflow == "revalidate":
            result = _run_public_revalidate(args)
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
            weak_values = (
                args.weak_input,
                args.weak_receipts,
                args.weak_task_id,
                args.weak_outcome,
                args.weak_decision,
                args.weak_authorize_current or None,
                args.weak_confirm_stopped or None,
            )
            if args.weak_work is None and any(value is not None for value in weak_values):
                raise ServiceError("weak-work inputs require --weak-work ACTION")
            if args.weak_work is not None:
                if any(strict_values) or args.depth is not None or args.initial_work is not None:
                    raise ServiceError("weak-work cannot be combined with strict Core next inputs")
                result = _run_weak_work(args)
            elif args.initial_work is not None:
                if any(strict_values) or args.depth is not None:
                    raise ServiceError("initial-work cannot be combined with strict Core next inputs")
                result = _next_initial_project_work(
                    root, execute=args.initial_work == "execute"
                )
            else:
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
        elif args.workflow == "tooling":
            result = _run_tooling(args, root)
        elif args.workflow == "selector-shards":
            result = _run_selector_shards(args, root)
        elif args.workflow == "inspect":
            inspected = inspect_product(root)
            if args.output is not None:
                output = (args.output if args.output.is_absolute() else root / args.output).absolute()
                _write_create_only(output, canonical_bytes(inspected))
            try:
                selected = parse_json_strict(
                    serialize_product_inspection(inspected, audience=args.audience).encode("utf-8"),
                    limits=_PUBLIC_INPUT_LIMITS,
                )
            except Exception as exc:
                raise ServiceError(str(exc)) from exc
            if not isinstance(selected, dict):
                raise ServiceError("inspection audience surface must be an object")
            if args.audience == "client":
                selected["effects"] = inspected["machine"]["effects"]
            result = selected
        elif args.workflow == "report":
            inspection_path = args.inspection if args.inspection.is_absolute() else root / args.inspection
            inspection = _load_canonical_object(inspection_path.absolute(), "inspection")
            try:
                result = report_from_inspection(inspection)
            except ClientReportError as exc:
                raise ServiceError(str(exc)) from exc
            if args.output is not None:
                output = (args.output if args.output.is_absolute() else root / args.output).absolute()
                _write_create_only(output, canonical_bytes(result))
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
            explicit_disabled=(
                bool(getattr(args, "no_telemetry", False))
                or _public_plan_boundary_disables_telemetry(args)
            ),
        ):
            record_observation(root, kind=f"command:{args.workflow}", status="pass", duration_ms=timer.duration_ms, details={"component": "cli"})
        return result
    except Exception as exc:
        initialized = _is_initialized(root)
        if telemetry_enabled_for_command(
            args.workflow,
            initialized=initialized,
            plan_only=not _command_mutates(args),
            explicit_disabled=(
                bool(getattr(args, "no_telemetry", False))
                or _public_plan_boundary_disables_telemetry(args)
            ),
        ):
            record_observation(root, kind=f"command:{args.workflow}", status="failed", duration_ms=timer.duration_ms, details={"component": "cli", "reason": type(exc).__name__})
        raise


def main(argv: list[str] | None = None) -> int:
    command_args = list(sys.argv[1:] if argv is None else argv)
    parser = _parser(include_public=any(item in {"inspect", "report"} for item in command_args))
    parsed: argparse.Namespace | None = None
    try:
        parsed = parser.parse_args(argv)
        result = _run(parsed)
        sys.stdout.buffer.write(canonical_bytes(result))
        if parsed.workflow == "selector-shards":
            return 0 if isinstance(result, Mapping) and result.get("status") == "PASS" else 2
        return 0
    except Exception as exc:
        root = None if parsed is None else Path(parsed.root).resolve()
        payload = {"record_type": "CommandFailure", "status": "rejected", "reason": _safe_public_reason(exc, root)}
        sys.stderr.buffer.write(canonical_bytes(payload))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
