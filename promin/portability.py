"""Portable-folder diagnostics and conservative host repair for promin alpha."""

from __future__ import annotations

import json
import os
import platform
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .canonical import digest_file, digest_value, load_json_strict
from .experience import apply_plan, load_resolved_plan, resolve_plan
from .documentation import documentation_status, sync_documentation
from .context_index import context_index_status, sync_context_index
from .host_integration import host_surface_status, sync_host_surfaces
from .gitpolicy import commit_surface_status
from .refresh import refresh_project
from .service import ProminService
from .telemetry import record_observation, utc_now


class PortabilityError(RuntimeError):
    pass


def host_binding() -> dict[str, Any]:
    executable = Path(sys.executable).resolve(strict=True)
    identity = {
        "record_type": "HostBinding",
        "system": {"windows": "windows", "darwin": "darwin", "linux": "linux"}.get(platform.system().casefold(), "other"),
        "release": platform.release(),
        "machine": platform.machine().casefold(),
        "python": platform.python_version(),
        "python_executable_digest": digest_file(executable),
        "path_separator": os.sep,
        "case_sensitive_default": os.name != "nt",
        "canonical": False,
        "rebuildable": True,
    }
    return {**identity, "host_binding_digest": digest_value(identity)}


def _host_binding_integrity(value: Mapping[str, Any] | None) -> str:
    if value is None:
        return "missing"
    stored = value.get("host_binding_digest")
    if not isinstance(stored, str):
        return "invalid"
    identity = {key: item for key, item in value.items() if key != "host_binding_digest"}
    return "valid" if stored == digest_value(identity) else "invalid"


def _load_previous(root: Path) -> dict[str, Any] | None:
    path = root / ".promin" / "host" / "host.json"
    if not path.is_file():
        return None
    value = load_json_strict(path, root=path.parent)
    return dict(value) if isinstance(value, Mapping) else None


def _host_record_integrity(value: Mapping[str, Any] | None) -> str:
    if value is None:
        return "missing"
    stored = value.get("host_binding_digest")
    identity = {key: item for key, item in value.items() if key != "host_binding_digest"}
    if not isinstance(stored, str) or stored != digest_value(identity):
        return "invalid"
    return "valid"


def _load_portable_plan(root: Path) -> dict[str, Any] | None:
    """Load the compact team brief and strip generated envelope fields."""

    path = root / ".promin" / "portable" / "project-brief.json"
    if not path.is_file() or path.is_symlink():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("record_type") != "PortableProjectBrief":
        return None
    identity = {key: item for key, item in value.items() if key != "brief_digest"}
    if value.get("brief_digest") != digest_value(identity):
        return None
    allowed = {
        "goal", "success_criteria", "constraints", "non_goals", "deliverables",
        "references", "work_sources", "autonomy", "language", "profile_overrides",
    }
    return {key: value[key] for key in allowed if key in value}


def _load_portable_team_state(root: Path) -> dict[str, Any] | None:
    path = root / ".promin" / "portable" / "team-state.json"
    if not path.is_file() or path.is_symlink():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("record_type") != "PortableTeamState":
        return None
    identity = {key: item for key, item in value.items() if key != "team_state_digest"}
    if value.get("team_state_digest") != digest_value(identity):
        return None
    return value


def _event_batches(root: Path) -> int:
    journal = root / ".promin" / "state" / "events" / "journal"
    if not journal.is_dir():
        return 0
    return sum(1 for path in journal.glob("*.json") if path.is_file() and not path.is_symlink())


def _classify_absolute_paths(root: Path) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Separate non-portable canonical values from explicit host-bound evidence.

    ``TechnologiesInit`` intentionally binds the implementation running on the
    current host.  Its dependency/implementation receipts may therefore contain
    absolute observed paths.  They are not portable project intent and are
    re-bound by ``doctor --repair`` after a host change.  Absolute paths anywhere
    else in canonical init or generated user-facing views remain blocking.
    """

    canonical_issues: list[dict[str, str]] = []
    host_specific: list[dict[str, str]] = []
    locations = [
        root / ".promin" / "init",
        root / ".promin" / "generated" / "config-view",
    ]
    files: list[Path] = []
    for directory in locations:
        if directory.is_dir() and not directory.is_symlink():
            files.extend(sorted(directory.glob("*.json"), key=lambda item: item.name.casefold()))

    def is_host_binding_location(relative_file: str, location: str) -> bool:
        # TechnologiesInit is the explicit host/provider binding. Absolute
        # executable and dependency paths are local evidence and are re-bound by
        # doctor after a host move; they are not portable project intent.
        return relative_file == "init/technologies.json" and location.startswith("$.bindings[")

    for path in files:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        relative_file = path.relative_to(root / ".promin").as_posix()
        stack: list[tuple[str, Any]] = [("$", value)]
        while stack:
            location, item = stack.pop()
            if isinstance(item, dict):
                stack.extend((f"{location}.{key}", nested) for key, nested in item.items())
            elif isinstance(item, list):
                stack.extend((f"{location}[{index}]", nested) for index, nested in enumerate(item))
            elif isinstance(item, str):
                if "://" in item or item.startswith("urn:"):
                    continue
                candidate = Path(item)
                absolute = candidate.is_absolute() or (len(item) > 2 and item[1:3] in {":\\", ":/"})
                if not absolute:
                    continue
                observation = {
                    "file": relative_file,
                    "location": location,
                    "value": item[:256],
                }
                if is_host_binding_location(relative_file, location):
                    host_specific.append(observation)
                else:
                    canonical_issues.append(observation)
    return canonical_issues, host_specific


def _absolute_path_issues(root: Path) -> list[dict[str, str]]:
    """Backward-compatible accessor for blocking canonical path violations."""

    return _classify_absolute_paths(root)[0]


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temporary, path)


def doctor_with_portability(project_root: Path | str, *, replay: bool = True) -> dict[str, Any]:
    root = Path(project_root).resolve()
    current = host_binding()
    previous = _load_previous(root)
    host_integrity = _host_record_integrity(previous)
    changed = (
        host_integrity == "valid"
        and previous is not None
        and previous.get("host_binding_digest") != current["host_binding_digest"]
    )
    host_binding_missing = previous is None and (root / ".promin").exists()
    core: dict[str, Any]
    try:
        core = ProminService(root).doctor(replay=replay)
    except Exception as exc:
        core = {"record_type": "DoctorResult", "status": "failed", "error": type(exc).__name__, "reason": str(exc)[:512]}
    issues, host_specific_paths = _classify_absolute_paths(root)
    plan = load_resolved_plan(root)
    portable_brief = _load_portable_plan(root)
    portable_team_state = _load_portable_team_state(root)
    if plan is None and portable_brief is not None:
        try:
            plan = resolve_plan(root, brief=portable_brief)
        except Exception:
            plan = None
    docs = documentation_status(root, plan)
    context = context_index_status(root, plan)
    language = "en" if plan is None else str(plan.get("reporting_language") or "en")
    hosts = host_surface_status(root, language=language)
    commit_surface = commit_surface_status(root)
    core_failed = core.get("status") in {"failed", "rejected", "error"}
    derived_stale = any(
        item.get("status") in {"stale", "missing", "blocked"}
        for item in (docs, context, hosts, commit_surface)
        if isinstance(item, Mapping)
    )
    integrity_invalid = host_integrity == "invalid"
    if integrity_invalid:
        status = "degraded"
    elif core_failed and plan is None and previous is None:
        status = "failed"
    elif changed or host_binding_missing or issues or core_failed or derived_stale:
        status = "degraded"
    else:
        status = "healthy"
    repair_available = bool(
        integrity_invalid or changed or host_binding_missing or core_failed or issues or derived_stale
    )
    return {
        "record_type": "PortableDoctorResult",
        "status": status,
        "core": core,
        "host_changed": changed,
        "host_binding_missing": host_binding_missing,
        "host_binding_integrity": host_integrity,
        "previous_host": previous,
        "current_host": current,
        "canonical_absolute_path_issues": issues,
        "host_specific_provider_paths": host_specific_paths,
        "host_specific_provider_path_count": len(host_specific_paths),
        "event_batch_count": _event_batches(root),
        "documentation": docs,
        "context_index": context,
        "host_surfaces": hosts,
        "commit_surface": commit_surface,
        "portable_plan_available": portable_brief is not None,
        "portable_team_state_available": portable_team_state is not None,
        "repair_available": repair_available,
        "repair_command": "promin doctor --repair",
        "authority": False,
        "pass_credit": False,
    }


def _brief_from_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "goal": str(plan.get("goal") or "Continue the project safely."),
        "success_criteria": list(plan.get("success_criteria", [])),
        "constraints": list(plan.get("constraints", [])),
        "non_goals": list(plan.get("non_goals", [])),
        "deliverables": list(plan.get("deliverables", [])),
        "references": list(plan.get("references", [])),
        "work_sources": list(plan.get("work_sources", [])),
        "autonomy": str(plan.get("autonomy") or "safe-auto"),
        "language": str(plan.get("reporting_language") or "auto"),
        "profile_overrides": [
            profile for profile in plan.get("profile_layers", [])
            if profile not in {"general-development", "ask", "safe-auto", "unsafe-auto", "uk", "en"}
        ],
    }


def repair_project(project_root: Path | str, *, apply: bool = False) -> dict[str, Any]:
    """Plan or apply the same bounded, reversible repair action set."""

    root = Path(project_root).resolve()
    diagnosis = doctor_with_portability(root, replay=False)
    current = diagnosis["current_host"]
    local_plan = load_resolved_plan(root)
    portable_plan = _load_portable_plan(root)
    portable_team_state = _load_portable_team_state(root)
    plan = local_plan
    if plan is None and portable_plan is not None:
        try:
            plan = resolve_plan(root, brief=portable_plan)
        except Exception:
            plan = None

    actions: list[dict[str, Any]] = []
    batches = int(diagnosis.get("event_batch_count", 0))
    canonical_issues = list(diagnosis.get("canonical_absolute_path_issues", []))
    activation_exists = (root / ".promin" / "init" / "activation.json").is_file()
    needs_rehydrate = bool(
        plan is not None
        and (
            diagnosis.get("host_changed")
            or diagnosis.get("host_binding_missing")
            or not activation_exists
        )
    )

    if plan is None:
        actions.append({"action": "guided-reinit", "status": "blocked", "reason": "resolved or portable plan is missing"})
    if canonical_issues:
        actions.append({
            "action": "remove-absolute-paths-from-canonical-init",
            "status": "blocked",
            "count": len(canonical_issues),
            "reason": "canonical paths require an explicit user correction",
        })
    if needs_rehydrate and not canonical_issues:
        actions.append({
            "action": "rehydrated-local-control-layer",
            "status": "planned",
            "event_batch_count": batches,
            "history_policy": "archive-old-state-no-silent-operational-migration",
        })
    elif plan is not None and not canonical_issues:
        if diagnosis.get("host_binding_integrity") == "invalid" or diagnosis.get("host_binding_missing"):
            actions.append({"action": "refreshed-host-binding", "status": "planned"})
        projection = root / ".promin" / "state" / "projection"
        core_status = str((diagnosis.get("core") or {}).get("status", "unknown"))
        if not projection.exists() or core_status in {"failed", "rejected", "error", "incomplete"}:
            actions.append({"action": "rebuilt-projection", "status": "planned"})
        if any(
            isinstance(diagnosis.get(key), Mapping)
            and diagnosis[key].get("status") in {"stale", "missing", "blocked"}
            for key in ("documentation", "context_index", "host_surfaces", "commit_surface")
        ):
            actions.append({"action": "refreshed-derived-surfaces", "status": "planned"})

    # De-duplicate actions while preserving diagnostic order.
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in actions:
        name = str(item["action"])
        if name not in seen:
            unique.append(item)
            seen.add(name)
    actions = unique

    performed: list[str] = []
    backup_path: str | None = None
    blocked = [item for item in actions if item.get("status") == "blocked"]
    if apply and not blocked:
        for item in actions:
            action = str(item["action"])
            try:
                if action == "rehydrated-local-control-layer":
                    assert plan is not None
                    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                    archive_root = root / ".promin-host" / "migrations" / timestamp
                    backup = archive_root / "promin-control-backup"
                    archive_root.mkdir(parents=True, exist_ok=False)
                    control = root / ".promin"
                    if control.is_dir() and not control.is_symlink():
                        archive_root.mkdir(parents=True, exist_ok=True)
                        shutil.move(str(control), str(backup))
                        backup_path = backup.relative_to(root).as_posix()
                    try:
                        refreshed_plan = resolve_plan(root, brief=_brief_from_plan(plan))
                        applied = apply_plan(root, refreshed_plan)
                        migration = {
                            "record_type": "AlphaHostRehydrate",
                            "migrated_at": utc_now(),
                            "old_host_binding_digest": (diagnosis.get("previous_host") or {}).get("host_binding_digest"),
                            "new_host_binding_digest": current["host_binding_digest"],
                            "archived_control_path": backup_path,
                            "archived_event_batch_count": batches,
                            "operational_history_migrated": False,
                            "new_activation_digest": applied.get("activation_digest"),
                            "authority": False,
                            "pass_credit": False,
                        }
                        _atomic_json(root / ".promin" / "generated" / "host-rehydrate.json", migration)
                        if portable_team_state is not None:
                            proposal_identity = {
                                "record_type": "TeamStateImportProposal",
                                "source_team_state_digest": portable_team_state.get("team_state_digest"),
                                "source_repository_content_digest": portable_team_state.get("repository_content_digest"),
                                "receiving_plan_digest": refreshed_plan.get("plan_digest"),
                                "receiving_activation_digest": applied.get("activation_digest"),
                                "latest_candidate": portable_team_state.get("latest_candidate"),
                                "active_tasks": list(portable_team_state.get("active_tasks", [])),
                                "active_findings": list(portable_team_state.get("active_findings", [])),
                                "requires_current_candidate_rebinding": True,
                                "requires_policy_validation": True,
                                "requires_authority": True,
                                "automatic_authoritative_import": False,
                                "authority": False,
                                "pass_credit": False,
                            }
                            _atomic_json(
                                root / ".promin" / "generated" / "team-import-proposal.json",
                                {**proposal_identity, "proposal_digest": digest_value(proposal_identity)},
                            )
                    except Exception:
                        if (root / ".promin").exists():
                            shutil.rmtree(root / ".promin", ignore_errors=True)
                        if backup.exists():
                            shutil.move(str(backup), str(root / ".promin"))
                        raise
                elif action == "refreshed-host-binding":
                    _atomic_json(root / ".promin" / "host" / "host.json", current)
                elif action == "rebuilt-projection":
                    ProminService(root).rebuild()
                elif action == "refreshed-derived-surfaces":
                    refresh_project(root, apply=True)
                else:
                    continue
                performed.append(action)
            except Exception as exc:
                item["status"] = "failed"
                item["reason"] = str(exc)[:512]
                break

    failed = any(item.get("status") == "failed" for item in actions)
    if blocked:
        result_status = "blocked" if apply else "planned"
    elif apply:
        result_status = "applied" if performed and not failed else "degraded" if failed else "healthy"
    else:
        result_status = "planned" if actions else "healthy"
    result = {
        "record_type": "HostRepairResult",
        "status": result_status,
        "actions": actions,
        "performed": performed,
        "backup_path": backup_path,
        "product_files_modified": False,
        "authority": False,
        "pass_credit": False,
    }
    if apply and (root / ".promin" / "init" / "activation.json").is_file():
        record_observation(
            root,
            kind="doctor-repair",
            status=result_status,
            details={"actions": len(actions), "performed": performed, "component": "portability"},
        )
    return result

