"""Token-bounded auto-discovery surfaces for Codex, Claude and Cursor.

The repository always-on instructions remain short.  Detailed procedures and
project skills load on demand through native host mechanisms.  Promin owns only
marker-bounded files/blocks and preserves unrelated human or host content.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

from .canonical import digest_value
from .gitpolicy import estimate_tokens
from .skills import SkillError, discover_skills

_AGENTS_START = "<!-- promin:agents:start -->"
_AGENTS_END = "<!-- promin:agents:end -->"
_CLAUDE_START = "<!-- promin:claude:start -->"
_CLAUDE_END = "<!-- promin:claude:end -->"
_CURSOR_MARKER = "promin-generated-cursor-rule-v2"
_SKILL_MARKER = "promin-generated-agent-skill-v4"
_PROJECT_SKILL_MARKER = "promin-generated-project-skill-wrapper-v1"
_STATE_PATH = Path(".promin/portable/host-surfaces.json")
_STARTUP_TOKEN_BUDGET = 1400
_SKILL_METADATA_TOKEN_BUDGET = 2000


class HostIntegrationError(RuntimeError):
    pass


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    _atomic_text(path, json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def _merge(existing: str, start_marker: str, end_marker: str, block: str) -> tuple[str, bool]:
    normalized = existing.replace("\r\n", "\n").replace("\r", "\n")
    start = normalized.find(start_marker)
    end = normalized.find(end_marker)
    if (start == -1) != (end == -1):
        raise HostIntegrationError(f"incomplete managed block: {start_marker}")
    if start != -1:
        end += len(end_marker)
        before = normalized[:start].rstrip("\n")
        after = normalized[end:].lstrip("\n")
        merged = "\n\n".join(item for item in (before, block.rstrip("\n"), after) if item) + "\n"
    else:
        merged = normalized.rstrip("\n")
        if merged:
            merged += "\n\n"
        merged += block.rstrip("\n") + "\n"
    return merged, merged != normalized


def _agents_block(language: str) -> str:
    if language == "uk":
        body = """## promin

- Почни з `promin doctor`; отримуй роботу через `promin next`.
- Для деталей викликай `promin context <запит> [--unit <id>]`; не завантажуй весь repository.
- Дотримуйся Task, Candidate, allowed paths, active profile та authority. Незареєстрований результат є proposal-only.
- Один верхньорівневий promin root координує всі web/mobile/backend units із `.promin/portable/workspace-map.json`.
- Після clone або зміни host виконай `promin doctor --repair`; portable team state є proposal-only handoff.
- `promin refresh` оновлює hash-bound документацію й локальний index; `promin audit` діагностує проблеми.
- Skills переглядай через `promin skills list`; повний skill завантажуй лише коли він релевантний.
- Generated docs, telemetry та projections не є source of truth і не дають pass credit.
"""
    else:
        body = """## promin

- Start with `promin doctor`; obtain work through `promin next`.
- Retrieve details with `promin context <query> [--unit <id>]`; do not load the whole repository.
- Respect the Task, Candidate, allowed paths, active profile, and authority. Unregistered results are proposal-only.
- One top-level promin root coordinates all web/mobile/backend units in `.promin/portable/workspace-map.json`.
- After clone or a host change run `promin doctor --repair`; portable team state is a proposal-only handoff.
- `promin refresh` updates hash-bound documentation and the local index; `promin audit` diagnoses problems.
- Inspect skills with `promin skills list`; load a full skill only when it is relevant.
- Generated docs, telemetry, and projections are not a source of truth and never grant pass credit.
"""
    return f"{_AGENTS_START}\n{body.rstrip()}\n{_AGENTS_END}\n"


def _claude_block(language: str) -> str:
    note = (
        "promin використовує AGENTS.md як коротке спільне джерело; процедури й skills завантажуються лише за потреби."
        if language == "uk"
        else "promin uses AGENTS.md as the short shared source; procedures and skills load only when needed."
    )
    return f"{_CLAUDE_START}\n@AGENTS.md\n\n{note}\n{_CLAUDE_END}\n"


def _cursor_rule(language: str) -> str:
    text = (
        "Виконуй promin-цикл: doctor -> next -> bounded context -> evidence. Дотримуйся AGENTS.md; не завантажуй весь repository."
        if language == "uk"
        else "Follow the promin loop: doctor -> next -> bounded context -> evidence. Respect AGENTS.md; do not load the whole repository."
    )
    return f"""---
description: promin project operation and bounded context
alwaysApply: true
---

<!-- {_CURSOR_MARKER} -->
{text}
"""


def _core_skill(language: str, host: str) -> str:
    if language == "uk":
        description = "Керуй роботою через promin: bounded work, context, refresh, repair, skills і self-audit."
        body = """1. Виконай `promin doctor`.
2. Прочитай `.promin/portable/AGENT_ENTRY.md`.
3. Отримай Task через `promin next`.
4. Для деталей викликай `promin context <запит>`.
5. Перевір `promin skills list` і завантаж релевантний skill лише за потреби.
6. Не обходь authority й не надавай pass credit generated reports.
7. Після розподілених змін виконай `promin refresh`; за збою — `promin audit` або `promin doctor --repair`.
"""
    else:
        description = "Operate through promin: bounded work, context, refresh, repair, skills, and self-audit."
        body = """1. Run `promin doctor`.
2. Read `.promin/portable/AGENT_ENTRY.md`.
3. Obtain the Task with `promin next`.
4. Retrieve details with `promin context <query>`.
5. Inspect `promin skills list` and load a relevant skill only when needed.
6. Never bypass authority or grant pass credit to generated reports.
7. After distributed changes run `promin refresh`; after failures use `promin audit` or `promin doctor --repair`.
"""
    return f"""---
name: promin
description: {description}
license: Apache-2.0
metadata:
  promin-surface: {host}
---

# promin

<!-- {_SKILL_MARKER} -->
{body}
Detailed context is loaded on demand to minimize tokens.
"""


def _project_skill_wrapper(skill: Mapping[str, Any], host: str) -> str:
    wrapper_name = f"promin-{skill['skill_id']}"
    canonical = f".promin/portable/skills/{skill['skill_id']}"
    description = str(skill["description"])
    if len(description) > 860:
        description = description[:857] + "..."
    return f"""---
name: {wrapper_name}
description: {description}
license: {skill['license']}
compatibility: Generated {host} wrapper for a portable promin Agent Skill.
metadata:
  promin-skill-id: {skill['skill_id']}
  promin-content-digest: {skill['content_digest']}
---

# {skill['skill_id']}

<!-- {_PROJECT_SKILL_MARKER} -->
The canonical open Agent Skills package is `{canonical}/`.

1. Read `{canonical}/SKILL.md` before following the procedure.
2. Resolve scripts, references, and assets relative to `{canonical}/`.
3. Respect the current Promin Task, Grant, allowed paths, and security scope `{skill['security_scope']}`.
4. Do not treat the skill as authority and do not install network dependencies implicitly.
"""


def _write_owned(path: Path, content: str, marker: str, *, apply: bool) -> tuple[str, bool]:
    if path.exists():
        if path.is_symlink() or not path.is_file():
            return "conflict", False
        existing = path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
        if marker not in existing:
            return "conflict", False
        if existing == content:
            return "healthy", False
    if apply:
        _atomic_text(path, content)
    return "updated", True


def _base_expected(language: str) -> dict[str, str]:
    return {
        "AGENTS.md": _agents_block(language),
        "CLAUDE.md": _claude_block(language),
        ".cursor/rules/promin.mdc": _cursor_rule(language),
        ".agents/skills/promin/SKILL.md": _core_skill(language, "codex"),
        ".claude/skills/promin/SKILL.md": _core_skill(language, "claude-code"),
        ".cursor/skills/promin/SKILL.md": _core_skill(language, "cursor"),
    }


def _project_skill_expected(root: Path) -> tuple[dict[str, str], list[dict[str, Any]]]:
    try:
        skills = [item for item in discover_skills(root) if item.get("catalog_source") == "project-portable"]
    except SkillError as exc:
        raise HostIntegrationError(str(exc)) from exc
    expected: dict[str, str] = {}
    metadata: list[dict[str, Any]] = []
    for skill in skills:
        wrapper = f"promin-{skill['skill_id']}"
        for host, base in (
            ("codex", ".agents/skills"),
            ("claude", ".claude/skills"),
            ("cursor", ".cursor/skills"),
        ):
            relative = f"{base}/{wrapper}/SKILL.md"
            expected[relative] = _project_skill_wrapper(skill, host)
        metadata.append({
            "skill_id": skill["skill_id"],
            "wrapper_name": wrapper,
            "description": skill["description"],
            "content_digest": skill["content_digest"],
            "security_scope": skill["security_scope"],
        })
    return expected, metadata


def _managed_skill_paths_from_state(root: Path) -> set[str]:
    path = root / _STATE_PATH
    if not path.is_file() or path.is_symlink():
        return set()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return set()
    files = value.get("files") if isinstance(value, Mapping) else None
    if not isinstance(files, list):
        return set()
    return {
        str(item.get("path"))
        for item in files
        if isinstance(item, Mapping)
        and isinstance(item.get("path"), str)
        and _PROJECT_SKILL_MARKER in str(item.get("marker", ""))
    }


def sync_host_surfaces(project_root: Path | str, *, language: str = "en", apply: bool = True) -> dict[str, Any]:
    root = Path(project_root).resolve()
    base_expected = _base_expected(language)
    project_expected, skill_metadata = _project_skill_expected(root)
    expected = {**base_expected, **project_expected}
    changed: list[str] = []
    removed: list[str] = []
    conflicts: list[str] = []
    files: list[dict[str, Any]] = []

    for relative in ("AGENTS.md", "CLAUDE.md"):
        path = root / relative
        if path.exists() and (path.is_symlink() or not path.is_file()):
            conflicts.append(relative)
            continue
        existing = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
        start, end = (_AGENTS_START, _AGENTS_END) if relative == "AGENTS.md" else (_CLAUDE_START, _CLAUDE_END)
        try:
            merged, is_changed = _merge(existing, start, end, base_expected[relative])
        except HostIntegrationError:
            conflicts.append(relative)
            continue
        if is_changed and apply:
            _atomic_text(path, merged)
            changed.append(relative)
        effective = merged if is_changed else existing.replace("\r\n", "\n")
        files.append({
            "path": relative,
            "bytes": len(effective.encode("utf-8")),
            "managed_tokens": estimate_tokens(base_expected[relative]),
            "managed_sha256": hashlib.sha256(base_expected[relative].encode("utf-8")).hexdigest(),
            "marker": "managed-block",
        })

    markers: dict[str, str] = {
        ".cursor/rules/promin.mdc": _CURSOR_MARKER,
        ".agents/skills/promin/SKILL.md": _SKILL_MARKER,
        ".claude/skills/promin/SKILL.md": _SKILL_MARKER,
        ".cursor/skills/promin/SKILL.md": _SKILL_MARKER,
    }
    markers.update({relative: _PROJECT_SKILL_MARKER for relative in project_expected})
    for relative, marker in sorted(markers.items()):
        status, is_changed = _write_owned(root / relative, expected[relative], marker, apply=apply)
        if status == "conflict":
            conflicts.append(relative)
        elif is_changed and apply:
            changed.append(relative)
        files.append({
            "path": relative,
            "bytes": len(expected[relative].encode("utf-8")),
            "managed_tokens": estimate_tokens(expected[relative]),
            "managed_sha256": hashlib.sha256(expected[relative].encode("utf-8")).hexdigest(),
            "marker": marker,
        })

    obsolete = _managed_skill_paths_from_state(root) - set(project_expected)
    for relative in sorted(obsolete):
        path = root / relative
        if not path.is_file() or path.is_symlink():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if _PROJECT_SKILL_MARKER not in text:
            conflicts.append(relative)
            continue
        if apply:
            path.unlink()
            for parent in (path.parent, path.parent.parent):
                try:
                    parent.rmdir()
                except OSError:
                    break
            removed.append(relative)

    startup_paths = {"AGENTS.md", "CLAUDE.md", ".cursor/rules/promin.mdc"}
    startup_tokens = sum(item["managed_tokens"] for item in files if item["path"] in startup_paths)
    skill_metadata_tokens = sum(
        estimate_tokens(str(item["skill_id"]) + " " + str(item["description"]))
        for item in skill_metadata
    )
    identity = {
        "record_type": "HostSurfaceState",
        "language": language,
        "files": sorted(files, key=lambda item: item["path"]),
        "startup_token_estimate": startup_tokens,
        "startup_token_budget": _STARTUP_TOKEN_BUDGET,
        "skill_metadata_token_estimate": skill_metadata_tokens,
        "skill_metadata_token_budget": _SKILL_METADATA_TOKEN_BUDGET,
        "project_skills": skill_metadata,
        "discovery": {
            "codex": "AGENTS.md and .agents/skills; progressive skill disclosure",
            "claude": "CLAUDE.md imports AGENTS.md and .claude/skills; progressive skill disclosure",
            "cursor": ".cursor/rules plus .cursor/skills and AGENTS.md",
            "generic": ".promin/portable/AGENT_ENTRY.md and open Agent Skills packages",
        },
        "enforcement_boundary": "Host instructions and skills guide discovery; Promin authority is enforced only by Promin operations.",
        "authority": False,
        "pass_credit": False,
    }
    state = {**identity, "state_digest": digest_value(identity)}
    if apply and not conflicts:
        _atomic_json(root / _STATE_PATH, state)
    return {
        "record_type": "HostSurfaceSyncResult",
        "status": "blocked" if conflicts else "updated" if changed or removed else "healthy" if apply else "planned",
        "changed": changed,
        "removed": removed,
        "conflicts": conflicts,
        "within_token_budget": (
            startup_tokens <= _STARTUP_TOKEN_BUDGET
            and skill_metadata_tokens <= _SKILL_METADATA_TOKEN_BUDGET
        ),
        **state,
    }


def host_surface_status(project_root: Path | str, *, language: str = "en") -> dict[str, Any]:
    root = Path(project_root).resolve()
    base_expected = _base_expected(language)
    try:
        project_expected, skill_metadata = _project_skill_expected(root)
    except HostIntegrationError as exc:
        return {
            "record_type": "HostSurfaceStatus",
            "status": "blocked",
            "missing": [],
            "stale": [],
            "conflicts": [str(exc)],
            "repair_command": "promin skills sync",
            "authority": False,
            "pass_credit": False,
        }
    expected = {**base_expected, **project_expected}
    missing: list[str] = []
    stale: list[str] = []
    conflicts: list[str] = []

    for relative in ("AGENTS.md", "CLAUDE.md"):
        path = root / relative
        if not path.is_file() or path.is_symlink():
            missing.append(relative)
            continue
        text = path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
        start, end = (_AGENTS_START, _AGENTS_END) if relative == "AGENTS.md" else (_CLAUDE_START, _CLAUDE_END)
        if (start in text) != (end in text):
            conflicts.append(relative)
        elif base_expected[relative].rstrip("\n") not in text:
            stale.append(relative)

    markers: dict[str, str] = {
        ".cursor/rules/promin.mdc": _CURSOR_MARKER,
        ".agents/skills/promin/SKILL.md": _SKILL_MARKER,
        ".claude/skills/promin/SKILL.md": _SKILL_MARKER,
        ".cursor/skills/promin/SKILL.md": _SKILL_MARKER,
    }
    markers.update({relative: _PROJECT_SKILL_MARKER for relative in project_expected})
    for relative, marker in sorted(markers.items()):
        path = root / relative
        if not path.is_file() or path.is_symlink():
            missing.append(relative)
            continue
        text = path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
        if marker not in text:
            conflicts.append(relative)
        elif text != expected[relative]:
            stale.append(relative)

    obsolete = _managed_skill_paths_from_state(root) - set(project_expected)
    stale.extend(sorted(obsolete))
    startup_tokens = sum(estimate_tokens(base_expected[path]) for path in ("AGENTS.md", "CLAUDE.md", ".cursor/rules/promin.mdc"))
    skill_metadata_tokens = sum(
        estimate_tokens(str(item["skill_id"]) + " " + str(item["description"]))
        for item in skill_metadata
    )
    return {
        "record_type": "HostSurfaceStatus",
        "status": "blocked" if conflicts else "stale" if missing or stale else "healthy",
        "missing": sorted(set(missing)),
        "stale": sorted(set(stale)),
        "conflicts": sorted(set(conflicts)),
        "startup_token_estimate": startup_tokens,
        "startup_token_budget": _STARTUP_TOKEN_BUDGET,
        "skill_metadata_token_estimate": skill_metadata_tokens,
        "skill_metadata_token_budget": _SKILL_METADATA_TOKEN_BUDGET,
        "within_token_budget": (
            startup_tokens <= _STARTUP_TOKEN_BUDGET
            and skill_metadata_tokens <= _SKILL_METADATA_TOKEN_BUDGET
        ),
        "project_skill_count": len(skill_metadata),
        "repair_command": "promin doctor --repair",
        "authority": False,
        "pass_credit": False,
    }


sync_agent_integrations = sync_host_surfaces
