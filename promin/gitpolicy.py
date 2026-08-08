"""Small, portable, Git-committable Promin surface.

Only stable team intent/navigation and tiny agent-host discovery files are meant
for version control. Operational events, evidence, telemetry, provider receipts,
indexes, caches and host bindings remain local and rebuildable.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping

from .artifact_policy import (
    DEFAULT_ARTIFACT_POLICY,
    DOCS_ROOT,
    ArtifactPolicyError,
    iter_tracked_document_paths,
    iter_tracked_extension_paths,
    validate_tracked_docs,
    validate_tracked_extensions,
)
from .canonical import digest_value

_MANAGED_START = "# >>> promin managed git policy >>>"
_MANAGED_END = "# <<< promin managed git policy <<<"
_ROOT_BLOCK = """# >>> promin managed git policy >>>
# Promin keeps only bounded typed documentation in Git.
.promin-host/
# Re-open the control directory even if an older repository rule ignored it;
# .promin/.gitignore owns the detailed allow-list below this boundary.
!.promin/
!.promin/.gitignore
!.promin/docs/
!.promin/docs/**
# <<< promin managed git policy <<<
"""
_CONTROL_IGNORE = """# promin tracked documentation policy
# Ignore all operational state by default. Commit only bounded typed project
# documentation required for another developer/agent to rehydrate the layer.
*
!.gitignore
!docs/
!docs/**
"""
_POLICY_PATH = DOCS_ROOT / "commit-policy.json"
_MAX_TRACKED_TOKENS = 20_000
_MAX_STARTUP_TOKENS = 2_500


class GitPolicyError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def _merge_block(existing: str, block: str) -> tuple[str, bool]:
    normalized = existing.replace("\r\n", "\n").replace("\r", "\n")
    start = normalized.find(_MANAGED_START)
    end = normalized.find(_MANAGED_END)
    if (start == -1) != (end == -1):
        raise GitPolicyError("incomplete promin managed block in .gitignore")
    if start != -1:
        end += len(_MANAGED_END)
        before = normalized[:start].rstrip("\n")
        after = normalized[end:].lstrip("\n")
        merged = "\n\n".join(part for part in (before, block.rstrip("\n"), after) if part) + "\n"
    else:
        merged = normalized.rstrip("\n")
        if merged:
            merged += "\n\n"
        merged += block.rstrip("\n") + "\n"
    return merged, merged != normalized


def estimate_tokens(text: str) -> int:
    """Conservative language-neutral token estimate; modeled, not measured."""

    if not text:
        return 0
    cyrillic = sum(1 for character in text if "\u0400" <= character <= "\u04ff")
    divisor = 2.7 if cyrillic > len(text) * 0.15 else 3.6
    lexical = len(re.findall(r"\w+|[^\w\s]", text, flags=re.UNICODE))
    return max(1, int(max(len(text.encode("utf-8")) / divisor, lexical * 1.08) + 0.999))


def ensure_git_policy(project_root: Path | str, *, apply: bool = True) -> dict[str, Any]:
    root = Path(project_root).resolve()
    root_ignore = root / ".gitignore"
    if root_ignore.exists() and (root_ignore.is_symlink() or not root_ignore.is_file()):
        raise GitPolicyError("repository .gitignore is not a regular file")
    existing = root_ignore.read_text(encoding="utf-8", errors="replace") if root_ignore.is_file() else ""
    merged, root_changed = _merge_block(existing, _ROOT_BLOCK)

    control = root / ".promin" / ".gitignore"
    if control.exists() and (control.is_symlink() or not control.is_file()):
        raise GitPolicyError(".promin/.gitignore is not a regular file")
    control_existing = control.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n") if control.is_file() else ""
    control_changed = control_existing != _CONTROL_IGNORE

    changed: list[str] = []
    if apply:
        if root_changed:
            _atomic_text(root_ignore, merged)
            changed.append(".gitignore")
        if control_changed:
            _atomic_text(control, _CONTROL_IGNORE)
            changed.append(".promin/.gitignore")
    return {
        "record_type": "GitPolicyResult",
        "status": "updated" if changed else "healthy" if apply else "planned",
        "changed": changed,
        "tracked_roots": [
            ".promin/docs", "AGENTS.md", "CLAUDE.md", ".cursor/rules/promin.mdc",
            ".agents/skills/promin", ".claude/skills/promin",
        ],
        "local_only_roots": [
            ".promin/init", ".promin/host", ".promin/providers", ".promin/standard",
            ".promin/generated", ".promin/cache", ".promin/state", ".promin/evidence",
            ".promin/logs", ".promin/recovery",
            ".promin-host",
        ],
        "authority": False,
        "pass_credit": False,
    }


def _tracked_files(root: Path) -> Iterable[Path]:
    candidates = [
        root / ".promin" / ".gitignore",
        root / "AGENTS.md",
        root / "CLAUDE.md",
        root / ".cursor" / "rules" / "promin.mdc",
        root / ".agents" / "skills" / "promin",
        root / ".claude" / "skills" / "promin",
    ]
    seen: set[Path] = set()
    try:
        docs = tuple(iter_tracked_document_paths(root))
        extensions = tuple(iter_tracked_extension_paths(root))
    except ArtifactPolicyError as exc:
        raise GitPolicyError(str(exc)) from exc
    for path in docs:
        if path not in seen:
            seen.add(path)
            yield path
    for path in extensions:
        if path not in seen:
            seen.add(path)
            yield path
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            if candidate not in seen:
                seen.add(candidate)
                yield candidate
        elif candidate.is_dir() and not candidate.is_symlink():
            for path in sorted(candidate.rglob("*"), key=lambda item: item.as_posix().casefold()):
                if path.is_file() and not path.is_symlink() and path not in seen:
                    seen.add(path)
                    yield path


def commit_footprint(project_root: Path | str) -> dict[str, Any]:
    root = Path(project_root).resolve()
    files: list[dict[str, Any]] = []
    total_bytes = 0
    text_tokens = 0
    startup_tokens = 0
    try:
        docs_boundary = validate_tracked_docs(root)
        extensions_boundary = validate_tracked_extensions(root)
    except ArtifactPolicyError as exc:
        return {
            "record_type": "TrackedCommitFootprint",
            "file_count": 0,
            "total_bytes": 0,
            "estimated_text_tokens": 0,
            "startup_instruction_tokens": 0,
            "token_estimate_kind": "modeled-conservative",
            "budgets": {
                "tracked_documentation": DEFAULT_ARTIFACT_POLICY.tracked_budget.as_dict(),
                "tracked_text_tokens_max": _MAX_TRACKED_TOKENS,
                "startup_instruction_tokens_max": _MAX_STARTUP_TOKENS,
            },
            "within_budget": False,
            "policy_error": str(exc),
            "files": [],
            "authority": False,
            "pass_credit": False,
        }
    for path in _tracked_files(root):
        size = path.stat().st_size
        total_bytes += size
        token_estimate = 0
        if size <= DEFAULT_ARTIFACT_POLICY.tracked_budget.max_file_bytes and path.suffix.casefold() in {"", ".md", ".mdc", ".txt", ".json", ".yaml", ".yml", ".toml"}:
            text = path.read_text(encoding="utf-8", errors="replace")
            token_estimate = estimate_tokens(text)
            text_tokens += token_estimate
            if path.name in {"AGENTS.md", "CLAUDE.md", "promin.mdc"}:
                startup_tokens += token_estimate
        files.append({
            "path": path.relative_to(root).as_posix(),
            "bytes": size,
            "sha256": _sha256(path),
            "estimated_tokens": token_estimate,
        })
    return {
        "record_type": "TrackedCommitFootprint",
        "file_count": len(files),
        "total_bytes": total_bytes,
        "estimated_text_tokens": text_tokens,
        "startup_instruction_tokens": startup_tokens,
        "token_estimate_kind": "modeled-conservative",
        "budgets": {
            "tracked_documentation": DEFAULT_ARTIFACT_POLICY.tracked_budget.as_dict(),
            "tracked_text_tokens_max": _MAX_TRACKED_TOKENS,
            "startup_instruction_tokens_max": _MAX_STARTUP_TOKENS,
        },
        "within_budget": (
            docs_boundary.get("within_budget") is True
            and extensions_boundary.get("within_budget") is True
            and total_bytes <= DEFAULT_ARTIFACT_POLICY.tracked_budget.max_total_bytes
            and text_tokens <= _MAX_TRACKED_TOKENS
            and startup_tokens <= _MAX_STARTUP_TOKENS
        ),
        "files": files,
        "authority": False,
        "pass_credit": False,
    }


def _git_check_ignore(root: Path, relative: str) -> dict[str, Any]:
    if not (root / ".git").exists():
        return {"path": relative, "ignored": None, "rule": None}
    try:
        quiet = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "-q", "--", relative],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
        verbose = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "-v", "--", relative],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"path": relative, "ignored": None, "rule": "unavailable"}
    # `git check-ignore -v` returns success for a matching negation rule as well.
    # The quiet invocation reports the final ignore decision; verbose output is
    # retained only as diagnostics.
    return {
        "path": relative,
        "ignored": quiet.returncode == 0,
        "rule": verbose.stdout.strip()[:512] or None,
    }


def git_tracking_status(project_root: Path | str) -> dict[str, Any]:
    root = Path(project_root).resolve()
    tracked = (
        ".promin/docs/project-brief.json",
        ".promin/docs/AGENT_ENTRY.md",
        ".promin/docs/workspace-map.json",
        ".promin/docs/team-seed.json",
        "AGENTS.md",
        "CLAUDE.md",
        ".cursor/rules/promin.mdc",
    )
    local = (
        ".promin/state/projection/context.sqlite3",
        ".promin/cache/documentation/repository-manifest.json",
        ".promin/init/activation.json",
        ".promin/evidence/run.json",
        ".promin/logs/forensic.log",
        ".promin/recovery/backup.json",
    )
    details = [_git_check_ignore(root, relative) for relative in (*tracked, *local)]
    ignored_tracked = [item["path"] for item in details[: len(tracked)] if item.get("ignored") is True]
    exposed_local = [item["path"] for item in details[len(tracked) :] if item.get("ignored") is False]
    return {
        "record_type": "GitTrackingStatus",
        "git_detected": (root / ".git").exists(),
        "status": "blocked" if ignored_tracked or exposed_local else "healthy",
        "ignored_tracked_document_paths": ignored_tracked,
        "exposed_local_paths": exposed_local,
        "details": details,
        "authority": False,
        "pass_credit": False,
    }


def _policy_record(plan: Mapping[str, Any]) -> dict[str, Any]:
    identity = {
        "record_type": "TrackedDocumentationCommitPolicy",
        "project_id": plan.get("project_id"),
        "plan_digest": plan.get("plan_digest"),
        "mode": "minimal-tracked-documentation",
        "tracked": [
            ".promin/docs/**", "AGENTS.md", "CLAUDE.md", ".cursor/rules/promin.mdc",
            ".agents/skills/promin/**", ".claude/skills/promin/**",
        ],
        "local_rebuildable": [
            ".promin/init/**", ".promin/host/**", ".promin/providers/**",
            ".promin/standard/**", ".promin/generated/**", ".promin/cache/**",
            ".promin/state/**", ".promin/evidence/**", ".promin-host/**",
        ],
        "artifact_mode": "minimal",
        "tracked_document_budget": DEFAULT_ARTIFACT_POLICY.tracked_budget.as_dict(),
        "operational_history": "host-local; derive current work after the receiving Activation",
        "binary_database_policy": "never commit or directly edit projections; rebuild through the normative context adapter",
        "large_artifact_policy": "detailed diagnostics and forensic output are host-local and explicit-mode only",
        "authority": False,
        "pass_credit": False,
    }
    return {**identity, "policy_digest": digest_value(identity)}


def sync_commit_surface(project_root: Path | str, plan: Mapping[str, Any], *, apply: bool = True) -> dict[str, Any]:
    root = Path(project_root).resolve()
    git_policy = ensure_git_policy(root, apply=apply)
    policy = _policy_record(plan)
    policy_path = root / _POLICY_PATH
    changed: list[str] = list(git_policy.get("changed", []))
    payload = json.dumps(policy, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    existing = policy_path.read_text(encoding="utf-8", errors="replace") if policy_path.is_file() else None
    if existing != payload:
        if apply:
            _atomic_text(policy_path, payload)
        changed.append(_POLICY_PATH.as_posix())
    footprint = commit_footprint(root) if apply else None
    tracking = git_tracking_status(root) if apply else None
    blocked = bool(
        (tracking and tracking.get("status") == "blocked")
        or (footprint and not footprint.get("within_budget"))
    )
    return {
        "record_type": "CommitSurfaceSyncResult",
        "status": "blocked" if blocked else "updated" if changed else "healthy" if apply else "planned",
        "changed": changed,
        "policy_digest": policy["policy_digest"],
        "git_policy": git_policy,
        "tracking": tracking,
        "footprint": footprint,
        "authority": False,
        "pass_credit": False,
    }


def commit_surface_status(project_root: Path | str) -> dict[str, Any]:
    root = Path(project_root).resolve()
    footprint = commit_footprint(root)
    tracking = git_tracking_status(root)
    policy_present = (root / _POLICY_PATH).is_file()
    blocked = tracking.get("status") == "blocked" or not footprint.get("within_budget")
    return {
        "record_type": "CommitSurfaceStatus",
        "status": "blocked" if blocked else "stale" if not policy_present else "healthy",
        "policy_present": policy_present,
        "tracking": tracking,
        "footprint": footprint,
        "authority": False,
        "pass_credit": False,
    }
