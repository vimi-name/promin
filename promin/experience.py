"""Low-friction alpha experience layer for promin.

This module turns repository facts and a short goal into a reviewable plan and
compiles that plan into the strict existing Core initialization records.  The
experience layer never bypasses Core authority; it only removes manual setup.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import unicodedata
from functools import lru_cache
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .canonical import atomic_write_json, digest_file, digest_value, load_json_strict
from .audit import duplicate_name_markers
from .contracts import load_contract_bundle, validate_definition
from .version import standard_version
from .init import (
    InitRequest,
    bind_implementation_closures,
    build_provider_dependency_receipt,
)
from .service import ProminService, ServiceError
from .resources import bundle_root
from .platform_paths import (
    filesystem_path,
    resolve_identity_path,
    resolved_temporary_directory,
    windows_extended_path,
)
from .provider_store import ensure_blob
from .limits import PREFLIGHT_FILE_ITEMS_MAX
from .skills import discover_skills
from .telemetry import heartbeat, record_observation, utc_now
from .workspace import discover_workspace_map

PACKAGE_ROOT = bundle_root()
PROFILE_ROOT = PACKAGE_ROOT / "profiles"
DEFAULT_PRESET = PACKAGE_ROOT / "presets" / "semantic-morok-tower.json"

_PREFLIGHT_MAX_FILES = PREFLIGHT_FILE_ITEMS_MAX
_PREFLIGHT_MAX_BYTES = 2 * 1024 * 1024
_PREFLIGHT_MAX_DEPTH = 2
_TEXT_SAMPLE_MAX = 64 * 1024
_IGNORED_DIRS = {
    ".git",
    ".promin",
    ".idea",
    ".vscode",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "target",
    "coverage",
    "vendor",
    "__pycache__",
}
_MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lockb",
    "pyproject.toml",
    "requirements.txt",
    "poetry.lock",
    "uv.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "go.sum",
    "CMakeLists.txt",
    "CMakePresets.json",
    "settings.gradle",
    "settings.gradle.kts",
    "build.gradle",
    "build.gradle.kts",
    "gradlew",
    "AndroidManifest.xml",
    "tsconfig.json",
    "vite.config.js",
    "vite.config.ts",
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "supabase.toml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile",
    "Makefile",
    "README.md",
    "README_UA.md",
    "AGENTS.md",
    "CLAUDE.md",
    "CONTRIBUTING.md",
    "ROADMAP.md",
    "BACKLOG.md",
}
_SOURCE_SUFFIXES = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".kt",
    ".kts",
    ".cpp",
    ".cxx",
    ".cc",
    ".c",
    ".h",
    ".hpp",
    ".cs",
    ".rs",
    ".go",
    ".swift",
    ".dart",
    ".vue",
    ".svelte",
}


class ExperienceError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def _alpha_budgets() -> dict[str, Any]:
    value = json.loads((PACKAGE_ROOT / "core" / "conformance.json").read_text(encoding="utf-8"))
    budgets = value.get("structural_budgets")
    if not isinstance(budgets, dict):
        raise ExperienceError("Core conformance structural budgets are unavailable")
    return dict(budgets)


def _technology_source_limit() -> int:
    value = _alpha_budgets().get("technology_source_items_max")
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ExperienceError("technology source budget is invalid")
    return value


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _safe_id(value: str, fallback: str = "project") -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    normalized = re.sub(r"[^A-Za-z0-9._:-]+", "-", normalized).strip("-._:")
    if not normalized:
        normalized = fallback
    if not normalized[0].isalnum():
        normalized = "p-" + normalized
    return normalized[:96]


def _run_git(root: Path, *args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=2.5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def _read_sample(path: Path, remaining: int) -> tuple[str, int]:
    if remaining <= 0:
        return "", 0
    try:
        if path.is_symlink() or not path.is_file():
            return "", 0
        amount = min(_TEXT_SAMPLE_MAX, remaining, path.stat().st_size)
        payload = path.read_bytes()[:amount]
        return payload.decode("utf-8", errors="replace"), len(payload)
    except OSError:
        return "", 0


def bounded_preflight(
    project_root: Path | str,
    *,
    max_files: int = _PREFLIGHT_MAX_FILES,
    max_bytes: int = _PREFLIGHT_MAX_BYTES,
    max_depth: int = _PREFLIGHT_MAX_DEPTH,
) -> dict[str, Any]:
    """Inspect bounded metadata without a hidden full repository scan."""

    root = Path(project_root).resolve()
    if not root.is_dir() or root.is_symlink():
        raise ExperienceError("project root must be a real directory")
    queue: list[tuple[Path, int]] = [(root, 0)]
    entries: list[dict[str, Any]] = []
    manifests: dict[str, str] = {}
    bytes_read = 0
    truncated = False
    while queue and len(entries) < max_files:
        directory, depth = queue.pop(0)
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
        except OSError:
            continue
        for child in children:
            if len(entries) >= max_files:
                truncated = True
                break
            name = child.name
            if name in _IGNORED_DIRS:
                continue
            try:
                relative = Path(child.path).relative_to(root).as_posix()
            except ValueError:
                continue
            try:
                if child.is_symlink():
                    entries.append({"path": relative, "kind": "symlink"})
                    continue
                if child.is_dir(follow_symlinks=False):
                    entries.append({"path": relative, "kind": "directory"})
                    if depth < max_depth:
                        queue.append((Path(child.path), depth + 1))
                    continue
                if not child.is_file(follow_symlinks=False):
                    continue
                stat_value = child.stat(follow_symlinks=False)
            except OSError:
                continue
            suffix = Path(name).suffix.casefold()
            entries.append(
                {
                    "path": relative,
                    "kind": "file",
                    "size_bytes": stat_value.st_size,
                    "suffix": suffix,
                }
            )
            if name in _MANIFEST_NAMES or suffix in {".json", ".toml", ".yaml", ".yml"} and depth <= 1:
                sample, used = _read_sample(Path(child.path), max_bytes - bytes_read)
                bytes_read += used
                if sample:
                    manifests[relative] = sample
        if len(entries) >= max_files:
            truncated = True
            break
    git_root = _run_git(root, "rev-parse", "--show-toplevel")
    git_head = _run_git(root, "rev-parse", "HEAD")
    git_branch = _run_git(root, "branch", "--show-current")
    git_status = _run_git(root, "status", "--porcelain=v1")
    result = {
        "record_type": "BoundedRepositoryPreflight",
        "root_name": root.name,
        "entry_count": len(entries),
        "bytes_read": bytes_read,
        "max_files": max_files,
        "max_bytes": max_bytes,
        "max_depth": max_depth,
        "truncated": truncated,
        "full_repository_scan": False,
        "entries": entries,
        "manifest_samples": manifests,
        "git": {
            "detected": git_root is not None,
            "root": None if git_root is None else Path(git_root).name,
            "head": git_head,
            "branch": git_branch,
            "dirty": bool(git_status),
            "changed_entry_count": 0 if not git_status else len(git_status.splitlines()),
        },
        "host": {
            "system": {"windows": "windows", "darwin": "darwin", "linux": "linux"}.get(platform.system().casefold(), "other"),
            "machine": platform.machine().casefold(),
            "python": platform.python_version(),
        },
    }
    return result


def _package_dependencies(sample: str) -> set[str]:
    try:
        value = json.loads(sample)
    except json.JSONDecodeError:
        return set()
    result: set[str] = set()
    if isinstance(value, dict):
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            section = value.get(key)
            if isinstance(section, dict):
                result.update(str(name).casefold() for name in section)
    return result


def detect_technologies(preflight: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    paths = {str(item.get("path", "")) for item in preflight.get("entries", [])}
    samples = preflight.get("manifest_samples", {})
    lower_paths = {value.casefold() for value in paths}
    facts: dict[str, dict[str, Any]] = {}
    source_seen: dict[str, set[str]] = {}
    signals: list[dict[str, Any]] = []
    source_limit = _technology_source_limit()

    def add(technology: str, source: str, confidence: float = 1.0) -> None:
        current = facts.setdefault(
            technology,
            {
                "technology": technology,
                "sources": [],
                "total_source_count": 0,
                "sources_truncated": False,
                "confidence": confidence,
            },
        )
        current["confidence"] = max(float(current["confidence"]), confidence)
        seen = source_seen.setdefault(technology, set())
        if source in seen:
            return
        seen.add(source)
        current["total_source_count"] = int(current["total_source_count"]) + 1

    for path in sorted(paths):
        lower = path.casefold()
        suffix = Path(lower).suffix
        if suffix in {".js", ".jsx"}:
            add("javascript", path, 0.9)
        if suffix in {".ts", ".tsx"}:
            add("typescript", path, 0.9)
        if suffix == ".py":
            add("python", path, 0.9)
        if suffix in {".kt", ".kts"}:
            add("kotlin", path, 0.9)
        if suffix == ".java":
            add("java", path, 0.8)
        if suffix in {".cpp", ".cxx", ".cc", ".c", ".h", ".hpp"}:
            add("cpp", path, 0.8)
        if suffix == ".cs":
            add("dotnet", path, 0.8)
        if suffix == ".rs":
            add("rust", path, 0.8)
        if suffix == ".go":
            add("go", path, 0.8)
        if suffix == ".swift":
            add("swift", path, 0.8)
        if suffix == ".dart":
            add("dart", path, 0.8)
        if lower.endswith("cmakelists.txt") or lower.endswith("cmakepresets.json"):
            add("cmake", path)
        if lower.endswith("androidmanifest.xml") or "gradle" in Path(lower).name:
            add("android", path)
            add("gradle", path)
        if lower.endswith(".sln") or lower.endswith(".vcxproj"):
            add("windows-native", path)
            add("visual-studio", path)
        if lower.endswith(".csproj"):
            add("dotnet", path)
        if lower.startswith("supabase/") or lower.endswith("supabase.toml"):
            add("supabase", path)
        if lower.endswith("dockerfile") or "docker-compose" in lower:
            add("containers", path, 0.8)

    for path, sample in samples.items():
        if Path(path).name.casefold() == "package.json":
            add("node", path)
            dependencies = _package_dependencies(sample)
            for dependency, technology in (
                ("react", "react"),
                ("react-native", "react-native"),
                ("expo", "expo"),
                ("next", "nextjs"),
                ("vite", "vite"),
                ("@supabase/supabase-js", "supabase"),
                ("vue", "vue"),
                ("svelte", "svelte"),
                ("express", "express"),
            ):
                if dependency in dependencies:
                    add(technology, path)
        if Path(path).name.casefold() == "pyproject.toml":
            add("python", path)
        if Path(path).name.casefold() == "cargo.toml":
            add("rust", path)
        if Path(path).name.casefold() == "go.mod":
            add("go", path)

    duplicate_like = duplicate_name_markers(tuple(paths), limit=16)
    if duplicate_like["total_count"]:
        signals.append(
            {
                "signal": "duplicate-like-paths",
                "confidence": 0.45,
                "examples": duplicate_like["examples"],
                "total_count": duplicate_like["total_count"],
                "interpretation": "filename-marker signal only; exact duplication is owned by runtime audit content hashes",
            }
        )
    large_samples = [
        item["path"]
        for item in preflight.get("entries", [])
        if item.get("kind") == "file"
        and item.get("suffix") in _SOURCE_SUFFIXES
        and isinstance(item.get("size_bytes"), int)
        and item["size_bytes"] >= 256 * 1024
    ]
    if large_samples:
        signals.append(
            {
                "signal": "large-source-files",
                "confidence": 0.7,
                "examples": large_samples[:16],
            }
        )
    # ``technology_source_items_max`` is a global plan budget, not a per-item
    # allowance.  Allocate it deterministically and fairly across all detected
    # technologies while retaining exact counts outside the sample list.
    ordered_technologies = sorted(facts)
    samples: dict[str, list[str]] = {
        technology: sorted(source_seen.get(technology, set()))
        for technology in ordered_technologies
    }
    selected: dict[str, list[str]] = {technology: [] for technology in ordered_technologies}
    remaining = source_limit
    # Give every detected technology one representative source first.  The
    # built-in technology vocabulary is deliberately smaller than this budget.
    for technology in ordered_technologies:
        if remaining <= 0:
            break
        if samples[technology]:
            selected[technology].append(samples[technology][0])
            remaining -= 1
    sample_index = 1
    while remaining > 0:
        progressed = False
        for technology in ordered_technologies:
            if remaining <= 0:
                break
            values = samples[technology]
            if sample_index < len(values):
                selected[technology].append(values[sample_index])
                remaining -= 1
                progressed = True
        if not progressed:
            break
        sample_index += 1

    normalized_facts: list[dict[str, Any]] = []
    for technology in ordered_technologies:
        item = facts[technology]
        clean = dict(item)
        clean["sources"] = selected[technology]
        clean["sources_truncated"] = bool(
            len(clean["sources"]) < int(clean["total_source_count"])
            or preflight.get("truncated")
        )
        clean["source_count_complete"] = not bool(preflight.get("truncated"))
        normalized_facts.append(clean)
    return normalized_facts, signals


def _detect_language(goal: str | None, requested: str) -> str:
    if requested in {"uk", "en"}:
        return requested
    text = goal or ""
    if re.search(r"[іїєґІЇЄҐ]", text) or re.search(r"[А-Яа-я]", text):
        return "uk"
    locale = " ".join(filter(None, [os.environ.get("LANG"), os.environ.get("LC_ALL")])).casefold()
    return "uk" if locale.startswith("uk") else "en"


def _profile_catalog() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    if not PROFILE_ROOT.is_dir():
        return result
    for path in sorted(PROFILE_ROOT.glob("*.json"), key=lambda item: item.name.casefold()):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and isinstance(value.get("profile_id"), str):
            result[value["profile_id"]] = value
    return result


def _resolve_profiles(
    technologies: Sequence[Mapping[str, Any]],
    signals: Sequence[Mapping[str, Any]],
    *,
    autonomy: str,
    language: str,
    explicit: Iterable[str],
) -> tuple[list[str], list[dict[str, Any]]]:
    tech = {str(item["technology"]) for item in technologies}
    layers = ["general-development"]
    reasons: list[dict[str, Any]] = [
        {"profile_id": "general-development", "reason": "base development policy", "confidence": 1.0}
    ]

    def add(profile_id: str, reason: str, confidence: float) -> None:
        if profile_id not in layers:
            layers.append(profile_id)
            reasons.append({"profile_id": profile_id, "reason": reason, "confidence": confidence})

    if tech & {"react-native", "expo"}:
        add("mobile-application", "React Native or Expo facts detected", 0.98)
    if tech & {"react", "nextjs", "vite", "vue", "svelte", "supabase", "node", "javascript", "typescript"}:
        add("web-application", "web technology facts detected", 0.95)
    if tech & {"android", "gradle", "kotlin"}:
        add("android-application", "Android/Gradle/Kotlin facts detected", 0.95)
    if tech & {"windows-native", "visual-studio", "dotnet"}:
        add("windows-development", "Windows project toolchain facts detected", 0.9)
    if tech & {"cpp", "cmake"} and not ({"web-application", "android-application"} & set(layers)):
        add("morok-tower-studio", "C++/CMake project matches studio baseline", 0.8)
    if len(layers) == 1:
        add("morok-tower-studio", "fallback when repository evidence is insufficient", 0.55)
    if signals:
        add("vibe-recovery", "repository complexity/duplication signals detected", 0.65)
    for profile_id in explicit:
        add(str(profile_id), "explicit operator selection", 1.0)
    add(autonomy, "selected autonomy policy", 1.0)
    add(language, "selected reporting language", 1.0)
    return layers, reasons


def _project_mode(preflight: Mapping[str, Any], technologies: Sequence[Mapping[str, Any]]) -> tuple[str, float]:
    paths = {str(item.get("path", "")).casefold() for item in preflight.get("entries", [])}
    code = any(Path(path).suffix in _SOURCE_SUFFIXES for path in paths) or bool(technologies)
    planning = any(
        Path(path).name in {"readme.md", "readme_ua.md", "roadmap.md", "backlog.md", "project.md", "brief.md"}
        for path in paths
    )
    if code and planning:
        return "hybrid", 0.9
    if code:
        return "existing-code", 0.95
    return "greenfield", 0.85


def _default_goal(root: Path, mode: str, technologies: Sequence[Mapping[str, Any]]) -> str:
    stack = ", ".join(item["technology"] for item in technologies[:5])
    if mode == "greenfield":
        return f"Create a reliable project in {root.name} from the available brief and references."
    if mode == "hybrid":
        return f"Align the existing code and project intent in {root.name}, then continue development safely."
    suffix = f" using {stack}" if stack else ""
    return f"Audit, stabilize, and safely continue development of {root.name}{suffix}."


def _operation_profiles(mode: str, layers: Sequence[str]) -> list[dict[str, Any]]:
    operations = [
        ("repository-preflight", "tool-only", "deterministic metadata inspection"),
        ("exact-search", "tool-only", "deterministic retrieval"),
        ("file-classification", "micro", "bounded mechanical classification"),
        ("plan-refinement", "standard", "bounded project planning"),
        ("implementation", "standard", "bounded coding and tests"),
        ("semantic-deduplication", "strong", "behavior and source-of-truth analysis"),
        ("security-review", "strong", "high-consequence reasoning"),
        ("release-or-destructive-decision", "critical-review", "human authority remains required"),
    ]
    if mode == "greenfield":
        operations.insert(3, ("architecture-skeleton", "strong", "initial architecture and invariants"))
    if "vibe-recovery" in layers:
        operations.append(("concurrent-change-reconciliation", "strong", "stale-base and divergent-fork control"))
    return [
        {"operation": operation, "model_tier": tier, "reason": reason}
        for operation, tier, reason in operations
    ]


def _brief_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ExperienceError(f"project brief field {field} must be an array of non-empty strings")
    return [item.strip() for item in value]


def _normalize_brief(brief: Mapping[str, Any] | None) -> dict[str, Any]:
    if brief is None:
        return {}
    allowed = {
        "goal", "success_criteria", "constraints", "non_goals", "deliverables",
        "references", "work_sources", "autonomy", "language", "profile_overrides",
    }
    unknown = set(brief) - allowed
    if unknown:
        raise ExperienceError(f"project brief has unknown fields: {sorted(unknown)}")
    result: dict[str, Any] = {}
    if "goal" in brief:
        if not isinstance(brief["goal"], str) or not brief["goal"].strip():
            raise ExperienceError("project brief goal must be a non-empty string")
        result["goal"] = brief["goal"].strip()
    for field in ("success_criteria", "constraints", "non_goals", "deliverables", "references", "work_sources", "profile_overrides"):
        result[field] = _brief_list(brief.get(field), field)
    if "autonomy" in brief:
        result["autonomy"] = brief["autonomy"]
    if "language" in brief:
        result["language"] = brief["language"]
    return result


def resolve_plan(
    project_root: Path | str,
    *,
    goal: str | None = None,
    autonomy: str | None = None,
    language: str | None = None,
    explicit_profiles: Sequence[str] = (),
    brief: Mapping[str, Any] | None = None,
    max_preflight_files: int = _PREFLIGHT_MAX_FILES,
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    normalized_brief = _normalize_brief(brief)
    selected_autonomy = autonomy or normalized_brief.get("autonomy") or "safe-auto"
    selected_language_request = language or normalized_brief.get("language") or "auto"
    if selected_autonomy not in {"ask", "safe-auto", "unsafe-auto"}:
        raise ExperienceError("autonomy must be ask, safe-auto, or unsafe-auto")
    if selected_language_request not in {"auto", "uk", "en"}:
        raise ExperienceError("language must be auto, uk, or en")
    preflight = bounded_preflight(root, max_files=max_preflight_files)
    technologies, signals = detect_technologies(preflight)
    workspace_map = discover_workspace_map(preflight, technologies, signals)
    mode, mode_confidence = _project_mode(preflight, technologies)
    resolved_goal_input = goal or normalized_brief.get("goal")
    selected_language = _detect_language(resolved_goal_input, selected_language_request)
    layers, reasons = _resolve_profiles(
        technologies,
        signals,
        autonomy=selected_autonomy,
        language=selected_language,
        explicit=tuple(normalized_brief.get("profile_overrides", [])) + tuple(explicit_profiles),
    )
    catalog = _profile_catalog()
    missing = [profile for profile in layers if profile not in catalog]
    if missing:
        raise ExperienceError(f"resolved profile layers are not installed: {missing}")
    resolved_goal = (resolved_goal_input or "").strip() or _default_goal(root, mode, technologies)
    project_id = _safe_id(root.name)
    planned_operations = [
        {
            "operation_id": "initialize-control-layer",
            "kind": "control",
            "hidden_full_scan": False,
            "requires_confirmation": selected_autonomy != "unsafe-auto",
        }
    ]
    if mode in {"existing-code", "hybrid"}:
        planned_operations.extend(
            [
                {
                    "operation_id": "build-one-pass-inventory",
                    "kind": "read-only",
                    "hidden_full_scan": False,
                    "requires_confirmation": selected_autonomy == "ask",
                },
                {
                    "operation_id": "build-semantic-map",
                    "kind": "read-only",
                    "hidden_full_scan": False,
                    "requires_confirmation": False,
                },
            ]
        )
    else:
        planned_operations.append(
            {
                "operation_id": "build-specification-baseline",
                "kind": "read-only",
                "hidden_full_scan": False,
                "requires_confirmation": False,
            }
        )
    planned_operations.append(
        {
            "operation_id": "prepare-first-work-proposal",
            "kind": "proposal-only",
            "hidden_full_scan": False,
            "requires_confirmation": False,
        }
    )
    plan_identity = {
        "record_type": "ResolvedInitPlan",
        "plan_version": 1,
        "standard_version": standard_version(),
        "project_id": project_id,
        "project_root": ".",
        "project_mode": mode,
        "project_mode_confidence": mode_confidence,
        "goal": resolved_goal,
        "success_criteria": normalized_brief.get("success_criteria") or [
            "The next work item is bounded and evidence-oriented.",
            "Routine work does not require repeated user supervision.",
            "No failed result receives pass credit.",
        ],
        "constraints": normalized_brief.get("constraints", []),
        "non_goals": normalized_brief.get("non_goals", []),
        "references": sorted(set(normalized_brief.get("references", [])) | {str(value) for value in preflight.get("manifest_samples", {}) if Path(str(value)).name.casefold() in {"readme.md", "readme_ua.md", "agents.md", "claude.md", "contributing.md", "roadmap.md", "backlog.md"}}),
        "work_sources": sorted(set(normalized_brief.get("work_sources", [])) | {str(value) for value in preflight.get("manifest_samples", {}) if any(token in Path(str(value)).name.casefold() for token in ("backlog", "roadmap", "todo", "plan"))}),
        "deliverables": normalized_brief.get("deliverables", []),
        "detected_technologies": technologies,
        "repository_signals": signals,
        "workspace_map": workspace_map,
        "profile_layers": layers,
        "profile_resolution": reasons,
        "autonomy": selected_autonomy,
        "reporting_language": selected_language,
        "operation_profiles": _operation_profiles(mode, layers),
        "available_skills": discover_skills(root),
        "material_permissions": {
            "read_and_analyze": "automatic",
            "local_tests": "automatic" if selected_autonomy != "ask" else "confirm",
            "repository_mutation": "automatic-within-grant" if selected_autonomy != "ask" else "confirm",
            "destructive_operations": "human-decision",
            "public_release": "human-decision",
            "network_or_remote_install": "explicit-source-policy",
        },
        "planned_operations": planned_operations,
        "material_unknowns": (["bounded preflight was truncated; full inventory remains a separate visible operation"] if preflight.get("truncated") else []),
        "preflight": {
            key: preflight[key]
            for key in (
                "entry_count",
                "bytes_read",
                "max_files",
                "max_bytes",
                "max_depth",
                "truncated",
                "full_repository_scan",
                "git",
            )
        },
        "question_count_before_plan": 0,
        "manual_digest_operations": 0,
        "user_authored_config_files_required": 0,
        "authority": False,
        "pass_credit": False,
    }
    return _fit_resolved_plan_budget(plan_identity)



def _plan_with_digest(plan_identity: Mapping[str, Any]) -> dict[str, Any]:
    return {**dict(plan_identity), "plan_digest": digest_value(plan_identity)}


def _fit_resolved_plan_budget(plan_identity: dict[str, Any]) -> dict[str, Any]:
    """Reduce only sampled evidence until the user-facing plan fits Core budget.

    Exact counts and semantic facts remain intact.  The routine never drops a
    detected technology; it removes representative source paths in a
    deterministic order and marks the affected facts as truncated.
    """

    max_bytes = _alpha_budgets().get("resolved_plan_bytes_max")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 1024:
        raise ExperienceError("resolved plan byte budget is invalid")

    result = dict(plan_identity)
    result["detected_technologies"] = [dict(item) for item in plan_identity["detected_technologies"]]
    result["repository_signals"] = [dict(item) for item in plan_identity["repository_signals"]]

    def size() -> int:
        return len(_json_bytes(_plan_with_digest(result)))

    while size() > max_bytes:
        candidates = [
            item
            for item in result["detected_technologies"]
            if isinstance(item.get("sources"), list) and len(item["sources"]) > 1
        ]
        if not candidates:
            break
        # Remove from the noisiest technology first; tie-break by ID for a
        # stable result independent of dict insertion order.
        selected = max(candidates, key=lambda item: (len(item["sources"]), str(item["technology"])))
        selected["sources"] = list(selected["sources"][:-1])
        selected["sources_truncated"] = True

    # Repository-signal examples are diagnostic samples, not canonical facts.
    # Compact them only if source samples alone cannot meet the budget.
    while size() > max_bytes:
        candidates = [
            item
            for item in result["repository_signals"]
            if isinstance(item.get("examples"), list) and item["examples"]
        ]
        if not candidates:
            break
        selected = max(candidates, key=lambda item: (len(item["examples"]), str(item.get("signal", ""))))
        selected["examples"] = list(selected["examples"][:-1])
        selected.setdefault("examples_truncated", True)

    if size() > max_bytes:
        raise ExperienceError(
            "resolved plan exceeds its structural byte budget after bounded evidence compaction"
        )
    return _plan_with_digest(result)

def _license(expression: str, uri: str) -> dict[str, Any]:
    return {
        "expression": expression,
        "source_uris": [uri],
        "review_state": "source-verified",
    }


def _materialize_host_python(project_root: Path) -> tuple[str, Path]:
    """Bind the real base interpreter through the shared verified store.

    A venv launcher is not relocatable on Windows, so ``sys._base_executable``
    is preferred. The shared blob is host-local derived state; the project keeps
    only one isolated content-addressed receipt created by Core initialization.
    """

    del project_root  # the shared source is intentionally not project-relative
    source = Path(getattr(sys, "_base_executable", None) or sys.executable).resolve(strict=True)
    source_digest = digest_file(source)
    blob = ensure_blob(source, source_digest)
    return str(blob), blob


def _provider_bindings(project_root: Path) -> list[dict[str, Any]]:
    relative_executable, executable = _materialize_host_python(project_root)
    digest = digest_file(executable)
    python_license = _license("PSF-2.0", "https://docs.python.org/3/license.html")
    capability_licenses = {
        "shape-validation": _license("MIT", "https://github.com/python-jsonschema/jsonschema/blob/main/COPYING"),
        "query-projection": _license("LicenseRef-SQLite-Public-Domain", "https://sqlite.org/copyright.html"),
    }
    required = [
        "control-runtime",
        "shape-validation",
        "content-identity",
        "local-serialization",
        "query-projection",
    ]
    bindings: list[dict[str, Any]] = []
    for index, capability in enumerate(required, start=1):
        binding = {
            "capability_id": capability,
            "provider_id": f"alpha-python-{index}",
            "version": platform.python_version(),
            "invocation": {"kind": "python-runtime", "value": relative_executable},
            "purpose": f"Provide {capability} for the local promin runtime.",
            "required": True,
            "healthcheck": {
                "argv": [relative_executable, "--version"],
                "timeout_ms": 5000,
                "expected_exit": 0,
            },
            "license": capability_licenses.get(capability, python_license),
            "identity": {
                "kind": "file-digest",
                "digest": digest,
                "source": relative_executable,
            },
        }
        binding["dependency_receipt"] = build_provider_dependency_receipt(binding, project_root)
        bindings.append(binding)
    technologies = bind_implementation_closures(
        {"record_type": "TechnologiesInit", "bindings": bindings}, project_root
    )
    return list(technologies["bindings"])


def _root_capability_ceiling(autonomy: str) -> list[str]:
    common = {
        "standard.activate",
        "authority.manage",
        "task.plan",
        "projection.read",
        "projection.rebuild",
        "finding.record",
    }
    if autonomy in {"safe-auto", "unsafe-auto"}:
        common |= {
            "task.execute",
            "lease.manage",
            "evidence.publish",
            "validation.evaluate",
            "finding.resolve",
        }
    if autonomy == "unsafe-auto":
        common |= {"export.create"}
    return sorted(common)


def _resolved_profile_record(plan: Mapping[str, Any]) -> dict[str, Any]:
    identity = {
        "revision": 1,
        "layers": list(plan["profile_layers"]),
        "detected_technologies": [dict(item) for item in plan["detected_technologies"]],
        "operation_profiles": [dict(item) for item in plan["operation_profiles"]],
        "resolution": [dict(item) for item in plan["profile_resolution"]],
        "authority_effect": "none",
    }
    return {**identity, "profile_digest": digest_value(identity)}


def compile_core_plans(plan: Mapping[str, Any], project_root: Path) -> dict[str, dict[str, Any]]:
    bindings = _provider_bindings(project_root)
    project_plan = {
        "record_type": "ProjectInit",
        "project_id": plan["project_id"],
        "roots": [{"path": ".", "kind": "product"}],
        "candidate_recipe": {
            "inventory_mode": "explicit",
            "include": ["**"],
            "exclude": [
                ".git/**",
                ".promin/**",
                ".promin-host/**",
                "node_modules/**",
                ".venv/**",
                "venv/**",
                "dist/**",
                "build/**",
                "target/**",
                "coverage/**",
                "__pycache__/**",
            ],
            "symlink_policy": "reject",
            "path_identity": "nfc-posix-relative",
            "collision_policy": "reject-nfc-and-casefold-collisions",
            "product_identity_excludes_control_state": True,
            "snapshot_consistency": "observational-best-effort",
        },
        "preset_id": "semantic-morok-tower",
        "operating_profile": "morok-local",
        "intent": {
            "project_mode": plan["project_mode"],
            "goal": plan["goal"],
            "success_criteria": list(plan["success_criteria"]),
            "constraints": list(plan["constraints"]),
            "non_goals": list(plan["non_goals"]),
            "deliverables": list(plan.get("deliverables", [])),
            "references": list(plan.get("references", [])),
            "work_sources": list(plan.get("work_sources", [])),
            "reporting_language": plan["reporting_language"],
            "autonomy": plan["autonomy"],
        },
        "resolved_profile": _resolved_profile_record(plan),
        "orchestration": {
            "enabled": True,
            "enforcement": "required",
            "unregistered_work": "external-proposal-only",
            "model_routing": "cheapest-adequate-with-evidence-escalation",
            "host_source": "generic-agent-envelope",
        },
        "telemetry": {
            "enabled": True,
            "local_only": True,
            "export_enabled": False,
            "max_log_bytes": 4 * 1024 * 1024,
            "retention_records": 5000,
            "store_full_prompts": False,
            "store_source_bodies": False,
            "store_secrets_or_pii": False,
        },
    }
    standards_plan = {"record_type": "StandardsInit", "bindings": []}
    technologies_plan = {"record_type": "TechnologiesInit", "bindings": bindings}
    authority_plan = {
        "record_type": "AuthorityInit",
        "trust_mode": "local-owner",
        "subjects": [
            {
                "subject_id": "owner",
                "kind": "human",
                "display_name": "Project owner",
            },
            {
                "subject_id": "agent-host",
                "kind": "agent",
                "display_name": "Active agent host",
            },
        ],
        "roots": [
            {
                "subject_id": "owner",
                "capability_ceiling": _root_capability_ceiling(str(plan["autonomy"])),
                "scope": [{"kind": "project", "value": plan["project_id"]}],
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
    return {
        "project.json": project_plan,
        "standards.json": standards_plan,
        "technologies.json": technologies_plan,
        "licenses.json": licenses_plan,
        "authority.json": authority_plan,
    }


def _write_json(path: Path, value: Any) -> None:
    os.makedirs(filesystem_path(path.parent), exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with open(filesystem_path(temporary), "xb") as handle:
        handle.write(_json_bytes(value))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(filesystem_path(temporary), filesystem_path(path))


def _config_documents(plan: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        "project.json": {
            "record_type": "GeneratedProjectConfigView",
            "authoritative": False,
            "project_id": plan["project_id"],
            "project_mode": plan["project_mode"],
            "goal": plan["goal"],
            "success_criteria": plan["success_criteria"],
            "constraints": plan["constraints"],
            "non_goals": plan["non_goals"],
            "references": plan["references"],
        },
        "profile.json": {
            "record_type": "GeneratedResolvedProfileView",
            "authoritative": False,
            "profile_layers": plan["profile_layers"],
            "resolution": plan["profile_resolution"],
            "detected_technologies": plan["detected_technologies"],
            "operation_profiles": plan["operation_profiles"],
            "revision": 1,
        },
        "orchestration.json": {
            "record_type": "GeneratedOrchestrationConfigView",
            "authoritative": False,
            "enabled": True,
            "enforcement": "required",
            "autonomy": plan["autonomy"],
            "unregistered_work": "external-proposal-only",
            "model_routing": "cheapest-adequate-with-evidence-escalation",
            "host_source": "generic-agent-envelope",
        },
        "telemetry.json": {
            "record_type": "GeneratedTelemetryConfigView",
            "authoritative": False,
            "enabled": True,
            "local_only": True,
            "export_enabled": False,
            "max_log_bytes": 4 * 1024 * 1024,
            "retention_records": 5000,
            "store_full_prompts": False,
            "store_source_bodies": False,
            "store_secrets_or_pii": False,
        },
        "language.json": {
            "record_type": "GeneratedReportingLanguageView",
            "authoritative": False,
            "language": plan["reporting_language"],
            "supported": ["uk", "en"],
        },
    }


def _plan_proposal(plan: Mapping[str, Any]) -> dict[str, Any]:
    mode = str(plan["project_mode"])
    if mode == "greenfield":
        tasks = [
            ("baseline", "Build a specification baseline from the goal, references, and constraints.", "read"),
            ("architecture", "Propose the smallest architecture that satisfies the success criteria.", "read"),
            ("skeleton", "Create the first bounded project skeleton after approval.", "mutate"),
            ("vertical-slice", "Implement and validate one end-to-end vertical slice.", "mutate"),
        ]
    else:
        tasks = [
            ("inventory", "Build one explicit product inventory and Candidate.", "read"),
            ("semantic-map", "Build a bounded semantic map and source-of-truth inventory.", "read"),
            ("audit", "Audit duplicates, monoliths, security boundaries, and missing tests.", "read"),
            ("prioritize", "Create an evidence-ranked repair and development plan.", "read"),
        ]
    items = []
    previous: str | None = None
    for index, (suffix, title, operation) in enumerate(tasks, start=1):
        task_id = f"proposal:{plan['project_id']}:{index:02d}-{suffix}"
        items.append(
            {
                "task_id": task_id,
                "title": title,
                "operation": operation,
                "depends_on": [] if previous is None else [previous],
                "acceptance_predicate": "Result is evidence-backed, bounded, and does not claim product acceptance.",
                "allowed_paths": ["**"] if operation == "read" else ["src/**", "tests/**", "docs/**"],
                "source_bindings": [plan["plan_digest"]],
                "authority": False,
                "pass_credit": False,
            }
        )
        previous = task_id
    identity = {
        "record_type": "PlanProposal",
        "proposal_id": "plan:" + str(plan["plan_digest"])[:24],
        "project_id": plan["project_id"],
        "project_mode": plan["project_mode"],
        "goal": plan["goal"],
        "source_plan_digest": plan["plan_digest"],
        "created_at": utc_now(),
        "tasks": items,
        "authority": False,
        "pass_credit": False,
    }
    return {**identity, "proposal_digest": digest_value(identity)}


def _write_alpha_state(project_root: Path, plan: Mapping[str, Any]) -> None:
    config_root = project_root / ".promin" / "generated" / "config-view"
    documents = _config_documents(plan)
    for name, value in documents.items():
        _write_json(config_root / name, value)
    lock_identity = {
        "record_type": "GeneratedConfigViewLock",
        "authoritative": False,
        "plan_digest": plan["plan_digest"],
        "files": [
            {"path": name, "sha256": hashlib.sha256(_json_bytes(value)).hexdigest()}
            for name, value in sorted(documents.items())
        ],
    }
    _write_json(config_root / "config.lock.json", {**lock_identity, "lock_digest": digest_value(lock_identity)})
    generated = project_root / ".promin" / "generated"
    proposal = _plan_proposal(plan)
    bundle = load_contract_bundle(PACKAGE_ROOT, DEFAULT_PRESET)
    validate_definition(bundle.schema, "PlanProposal", proposal)
    _write_json(generated / "resolved-plan.json", dict(plan))
    _write_json(generated / "plan-proposal.json", proposal)
    host_identity_base = {
        "record_type": "HostBinding",
        "system": {"windows": "windows", "darwin": "darwin", "linux": "linux"}.get(platform.system().casefold(), "other"),
        "release": platform.release(),
        "machine": platform.machine().casefold(),
        "python": platform.python_version(),
        "python_executable_digest": digest_file(Path(sys.executable).resolve(strict=True)),
        "path_separator": os.sep,
        "case_sensitive_default": os.name != "nt",
        "canonical": False,
        "rebuildable": True,
    }
    host_identity = {**host_identity_base, "host_binding_digest": digest_value(host_identity_base)}
    _write_json(project_root / ".promin" / "host" / "host.json", host_identity)



def _cleanup_partial_control_state(project_root: Path) -> None:
    """Remove non-authoritative residue from an incomplete first init.

    Portable team files are preserved so a cloned repository can still be
    rehydrated. No failed initialization may poison the next attempt.
    """

    control = project_root / ".promin"
    if not os.path.isdir(filesystem_path(control)) or os.path.islink(filesystem_path(control)):
        return
    for child in tuple(Path(filesystem_path(control)).iterdir()):
        if child.name in {"portable", ".gitignore"}:
            continue
        if os.path.isdir(filesystem_path(child)) and not os.path.islink(filesystem_path(child)):
            _remove_owner_tree(child)
        else:
            os.unlink(filesystem_path(child))
    remaining = tuple(Path(filesystem_path(control)).iterdir())
    if not remaining:
        os.rmdir(filesystem_path(control))


def _remove_owner_tree(root: Path) -> None:
    """Remove a tree created by this init attempt, including read-only files.

    Standards are intentionally made read-only before publication.  A failed
    guided init must nevertheless clean only its own unpublished tree so that
    a corrected retry can restore a previously archived partial control tree.
    All host calls use the final filesystem spelling; the ordinary ``Path`` is
    retained solely for project identity and reporting.
    """

    native_root = (
        windows_extended_path(root.absolute()) if os.name == "nt" else filesystem_path(root)
    )
    if not os.path.lexists(native_root):
        return
    if os.path.islink(native_root):
        os.unlink(native_root)
        return
    if not os.path.isdir(native_root):
        os.chmod(native_root, stat.S_IREAD | stat.S_IWRITE)
        os.unlink(native_root)
        return
    for directory, directories, filenames in os.walk(
        native_root, topdown=False, followlinks=False
    ):
        for name in filenames:
            path = os.path.join(directory, name)
            if not os.path.islink(path):
                os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
            os.unlink(path)
        for name in directories:
            path = os.path.join(directory, name)
            if os.path.islink(path):
                os.unlink(path)
                continue
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
            os.rmdir(path)
    os.chmod(native_root, stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
    os.rmdir(native_root)

def apply_plan(
    project_root: Path | str,
    plan: Mapping[str, Any],
    *,
    standard_bundle: Path | None = None,
    preset_path: Path | None = None,
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    if plan.get("plan_digest") != digest_value({key: value for key, value in plan.items() if key != "plan_digest"}):
        raise ExperienceError("resolved plan digest mismatch")
    existing_plan = load_resolved_plan(root)
    activation_exists = (root / ".promin" / "init" / "activation.json").is_file()
    if activation_exists:
        if existing_plan is None:
            raise ExperienceError(
                "promin is initialized but its resolved plan is missing; run promin doctor --repair"
            )
        if existing_plan.get("plan_digest") != plan.get("plan_digest"):
            raise ExperienceError(
                "initialized project resolves to a different plan; review the new plan and use an explicit plan-update workflow"
            )
        bootstrap = load_bootstrap_state(root)
        if bootstrap is None:
            bootstrap = bootstrap_operational_state(root, existing_plan)
        else:
            bootstrap = {**bootstrap, "status": "idempotent"}
        from .refresh import refresh_project
        refresh = refresh_project(root, apply=True)
        record_observation(
            root,
            kind="guided-init",
            status="idempotent",
            details={"plan_digest": plan["plan_digest"], "component": "initialization"},
        )
        return {
            "record_type": "InitializationResult",
            "status": "idempotent",
            "mode": "guided",
            "resolved_plan_digest": plan["plan_digest"],
            "project_mode": plan["project_mode"],
            "profile_layers": plan["profile_layers"],
            "autonomy": plan["autonomy"],
            "reporting_language": plan["reporting_language"],
            "product_tree_scans_before_plan": 0,
            "next_command": "promin next",
            "audit_command": "promin audit",
            "bootstrap": bootstrap,
            "first_work_card": bootstrap.get("first_work_card"),
            "refresh": refresh,
            "authority": False,
            "pass_credit": False,
            "product_acceptance_pass": False,
        }

    control = root / ".promin"
    host_state = root / ".promin-host"
    control_existed = os.path.lexists(filesystem_path(control))
    host_existed = os.path.lexists(filesystem_path(host_state))
    partial_archive: Path | None = None
    if control_existed:
        # No Activation means the directory is not canonical initialized state.
        # Preserve it outside the control root so a corrected init can proceed
        # without manual deletion while retaining forensic evidence.
        recovery = host_state / "recovery"
        os.makedirs(filesystem_path(recovery), exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        partial_archive = recovery / f"partial-control-{stamp}"
        os.rename(filesystem_path(control), filesystem_path(partial_archive))
        control_existed = False

    bundle = (standard_bundle or PACKAGE_ROOT).resolve()
    preset = (preset_path or DEFAULT_PRESET).resolve()
    try:
        plans = compile_core_plans(plan, root)
        bundle_contracts = load_contract_bundle(bundle, preset)
        validate_definition(bundle_contracts.schema, "ProjectInit", plans["project.json"])
        with resolved_temporary_directory(prefix="promin-alpha-init-") as staging:
            for name, value in plans.items():
                _write_json(staging / name, value)
            request = InitRequest(
                project_root=root,
                standard_bundle=bundle,
                preset_path=preset,
                project_plan=staging / "project.json",
                standards_plan=staging / "standards.json",
                technologies_plan=staging / "technologies.json",
                licenses_plan=staging / "licenses.json",
                authority_plan=staging / "authority.json",
            )
            result = ProminService(root).initialize(request)
        _write_alpha_state(root, plan)
        bootstrap = bootstrap_operational_state(root, plan)
        from .refresh import refresh_project
        refresh = refresh_project(root, apply=True)
    except Exception:
        if not control_existed and os.path.lexists(filesystem_path(control)):
            _remove_owner_tree(control)
        if partial_archive is not None and os.path.lexists(filesystem_path(control)):
            _remove_owner_tree(control)
        if partial_archive is not None and os.path.lexists(filesystem_path(partial_archive)):
            os.rename(filesystem_path(partial_archive), filesystem_path(control))
        elif not host_existed and os.path.lexists(filesystem_path(host_state)):
            _remove_owner_tree(host_state)
        raise

    record_observation(
        root,
        kind="guided-init",
        status="pass",
        details={
            "project_mode": plan["project_mode"],
            "profile_layers": plan["profile_layers"],
            "autonomy": plan["autonomy"],
            "product_tree_scans": 0,
        },
    )
    return {
        **result,
        "mode": "guided",
        "resolved_plan_digest": plan["plan_digest"],
        "project_mode": plan["project_mode"],
        "profile_layers": plan["profile_layers"],
        "autonomy": plan["autonomy"],
        "reporting_language": plan["reporting_language"],
        "product_tree_scans_before_plan": 0,
        "partial_control_archived": None if partial_archive is None else partial_archive.relative_to(root).as_posix(),
        "next_command": "promin next",
        "audit_command": "promin audit",
        "bootstrap": bootstrap,
        "first_work_card": bootstrap.get("first_work_card"),
        "refresh": refresh,
    }


def load_resolved_plan(project_root: Path | str) -> dict[str, Any] | None:
    path = Path(project_root).resolve() / ".promin" / "generated" / "resolved-plan.json"
    if not os.path.isfile(filesystem_path(path)):
        return None
    value = load_json_strict(path, root=path.parent)
    return dict(value) if isinstance(value, Mapping) else None


def load_plan_proposal(project_root: Path | str) -> dict[str, Any] | None:
    path = Path(project_root).resolve() / ".promin" / "generated" / "plan-proposal.json"
    if not os.path.isfile(filesystem_path(path)):
        return None
    value = load_json_strict(path, root=path.parent)
    return dict(value) if isinstance(value, Mapping) else None


def next_proposal(project_root: Path | str) -> dict[str, Any]:
    root = Path(project_root).resolve()
    bootstrap = load_bootstrap_state(root)
    if bootstrap is not None:
        grants = bootstrap.get("grants", {})
        holder = grants.get("holder", {}) if isinstance(grants, Mapping) else {}
        reader = grants.get("reader", {}) if isinstance(grants, Mapping) else {}
        if isinstance(holder, Mapping) and isinstance(reader, Mapping):
            holder_id = holder.get("grant_id")
            reader_id = reader.get("grant_id")
            if isinstance(holder_id, str) and isinstance(reader_id, str):
                return ProminService(root).next(
                    subject_id="owner",
                    grant_id=holder_id,
                    query_grant_id=reader_id,
                    depth=1,
                )
    proposal = load_plan_proposal(root)
    if proposal is None:
        raise ExperienceError("no alpha PlanProposal exists; run promin init")
    progress_path = root / ".promin" / "state" / "experience" / "progress.json"
    completed: set[str] = set()
    if os.path.isfile(filesystem_path(progress_path)):
        value = load_json_strict(progress_path, root=progress_path.parent)
        if isinstance(value, Mapping) and isinstance(value.get("completed_task_ids"), list):
            completed = {str(item) for item in value["completed_task_ids"]}
    for task in proposal.get("tasks", []):
        if task.get("task_id") in completed:
            continue
        if any(dependency not in completed for dependency in task.get("depends_on", [])):
            continue
        plan = load_resolved_plan(root) or {}
        context_limit = 8192
        if "tower-strong" in plan.get("profile_layers", []):
            context_limit = 16384
        identity = {
            "record_type": "SuggestedWorkCard",
            "task": task,
            "goal": proposal.get("goal"),
            "project_mode": proposal.get("project_mode"),
            "profile_layers": plan.get("profile_layers", []),
            "autonomy": plan.get("autonomy", "safe-auto"),
            "max_context_bytes": context_limit,
            "authority": False,
            "pass_credit": False,
            "note": "Proposal-only card; strict Core Task/Grant flow is required before authoritative mutation or acceptance.",
        }
        return {**identity, "context_digest": digest_value(identity)}
    return {
        "record_type": "SuggestedWorkCard",
        "status": "no-ready-proposal",
        "authority": False,
        "pass_credit": False,
    }


def experience_status(project_root: Path | str) -> dict[str, Any]:
    root = Path(project_root).resolve()
    plan = load_resolved_plan(root)
    proposal = load_plan_proposal(root)
    bootstrap = load_bootstrap_state(root)
    return {
        "record_type": "AlphaExperienceStatus",
        "initialized": (root / ".promin" / "init" / "activation.json").is_file(),
        "project_mode": None if plan is None else plan.get("project_mode"),
        "goal": None if plan is None else plan.get("goal"),
        "profile_layers": [] if plan is None else plan.get("profile_layers", []),
        "autonomy": None if plan is None else plan.get("autonomy"),
        "reporting_language": None if plan is None else plan.get("reporting_language"),
        "proposal_task_count": 0 if proposal is None else len(proposal.get("tasks", [])),
        "bootstrap_status": None if bootstrap is None else bootstrap.get("status"),
        "first_task_id": None if bootstrap is None else bootstrap.get("task_id"),
        "heartbeat": heartbeat(root),
        "authority": False,
        "pass_credit": False,
    }


def write_plan(path: Path, plan: Mapping[str, Any]) -> None:
    _write_json(path, dict(plan))


def emit_expert_config(destination: Path, plan: Mapping[str, Any], project_root: Path) -> dict[str, Any]:
    if destination.exists():
        raise ExperienceError("expert config destination already exists")
    destination.mkdir(parents=True)
    core_plans = compile_core_plans(plan, project_root)
    for name, value in core_plans.items():
        _write_json(destination / name, value)
    for name, value in _config_documents(plan).items():
        _write_json(destination / f"alpha-{name}", value)
    _write_json(destination / "resolved-plan.json", dict(plan))
    return {
        "record_type": "ExpertConfigEmission",
        "status": "created",
        "directory": str(destination),
        "file_count": len(list(destination.iterdir())),
        "authority": False,
        "pass_credit": False,
    }


def _utc_second(offset_seconds: int = 0) -> str:
    from datetime import timedelta

    return (
        datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _grant_record(
    authority: Mapping[str, Any],
    activation_digest: str,
    *,
    grant_id: str,
    capability_id: str,
    issued_at: str,
    project_id: str,
    issuer: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz

    expires_at = (
        _dt.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_tz.utc)
        + _td(days=7 if issuer is not None else 30)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    record: dict[str, Any] = {
        "record_type": "Grant",
        "grant_id": grant_id,
        "subject_id": "owner",
        "capability_id": capability_id,
        "scope": [{"kind": "project", "value": project_id}],
        "activation_digest": activation_digest,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": "nonce-" + grant_id,
    }
    record["claim_digest"] = digest_value(record)
    if issuer is None:
        record["trust_proofs"] = [
            {
                "kind": "local-root",
                "root_subject_id": "owner",
                "authority_init_digest": digest_value(authority),
                "signed_claim_digest": record["claim_digest"],
            }
        ]
    else:
        record["trust_proofs"] = [
            {
                "kind": "issuer-grant",
                "issuer_grant_id": issuer["grant_id"],
                "issuer_signed_claim_digest": issuer["claim_digest"],
                "signed_claim_digest": record["claim_digest"],
            }
        ]
    return record


def _grant_authorization(grant: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "kind": "grant",
        "grant_id": grant["grant_id"],
        "grant_claim_digest": grant["claim_digest"],
    }


def _command_request(
    *,
    activation_digest: str,
    project_id: str,
    command_id: str,
    command_kind: str,
    payload: Mapping[str, Any],
    expected_head_digest: str | None,
    issued_at: str,
    authorization: Mapping[str, Any],
    effect_scope: Sequence[Mapping[str, str]] = (),
) -> dict[str, Any]:
    requested_scope: list[dict[str, str]] = [
        {"kind": "project", "value": project_id}
    ]
    task_id = payload.get("task_id")
    if isinstance(task_id, str):
        requested_scope.append({"kind": "task", "value": task_id})
    for selector in effect_scope:
        normalized = {"kind": str(selector["kind"]), "value": str(selector["value"])}
        if normalized not in requested_scope:
            requested_scope.append(normalized)
    command: dict[str, Any] = {
        "record_type": "CommandRequest",
        "command_id": command_id,
        "command_kind": command_kind,
        "subject_id": "owner",
        "activation_digest": activation_digest,
        "idempotency_key": "idempotency:" + command_id,
        "requested_scope": requested_scope,
        "expected_head_digest": expected_head_digest,
        "issued_at": issued_at,
        "payload": dict(payload),
    }
    command["intent_digest"] = digest_value(command)
    command["authorization"] = dict(authorization)
    return command


def _task_gate_definition(
    service: ProminService,
    task: Mapping[str, Any],
    *,
    head_digest: str,
) -> dict[str, Any]:
    value = dict(task)
    owner_digest = digest_value(
        {key: item for key, item in value.items() if key != "state"}
    )
    context = service._context()
    definition = {
        "definition_kind": "GateRunDefinition",
        "definition_id": "definition:alpha-initial-readonly",
        "owner_kind": "Task",
        "owner_digest": owner_digest,
        "defined_at_head_digest": head_digest,
        "gate_id": "gate:alpha-initial-readonly",
        "run_kind": "validation",
        "expected_evidence_class": "validator",
        "expected_evidence_purpose": "gate",
        "product_credit_required": False,
        "target_kind": "candidate",
        "target_digest": value["candidate_digest"],
        "target_scope": [
            {"kind": "candidate", "value": value["candidate_digest"]}
        ],
        "candidate_digest": value["candidate_digest"],
        "policy_digest": digest_value({"policy": "alpha-readonly-audit"}),
        "tool_digest": digest_value({"tool": "promin-audit"}),
        "implementation_closure_digest": context.implementation_closure_digest,
        "provider_binding_digest": digest_value(
            list(context.provider_dispatch.binding_evidence())
        ),
        "input_digests": [digest_value({"plan": value["task_id"]})],
        "activation_digest": value["activation_digest"],
    }
    value["gate_run_definitions"] = [
        {
            "definition_digest": digest_value(definition),
            "definition": definition,
        }
    ]
    return value


def load_bootstrap_state(project_root: Path | str) -> dict[str, Any] | None:
    path = (
        Path(project_root).resolve()
        / ".promin"
        / "generated"
        / "bootstrap-state.json"
    )
    if not os.path.isfile(filesystem_path(path)):
        return None
    value = load_json_strict(path, root=path.parent)
    return dict(value) if isinstance(value, Mapping) else None


def bootstrap_operational_state(
    project_root: Path | str,
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Create the minimal authoritative read-only workflow for deployable alpha.

    The bootstrap is idempotent through the generated binding and immutable event
    idempotency keys.  It does not grant product acceptance or release authority.
    """

    root = Path(project_root).resolve()
    service = ProminService(root)
    # Execute provider preflight on the same service context before status/commit.
    service.doctor(replay=False)
    existing = load_bootstrap_state(root)
    if existing is not None:
        try:
            status = service.status()
        except Exception as exc:
            raise ExperienceError(
                "bootstrap state exists but the control layer is unreadable"
            ) from exc
        return {
            **existing,
            "status": "idempotent",
            "current_head": status.get("head"),
        }
    status = service.status()
    head = status.get("head")
    if isinstance(head, Mapping) and int(head.get("sequence", 0)) != 0:
        raise ExperienceError(
            "operational history exists without a guided bootstrap binding"
        )
    context = service._context()
    activation_digest = context.activation_digest
    authority = context.plans["authority.json"]
    project_id = context.plans["project.json"]["project_id"]
    issued_at = _utc_second()
    manager = _grant_record(
        authority,
        activation_digest,
        grant_id="grant:alpha-owner-manager",
        capability_id="authority.manage",
        issued_at=issued_at,
        project_id=project_id,
    )
    bootstrap = _command_request(
        activation_digest=activation_digest,
        project_id=project_id,
        command_id="command:alpha-bootstrap-manager",
        command_kind="grant.issue",
        payload=manager,
        expected_head_digest=None,
        issued_at=issued_at,
        authorization={
            "kind": "root",
            "subject_id": "owner",
            "proofs": [
                {
                    "kind": "local-root-command",
                    "subject_id": "owner",
                    "authority_init_digest": digest_value(authority),
                    "signed_intent_digest": "0" * 64,
                }
            ],
        },
    )
    bootstrap["authorization"]["proofs"][0]["signed_intent_digest"] = bootstrap[
        "intent_digest"
    ]
    current_head = service.commit(bootstrap)["batch_digest"]
    grants: dict[str, dict[str, Any]] = {"manager": manager}
    for name, capability in (
        ("planner", "task.plan"),
        ("holder", "task.execute"),
        ("reader", "projection.read"),
        ("finder", "finding.record"),
        ("validator", "validation.evaluate"),
        ("publisher", "evidence.publish"),
    ):
        grant = _grant_record(
            authority,
            activation_digest,
            grant_id=f"grant:alpha-owner-{name}",
            capability_id=capability,
            issued_at=issued_at,
            project_id=project_id,
            issuer=manager,
        )
        command = _command_request(
            activation_digest=activation_digest,
            project_id=project_id,
            command_id=f"command:alpha-issue-{name}",
            command_kind="grant.issue",
            payload=grant,
            expected_head_digest=current_head,
            issued_at=issued_at,
            authorization=_grant_authorization(manager),
        )
        current_head = service.commit(command)["batch_digest"]
        grants[name] = grant

    specification_digest = str(plan["plan_digest"])
    candidate_identity = {
        "kind": "alpha-specification-candidate",
        "project_id": project_id,
        "plan_digest": specification_digest,
        "activation_digest": activation_digest,
    }
    candidate_digest = digest_value(candidate_identity)
    candidate = {
        "record_type": "Candidate",
        "candidate_id": "candidate:alpha-specification",
        "candidate_digest": candidate_digest,
        "inventory_digest": digest_value(
            {"kind": "specification-inventory", "plan": specification_digest}
        ),
        "product_root_digest": digest_value(
            {"kind": "specification-root", "project": project_id}
        ),
        "control_excluded": True,
        "candidate_recipe_digest": digest_value(
            context.plans["project.json"]["candidate_recipe"]
        ),
        "consistency_mode": "observational-best-effort",
        "creditable": False,
        "baseline_kind": "specification",
        "specification_digest": specification_digest,
    }
    candidate_command = _command_request(
        activation_digest=activation_digest,
        project_id=project_id,
        command_id="command:alpha-record-specification-candidate",
        command_kind="candidate.record",
        payload=candidate,
        expected_head_digest=current_head,
        issued_at=issued_at,
        authorization=_grant_authorization(grants["holder"]),
        effect_scope=[
            {"kind": "candidate", "value": candidate["candidate_id"]}
        ],
    )
    current_head = service.commit(candidate_command)["batch_digest"]

    mode = str(plan["project_mode"])
    first_operation = (
        "build-one-pass-inventory"
        if mode in {"existing-code", "hybrid"}
        else "build-specification-baseline"
    )
    model_tier = "tool-only" if first_operation == "build-one-pass-inventory" else "standard"
    task = {
        "record_type": "Task",
        "task_id": "task:alpha-first-operation",
        "state": "PLANNED",
        "required_capability": "task.execute",
        "acceptance_predicate": (
            "Produce bounded evidence for the first project operation without "
            "claiming product acceptance or public release."
        ),
        "allowed_paths": ["**"],
        "activation_digest": activation_digest,
        "candidate_digest": candidate_digest,
        "created_at": issued_at,
        "operation_profile_id": first_operation,
        "recommended_model_tier": model_tier,
        "orchestration_required": True,
    }
    task = _task_gate_definition(service, task, head_digest=current_head)
    task_command = _command_request(
        activation_digest=activation_digest,
        project_id=project_id,
        command_id="command:alpha-record-first-task",
        command_kind="task.record",
        payload=task,
        expected_head_digest=current_head,
        issued_at=issued_at,
        authorization=_grant_authorization(grants["planner"]),
    )
    current_head = service.commit(task_command)["batch_digest"]
    ready_command = _command_request(
        activation_digest=activation_digest,
        project_id=project_id,
        command_id="command:alpha-first-task-ready",
        command_kind="task.transition",
        payload={
            "task_id": task["task_id"],
            "from_state": "PLANNED",
            "to_state": "READY",
            "reason": "guided alpha plan is ready for one bounded operation",
        },
        expected_head_digest=current_head,
        issued_at=issued_at,
        authorization=_grant_authorization(grants["planner"]),
    )
    current_head = service.commit(ready_command)["batch_digest"]
    service.rebuild()
    next_result = service.next(
        subject_id="owner",
        grant_id=grants["holder"]["grant_id"],
        query_grant_id=grants["reader"]["grant_id"],
        depth=1,
    )
    identity = {
        "record_type": "AlphaBootstrapState",
        "activation_digest": activation_digest,
        "project_id": project_id,
        "candidate_id": candidate["candidate_id"],
        "candidate_digest": candidate_digest,
        "task_id": task["task_id"],
        "grants": {
            name: {
                "grant_id": grant["grant_id"],
                "claim_digest": grant["claim_digest"],
                "capability_id": grant["capability_id"],
            }
            for name, grant in sorted(grants.items())
        },
        "head_digest": current_head,
        "first_work_card": next_result.get("work_card"),
        "authority": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
    }
    result = {**identity, "bootstrap_digest": digest_value(identity), "status": "created"}
    _write_json(root / ".promin" / "generated" / "bootstrap-state.json", result)
    record_observation(
        root,
        kind="bootstrap-operational-state",
        status="pass",
        details={
            "task_id": task["task_id"],
            "operation": first_operation,
            "model_tier": model_tier,
            "component": "orchestration",
        },
    )
    return result
