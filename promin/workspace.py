"""Bounded, deterministic navigation for heterogeneous repositories.

A single promin control layer owns the repository.  ``WorkspaceMap`` is a
rebuildable navigation projection that partitions a monorepo into project units
(web, Android/mobile, native Windows, backend/service, libraries, and root
applications) without creating a second control plane per application.
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import PurePosixPath
from typing import Any, Mapping, Sequence

from .canonical import digest_value

_COMPONENT_MANIFESTS = {
    "package.json",
    "pyproject.toml",
    "cargo.toml",
    "go.mod",
    "cmakelists.txt",
    "cmakepresets.json",
    "settings.gradle",
    "settings.gradle.kts",
    "build.gradle",
    "build.gradle.kts",
    "androidmanifest.xml",
    "pubspec.yaml",
    "package.swift",
    "supabase.toml",
}
_WINDOWS_SUFFIXES = {".sln", ".vcxproj", ".csproj", ".fsproj"}
_SOURCE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".kts",
    ".cpp", ".cxx", ".cc", ".c", ".h", ".hpp", ".cs", ".rs",
    ".go", ".swift", ".dart", ".vue", ".svelte",
}
_ID_RE = re.compile(r"[^a-z0-9._-]+")


class WorkspaceError(RuntimeError):
    pass


def _safe_id(value: str, fallback: str = "unit") -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    normalized = _ID_RE.sub("-", normalized.casefold()).strip("-._") or fallback
    return normalized[:96]


def _unit_id(root: str, kind: str) -> str:
    base = "root" if root == "." else root.replace("/", "-")
    suffix = kind.removesuffix("-application").removesuffix("-service")
    return _safe_id(f"{base}-{suffix}")


def _package_dependencies(sample: str) -> set[str]:
    try:
        value = json.loads(sample)
    except (TypeError, json.JSONDecodeError):
        return set()
    if not isinstance(value, dict):
        return set()
    result: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        section = value.get(key)
        if isinstance(section, dict):
            result.update(str(name).casefold() for name in section)
    return result


def _workspace_patterns(sample: str) -> list[str]:
    try:
        value = json.loads(sample)
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(value, dict):
        return []
    raw = value.get("workspaces")
    if isinstance(raw, dict):
        raw = raw.get("packages")
    if not isinstance(raw, list):
        return []
    result: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item or item.startswith("/"):
            continue
        if ".." in PurePosixPath(item).parts:
            continue
        result.append(item.rstrip("/"))
    return result[:128]


def _parent(path: str) -> str:
    parent = PurePosixPath(path).parent.as_posix()
    return "." if parent == "." else parent


def _is_manifest(path: str) -> bool:
    posix = PurePosixPath(path)
    return posix.name.casefold() in _COMPONENT_MANIFESTS or posix.suffix.casefold() in _WINDOWS_SUFFIXES


def _candidate_roots(preflight: Mapping[str, Any]) -> dict[str, set[str]]:
    paths = [
        str(item.get("path", ""))
        for item in preflight.get("entries", [])
        if isinstance(item, Mapping) and item.get("kind") == "file"
    ]
    roots: dict[str, set[str]] = {}
    for path in paths:
        if not _is_manifest(path):
            continue
        parent = _parent(path)
        name = PurePosixPath(path).name.casefold()
        if name == "androidmanifest.xml":
            # Prefer the nearest visible Gradle project root instead of app/src/main.
            selected = None
            for ancestor in PurePosixPath(parent).parents:
                candidate = "." if ancestor.as_posix() == "." else ancestor.as_posix()
                if any(
                    PurePosixPath(other).name.casefold()
                    in {"settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts"}
                    and _parent(other) == candidate
                    for other in paths
                ):
                    selected = candidate
                    break
            parent = selected or parent
        roots.setdefault(parent, set()).add(path)

    samples = preflight.get("manifest_samples", {})
    root_package = samples.get("package.json") if isinstance(samples, Mapping) else None
    if isinstance(root_package, str):
        for pattern in _workspace_patterns(root_package):
            if "*" not in pattern:
                roots.setdefault(pattern or ".", set()).add("package.json#workspaces")
                continue
            prefix = pattern.split("*", 1)[0].rstrip("/")
            for root in list(roots):
                if root != "." and (not prefix or root == prefix or root.startswith(prefix + "/")):
                    roots[root].add("package.json#workspaces")

    # Gradle settings and Visual Studio solutions are project aggregators.  Their
    # module manifests remain queryable through the local context index, but they
    # do not create a second top-level Promin unit unless they declare another
    # independent aggregator.  This keeps a mobile application navigable without
    # turning every Android module into a separate control surface.
    def manifest_names(root: str) -> set[str]:
        return {PurePosixPath(path.split("#", 1)[0]).name.casefold() for path in roots.get(root, set())}

    aggregator_roots: list[tuple[str, str]] = []
    for root in list(roots):
        names = manifest_names(root)
        if names & {"settings.gradle", "settings.gradle.kts"}:
            aggregator_roots.append((root, "gradle"))
        if any(name.endswith(".sln") for name in names):
            aggregator_roots.append((root, "visual-studio"))

    for candidate in list(roots):
        for owner, family in aggregator_roots:
            if candidate == owner or owner != "." and not candidate.startswith(owner + "/"):
                continue
            candidate_names = manifest_names(candidate)
            if family == "gradle" and candidate_names & {"settings.gradle", "settings.gradle.kts"}:
                continue
            if family == "visual-studio" and any(name.endswith(".sln") for name in candidate_names):
                continue
            if owner == "." or candidate.startswith(owner + "/"):
                roots.pop(candidate, None)
                break
    return roots


def _facts_for_root(
    root: str,
    preflight: Mapping[str, Any],
    manifests: Sequence[str],
    *,
    nested_roots: Sequence[str] = (),
) -> tuple[list[str], list[str], dict[str, int]]:
    prefix = "" if root == "." else root + "/"

    def owned_path(path: str) -> bool:
        if not path.startswith(prefix):
            return False
        for nested in nested_roots:
            if path == nested or path.startswith(nested + "/"):
                return False
        return True

    entries = [
        item
        for item in preflight.get("entries", [])
        if isinstance(item, Mapping) and owned_path(str(item.get("path", "")))
    ]
    samples = preflight.get("manifest_samples", {})
    technology: set[str] = set()
    evidence: list[str] = []
    suffix_counts: dict[str, int] = {}

    for path in manifests:
        if "#" not in path:
            evidence.append(path)
        lower = path.casefold()
        name = PurePosixPath(lower).name
        suffix = PurePosixPath(lower).suffix
        if name == "package.json":
            technology.add("node")
            sample = samples.get(path) if isinstance(samples, Mapping) else None
            if isinstance(sample, str):
                deps = _package_dependencies(sample)
                for dependency, fact in (
                    ("react", "react"), ("next", "nextjs"), ("vite", "vite"),
                    ("@supabase/supabase-js", "supabase"), ("vue", "vue"),
                    ("svelte", "svelte"), ("express", "express"),
                ):
                    if dependency in deps:
                        technology.add(fact)
        if name in {"settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts", "androidmanifest.xml"}:
            technology.update({"android", "gradle"})
        if name == "pyproject.toml":
            technology.add("python")
        if name == "cargo.toml":
            technology.add("rust")
        if name == "go.mod":
            technology.add("go")
        if name in {"cmakelists.txt", "cmakepresets.json"}:
            technology.add("cmake")
        if name == "pubspec.yaml":
            technology.update({"flutter", "dart"})
        if name == "package.swift":
            technology.add("swift")
        if name == "supabase.toml":
            technology.add("supabase")
        if suffix in _WINDOWS_SUFFIXES:
            technology.update({"windows-native", "visual-studio"})

    for item in entries[:8192]:
        path = str(item.get("path", ""))
        suffix = PurePosixPath(path).suffix.casefold()
        if suffix:
            suffix_counts[suffix] = suffix_counts.get(suffix, 0) + 1
        if suffix in {".js", ".jsx"}:
            technology.add("javascript")
        elif suffix in {".ts", ".tsx"}:
            technology.add("typescript")
        elif suffix == ".py":
            technology.add("python")
        elif suffix in {".kt", ".kts"}:
            technology.add("kotlin")
        elif suffix == ".java":
            technology.add("java")
        elif suffix in {".cpp", ".cxx", ".cc", ".c", ".h", ".hpp"}:
            technology.add("cpp")
        elif suffix == ".cs":
            technology.add("dotnet")
        elif suffix == ".rs":
            technology.add("rust")
        elif suffix == ".go":
            technology.add("go")
        elif suffix == ".swift":
            technology.add("swift")
        elif suffix == ".dart":
            technology.add("dart")
    return sorted(technology), sorted(set(evidence)), dict(sorted(suffix_counts.items()))


def _classify(root: str, technologies: set[str]) -> tuple[str, list[str], float]:
    tokens = set(root.casefold().split("/"))
    profiles: list[str] = []
    if technologies & {"android", "gradle", "kotlin"}:
        return "android-application", ["android-application"], 0.98
    if technologies & {"flutter", "dart"}:
        return "mobile-application", ["general-development"], 0.90
    if technologies & {"react", "nextjs", "vite", "vue", "svelte", "supabase"}:
        return "web-application", ["web-application"], 0.97
    if technologies & {"windows-native", "visual-studio"}:
        return "windows-application", ["windows-development"], 0.95
    if tokens & {"web", "frontend", "client"} and technologies & {"node", "javascript", "typescript"}:
        return "web-application", ["web-application"], 0.86
    if tokens & {"mobile", "android", "ios"}:
        return "mobile-application", profiles, 0.80
    if tokens & {"api", "backend", "server", "service", "services"}:
        return "service", profiles, 0.82
    if tokens & {"packages", "libs", "library", "shared"}:
        return "library", profiles, 0.80
    if technologies:
        return "application", profiles, 0.72
    return "unknown", profiles, 0.50


def discover_workspace_map(
    preflight: Mapping[str, Any],
    technologies: Sequence[Mapping[str, Any]] = (),
    signals: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Build one project-wide map from bounded preflight evidence.

    ``technologies`` and ``signals`` are accepted to keep the resolver and
    workspace detector on the same evidence packet. They do not create units by
    themselves; manifests and paths remain the unit boundary evidence.
    """

    roots = _candidate_roots(preflight)
    if not roots:
        roots = {".": set()}

    # Remove a pure umbrella root when concrete children exist and no root source
    # is visible. Keep it when the root itself is a real web/native application.
    if "." in roots and len(roots) > 1:
        root_sources = [
            str(item.get("path", ""))
            for item in preflight.get("entries", [])
            if isinstance(item, Mapping)
            and item.get("kind") == "file"
            and "/" not in str(item.get("path", ""))
            and PurePosixPath(str(item.get("path", ""))).suffix.casefold() in _SOURCE_SUFFIXES
        ]
        root_samples = preflight.get("manifest_samples", {})
        root_package = root_samples.get("package.json") if isinstance(root_samples, Mapping) else None
        root_deps = _package_dependencies(root_package) if isinstance(root_package, str) else set()
        root_is_application = bool(root_sources or root_deps & {"react", "next", "vite", "vue", "svelte", "express"})
        if not root_is_application:
            roots.pop(".", None)

    units: list[dict[str, Any]] = []
    seen: set[str] = set()
    ordered_roots = sorted(roots, key=lambda value: (value.count("/"), value.encode("utf-8")))
    for unit_root in ordered_roots:
        nested_roots = [
            candidate
            for candidate in ordered_roots
            if candidate != unit_root
            and candidate != "."
            and (unit_root == "." or candidate.startswith(unit_root + "/"))
        ]
        technology_ids, evidence, suffix_counts = _facts_for_root(
            unit_root,
            preflight,
            sorted(roots[unit_root]),
            nested_roots=nested_roots,
        )
        kind, profile_layers, confidence = _classify(unit_root, set(technology_ids))
        unit_id = _unit_id(unit_root, kind)
        if unit_id in seen:
            unit_id += "-" + digest_value({"path": unit_root, "kind": kind})[:8]
        seen.add(unit_id)
        identity = {
            "unit_id": unit_id,
            "path": unit_root,
            "kind": kind,
            "technology_ids": technology_ids,
            "profile_layers": profile_layers,
            "manifests": evidence[:64],
            "source_suffix_counts": suffix_counts,
            "confidence": confidence,
            "authoritative": False,
        }
        units.append({**identity, "unit_digest": digest_value(identity)})

    if not units:
        identity = {
            "unit_id": "root-unknown",
            "path": ".",
            "kind": "unknown",
            "technology_ids": [],
            "profile_layers": [],
            "manifests": [],
            "source_suffix_counts": {},
            "confidence": 0.4,
            "authoritative": False,
        }
        units = [{**identity, "unit_digest": digest_value(identity)}]

    relations = [
        {"relation": "contains", "from": "workspace", "to": unit["unit_id"]}
        for unit in units
    ]
    identity = {
        "record_type": "WorkspaceMap",
        "workspace_id": _safe_id(str(preflight.get("root_name") or "workspace"), "workspace"),
        "workspace_kind": "combined" if len(units) > 1 else "single",
        "one_control_layer": True,
        "unit_count": len(units),
        "units": units,
        "relations": relations,
        "navigation_policy": "top-level-map-then-task-scoped-unit-context",
        "cross_unit_navigation": True,
        "bounded_preflight": True,
        "preflight_truncated": bool(preflight.get("truncated")),
        "repository_signal_count": len(signals),
        "detected_technology_count": len(technologies),
        "authoritative": False,
        "pass_credit": False,
    }
    return {**identity, "workspace_map_digest": digest_value(identity)}


def unit_for_path(workspace: Mapping[str, Any], path: str) -> Mapping[str, Any] | None:
    normalized = (lambda value: value[2:] if value.startswith("./") else value.lstrip("/"))(PurePosixPath(path).as_posix())
    candidates: list[tuple[int, Mapping[str, Any]]] = []
    for unit in workspace.get("units", []):
        if not isinstance(unit, Mapping):
            continue
        root = str(unit.get("path", "."))
        if root == "." or normalized == root or normalized.startswith(root + "/"):
            candidates.append((0 if root == "." else root.count("/") + 1, unit))
    return max(candidates, key=lambda item: item[0])[1] if candidates else None


def workspace_navigation_summary(workspace: Mapping[str, Any], *, limit: int = 24) -> str:
    lines: list[str] = []
    for unit in workspace.get("units", [])[:limit]:
        if not isinstance(unit, Mapping):
            continue
        technologies = ", ".join(str(value) for value in unit.get("technology_ids", [])) or "unknown"
        lines.append(
            f"- `{unit.get('unit_id')}` → `{unit.get('path', '.')}` "
            f"({unit.get('kind', 'unit')}; {technologies})"
        )
    remaining = max(0, int(workspace.get("unit_count", len(lines))) - len(lines))
    if remaining:
        lines.append(f"- … {remaining} more units; query with `promin context --unit <id>`")
    return "\n".join(lines) or "- `root-unknown` → `.`"


# Compatibility aliases for internal alpha callers. They are not public identity
# aliases and can be removed after the next schema freeze.
def detect_workspace(project_root: object, preflight: Mapping[str, Any]) -> dict[str, Any]:
    del project_root
    return discover_workspace_map(preflight)


def component_for_path(workspace: Mapping[str, Any], path: str) -> Mapping[str, Any] | None:
    return unit_for_path(workspace, path)
