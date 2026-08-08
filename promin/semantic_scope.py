"""Bounded semantic scope for C/C++ analysis.

This module owns only reverse-dependency scope calculation.  Gate invalidation
and cheapest-sufficient execution policy are canonical in
``promin.gate_admission``; keeping them there prevents two authority surfaces
from classifying the same change differently.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Iterable, Mapping, Sequence

from .language_analysis import AnalysisError, GateStatus


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ModuleGraph:
    """Canonical reverse dependency edges: imported unit -> dependent units."""

    reverse_edges: Mapping[str, tuple[str, ...]]
    digest: str


@dataclass(frozen=True)
class AffectedSemanticScope:
    status: GateStatus
    changed_paths: tuple[str, ...]
    paths: tuple[str, ...]
    graph_digest: str
    compilation_database_digest: str | None
    max_depth: int
    max_files: int
    truncated: bool
    errors: tuple[str, ...]
    digest: str
    pass_credit: bool = False
    acceptance_pass: bool = False


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _safe_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        raise AnalysisError("semantic path must be a non-empty POSIX relative path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} or "\x00" in part for part in parts):
        raise AnalysisError("semantic path contains an invalid segment")
    return value


def _canonical_path_tuple(values: Iterable[str], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise AnalysisError(f"{label} must be an iterable of paths, not one string")
    try:
        materialized = tuple(values)
    except TypeError as exc:
        raise AnalysisError(f"{label} must be an iterable of paths") from exc
    normalized_values = tuple(_safe_relative_path(item) for item in materialized)
    if len(normalized_values) != len(set(normalized_values)):
        raise AnalysisError(f"{label} contains duplicate paths")
    normalized = tuple(sorted(normalized_values))
    if not normalized:
        raise AnalysisError(f"{label} must not be empty")
    return normalized


def build_module_graph(reverse_dependencies: Mapping[str, Iterable[str]]) -> ModuleGraph:
    """Bind a fully supplied canonical reverse graph; no source scan is hidden."""

    if not isinstance(reverse_dependencies, Mapping) or not reverse_dependencies:
        raise AnalysisError("module graph must be a non-empty reverse dependency mapping")
    normalized: dict[str, tuple[str, ...]] = {}
    for source, dependents in reverse_dependencies.items():
        source_path = _safe_relative_path(source)
        if isinstance(dependents, (str, bytes)):
            raise AnalysisError("module graph dependents must be a path iterable")
        materialized = tuple(dependents)
        values = _canonical_path_tuple(materialized, f"dependents for {source_path}") if materialized else ()
        if source_path in values:
            raise AnalysisError("module graph must not contain a self reverse dependency")
        normalized[source_path] = values
    # Leaves must be explicit so a later scope cannot silently treat an omitted
    # node as an empty canonical graph entry.
    missing = sorted({item for values in normalized.values() for item in values} - set(normalized))
    if missing:
        raise AnalysisError(f"module graph omits explicit leaf entries: {missing}")
    ordered = {path: normalized[path] for path in sorted(normalized)}
    digest = hashlib.sha256(_canonical_bytes({"reverse_edges": ordered})).hexdigest()
    return ModuleGraph(reverse_edges=ordered, digest=digest)


def _scope_result(
    *,
    status: GateStatus,
    changed_paths: tuple[str, ...],
    paths: tuple[str, ...],
    graph: ModuleGraph,
    compilation_database_digest: str | None,
    max_depth: int,
    max_files: int,
    truncated: bool,
    errors: Sequence[str],
) -> AffectedSemanticScope:
    identity = {
        "status": status.value,
        "changed_paths": changed_paths,
        "paths": paths,
        "graph_digest": graph.digest,
        "compilation_database_digest": compilation_database_digest,
        "max_depth": max_depth,
        "max_files": max_files,
        "truncated": truncated,
        "errors": tuple(errors),
    }
    return AffectedSemanticScope(
        status=status,
        changed_paths=changed_paths,
        paths=paths,
        graph_digest=graph.digest,
        compilation_database_digest=compilation_database_digest,
        max_depth=max_depth,
        max_files=max_files,
        truncated=truncated,
        errors=tuple(errors),
        digest=hashlib.sha256(_canonical_bytes(identity)).hexdigest(),
    )


def affected_semantic_scope(
    *,
    changed_paths: Iterable[str],
    graph: ModuleGraph,
    compilation_database_digest: str | None,
    compilation_database_sources: Iterable[str] | None,
    max_depth: int,
    max_files: int,
) -> AffectedSemanticScope:
    """Compute an exact, bounded reverse closure with explicit truncation."""

    if not isinstance(graph, ModuleGraph):
        raise AnalysisError("affected semantic scope requires a canonical ModuleGraph")
    changed = _canonical_path_tuple(changed_paths, "changed_paths")
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 0:
        raise AnalysisError("max_depth must be a non-negative integer")
    if not isinstance(max_files, int) or isinstance(max_files, bool) or max_files < len(changed):
        raise AnalysisError("max_files must be an integer large enough for the changed paths")
    if compilation_database_digest is None or compilation_database_sources is None:
        return _scope_result(
            status=GateStatus.UNAVAILABLE,
            changed_paths=changed,
            paths=changed,
            graph=graph,
            compilation_database_digest=compilation_database_digest,
            max_depth=max_depth,
            max_files=max_files,
            truncated=False,
            errors=("canonical compilation database binding is unavailable",),
        )
    if not isinstance(compilation_database_digest, str) or not _HEX64.fullmatch(compilation_database_digest):
        return _scope_result(
            status=GateStatus.FAIL,
            changed_paths=changed,
            paths=changed,
            graph=graph,
            compilation_database_digest=compilation_database_digest,
            max_depth=max_depth,
            max_files=max_files,
            truncated=False,
            errors=("canonical compilation database digest is invalid",),
        )
    database_sources = _canonical_path_tuple(compilation_database_sources, "compilation_database_sources")
    selected: set[str] = set(changed)
    queue: list[tuple[str, int]] = [(path, 0) for path in changed]
    truncated = False
    while queue:
        current, depth = queue.pop(0)
        dependents = graph.reverse_edges.get(current)
        if dependents is None:
            return _scope_result(
                status=GateStatus.FAIL,
                changed_paths=changed,
                paths=tuple(sorted(selected)),
                graph=graph,
                compilation_database_digest=compilation_database_digest,
                max_depth=max_depth,
                max_files=max_files,
                truncated=truncated,
                errors=(f"canonical module graph has no entry for {current}",),
            )
        if depth >= max_depth:
            if dependents:
                truncated = True
            continue
        for dependent in dependents:
            if dependent in selected:
                continue
            if len(selected) >= max_files:
                truncated = True
                continue
            selected.add(dependent)
            queue.append((dependent, depth + 1))
    paths = tuple(sorted(selected))
    uncovered = tuple(path for path in paths if path not in database_sources)
    if uncovered:
        return _scope_result(
            status=GateStatus.FAIL,
            changed_paths=changed,
            paths=paths,
            graph=graph,
            compilation_database_digest=compilation_database_digest,
            max_depth=max_depth,
            max_files=max_files,
            truncated=truncated,
            errors=(f"canonical compilation database does not cover selected scope: {list(uncovered)}",),
        )
    return _scope_result(
        status=GateStatus.UNAVAILABLE if truncated else GateStatus.PASS,
        changed_paths=changed,
        paths=paths,
        graph=graph,
        compilation_database_digest=compilation_database_digest,
        max_depth=max_depth,
        max_files=max_files,
        truncated=truncated,
        errors=("affected semantic scope was explicitly truncated",) if truncated else (),
    )
