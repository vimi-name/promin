"""Bounded runtime/repository self-audit for promin alpha."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import digest_value
from .telemetry import heartbeat, record_observation, utc_now

_SOURCE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".cs", ".go", ".java",
    ".js", ".jsx", ".kt", ".kts", ".m", ".mm", ".php", ".py", ".rb",
    ".rs", ".swift", ".ts", ".tsx", ".vue", ".svelte", ".dart",
}
_IGNORED_DIRS = {
    ".git", ".promin", ".promin-host", ".venv", "venv", "node_modules",
    "build", "dist", "target", "coverage", "vendor", "__pycache__",
}
_LARGE_FILE_LINES = 1000
_MAX_DUPLICATE_CLUSTERS = 64
_MAX_FINDINGS = 128


class AuditError(RuntimeError):
    pass


_DUPLICATE_NAME_MARKER = re.compile(
    r"(?:\(\d+\)$|~$|(?:^|[._\-\s])(?:copy|backup|old|legacy|bak|v\d+|final(?:[._\-\s]?\d+)?|new(?:[._\-\s]?\d+)?|\d+)$)",
    re.IGNORECASE,
)


def duplicate_name_markers(paths: list[str] | tuple[str, ...], *, limit: int = 16) -> dict[str, Any]:
    """Return bounded filename markers without claiming semantic duplication.

    Exact/content duplication remains owned by ``audit_project``.  This helper is
    shared with guided init only as a low-confidence naming signal.
    """

    matches = [
        path
        for path in sorted(set(paths))
        if _DUPLICATE_NAME_MARKER.search(Path(path).stem)
    ]
    return {
        "examples": matches[: max(0, limit)],
        "total_count": len(matches),
    }


def _iter_files(root: Path, *, max_files: int, max_total_bytes: int) -> tuple[list[Path], int, bool]:
    files: list[Path] = []
    total = 0
    truncated = False
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            [name for name in dirnames if name not in _IGNORED_DIRS and not name.startswith(".pytest")]
        )
        base = Path(current)
        for name in sorted(filenames):
            path = base / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                relative = path.relative_to(root).as_posix()
                if relative in {"AGENTS.md", "CLAUDE.md"} or relative.startswith((".agents/", ".claude/", ".cursor/")):
                    continue
                if path.suffix.casefold() not in _SOURCE_SUFFIXES:
                    continue
                size = path.stat().st_size
            except OSError:
                continue
            if len(files) >= max_files or total + size > max_total_bytes:
                truncated = True
                return files, total, truncated
            files.append(path)
            total += size
    return files, total, truncated


def _finding(
    finding_id: str,
    kind: str,
    title: str,
    *,
    severity: str,
    evidence: list[dict[str, Any]],
    confidence: str = "high",
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "finding_kind": kind,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "evidence_class": "measured" if kind in {"exact-duplicate", "large-file"} else "inferred",
        "evidence": evidence,
        "details": dict(details or {}),
        "authority": False,
        "pass_credit": False,
    }


def _plan_from_findings(root: Path, findings: list[dict[str, Any]], audit_digest: str) -> dict[str, Any]:
    tasks = []
    previous: str | None = None
    for index, finding in enumerate(findings[:32], start=1):
        task_id = f"audit-plan:{index:03d}:{finding['finding_id']}"
        tasks.append(
            {
                "task_id": task_id,
                "title": f"Validate and address {finding['title']}",
                "operation": "read",
                "depends_on": [] if previous is None else [previous],
                "acceptance_predicate": "The finding is validated with repository-bound evidence and no unsupported deletion or pass claim.",
                "allowed_paths": [item.get("path", "**") for item in finding.get("evidence", [])[:8]] or ["**"],
                "source_bindings": [audit_digest, finding["finding_id"]],
                "authority": False,
                "pass_credit": False,
            }
        )
        previous = task_id
    identity = {
        "record_type": "PlanProposal",
        "proposal_id": f"runtime-audit:{audit_digest[:24]}",
        "project_id": root.name or "project",
        "project_mode": "existing-code",
        "goal": "Reduce evidence-backed operational and repository risks discovered by promin audit.",
        "source_plan_digest": audit_digest,
        "created_at": utc_now(),
        "tasks": tasks,
        "authority": False,
        "pass_credit": False,
    }
    return {**identity, "proposal_digest": digest_value(identity)}


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def audit_project(
    project_root: Path | str,
    *,
    since_seconds: int | None = None,
    build_plan: bool = False,
    max_files: int = 10_000,
    max_total_bytes: int = 256 * 1024 * 1024,
    persist: bool = False,
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    if not root.is_dir():
        raise AuditError("project root is not a directory")
    files, scanned_bytes, truncated = _iter_files(
        root,
        max_files=max(1, max_files),
        max_total_bytes=max(1, max_total_bytes),
    )

    hashes: dict[str, list[Path]] = defaultdict(list)
    findings: list[dict[str, Any]] = []
    for path in files:
        try:
            payload = path.read_bytes()
        except OSError:
            continue
        relative = path.relative_to(root).as_posix()
        hashes[hashlib.sha256(payload).hexdigest()].append(path)
        line_count = payload.count(b"\n") + (1 if payload and not payload.endswith(b"\n") else 0)
        if line_count >= _LARGE_FILE_LINES:
            findings.append(
                _finding(
                    f"AUD-LARGE-{len(findings)+1:03d}",
                    "large-file",
                    f"Large source file: {relative}",
                    severity="high" if line_count >= 5000 or len(payload) >= 2 * 1024 * 1024 else "medium",
                    evidence=[{"path": relative, "line_count": line_count, "size_bytes": len(payload)}],
                    details={"interpretation": "signal-only; inspect responsibility and change history before refactoring"},
                )
            )

    duplicate_clusters: list[dict[str, Any]] = []
    for digest, paths in sorted(hashes.items()):
        if len(paths) < 2:
            continue
        relative_paths = sorted(path.relative_to(root).as_posix() for path in paths)
        cluster_id = f"DUP-{len(duplicate_clusters)+1:03d}"
        cluster = {
            "cluster_id": cluster_id,
            "duplicate_type": "exact",
            "content_sha256": digest,
            "paths": relative_paths,
            "decision": "investigate-runtime-use",
            "authority": False,
        }
        duplicate_clusters.append(cluster)
        findings.append(
            _finding(
                f"AUD-{cluster_id}",
                "exact-duplicate",
                f"Exact duplicate source cluster {cluster_id}",
                severity="medium",
                evidence=[{"path": path, "content_sha256": digest} for path in relative_paths],
                details={"safe_removal": False, "required_validation": "runtime consumers and unique behavior"},
            )
        )
        if len(duplicate_clusters) >= _MAX_DUPLICATE_CLUSTERS:
            break

    hb = heartbeat(root)
    self_observations = [
        {
            "kind": item.get("kind"),
            "status": item.get("status"),
            "fingerprint": item.get("fingerprint"),
            "occurrence_count": item.get("occurrence_count"),
            "last_seen": item.get("last_seen"),
            "evidence_class": "measured",
        }
        for item in hb.get("top_active", [])[:32]
    ]

    findings = findings[:_MAX_FINDINGS]
    identity = {
        "record_type": "ProminRuntimeAudit",
        "status": "degraded" if findings else "healthy",
        "audited_at": utc_now(),
        "project_root": ".",
        "since_seconds": since_seconds,
        "files_examined": len(files),
        "bytes_examined": scanned_bytes,
        "scan_truncated": truncated,
        "duplicate_clusters": duplicate_clusters,
        "findings": findings,
        "finding_count": len(findings),
        "heartbeat": hb,
        "self_observations": self_observations,
        "implemented_repository_observation_classes": ["large-file", "exact-duplicate"],
        "implemented_self_observation_classes": ["operational-error"],
        "claim_classes": ["measured", "inferred"],
        "authority": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
        "public_release_approved": False,
    }
    audit_digest = digest_value(identity)
    result: dict[str, Any] = {**identity, "audit_digest": audit_digest}
    if build_plan:
        result["plan_proposal"] = _plan_from_findings(root, findings, audit_digest)

    if persist:
        try:
            _atomic_json(root / ".promin" / "generated" / "audits" / "latest.json", result)
        except OSError:
            pass
        record_observation(
            root,
            kind="runtime-audit",
            status="degraded" if findings else "pass",
            details={
                "component": "audit",
                "finding_count": len(findings),
                "duplicate_cluster_count": len(duplicate_clusters),
                "scan_truncated": truncated,
            },
        )
    return result
