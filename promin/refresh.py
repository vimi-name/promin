"""One bounded refresh path for documentation, host pickup and local context."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .context_index import context_cost_model, sync_context_index
from .documentation import sync_documentation
from .gitpolicy import ensure_git_policy, sync_commit_surface
from .host_integration import sync_host_surfaces
from .telemetry import OperationTimer, record_observation


class RefreshError(RuntimeError):
    pass


def refresh_project(
    project_root: Path | str,
    *,
    deep_context: bool = False,
    apply: bool = True,
) -> dict[str, Any]:
    """Refresh all derived/portable surfaces from one hash inventory.

    ``deep_context`` is reserved for future language-aware source adapters. Alpha
    always indexes bounded project documentation/manifests and workspace summaries.
    """

    root = Path(project_root).resolve()
    from .experience import load_resolved_plan

    plan = load_resolved_plan(root)
    if plan is None:
        raise RefreshError("resolved plan is missing; run promin init or promin doctor --repair")
    timer = OperationTimer()

    # Git ignore policy is itself part of the product-tree view. Establish it
    # before the hash-driven documentation snapshot so refresh cannot make its
    # own snapshot stale by writing .gitignore afterwards.
    git_policy = ensure_git_policy(root, apply=apply)
    documentation = sync_documentation(root, plan, apply=apply)
    references = documentation.pop("reference_records", [])
    context = sync_context_index(root, plan, reference_records=references, apply=apply)
    hosts = sync_host_surfaces(root, language=str(plan.get("reporting_language") or "en"), apply=apply)
    commit = sync_commit_surface(root, plan, apply=apply)
    startup_tokens = int(
        (commit.get("footprint") or {}).get("startup_instruction_tokens", 0)
    )
    # Conservative Cyrillic-aware upper model for the default 16 KiB context
    # packet. Actual query results report their own estimate.
    token_cost = context_cost_model(
        startup_tokens=startup_tokens,
        query_tokens=int((16 * 1024 + 2) / 2.7),
        query_probability=0.70,
    )

    components = (git_policy, documentation, context, hosts, commit)
    blocked = any(isinstance(value, dict) and value.get("status") == "blocked" for value in components)
    changed = sum(
        len(value.get("written", [])) + len(value.get("changed", [])) + len(value.get("removed", []))
        for value in components if isinstance(value, dict)
    )
    if context.get("status") == "updated":
        changed += 1

    result = {
        "record_type": "ProminRefreshResult",
        "status": "blocked" if blocked else "updated" if changed else "current" if apply else "planned",
        "deep_context_requested": bool(deep_context),
        "deep_context_status": "alpha-deferred" if deep_context else "not-requested",
        "git_policy": git_policy,
        "documentation": documentation,
        "context_index": context,
        "host_integration": hosts,
        "commit_surface": commit,
        "token_cost_model": token_cost,
        "changed_operations": changed,
        "duration_ms": timer.duration_ms,
        "authority": False,
        "pass_credit": False,
    }
    if apply:
        record_observation(
            root,
            kind="refresh",
            status="blocked" if blocked else "pass",
            duration_ms=timer.duration_ms,
            details={
                "changed_operations": changed,
                "changed_units": len(documentation.get("changed_units", [])),
                "portable_documentation_bytes": documentation.get("portable_documentation_bytes", 0),
                "context_index_bytes": context.get("bytes", 0),
                "context_record_count": context.get("record_count", 0),
                "startup_instruction_tokens": (
                    hosts.get("startup_token_estimate", 0) if isinstance(hosts, dict) else 0
                ),
                "commit_surface_bytes": (
                    ((commit.get("footprint") or {}).get("total_bytes", 0))
                    if isinstance(commit, dict) else 0
                ),
                "component": "documentation-context-host",
            },
        )
    return result
