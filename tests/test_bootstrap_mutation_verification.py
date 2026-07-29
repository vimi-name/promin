from __future__ import annotations

from pathlib import Path

from promin.experience import apply_plan, resolve_plan
from promin import service as service_module


def test_bootstrap_reuses_one_authoritative_mutation_verification(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """The dependent bootstrap commands share one verified service boundary.

    Bootstrap commands intentionally remain individually journaled: every
    command binds the preceding HEAD and must therefore preserve its event
    ordering and recovery semantics.  The service cache may only remove
    redundant byte verification while the Activation-bound filesystem inputs
    remain unchanged.
    """

    original_verify = service_module.verify_before_mutation
    calls = 0

    def counted_verify(project_root: Path | str, **kwargs):
        nonlocal calls
        calls += 1
        return original_verify(project_root, **kwargs)

    monkeypatch.setattr(service_module, "verify_before_mutation", counted_verify)

    plan = resolve_plan(tmp_path, goal="Create a small reliable tool", language="en")
    result = apply_plan(tmp_path, plan)

    assert result["status"] == "created"
    assert calls == 1
