from __future__ import annotations

from pathlib import Path

from promin.experience import apply_plan, resolve_plan
from promin import service as service_module


def test_guided_init_does_not_create_or_verify_a_legacy_generic_bootstrap(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Alpha.4 stops after minimal init until package tasks are imported.

    No generic bootstrap Task, Grant sequence, projection rebuild, or service
    mutation verification is allowed as an implicit side effect of guided init.
    Package-defined task import is a later explicit normative operation.
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
    assert calls == 0
    assert result["first_work_card"] is None
    assert result["minimal_postcheck"] == {
        "activation_present": True,
        "replay_performed": False,
        "first_work_card": "PENDING_PACKAGE_DEFINED_WORK_CARD",
    }
    assert not (tmp_path / ".promin" / "generated" / "bootstrap-state.json").exists()
