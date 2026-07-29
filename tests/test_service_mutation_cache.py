from __future__ import annotations

from types import SimpleNamespace
from pathlib import Path

from promin import service as service_runtime


def test_mutation_cache_reuses_verified_bindings_and_rejects_provider_tree_drift(
    tmp_path: Path, monkeypatch
) -> None:
    """A cache hit keeps the original file set but not a mutable receipt tree."""

    control = tmp_path / ".promin"
    providers = control / "providers"
    component = providers / "provider-a" / "components" / "source"
    component.mkdir(parents=True)
    bound = tmp_path / "bound.json"
    bound.write_text("{}", encoding="utf-8")
    context = SimpleNamespace(control_root=control)
    calls = 0

    def exact_bindings(_context: object):
        nonlocal calls
        calls += 1
        return (("bound", bound, "file"),)

    monkeypatch.setattr(service_runtime, "activation_read_bindings", exact_bindings)
    bindings = service_runtime._mutation_cache_bindings(context)
    baseline = service_runtime._fast_implementation_stat_fingerprint(
        context, tmp_path, bindings=bindings
    )
    assert baseline is not None
    assert service_runtime._fast_implementation_stat_fingerprint(
        context, tmp_path, bindings=bindings
    ) == baseline
    assert calls == 1

    # A receipt file not present in the verified list still changes its parent
    # directory witness, so the service cannot reuse the byte-verified context.
    (component / "unexpected.json").write_text("{}", encoding="utf-8")
    assert service_runtime._fast_implementation_stat_fingerprint(
        context, tmp_path, bindings=bindings
    ) != baseline
