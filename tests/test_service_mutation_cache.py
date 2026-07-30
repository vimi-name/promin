from __future__ import annotations

import os
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


def test_mutation_cache_rejects_byte_substitution_with_restored_mtime(
    tmp_path: Path, monkeypatch
) -> None:
    """A bound receipt byte change is not hidden by restored file metadata."""

    control = tmp_path / ".promin"
    (control / "providers").mkdir(parents=True)
    bound = tmp_path / "bound.json"
    bound.write_bytes(b"{}")
    context = SimpleNamespace(control_root=control)
    monkeypatch.setattr(
        service_runtime,
        "activation_read_bindings",
        lambda _context: (("bound", bound, "file"),),
    )
    bindings = service_runtime._mutation_cache_bindings(context)
    baseline = service_runtime._fast_implementation_stat_fingerprint(
        context, tmp_path, bindings=bindings
    )
    assert baseline is not None

    original = bound.read_bytes()
    original_stat = bound.stat()
    substituted = bytes([original[0] ^ 1]) + original[1:]
    bound.write_bytes(substituted)
    os.utime(
        bound,
        ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
    )
    restored_stat = bound.stat()
    assert restored_stat.st_size == original_stat.st_size
    assert restored_stat.st_mtime_ns == original_stat.st_mtime_ns

    assert service_runtime._fast_implementation_stat_fingerprint(
        context, tmp_path, bindings=bindings
    ) != baseline
