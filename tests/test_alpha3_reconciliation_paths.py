from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

import promin.init as init_module
import promin.system_check as system_check
from promin.contracts import load_contract_bundle
from promin.platform_paths import (
    filesystem_path,
)


ROOT = Path(__file__).parents[1]


def _create_directory_alias(physical: Path, alias: Path) -> None:
    if os.name == "nt":
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(alias), str(physical)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
        return
    alias.symlink_to(physical, target_is_directory=True)


def test_sandbox_init_check_cleans_real_init_tree_through_junction_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    physical = tmp_path / "physical"
    physical.mkdir()
    alias = tmp_path / "alias"
    _create_directory_alias(physical, alias)
    monkeypatch.setenv("TEMP", str(alias))
    monkeypatch.setenv("TMP", str(alias))
    monkeypatch.setattr(tempfile, "tempdir", None)

    result = system_check._sandbox_init_check()

    assert result["status"] == "created"
    assert list(physical.iterdir()) == []


def test_bundle_install_uses_final_filesystem_boundary_for_deep_project_staging(
    tmp_path: Path,
) -> None:
    """A valid long project root may put private staging beyond Win32 MAX_PATH."""

    deep_root = tmp_path
    index = 0
    while len(str(deep_root)) < 220:
        deep_root = deep_root / (f"segment-{index:02d}-" + ("x" * 36))
        deep_root.mkdir()
        index += 1
    staging = deep_root / ".p-long-boundary"
    os.mkdir(filesystem_path(staging))
    bundle = load_contract_bundle(
        ROOT, ROOT / "presets" / "semantic-standard.json"
    )

    installed = init_module._install_bundle(staging, bundle)

    manifest = installed / "core" / "promin.manifest.json"
    assert os.path.isfile(filesystem_path(manifest))
    init_module._remove_staging(staging)
    assert not os.path.lexists(filesystem_path(staging))


def test_provider_process_transport_is_separate_from_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "provider.exe"
    executable.write_bytes(b"provider")
    binding = {"provider_id": "p", "invocation": {"kind": "executable"}}

    monkeypatch.setattr(init_module, "subprocess_path", lambda path: "TRANSPORT-ONLY")
    argv = init_module._spawn_provider_argv(binding, [str(executable)], tmp_path)

    assert argv == [str(executable.resolve())]
    assert init_module._spawn_provider_executable(argv) == "TRANSPORT-ONLY"
