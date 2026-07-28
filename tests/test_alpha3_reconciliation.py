from __future__ import annotations

import inspect
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest

import promin.init as init_module
import promin.system_check as system_check
from promin.contracts import load_contract_bundle
from promin.platform_paths import (
    filesystem_path,
    resolve_identity_path,
    resolved_temporary_directory,
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


def test_runtime_temporary_directories_have_one_identity_owner() -> None:
    offenders: list[str] = []
    for path in sorted((ROOT / "promin").glob("*.py")):
        if path.name == "platform_paths.py":
            continue
        source = path.read_text(encoding="utf-8")
        if "TemporaryDirectory(" in source:
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_resolved_temporary_directory_collapses_alias(tmp_path: Path) -> None:
    physical = tmp_path / "physical"
    physical.mkdir()
    alias = tmp_path / "alias"
    _create_directory_alias(physical, alias)

    with resolved_temporary_directory(prefix="promin-test-", dir=alias) as temporary:
        assert temporary.is_dir()
        assert temporary.parent == physical.resolve()
        assert resolve_identity_path(temporary, strict=True) == temporary


def test_resolved_temporary_directory_cleans_read_only_tree_through_alias(
    tmp_path: Path,
) -> None:
    physical = tmp_path / "physical"
    physical.mkdir()
    alias = tmp_path / "alias"
    _create_directory_alias(physical, alias)

    with resolved_temporary_directory(prefix="promin-test-", dir=alias) as temporary:
        protected = temporary / "standard" / "presets"
        protected.mkdir(parents=True)
        payload = protected / "profile.json"
        payload.write_text("{}", encoding="utf-8")
        os.chmod(payload, stat.S_IREAD)
        os.chmod(protected, stat.S_IREAD | stat.S_IEXEC)
        os.chmod(protected.parent, stat.S_IREAD | stat.S_IEXEC)
        cleanup_target = temporary

    assert not cleanup_target.exists()


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
        ROOT, ROOT / "presets" / "semantic-morok-tower.json"
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


def test_provider_process_creation_has_one_owner() -> None:
    source = (ROOT / "promin" / "init.py").read_text(encoding="utf-8")
    assert source.count("subprocess.run(") == 1
    assert "def _run_identity_process" in source
    assert "def _run_provider_process" in source
    assert "executable=_spawn_provider_executable" in source
    assert "subprocess_path(_init_identity_path" not in source


def test_provider_argv_builder_never_adds_transport_prefix() -> None:
    source = inspect.getsource(init_module._spawn_provider_argv)
    assert "subprocess_path" not in source
    assert "_init_identity_path" in source


def test_alias_ci_uses_readme_venv_default_store_and_deep_root() -> None:
    workflow = (ROOT / ".github" / "workflows" / "alpha-portability.yml").read_text(
        encoding="utf-8"
    )
    assert "python -m venv" in workflow
    assert "PROMIN_PROVIDER_STORE" in workflow
    assert "Remove-Item Env:PROMIN_PROVIDER_STORE" in workflow
    assert "TEMP" in workflow and "LOCALAPPDATA" in workflow
    assert "doctor --checklist" in workflow
    assert "status" in workflow
    assert "next" in workflow
    assert "test_alpha3_reconciliation.py" in workflow
