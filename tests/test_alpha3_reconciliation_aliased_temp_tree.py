from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from promin.platform_paths import resolve_identity_path, resolved_temporary_directory


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
