import importlib.util
import shutil
from pathlib import Path
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
TOOLS_ROOT = PACKAGE_ROOT / "tools"
_SPEC = importlib.util.spec_from_file_location(
    "promin_saturation_tool", TOOLS_ROOT / "promin_saturation.py"
)
assert _SPEC is not None and _SPEC.loader is not None
saturation = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(saturation)


def test_vcs_snapshot_disables_git_automatic_maintenance_for_real_add_and_commit(
    tmp_path: Path,
) -> None:
    git = shutil.which("git")
    assert git is not None
    workspace = tmp_path / "physical-saturation"
    product = workspace / "product"
    product.mkdir(parents=True)
    (product / "record.txt").write_text("promin fixture\n", encoding="utf-8")

    provider = {
        "provider_id": "fixture-git",
        "executable": git,
        "version": "fixture-v1",
    }

    commands: list[tuple[str, ...]] = []
    real_run = saturation.subprocess.run

    def record_run(*args: object, **kwargs: object):
        command = kwargs.get("args") if "args" in kwargs else args[0]
        recorded = tuple(str(value) for value in command)
        commands.append(recorded)
        return real_run(*args, **kwargs)

    with (
        mock.patch.object(saturation, "_snapshot_provider", return_value=provider),
        mock.patch.object(saturation.subprocess, "run", side_effect=record_run),
    ):
        descriptor = saturation._prepare_vcs_snapshot(workspace, reuse_product=False)

    for operation in ("add", "commit"):
        command = next(
            command
            for command in commands
            if operation in command and "-C" in command
        )
        assert ("-c", "maintenance.auto=false") in tuple(
            zip(command, command[1:])
        )

    assert descriptor["tree_file_count"] == "1"
    assert descriptor["vcs_maintenance_policy"] == {
        "automatic_maintenance": False,
        "git_config": "maintenance.auto=false",
        "operations": ["git add", "git commit"],
    }
