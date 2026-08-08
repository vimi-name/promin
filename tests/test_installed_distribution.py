from __future__ import annotations

import importlib.metadata
import os
from pathlib import Path
import platform
import sys
import sysconfig

import promin


def test_required_suite_uses_installed_distribution_when_declared() -> None:
    expected = os.environ.get("PROMIN_EXPECTED_INSTALLED_ROOT")
    expected_interpreter = os.environ.get("PROMIN_EXPECTED_INSTALLED_INTERPRETER")
    source_fixture = os.environ.get("PROMIN_SOURCE_FIXTURE_ROOT")
    expected_mode = os.environ.get("PROMIN_EXPECTED_INSTALL_MODE")
    expected_platform = os.environ.get("PROMIN_EXPECTED_PLATFORM")
    if expected is None and source_fixture is None:
        assert expected_mode is None
        assert expected_platform is None
        assert expected_interpreter is None
        return
    assert expected is not None
    assert source_fixture is not None
    assert expected_mode == "offline-wheelhouse"
    assert expected_platform in {"linux", "windows"}
    assert expected_platform == platform.system().casefold()
    assert expected_interpreter is not None
    module_file = Path(promin.__file__).resolve()
    installed_root = Path(expected).resolve()
    source_root = Path(source_fixture).resolve()
    interpreter = Path(sys.executable).resolve()
    assert interpreter == Path(expected_interpreter).resolve()
    prefix = Path(sys.prefix).resolve()
    assert sys.flags.isolated == 1
    assert sys.flags.safe_path is True
    assert os.environ.get("PROMIN_INSTALLED_TEST_MODE") == "1"
    assert "PYTHONPATH" not in os.environ
    assert "PYTHONHOME" not in os.environ
    assert Path(sysconfig.get_paths()["purelib"]).resolve() == installed_root
    assert installed_root == module_file.parent or installed_root in module_file.parents
    assert source_root != module_file and source_root not in module_file.parents
    assert source_root != installed_root and source_root not in installed_root.parents
    assert installed_root not in source_root.parents
    assert prefix == interpreter.parent or prefix in interpreter.parents
    assert source_root != interpreter and source_root not in interpreter.parents
    assert str(source_root) not in [str(Path(item).resolve()) for item in sys.path if item]
    distribution = importlib.metadata.distribution("promin")
    from promin.version import python_distribution_version, standard_version

    assert distribution.version == python_distribution_version()
    assert promin.__version__ == standard_version()
    record = next(
        item
        for item in distribution.files or ()
        if str(item).replace("\\", "/").endswith(".dist-info/RECORD")
    )
    record_path = Path(distribution.locate_file(record)).resolve()
    assert record_path.is_file()
    assert installed_root in record_path.parents
    assert isinstance(sysconfig.get_config_var("SOABI"), str)
    assert sysconfig.get_config_var("SOABI")


def test_distribution_declares_portable_runtime_bundle_data() -> None:
    """The installed CLI must carry its canonical bundle instead of relying on the source tree."""

    import tomllib

    package_root = Path(__file__).resolve().parents[1]
    metadata = tomllib.loads((package_root / "pyproject.toml").read_text(encoding="utf-8"))
    data_files = metadata.get("tool", {}).get("setuptools", {}).get("data-files", {})
    expected = {
        "share/promin": {"LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "VERSION.json"},
        "share/promin/core": {"core/*.json"},
        "share/promin/presets": {"presets/*.json"},
        "share/promin/profiles": {"profiles/*.json", "profiles/README.md"},
        "share/promin/capability_profiles": {"capability_profiles/*.json"},
        "share/promin/language_profiles": {"language_profiles/*.json"},
        "share/promin/skills": {"skills/README.md", "skills/skill.schema.json"},
        "share/promin/skills/example": {
            "skills/example/SKILL.md",
            "skills/example/promin.skill.json",
        },
        "share/promin/prompts": {"prompts/*.txt"},
    }
    assert set(data_files) == set(expected)
    for destination, sources in expected.items():
        assert set(data_files[destination]) == sources
