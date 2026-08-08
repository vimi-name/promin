"""Bounded real-host Windows reconciliation route.

This lane intentionally executes the installed public CLI once per session.  The
other reconciliation lanes cover pure identity and static ownership rules;
keeping the host route here makes their timings independent of Windows setup.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

import pytest

from promin.platform_paths import filesystem_path


ROOT = Path(__file__).parents[1]

pytestmark = [
    pytest.mark.windows_integration,
    pytest.mark.skipif(os.name != "nt", reason="requires a real Windows host"),
]


@dataclass(frozen=True)
class WindowsCliRuntime:
    """One installed CLI and one provider/cache environment for this session."""

    command: tuple[str, ...]
    environment: Mapping[str, str]
    physical_temp: Path
    physical_cache: Path
    selected_temp: Path
    used_short_83_spelling: bool


def _create_junction(physical: Path, alias: Path) -> None:
    completed = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(alias), str(physical)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")


def _short_83_spelling(path: Path) -> Path | None:
    """Return an actual 8.3 spelling when the current volume exposes one."""

    import ctypes

    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, len(buffer))
    if not length or length >= len(buffer):
        return None
    candidate = Path(buffer.value)
    return candidate if str(candidate) != str(path) else None


def _non_c_fixed_volume() -> Path | None:
    """Return a writable local Windows volume other than C:, when one exists.

    A non-C route must be executed on a real volume.  Substituting a C: directory
    would turn this into a spelling-only test and would not cover the host-bound
    provider, staging, and SQLite paths that receive a different drive prefix.
    """

    import ctypes

    override = os.environ.get("PROMIN_TEST_NON_C_ROOT")
    if override:
        selected = Path(override).resolve(strict=True)
        if selected.drive.casefold() == "c:":
            raise AssertionError("PROMIN_TEST_NON_C_ROOT must not be on C:")
        return selected

    drive_mask = ctypes.windll.kernel32.GetLogicalDrives()
    drive_fixed = 3
    for letter in "DEFGHIJKLMNOPQRSTUVWXYZAB":
        root = Path(f"{letter}:\\")
        if not drive_mask & (1 << (ord(letter) - ord("A"))):
            continue
        if ctypes.windll.kernel32.GetDriveTypeW(str(root)) == drive_fixed:
            return root
    return None


def _remove_owned_fixture_path(operation: object, path: str, _error: object) -> None:
    """Permit teardown of Promin's deliberately read-only provider receipts."""

    os.chmod(path, stat.S_IWRITE)
    operation(path)  # type: ignore[operator]


@pytest.fixture
def non_c_non_ascii_root() -> Path:
    """Create an owned non-ASCII project root on a real non-C: volume."""

    volume = _non_c_fixed_volume()
    if volume is None:
        pytest.skip("requires a writable fixed Windows volume other than C:")
    base = Path(tempfile.mkdtemp(prefix="promin-київ-", dir=str(volume)))
    try:
        yield base / "проєкт-Львів"
    finally:
        shutil.rmtree(filesystem_path(base), onexc=_remove_owned_fixture_path)


@pytest.fixture(scope="session")
def windows_cli_runtime(tmp_path_factory: pytest.TempPathFactory) -> WindowsCliRuntime:
    """Prepare a single README-style installed CLI runtime for the host lane.

    CI supplies ``PROMIN_TEST_EXE`` from its session venv.  Local Windows runs use
    the current Python module entry point, avoiding a per-test venv/install while
    still exercising the public CLI boundary in a subprocess.
    """

    base = tmp_path_factory.mktemp("promin-windows-integration")
    physical_temp = base / "physical-temp"
    physical_cache = base / "physical-cache"
    physical_temp.mkdir()
    physical_cache.mkdir()
    temp_alias = base / "temp-alias"
    cache_alias = base / "cache-alias"
    _create_junction(physical_temp, temp_alias)
    _create_junction(physical_cache, cache_alias)

    short_temp = _short_83_spelling(physical_temp)
    selected_temp = short_temp or temp_alias
    executable = os.environ.get("PROMIN_TEST_EXE")
    command = (executable,) if executable else (sys.executable, "-m", "promin")
    assert all(Path(part).exists() for part in command[:1]), command

    environment = os.environ.copy()
    environment.update(
        {
            "TEMP": str(selected_temp),
            "TMP": str(selected_temp),
            "LOCALAPPDATA": str(cache_alias),
            "PROMIN_NO_TELEMETRY": "1",
        }
    )
    environment.pop("PROMIN_PROVIDER_STORE", None)
    return WindowsCliRuntime(
        command=command,
        environment=environment,
        physical_temp=physical_temp,
        physical_cache=physical_cache,
        selected_temp=selected_temp,
        used_short_83_spelling=short_temp is not None,
    )


def _deep_root(base: Path) -> Path:
    base.mkdir()
    root = base
    while len(str(root)) < 212:
        # Land at the acceptance boundary rather than accidentally making a
        # much longer fixture path than the documented >=212-character route.
        component_length = min(42, 212 - len(str(root)) - 1)
        root = root / ("x" * max(1, component_length))
        # This is fixture transport only: constructing the long root must not
        # fail in pathlib before the public CLI gets a chance to exercise it.
        os.mkdir(filesystem_path(root))
    assert len(str(root)) == 212
    return root


def _run_cli(runtime: WindowsCliRuntime, root: Path, *arguments: str) -> dict[str, object]:
    completed = subprocess.run(
        [*runtime.command, "--root", str(root), *arguments],
        cwd=ROOT,
        env=dict(runtime.environment),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=480,
    )
    assert completed.returncode == 0, (
        f"command={arguments!r}; returncode={completed.returncode}; "
        f"stdout={completed.stdout.decode('utf-8', 'replace')[-2048:]}; "
        f"stderr={completed.stderr.decode('utf-8', 'replace')[-2048:]}"
    )
    payload = json.loads(completed.stdout)
    assert isinstance(payload, dict)
    return payload


def test_windows_alias_83_deep_root_public_init_route(
    tmp_path: Path, windows_cli_runtime: WindowsCliRuntime
) -> None:
    """Prove one real Windows init route through alias/8.3 temp and deep root.

    Volumes where 8.3 creation is disabled still execute the required alias route
    through a junction; the assertion keeps that environmental fact explicit and
    never turns it into a skipped or synthetic success.
    """

    runtime = windows_cli_runtime
    assert runtime.selected_temp != runtime.physical_temp
    assert runtime.selected_temp.resolve() == runtime.physical_temp.resolve()
    root = _deep_root(tmp_path / "project")

    initialized = _run_cli(
        runtime,
        root,
        "init",
        "--goal",
        "Windows reconciliation route",
        "--documentation",
        "decline",
        "--verification",
        "decline",
        "--yes",
    )
    assert initialized.get("record_type") in {"InitializationResult", "InitResult"}

    doctor = _run_cli(runtime, root, "doctor", "--checklist")
    # Both optional tooling surfaces were explicitly declined above.  A real
    # Windows init and core health must still work, but the checklist must not
    # claim their documentation/context credit as a full pass.
    assert doctor.get("status") == "degraded"
    assert doctor.get("fail_count") == 0
    status = _run_cli(runtime, root, "status")
    assert status.get("status") in {"ready", "ready-for-inventory"}
    next_result = _run_cli(runtime, root, "next")
    assert next_result.get("record_type") == "SuggestedWorkCard"
    assert next_result.get("pass_credit") is False
    assert next_result.get("product_acceptance_pass") is False
    validated = _run_cli(runtime, root, "validate")
    assert validated.get("status") == "pass"

    default_store = runtime.physical_cache / "promin" / "provider-store-v1"
    assert default_store.is_dir()
    assert any(path.is_file() for path in default_store.rglob("*"))
    assert isinstance(runtime.used_short_83_spelling, bool)


def test_windows_non_c_non_ascii_root_public_init_route(
    non_c_non_ascii_root: Path, windows_cli_runtime: WindowsCliRuntime
) -> None:
    """Exercise init and validation on a real non-C:, non-ASCII project root."""

    runtime = windows_cli_runtime
    assert non_c_non_ascii_root.drive.casefold() != "c:"
    assert any(ord(character) > 127 for character in str(non_c_non_ascii_root))
    # The separate route above owns the MAX_PATH boundary.  Keep this fixture
    # focused on the independent non-C: and Unicode dimensions, so a failure
    # identifies the affected Windows variability rather than a combined path
    # length limit.
    root = non_c_non_ascii_root
    root.mkdir()

    initialized = _run_cli(
        runtime,
        root,
        "init",
        "--goal",
        "Windows non-C Unicode route",
        "--documentation",
        "decline",
        "--verification",
        "decline",
        "--yes",
    )
    assert initialized.get("record_type") in {"InitializationResult", "InitResult"}
    assert (root / ".promin").is_dir()
    doctor = _run_cli(runtime, root, "doctor", "--checklist")
    assert doctor.get("status") == "degraded"
    assert doctor.get("fail_count") == 0
    assert _run_cli(runtime, root, "validate").get("status") == "pass"

    # ``LOCALAPPDATA`` is redirected in the subprocess fixture.  Its physical
    # target, rather than the user's actual profile cache, must contain receipts.
    redirected_store = runtime.physical_cache / "promin" / "provider-store-v1"
    assert redirected_store.is_dir()
    assert any(path.is_file() for path in redirected_store.rglob("*"))
