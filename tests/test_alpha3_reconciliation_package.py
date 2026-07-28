from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).parents[1]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from promin_package import build_archive, sync_version, verify_archive, write_integrity  # noqa: E402
from promin_validate import verify_package_integrity  # noqa: E402


def _canonical_package_copy(destination: Path) -> Path:
    package = destination / "promin"
    shutil.copytree(
        ROOT,
        package,
        ignore=shutil.ignore_patterns(
            "MANIFEST.json",
            "SHA256SUMS.txt",
            ".git",
            "__pycache__",
            "*.pyc",
            ".pytest_cache",
            ".mypy_cache",
            ".cache",
            "cache",
            "_work",
            ".venv",
            "venv",
            "build",
            "dist",
            "htmlcov",
            "*.egg-info",
        ),
    )
    sync_version(package)
    write_integrity(package)
    return package


def test_manifest_and_checksums_close_over_canonical_package_copy() -> None:
    with tempfile.TemporaryDirectory(prefix="promin-r2-package-") as temporary_name:
        package = _canonical_package_copy(Path(temporary_name))

        result = verify_package_integrity(package)

    assert result["closure"] is True
    assert result["inventory"]["files"] > 0
    assert result["inventory"]["directories"] > 0


def test_exact_archive_is_deterministic_and_cleanly_verifiable() -> None:
    with tempfile.TemporaryDirectory(prefix="promin-r2-package-") as temporary_name:
        temporary = Path(temporary_name)
        package = _canonical_package_copy(temporary)
        first = temporary / "first.zip"
        second = temporary / "second.zip"

        first_result = build_archive(package, first, install_mode=None)
        second_result = build_archive(package, second, install_mode=None)
        verified = verify_archive(first, install_mode=None)

        assert first_result["archive_sha256"] == second_result["archive_sha256"]
        assert first.read_bytes() == second.read_bytes()
        assert verified["clean_extraction"] is True
        assert verified["byte_deterministic"] is True
        assert verified["archive_sha256"] == verified["second_build_sha256"]
