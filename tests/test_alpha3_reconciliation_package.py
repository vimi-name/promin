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
from promin_validate import (  # noqa: E402
    CANONICAL_PAYLOAD_FILES,
    validate_tree,
    verify_package_integrity,
)


def _canonical_package_copy(destination: Path) -> Path:
    package = destination / "promin"
    package.mkdir(parents=True, exist_ok=True)
    for relative_path in sorted(CANONICAL_PAYLOAD_FILES, key=lambda path: path.encode("utf-8")):
        source = ROOT / relative_path
        target = package / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
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


def test_archive_build_defers_pdf_parsing_to_clean_extraction(monkeypatch) -> None:
    """The candidate check parses the bytes that are actually archived once."""

    calls: list[bool] = []

    def tracked_validate_tree(*args, **kwargs):
        calls.append(kwargs["require_docs"])
        return validate_tree(*args, **kwargs)

    with tempfile.TemporaryDirectory(prefix="promin-r2-package-") as temporary_name:
        temporary = Path(temporary_name)
        package = _canonical_package_copy(temporary)
        archive = temporary / "candidate.zip"

        monkeypatch.setattr("promin_package.validate_tree", tracked_validate_tree)
        build_archive(package, archive, install_mode=None)

    assert calls == [False, False, True]
