from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from promin.final_admission import (
    FinalAdmissionError,
    admit_final_package,
    verify_final_archive,
)


def _make_source(tmp_path: Path) -> tuple[Path, Path, list[str]]:
    source = tmp_path / "source"
    output = tmp_path / "external-output"
    (source / ".github" / "workflows").mkdir(parents=True)
    (source / "promin").mkdir(parents=True)
    (source / ".promin" / "state").mkdir(parents=True)
    (source / "__pycache__").mkdir(parents=True)
    output.mkdir()
    (source / ".github" / "workflows" / "check.yml").write_text("name: check\n", encoding="utf-8")
    (source / "README.md").write_text("portable standard\n", encoding="utf-8")
    (source / "promin" / "core.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / ".promin" / "state" / "projection.sqlite3").write_bytes(b"not portable")
    (source / "__pycache__" / "core.pyc").write_bytes(b"compiled")
    return source, output, [".github/workflows/check.yml", "README.md", "promin/core.py"]


def _payloads(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_final_admission_builds_external_byte_identical_candidate(tmp_path: Path) -> None:
    source, output, tracked = _make_source(tmp_path)
    before = _payloads(source)

    record = admit_final_package(source, output, tracked_paths=tracked)

    candidate = output / "promin-standard-candidate.zip"
    receipt = output / "final-package-admission.json"
    assert candidate.is_file()
    assert receipt.is_file()
    assert _payloads(source) == before
    assert record["status"] == "candidate"
    assert record["acceptance_pass"] is False
    assert record["pass_credit"] is False
    assert record["product_acceptance_pass"] is False
    assert record["source_unchanged"] is True
    assert record["byte_identical_archives"] is True
    assert (
        record["independent_generation_a"]["archive_sha256"]
        == record["independent_generation_b"]["archive_sha256"]
    )
    assert any(item["path"].startswith(".promin/") for item in record["delete_manifest"])
    assert str(source) not in json.dumps(record, ensure_ascii=False)
    with zipfile.ZipFile(candidate) as archive:
        assert archive.namelist() == [
            "promin/.github/workflows/check.yml",
            "promin/README.md",
            "promin/promin/core.py",
        ]
        assert not any(name.startswith("promin/.promin/") for name in archive.namelist())
    verified = verify_final_archive(
        candidate,
        record["source_file_manifest"],
        archive_prefix=record["archive_prefix"],
    )
    assert verified["archive_sha256"] == record["self_verification"]["archive_sha256"]
    assert sorted(path.name for path in output.iterdir()) == [
        "final-package-admission.json",
        "promin-standard-candidate.zip",
    ]


def test_final_admission_rejects_unknown_source_file(tmp_path: Path) -> None:
    source, output, tracked = _make_source(tmp_path)
    (source / "unowned.txt").write_text("not in boundary\n", encoding="utf-8")

    with pytest.raises(FinalAdmissionError, match="outside the declared tracked boundary"):
        admit_final_package(source, output, tracked_paths=tracked)

    assert list(output.iterdir()) == []


def test_final_admission_never_writes_to_source_descendant(tmp_path: Path) -> None:
    source, _, tracked = _make_source(tmp_path)
    nested_output = source / "external-output"
    nested_output.mkdir()

    with pytest.raises(FinalAdmissionError, match="must not be source root"):
        admit_final_package(source, nested_output, tracked_paths=tracked)
