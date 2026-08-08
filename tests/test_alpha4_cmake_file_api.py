from __future__ import annotations

import json
from pathlib import Path

import pytest

from promin.cmake_file_api import (
    CMakeFileApiError,
    CMakeFileApiStatus,
    create_cmake_file_api_query,
    read_cmake_file_api_reply,
    require_cmake_file_api_reply,
)
from promin.input_identity import validate_source_selection


def _selection(root: Path):
    source = root / "src" / "unit.cpp"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("int unit() { return 1; }\n", encoding="utf-8")
    return validate_source_selection(root, ("src/unit.cpp",), allowed_roots=("src",))


def _write_reply(query) -> None:
    reply = query.reply_root
    reply.mkdir(parents=True)
    codemodel = reply / "codemodel-v2.json"
    toolchains = reply / "toolchains-v1.json"
    codemodel.write_text(json.dumps({"kind": "codemodel"}), encoding="utf-8")
    toolchains.write_text(json.dumps({"kind": "toolchains"}), encoding="utf-8")
    index = {
        "reply": {
            f"client-{query.client_id}": {
                "query.json": {
                    "requests": [
                        {
                            "kind": "codemodel",
                            "version": {"major": 2, "minor": 0},
                            "jsonFile": codemodel.name,
                        },
                        {
                            "kind": "toolchains",
                            "version": {"major": 1, "minor": 0},
                            "jsonFile": toolchains.name,
                        },
                    ]
                }
            }
        }
    }
    (reply / "index-2026-08-08T12-00-00-0000.json").write_text(
        json.dumps(index), encoding="utf-8"
    )


def test_query_is_create_only_physical_and_precedes_any_configure(tmp_path: Path) -> None:
    selection = _selection(tmp_path / "source")
    build_root = tmp_path / "build"

    query = create_cmake_file_api_query(build_root, selection)

    assert query.created is True
    assert query.query_path.is_file()
    payload = json.loads(query.query_path.read_text(encoding="utf-8"))
    assert payload["requests"] == [
        {"kind": "codemodel", "version": [{"major": 2}]},
        {"kind": "toolchains", "version": [{"major": 1}]},
    ]
    assert query.to_record()["acceptance_pass"] is False
    assert query.to_record()["pass_credit"] is False

    exact_reuse = create_cmake_file_api_query(build_root, selection)
    assert exact_reuse.created is False
    query.query_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(CMakeFileApiError, match="replacement is forbidden"):
        create_cmake_file_api_query(build_root, selection)


def test_source_drift_is_rejected_before_query_directory_mutation(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    selection = _selection(source_root)
    (source_root / "src" / "unit.cpp").write_text(
        "int unit() { return 100; }\n", encoding="utf-8"
    )
    build_root = tmp_path / "new-build"

    with pytest.raises(CMakeFileApiError, match="before CMake mutation"):
        create_cmake_file_api_query(build_root, selection)
    assert not build_root.exists()


def test_reply_requires_physical_index_and_every_requested_response(tmp_path: Path) -> None:
    selection = _selection(tmp_path / "source")
    query = create_cmake_file_api_query(tmp_path / "build", selection)

    unavailable = read_cmake_file_api_reply(query)
    assert unavailable.status == CMakeFileApiStatus.UNAVAILABLE
    assert unavailable.to_record()["pass_credit"] is False

    _write_reply(query)
    reply = require_cmake_file_api_reply(query)
    assert reply.status == CMakeFileApiStatus.PASS
    assert {path for path, _digest in reply.response_files} == {
        "codemodel-v2.json",
        "toolchains-v1.json",
    }
    assert reply.to_record()["acceptance_pass"] is False

    (query.reply_root / "toolchains-v1.json").unlink()
    failed = read_cmake_file_api_reply(query)
    assert failed.status == CMakeFileApiStatus.FAIL
    with pytest.raises(CMakeFileApiError, match="not available"):
        require_cmake_file_api_reply(query)
