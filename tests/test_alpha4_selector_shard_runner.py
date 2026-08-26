from __future__ import annotations

import io
import json
from pathlib import Path
import sys
from unittest.mock import patch

import pytest

from promin.selector_shards import (
    SelectorShardError,
    load_selector_shard_manifest,
    record_selector_aggregate,
    run_selector_aggregate,
    run_selector_shard,
    validate_selector_aggregate_evidence,
    validate_selector_shard_manifest,
)
from promin.canonical import canonical_bytes, digest_bytes, digest_value


ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "tests" / "ALPHA4_TEST_SHARDS.json"


def _fixture_manifest(
    selector: str,
    *,
    timeout_seconds: int = 30,
) -> dict[str, object]:
    return {
        "schema": "promin.selector-shards.v1",
        "selector_set_id": "runner-fixture",
        "marker_expression": "not scale",
        "selectors": [selector],
        "selector_count": 1,
        "per_process": {
            "timeout_seconds": timeout_seconds,
            "memory_bytes": 512 * 1024 * 1024,
        },
        "aggregate": {"timeout_seconds": timeout_seconds * 2},
        "shards": [
            {
                "id": "fixture",
                "selectors": [selector],
                "limits": {
                    "timeout_seconds": timeout_seconds,
                    "memory_bytes": 512 * 1024 * 1024,
                },
            }
        ],
    }


def test_alpha4_plan_has_exact_current_test_file_coverage() -> None:
    manifest = load_selector_shard_manifest(PLAN_PATH)
    expected = tuple(
        sorted(
            f"tests/{path.name}"
            for path in (ROOT / "tests").glob("test_*.py")
            if path.name != "test_heavy_linux_model.py"
        )
    )

    result = validate_selector_shard_manifest(
        manifest,
        expected_selectors=expected,
    )

    assert len(expected) == 126
    assert manifest["selector_count"] == 126
    assert manifest["marker_expression"] == "not scale"
    assert result["coverage"]["exact"] is True
    assert result["coverage"]["duplicates"] == []
    assert result["coverage"]["extra"] == []
    assert result["coverage"]["missing"] == []
    assert result["per_process"] == {
        "timeout_seconds": 600,
        "memory_bytes": 1024 * 1024 * 1024,
    }
    assert result["acceptance_pass"] is False
    assert result["pass_credit"] is False


def test_loader_rejects_duplicate_json_keys_before_runner_can_spawn(
    tmp_path: Path,
) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"schema":"promin.selector-shards.v1",'
        '"schema":"promin.selector-shards.v1"}',
        encoding="utf-8",
    )

    with pytest.raises(SelectorShardError):
        load_selector_shard_manifest(path)


def test_runner_validates_loaded_manifest_before_spawning(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    selector = "tests/test_fast.py"
    invalid = _fixture_manifest(selector)
    shard = invalid["shards"]
    assert isinstance(shard, list)
    assert isinstance(shard[0], dict)
    limits = shard[0]["limits"]
    assert isinstance(limits, dict)
    limits["timeout_seconds"] = 29

    with patch("promin.selector_shards.subprocess.run") as spawn:
        with pytest.raises(SelectorShardError):
            run_selector_shard(
                invalid,
                "fixture",
                project_root=project,
                python_executable=sys.executable,
            )
    spawn.assert_not_called()


def test_runner_executes_a_validated_shard_when_memory_limiter_is_unavailable(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    tests = project / "tests"
    tests.mkdir(parents=True)
    (tests / "test_fast.py").write_text(
        "def test_fast() -> None:\n"
        "    assert True\n",
        encoding="utf-8",
    )
    selector = "tests/test_fast.py"
    manifest_path = tmp_path / "runner-manifest.json"
    manifest_path.write_text(
        json.dumps(_fixture_manifest(selector), sort_keys=True),
        encoding="utf-8",
    )
    manifest = load_selector_shard_manifest(manifest_path)

    with patch("promin.selector_shards._memory_preexec", return_value=None):
        receipt = run_selector_shard(
            manifest,
            "fixture",
            project_root=project,
            python_executable=sys.executable,
        )

    assert receipt["id"] == "fixture"
    assert receipt["selector_digest"] == manifest["selector_digest"]
    assert receipt["timeout_seconds"] == 30
    assert receipt["memory_bytes"] == 512 * 1024 * 1024
    assert receipt["acceptance_pass"] is False
    assert receipt["pass_credit"] is False
    assert receipt["status"] == "PASS"
    assert receipt["memory_enforcement"] == "host-responsibility"
    assert receipt["semantic_failure"] is False
    assert receipt["exit_code"] == 0


def test_runner_timeout_is_not_a_semantic_failure_or_credit(tmp_path: Path) -> None:
    project = tmp_path / "project"
    tests = project / "tests"
    tests.mkdir(parents=True)
    (tests / "test_slow.py").write_text(
        "import time\n\n"
        "def test_slow() -> None:\n"
        "    time.sleep(2)\n",
        encoding="utf-8",
    )
    manifest_path = tmp_path / "timeout-manifest.json"
    manifest_path.write_text(
        json.dumps(
            _fixture_manifest("tests/test_slow.py", timeout_seconds=1),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    manifest = load_selector_shard_manifest(manifest_path)

    with patch("promin.selector_shards._memory_preexec", return_value=None):
        receipt = run_selector_shard(
            manifest,
            "fixture",
            project_root=project,
            python_executable=sys.executable,
        )

    assert receipt["status"] == "TIMEOUT"
    assert receipt["memory_enforcement"] == "host-responsibility"
    assert receipt["semantic_failure"] is False
    assert receipt["acceptance_pass"] is False
    assert receipt["pass_credit"] is False
    assert receipt["exit_code"] is None


def _candidate_for_project(project: Path, test_manifest_digest: str) -> dict[str, object]:
    import hashlib

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    identity = {
        "record_type": "StandardReleaseCandidateBinding",
        "standard_name": "promin",
        "version": "1.0.0-alpha.4",
        "archive_sha256": "a" * 64,
        "archive_bytes": 1,
        "archive_member_manifest_digest": "b" * 64,
        "package_manifest_digest": digest(project / "MANIFEST.json"),
        "checksums_digest": digest(project / "SHA256SUMS.txt"),
        "core_bundle_digest": "c" * 64,
        "preset_digest": "d" * 64,
        "package_tool_digest": "e" * 64,
        "validator_digest": "f" * 64,
        "test_manifest_digest": test_manifest_digest,
        "portable_implementation_closure_digest": "1" * 64,
        "evidence_tool_digests": {
            path: "2" * 64
            for path in (
                "tools/generate_human.py",
                "tools/promin_no_degradation.py",
                "tools/promin_package.py",
                "tools/promin_saturation.py",
                "tools/promin_saturation_audit.py",
                "tools/promin_validate.py",
            )
        },
    }
    return {**identity, "candidate_binding_digest": digest_value(identity)}


def test_aggregate_rejects_non_windows_before_spawn(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    manifest = _fixture_manifest("tests/test_fast.py")
    candidate = {"not": "a candidate"}
    monkeypatch.setattr("promin.selector_shards.os.name", "posix")
    with patch("promin.selector_shards.subprocess.run") as spawn:
        with pytest.raises(SelectorShardError, match="Windows"):
            run_selector_aggregate(
                manifest,
                project_root=project,
                evidence_root=tmp_path / "evidence",
                candidate_binding=candidate,
            )
    spawn.assert_not_called()


def test_aggregate_persists_exact_logs_and_independently_validates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, manifest, candidate = _canonical_eleven_shard_fixture(tmp_path)
    _patch_aggregate_execution(monkeypatch)
    evidence = tmp_path / "evidence"
    result = run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=evidence,
        candidate_binding=candidate,
        python_executable=sys.executable,
    )
    assert result["status"] == "PASS"
    assert result["acceptance_pass"] is False
    assert (evidence / "execution.json").is_file()
    assert validate_selector_aggregate_evidence(
        manifest,
        project_root=project,
        evidence_root=evidence,
        candidate_binding=candidate,
    )["status"] == "PASS"


def test_aggregate_rejects_structurally_valid_non_current_candidate_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, manifest, candidate = _canonical_eleven_shard_fixture(tmp_path)
    candidate = dict(candidate)
    candidate["version"] = "1.0.1"
    candidate["candidate_binding_digest"] = digest_value(
        {key: value for key, value in candidate.items() if key != "candidate_binding_digest"}
    )
    monkeypatch.setattr("promin.selector_shards.os.name", "nt")

    import promin.selector_shards as selector_module

    with patch("promin.selector_shards.subprocess.Popen") as spawn:
        with pytest.raises(SelectorShardError, match="version"):
            selector_module._validated_aggregate_inputs(
                manifest,
                project_root=project,
                candidate_binding=candidate,
            )

    spawn.assert_not_called()


def _eleven_shard_fixture(tmp_path: Path) -> tuple[Path, dict[str, object], dict[str, object]]:
    return _canonical_eleven_shard_fixture(tmp_path)


def _canonical_eleven_shard_fixture(
    tmp_path: Path,
) -> tuple[Path, dict[str, object], dict[str, object]]:
    project = tmp_path / "canonical-eleven-project"
    tests = project / "tests"
    tests.mkdir(parents=True)
    source_plan = json.loads(PLAN_PATH.read_text(encoding="utf-8"))
    selectors = source_plan["selectors"]
    assert isinstance(selectors, list) and len(selectors) == 126
    rows = []
    import hashlib

    for index, selector in enumerate(selectors):
        assert isinstance(selector, str)
        path = project / selector
        path.write_text(
            f"def test_fixture_{index}() -> None:\n    assert True\n",
            encoding="utf-8",
        )
        rows.append({
            "path": selector,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        })
    excluded = tests / "test_heavy_linux_model.py"
    excluded.write_text(
        "def test_linux_model_fixture() -> None:\n    assert True\n",
        encoding="utf-8",
    )
    rows.append({
        "path": "tests/test_heavy_linux_model.py",
        "sha256": hashlib.sha256(excluded.read_bytes()).hexdigest(),
        "size": excluded.stat().st_size,
    })
    (project / "MANIFEST.json").write_bytes(b"{}\n")
    (project / "SHA256SUMS.txt").write_bytes(b"\n")
    (tests / "ALPHA4_TEST_SHARDS.json").write_bytes(canonical_bytes(source_plan))
    rows.sort(key=lambda row: str(row["path"]))
    manifest = load_selector_shard_manifest(tests / "ALPHA4_TEST_SHARDS.json")
    candidate = _candidate_for_project(project, digest_value(rows))
    return project, manifest, candidate


def _drop_manifest_digests(manifest: dict[str, object]) -> None:
    manifest.pop("manifest_digest", None)
    manifest.pop("selector_digest", None)


def _mutate_selector_assignment(manifest: dict[str, object]) -> None:
    shards = manifest["shards"]
    assert isinstance(shards, list)
    first = shards[0]
    second = shards[1]
    assert isinstance(first, dict) and isinstance(second, dict)
    first_selectors = first["selectors"]
    second_selectors = second["selectors"]
    assert isinstance(first_selectors, list) and isinstance(second_selectors, list)
    first_selectors[0], second_selectors[0] = second_selectors[0], first_selectors[0]


def _mutate_shard_order(manifest: dict[str, object]) -> None:
    shards = manifest["shards"]
    assert isinstance(shards, list)
    shards[0], shards[1] = shards[1], shards[0]


def _mutate_shard_id(manifest: dict[str, object]) -> None:
    shards = manifest["shards"]
    assert isinstance(shards, list) and isinstance(shards[0], dict)
    shards[0]["id"] = "core-state-alt"


def _mutate_limits(manifest: dict[str, object], key: str, value: int) -> None:
    per_process = manifest["per_process"]
    shards = manifest["shards"]
    assert isinstance(per_process, dict) and isinstance(shards, list)
    per_process[key] = value
    for shard in shards:
        assert isinstance(shard, dict) and isinstance(shard["limits"], dict)
        shard["limits"][key] = value


def _mutate_selector_omission(manifest: dict[str, object]) -> None:
    selectors = manifest["selectors"]
    shards = manifest["shards"]
    assert isinstance(selectors, list) and isinstance(shards, list)
    removed = selectors.pop()
    for shard in shards:
        assert isinstance(shard, dict) and isinstance(shard["selectors"], list)
        if removed in shard["selectors"]:
            shard["selectors"].remove(removed)
            break
    manifest["selector_count"] = len(selectors)


def _mutate_selector_addition(manifest: dict[str, object]) -> None:
    selectors = manifest["selectors"]
    shards = manifest["shards"]
    assert isinstance(selectors, list) and isinstance(shards, list)
    original = selectors[0]
    added = "tests/test_added.py"
    selectors[0] = added
    for shard in shards:
        assert isinstance(shard, dict) and isinstance(shard["selectors"], list)
        if original in shard["selectors"]:
            index = shard["selectors"].index(original)
            shard["selectors"][index] = added
            break


def _patch_aggregate_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    import promin.selector_shards as selector_module

    def execute(
        normalized: dict[str, object], shard: dict[str, object], **_kwargs: object,
    ) -> tuple[dict[str, object], bytes, bytes]:
        receipt, stdout, stderr = selector_module._aggregate_receipt(
            normalized,
            shard,
            shard_order=0,
            status="PASS",
            execution_state="completed",
            elapsed_seconds=0.1,
            timeout_seconds=int(shard["limits"]["timeout_seconds"]),
            exit_code=0,
            stdout=b"",
            stderr=b"",
        )
        return receipt, stdout, stderr

    monkeypatch.setattr(selector_module, "_execute_aggregate_shard", execute)


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(lambda manifest: manifest.__setitem__("selector_set_id", "alternative"), id="selector-set-id"),
        pytest.param(lambda manifest: manifest.__setitem__("marker_expression", "scale"), id="marker"),
        pytest.param(lambda manifest: manifest.__setitem__("selector_count", 124), id="selector-count"),
        pytest.param(_mutate_selector_assignment, id="selector-assignment"),
        pytest.param(_mutate_shard_order, id="shard-order"),
        pytest.param(_mutate_shard_id, id="shard-id"),
        pytest.param(lambda manifest: _mutate_limits(manifest, "timeout_seconds", 599), id="timeout"),
        pytest.param(lambda manifest: _mutate_limits(manifest, "memory_bytes", 1024), id="memory"),
        pytest.param(lambda manifest: manifest.__setitem__("aggregate", {"timeout_seconds": 6599}), id="aggregate-timeout"),
        pytest.param(_mutate_selector_omission, id="selector-omission"),
        pytest.param(_mutate_selector_addition, id="selector-addition"),
    ],
)
def test_aggregate_rejects_every_noncanonical_fixed_protocol_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation,
) -> None:
    project, manifest, candidate = _canonical_eleven_shard_fixture(tmp_path)
    mutation(manifest)
    _drop_manifest_digests(manifest)
    monkeypatch.setattr("promin.selector_shards.os.name", "nt")

    import promin.selector_shards as selector_module

    with patch("promin.selector_shards.subprocess.Popen") as spawn:
        with pytest.raises(SelectorShardError):
            selector_module._validated_aggregate_inputs(
                manifest,
                project_root=project,
                candidate_binding=candidate,
            )

    spawn.assert_not_called()


def test_evidence_walk_propagates_scan_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import promin.selector_shards as selector_module

    def failing_walk(_root: Path, **kwargs: object):
        onerror = kwargs.get("onerror")
        assert callable(onerror)
        onerror(OSError("scan denied"))
        return iter(())

    monkeypatch.setattr(selector_module.os, "walk", failing_walk)

    with pytest.raises(SelectorShardError, match="scan denied"):
        selector_module._walk_evidence_files(tmp_path)


def test_aggregate_requires_standard_alpha4_eleven_shards(tmp_path: Path) -> None:
    project = tmp_path / "project"
    tests = project / "tests"
    tests.mkdir(parents=True)
    test_file = tests / "test_fast.py"
    test_file.write_text("def test_fast() -> None:\n    assert True\n", encoding="utf-8")
    (project / "MANIFEST.json").write_bytes(b"{}\n")
    (project / "SHA256SUMS.txt").write_bytes(b"\n")
    import hashlib

    candidate = _candidate_for_project(
        project,
        digest_value([{
            "path": "tests/test_fast.py",
            "sha256": hashlib.sha256(test_file.read_bytes()).hexdigest(),
            "size": test_file.stat().st_size,
        }]),
    )
    invalid_manifest = _fixture_manifest("tests/test_fast.py")
    invalid_manifest["selector_set_id"] = "standard-alpha4-non-scale-v1"
    invalid_manifest.pop("manifest_digest", None)
    with pytest.raises(SelectorShardError, match="126 selectors"):
        run_selector_aggregate(
            invalid_manifest,
            project_root=project,
            evidence_root=tmp_path / "evidence",
            candidate_binding=candidate,
        )


def test_aggregate_passes_exact_command_and_environment(tmp_path: Path, monkeypatch) -> None:
    project, manifest, candidate = _eleven_shard_fixture(tmp_path)
    calls: list[tuple[list[str], dict[str, object]]] = []

    class FinishedProcess:
        returncode = 0

        def __init__(self) -> None:
            self.stdout = io.BytesIO(b"")
            self.stderr = io.BytesIO(b"")

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

    def fake_popen(command, **kwargs):
        calls.append((command, kwargs))
        return FinishedProcess()

    monkeypatch.setattr("promin.selector_shards.subprocess.Popen", fake_popen)
    run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=tmp_path / "evidence",
        candidate_binding=candidate,
    )
    assert len(calls) == 11
    command, kwargs = calls[0]
    assert command[1:8] == ["-B", "-m", "pytest", "-p", "no:cacheprovider", "-q", "-m"]
    assert command[8] == "not scale"
    assert kwargs["shell"] is False
    environment = kwargs["env"]
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
    assert "PYTEST_ADDOPTS" not in environment


def test_validator_rejects_canonically_rewritten_inconsistent_pass_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, manifest, candidate = _eleven_shard_fixture(tmp_path)
    _patch_aggregate_execution(monkeypatch)
    evidence = tmp_path / "evidence"
    run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=evidence,
        candidate_binding=candidate,
    )
    receipt_path = evidence / "shards" / "core-state" / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["status"] = "PASS"
    receipt["execution_state"] = "completed"
    receipt["exit_code"] = 1
    receipt_path.write_bytes(canonical_bytes(receipt))
    with pytest.raises(SelectorShardError, match="state"):
        validate_selector_aggregate_evidence(
            manifest,
            project_root=project,
            evidence_root=evidence,
            candidate_binding=candidate,
        )


def test_cli_non_pass_selector_result_is_not_success(tmp_path: Path, monkeypatch, capsys) -> None:
    from promin.__main__ import main

    monkeypatch.setattr("promin.__main__._run", lambda _args: {"status": "FAIL"})
    assert main([
        "--root", str(tmp_path), "--no-telemetry", "selector-shards", "validate",
        "--manifest", "manifest.json", "--candidate-binding", "candidate.json",
        "--evidence-root", "evidence",
    ]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "FAIL"


def test_aggregate_overflow_is_invalid_harness_and_bounded(tmp_path: Path, monkeypatch) -> None:
    project, manifest, candidate = _eleven_shard_fixture(tmp_path)

    class FinishedProcess:
        returncode = 0

        def __init__(self) -> None:
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

    def fake_popen(_command, **kwargs):
        process = FinishedProcess()
        process.stdout.write(b"x" * (1024 * 1024 + 1))
        process.stdout.seek(0)
        return process

    monkeypatch.setattr("promin.selector_shards.subprocess.Popen", fake_popen)
    result = run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=tmp_path / "evidence",
        candidate_binding=candidate,
    )
    assert result["status"] == "INVALID_HARNESS"
    assert result["aggregate"]["status"] == "INVALID_HARNESS"
    assert (tmp_path / "evidence" / "shards" / "core-state" / "stdout.log").stat().st_size == 1024 * 1024


def test_aggregate_non_utf8_output_is_invalid_harness(tmp_path: Path, monkeypatch) -> None:
    project, manifest, candidate = _eleven_shard_fixture(tmp_path)

    class FinishedProcess:
        returncode = 0

        def __init__(self) -> None:
            self.stdout = io.BytesIO()
            self.stderr = io.BytesIO()

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

    def fake_popen(_command, **kwargs):
        process = FinishedProcess()
        process.stderr.write(b"\xff")
        process.stderr.seek(0)
        return process

    monkeypatch.setattr("promin.selector_shards.subprocess.Popen", fake_popen)
    result = run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=tmp_path / "evidence",
        candidate_binding=candidate,
    )
    assert result["status"] == "INVALID_HARNESS"


def test_aggregate_source_drift_is_invalid_harness(tmp_path: Path, monkeypatch) -> None:
    project, manifest, candidate = _eleven_shard_fixture(tmp_path)
    import promin.selector_shards as selector_module

    _patch_aggregate_execution(monkeypatch)
    original = selector_module._source_observation(project)
    drifted = {**original, "test_manifest_digest": "0" * 64}
    observations = iter((original, drifted))
    monkeypatch.setattr(selector_module, "_source_observation", lambda _project: next(observations))
    result = run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=tmp_path / "evidence",
        candidate_binding=candidate,
    )
    assert result["status"] == "INVALID_HARNESS"


def test_aggregate_deadline_marks_unstarted_shards_terminal(tmp_path: Path, monkeypatch) -> None:
    project, manifest, candidate = _eleven_shard_fixture(tmp_path)
    import promin.selector_shards as selector_module

    clock = [0.0]
    monkeypatch.setattr(selector_module.time, "monotonic", lambda: clock[0])
    calls = []

    def fake_execute(normalized, shard, **kwargs):
        calls.append(shard["id"])
        clock[0] = 7000.0
        return selector_module._aggregate_receipt(
            normalized, shard, shard_order=0, status="PASS", execution_state="completed",
            elapsed_seconds=0.1, timeout_seconds=30, exit_code=0, stdout=b"", stderr=b"",
        )

    monkeypatch.setattr(selector_module, "_execute_aggregate_shard", fake_execute)
    result = run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=tmp_path / "evidence",
        candidate_binding=candidate,
    )
    assert calls == ["core-state"]
    persisted = [
        json.loads(
            (tmp_path / "evidence" / "shards" / str(shard["id"]) / "receipt.json").read_text(
                encoding="utf-8"
            )
        )
        for shard in manifest["shards"]
    ]
    assert all(row["status"] == "TIMEOUT" for row in persisted[1:])
    assert all(row["execution_state"] == "not-started" for row in persisted[1:])
    assert result["status"] == "TIMEOUT"


def test_validator_rejects_extra_file_and_create_only_sentinel_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, manifest, candidate = _eleven_shard_fixture(tmp_path)
    _patch_aggregate_execution(monkeypatch)
    evidence = tmp_path / "evidence"
    sentinel = tmp_path / "sentinel"
    sentinel.write_bytes(b"keep")
    with pytest.raises(SelectorShardError, match="absent"):
        run_selector_aggregate(
            manifest,
            project_root=project,
            evidence_root=sentinel,
            candidate_binding=candidate,
        )
    assert sentinel.read_bytes() == b"keep"
    run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=evidence,
        candidate_binding=candidate,
    )
    (evidence / "extra.log").write_bytes(b"extra")
    with pytest.raises(SelectorShardError, match="exact"):
        validate_selector_aggregate_evidence(
            manifest,
            project_root=project,
            evidence_root=evidence,
            candidate_binding=candidate,
        )


def test_validator_rejects_reparse_evidence_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, manifest, candidate = _eleven_shard_fixture(tmp_path)
    _patch_aggregate_execution(monkeypatch)
    evidence = tmp_path / "evidence"
    run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=evidence,
        candidate_binding=candidate,
    )
    alias = tmp_path / "evidence-alias"
    try:
        alias.symlink_to(evidence, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable on this Windows host")
    with pytest.raises(SelectorShardError, match="directory"):
        validate_selector_aggregate_evidence(
            manifest,
            project_root=project,
            evidence_root=alias,
            candidate_binding=candidate,
        )


def test_aggregate_exact_deadline_boundary_is_timeout() -> None:
    from promin.selector_shards import build_selector_shard_manifest

    selectors = ("tests/test_a.py", "tests/test_b.py")
    manifest = build_selector_shard_manifest(
        selectors,
        shard_count=2,
        timeout_seconds=45,
        memory_bytes=512 * 1024 * 1024,
        aggregate_timeout_seconds=180,
    )
    rows = [
        {"id": shard["id"], "status": "PASS", "elapsed_seconds": 1.0}
        for shard in manifest["shards"]
    ]
    result = record_selector_aggregate(
        manifest,
        rows,
        aggregate_elapsed_seconds=180.0,
        expected_selectors=selectors,
    )
    assert result["status"] == "TIMEOUT"


def test_validator_rejects_receipt_schema_and_type_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, manifest, candidate = _eleven_shard_fixture(tmp_path)
    _patch_aggregate_execution(monkeypatch)
    evidence = tmp_path / "evidence"
    run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=evidence,
        candidate_binding=candidate,
    )
    receipt_path = evidence / "shards" / "core-state" / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["schema"] = "forged"
    receipt_path.write_bytes(canonical_bytes(receipt))
    with pytest.raises(SelectorShardError, match="schema"):
        validate_selector_aggregate_evidence(
            manifest,
            project_root=project,
            evidence_root=evidence,
            candidate_binding=candidate,
        )


def test_validator_rejects_evidence_root_ancestor_of_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, manifest, candidate = _eleven_shard_fixture(tmp_path)
    _patch_aggregate_execution(monkeypatch)
    evidence = tmp_path / "evidence"
    run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=evidence,
        candidate_binding=candidate,
    )
    with pytest.raises(SelectorShardError, match="outside"):
        validate_selector_aggregate_evidence(
            manifest,
            project_root=project,
            evidence_root=tmp_path,
            candidate_binding=candidate,
        )


def test_aggregate_termination_uses_bounded_kill_fallback(tmp_path: Path, monkeypatch) -> None:
    project, manifest, _candidate = _eleven_shard_fixture(tmp_path)
    import promin.selector_shards as selector_module

    normalized = selector_module._normalize_manifest(manifest)
    shard = normalized["shards"][0]
    shard_dir = tmp_path / "termination-evidence"
    shard_dir.mkdir()
    events: list[str] = []

    class NeverEndingProcess:
        returncode = None
        stdout = io.BytesIO(b"")
        stderr = io.BytesIO(b"")

        def poll(self):
            return self.returncode

        def terminate(self):
            events.append("terminate")

        def wait(self, timeout=None):
            events.append(f"wait:{timeout}")
            raise subprocess.TimeoutExpired("child", timeout)

        def kill(self):
            events.append("kill")
            self.returncode = -9

    import subprocess

    monkeypatch.setattr(
        selector_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: NeverEndingProcess(),
    )
    receipt, _stdout, _stderr = selector_module._execute_aggregate_shard(
        normalized,
        shard,
        project_root=project,
        shard_dir=shard_dir,
        timeout_seconds=1.0,
        python_executable=sys.executable,
    )
    assert events[:3] == ["terminate", "wait:0.25", "kill"]
    assert receipt["status"] == "TIMEOUT"


def test_aggregate_reader_error_is_invalid_harness(tmp_path: Path, monkeypatch) -> None:
    project, manifest, candidate = _eleven_shard_fixture(tmp_path)

    class BrokenStream:
        def read(self, _size):
            raise OSError("reader failed")

    class FinishedProcess:
        returncode = 0
        stdout = BrokenStream()
        stderr = BrokenStream()

        def poll(self):
            return self.returncode

    monkeypatch.setattr("promin.selector_shards.subprocess.Popen", lambda *_args, **_kwargs: FinishedProcess())
    result = run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=tmp_path / "evidence",
        candidate_binding=candidate,
    )
    assert result["status"] == "INVALID_HARNESS"


def test_aggregate_failed_termination_is_invalid_harness(tmp_path: Path, monkeypatch) -> None:
    project, manifest, _candidate = _eleven_shard_fixture(tmp_path)
    import promin.selector_shards as selector_module

    normalized = selector_module._normalize_manifest(manifest)
    shard = normalized["shards"][0]
    shard_dir = tmp_path / "failed-termination-evidence"
    shard_dir.mkdir()

    class NeverContained:
        returncode = None
        stdout = io.BytesIO(b"")
        stderr = io.BytesIO(b"")

        def poll(self):
            return self.returncode

        def terminate(self):
            raise OSError("terminate failed")

        def kill(self):
            raise OSError("kill failed")

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("child", timeout)

    import subprocess

    monkeypatch.setattr(
        selector_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: NeverContained(),
    )
    receipt, _stdout, _stderr = selector_module._execute_aggregate_shard(
        normalized,
        shard,
        project_root=project,
        shard_dir=shard_dir,
        timeout_seconds=1.0,
        python_executable=sys.executable,
    )
    assert receipt["status"] == "INVALID_HARNESS"
    assert "child" in receipt["reason"]


def test_validator_rejects_execution_marker_tamper(tmp_path: Path) -> None:
    project, manifest, candidate = _eleven_shard_fixture(tmp_path)
    evidence = tmp_path / "evidence"
    run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=evidence,
        candidate_binding=candidate,
    )
    execution_path = evidence / "execution.json"
    execution = json.loads(execution_path.read_text(encoding="utf-8"))
    execution["marker_expression"] = "scale"
    execution_path.write_bytes(canonical_bytes(execution))
    with pytest.raises(SelectorShardError, match="marker"):
        validate_selector_aggregate_evidence(
            manifest,
            project_root=project,
            evidence_root=evidence,
            candidate_binding=candidate,
        )


def test_validator_rejects_reparse_ancestor_metadata(tmp_path: Path, monkeypatch) -> None:
    project, manifest, candidate = _eleven_shard_fixture(tmp_path)
    evidence = tmp_path / "evidence"
    run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=evidence,
        candidate_binding=candidate,
    )
    from types import SimpleNamespace

    original_lstat = Path.lstat

    def patched_lstat(path):
        metadata = original_lstat(path)
        if path == tmp_path:
            return SimpleNamespace(st_mode=metadata.st_mode, st_file_attributes=0x0400)
        return metadata

    monkeypatch.setattr(Path, "lstat", patched_lstat)
    with pytest.raises(SelectorShardError, match="reparse"):
        validate_selector_aggregate_evidence(
            manifest,
            project_root=project,
            evidence_root=evidence,
            candidate_binding=candidate,
        )


def test_aggregate_poll_failure_enters_bounded_containment_and_invalid_receipt(
    tmp_path: Path, monkeypatch,
) -> None:
    project, manifest, _candidate = _eleven_shard_fixture(tmp_path)
    import subprocess

    import promin.selector_shards as selector_module

    normalized = selector_module._normalize_manifest(manifest)
    shard = normalized["shards"][0]
    assert isinstance(shard, dict)
    shard_dir = tmp_path / "shard"
    shard_dir.mkdir()
    events: list[str] = []

    class TrackingStream:
        def __init__(self, name: str) -> None:
            self.name = name

        def read(self, _size: int) -> bytes:
            events.append(f"{self.name}.read")
            return b""

        def close(self) -> None:
            events.append(f"{self.name}.close")

    class PollFailureProcess:
        returncode = None

        def __init__(self) -> None:
            self.stdout = TrackingStream("stdout")
            self.stderr = TrackingStream("stderr")
            self._poll_calls = 0
            self._wait_calls = 0

        def poll(self):
            self._poll_calls += 1
            events.append("poll")
            if self._poll_calls == 1:
                raise OSError("poll failed")
            return self.returncode

        def terminate(self) -> None:
            events.append("terminate")

        def wait(self, timeout=None):
            events.append(f"wait:{timeout}")
            self._wait_calls += 1
            if self._wait_calls == 1:
                raise subprocess.TimeoutExpired("child", timeout)
            return self.returncode

        def kill(self) -> None:
            events.append("kill")
            self.returncode = -9

    class RecordingThread:
        def __init__(self, target, *, name: str, daemon: bool) -> None:
            self._target = target
            self.name = name
            self._alive = False

        def start(self) -> None:
            events.append(f"{self.name}.start")
            self._alive = True
            self._target()
            self._alive = False

        def join(self, timeout=None) -> None:
            events.append(f"{self.name}.join:{timeout}")

        def is_alive(self) -> bool:
            return self._alive

    process = PollFailureProcess()
    monkeypatch.setattr(selector_module.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(selector_module.threading, "Thread", RecordingThread)

    receipt, _stdout, _stderr = selector_module._execute_aggregate_shard(
        normalized,
        shard,
        project_root=project,
        shard_dir=shard_dir,
        timeout_seconds=1.0,
        python_executable=sys.executable,
    )

    assert receipt["status"] == "INVALID_HARNESS"
    assert receipt["execution_state"] == "invalid"
    assert "poll" in str(receipt["reason"])
    assert "terminate" in events
    assert "kill" in events
    assert events.count("wait:0.25") >= 2
    assert events.index("terminate") < events.index("kill")
    assert "stdout.close" not in events
    assert "stderr.close" not in events
    assert any(event.startswith("promin-selector-stdout.join:") for event in events)
    assert any(event.startswith("promin-selector-stderr.join:") for event in events)


def test_aggregate_termination_error_is_invalid_not_timeout(
    tmp_path: Path, monkeypatch,
) -> None:
    project, manifest, _candidate = _eleven_shard_fixture(tmp_path)
    import subprocess

    import promin.selector_shards as selector_module

    normalized = selector_module._normalize_manifest(manifest)
    shard = normalized["shards"][0]
    assert isinstance(shard, dict)
    shard_dir = tmp_path / "shard"
    shard_dir.mkdir()
    clock = [0.0]

    class TerminationErrorProcess:
        returncode = None
        stdout = io.BytesIO(b"")
        stderr = io.BytesIO(b"")

        def __init__(self) -> None:
            self._wait_calls = 0

        def poll(self):
            return self.returncode

        def terminate(self) -> None:
            raise OSError("terminate failed")

        def wait(self, timeout=None):
            self._wait_calls += 1
            if self._wait_calls == 1:
                raise subprocess.TimeoutExpired("child", timeout)
            return self.returncode

        def kill(self) -> None:
            self.returncode = 0

    monkeypatch.setattr(
        selector_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: TerminationErrorProcess(),
    )
    monkeypatch.setattr(selector_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(selector_module.time, "sleep", lambda _seconds: clock.__setitem__(0, 1.0))

    receipt, _stdout, _stderr = selector_module._execute_aggregate_shard(
        normalized,
        shard,
        project_root=project,
        shard_dir=shard_dir,
        timeout_seconds=1.0,
        python_executable=sys.executable,
    )

    assert receipt["status"] == "INVALID_HARNESS"
    assert receipt["status"] != "TIMEOUT"
    assert "terminate" in str(receipt["reason"])


def test_persisted_invalid_harness_aggregate_roundtrips_through_validator(
    tmp_path: Path, monkeypatch,
) -> None:
    project, manifest, candidate = _eleven_shard_fixture(tmp_path)

    class BrokenStream:
        def read(self, _size: int) -> bytes:
            raise OSError("reader failed")

    class FinishedProcess:
        returncode = 0
        stdout = BrokenStream()
        stderr = BrokenStream()

        def poll(self):
            return self.returncode

    import promin.selector_shards as selector_module

    monkeypatch.setattr(
        selector_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: FinishedProcess(),
    )
    evidence = tmp_path / "evidence"
    result = run_selector_aggregate(
        manifest,
        project_root=project,
        evidence_root=evidence,
        candidate_binding=candidate,
    )

    assert result["status"] == "INVALID_HARNESS"
    receipt = json.loads(
        (evidence / "shards" / "core-state" / "receipt.json").read_text(encoding="utf-8")
    )
    assert receipt["status"] == "INVALID_HARNESS"
    assert isinstance(receipt["reason"], str) and receipt["reason"]
    validated = validate_selector_aggregate_evidence(
        manifest,
        project_root=project,
        evidence_root=evidence,
        candidate_binding=candidate,
    )
    assert validated["status"] == "INVALID_HARNESS"
    assert validated["aggregate"]["status"] == "INVALID_HARNESS"


def test_real_subprocess_timeout_drains_marked_streams() -> None:
    """Exercise bounded child cleanup without running the full selector plan."""

    import tempfile
    import promin.selector_shards as selector_module

    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory)
        tests = project / "tests"
        tests.mkdir()
        target = tests / "test_timeout.py"
        target.write_text(
            "import sys\n"
            "import time\n\n"
            "def test_timeout_fixture(capsys) -> None:\n"
            "    with capsys.disabled():\n"
            "        print('REAL_STDOUT_MARKER', flush=True)\n"
            "        print('REAL_STDERR_MARKER', file=sys.stderr, flush=True)\n"
            "    time.sleep(4)\n",
            encoding="utf-8",
        )
        manifest = selector_module._normalize_manifest(
            _fixture_manifest("tests/test_timeout.py", timeout_seconds=2)
        )
        shard = manifest["shards"][0]
        receipt, stdout_payload, stderr_payload = selector_module._execute_aggregate_shard(
            manifest,
            shard,
            project_root=project,
            shard_dir=project / "evidence",
            timeout_seconds=2.0,
            python_executable=sys.executable,
        )

    assert receipt["status"] == "TIMEOUT"
    assert stdout_payload.count(b"REAL_STDOUT_MARKER") == 1
    assert stderr_payload.count(b"REAL_STDERR_MARKER") == 1
    assert receipt["stdout_bytes"] == len(stdout_payload)
    assert receipt["stdout_sha256"] == digest_bytes(stdout_payload)
    assert receipt["stderr_bytes"] == len(stderr_payload)
    assert receipt["stderr_sha256"] == digest_bytes(stderr_payload)
