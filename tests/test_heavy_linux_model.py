from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools" / "promin_linux_model.py"
SPEC = importlib.util.spec_from_file_location("promin_linux_model", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
linux_model = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = linux_model
SPEC.loader.exec_module(linux_model)


def _available_docker() -> dict[str, object]:
    return {
        "status": "AVAILABLE",
        "executable": "C:/Program Files/Docker/docker.exe",
        "client_version": "27.2.0",
        "server_version": "27.2.0",
    }


def _available_image(reference: str) -> dict[str, object]:
    return {
        "status": "AVAILABLE",
        "reference": reference,
        "image_id": "sha256:" + ("a" * 64),
        "repo_digests": [reference + "@sha256:" + ("b" * 64)],
    }


def _plan(monkeypatch, source: Path) -> dict[str, object]:
    """Build a deterministic modeled plan; these tests do not run Docker."""
    monkeypatch.setattr(linux_model, "discover_docker", lambda *_: _available_docker())
    monkeypatch.setattr(
        linux_model,
        "inspect_image",
        lambda _docker, image: _available_image(image),
    )
    return linux_model.build_linux_model_plan(
        source,
        image="python:3.14-slim",
        commands=[
            ("python", "--version"),
            ("python", "-c", "print('container-only')"),
        ],
        limits=linux_model.LinuxModelLimits(
            timeout_seconds=45,
            memory_bytes=768 * 1024 * 1024,
            cpus_millis=1250,
            pids_limit=96,
            tmpfs_bytes=32 * 1024 * 1024,
        ),
    )


def test_plan_binds_image_tool_identity_read_only_mount_limits_and_exact_argv(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.txt").write_text("stable\n", encoding="utf-8")

    plan = _plan(monkeypatch, source)

    assert plan["schema"] == "promin.linux-model.v1"
    assert plan["tool"]["status"] == "AVAILABLE"
    assert plan["image"]["status"] == "AVAILABLE"
    assert plan["source_mount"] == {
        "host_path": str(source.absolute()),
        "target_path": "/workspace",
        "read_only": True,
        "source_digest": plan["source_mount"]["source_digest"],
    }
    assert plan["limits"] == {
        "timeout_seconds": 45,
        "memory_bytes": 768 * 1024 * 1024,
        "cpus_millis": 1250,
        "pids_limit": 96,
        "tmpfs_bytes": 32 * 1024 * 1024,
    }
    assert plan["commands"] == [
        {"id": "command-001", "argv": ["python", "--version"]},
        {
            "id": "command-002",
            "argv": ["python", "-c", "print('container-only')"],
        },
    ]
    assert plan["claims"] == {
        "actual_linux_host_validated": False,
        "linux_standard_validated": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "release_eligible": False,
        "pass_credit": False,
    }
    assert plan["labels"] == {
        "evidence_class": "MODELLED_ONLY",
        "execution_scope": "docker-container-model",
        "product_credit_eligible": False,
    }

    argv = linux_model.docker_run_argv(plan, command_id="command-001")
    assert argv[0] == "C:/Program Files/Docker/docker.exe"
    assert "--pull=never" in argv
    assert "--read-only" in argv
    assert "--network=none" in argv
    assert "--cap-drop=ALL" in argv
    assert "--security-opt=no-new-privileges" in argv
    assert "--memory=805306368b" in argv
    assert "--cpus=1.250" in argv
    assert "--pids-limit=96" in argv
    assert "--mount" in argv
    mount = argv[argv.index("--mount") + 1]
    assert mount == f"type=bind,source={source.absolute()},target=/workspace,readonly"
    assert argv[-3:] == ["sha256:" + ("a" * 64), "python", "--version"]


def test_docker_argv_is_fully_bound_to_exact_candidate_and_resource_contract(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.txt").write_text("stable\n", encoding="utf-8")
    plan = _plan(monkeypatch, source)

    assert plan["image"]["reference"] == "python:3.14-slim"
    assert plan["image"]["image_id"] == "sha256:" + ("a" * 64)
    assert plan["image"]["resolved_reference"] == "sha256:" + ("a" * 64)
    assert plan["image"]["repo_digests"] == [
        "python:3.14-slim@sha256:" + ("b" * 64)
    ]
    assert len(plan["image"]["identity_digest"]) == 64
    assert plan["tool"]["identity_digest"]

    argv = linux_model.docker_run_argv(plan, command_id="command-002")
    assert argv == [
        "C:/Program Files/Docker/docker.exe",
        "run",
        "--rm",
        "--pull=never",
        "--read-only",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=96",
        "--memory=805306368b",
        "--cpus=1.250",
        "--user=65534:65534",
        "--workdir=/workspace",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=33554432b",
        "--mount",
        f"type=bind,source={source.absolute()},target=/workspace,readonly",
        "sha256:" + ("a" * 64),
        "python",
        "-c",
        "print('container-only')",
    ]


def test_runner_rechecks_bound_docker_identity_before_container_spawn(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.txt").write_text("stable\n", encoding="utf-8")
    plan = _plan(monkeypatch, source)
    changed = _available_docker()
    changed["server_version"] = "27.2.1"
    monkeypatch.setattr(linux_model, "discover_docker", lambda *_: changed)

    with patch.object(linux_model.subprocess, "run") as spawn:
        result = linux_model.run_linux_model(plan)

    assert result["status"] == "FAIL"
    assert result["reason"] == "docker-identity-drift"
    assert result["container_executed"] is False
    assert result["linux_container_observed"] is False
    assert result["claims"]["pass_credit"] is False
    spawn.assert_not_called()


def test_runner_reports_unavailable_without_claiming_linux_when_docker_is_absent(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.txt").write_text("stable\n", encoding="utf-8")
    monkeypatch.setattr(
        linux_model,
        "discover_docker",
        lambda *_: {"status": "UNAVAILABLE", "reason": "docker-not-found"},
    )

    plan = linux_model.build_linux_model_plan(source)
    with patch.object(linux_model.subprocess, "run") as spawn:
        result = linux_model.run_linux_model(plan)

    assert plan["tool"]["status"] == "UNAVAILABLE"
    assert plan["image"]["status"] == "UNAVAILABLE"
    assert result["status"] == "UNAVAILABLE"
    assert result["reason"] == "plan-docker-unavailable"
    assert result["container_executed"] is False
    assert result["linux_container_observed"] is False
    assert result["command_results"] == []
    assert result["claims"] == plan["claims"]
    assert all(value is False for value in result["claims"].values())
    spawn.assert_not_called()


def test_plan_and_result_are_explicitly_modeled_only_even_after_container_pass(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.txt").write_text("stable\n", encoding="utf-8")
    plan = _plan(monkeypatch, source)

    with patch.object(
        linux_model.subprocess,
        "run",
        return_value=subprocess.CompletedProcess([], 0, stdout="ok\n", stderr=""),
    ):
        result = linux_model.run_linux_model(plan)

    assert plan["record_type"] == "LinuxModelPlan"
    assert result["record_type"] == "LinuxModelResult"
    assert plan["schema"] == "promin.linux-model.v1"
    assert result["schema"] == "promin.linux-model-result.v1"
    assert plan["labels"] == {
        "evidence_class": "MODELLED_ONLY",
        "execution_scope": "docker-container-model",
        "product_credit_eligible": False,
    }
    assert result["labels"] == {
        "evidence_class": "MODELLED_ONLY",
        "execution_scope": "docker-container-model",
        "product_credit_eligible": False,
    }
    assert result["status"] == "PASS"
    assert result["reason"] == "all-container-commands-passed"
    assert result["linux_container_observed"] is True
    assert result["claims"] == {
        "actual_linux_host_validated": False,
        "linux_standard_validated": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "release_eligible": False,
        "pass_credit": False,
    }


def test_modeled_runner_pass_path_uses_mocked_process_and_never_promotes_credit(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.txt").write_text("stable\n", encoding="utf-8")
    plan = _plan(monkeypatch, source)
    calls: list[list[str]] = []

    def completed(argv, **_kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, stdout="safe\n", stderr="")

    with patch.object(linux_model.subprocess, "run", side_effect=completed):
        result = linux_model.run_linux_model(plan)

    assert result["status"] == "PASS"
    assert result["container_executed"] is True
    assert result["linux_container_observed"] is True
    assert result["claims"] == plan["claims"]
    assert len(calls) == 2
    assert all("--read-only" in command for command in calls)
    assert all("--network=none" in command for command in calls)


def test_runner_fails_closed_on_image_identity_drift_before_container_spawn(
    tmp_path: Path, monkeypatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.txt").write_text("stable\n", encoding="utf-8")
    plan = _plan(monkeypatch, source)

    def drifted_image(reference: str) -> dict[str, object]:
        image = _available_image(reference)
        image["image_id"] = "sha256:" + ("c" * 64)
        return image

    monkeypatch.setattr(
        linux_model,
        "inspect_image",
        lambda _docker, image: drifted_image(image),
    )
    with patch.object(linux_model.subprocess, "run") as spawn:
        result = linux_model.run_linux_model(plan)

    assert result["status"] == "FAIL"
    assert result["container_executed"] is False
    assert result["reason"] == "image-identity-drift"
    assert result["claims"] == plan["claims"]
    spawn.assert_not_called()
