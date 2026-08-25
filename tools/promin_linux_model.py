#!/usr/bin/env python3
"""Plan and run a bounded Docker Linux model without granting Linux-host credit.

The tool binds an inspected local Docker image, Docker client/server identity, a
read-only source tree, immutable resource limits, and exact argv commands.  It
never pulls an image, never writes into the mounted source tree, and never
turns a container result into product, release, or Linux-host acceptance.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
import re
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
from typing import Any, Final


PLAN_SCHEMA: Final = "promin.linux-model.v1"
RESULT_SCHEMA: Final = "promin.linux-model-result.v1"
_MAX_COMMANDS: Final = 32
_MAX_ARGUMENTS_PER_COMMAND: Final = 128
_MAX_ARGUMENT_BYTES: Final = 16 * 1024
_MAX_SOURCE_FILES: Final = 20_000
_MAX_SOURCE_BYTES: Final = 1024 * 1024 * 1024
_MAX_RESULT_SNIPPET_BYTES: Final = 16 * 1024
_MAX_TIMEOUT_SECONDS: Final = 3600
_MAX_MEMORY_BYTES: Final = 8 * 1024 * 1024 * 1024
_MAX_CPUS_MILLIS: Final = 16_000
_MAX_PIDS: Final = 4096
_MAX_TMPFS_BYTES: Final = 1024 * 1024 * 1024
_REPARSE_POINT: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
_MODELLED_ONLY: Final = "MODELLED_ONLY"
_CLAIMS: Final = {
    "actual_linux_host_validated": False,
    "linux_standard_validated": False,
    "acceptance_pass": False,
    "product_acceptance_pass": False,
    "release_eligible": False,
    "pass_credit": False,
}
_EVIDENCE_LABELS: Final = {
    "evidence_class": _MODELLED_ONLY,
    "execution_scope": "docker-container-model",
    "product_credit_eligible": False,
}
_ISOLATION: Final = {
    "read_only_root_filesystem": True,
    "network": "none",
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges"],
    "pull_policy": "never",
    "user": "65534:65534",
    "tmpfs": "/tmp",
}
_DIGEST_RE: Final = re.compile(r"^sha256:[0-9a-f]{64}$")


class LinuxModelError(ValueError):
    """Raised when a Linux model cannot be formed or verified safely."""


@dataclass(frozen=True)
class LinuxModelLimits:
    """Immutable limits passed to every modeled Docker command."""

    timeout_seconds: int = 120
    memory_bytes: int = 1024 * 1024 * 1024
    cpus_millis: int = 1000
    pids_limit: int = 128
    tmpfs_bytes: int = 64 * 1024 * 1024


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & _REPARSE_POINT)


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise LinuxModelError(f"{label} must be a positive integer")
    return value


def _required_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise LinuxModelError(f"{label} must be a string-keyed mapping")
    return value


def _require_exact_keys(value: object, expected: frozenset[str], label: str) -> Mapping[str, object]:
    mapping = _required_mapping(value, label)
    actual = frozenset(mapping)
    if actual != expected:
        raise LinuxModelError(
            f"{label} fields must be exact; missing={sorted(expected - actual)} "
            f"unexpected={sorted(actual - expected)}"
        )
    return mapping


def _normalize_limits(value: LinuxModelLimits | Mapping[str, object]) -> dict[str, int]:
    raw = asdict(value) if isinstance(value, LinuxModelLimits) else value
    limits = _require_exact_keys(
        raw,
        frozenset({"timeout_seconds", "memory_bytes", "cpus_millis", "pids_limit", "tmpfs_bytes"}),
        "limits",
    )
    normalized = {key: _positive_int(limits[key], f"limits.{key}") for key in limits}
    maxima = {
        "timeout_seconds": _MAX_TIMEOUT_SECONDS,
        "memory_bytes": _MAX_MEMORY_BYTES,
        "cpus_millis": _MAX_CPUS_MILLIS,
        "pids_limit": _MAX_PIDS,
        "tmpfs_bytes": _MAX_TMPFS_BYTES,
    }
    for key, maximum in maxima.items():
        if normalized[key] > maximum:
            raise LinuxModelError(f"limits.{key} exceeds bounded maximum {maximum}")
    return normalized


def _normalize_image_reference(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise LinuxModelError("image must be a non-empty trimmed reference")
    if any(character.isspace() for character in value) or "\x00" in value:
        raise LinuxModelError("image must not contain whitespace or NUL")
    if "@" in value:
        if value.count("@") != 1:
            raise LinuxModelError("image digest reference must contain one @")
        repository, digest = value.rsplit("@", 1)
        if not repository or _DIGEST_RE.fullmatch(digest) is None:
            raise LinuxModelError("image digest reference must use canonical sha256 form")
    elif _DIGEST_RE.fullmatch(value) is not None:
        # A bare content ID is already immutable and is accepted as a lookup.
        pass
    return value


def _normalize_commands(value: Sequence[Sequence[str]] | None) -> list[dict[str, object]]:
    raw_commands: Sequence[Sequence[str]] = (("python", "--version"),) if value is None else value
    if isinstance(raw_commands, (str, bytes)) or not isinstance(raw_commands, Sequence):
        raise LinuxModelError("commands must be a sequence of argv sequences")
    if not raw_commands or len(raw_commands) > _MAX_COMMANDS:
        raise LinuxModelError(f"commands must contain 1..{_MAX_COMMANDS} entries")
    normalized: list[dict[str, object]] = []
    for command_index, raw_command in enumerate(raw_commands, start=1):
        if isinstance(raw_command, (str, bytes)) or not isinstance(raw_command, Sequence):
            raise LinuxModelError(f"commands[{command_index - 1}] must be an argv sequence")
        if not raw_command or len(raw_command) > _MAX_ARGUMENTS_PER_COMMAND:
            raise LinuxModelError(
                f"commands[{command_index - 1}] must contain 1..{_MAX_ARGUMENTS_PER_COMMAND} arguments"
            )
        argv: list[str] = []
        for argument_index, argument in enumerate(raw_command):
            if (
                not isinstance(argument, str)
                or not argument
                or argument != argument.strip()
                or "\x00" in argument
                or "\r" in argument
                or "\n" in argument
                or len(argument.encode("utf-8")) > _MAX_ARGUMENT_BYTES
            ):
                raise LinuxModelError(
                    f"commands[{command_index - 1}][{argument_index}] is not a bounded argv argument"
                )
            argv.append(argument)
        normalized.append({"id": f"command-{command_index:03d}", "argv": argv})
    return normalized


def _source_identity(source_root: Path) -> dict[str, object]:
    if not isinstance(source_root, Path):
        raise LinuxModelError("source_root must be a pathlib.Path")
    root = source_root.absolute()
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise LinuxModelError(f"source_root is unavailable: {type(error).__name__}") from error
    if _is_link_or_reparse(root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise LinuxModelError("source_root must be a real non-link directory")

    entries: list[dict[str, object]] = []
    file_count = 0
    total_bytes = 0
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            children = sorted(current.iterdir(), key=lambda item: item.name)
        except OSError as error:
            raise LinuxModelError(
                f"source tree cannot be enumerated at {current}: {type(error).__name__}"
            ) from error
        for child in children:
            try:
                metadata = child.lstat()
            except OSError as error:
                raise LinuxModelError(
                    f"source tree entry is unavailable at {child}: {type(error).__name__}"
                ) from error
            relative = child.relative_to(root).as_posix()
            if _is_link_or_reparse(metadata):
                raise LinuxModelError(f"source tree link or reparse entry is forbidden: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(child)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise LinuxModelError(f"source tree special entry is forbidden: {relative}")
            file_count += 1
            total_bytes += metadata.st_size
            if file_count > _MAX_SOURCE_FILES or total_bytes > _MAX_SOURCE_BYTES:
                raise LinuxModelError("source tree exceeds modeled identity budget")
            digest = hashlib.sha256()
            try:
                with child.open("rb") as stream:
                    while True:
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
            except OSError as error:
                raise LinuxModelError(
                    f"source tree entry cannot be read at {relative}: {type(error).__name__}"
                ) from error
            entries.append(
                {
                    "path": relative,
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "bytes": metadata.st_size,
                    "sha256": digest.hexdigest(),
                }
            )
    entries.sort(key=lambda item: str(item["path"]))
    return {
        "root": str(root),
        "file_count": file_count,
        "total_bytes": total_bytes,
        "tree_digest": _digest(entries),
    }


def _run_identity_command(argv: list[str]) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None


def _normalize_tool_identity(value: Mapping[str, object]) -> dict[str, object]:
    raw = _required_mapping(value, "docker identity")
    status = raw.get("status")
    if status == "UNAVAILABLE":
        reason = raw.get("reason")
        if not isinstance(reason, str) or not reason:
            raise LinuxModelError("unavailable docker identity requires a reason")
        return {"status": "UNAVAILABLE", "reason": reason}
    if status != "AVAILABLE":
        raise LinuxModelError("docker identity status must be AVAILABLE or UNAVAILABLE")
    executable = raw.get("executable")
    client_version = raw.get("client_version")
    server_version = raw.get("server_version")
    if not all(isinstance(item, str) and item for item in (executable, client_version, server_version)):
        raise LinuxModelError("available docker identity is incomplete")
    identity = {
        "status": "AVAILABLE",
        "executable": executable,
        "client_version": client_version,
        "server_version": server_version,
    }
    return {**identity, "identity_digest": _digest(identity)}


def discover_docker(executable: str = "docker") -> dict[str, object]:
    """Inspect only Docker's local client/server identity; never pull or run a container."""

    if not isinstance(executable, str) or not executable or executable != executable.strip():
        raise LinuxModelError("docker executable must be a non-empty trimmed string")
    resolved = shutil.which(executable)
    if resolved is None:
        return {"status": "UNAVAILABLE", "reason": "docker-command-not-found"}
    client = _run_identity_command([resolved, "version", "--format", "{{json .Client}}"])
    server = _run_identity_command([resolved, "version", "--format", "{{json .Server}}"])
    if client is None or server is None:
        return {"status": "UNAVAILABLE", "reason": "docker-identity-command-unavailable"}
    if client.returncode != 0 or server.returncode != 0:
        return {"status": "UNAVAILABLE", "reason": "docker-daemon-unavailable"}
    try:
        client_record = json.loads(client.stdout)
        server_record = json.loads(server.stdout)
    except json.JSONDecodeError:
        return {"status": "UNAVAILABLE", "reason": "docker-identity-output-invalid"}
    if not isinstance(client_record, Mapping) or not isinstance(server_record, Mapping):
        return {"status": "UNAVAILABLE", "reason": "docker-identity-output-invalid"}
    client_version = client_record.get("Version")
    server_version = server_record.get("Version")
    if not isinstance(client_version, str) or not client_version or not isinstance(server_version, str) or not server_version:
        return {"status": "UNAVAILABLE", "reason": "docker-version-unavailable"}
    return {
        "status": "AVAILABLE",
        "executable": str(Path(resolved).absolute()),
        "client_version": client_version,
        "server_version": server_version,
    }


def _normalize_image_identity(value: Mapping[str, object], reference: str) -> dict[str, object]:
    raw = _required_mapping(value, "image identity")
    status = raw.get("status")
    if status == "UNAVAILABLE":
        reason = raw.get("reason")
        if not isinstance(reason, str) or not reason:
            raise LinuxModelError("unavailable image identity requires a reason")
        return {"status": "UNAVAILABLE", "reference": reference, "reason": reason}
    if status != "AVAILABLE":
        raise LinuxModelError("image identity status must be AVAILABLE or UNAVAILABLE")
    observed_reference = raw.get("reference")
    image_id = raw.get("image_id")
    repo_digests = raw.get("repo_digests")
    if (
        observed_reference != reference
        or not isinstance(image_id, str)
        or _DIGEST_RE.fullmatch(image_id) is None
    ):
        raise LinuxModelError("available image identity is incomplete")
    if isinstance(repo_digests, (str, bytes)) or not isinstance(repo_digests, Sequence):
        raise LinuxModelError("image repo digests must be a string sequence")
    normalized_digests = sorted(str(item) for item in repo_digests)
    if any(
        not item
        or item.count("@") != 1
        or _DIGEST_RE.fullmatch(item.rsplit("@", 1)[1]) is None
        for item in normalized_digests
    ):
        raise LinuxModelError("image repo digests must be content-addressed")
    identity = {
        "status": "AVAILABLE",
        "reference": reference,
        "image_id": image_id,
        "repo_digests": normalized_digests,
        # The tag/reference is lookup identity only. Docker must run this
        # content-addressed local image ID to avoid tag retargeting between
        # inspection and spawn.
        "resolved_reference": image_id,
    }
    return {**identity, "identity_digest": _digest(identity)}


def inspect_image(docker: Mapping[str, object], image: str) -> dict[str, object]:
    """Inspect a local image only; absence is UNAVAILABLE and never triggers pull."""

    normalized_docker = _normalize_tool_identity(docker)
    if normalized_docker["status"] != "AVAILABLE":
        return {"status": "UNAVAILABLE", "reason": "docker-unavailable"}
    completed = _run_identity_command(
        [str(normalized_docker["executable"]), "image", "inspect", "--format", "{{json .}}", image]
    )
    if completed is None or completed.returncode != 0:
        return {"status": "UNAVAILABLE", "reason": "docker-image-unavailable"}
    try:
        record = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"status": "UNAVAILABLE", "reason": "docker-image-identity-invalid"}
    if not isinstance(record, Mapping):
        return {"status": "UNAVAILABLE", "reason": "docker-image-identity-invalid"}
    image_id = record.get("Id")
    repo_digests = record.get("RepoDigests")
    if not isinstance(image_id, str) or _DIGEST_RE.fullmatch(image_id) is None:
        return {"status": "UNAVAILABLE", "reason": "docker-image-id-unavailable"}
    if repo_digests is None:
        repo_digests = []
    if isinstance(repo_digests, (str, bytes)) or not isinstance(repo_digests, Sequence):
        return {"status": "UNAVAILABLE", "reason": "docker-image-digests-invalid"}
    return {
        "status": "AVAILABLE",
        "reference": image,
        "image_id": image_id,
        "repo_digests": list(repo_digests),
    }


def build_linux_model_plan(
    source_root: Path,
    *,
    image: str = "python:3.14-slim",
    commands: Sequence[Sequence[str]] | None = None,
    limits: LinuxModelLimits | Mapping[str, object] = LinuxModelLimits(),
    docker_executable: str = "docker",
) -> dict[str, object]:
    """Create a Docker-only Linux model plan with all host-facing inputs bound."""

    normalized_image = _normalize_image_reference(image)
    source_identity = _source_identity(source_root)
    normalized_limits = _normalize_limits(limits)
    normalized_commands = _normalize_commands(commands)
    tool = _normalize_tool_identity(discover_docker(docker_executable))
    inspected_image = (
        inspect_image(tool, normalized_image)
        if tool["status"] == "AVAILABLE"
        else {"status": "UNAVAILABLE", "reason": "docker-unavailable"}
    )
    image_identity = _normalize_image_identity(inspected_image, normalized_image)
    source_mount = {
        "host_path": source_identity["root"],
        "target_path": "/workspace",
        "read_only": True,
        "source_digest": source_identity["tree_digest"],
    }
    plan: dict[str, object] = {
        "schema": PLAN_SCHEMA,
        "record_type": "LinuxModelPlan",
        "source_mount": source_mount,
        "source_identity": source_identity,
        "tool": tool,
        "image": image_identity,
        "limits": normalized_limits,
        "isolation": dict(_ISOLATION),
        "commands": normalized_commands,
        "claims": dict(_CLAIMS),
        "labels": dict(_EVIDENCE_LABELS),
    }
    plan["plan_digest"] = _digest(plan)
    return plan


def _validated_plan(value: Mapping[str, object]) -> dict[str, object]:
    plan = _required_mapping(value, "linux model plan")
    expected = frozenset(
        {
            "schema",
            "record_type",
            "source_mount",
            "source_identity",
            "tool",
            "image",
            "limits",
            "isolation",
            "commands",
            "claims",
            "labels",
            "plan_digest",
        }
    )
    if frozenset(plan) != expected:
        raise LinuxModelError("linux model plan fields are not exact")
    if plan["schema"] != PLAN_SCHEMA or plan["record_type"] != "LinuxModelPlan":
        raise LinuxModelError("linux model plan schema is invalid")
    supplied_digest = plan["plan_digest"]
    if not isinstance(supplied_digest, str) or len(supplied_digest) != 64:
        raise LinuxModelError("linux model plan digest is invalid")
    unsigned = {key: plan[key] for key in plan if key != "plan_digest"}
    if _digest(unsigned) != supplied_digest:
        raise LinuxModelError("linux model plan digest does not bind contents")
    source_mount = _require_exact_keys(
        plan["source_mount"],
        frozenset({"host_path", "target_path", "read_only", "source_digest"}),
        "source_mount",
    )
    if (
        not isinstance(source_mount["host_path"], str)
        or source_mount["target_path"] != "/workspace"
        or source_mount["read_only"] is not True
        or not isinstance(source_mount["source_digest"], str)
    ):
        raise LinuxModelError("source mount is invalid")
    source_identity = _require_exact_keys(
        plan["source_identity"],
        frozenset({"root", "file_count", "total_bytes", "tree_digest"}),
        "source_identity",
    )
    if (
        source_identity["root"] != source_mount["host_path"]
        or not isinstance(source_identity["file_count"], int)
        or isinstance(source_identity["file_count"], bool)
        or source_identity["file_count"] < 0
        or not isinstance(source_identity["total_bytes"], int)
        or isinstance(source_identity["total_bytes"], bool)
        or source_identity["total_bytes"] < 0
        or source_identity["tree_digest"] != source_mount["source_digest"]
        or not isinstance(source_identity["tree_digest"], str)
        or len(source_identity["tree_digest"]) != 64
    ):
        raise LinuxModelError("source identity is not bound to the source mount")
    isolation = _require_exact_keys(
        plan["isolation"], frozenset(_ISOLATION), "isolation"
    )
    if dict(isolation) != _ISOLATION:
        raise LinuxModelError("linux model isolation policy is invalid")
    _normalize_tool_identity(_required_mapping(plan["tool"], "tool"))
    image = _required_mapping(plan["image"], "image")
    reference = image.get("reference")
    normalized_image = _normalize_image_identity(image, _normalize_image_reference(reference))
    if dict(image) != normalized_image:
        raise LinuxModelError("image identity is not canonical or immutable")
    _normalize_limits(_required_mapping(plan["limits"], "limits"))
    command_values = plan["commands"]
    if isinstance(command_values, (str, bytes)) or not isinstance(command_values, Sequence):
        raise LinuxModelError("plan commands are invalid")
    raw_commands: list[Sequence[str]] = []
    for index, command in enumerate(command_values, start=1):
        normalized = _require_exact_keys(command, frozenset({"id", "argv"}), f"commands[{index - 1}]")
        if normalized["id"] != f"command-{index:03d}":
            raise LinuxModelError("plan command ids are not canonical")
        argv = normalized["argv"]
        if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence):
            raise LinuxModelError("plan command argv is invalid")
        raw_commands.append(argv)
    if _normalize_commands(raw_commands) != list(command_values):
        raise LinuxModelError("plan commands are not canonical")
    if plan["claims"] != _CLAIMS:
        raise LinuxModelError("linux model claims must remain non-crediting")
    if plan["labels"] != _EVIDENCE_LABELS:
        raise LinuxModelError("linux model evidence labels must remain MODELLED_ONLY")
    return dict(plan)


def docker_run_argv(plan: Mapping[str, object], *, command_id: str) -> list[str]:
    """Return the exact no-shell Docker argv for one plan-bound command."""

    normalized = _validated_plan(plan)
    if not isinstance(command_id, str):
        raise LinuxModelError("command_id must be a string")
    command = next((item for item in normalized["commands"] if item["id"] == command_id), None)
    if command is None:
        raise LinuxModelError("command_id is absent from the plan")
    tool = normalized["tool"]
    image = normalized["image"]
    if tool["status"] != "AVAILABLE" or image["status"] != "AVAILABLE":
        raise LinuxModelError("a Docker run argv requires available bound tool and image")
    limits = normalized["limits"]
    source_mount = normalized["source_mount"]
    return [
        str(tool["executable"]),
        "run",
        "--rm",
        "--pull=never",
        "--read-only",
        "--network=none",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--pids-limit={limits['pids_limit']}",
        f"--memory={limits['memory_bytes']}b",
        f"--cpus={int(limits['cpus_millis']) / 1000:.3f}",
        "--user=65534:65534",
        "--workdir=/workspace",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,size={limits['tmpfs_bytes']}b",
        "--mount",
        "type=bind,source={source},target={target},readonly".format(
            source=source_mount["host_path"], target=source_mount["target_path"]
        ),
        str(image["resolved_reference"]),
        *(str(argument) for argument in command["argv"]),
    ]


def _unavailable_result(plan: Mapping[str, object], *, reason: str) -> dict[str, object]:
    return {
        "schema": RESULT_SCHEMA,
        "record_type": "LinuxModelResult",
        "status": "UNAVAILABLE",
        "reason": reason,
        "plan_digest": plan["plan_digest"],
        "container_executed": False,
        "linux_container_observed": False,
        "command_results": [],
        "claims": dict(_CLAIMS),
        "labels": dict(_EVIDENCE_LABELS),
    }


def _failed_result(
    plan: Mapping[str, object], *, reason: str, container_executed: bool = False, results: Sequence[Mapping[str, object]] = ()
) -> dict[str, object]:
    return {
        "schema": RESULT_SCHEMA,
        "record_type": "LinuxModelResult",
        "status": "FAIL",
        "reason": reason,
        "plan_digest": plan["plan_digest"],
        "container_executed": container_executed,
        "linux_container_observed": container_executed,
        "command_results": list(results),
        "claims": dict(_CLAIMS),
        "labels": dict(_EVIDENCE_LABELS),
    }


def _snippet(value: str | bytes | None) -> str:
    if value is None:
        return ""
    encoded = value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")
    return encoded[:_MAX_RESULT_SNIPPET_BYTES].decode("utf-8", errors="replace")


def run_linux_model(plan: Mapping[str, object]) -> dict[str, object]:
    """Execute only an identity-stable Docker plan, or return non-crediting UNAVAILABLE."""

    normalized = _validated_plan(plan)
    source_mount = normalized["source_mount"]
    try:
        current_source = _source_identity(Path(str(source_mount["host_path"])))
    except LinuxModelError:
        return _failed_result(normalized, reason="source-identity-unavailable")
    if current_source["tree_digest"] != source_mount["source_digest"]:
        return _failed_result(normalized, reason="source-identity-drift")

    bound_tool = normalized["tool"]
    if bound_tool["status"] != "AVAILABLE":
        return _unavailable_result(normalized, reason="plan-docker-unavailable")
    current_tool = _normalize_tool_identity(discover_docker(str(bound_tool["executable"])))
    if current_tool["status"] != "AVAILABLE":
        return _unavailable_result(normalized, reason="docker-unavailable-before-container")
    if current_tool["identity_digest"] != bound_tool["identity_digest"]:
        return _failed_result(normalized, reason="docker-identity-drift")

    bound_image = normalized["image"]
    if bound_image["status"] != "AVAILABLE":
        return _unavailable_result(normalized, reason="plan-image-unavailable")
    current_image = _normalize_image_identity(
        inspect_image(current_tool, str(bound_image["reference"])), str(bound_image["reference"])
    )
    if current_image["status"] != "AVAILABLE":
        return _unavailable_result(normalized, reason="docker-image-unavailable-before-container")
    if current_image["identity_digest"] != bound_image["identity_digest"]:
        return _failed_result(normalized, reason="image-identity-drift")

    command_results: list[dict[str, object]] = []
    container_executed = False
    timeout_seconds = int(normalized["limits"]["timeout_seconds"])
    for command in normalized["commands"]:
        command_id = str(command["id"])
        argv = docker_run_argv(normalized, command_id=command_id)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                check=False,
            )
            container_executed = True
        except subprocess.TimeoutExpired as error:
            container_executed = True
            command_results.append(
                {
                    "id": command_id,
                    "status": "FAIL",
                    "failure_class": "timeout",
                    "exit_code": None,
                    "elapsed_seconds": round(time.monotonic() - started, 6),
                    "stdout": _snippet(error.stdout),
                    "stderr": _snippet(error.stderr),
                }
            )
            return _failed_result(
                normalized,
                reason="container-command-timeout",
                container_executed=True,
                results=command_results,
            )
        except OSError as error:
            # Keep every earlier command receipt and the observation that a
            # prior container really ran. An OSError from a later launch must
            # not erase that evidence or relabel it pre-spawn unavailable.
            command_results.append(
                {
                    "id": command_id,
                    "status": "FAIL",
                    "failure_class": "docker-run-error",
                    "exit_code": None,
                    "elapsed_seconds": round(time.monotonic() - started, 6),
                    "stdout": "",
                    "stderr": _snippet(str(error)),
                }
            )
            return _failed_result(
                normalized,
                reason="docker-run-unavailable",
                container_executed=container_executed,
                results=command_results,
            )
        command_results.append(
            {
                "id": command_id,
                "status": "PASS" if completed.returncode == 0 else "FAIL",
                "failure_class": None if completed.returncode == 0 else "container-command-exit",
                "exit_code": completed.returncode,
                "elapsed_seconds": round(time.monotonic() - started, 6),
                "stdout": _snippet(completed.stdout),
                "stderr": _snippet(completed.stderr),
            }
        )
        if completed.returncode != 0:
            return _failed_result(
                normalized,
                reason="container-command-failed",
                container_executed=True,
                results=command_results,
            )

    try:
        post_source = _source_identity(Path(str(source_mount["host_path"])))
    except LinuxModelError:
        return _failed_result(
            normalized,
            reason="source-identity-unavailable-after-container",
            container_executed=container_executed,
            results=command_results,
        )
    if post_source["tree_digest"] != source_mount["source_digest"]:
        return _failed_result(
            normalized,
            reason="source-identity-drift-after-container",
            container_executed=container_executed,
            results=command_results,
        )
    return {
        "schema": RESULT_SCHEMA,
        "record_type": "LinuxModelResult",
        "status": "PASS",
        "reason": "all-container-commands-passed",
        "plan_digest": normalized["plan_digest"],
        "container_executed": True,
        "linux_container_observed": True,
        "command_results": command_results,
        "claims": dict(_CLAIMS),
        "labels": dict(_EVIDENCE_LABELS),
    }


def _command_json(value: str) -> tuple[str, ...]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise argparse.ArgumentTypeError("--command-json must be a JSON argv array") from error
    try:
        normalized = _normalize_commands([parsed])
    except LinuxModelError as error:
        raise argparse.ArgumentTypeError(str(error)) from error
    return tuple(str(item) for item in normalized[0]["argv"])


def _write_output(path: Path, payload: Mapping[str, object], source_root: Path) -> None:
    output = path.absolute()
    source = source_root.absolute()
    try:
        output.relative_to(source)
    except ValueError:
        pass
    else:
        raise LinuxModelError("output must be host-local and outside the read-only source root")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(_canonical_bytes(payload) + b"\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    for name in ("plan", "run"):
        command = commands.add_parser(name)
        command.add_argument("source_root", type=Path)
        command.add_argument("--image", default="python:3.14-slim")
        command.add_argument(
            "--command-json",
            action="append",
            type=_command_json,
            help="exact JSON argv array; may be repeated (default: [\"python\", \"--version\"])",
        )
        command.add_argument("--timeout-seconds", type=int, default=LinuxModelLimits.timeout_seconds)
        command.add_argument("--memory-bytes", type=int, default=LinuxModelLimits.memory_bytes)
        command.add_argument("--cpus-millis", type=int, default=LinuxModelLimits.cpus_millis)
        command.add_argument("--pids-limit", type=int, default=LinuxModelLimits.pids_limit)
        command.add_argument("--tmpfs-bytes", type=int, default=LinuxModelLimits.tmpfs_bytes)
        command.add_argument("--docker-executable", default="docker")
        command.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        limits = LinuxModelLimits(
            timeout_seconds=args.timeout_seconds,
            memory_bytes=args.memory_bytes,
            cpus_millis=args.cpus_millis,
            pids_limit=args.pids_limit,
            tmpfs_bytes=args.tmpfs_bytes,
        )
        plan = build_linux_model_plan(
            args.source_root,
            image=args.image,
            commands=args.command_json,
            limits=limits,
            docker_executable=args.docker_executable,
        )
        payload = plan if args.operation == "plan" else run_linux_model(plan)
        if args.output is not None:
            _write_output(args.output, payload, args.source_root)
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    except LinuxModelError as error:
        payload = {
            "schema": RESULT_SCHEMA,
            "record_type": "LinuxModelResult",
            "status": "FAIL",
            "reason": str(error),
            "container_executed": False,
            "linux_container_observed": False,
            "command_results": [],
            "claims": dict(_CLAIMS),
            "labels": dict(_EVIDENCE_LABELS),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return 1
    if args.operation == "plan":
        return 0
    return {"PASS": 0, "FAIL": 1, "UNAVAILABLE": 3}[str(payload["status"])]


if __name__ == "__main__":
    raise SystemExit(main())
