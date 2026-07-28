#!/usr/bin/env python3
"""Bounded, local command-cost measurements for the alpha.3 contract.

The harness deliberately distinguishes a new command process from a reused
``ProminService``.  It is evidence tooling, not a product/release gate: every
result is explicitly marked ``pass_credit=false``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
# Direct execution places ``tools/`` ahead of the repository.  That directory
# contains a compatibility ``promin.py`` launcher, so make the package root
# explicit before a measured runtime imports ``promin``.
if not sys.path or sys.path[0] != str(PACKAGE_ROOT):
    sys.path.insert(0, str(PACKAGE_ROOT))
_MEASUREMENT_MODES = {"cli_cold", "runtime_warm", "operation_incremental"}
_CONTRACT_STATUSES = {"enforced", "provisional"}
_PERCENTILES = {"p50", "p95", "p99"}
_COMMAND_ALIASES = {
    "init_review": "init review",
    "init_apply_small": "init apply small",
}
_REQUIRED_COMMANDS = {
    "status",
    "next",
    "context",
    "audit",
    "init review",
    "init apply small",
    "validate",
}
_REQUIRED_FIELDS = {
    "command",
    "measurement_mode",
    "workload_id",
    "status",
    "percentile",
    "budget_ms",
    "warmup_runs",
    "measured_runs",
    "max_files",
    "max_total_bytes",
    "provider_state",
    "projection_state",
}


class BenchError(RuntimeError):
    """Raised when a measurement contract or a bounded run is invalid."""


@dataclass(frozen=True)
class Sample:
    duration_ms: float
    phases_ms: Mapping[str, float]
    process_pid: int | None


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _canonical_command(value: object) -> str:
    if not isinstance(value, str):
        raise BenchError("latency contract command must be a string")
    return _COMMAND_ALIASES.get(value, value)


def _as_records(value: object) -> list[dict[str, Any]]:
    """Accept only the single new latency owner, either array or keyed map."""

    if isinstance(value, list):
        records = value
    elif isinstance(value, Mapping):
        records = list(value.values())
    else:
        raise BenchError("command_latency_contracts must be an array or object")
    if not records or not all(isinstance(record, Mapping) for record in records):
        raise BenchError("command_latency_contracts must contain records")
    return [dict(record) for record in records]


def validate_latency_contracts(conformance: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Validate the exact, unambiguous command-cost contract shape.

    This intentionally does not read the legacy ``*_warm`` maps.  Retaining
    those as a parallel source of truth would make a reported measurement
    ambiguous again.
    """

    if "command_latency_contracts" not in conformance:
        raise BenchError("canonical command_latency_contracts owner is missing")
    records = _as_records(conformance["command_latency_contracts"])
    observed: set[str] = set()
    identities: set[tuple[str, str, str]] = set()
    for index, record in enumerate(records):
        missing = sorted(_REQUIRED_FIELDS.difference(record))
        if missing:
            raise BenchError(f"latency contract {index} lacks fields: {', '.join(missing)}")
        command = _canonical_command(record["command"])
        mode = record["measurement_mode"]
        status = record["status"]
        percentile = record["percentile"]
        workload = record["workload_id"]
        if mode not in _MEASUREMENT_MODES:
            raise BenchError(f"latency contract {command!r} has invalid measurement_mode")
        if status not in _CONTRACT_STATUSES:
            raise BenchError(f"latency contract {command!r} has invalid status")
        if percentile not in _PERCENTILES:
            raise BenchError(f"latency contract {command!r} has invalid percentile")
        if not isinstance(workload, str) or not workload:
            raise BenchError(f"latency contract {command!r} lacks workload_id")
        for field in ("budget_ms", "warmup_runs", "measured_runs", "max_files", "max_total_bytes"):
            value = record[field]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise BenchError(f"latency contract {command!r} has invalid {field}")
        if record["budget_ms"] <= 0 or record["measured_runs"] <= 0:
            raise BenchError(f"latency contract {command!r} requires a positive budget and measured_runs")
        if not isinstance(record["provider_state"], str) or not record["provider_state"]:
            raise BenchError(f"latency contract {command!r} lacks provider_state")
        if not isinstance(record["projection_state"], str) or not record["projection_state"]:
            raise BenchError(f"latency contract {command!r} lacks projection_state")
        identity = (command, str(mode), str(workload))
        if identity in identities:
            raise BenchError(f"duplicate latency contract: {identity!r}")
        identities.add(identity)
        observed.add(command)
        record["command"] = command
    missing_commands = sorted(_REQUIRED_COMMANDS.difference(observed))
    if missing_commands:
        raise BenchError("latency contracts omit commands: " + ", ".join(missing_commands))
    observed_modes = {record["measurement_mode"] for record in records}
    missing_modes = sorted(_MEASUREMENT_MODES.difference(observed_modes))
    if missing_modes:
        raise BenchError("latency contracts omit measurement modes: " + ", ".join(missing_modes))
    validate_modes = {record["measurement_mode"] for record in records if record["command"] == "validate"}
    if not {"cli_cold", "runtime_warm"}.issubset(validate_modes):
        raise BenchError("validate requires both cli_cold and runtime_warm contracts")
    return sorted(records, key=lambda record: (record["command"], record["measurement_mode"], record["workload_id"]))


def _percentile(values: Iterable[float], label: str) -> float:
    ordered = sorted(values)
    if not ordered:
        raise BenchError("no duration samples were recorded")
    fraction = {"p50": 0.50, "p95": 0.95, "p99": 0.99}[label]
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _fixture(root: Path) -> None:
    """Create only bounded synthetic files; never point at production data."""

    root.mkdir(parents=True, exist_ok=True)
    (root / "README.md").write_text("# bounded command benchmark\n", encoding="utf-8")
    source = root / "src"
    source.mkdir(exist_ok=True)
    for index in range(8):
        (source / f"unit-{index}.py").write_text(f"VALUE_{index} = {index}\n", encoding="utf-8")


def _cli_argv(command: str, root: Path) -> list[str]:
    prefix = [sys.executable, "-m", "promin", "--root", str(root), "--no-telemetry"]
    commands = {
        "status": ["status"],
        "next": ["next"],
        "context": ["context", "README"],
        "audit": ["audit", "--max-files", "32", "--max-bytes", "65536"],
        "init review": ["init", "--goal", "bounded benchmark"],
        "init apply small": ["init", "--goal", "bounded benchmark", "--yes", "--max-preflight-files", "32"],
        "validate": ["validate", "--no-replay"],
    }
    try:
        return prefix + commands[command]
    except KeyError as exc:
        raise BenchError(f"unsupported benchmark command: {command}") from exc


def _run_cli_cold(command: str, root: Path) -> Sample:
    started = time.perf_counter_ns()
    process = subprocess.Popen(
        _cli_argv(command, root),
        cwd=PACKAGE_ROOT,
        env={**os.environ, "PYTHONPATH": str(PACKAGE_ROOT)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    _stdout, stderr = process.communicate()
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace")[:512]
        raise BenchError(f"cli_cold {command!r} failed: {detail}")
    return Sample(
        duration_ms=elapsed_ms,
        phases_ms={
            "process_import_ms": elapsed_ms,
            "contract_loading_ms": 0.0,
            "state_replay_ms": 0.0,
            "projection_open_update_ms": 0.0,
            "command_logic_ms": elapsed_ms,
            "serialization_ms": 0.0,
        },
        process_pid=process.pid,
    )


def _runtime_operation(command: str, root: Path, service: Any) -> Mapping[str, Any]:
    from promin.audit import audit_project
    from promin.context_index import query_context
    from promin.experience import load_bootstrap_state

    if command == "status":
        return service.status()
    if command == "next":
        bootstrap = load_bootstrap_state(root)
        grants = {} if not isinstance(bootstrap, Mapping) else bootstrap.get("grants", {})
        holder = grants.get("holder", {}) if isinstance(grants, Mapping) else {}
        reader = grants.get("reader", {}) if isinstance(grants, Mapping) else {}
        holder_id = holder.get("grant_id") if isinstance(holder, Mapping) else None
        reader_id = reader.get("grant_id") if isinstance(reader, Mapping) else None
        if not isinstance(holder_id, str) or not isinstance(reader_id, str):
            raise BenchError("runtime_warm next fixture lacks verified bootstrap grants")
        return service.next(
            subject_id="owner",
            grant_id=holder_id,
            query_grant_id=reader_id,
            depth=1,
        )
    if command == "context":
        return query_context(root, "README", limit=4, max_bytes=2048)
    if command == "audit":
        return audit_project(root, max_files=32, max_total_bytes=65536)
    if command == "validate":
        return service.validate(replay=False)
    raise BenchError(f"{command!r} is only measurable as cli_cold")


def _runtime_sample(command: str, root: Path, service: Any, startup_baseline_ms: float) -> Sample:
    from promin.contracts import load_contract_bundle
    from promin.context_index import context_index_status

    replay_started = time.perf_counter_ns()
    context = service._context()
    replay_ms = (time.perf_counter_ns() - replay_started) / 1_000_000
    contracts_started = time.perf_counter_ns()
    load_contract_bundle(context.installed_standard, context.bundle.preset_path)
    contract_ms = (time.perf_counter_ns() - contracts_started) / 1_000_000
    projection_started = time.perf_counter_ns()
    context_index_status(root)
    projection_ms = (time.perf_counter_ns() - projection_started) / 1_000_000
    command_started = time.perf_counter_ns()
    result = _runtime_operation(command, root, service)
    command_ms = (time.perf_counter_ns() - command_started) / 1_000_000
    serialization_started = time.perf_counter_ns()
    _canonical_bytes(dict(result))
    serialization_ms = (time.perf_counter_ns() - serialization_started) / 1_000_000
    total_ms = command_ms + serialization_ms
    return Sample(
        duration_ms=max(0.0, total_ms - startup_baseline_ms),
        phases_ms={
            "process_import_ms": 0.0,
            "contract_loading_ms": contract_ms,
            "state_replay_ms": replay_ms,
            "projection_open_update_ms": projection_ms,
            "command_logic_ms": command_ms,
            "serialization_ms": serialization_ms,
        },
        process_pid=os.getpid(),
    )


def _startup_baseline() -> float:
    started = time.perf_counter_ns()
    _canonical_bytes({"record_type": "ProminCommandBenchStartup"})
    return (time.perf_counter_ns() - started) / 1_000_000


def measure_contract(
    contract: Mapping[str, Any],
    *,
    root: Path,
    requested_mode: str,
) -> dict[str, Any]:
    """Measure a single canonical contract without widening its workload."""

    command = _canonical_command(contract["command"])
    mode = str(contract["measurement_mode"])
    if requested_mode != mode:
        raise BenchError(f"contract is {mode!r}, not requested mode {requested_mode!r}")
    _fixture(root)
    if command in {"next", "context", "validate"} or mode != "cli_cold":
        apply = _run_cli_cold("init apply small", root)
        if apply.process_pid is None:  # pragma: no cover - defensive invariant
            raise BenchError("fixture initialization did not run as a child process")
    samples: list[Sample] = []
    repetitions = int(contract["warmup_runs"]) + int(contract["measured_runs"])
    if mode == "cli_cold":
        for index in range(repetitions):
            # A first apply is semantically different from idempotent reapply.
            # Keep every sample a genuine first apply without touching data
            # outside the supplied bounded fixture root.
            sample_root = root / f"init-apply-{index}" if command == "init apply small" else root
            if sample_root != root:
                _fixture(sample_root)
            samples.append(_run_cli_cold(command, sample_root))
        service_pid = None
        startup_baseline_ms = None
    else:
        from promin.service import ProminService

        service = ProminService(root)
        service_pid = os.getpid()
        baseline = _startup_baseline() if mode == "operation_incremental" else 0.0
        startup_baseline_ms = baseline
        for _ in range(repetitions):
            samples.append(_runtime_sample(command, root, service, baseline))
    measured = samples[int(contract["warmup_runs"]) :]
    percentile = str(contract["percentile"])
    measured_ms = [sample.duration_ms for sample in measured]
    phase_names = tuple(measured[0].phases_ms) if measured else ()
    phases = {name: _percentile([sample.phases_ms[name] for sample in measured], percentile) for name in phase_names}
    value = _percentile(measured_ms, percentile)
    budget = int(contract["budget_ms"])
    from promin import __version__

    child_pids = [sample.process_pid for sample in measured if sample.process_pid and sample.process_pid != os.getpid()]
    return {
        "record_type": "ProminCommandBenchmark",
        "command": command,
        "measurement_mode": mode,
        "workload_id": contract["workload_id"],
        "contract_status": contract["status"],
        "percentile": percentile,
        "budget_ms": budget,
        "observed_ms": value,
        "within_budget": value <= budget,
        "warmup_runs": int(contract["warmup_runs"]),
        "measured_runs": int(contract["measured_runs"]),
        "provider_state": contract["provider_state"],
        "projection_state": contract["projection_state"],
        "max_files": int(contract["max_files"]),
        "max_total_bytes": int(contract["max_total_bytes"]),
        "phase_timings_ms": phases,
        "startup_baseline_ms": startup_baseline_ms,
        "runner_pid": os.getpid(),
        "service_pid": service_pid,
        "service_instance_count": 0 if service_pid is None else 1,
        "runtime_warm_single_service": mode != "runtime_warm" or service_pid == os.getpid(),
        "child_pids": child_pids,
        "new_process_per_sample": mode != "cli_cold" or len(set(child_pids)) == len(child_pids) == len(measured),
        "platform": platform.platform(),
        "python": sys.version,
        "package_version": __version__,
        "package_root": str(PACKAGE_ROOT),
        "production_data": False,
        "network_used": False,
        "global_install_used": False,
        "product_acceptance_pass": False,
        "public_release_approved": False,
        "pass_credit": False,
    }


def _load_contracts(path: Path) -> list[dict[str, Any]]:
    try:
        # Windows evidence generators commonly emit UTF-8 with BOM; this is
        # transport syntax, not a different canonical contract.
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchError(f"cannot load conformance: {exc}") from exc
    if not isinstance(data, Mapping):
        raise BenchError("conformance document must be an object")
    return validate_latency_contracts(data)


def _candidate_binding(path: Path | None) -> Mapping[str, Any] | None:
    if path is None:
        return None
    try:
        payload = path.read_bytes()
        value = json.loads(payload.decode("utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchError(f"cannot load CandidateBinding: {exc}") from exc
    if not isinstance(value, Mapping):
        raise BenchError("CandidateBinding must be an object")
    return {
        "path": str(path.resolve()),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "record_type": value.get("record_type"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=sorted(_MEASUREMENT_MODES))
    parser.add_argument("--command", required=True, choices=sorted(_REQUIRED_COMMANDS))
    parser.add_argument("--conformance", type=Path, default=PACKAGE_ROOT / "core" / "conformance.json")
    parser.add_argument("--fixture-root", type=Path)
    parser.add_argument("--candidate-binding", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    contracts = _load_contracts(args.conformance)
    matches = [
        contract
        for contract in contracts
        if contract["command"] == args.command and contract["measurement_mode"] == args.mode
    ]
    if len(matches) != 1:
        raise BenchError("exactly one matching command/mode contract is required")
    if args.fixture_root is None:
        with tempfile.TemporaryDirectory(prefix="promin-command-bench-") as temporary:
            result = measure_contract(matches[0], root=Path(temporary), requested_mode=args.mode)
    else:
        result = measure_contract(matches[0], root=args.fixture_root, requested_mode=args.mode)
    result["candidate_binding"] = _candidate_binding(args.candidate_binding)
    encoded = _canonical_bytes(result)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(encoded + b"\n")
    sys.stdout.buffer.write(encoded + b"\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BenchError as exc:
        sys.stderr.write(f"promin-command-bench: {exc}\n")
        raise SystemExit(2)
