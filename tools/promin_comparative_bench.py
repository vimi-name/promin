#!/usr/bin/env python3
"""Run a bounded, repeatable Promin comparative benchmark.

The benchmark compares three deliberately different repository shapes:

* ``promin``: a synthetic Markdown source tree operated through Promin's public
  CLI command handler;
* ``markdown``: the same source tree operated by a small conventional
  Markdown-index workflow; and
* ``empty``: an empty-root filesystem baseline.

It is evidence tooling, never an acceptance gate.  Both the planned and the
executed JSON record have ``claim=false`` and ``pass_credit=false``.  The
Markdown and empty paths are measurement baselines, not substitutes for
Promin's authority, documentation, or query semantics.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
from ctypes import wintypes
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import io
import json
from itertools import product
import math
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Iterable, Mapping, Sequence


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
# Direct execution starts from ``tools/``, which also contains a compatibility
# ``promin.py`` launcher.  Always put the checked-out package first rather
# than accepting either that launcher or an unrelated global installation.
if str(PACKAGE_ROOT) in sys.path:
    sys.path.remove(str(PACKAGE_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT))

SCENARIOS = ("promin", "markdown", "empty")
OPERATIONS = ("init", "update", "query", "docs")
TEMPERATURES = ("cold", "warm")
DEFAULT_SIZES = (16, 64, 256)
DEFAULT_WARMUP_RUNS = 1
DEFAULT_MEASURED_RUNS = 3
DEFAULT_SAMPLING_INTERVAL_MS = 5
QUERY_TEXT = "comparative benchmark"
_MAX_ERROR_TEXT = 1024
FIXED_BUCKET_COUNT = len(SCENARIOS) * len(OPERATIONS) * len(TEMPERATURES) * len(DEFAULT_SIZES)


class ComparativeBenchError(RuntimeError):
    """Raised when the benchmark protocol cannot produce truthful evidence."""


@dataclass(frozen=True)
class BenchmarkConfig:
    """Immutable run settings that are copied verbatim into the JSON result."""

    sizes: tuple[int, ...] = DEFAULT_SIZES
    warmup_runs: int = DEFAULT_WARMUP_RUNS
    measured_runs: int = DEFAULT_MEASURED_RUNS
    sampling_interval_ms: int = DEFAULT_SAMPLING_INTERVAL_MS
    scenarios: tuple[str, ...] = SCENARIOS
    operations: tuple[str, ...] = OPERATIONS


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_error(exc: BaseException) -> str:
    text = str(exc) or type(exc).__name__
    return text.replace("\r", " ").replace("\n", " ")[:_MAX_ERROR_TEXT]


def _parse_csv(value: str, *, allowed: Iterable[str], label: str) -> tuple[str, ...]:
    values = tuple(item.strip() for item in value.split(",") if item.strip())
    allowed_values = set(allowed)
    if not values:
        raise ComparativeBenchError(f"{label} must not be empty")
    if len(set(values)) != len(values):
        raise ComparativeBenchError(f"{label} must not contain duplicates")
    unknown = sorted(set(values).difference(allowed_values))
    if unknown:
        raise ComparativeBenchError(f"{label} contains unsupported values: {', '.join(unknown)}")
    return values


def parse_sizes(value: str) -> tuple[int, ...]:
    """Parse exactly three or more strictly increasing fixture sizes."""

    try:
        sizes = tuple(int(item.strip()) for item in value.split(",") if item.strip())
    except ValueError as exc:
        raise ComparativeBenchError("sizes must be a comma-separated list of integers") from exc
    if len(sizes) < 3:
        raise ComparativeBenchError("nonlinear scaling requires at least three sizes")
    if any(size < 1 for size in sizes):
        raise ComparativeBenchError("sizes must be positive")
    if tuple(sorted(sizes)) != sizes or len(set(sizes)) != len(sizes):
        raise ComparativeBenchError("sizes must be strictly increasing")
    return sizes


def validate_config(config: BenchmarkConfig) -> None:
    if len(config.sizes) < 3 or tuple(sorted(config.sizes)) != config.sizes or any(size < 1 for size in config.sizes):
        raise ComparativeBenchError("config requires at least three strictly increasing positive sizes")
    if config.warmup_runs < 0:
        raise ComparativeBenchError("warmup_runs must be non-negative")
    if config.measured_runs < 1:
        raise ComparativeBenchError("measured_runs must be positive")
    if not 1 <= config.sampling_interval_ms <= 1_000:
        raise ComparativeBenchError("sampling_interval_ms must be between 1 and 1000")
    for label, values, allowed in (
        ("scenarios", config.scenarios, SCENARIOS),
        ("operations", config.operations, OPERATIONS),
    ):
        if not values or len(values) != len(set(values)) or not set(values).issubset(allowed):
            raise ComparativeBenchError(f"config has invalid {label}")


def percentile(values: Sequence[float], fraction: float) -> float:
    """Linearly interpolate a percentile without an optional dependency."""

    if not values:
        raise ComparativeBenchError("cannot calculate a percentile without samples")
    if not 0.0 <= fraction <= 1.0:
        raise ComparativeBenchError("percentile fraction must be between zero and one")
    ordered = sorted(float(value) for value in values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _percentile_summary(values: Sequence[float | int]) -> dict[str, float] | None:
    numeric = [float(value) for value in values]
    if not numeric:
        return None
    return {
        "p50": round(percentile(numeric, 0.50), 6),
        "p95": round(percentile(numeric, 0.95), 6),
        "p99": round(percentile(numeric, 0.99), 6),
    }


def _read_rss() -> tuple[int | None, int | None, str]:
    """Return current and lifetime RSS when the local OS exposes them.

    The benchmark needs no optional dependency.  Linux and Windows expose a
    current working-set value.  Unsupported hosts report unavailable metrics
    instead of manufacturing a zero value.
    """

    if os.name == "nt":
        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        try:
            current = ctypes.windll.kernel32.GetCurrentProcess
            current.argtypes = []
            current.restype = wintypes.HANDLE
            memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
            memory_info.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessMemoryCounters), wintypes.DWORD]
            memory_info.restype = wintypes.BOOL
            if not memory_info(current(), ctypes.byref(counters), counters.cb):
                return None, None, "windows-psapi-unavailable"
        except (AttributeError, OSError):
            return None, None, "windows-psapi-unavailable"
        return int(counters.WorkingSetSize), int(counters.PeakWorkingSetSize), "windows-psapi"

    if sys.platform.startswith("linux"):
        try:
            fields = (Path("/proc/self/statm").read_text(encoding="ascii").split())
            current = int(fields[1]) * int(os.sysconf("SC_PAGE_SIZE"))
            return current, None, "linux-proc-statm"
        except (OSError, ValueError, IndexError):
            return None, None, "linux-proc-unavailable"

    return None, None, "unavailable"


def _measure_operation(
    operation: Callable[[], Mapping[str, Any]],
    *,
    sampling_interval_ms: int,
) -> tuple[Mapping[str, Any], dict[str, Any]]:
    """Measure actual work in this process, including CPU and sampled RSS."""

    baseline_rss, baseline_lifetime_peak, rss_source = _read_rss()
    sampled_peak = baseline_rss
    sample_count = 1 if baseline_rss is not None else 0
    sampling_error: str | None = None
    stop = threading.Event()
    lock = threading.Lock()

    def sample() -> None:
        nonlocal sampled_peak, sample_count, sampling_error, rss_source
        try:
            while not stop.wait(sampling_interval_ms / 1_000.0):
                current, _lifetime_peak, observed_source = _read_rss()
                if observed_source != rss_source and rss_source == "unavailable":
                    rss_source = observed_source
                if current is not None:
                    with lock:
                        sampled_peak = current if sampled_peak is None else max(sampled_peak, current)
                        sample_count += 1
        except Exception as exc:  # evidence must expose, never hide, sampler loss.
            sampling_error = _safe_error(exc)

    sampler = threading.Thread(target=sample, name="promin-comparative-rss", daemon=True)
    sampler.start()
    wall_started = time.perf_counter_ns()
    cpu_started = time.process_time_ns()
    try:
        result = operation()
    finally:
        cpu_elapsed_ns = time.process_time_ns() - cpu_started
        wall_elapsed_ns = time.perf_counter_ns() - wall_started
        stop.set()
        sampler.join(timeout=2.0)
        if sampler.is_alive():
            sampling_error = "rss sampler did not stop within two seconds"
    final_rss, final_lifetime_peak, final_source = _read_rss()
    if final_rss is not None:
        with lock:
            sampled_peak = final_rss if sampled_peak is None else max(sampled_peak, final_rss)
            sample_count += 1
    if rss_source == "unavailable":
        rss_source = final_source
    lifetime_peak = final_lifetime_peak if final_lifetime_peak is not None else baseline_lifetime_peak
    incremental = None if baseline_rss is None or sampled_peak is None else max(0, sampled_peak - baseline_rss)
    return result, {
        "wall_ms": round(wall_elapsed_ns / 1_000_000.0, 6),
        "cpu_ms": round(cpu_elapsed_ns / 1_000_000.0, 6),
        "rss": {
            "available": sampled_peak is not None,
            "source": rss_source,
            "sampling_interval_ms": sampling_interval_ms,
            "sample_count": sample_count,
            "baseline_bytes": baseline_rss,
            "peak_sampled_bytes": sampled_peak,
            "incremental_peak_bytes": incremental,
            "lifetime_peak_bytes": lifetime_peak,
            "sampling_error": sampling_error,
        },
    }


def _tree_storage(root: Path) -> dict[str, int]:
    """Count regular-file payloads only; never follow a link into user data."""

    if not root.exists():
        return {"file_count": 0, "total_bytes": 0, "markdown_bytes": 0, "control_bytes": 0}
    file_count = total_bytes = markdown_bytes = control_bytes = 0
    for directory, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        directories[:] = [
            name for name in directories if not (current / name).is_symlink()
        ]
        for name in filenames:
            path = current / name
            try:
                info = path.lstat()
            except OSError:
                continue
            if path.is_symlink() or not path.is_file():
                continue
            size = int(info.st_size)
            file_count += 1
            total_bytes += size
            relative = path.relative_to(root)
            if path.suffix.casefold() == ".md":
                markdown_bytes += size
            if relative.parts and relative.parts[0] == ".promin":
                control_bytes += size
    return {
        "file_count": file_count,
        "total_bytes": total_bytes,
        "markdown_bytes": markdown_bytes,
        "control_bytes": control_bytes,
    }


def _seed_markdown_source(root: Path, size: int) -> None:
    """Write the same deterministic Markdown corpus for Promin and baseline."""

    docs = root / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    root.joinpath("README.md").write_text(
        "# Comparative benchmark source\n\n"
        "This repository contains deterministic comparative benchmark material.\n",
        encoding="utf-8",
        newline="\n",
    )
    for index in range(size):
        text = (
            f"# Benchmark note {index:05d}\n\n"
            "Comparative benchmark content is intentionally deterministic. "
            f"Document {index:05d} provides a Markdown-only source unit.\n"
        )
        docs.joinpath(f"note-{index:05d}.md").write_text(text, encoding="utf-8", newline="\n")


def _mutate_markdown_source(root: Path) -> None:
    target = root / "docs" / "note-00000.md"
    if not target.is_file():
        raise ComparativeBenchError("benchmark source fixture is missing note-00000.md")
    with target.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write("\nUpdate input: comparative benchmark revision one.\n")


def _markdown_index(root: Path) -> dict[str, Any]:
    """Execute a real conventional Markdown index update for the baseline."""

    index = root / "docs" / "INDEX.md"
    sources = sorted(
        (
            path for path in root.rglob("*.md")
            if path != index and not path.is_symlink() and path.is_file()
        ),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    rows = ["# Markdown index", ""]
    for path in sources:
        relative = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="strict")
        title = next((line[2:].strip() for line in text.splitlines() if line.startswith("# ")), relative)
        rows.append(f"- [{title}]({relative})")
    payload = ("\n".join(rows) + "\n").encode("utf-8")
    temporary = index.with_suffix(".tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, index)
    return {"route": "markdown-index", "status": "updated", "indexed_documents": len(sources), "index_bytes": len(payload)}


def _markdown_query(root: Path, query: str) -> dict[str, Any]:
    query_folded = query.casefold()
    matches: list[str] = []
    for path in sorted(root.rglob("*.md"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink() or not path.is_file():
            continue
        if query_folded in path.read_text(encoding="utf-8", errors="strict").casefold():
            matches.append(path.relative_to(root).as_posix())
    if not matches:
        raise ComparativeBenchError("Markdown query returned no known benchmark content")
    return {"route": "markdown-linear-scan", "status": "ok", "result_count": len(matches)}


def _empty_probe(root: Path, operation: str) -> dict[str, Any]:
    if operation == "init":
        root.mkdir(parents=True, exist_ok=False)
    if not root.is_dir():
        raise ComparativeBenchError("empty baseline root is unavailable")
    entries = list(os.scandir(root))
    if entries:
        raise ComparativeBenchError("empty baseline unexpectedly contains files")
    return {"route": "empty-filesystem-baseline", "status": "ok", "entry_count": 0}


def _call_promin_cli(arguments: Sequence[str]) -> dict[str, Any]:
    """Invoke Promin's public CLI handler without polluting worker JSONL stdout."""

    from promin.__main__ import main as promin_main

    stdout_raw = io.BytesIO()
    stderr_raw = io.BytesIO()
    stdout = io.TextIOWrapper(stdout_raw, encoding="utf-8", write_through=True)
    stderr = io.TextIOWrapper(stderr_raw, encoding="utf-8", write_through=True)
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = promin_main(list(arguments))
        stdout.flush()
        stderr.flush()
        captured_stdout = stdout_raw.getvalue()
        captured_stderr = stderr_raw.getvalue().decode("utf-8", errors="replace")
    finally:
        # ``detach`` prevents the wrapper finalizer from closing BytesIO before
        # its captured contents are consumed above.
        with contextlib.suppress(ValueError):
            stdout.detach()
        with contextlib.suppress(ValueError):
            stderr.detach()
    if code != 0:
        raise ComparativeBenchError(f"Promin CLI returned {code}: {captured_stderr[:_MAX_ERROR_TEXT]}")
    try:
        value = json.loads(captured_stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ComparativeBenchError("Promin CLI did not emit one JSON result") from exc
    if not isinstance(value, dict):
        raise ComparativeBenchError("Promin CLI result must be a JSON object")
    return value


def _promin_init(root: Path, size: int) -> dict[str, Any]:
    result = _call_promin_cli(
        (
            "--root", str(root), "--no-telemetry", "init", "--goal", "comparative benchmark",
            "--yes", "--documentation", "decline", "--verification", "decline",
            "--max-preflight-files", str(max(32, size + 4)),
        )
    )
    activation = root / ".promin" / "init" / "activation.json"
    if result.get("record_type") not in {"InitializationResult", "InitResult"} or not activation.is_file():
        raise ComparativeBenchError("Promin init did not create a verified activation")
    return {
        "route": "promin-public-cli:init",
        "status": result.get("status"),
        "activation_present": True,
        "project_mode": result.get("project_mode"),
    }


def _promin_refresh(root: Path) -> dict[str, Any]:
    result = _call_promin_cli(("--root", str(root), "--no-telemetry", "refresh"))
    if result.get("record_type") != "ProminRefreshResult" or result.get("status") not in {"updated", "current"}:
        raise ComparativeBenchError("Promin refresh did not produce a current or updated result")
    return {
        "route": "promin-public-cli:refresh",
        "status": result.get("status"),
        "changed_operations": result.get("changed_operations"),
        "documentation_status": (result.get("documentation") or {}).get("status"),
        "context_status": (result.get("context_index") or {}).get("status"),
    }


def _promin_query(root: Path) -> dict[str, Any]:
    result = _call_promin_cli(
        ("--root", str(root), "--no-telemetry", "context", QUERY_TEXT, "--limit", "8", "--max-bytes", "8192")
    )
    if result.get("record_type") != "ContextQueryResult" or not isinstance(result.get("result_count"), int):
        raise ComparativeBenchError("Promin context query did not return a valid result")
    if result["result_count"] < 1:
        raise ComparativeBenchError("Promin context query returned no known benchmark content")
    return {
        "route": "promin-public-cli:context",
        "status": "ok",
        "backend": result.get("backend"),
        "result_count": result["result_count"],
        "truncated": result.get("truncated"),
    }


def prepare_case(root: Path, *, scenario: str, operation: str, size: int) -> dict[str, Any]:
    """Create an unmeasured precondition for exactly one isolated sample."""

    if scenario not in SCENARIOS or operation not in OPERATIONS or size < 1:
        raise ComparativeBenchError("worker received an invalid scenario, operation, or size")
    if root.exists():
        raise ComparativeBenchError("sample root already exists; refusing to overwrite a fixture")
    root.parent.mkdir(parents=True, exist_ok=True)

    # A genuine empty-repository init measures root creation.  Other cases
    # receive their same source corpus as an unmeasured input precondition.
    if scenario == "empty" and operation == "init":
        return {"precondition": "empty parent ready; init creates the root", "storage_before": _tree_storage(root)}

    root.mkdir(parents=True, exist_ok=False)
    if scenario in {"promin", "markdown"}:
        _seed_markdown_source(root, size)

    if scenario == "promin":
        if operation != "init":
            _promin_init(root, size)
        if operation in {"update", "query"}:
            _promin_refresh(root)
        if operation == "update":
            _mutate_markdown_source(root)
    elif scenario == "markdown":
        if operation == "update":
            _markdown_index(root)
            _mutate_markdown_source(root)
    return {
        "precondition": "prepared outside timed interval",
        "storage_before": _tree_storage(root),
    }


def measure_case(
    root: Path,
    *,
    scenario: str,
    operation: str,
    size: int,
    sampling_interval_ms: int,
) -> dict[str, Any]:
    """Run one real operation after ``prepare_case`` established its input."""

    if scenario not in SCENARIOS or operation not in OPERATIONS or size < 1:
        raise ComparativeBenchError("worker received an invalid scenario, operation, or size")
    if scenario != "empty" or operation != "init":
        if not root.is_dir():
            raise ComparativeBenchError("prepared sample root is unavailable")
    storage_before = _tree_storage(root)

    def execute() -> Mapping[str, Any]:
        if scenario == "promin":
            if operation == "init":
                return _promin_init(root, size)
            if operation in {"update", "docs"}:
                return _promin_refresh(root)
            return _promin_query(root)
        if scenario == "markdown":
            if operation in {"init", "update", "docs"}:
                return _markdown_index(root)
            return _markdown_query(root, QUERY_TEXT)
        return _empty_probe(root, operation)

    operation_result, measurement = _measure_operation(execute, sampling_interval_ms=sampling_interval_ms)
    return {
        "scenario": scenario,
        "operation": operation,
        "size": size,
        "worker_pid": os.getpid(),
        "operation_result": dict(operation_result),
        "measurement": measurement,
        "storage_before": storage_before,
        "storage_after": _tree_storage(root),
    }


def _worker_response(request: Mapping[str, Any]) -> dict[str, Any]:
    action = request.get("action")
    root_value = request.get("root")
    scenario = request.get("scenario")
    operation = request.get("operation")
    size = request.get("size")
    if not isinstance(action, str) or not isinstance(root_value, str) or not isinstance(scenario, str) or not isinstance(operation, str):
        raise ComparativeBenchError("worker request has invalid required fields")
    if not isinstance(size, int) or isinstance(size, bool):
        raise ComparativeBenchError("worker request size must be an integer")
    root = Path(root_value)
    if action == "prepare":
        return {
            "status": "ok",
            "action": action,
            "result": prepare_case(root, scenario=scenario, operation=operation, size=size),
            "worker_pid": os.getpid(),
        }
    if action == "measure":
        interval = request.get("sampling_interval_ms")
        if not isinstance(interval, int) or isinstance(interval, bool):
            raise ComparativeBenchError("worker request sampling_interval_ms must be an integer")
        return {
            "status": "ok",
            "action": action,
            "sample": measure_case(root, scenario=scenario, operation=operation, size=size, sampling_interval_ms=interval),
            "worker_pid": os.getpid(),
        }
    raise ComparativeBenchError("worker request action must be prepare or measure")


def worker_main() -> int:
    """JSONL worker protocol used only by the parent benchmark process."""

    for raw_line in sys.stdin:
        try:
            value = json.loads(raw_line)
            if not isinstance(value, Mapping):
                raise ComparativeBenchError("worker request must be a JSON object")
            response = _worker_response(value)
        except Exception as exc:
            response = {"status": "error", "error_type": type(exc).__name__, "reason": _safe_error(exc), "worker_pid": os.getpid()}
        sys.stdout.buffer.write(_canonical_bytes(response) + b"\n")
        sys.stdout.buffer.flush()
    return 0


class _WorkerClient:
    """One isolated Python worker with a line-oriented, failure-visible API."""

    def __init__(self) -> None:
        environment = dict(os.environ)
        previous_path = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = str(PACKAGE_ROOT) if not previous_path else str(PACKAGE_ROOT) + os.pathsep + previous_path
        self._process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--worker"],
            cwd=PACKAGE_ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )

    def request(self, value: Mapping[str, Any]) -> dict[str, Any]:
        if self._process.stdin is None or self._process.stdout is None:
            raise ComparativeBenchError("benchmark worker pipes are unavailable")
        self._process.stdin.write(_canonical_bytes(value).decode("utf-8") + "\n")
        self._process.stdin.flush()
        line = self._process.stdout.readline()
        if not line:
            detail = ""
            if self._process.stderr is not None:
                detail = self._process.stderr.read()[:_MAX_ERROR_TEXT]
            raise ComparativeBenchError(f"benchmark worker stopped before responding: {detail}")
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ComparativeBenchError("benchmark worker emitted invalid JSON") from exc
        if not isinstance(response, dict):
            raise ComparativeBenchError("benchmark worker response must be an object")
        return response

    def close(self) -> None:
        if self._process.stdin is not None and not self._process.stdin.closed:
            self._process.stdin.close()
        try:
            self._process.wait(timeout=20)
        except subprocess.TimeoutExpired as exc:
            self._process.kill()
            self._process.wait(timeout=5)
            raise ComparativeBenchError("benchmark worker did not exit within twenty seconds") from exc
        if self._process.returncode not in {0, None}:
            detail = ""
            if self._process.stderr is not None:
                detail = self._process.stderr.read()[:_MAX_ERROR_TEXT]
            raise ComparativeBenchError(f"benchmark worker exited with {self._process.returncode}: {detail}")

    def __enter__(self) -> "_WorkerClient":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def _new_case_path(
    fixture_root: Path,
    *,
    scenario: str,
    operation: str,
    temperature: str,
    size: int,
    phase: str,
    index: int,
) -> Path:
    return fixture_root / "cases" / f"{scenario}-{operation}-{temperature}-size{size}-{phase}{index:03d}"


def _request_payload(root: Path, *, action: str, scenario: str, operation: str, size: int, config: BenchmarkConfig) -> dict[str, Any]:
    value: dict[str, Any] = {
        "action": action,
        "root": str(root),
        "scenario": scenario,
        "operation": operation,
        "size": size,
    }
    if action == "measure":
        value["sampling_interval_ms"] = config.sampling_interval_ms
    return value


def _failed_sample(response: Mapping[str, Any], *, temperature: str, phase: str, index: int) -> dict[str, Any]:
    return {
        "status": "failed",
        "temperature": temperature,
        "phase": phase,
        "index": index,
        "error_type": response.get("error_type", "WorkerProtocolError"),
        "reason": response.get("reason", "worker returned no reason"),
    }


def _prepared_sample(
    worker: _WorkerClient,
    root: Path,
    *,
    scenario: str,
    operation: str,
    size: int,
    config: BenchmarkConfig,
    temperature: str,
    phase: str,
    index: int,
) -> dict[str, Any]:
    prepared = worker.request(_request_payload(root, action="prepare", scenario=scenario, operation=operation, size=size, config=config))
    if prepared.get("status") != "ok":
        return _failed_sample(prepared, temperature=temperature, phase=phase, index=index)
    measured = worker.request(_request_payload(root, action="measure", scenario=scenario, operation=operation, size=size, config=config))
    if measured.get("status") != "ok" or not isinstance(measured.get("sample"), Mapping):
        return _failed_sample(measured, temperature=temperature, phase=phase, index=index)
    sample = dict(measured["sample"])
    sample.update({"status": "measured", "temperature": temperature, "phase": phase, "index": index})
    return sample


def _cold_sample(
    root: Path,
    *,
    scenario: str,
    operation: str,
    size: int,
    config: BenchmarkConfig,
    phase: str,
    index: int,
) -> dict[str, Any]:
    # The preparation worker exits before the measurement worker starts.  The
    # measured process therefore imports and opens the actual initialized state
    # afresh, while setup itself remains outside the timed interval.
    with _WorkerClient() as preparation_worker:
        prepared = preparation_worker.request(
            _request_payload(
                root,
                action="prepare",
                scenario=scenario,
                operation=operation,
                size=size,
                config=config,
            )
        )
    if prepared.get("status") != "ok":
        return _failed_sample(prepared, temperature="cold", phase=phase, index=index)
    with _WorkerClient() as measurement_worker:
        measured = measurement_worker.request(
            _request_payload(
                root,
                action="measure",
                scenario=scenario,
                operation=operation,
                size=size,
                config=config,
            )
        )
    if measured.get("status") != "ok" or not isinstance(measured.get("sample"), Mapping):
        return _failed_sample(measured, temperature="cold", phase=phase, index=index)
    sample = dict(measured["sample"])
    sample.update({"status": "measured", "temperature": "cold", "phase": phase, "index": index})
    return sample


def _summary_for_samples(
    *,
    scenario: str,
    operation: str,
    temperature: str,
    size: int,
    warmups: Sequence[Mapping[str, Any]],
    samples: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    successful = [sample for sample in samples if sample.get("status") == "measured"]

    def values(path: Sequence[str]) -> list[float | int]:
        result: list[float | int] = []
        for sample in successful:
            current: Any = sample
            for key in path:
                if not isinstance(current, Mapping):
                    current = None
                    break
                current = current.get(key)
            if isinstance(current, (int, float)) and not isinstance(current, bool):
                result.append(current)
        return result

    complete = len(successful) == len(samples)
    return {
        "scenario": scenario,
        "operation": operation,
        "temperature": temperature,
        "size": size,
        "status": "measured" if complete else "failed",
        "warmup_sample_count": len(warmups),
        "measured_sample_count": len(samples),
        "successful_sample_count": len(successful),
        "latency_ms": _percentile_summary(values(("measurement", "wall_ms"))),
        "cpu_ms": _percentile_summary(values(("measurement", "cpu_ms"))),
        "rss_peak_sampled_bytes": _percentile_summary(values(("measurement", "rss", "peak_sampled_bytes"))),
        "rss_incremental_peak_bytes": _percentile_summary(values(("measurement", "rss", "incremental_peak_bytes"))),
        "storage_total_bytes": _percentile_summary(values(("storage_after", "total_bytes"))),
        "storage_control_bytes": _percentile_summary(values(("storage_after", "control_bytes"))),
        "samples": list(samples),
        "warmup_samples": list(warmups),
        "claim": False,
        "pass_credit": False,
    }


def scaling_checks(results: Sequence[Mapping[str, Any]], *, sizes: Sequence[int]) -> list[dict[str, Any]]:
    """Report p95 growth observations; never turn a heuristic into a pass."""

    grouped: dict[tuple[str, str, str], dict[int, Mapping[str, Any]]] = {}
    for result in results:
        key = (str(result.get("scenario")), str(result.get("operation")), str(result.get("temperature")))
        size = result.get("size")
        if isinstance(size, int) and not isinstance(size, bool):
            grouped.setdefault(key, {})[size] = result
    checks: list[dict[str, Any]] = []
    for key in sorted(grouped):
        by_size = grouped[key]
        intervals: list[dict[str, Any]] = []
        complete = True
        for lower, upper in zip(sizes, sizes[1:]):
            lower_latency = ((by_size.get(lower, {}).get("latency_ms") or {}).get("p95"))
            upper_latency = ((by_size.get(upper, {}).get("latency_ms") or {}).get("p95"))
            if (
                not isinstance(lower_latency, (int, float))
                or not isinstance(upper_latency, (int, float))
                or lower_latency <= 0
                or upper_latency <= 0
            ):
                complete = False
                intervals.append({"from_size": lower, "to_size": upper, "status": "unavailable"})
                continue
            workload_factor = upper / lower
            latency_factor = float(upper_latency) / float(lower_latency)
            slope = math.log(latency_factor) / math.log(workload_factor)
            intervals.append(
                {
                    "from_size": lower,
                    "to_size": upper,
                    "status": "observed",
                    "workload_factor": round(workload_factor, 6),
                    "p95_latency_factor": round(latency_factor, 6),
                    "p95_log_slope": round(slope, 6),
                    "superlinear_indicator": slope > 1.20,
                }
            )
        checks.append(
            {
                "scenario": key[0],
                "operation": key[1],
                "temperature": key[2],
                "sizes": list(sizes),
                "status": "review-required" if complete else "incomplete",
                "p95_intervals": intervals,
                "claim": False,
                "pass_credit": False,
                "note": "A p95 slope above 1.20 is an observation requiring review, not an automatic failure or pass.",
            }
        )
    return checks


def expected_bucket_keys(config: BenchmarkConfig) -> frozenset[tuple[str, str, str, int]]:
    return frozenset(product(config.scenarios, config.operations, TEMPERATURES, config.sizes))


def fixed_full_scope_selected(config: BenchmarkConfig) -> bool:
    return (
        set(config.scenarios) == set(SCENARIOS)
        and set(config.operations) == set(OPERATIONS)
        and tuple(config.sizes) == DEFAULT_SIZES
    )


def _require_fixed_execution_scope(config: BenchmarkConfig) -> None:
    """Reject execution requests that silently shrink the 72-bucket workload."""

    if not fixed_full_scope_selected(config):
        raise ComparativeBenchError(
            "execution requires the fixed 72-bucket scope: "
            "scenarios=promin,markdown,empty; operations=init,update,query,docs; sizes=16,64,256"
        )


def _strict_result_key(result: Mapping[str, Any]) -> tuple[str, str, str, int] | None:
    scenario = result.get("scenario")
    operation = result.get("operation")
    temperature = result.get("temperature")
    size = result.get("size")
    if not all(type(value) is str for value in (scenario, operation, temperature)) or type(size) is not int:
        return None
    return scenario, operation, temperature, size


def result_key_closure(
    expected: Iterable[tuple[str, str, str, int]],
    results: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    expected_set = frozenset(expected)
    observed_keys = [key for result in results if (key := _strict_result_key(result)) is not None]
    observed_set = frozenset(observed_keys)
    counts = Counter(observed_keys)
    missing = sorted(expected_set - observed_set)
    unexpected = sorted(observed_set - expected_set)
    duplicate = sorted(key for key, count in counts.items() if count > 1)
    return {
        "expected_bucket_count": len(expected_set),
        "observed_bucket_count": len(results),
        "unique_bucket_count": len(observed_set),
        "complete": len(results) == len(expected_set) and observed_set == expected_set and not duplicate,
        "missing": missing,
        "missing_count": len(missing),
        "unexpected": unexpected,
        "unexpected_count": len(unexpected),
        "duplicate": duplicate,
        "duplicate_count": sum(count - 1 for count in counts.values() if count > 1),
        "malformed_count": len(results) - len(observed_keys),
        "claim": False,
        "pass_credit": False,
    }


def _base_report(config: BenchmarkConfig, *, executed: bool) -> dict[str, Any]:
    selected_full_scope = fixed_full_scope_selected(config)
    return {
        "schema": "promin.comparative-benchmark.v1",
        "record_type": "ProminComparativeBenchmark",
        "claim": False,
        "pass_credit": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "public_release_approved": False,
        "execution": {
            "performed": executed,
            "status": "planned" if not executed else "running",
            "full_comparison_scope_selected": selected_full_scope,
            "expected_bucket_count": len(expected_bucket_keys(config)),
            "reason": (
                "Use --execute to collect host-local evidence; planned output has no measurements."
                if not executed
                else "Host-local evidence collection is in progress."
            ),
        },
        "config": {
            "sizes": list(config.sizes),
            "warmup_runs": config.warmup_runs,
            "measured_runs": config.measured_runs,
            "sampling_interval_ms": config.sampling_interval_ms,
            "scenarios": list(config.scenarios),
            "operations": list(config.operations),
            "temperatures": list(TEMPERATURES),
            "execution_order": "sequential; no benchmark samples run concurrently",
            # A plan may be inspected for a partial/expanded configuration,
            # but only the exact Cartesian scope is the executable benchmark.
            "fixed_workload": selected_full_scope,
            "fixed_bucket_count": FIXED_BUCKET_COUNT,
        },
        "protocol": {
            "source_fixture": "Each non-empty scenario receives one deterministic README plus size Markdown notes.",
            "promin_routes": {
                "init": "public CLI handler: promin init --yes with explicit decline selections",
                "update": "public CLI handler: promin refresh after one source mutation",
                "query": "public CLI handler: promin context after refresh",
                "docs": "public CLI handler: promin refresh from initialized source state",
            },
            "markdown_routes": {
                "init": "build a deterministic Markdown INDEX.md",
                "update": "regenerate INDEX.md after one source mutation",
                "query": "linear scan of Markdown text",
                "docs": "build a deterministic Markdown INDEX.md",
            },
            "empty_routes": "empty-root create/scan baseline; it is intentionally not a feature-equivalent repository.",
            "cold_definition": "preparation worker exits; a fresh worker imports and opens state for the measured operation",
            "warm_definition": "one worker process prepares and measures repeated isolated samples",
            "metrics": "wall time from perf_counter_ns, process CPU time from process_time_ns, sampled current RSS, lifetime RSS where available, and regular-file storage",
            "metric_reproducibility": {
                "timed_region": "one prepared operation in one isolated worker process; preparation is excluded",
                "clock_sources": {"wall": "time.perf_counter_ns", "cpu": "time.process_time_ns"},
                "rss": "sampled at the configured interval plus before/after samples; unavailable values remain null",
                "storage": "regular non-symlink file count and byte totals after the operation, including Markdown and .promin control bytes",
                "ordering": "scenario, operation, temperature, size; samples sequential and never concurrent",
            },
            "comparability_limit": "This compares defined local workflows, not equivalent products or an acceptance/performance budget.",
        },
        "environment": {
            "platform": platform.platform(),
            "python": sys.version,
            "python_implementation": platform.python_implementation(),
            "machine": platform.machine(),
            "package_root": str(PACKAGE_ROOT),
        },
        "results": [],
        "scaling_checks": [],
        "result_key_closure": result_key_closure(expected_bucket_keys(config), []),
    }


def build_plan(config: BenchmarkConfig) -> dict[str, Any]:
    """Return a reviewable no-execution record with no synthetic measurements."""

    validate_config(config)
    return _base_report(config, executed=False)


def run_benchmark(config: BenchmarkConfig, *, fixture_root: Path) -> dict[str, Any]:
    """Collect all configured samples sequentially and preserve every failure."""

    validate_config(config)
    # Keep the in-process API subject to the same no-shrinking boundary as the
    # CLI.  Otherwise callers could bypass the fixed 72-bucket protocol.
    _require_fixed_execution_scope(config)
    if fixture_root.exists() and any(fixture_root.iterdir()):
        raise ComparativeBenchError("fixture_root must be empty so this tool never overwrites user data")
    fixture_root.mkdir(parents=True, exist_ok=True)
    report = _base_report(config, executed=True)
    results: list[dict[str, Any]] = []
    case_index = 0
    for scenario in config.scenarios:
        for operation in config.operations:
            for temperature in TEMPERATURES:
                for size in config.sizes:
                    warmups: list[dict[str, Any]] = []
                    samples: list[dict[str, Any]] = []
                    if temperature == "warm":
                        with _WorkerClient() as worker:
                            phases = (
                                ("warmup", config.warmup_runs, warmups),
                                ("measure", config.measured_runs, samples),
                            )
                            for phase, count, destination in phases:
                                for local_index in range(count):
                                    root = _new_case_path(
                                        fixture_root,
                                        scenario=scenario,
                                        operation=operation,
                                        temperature=temperature,
                                        size=size,
                                        phase=phase,
                                        index=case_index,
                                    )
                                    case_index += 1
                                    destination.append(
                                        _prepared_sample(
                                            worker,
                                            root,
                                            scenario=scenario,
                                            operation=operation,
                                            size=size,
                                            config=config,
                                            temperature=temperature,
                                            phase=phase,
                                            index=local_index,
                                        )
                                    )
                    else:
                        phases = (
                            ("warmup", config.warmup_runs, warmups),
                            ("measure", config.measured_runs, samples),
                        )
                        for phase, count, destination in phases:
                            for local_index in range(count):
                                root = _new_case_path(
                                    fixture_root,
                                    scenario=scenario,
                                    operation=operation,
                                    temperature=temperature,
                                    size=size,
                                    phase=phase,
                                    index=case_index,
                                )
                                case_index += 1
                                destination.append(
                                    _cold_sample(
                                        root,
                                        scenario=scenario,
                                        operation=operation,
                                        size=size,
                                        config=config,
                                        phase=phase,
                                        index=local_index,
                                    )
                                )
                    results.append(
                        _summary_for_samples(
                            scenario=scenario,
                            operation=operation,
                            temperature=temperature,
                            size=size,
                            warmups=warmups,
                            samples=samples,
                        )
                    )
    report["results"] = results
    closure = result_key_closure(expected_bucket_keys(config), results)
    report["result_key_closure"] = closure
    report["scaling_checks"] = scaling_checks(results, sizes=config.sizes)
    all_successful = all(result["status"] == "measured" for result in results)
    report["execution"] = {
        **dict(report["execution"]),
        "status": "completed" if all_successful and closure["complete"] else "completed-with-failures",
        "completed_at_utc": _utc_now(),
        "all_samples_succeeded": all_successful,
        "fixture_root_retained": True,
        "reason": "Measurements are host-local evidence only; independent review is still required.",
    }
    return report


def _emit(value: Mapping[str, Any], output: Path | None) -> None:
    payload = _canonical_bytes(value) + b"\n"
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(payload)
    sys.stdout.buffer.write(payload)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true", help="collect measurements; absent means emit a claim-free plan only")
    parser.add_argument("--sizes", default=",".join(str(size) for size in DEFAULT_SIZES))
    parser.add_argument("--warmup-runs", type=int, default=DEFAULT_WARMUP_RUNS)
    parser.add_argument("--measured-runs", type=int, default=DEFAULT_MEASURED_RUNS)
    parser.add_argument("--sampling-interval-ms", type=int, default=DEFAULT_SAMPLING_INTERVAL_MS)
    parser.add_argument("--scenarios", default=",".join(SCENARIOS))
    parser.add_argument("--operations", default=",".join(OPERATIONS))
    parser.add_argument("--fixture-root", type=Path, help="an empty directory to retain benchmark fixtures")
    parser.add_argument("--keep-fixtures", action="store_true", help="retain an automatically created fixture directory")
    parser.add_argument("--output", type=Path, help="write the same canonical JSON record to this path")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    return parser


def _config_from_args(args: argparse.Namespace) -> BenchmarkConfig:
    config = BenchmarkConfig(
        sizes=parse_sizes(args.sizes),
        warmup_runs=args.warmup_runs,
        measured_runs=args.measured_runs,
        sampling_interval_ms=args.sampling_interval_ms,
        scenarios=_parse_csv(args.scenarios, allowed=SCENARIOS, label="scenarios"),
        operations=_parse_csv(args.operations, allowed=OPERATIONS, label="operations"),
    )
    validate_config(config)
    return config


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.worker:
        return worker_main()
    try:
        config = _config_from_args(args)
        if not args.execute:
            _emit(build_plan(config), args.output)
            return 0
        if args.fixture_root is not None:
            _require_fixed_execution_scope(config)
            fixture_root = args.fixture_root.resolve()
            report = run_benchmark(config, fixture_root=fixture_root)
            _emit(report, args.output)
            return 0
        if args.keep_fixtures:
            _require_fixed_execution_scope(config)
            fixture_root = Path(tempfile.mkdtemp(prefix="promin-comparative-bench-"))
            report = run_benchmark(config, fixture_root=fixture_root)
            report["execution"]["fixture_root"] = str(fixture_root)
            _emit(report, args.output)
            return 0
        with tempfile.TemporaryDirectory(prefix="promin-comparative-bench-") as temporary:
            _require_fixed_execution_scope(config)
            report = run_benchmark(config, fixture_root=Path(temporary))
        report["execution"]["fixture_root_retained"] = False
        _emit(report, args.output)
        return 0
    except ComparativeBenchError as exc:
        failure = {
            "schema": "promin.comparative-benchmark.v1",
            "record_type": "ProminComparativeBenchmarkFailure",
            "claim": False,
            "pass_credit": False,
            "acceptance_pass": False,
            "execution": {"performed": bool(getattr(args, "execute", False)), "status": "failed"},
            "reason": _safe_error(exc),
        }
        _emit(failure, args.output)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
