from __future__ import annotations

import argparse
import contextvars
import errno
import functools
import hashlib
import io
import json
import math
import os
import platform
import shutil
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import unicodedata
import uuid
import zipfile
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True


TOOLS_ROOT = Path(__file__).resolve().parent
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
for entry in (str(TOOLS_ROOT), str(PACKAGE_ROOT)):
    while entry in sys.path:
        sys.path.remove(entry)
if os.environ.get("PROMIN_INSTALLED_TEST_MODE") == "1":
    sys.path.append(str(TOOLS_ROOT))
else:
    sys.path.insert(0, str(PACKAGE_ROOT))
    sys.path.insert(1, str(TOOLS_ROOT))

from promin.evidence import (
    EvidenceError,
    release_evidence_invocation,
    release_evidence_producer,
    seal_release_evidence,
    validate_release_archive_basename,
    validate_saturation_evidence,
)

EVIDENCE_PROTOCOL_VERSION = "promin-evidence-v1"
EVIDENCE_TOOL_VERSIONS = {
    "tools/promin_no_degradation.py": "promin-no-degradation-v1",
    "tools/promin_package.py": "promin-package-v1",
    "tools/promin_saturation.py": "promin-saturation-v1",
    "tools/promin_saturation_audit.py": "promin-saturation-audit-v1",
    "tools/promin_validate.py": "promin-validate-v1",
}

_SATURATION_PROJECT_ID = "promin-physical-saturation"
_SATURATION_SUBJECT_ID = "promin-saturation-owner"
_SATURATION_PROVIDER_ID = "git-filesystem-inventory"
_PHYSICAL_CORPUS_RECIPE = "representative-operational-text-v3"
_EXACT_PHYSICAL_FILES = 100_000
_EXACT_CORE_VALID_RELATIONS = 198_999
_EXACT_RUNTIME_QUERIES = 600
_CONTINUATION_STATE_ROWS_MAX = 10_000
_CONTINUATION_STATE_BYTES_MAX = 16_384
_CONTINUATION_STATE_TOTAL_BYTES_MAX = (
    _CONTINUATION_STATE_ROWS_MAX * _CONTINUATION_STATE_BYTES_MAX
)
_CONTINUATION_STATE_OBSERVATIONS_MAX = 100_000
_SATURATION_CONTINUATION_TTL_SECONDS = 900
_SEARCH_FIXTURE_TASK_COUNT = 32
_SEARCH_FIXTURE_RELATION_COUNT = 28
_PHYSICAL_RELATION_COUNT = (
    _EXACT_CORE_VALID_RELATIONS - _SEARCH_FIXTURE_RELATION_COUNT
)
_PHYSICAL_RELATIONS_PER_TASK = 127
_PHYSICAL_RELATION_TASK_PREFIX = "task:physical-relation-saturation:"
_PHYSICAL_RELATION_PREFIX = "relation:physical-relation-saturation:"
_GIBIBYTE = 1024**3
_DEFAULT_STORAGE_HEADROOM_BYTES = 8 * _GIBIBYTE
_STORAGE_FAILURE_RESERVE_BYTES = 2 * 1024 * 1024
_STORAGE_SAMPLE_INTERVAL_SECONDS = 0.5
_BOUND_STORAGE_CHECKPOINT_LIMIT = 10_000
_REPRESENTATIVE_PHRASES = (
    "task workflow objective",
    "grant authority capability",
    "lease heartbeat fencing",
    "evidence candidate identity",
    "finding severity disposition",
    "gate predicate outcome",
    "decision rationale state",
    "relation dependency edge",
)
_PHYSICAL_QUERY_DEPTH_ONE_CLASSES = frozenset(
    {
        "exact-artifact",
        "content-high-cardinality",
        "content-probe",
        "hostile-content",
        "broad",
    }
)
_SATURATION_CAPABILITY_CEILING = [
    "standard.activate",
    "authority.manage",
    "task.plan",
    "task.execute",
    "projection.read",
]


class SaturationError(RuntimeError):
    pass


class StorageBudgetError(SaturationError):
    def __init__(self, message: str, *, failure_code: str) -> None:
        super().__init__(message)
        self.failure_code = failure_code


class TerminalPublicationError(SaturationError):
    """The create-only terminal result path was already occupied."""


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if hasattr(value, "__dict__"):
        return dict(vars(value))
    return value


def _field(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _canonical_bytes(value: Any) -> bytes:
    try:
        from promin.canonical import canonical_bytes
    except ImportError as exc:  # pragma: no cover - distribution fault path
        raise SaturationError("production canonical module is unavailable") from exc
    return canonical_bytes(_plain(value))


def _digest(value: Any) -> str:
    try:
        from promin.canonical import digest_value
    except ImportError as exc:  # pragma: no cover - distribution fault path
        raise SaturationError("production canonical module is unavailable") from exc
    return digest_value(_plain(value))


def _write_json(path: Path, value: Any) -> None:
    payload = _canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _write_json_create_only(path: Path, value: Any) -> None:
    """Atomically publish canonical JSON without replacing an existing path."""

    payload = _canonical_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise TerminalPublicationError(
                f"terminal result already exists: {path}"
            ) from exc
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            # The final hard link, once created, is already the durable result.
            pass


def _write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _write_jsonl(path: Path, rows: list[Mapping[str, Any]]) -> None:
    payload = b"".join(_canonical_bytes(dict(row)) for row in rows)
    _write_bytes(path, payload)


def _raw_artifact_binding(
    output: Path,
    relative: str,
    *,
    role: str,
    media_type: str,
    records: int,
) -> dict[str, Any]:
    path = output.joinpath(*relative.split("/"))
    payload = _read_stable_file(path)
    return {
        "role": role,
        "path": relative,
        "media_type": media_type,
        "sha256": _sha256_bytes(payload),
        "bytes": len(payload),
        "records": records,
    }


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_stable_file(path: Path) -> bytes:
    before = path.stat()
    payload = path.read_bytes()
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise SaturationError(f"artifact changed while reading: {path}")
    return payload


def _hex_digest(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise SaturationError(f"{label} is not a SHA-256 string")
    selected = value.removeprefix("sha256:")
    if len(selected) != 64 or any(character not in "0123456789abcdef" for character in selected):
        raise SaturationError(f"{label} is not a lowercase SHA-256 digest")
    return selected


def _relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise SaturationError(f"{label} is not a canonical relative POSIX path")
    parts = value.split("/")
    if value.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        raise SaturationError(f"{label} is not a canonical relative POSIX path")
    if unicodedata.normalize("NFC", value) != value:
        raise SaturationError(f"{label} is not NFC-normalized")
    return value


def _platform_binding() -> dict[str, Any]:
    executable = Path(getattr(sys, "_base_executable", None) or sys.executable).resolve(
        strict=True
    )
    executable_bytes = _read_stable_file(executable)
    value = {
        "system": platform.system().casefold(),
        "release": platform.release(),
        "machine": (platform.machine() or "unknown").casefold(),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_executable_sha256": "sha256:" + _sha256_bytes(executable_bytes),
        "sqlite_version": sqlite3.sqlite_version,
    }
    value["profile_key"] = "-".join(
        (
            value["system"],
            value["machine"],
            value["python_implementation"].casefold(),
            ".".join(value["python_version"].split(".")[:2]),
        )
    )
    value["binding_digest"] = "sha256:" + _sha256_bytes(_canonical_bytes(value))
    return value


def _nearest_existing_directory(path: Path) -> Path:
    selected = Path(os.path.abspath(path))
    while not selected.exists():
        parent = selected.parent
        if parent == selected:
            raise StorageBudgetError(
                f"no existing filesystem ancestor is available for storage telemetry: {path}",
                failure_code="storage-telemetry-unavailable",
            )
        selected = parent
    if selected.is_file():
        selected = selected.parent
    if not selected.is_dir():
        raise StorageBudgetError(
            f"storage telemetry anchor is not a directory: {selected}",
            failure_code="storage-telemetry-unavailable",
        )
    return selected


def _disk_space_record(path: Path) -> dict[str, Any]:
    try:
        anchor = _nearest_existing_directory(path)
        usage = shutil.disk_usage(anchor)
        device = int(anchor.stat().st_dev)
    except StorageBudgetError:
        raise
    except (OSError, ValueError) as exc:
        raise StorageBudgetError(
            f"free-space telemetry is unavailable for {path}: {exc}",
            failure_code="storage-telemetry-unavailable",
        ) from exc
    values = (int(usage.total), int(usage.used), int(usage.free))
    if values[0] <= 0 or values[1] < 0 or values[2] < 0 or values[1] + values[2] > values[0]:
        raise StorageBudgetError(
            f"free-space telemetry returned inconsistent values for {path}",
            failure_code="storage-telemetry-unavailable",
        )
    if os.name == "nt":
        anchor_identity = anchor.anchor.casefold()
    else:
        anchor_identity = str(device)
    return {
        "volume_id": f"{platform.system().casefold()}:{anchor_identity}",
        "total_bytes": values[0],
        "used_bytes": values[1],
        "free_bytes": values[2],
    }


def _tree_logical_measurement(root: Path) -> dict[str, int]:
    if not root.exists():
        return {
            "logical_bytes": 0,
            "regular_files": 0,
            "directories": 0,
            "reparse_entries_skipped": 0,
        }
    if root.is_symlink() or not root.is_dir():
        raise StorageBudgetError(
            f"storage telemetry root is not a physical directory: {root}",
            failure_code="storage-telemetry-unavailable",
        )
    logical_bytes = 0
    regular_files = 0
    directories = 1
    reparse_entries_skipped = 0
    pending = [root]
    try:
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as entries:
                for entry in entries:
                    metadata = entry.stat(follow_symlinks=False)
                    is_reparse = bool(
                        getattr(metadata, "st_file_attributes", 0) & 0x400
                    )
                    if entry.is_symlink() or is_reparse:
                        reparse_entries_skipped += 1
                    elif stat.S_ISDIR(metadata.st_mode):
                        directories += 1
                        pending.append(Path(entry.path))
                    elif stat.S_ISREG(metadata.st_mode):
                        regular_files += 1
                        logical_bytes += int(metadata.st_size)
    except OSError as exc:
        raise StorageBudgetError(
            f"logical storage measurement failed under {root}: {exc}",
            failure_code="storage-telemetry-unavailable",
        ) from exc
    return {
        "logical_bytes": logical_bytes,
        "regular_files": regular_files,
        "directories": directories,
        "reparse_entries_skipped": reparse_entries_skipped,
    }


def _is_database_payload_name(name: str) -> bool:
    lowered = name.casefold()
    return lowered.endswith(
        (
            ".db",
            ".db-journal",
            ".db-shm",
            ".db-wal",
            ".sqlite",
            ".sqlite-journal",
            ".sqlite-shm",
            ".sqlite-wal",
            ".sqlite3",
            ".sqlite3-journal",
            ".sqlite3-shm",
            ".sqlite3-wal",
        )
    )


def _database_storage_measurement(workspace: Path) -> dict[str, Any]:
    state_root = workspace / ".promin" / "state"
    directories = [
        state_root / "projection",
        state_root / "inventory",
        state_root / "events",
        state_root / "events" / "derived-rows",
    ]
    generation_root = state_root / "events" / "derived-index"
    if generation_root.is_dir() and not generation_root.is_symlink():
        try:
            directories.extend(
                path
                for path in generation_root.iterdir()
                if path.is_dir() and not path.is_symlink()
            )
        except OSError as exc:
            raise StorageBudgetError(
                f"database storage discovery failed under {generation_root}: {exc}",
                failure_code="storage-telemetry-unavailable",
            ) from exc
    files: list[dict[str, Any]] = []
    seen: set[str] = set()
    try:
        for directory in directories:
            if not directory.is_dir() or directory.is_symlink():
                continue
            with os.scandir(directory) as entries:
                for entry in entries:
                    if not _is_database_payload_name(entry.name):
                        continue
                    metadata = entry.stat(follow_symlinks=False)
                    if not stat.S_ISREG(metadata.st_mode):
                        continue
                    path = Path(entry.path)
                    relative = path.relative_to(workspace).as_posix()
                    if relative in seen:
                        continue
                    seen.add(relative)
                    files.append({"path": relative, "logical_bytes": int(metadata.st_size)})
    except OSError as exc:
        raise StorageBudgetError(
            f"database storage measurement failed under {state_root}: {exc}",
            failure_code="storage-telemetry-unavailable",
        ) from exc
    files.sort(key=lambda value: value["path"])
    journal_checkpoint_path = state_root / "events" / "journal-checkpoint.json"
    journal_checkpoint_bytes = 0
    if journal_checkpoint_path.is_file() and not journal_checkpoint_path.is_symlink():
        try:
            journal_checkpoint_bytes = int(journal_checkpoint_path.stat().st_size)
        except OSError as exc:
            raise StorageBudgetError(
                f"journal checkpoint storage measurement failed: {exc}",
                failure_code="storage-telemetry-unavailable",
            ) from exc
    derived_state_root = state_root / "events" / "derived-state"
    derived_state_files: list[dict[str, Any]] = []
    if derived_state_root.is_dir() and not derived_state_root.is_symlink():
        try:
            with os.scandir(derived_state_root) as entries:
                for entry in entries:
                    metadata = entry.stat(follow_symlinks=False)
                    if stat.S_ISREG(metadata.st_mode) and entry.name.casefold().endswith(".json"):
                        derived_state_files.append(
                            {
                                "path": Path(entry.path).relative_to(workspace).as_posix(),
                                "logical_bytes": int(metadata.st_size),
                            }
                        )
        except OSError as exc:
            raise StorageBudgetError(
                f"derived-state storage measurement failed: {exc}",
                failure_code="storage-telemetry-unavailable",
            ) from exc
    derived_state_files.sort(key=lambda value: value["path"])
    runtime_checkpoint_name = hashlib.sha256(b"runtime").hexdigest() + ".sqlite3"
    runtime_checkpoint_path = (
        state_root / "events" / "derived-rows" / runtime_checkpoint_name
    )
    runtime_derived_checkpoint_bytes = 0
    if runtime_checkpoint_path.is_file() and not runtime_checkpoint_path.is_symlink():
        try:
            runtime_derived_checkpoint_bytes = int(runtime_checkpoint_path.stat().st_size)
        except OSError as exc:
            raise StorageBudgetError(
                f"runtime derived checkpoint storage measurement failed: {exc}",
                failure_code="storage-telemetry-unavailable",
            ) from exc
    database_bytes = sum(int(value["logical_bytes"]) for value in files)
    derived_state_bytes = sum(
        int(value["logical_bytes"]) for value in derived_state_files
    )
    return {
        "database_files": files,
        "database_file_count": len(files),
        "database_logical_bytes": database_bytes,
        "journal_checkpoint_logical_bytes": journal_checkpoint_bytes,
        "derived_state_files": derived_state_files,
        "derived_state_file_count": len(derived_state_files),
        "derived_state_logical_bytes": derived_state_bytes,
        "runtime_derived_checkpoint_path": runtime_checkpoint_path.relative_to(
            workspace
        ).as_posix(),
        "runtime_derived_checkpoint_logical_bytes": runtime_derived_checkpoint_bytes,
        "observed_control_storage_bytes": (
            database_bytes + journal_checkpoint_bytes + derived_state_bytes
        ),
        "observed_control_storage_scope": (
            "sqlite-databases-journal-checkpoint-and-derived-state"
        ),
    }


def _storage_growth_plan(
    performance_contract: Mapping[str, Any],
    *,
    files: int,
    queries: int,
    reuse_product: bool,
) -> dict[str, Any]:
    thresholds = performance_contract.get("thresholds")
    if not isinstance(thresholds, Mapping):
        raise StorageBudgetError(
            "performance profile omitted storage planning thresholds",
            failure_code="storage-telemetry-unavailable",
        )
    database_bytes = thresholds.get("database_bytes_max")
    changed_record_bytes = thresholds.get("commit_bytes_per_changed_record_max")
    if (
        not isinstance(database_bytes, int)
        or isinstance(database_bytes, bool)
        or database_bytes < 1
        or not isinstance(changed_record_bytes, int)
        or isinstance(changed_record_bytes, bool)
        or changed_record_bytes < 1
    ):
        raise StorageBudgetError(
            "performance profile storage thresholds are invalid",
            failure_code="storage-telemetry-unavailable",
        )
    physical_task_count = math.ceil(
        _PHYSICAL_RELATION_COUNT / _PHYSICAL_RELATIONS_PER_TASK
    )
    semantic_changed_records = (
        _EXACT_CORE_VALID_RELATIONS
        + physical_task_count
        + _SEARCH_FIXTURE_TASK_COUNT
        + 8
    )
    event_and_derived_bytes = 2 * changed_record_bytes * semantic_changed_records
    product_and_vcs_bytes = 0 if reuse_product else files * 24 * 1024
    workspace_components = {
        "canonical_projection_database_bytes": database_bytes,
        "event_and_derived_state_bytes": event_and_derived_bytes,
        "product_and_vcs_bytes": product_and_vcs_bytes,
    }
    ceiling = _load_ceiling()
    output_components = {
        "inventory_and_manifest_bytes": files * 2 * 1024,
        "bounded_query_evidence_bytes": queries * ceiling["max_bytes"] * 2,
        "publication_reserve_bytes": 256 * 1024 * 1024,
    }
    return {
        "record_type": "SaturationStorageGrowthPlan",
        "workload": {
            "physical_files": files,
            "runtime_queries": queries,
            "core_valid_relations": _EXACT_CORE_VALID_RELATIONS,
            "workload_reduced": False,
        },
        "workspace_components": workspace_components,
        "workspace_planned_growth_bytes": sum(workspace_components.values()),
        "output_components": output_components,
        "output_planned_growth_bytes": sum(output_components.values()),
        "planning_basis": (
            "canonical performance ceilings plus exact workload and bounded raw evidence; "
            "runtime headroom monitoring remains fail-closed if actual or external growth is larger"
        ),
    }


def _exception_chain(error: BaseException) -> list[BaseException]:
    values: list[BaseException] = []
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        values.append(current)
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return values


def _storage_failure_code(error: BaseException) -> str | None:
    messages: list[str] = []
    for current in _exception_chain(error):
        if isinstance(current, StorageBudgetError):
            return current.failure_code
        if isinstance(current, OSError) and current.errno in {errno.ENOSPC, errno.EDQUOT}:
            return "storage-write-exhausted"
        if isinstance(current, OSError) and getattr(current, "winerror", None) in {
            39,
            112,
            1816,
        }:
            return "storage-write-exhausted"
        messages.append(str(current).casefold())
    joined = "\n".join(messages)
    if any(
        marker in joined
        for marker in (
            "database or disk is full",
            "disk full",
            "disk is full",
            "no space left on device",
            "not enough space on the disk",
            "quota exceeded",
        )
    ):
        return "storage-write-exhausted"
    return None


class _StorageRunTelemetry:
    def __init__(
        self,
        workspace: Path,
        output: Path,
        *,
        archive: Path | None,
        performance_contract: Mapping[str, Any],
        files: int,
        queries: int,
        reuse_product: bool,
        headroom_bytes: int = _DEFAULT_STORAGE_HEADROOM_BYTES,
    ) -> None:
        if (
            not isinstance(headroom_bytes, int)
            or isinstance(headroom_bytes, bool)
            or headroom_bytes < 1
        ):
            raise StorageBudgetError(
                "storage headroom must be a positive integer",
                failure_code="storage-telemetry-unavailable",
            )
        self.workspace = Path(os.path.abspath(workspace))
        self.output = Path(os.path.abspath(output))
        self.archive = archive
        self.files = files
        self.queries = queries
        self.reuse_product = reuse_product
        self.performance_profile = str(performance_contract["profile_id"])
        self.performance_contract_digest = _digest(performance_contract)
        self.headroom_bytes = headroom_bytes
        self.plan = _storage_growth_plan(
            performance_contract,
            files=files,
            queries=queries,
            reuse_product=reuse_product,
        )
        self.started_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )
        self.preflight: dict[str, Any] | None = None
        self.phase_measurements: dict[str, dict[str, Any]] = {}
        self.checkpoint_measurements: list[dict[str, Any]] = []
        self._volume_roles: dict[str, list[str]] = {}
        self._minimum_free_bytes: dict[str, int] = {}
        self._breach: dict[str, Any] | None = None
        self._sampling_error: str | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sampler: threading.Thread | None = None
        self._reserve_path = self.output / ".storage-failure-reserve.bin"
        self._output_created = False
        self._prepared = False
        self._output_identity: dict[str, int] | None = None
        self._terminal_observed = False
        self._terminal_free_space: list[dict[str, Any]] = []
        self._terminal_telemetry_error: str | None = None

    @staticmethod
    def _directory_identity(state: os.stat_result) -> dict[str, int]:
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
        return {
            "device": int(state.st_dev),
            "inode": int(state.st_ino),
            "file_type": int(stat.S_IFMT(state.st_mode)),
            "reparse_attributes": int(
                getattr(state, "st_file_attributes", 0)
            )
            & reparse_flag,
        }

    def _bind_output_identity(self) -> None:
        try:
            state = os.lstat(self.output)
        except OSError as exc:
            raise StorageBudgetError(
                f"output directory identity is unavailable: {exc}",
                failure_code="storage-telemetry-unavailable",
            ) from exc
        attributes = int(getattr(state, "st_file_attributes", 0))
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
        if not stat.S_ISDIR(state.st_mode) or attributes & reparse_flag:
            raise StorageBudgetError(
                "output destination must be a physical directory, not a symlink or reparse point",
                failure_code="storage-telemetry-unavailable",
            )
        self._output_identity = self._directory_identity(state)

    def _assert_output_identity(self) -> None:
        if self._output_identity is None:
            raise StorageBudgetError(
                "output directory physical identity was not bound",
                failure_code="storage-telemetry-unavailable",
            )
        try:
            state = os.lstat(self.output)
        except OSError as exc:
            raise StorageBudgetError(
                f"output directory physical identity is unavailable: {exc}",
                failure_code="storage-telemetry-unavailable",
            ) from exc
        attributes = int(getattr(state, "st_file_attributes", 0))
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
        observed = self._directory_identity(state)
        if (
            not stat.S_ISDIR(state.st_mode)
            or attributes & reparse_flag
            or observed != self._output_identity
        ):
            raise StorageBudgetError(
                "output directory physical identity changed during saturation",
                failure_code="storage-telemetry-unavailable",
            )

    def _role_space(self) -> dict[str, dict[str, Any]]:
        return {
            "workspace": _disk_space_record(self.workspace),
            "output": _disk_space_record(self.output),
        }

    def _grouped_space(self) -> list[dict[str, Any]]:
        records = self._role_space()
        grouped: dict[str, dict[str, Any]] = {}
        role_growth = {
            "workspace": self.plan["workspace_planned_growth_bytes"],
            "output": self.plan["output_planned_growth_bytes"],
        }
        for role, record in records.items():
            volume_id = record["volume_id"]
            current = grouped.setdefault(
                volume_id,
                {
                    **record,
                    "roles": [],
                    "planned_growth_bytes": 0,
                },
            )
            if current["total_bytes"] != record["total_bytes"]:
                raise StorageBudgetError(
                    f"same-volume telemetry disagrees for {volume_id}",
                    failure_code="storage-telemetry-unavailable",
                )
            current["used_bytes"] = max(current["used_bytes"], record["used_bytes"])
            current["free_bytes"] = min(current["free_bytes"], record["free_bytes"])
            current["roles"].append(role)
            current["planned_growth_bytes"] += role_growth[role]
        result: list[dict[str, Any]] = []
        for volume_id in sorted(grouped):
            value = grouped[volume_id]
            value["roles"].sort()
            value["headroom_bytes"] = self.headroom_bytes
            value["required_free_bytes"] = (
                value["planned_growth_bytes"] + self.headroom_bytes
            )
            value["within_preflight_budget"] = (
                value["free_bytes"] >= value["required_free_bytes"]
            )
            result.append(value)
        return result

    def _ensure_failure_destination(self) -> None:
        if self._output_created:
            return
        if self.output.exists():
            raise SaturationError("output directory already exists")
        self.output.mkdir(parents=True, exist_ok=False)
        self._output_created = True
        self._bind_output_identity()
        try:
            self._assert_output_identity()
            with self._reserve_path.open("xb") as handle:
                block = bytes(64 * 1024)
                remaining = _STORAGE_FAILURE_RESERVE_BYTES
                while remaining:
                    selected = block[: min(len(block), remaining)]
                    handle.write(selected)
                    remaining -= len(selected)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            self._assert_output_identity()
            self._reserve_path.unlink(missing_ok=True)
            raise StorageBudgetError(
                f"storage failure receipt reserve could not be allocated: {exc}",
                failure_code="storage-preflight-insufficient",
            ) from exc

    def prepare(self) -> None:
        if self.output.exists():
            raise SaturationError("output directory already exists")
        try:
            volumes = self._grouped_space()
            self._volume_roles = {
                value["volume_id"]: list(value["roles"]) for value in volumes
            }
            self._minimum_free_bytes = {
                value["volume_id"]: int(value["free_bytes"]) for value in volumes
            }
            self.preflight = {
                "record_type": "SaturationStoragePreflight",
                "status": "pass"
                if all(value["within_preflight_budget"] for value in volumes)
                else "fail",
                "headroom_bytes": self.headroom_bytes,
                "growth_plan": self.plan,
                "volumes": volumes,
                "telemetry_available": True,
                "workload_reduced": False,
            }
        except StorageBudgetError as exc:
            self.preflight = {
                "record_type": "SaturationStoragePreflight",
                "status": "fail",
                "headroom_bytes": self.headroom_bytes,
                "growth_plan": self.plan,
                "volumes": [],
                "telemetry_available": False,
                "telemetry_error": str(exc),
                "workload_reduced": False,
            }
            self._ensure_failure_destination()
            raise
        self._ensure_failure_destination()
        if self.preflight["status"] != "pass":
            raise StorageBudgetError(
                "free-space preflight cannot preserve planned growth and storage headroom",
                failure_code="storage-preflight-insufficient",
            )
        self.measure_phase("preflight")
        self._sampler = threading.Thread(
            target=self._sample_space,
            name="promin-storage-sampler",
            daemon=True,
        )
        self._sampler.start()
        self._prepared = True

    def _observe_free_space(self) -> list[dict[str, Any]]:
        if self._output_created:
            self._assert_output_identity()
        current = self._role_space()
        by_volume: dict[str, dict[str, Any]] = {}
        for role, record in current.items():
            volume_id = record["volume_id"]
            if volume_id not in self._volume_roles or role not in self._volume_roles[volume_id]:
                raise StorageBudgetError(
                    "workspace/output filesystem identity changed during saturation",
                    failure_code="storage-telemetry-unavailable",
                )
            value = by_volume.setdefault(
                volume_id,
                {
                    "volume_id": volume_id,
                    "roles": [],
                    "free_bytes": record["free_bytes"],
                },
            )
            value["free_bytes"] = min(value["free_bytes"], record["free_bytes"])
            value["roles"].append(role)
        values = [by_volume[key] for key in sorted(by_volume)]
        for value in values:
            value["roles"].sort()
            volume_id = value["volume_id"]
            free_bytes = int(value["free_bytes"])
            with self._lock:
                previous = self._minimum_free_bytes.get(volume_id, free_bytes)
                self._minimum_free_bytes[volume_id] = min(previous, free_bytes)
                if free_bytes < self.headroom_bytes and self._breach is None:
                    self._breach = {
                        "volume_id": volume_id,
                        "roles": list(value["roles"]),
                        "free_bytes": free_bytes,
                        "required_headroom_bytes": self.headroom_bytes,
                    }
        return values

    def _sample_space(self) -> None:
        while not self._stop.wait(_STORAGE_SAMPLE_INTERVAL_SECONDS):
            try:
                self._observe_free_space()
            except Exception as exc:  # telemetry loss must fail the run at the next boundary
                with self._lock:
                    self._sampling_error = str(exc)
                self._stop.set()
                return

    def _raise_if_unhealthy(self) -> None:
        with self._lock:
            sampling_error = self._sampling_error
            breach = dict(self._breach) if self._breach is not None else None
        if sampling_error is not None:
            raise StorageBudgetError(
                f"free-space telemetry became unavailable: {sampling_error}",
                failure_code="storage-telemetry-unavailable",
            )
        if breach is not None:
            raise StorageBudgetError(
                "storage headroom was exhausted during the unchanged saturation workload: "
                f"{breach['free_bytes']} < {breach['required_headroom_bytes']} bytes",
                failure_code="storage-headroom-exhausted",
            )

    def measure_phase(self, phase: str) -> dict[str, Any]:
        free_space = self._observe_free_space() if self._volume_roles else []
        self._raise_if_unhealthy()
        databases = _database_storage_measurement(self.workspace)
        value = {
            "record_type": "SaturationPhaseStorageMeasurement",
            "phase": phase,
            "free_space": free_space,
            "workspace_tree": _tree_logical_measurement(self.workspace),
            "control_state_tree": _tree_logical_measurement(
                self.workspace / ".promin" / "state"
            ),
            "output_tree": _tree_logical_measurement(self.output),
            **databases,
        }
        self.phase_measurements[phase] = value
        return value

    def record_commit(self, observation: Mapping[str, Any]) -> None:
        if len(self.checkpoint_measurements) >= _BOUND_STORAGE_CHECKPOINT_LIMIT:
            raise StorageBudgetError(
                "storage checkpoint telemetry exceeded its fixed evidence bound",
                failure_code="storage-telemetry-unavailable",
            )
        free_space = self._observe_free_space()
        self._raise_if_unhealthy()
        databases = _database_storage_measurement(self.workspace)
        self.checkpoint_measurements.append(
            {
                "sequence": len(self.checkpoint_measurements) + 1,
                "phase": observation["phase"],
                "operation_sequence": observation["sequence"],
                "checkpoint_written": observation["checkpoint_written"],
                "runtime_checkpoint_bytes": observation["checkpoint_bytes"],
                "physical_payload_bytes": observation["physical_payload_bytes"],
                "database_logical_bytes": databases["database_logical_bytes"],
                "journal_checkpoint_logical_bytes": databases[
                    "journal_checkpoint_logical_bytes"
                ],
                "runtime_derived_checkpoint_logical_bytes": databases[
                    "runtime_derived_checkpoint_logical_bytes"
                ],
                "observed_control_storage_bytes": databases[
                    "observed_control_storage_bytes"
                ],
                "free_bytes_by_volume": [
                    int(value["free_bytes"]) for value in free_space
                ],
            }
        )

    def stop_for_publication(self) -> None:
        self._stop.set()
        if self._sampler is not None:
            self._sampler.join(timeout=2.0)
            if self._sampler.is_alive():
                raise StorageBudgetError(
                    "storage sampler did not stop before evidence publication",
                    failure_code="storage-telemetry-unavailable",
                )
        self._raise_if_unhealthy()
        self.measure_phase("result")

    def bound_phase_payload(self, phase: str) -> dict[str, Any]:
        if phase not in self.phase_measurements:
            raise StorageBudgetError(
                f"storage phase measurement is missing: {phase}",
                failure_code="storage-telemetry-unavailable",
            )
        value: dict[str, Any] = {
            "measurement": self.phase_measurements[phase],
            "headroom_bytes": self.headroom_bytes,
        }
        if phase == "physical-generation":
            value["preflight"] = self.preflight
        if phase == "semantic-ingestion":
            value["commit_checkpoints"] = list(self.checkpoint_measurements)
            value["commit_checkpoint_count"] = len(self.checkpoint_measurements)
            value["commit_checkpoint_digest"] = _digest(self.checkpoint_measurements)
            value["commit_checkpoint_volume_order"] = [
                {
                    "volume_id": volume_id,
                    "roles": list(self._volume_roles[volume_id]),
                }
                for volume_id in sorted(self._volume_roles)
            ]
        if phase == "result":
            with self._lock:
                value["minimum_free_bytes_by_volume"] = dict(
                    sorted(self._minimum_free_bytes.items())
                )
            value["workload_reduced"] = False
        return value

    def _stop_sampler(self) -> None:
        self._stop.set()
        if self._sampler is None:
            return
        self._sampler.join(timeout=2.0)
        if self._sampler.is_alive():
            with self._lock:
                if self._sampling_error is None:
                    self._sampling_error = (
                        "storage sampler did not stop before terminal classification"
                    )

    def _observe_terminal_free_space(self) -> None:
        if self._terminal_observed:
            return
        self._stop_sampler()
        self._terminal_observed = True
        try:
            self._terminal_free_space = (
                self._observe_free_space() if self._volume_roles else []
            )
        except Exception as telemetry_error:
            self._terminal_free_space = []
            self._terminal_telemetry_error = str(telemetry_error)
            with self._lock:
                if self._sampling_error is None:
                    self._sampling_error = str(telemetry_error)

    def failure_code(self, error: BaseException) -> str | None:
        # This is the sole terminal observation.  Receipt publication consumes
        # the captured values so no later probe can change the classification.
        self._observe_terminal_free_space()
        direct = _storage_failure_code(error)
        if direct is not None:
            return direct
        with self._lock:
            if self._breach is not None:
                return "storage-headroom-exhausted"
            if self._sampling_error is not None:
                return "storage-telemetry-unavailable"
        return None

    def _release_reserve(self) -> None:
        if not self._output_created:
            return
        self._assert_output_identity()
        self._reserve_path.unlink(missing_ok=True)

    def stop(self, *, suppress_identity_error: bool = False) -> None:
        self._stop_sampler()
        try:
            self._release_reserve()
        except (OSError, StorageBudgetError):
            if not suppress_identity_error:
                raise

    def _remove_result_if_present(self) -> None:
        self._assert_output_identity()
        (self.output / "saturation-result.json").unlink(missing_ok=True)

    def _write_failure_receipt_once(
        self, path: Path, receipt: Mapping[str, Any]
    ) -> None:
        self._assert_output_identity()
        payload = _canonical_bytes(receipt)
        with path.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

    def publish_failure(self, error: BaseException, failure_code: str) -> Path | None:
        self._stop_sampler()
        if not self._output_created:
            try:
                self.output.mkdir(parents=True, exist_ok=False)
                self._output_created = True
                self._bind_output_identity()
            except OSError:
                return None
        try:
            self._release_reserve()
            self._remove_result_if_present()
        except (OSError, StorageBudgetError):
            return None
        archive_binding: dict[str, Any] | None = None
        if self.archive is not None:
            try:
                archive_path = self.archive.resolve(strict=True)
                payload = _read_stable_file(archive_path)
                archive_binding = {
                    "name": archive_path.name,
                    "bytes": len(payload),
                    "sha256": _sha256_bytes(payload),
                }
            except (OSError, SaturationError):
                archive_binding = None
        with self._lock:
            minimum_free = dict(sorted(self._minimum_free_bytes.items()))
            breach = dict(self._breach) if self._breach is not None else None
            sampling_error = self._sampling_error
        checkpoint_tail = self.checkpoint_measurements[-512:]
        identity = {
            "record_type": "SaturationStorageFailure",
            "status": "fail",
            "failure_code": failure_code,
            "reason": str(error),
            "exception_type": type(error).__name__,
            "started_at": self.started_at,
            "completed_at": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "pass_credit": False,
            "acceptance_pass": False,
            "product_acceptance_pass": False,
            "public_release_approved": False,
            "workload": {
                "physical_files": self.files,
                "runtime_queries": self.queries,
                "core_valid_relations": _EXACT_CORE_VALID_RELATIONS,
                "workload_reduced": False,
            },
            "archive_binding": archive_binding,
            "tool_binding": {
                "path": "tools/promin_saturation.py",
                "sha256": _sha256_bytes(_read_stable_file(Path(__file__).resolve())),
            },
            "storage": {
                "preflight": self.preflight,
                "phase_measurements": [
                    self.phase_measurements[key]
                    for key in self.phase_measurements
                ],
                "commit_checkpoint_count": len(self.checkpoint_measurements),
                "commit_checkpoint_digest": _digest(self.checkpoint_measurements),
                "commit_checkpoint_tail": checkpoint_tail,
                "minimum_free_bytes_by_volume": minimum_free,
                "terminal_free_space": self._terminal_free_space,
                "terminal_telemetry_error": self._terminal_telemetry_error,
                "headroom_breach": breach,
                "sampling_error": sampling_error,
                "external_disk_pressure_attribution": "not-inferred-from-free-space",
            },
        }
        receipt = {**identity, "receipt_digest": _digest(identity)}
        path = self.output / "saturation-storage-failure.json"
        try:
            self._write_failure_receipt_once(path, receipt)
        except OSError:
            return None
        return path

    def publish_rejection(self, error: BaseException) -> Path | None:
        """Publish one fail-closed receipt after an acquired, prepared run fails."""

        if not self._prepared or not self._output_created:
            return None
        self._stop_sampler()
        self._release_reserve()
        self._remove_result_if_present()

        archive_binding: dict[str, Any]
        if self.archive is None:
            archive_identity = {
                "available": False,
                "requested_path": None,
            }
        else:
            requested_archive = Path(os.path.abspath(self.archive))
            try:
                archive_path = requested_archive.resolve(strict=True)
                archive_payload = _read_stable_file(archive_path)
            except (OSError, SaturationError) as archive_error:
                archive_identity = {
                    "available": False,
                    "requested_path": str(requested_archive),
                    "binding_error": str(archive_error),
                }
            else:
                archive_identity = {
                    "available": True,
                    "requested_path": str(requested_archive),
                    "resolved_path": str(archive_path),
                    "name": archive_path.name,
                    "bytes": len(archive_payload),
                    "sha256": _sha256_bytes(archive_payload),
                }
        archive_binding = {
            **archive_identity,
            "binding_digest": _digest(archive_identity),
        }

        tool_path = Path(__file__).resolve(strict=True)
        tool_payload = _read_stable_file(tool_path)
        tool_identity = {
            "path": "tools/promin_saturation.py",
            "resolved_path": str(tool_path),
            "bytes": len(tool_payload),
            "sha256": _sha256_bytes(tool_payload),
        }
        tool_binding = {
            **tool_identity,
            "binding_digest": _digest(tool_identity),
        }
        with self._lock:
            minimum_free = dict(sorted(self._minimum_free_bytes.items()))
            breach = dict(self._breach) if self._breach is not None else None
            sampling_error = self._sampling_error
        checkpoint_tail = self.checkpoint_measurements[-512:]
        storage_identity = {
            "preflight": self.preflight,
            "growth_plan": self.plan,
            "headroom_bytes": self.headroom_bytes,
            "phase_measurements": [
                self.phase_measurements[key] for key in self.phase_measurements
            ],
            "commit_checkpoint_count": len(self.checkpoint_measurements),
            "commit_checkpoint_digest": _digest(self.checkpoint_measurements),
            "commit_checkpoint_tail": checkpoint_tail,
            "minimum_free_bytes_by_volume": minimum_free,
            "terminal_free_space": self._terminal_free_space,
            "terminal_telemetry_error": self._terminal_telemetry_error,
            "headroom_breach": breach,
            "sampling_error": sampling_error,
            "external_disk_pressure_attribution": "not-inferred-from-free-space",
        }
        storage_binding = {
            **storage_identity,
            "binding_digest": _digest(storage_identity),
        }
        workspace_exists = self.workspace.exists()
        identity = {
            "schema": "promin.saturation-failure.v1",
            "record_type": "SaturationFailure",
            "status": "rejected",
            "failure_code": "saturation-rejected",
            "reason": str(error),
            "exception_type": type(error).__name__,
            "started_at": self.started_at,
            "completed_at": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "pass_credit": False,
            "acceptance_pass": False,
            "product_acceptance_pass": False,
            "public_release_approved": False,
            "workload": {
                "physical_files": self.files,
                "runtime_queries": self.queries,
                "core_valid_relations": _EXACT_CORE_VALID_RELATIONS,
                "performance_profile": self.performance_profile,
                "performance_contract_digest": self.performance_contract_digest,
                "reuse_product": self.reuse_product,
                "workload_reduced": False,
            },
            "archive_binding": archive_binding,
            "tool_binding": tool_binding,
            "storage": storage_binding,
            "workspace": {
                "path": str(self.workspace),
                "exists": workspace_exists,
                "preservation_verified": False,
            },
            "saturation_result_written": False,
        }
        receipt = {**identity, "receipt_digest": _digest(identity)}
        path = self.output / "saturation-failure.json"
        self._write_failure_receipt_once(path, receipt)
        return path


_ACTIVE_STORAGE_TELEMETRY: contextvars.ContextVar[_StorageRunTelemetry | None] = (
    contextvars.ContextVar("promin_saturation_storage_telemetry", default=None)
)


def _measure_storage_phase(phase: str) -> None:
    telemetry = _ACTIVE_STORAGE_TELEMETRY.get()
    if telemetry is not None:
        telemetry.measure_phase(phase)


def _peak_rss_bytes() -> int:
    """Return the process peak resident set without an optional dependency."""

    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

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
        get_current_process = ctypes.windll.kernel32.GetCurrentProcess
        get_current_process.argtypes = []
        get_current_process.restype = wintypes.HANDLE
        get_process_memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
        get_process_memory_info.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ProcessMemoryCounters),
            wintypes.DWORD,
        ]
        get_process_memory_info.restype = wintypes.BOOL
        process = get_current_process()
        if not get_process_memory_info(
            process,
            ctypes.byref(counters),
            counters.cb,
        ):
            raise SaturationError("peak RSS measurement failed on Windows")
        result = int(counters.PeakWorkingSetSize)
    else:
        try:
            import resource
        except ImportError as exc:  # pragma: no cover - unsupported platform
            raise SaturationError("peak RSS measurement is unavailable") from exc
        maximum = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        result = maximum if sys.platform == "darwin" else maximum * 1024
    if result <= 0:
        raise SaturationError("peak RSS measurement returned a non-positive value")
    return result


def _current_rss_bytes() -> int:
    """Return the current resident set for bounded pipeline sampling."""

    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

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
        get_current_process = ctypes.windll.kernel32.GetCurrentProcess
        get_current_process.argtypes = []
        get_current_process.restype = wintypes.HANDLE
        get_process_memory_info = ctypes.windll.psapi.GetProcessMemoryInfo
        get_process_memory_info.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ProcessMemoryCounters),
            wintypes.DWORD,
        ]
        get_process_memory_info.restype = wintypes.BOOL
        process = get_current_process()
        if not get_process_memory_info(
            process,
            ctypes.byref(counters),
            counters.cb,
        ):
            raise SaturationError("current RSS measurement failed on Windows")
        result = int(counters.WorkingSetSize)
    elif sys.platform.startswith("linux"):
        try:
            resident_pages = int(Path("/proc/self/statm").read_text(encoding="ascii").split()[1])
            result = resident_pages * int(os.sysconf("SC_PAGE_SIZE"))
        except (OSError, ValueError, IndexError) as exc:
            raise SaturationError("current RSS measurement failed on Linux") from exc
    else:  # pragma: no cover - evidence profiles currently target Windows and Linux
        raise SaturationError("current RSS measurement is unavailable on this platform")
    if result <= 0:
        raise SaturationError("current RSS measurement returned a non-positive value")
    return result


def _measure_rss(operation: Any) -> tuple[Any, dict[str, int], list[dict[str, int]]]:
    baseline = _current_rss_bytes()
    maximum = baseline
    started_ns = time.monotonic_ns()
    samples = [{"elapsed_ns": 0, "rss_bytes": baseline}]
    stop = threading.Event()
    sampling_errors: list[Exception] = []

    def sample() -> None:
        nonlocal maximum
        try:
            while not stop.wait(0.05):
                observed = _current_rss_bytes()
                maximum = max(maximum, observed)
                if len(samples) >= 100_000:
                    raise SaturationError("RSS sample count exceeded its bound")
                samples.append(
                    {
                        "elapsed_ns": time.monotonic_ns() - started_ns,
                        "rss_bytes": observed,
                    }
                )
        except Exception as exc:  # sampled failure must invalidate evidence
            sampling_errors.append(exc)
            stop.set()

    sampler = threading.Thread(target=sample, name="promin-rss-sampler", daemon=True)
    sampler.start()
    try:
        result = operation()
        observed = _current_rss_bytes()
        maximum = max(maximum, observed)
        samples.append(
            {
                "elapsed_ns": time.monotonic_ns() - started_ns,
                "rss_bytes": observed,
            }
        )
    finally:
        stop.set()
        sampler.join(timeout=1.0)
        if sampler.is_alive():
            raise SaturationError("RSS sampler did not stop")
        if sampling_errors:
            raise SaturationError("RSS sampling failed during the measured operation") from sampling_errors[0]
    return (
        result,
        {
            "baseline_bytes": baseline,
            "peak_bytes": maximum,
            "incremental_peak_bytes": max(0, maximum - baseline),
        },
        samples,
    )


def _percentile(values: list[float], fraction: float) -> float:
    if not values or not 0.0 <= fraction <= 1.0:
        raise SaturationError("percentile input is invalid")
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


def _semantic_ingestion_elapsed_seconds(started: float, completed: float) -> float:
    elapsed = completed - started
    if elapsed <= 0:
        raise SaturationError("semantic ingestion elapsed time is not positive")
    return round(elapsed, 6)


def _record_commit_observation(
    observations: list[dict[str, Any]],
    result: Mapping[str, Any],
    *,
    phase: str,
) -> str:
    metrics = result.get("operation_metrics")
    checkpoint = metrics.get("runtime_checkpoint") if isinstance(metrics, Mapping) else None
    if not isinstance(metrics, Mapping) or not isinstance(checkpoint, Mapping):
        raise SaturationError("semantic commit omitted bounded operation metrics")
    required = {
        "duration_ms",
        "changed_records",
        "physical_payload_bytes",
        "bytes_per_changed_record",
    }
    if not required <= set(metrics):
        raise SaturationError("semantic commit operation metrics are incomplete")
    observation = {
        "sequence": len(observations) + 1,
        "phase": phase,
        "command_id": result.get("command_id"),
        "batch_digest": result.get("batch_digest"),
        "duration_ms": metrics["duration_ms"],
        "changed_records": metrics["changed_records"],
        "physical_payload_bytes": metrics["physical_payload_bytes"],
        "bytes_per_changed_record": metrics["bytes_per_changed_record"],
        "checkpoint_written": checkpoint.get("written"),
        "checkpoint_count": checkpoint.get("checkpoint_count"),
        "checkpoint_bytes": checkpoint.get("checkpoint_bytes"),
        "checkpoint_tail_batches": checkpoint.get("tail_batches"),
        "checkpoint_tail_bytes": checkpoint.get("tail_bytes"),
    }
    if (
        not isinstance(observation["duration_ms"], (int, float))
        or isinstance(observation["duration_ms"], bool)
        or observation["duration_ms"] < 0
        or not isinstance(observation["changed_records"], int)
        or isinstance(observation["changed_records"], bool)
        or observation["changed_records"] < 1
        or not isinstance(observation["physical_payload_bytes"], int)
        or isinstance(observation["physical_payload_bytes"], bool)
        or observation["physical_payload_bytes"] < 1
        or not isinstance(observation["checkpoint_written"], bool)
        or not isinstance(observation["checkpoint_count"], int)
        or isinstance(observation["checkpoint_count"], bool)
            or observation["checkpoint_count"] < 1
        or (
            observation["checkpoint_written"]
            and (
                observation["checkpoint_count"] < 1
                or not isinstance(observation["checkpoint_bytes"], int)
                or isinstance(observation["checkpoint_bytes"], bool)
                or observation["checkpoint_bytes"] < 1
            )
        )
        or (
            not observation["checkpoint_written"]
            and (
                    observation["checkpoint_bytes"] != 0
            )
        )
    ):
        raise SaturationError("semantic commit operation metrics are invalid")
    observations.append(observation)
    batch_digest = observation["batch_digest"]
    if not isinstance(batch_digest, str) or len(batch_digest) != 64:
        raise SaturationError("semantic commit omitted its batch digest")
    storage_telemetry = _ACTIVE_STORAGE_TELEMETRY.get()
    if storage_telemetry is not None:
        storage_telemetry.record_commit(observation)
    return batch_digest


def build_artifact_binding(package_root: Path, archive: Path | None) -> dict[str, Any]:
    """Bind evidence to one byte-exact folder/archive/tool identity."""

    root = package_root.resolve(strict=True)
    if archive is None:
        raise SaturationError("exact archive path is required for saturation evidence")
    archive_source = archive.absolute()
    if archive_source.is_symlink():
        raise SaturationError("exact archive must not be a symbolic link")
    archive_path = archive_source.resolve(strict=True)
    if not archive_path.is_file():
        raise SaturationError("exact archive must be a regular non-symlink file")
    try:
        archive_name = validate_release_archive_basename(archive_path.name)
    except EvidenceError as exc:
        raise SaturationError(str(exc)) from exc
    archive_bytes = _read_stable_file(archive_path)

    version_bytes = (root / "VERSION.json").read_bytes()
    manifest_bytes = (root / "MANIFEST.json").read_bytes()
    sums_bytes = (root / "SHA256SUMS.txt").read_bytes()
    try:
        version = json.loads(version_bytes)
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise SaturationError(f"package identity JSON is invalid: {exc}") from exc
    canonical_name = version.get("canonical_name")
    if canonical_name != "promin":
        raise SaturationError("exact archive binding requires canonical name promin")
    selected_preset = version.get("selected_preset")
    if not isinstance(selected_preset, Mapping) or not isinstance(selected_preset.get("path"), str):
        raise SaturationError("VERSION.json selected preset identity is invalid")
    preset_relative = _relative_path(selected_preset["path"], "selected preset path")
    core_relative = "core/promin.manifest.json"
    core_bytes = (root / core_relative).read_bytes()
    preset_bytes = (root / preset_relative).read_bytes()
    try:
        core_manifest = json.loads(core_bytes)
    except json.JSONDecodeError as exc:
        raise SaturationError(f"Core manifest is invalid: {exc}") from exc
    core_digest = _hex_digest(core_manifest.get("bundle_digest"), "Core bundle digest")
    if _hex_digest(version.get("core_bundle_digest"), "VERSION Core bundle digest") != core_digest:
        raise SaturationError("VERSION Core digest differs from the canonical Core owner")
    preset_digest = _sha256_bytes(preset_bytes)
    if _hex_digest(selected_preset.get("sha256"), "VERSION preset digest") != preset_digest:
        raise SaturationError("VERSION preset digest differs from selected preset bytes")

    rows = manifest.get("files")
    if not isinstance(rows, list) or not rows:
        raise SaturationError("package manifest files are missing")
    live_payloads: dict[str, bytes] = {}
    folded_paths: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("path"), str):
            raise SaturationError("package manifest contains an invalid file row")
        relative = _relative_path(row["path"], "package manifest path")
        if relative in live_payloads:
            raise SaturationError(f"package manifest contains duplicate path: {relative}")
        folded = unicodedata.normalize("NFC", relative).casefold()
        if folded in folded_paths:
            raise SaturationError(f"package manifest contains a normalized path collision: {relative}")
        folded_paths.add(folded)
        target = root / relative
        if target.is_symlink() or not target.is_file() or root not in target.resolve().parents:
            raise SaturationError(f"manifest file is missing or a symlink: {relative}")
        payload = target.read_bytes()
        expected_size = row.get("size", row.get("bytes"))
        if expected_size != len(payload):
            raise SaturationError(f"manifest byte count differs for {relative}")
        if _hex_digest(row.get("sha256"), f"manifest digest for {relative}") != _sha256_bytes(payload):
            raise SaturationError(f"manifest digest differs for {relative}")
        live_payloads[relative] = payload

    required_unlisted = {
        "MANIFEST.json": manifest_bytes,
        "SHA256SUMS.txt": sums_bytes,
    }
    try:
        checksum_rows: dict[str, str] = {}
        for line in sums_bytes.decode("utf-8").splitlines():
            digest_text, separator, relative_text = line.partition("  ")
            relative = _relative_path(relative_text, "checksum path")
            if separator != "  " or relative in checksum_rows:
                raise SaturationError("SHA256SUMS.txt contains a malformed or duplicate row")
            checksum_rows[relative] = _hex_digest(digest_text, f"checksum digest for {relative}")
    except UnicodeDecodeError as exc:
        raise SaturationError("SHA256SUMS.txt is not UTF-8") from exc
    expected_checksums = {
        relative: _sha256_bytes(payload) for relative, payload in live_payloads.items()
    }
    expected_checksums["MANIFEST.json"] = _sha256_bytes(manifest_bytes)
    if checksum_rows != expected_checksums:
        missing = sorted(set(expected_checksums) - set(checksum_rows))
        extra = sorted(set(checksum_rows) - set(expected_checksums))
        mismatched = sorted(
            relative
            for relative in set(checksum_rows).intersection(expected_checksums)
            if checksum_rows[relative] != expected_checksums[relative]
        )
        raise SaturationError(
            f"SHA256SUMS closure differs: missing={missing} extra={extra} mismatched={mismatched}"
        )
    prefix = f"{canonical_name}/"
    expected_members = {prefix + relative for relative in live_payloads}
    expected_members.update(prefix + relative for relative in required_unlisted)
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as handle:
            infos = handle.infolist()
            if any(item.is_dir() or item.filename.endswith("/") for item in infos):
                raise SaturationError("exact archive contains a forbidden directory entry")
            if any(item.flag_bits & 0x1 for item in infos):
                raise SaturationError("exact archive contains an encrypted member")
            if any(((item.external_attr >> 16) & 0o170000) == 0o120000 for item in infos):
                raise SaturationError("exact archive contains a symbolic-link member")
            if any(
                ((item.external_attr >> 16) & 0o170000) not in (0, 0o100000)
                for item in infos
            ):
                raise SaturationError("exact archive contains a special-file member")
            members = [item.filename for item in infos]
            forbidden_parts = {"_work", "__pycache__", ".pytest_cache", "cache"}
            if any(
                forbidden_parts.intersection(name.casefold() for name in member.split("/"))
                or member.casefold().endswith((".pyc", ".pyo"))
                for member in members
            ):
                raise SaturationError("exact archive contains work/cache/compiled payload")
            if len(members) != len(set(members)):
                raise SaturationError("exact archive contains duplicate members")
            if set(members) != expected_members:
                missing = sorted(expected_members - set(members))
                extra = sorted(set(members) - expected_members)
                raise SaturationError(
                    f"exact archive closure differs from manifest: missing={missing} extra={extra}"
                )
            for relative, payload in {**live_payloads, **required_unlisted}.items():
                if handle.read(prefix + relative) != payload:
                    raise SaturationError(f"exact archive bytes differ from folder: {relative}")
    except zipfile.BadZipFile as exc:
        raise SaturationError(f"exact archive is not a valid ZIP: {exc}") from exc

    tools: list[dict[str, Any]] = []
    for relative, tool_version in EVIDENCE_TOOL_VERSIONS.items():
        payload = live_payloads.get(relative)
        if payload is None:
            raise SaturationError(f"evidence tool is absent from package manifest: {relative}")
        tools.append(
            {
                "path": relative,
                "version": tool_version,
                "sha256": "sha256:" + _sha256_bytes(payload),
                "bytes": len(payload),
            }
        )
    tools_directory = str(Path(__file__).resolve().parent)
    if tools_directory not in sys.path:
        sys.path.insert(1, tools_directory)
    try:
        from promin_package import verify_archive
        from promin_validate import ValidationFailure

        canonical_archive = verify_archive(archive_path, install_mode=None)
    except (ImportError, ValidationFailure, ValueError) as exc:
        raise SaturationError(
            f"exact StandardReleaseCandidateBinding verification failed: {exc}"
        ) from exc
    candidate_binding = canonical_archive.get("candidate_binding")
    if not isinstance(candidate_binding, Mapping):
        raise SaturationError("canonical archive verification omitted CandidateBinding")
    candidate_checks = {
        "archive_sha256": _sha256_bytes(archive_bytes),
        "archive_bytes": len(archive_bytes),
        "package_manifest_digest": _sha256_bytes(manifest_bytes),
        "checksums_digest": _sha256_bytes(sums_bytes),
        "core_bundle_digest": core_digest,
        "preset_digest": preset_digest,
        "package_tool_digest": _sha256_bytes(live_payloads["tools/promin_package.py"]),
        "validator_digest": _sha256_bytes(live_payloads["tools/promin_validate.py"]),
    }
    mismatched_candidate_fields = sorted(
        field
        for field, expected in candidate_checks.items()
        if candidate_binding.get(field) != expected
    )
    if mismatched_candidate_fields:
        raise SaturationError(
            "CandidateBinding differs from saturation artifact identity: "
            + ", ".join(mismatched_candidate_fields)
        )
    binding: dict[str, Any] = {
        "record_type": "ExactArtifactBinding",
        "protocol_version": EVIDENCE_PROTOCOL_VERSION,
        "archive": {
            "name": archive_name,
            "sha256": "sha256:" + _sha256_bytes(archive_bytes),
            "bytes": len(archive_bytes),
            "member_count": len(expected_members),
            "manifest_member_bytes_match": True,
        },
        "package_manifest_sha256": "sha256:" + _sha256_bytes(manifest_bytes),
        "checksums_sha256": "sha256:" + _sha256_bytes(sums_bytes),
        "core_bundle_digest": "sha256:" + core_digest,
        "preset": {
            "path": preset_relative,
            "sha256": "sha256:" + preset_digest,
        },
        "tools": tools,
        "platform": _platform_binding(),
        "standard_candidate_binding": dict(candidate_binding),
        "candidate_binding_digest": candidate_binding["candidate_binding_digest"],
    }
    binding["binding_digest"] = "sha256:" + _sha256_bytes(_canonical_bytes(binding))
    return binding


def _create_physical_product(product: Path, count: int) -> float:
    if product.exists() and any(product.iterdir()):
        raise SaturationError("product must be empty unless --reuse-product is used")
    product.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    for index in range(count):
        relative = _physical_product_relative_path(index)
        target = product.parent.joinpath(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        phrase = _REPRESENTATIVE_PHRASES[index % len(_REPRESENTATIVE_PHRASES)]
        content_probe = " semantic source" if index % 257 == 0 else ""
        hostile_probe = (
            " hostile exact identity task:saturation:needle" if index % 509 == 0 else ""
        )
        target.write_text(
            f"promin {phrase}{content_probe}{hostile_probe} {index:06d}\n",
            encoding="utf-8",
            newline="\n",
        )
    _write_json(
        product.parent / ".promin" / "state" / "physical-corpus.json",
        {
            "record_type": "PhysicalCorpusRecipe",
            "recipe": _PHYSICAL_CORPUS_RECIPE,
            "file_count": count,
            "representative_classes": list(_REPRESENTATIVE_PHRASES),
            "content_probe_stride": 257,
            "hostile_probe_stride": 509,
        },
    )
    return time.perf_counter() - started


def _verify_physical_product_recipe(workspace: Path, files: int) -> None:
    path = workspace / ".promin" / "state" / "physical-corpus.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SaturationError(
            "reused product lacks the representative physical-corpus recipe binding"
        ) from exc
    if (
        not isinstance(value, Mapping)
        or value.get("record_type") != "PhysicalCorpusRecipe"
        or value.get("recipe") != _PHYSICAL_CORPUS_RECIPE
        or value.get("file_count") != files
        or value.get("content_probe_stride") != 257
        or value.get("hostile_probe_stride") != 509
        or not isinstance(value.get("representative_classes"), list)
        or len(value["representative_classes"]) != 8
    ):
        raise SaturationError("reused product physical-corpus recipe is stale or incomplete")


def _git(workspace: Path, *arguments: str, executable: str = "git") -> str:
    completed = subprocess.run(
        [executable, "-C", str(workspace), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise SaturationError(f"git {' '.join(arguments)} failed: {detail}")
    return completed.stdout.strip()


def _snapshot_provider(workspace: Path) -> dict[str, str]:
    project_path = workspace / ".promin" / "init" / "project.json"
    technologies_path = workspace / ".promin" / "init" / "technologies.json"
    try:
        project = json.loads(project_path.read_text(encoding="utf-8"))
        technologies = json.loads(technologies_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SaturationError(f"installed init plans cannot be read: {exc}") from exc
    recipe = project.get("candidate_recipe")
    if not isinstance(recipe, Mapping):
        raise SaturationError("ProjectInit candidate_recipe is missing")
    if recipe.get("snapshot_consistency") != "immutable-vcs-tree":
        raise SaturationError("physical saturation requires immutable-vcs-tree Candidate recipe")
    provider_id = recipe.get("snapshot_provider_id")
    if not isinstance(provider_id, str) or not provider_id:
        raise SaturationError("immutable Candidate recipe omitted snapshot_provider_id")
    bindings = technologies.get("bindings")
    if not isinstance(bindings, list):
        raise SaturationError("TechnologiesInit bindings are missing")
    provider = next(
        (
            binding
            for binding in bindings
            if isinstance(binding, Mapping) and binding.get("provider_id") == provider_id
        ),
        None,
    )
    if provider is None or provider.get("capability_id") != "filesystem-inventory":
        raise SaturationError(
            "snapshot_provider_id must resolve to the filesystem-inventory technology binding"
        )
    invocation = provider.get("invocation")
    if not isinstance(invocation, Mapping) or invocation.get("kind") != "executable":
        raise SaturationError("filesystem-inventory provider must use executable invocation")
    executable_value = invocation.get("value")
    if not isinstance(executable_value, str) or not executable_value:
        raise SaturationError("filesystem-inventory provider executable is missing")
    executable_path = Path(executable_value)
    if not executable_path.is_absolute():
        executable_path = workspace / executable_path
    try:
        executable_path = executable_path.resolve(strict=True)
    except OSError as exc:
        raise SaturationError(f"filesystem-inventory provider executable is unavailable: {exc}") from exc
    version = _git(workspace, "--version", executable=str(executable_path))
    if not version.startswith("git version "):
        raise SaturationError("filesystem-inventory provider is not git-compatible")
    return {
        "provider_id": provider_id,
        "executable": str(executable_path),
        "version": version,
    }


def _saturation_project_plan() -> dict[str, Any]:
    return {
        "record_type": "ProjectInit",
        "project_id": _SATURATION_PROJECT_ID,
        "roots": [{"path": "product", "kind": "product"}],
        "candidate_recipe": {
            "inventory_mode": "explicit",
            "include": ["product/**"],
            "exclude": [".promin/**"],
            "symlink_policy": "reject",
            "path_identity": "nfc-posix-relative",
            "collision_policy": "reject-nfc-and-casefold-collisions",
            "product_identity_excludes_control_state": True,
            "snapshot_consistency": "immutable-vcs-tree",
            "snapshot_provider_id": _SATURATION_PROVIDER_ID,
        },
        "preset_id": "semantic-standard",
        "operating_profile": "baseline",
    }


def _canonical_saturation_project_plan() -> dict[str, Any]:
    """Return the strict installed ProjectInit for the dedicated fixture."""

    try:
        from promin.contracts import compile_project_init, load_contract_bundle
    except ImportError as exc:  # pragma: no cover - distribution fault path
        raise SaturationError(f"production project compiler is unavailable: {exc}") from exc
    preset_path = PACKAGE_ROOT / "presets" / "semantic-standard.json"
    bundle = load_contract_bundle(PACKAGE_ROOT, preset_path)
    return compile_project_init(_saturation_project_plan(), bundle)


def _saturation_authority_plan() -> dict[str, Any]:
    return {
        "record_type": "AuthorityInit",
        "trust_mode": "local-owner",
        "subjects": [
            {
                "subject_id": _SATURATION_SUBJECT_ID,
                "kind": "human",
                "display_name": "Promin saturation owner",
            }
        ],
        "roots": [
            {
                "subject_id": _SATURATION_SUBJECT_ID,
                "capability_ceiling": list(_SATURATION_CAPABILITY_CEILING),
                "scope": [{"kind": "project", "value": _SATURATION_PROJECT_ID}],
            }
        ],
    }


def _make_saturation_init_plan(workspace: Path) -> dict[str, Any]:
    try:
        from promin.canonical import digest_file
        from promin.contracts import load_contract_bundle
        from promin.init import (
            bind_implementation_closures,
            build_provider_dependency_receipt,
        )
        from promin_init import make_plan
    except ImportError as exc:  # pragma: no cover - distribution fault path
        raise SaturationError(f"production initialization modules are unavailable: {exc}") from exc

    git_value = shutil.which("git")
    if git_value is None:
        raise SaturationError("physical saturation requires an available Git executable")
    try:
        git_path = Path(git_value).resolve(strict=True)
    except OSError as exc:
        raise SaturationError(f"Git executable cannot be resolved: {exc}") from exc
    git_version_line = _git(workspace, "--version", executable=str(git_path))
    if not git_version_line.startswith("git version "):
        raise SaturationError("filesystem-inventory provider is not git-compatible")

    preset_path = PACKAGE_ROOT / "presets" / "semantic-standard.json"
    bundle = load_contract_bundle(PACKAGE_ROOT, preset_path)
    runtime_path = Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
    runtime_license = {
        "expression": "Python-2.0",
        "source_uris": ["https://docs.python.org/3/license.html"],
        "review_state": "source-verified",
    }
    bindings = [
        {
            "capability_id": capability_id,
            "provider_id": f"python-{capability_id}",
            "version": platform.python_version(),
            "invocation": {"kind": "python-runtime", "value": str(runtime_path)},
            "purpose": f"Provide {capability_id} for the physical saturation workspace",
            "required": True,
            "healthcheck": {
                "argv": [str(runtime_path), "--version"],
                "timeout_ms": 5000,
                "expected_exit": 0,
            },
            "license": runtime_license,
            "identity": {
                "kind": "file-digest",
                "digest": digest_file(runtime_path),
                "source": str(runtime_path),
            },
        }
        for capability_id in bundle.preset["required_provider_capabilities"]
    ]
    for binding in bindings:
        binding["dependency_receipt"] = build_provider_dependency_receipt(
            binding, workspace
        )
    git_license = {
        "expression": "GPL-2.0-only",
        "source_uris": ["https://github.com/git/git/blob/master/COPYING"],
        "review_state": "source-verified",
    }
    git_binding = {
        "capability_id": "filesystem-inventory",
        "provider_id": _SATURATION_PROVIDER_ID,
        "version": git_version_line.removeprefix("git version ").strip(),
        "invocation": {"kind": "executable", "value": str(git_path)},
        "purpose": "Create and read the immutable physical saturation inventory",
        "required": False,
        "healthcheck": {
            "argv": [str(git_path), "--version"],
            "timeout_ms": 5000,
            "expected_exit": 0,
        },
        "license": git_license,
        "identity": {
            "kind": "file-digest",
            "digest": digest_file(git_path),
            "source": str(git_path),
        },
    }
    # The saturation harness exercises only Git built-ins (rev-parse and
    # archive).  Binding the complete host-wide git-core directory would add
    # hundreds of megabytes of unrelated helpers to every small focused run
    # and would make semantic-operation cost depend on the host installation.
    # Keep the primary Git executable content-bound, while the provider-tree
    # receipt contains a tiny explicit marker proving that no external helper
    # set is required by this harness.  GIT_EXEC_PATH still points at the
    # materialized receipt, so an unexpected external subcommand fails closed.
    git_provider_root = workspace.parent / (
        ".promin-saturation-git-builtins-" + digest_file(git_path)[:16]
    )
    git_provider_root.mkdir(parents=True, exist_ok=True)
    marker = git_provider_root / "BUILTINS_ONLY"
    marker.write_text(
        "rev-parse\narchive\n",
        encoding="utf-8",
    )
    git_binding["dependency_receipt"] = build_provider_dependency_receipt(
        git_binding,
        workspace,
        provider_tree=git_provider_root,
    )
    bindings.append(git_binding)
    technologies = bind_implementation_closures(
        {"record_type": "TechnologiesInit", "bindings": bindings},
        workspace,
        contract_bundle=bundle,
    )
    licenses = {
        "record_type": "LicensesPlan",
        "bindings": [
            {"provider_id": binding["provider_id"], "license": binding["license"]}
            for binding in technologies["bindings"]
        ],
    }
    return make_plan(
        standard_bundle=PACKAGE_ROOT,
        preset_path=preset_path,
        project_root=workspace,
        project_plan=_saturation_project_plan(),
        standards_plan={"record_type": "StandardsInit", "bindings": []},
        technologies_plan=technologies,
        licenses_plan=licenses,
        authority_plan=_saturation_authority_plan(),
    )


def _validate_saturation_workspace(workspace: Path, *, status: str) -> dict[str, Any]:
    try:
        from promin import service
    except ImportError as exc:  # pragma: no cover - distribution fault path
        raise SaturationError(f"production promin.service is unavailable: {exc}") from exc
    runtime = service.ProminService(workspace)
    context = runtime._context()
    plans = _plain(_field(context, "plans", {}))
    if not isinstance(plans, Mapping):
        raise SaturationError("installed saturation plans are unavailable")
    if plans.get("project.json") != _canonical_saturation_project_plan():
        raise SaturationError("workspace ProjectInit is not the dedicated saturation plan")
    if plans.get("authority.json") != _saturation_authority_plan():
        raise SaturationError("workspace AuthorityInit is not the dedicated saturation plan")
    provider = _snapshot_provider(workspace)
    init_directory = workspace / ".promin" / "init"
    init_records = sorted(path.name for path in init_directory.glob("*.json") if path.is_file())
    expected_records = [
        "activation.json",
        "authority.json",
        "project.json",
        "standards.json",
        "technologies.json",
    ]
    if init_records != expected_records:
        raise SaturationError("saturation initialization did not install exactly five init records")
    return {
        "record_type": "SaturationWorkspaceInitialization",
        "status": status,
        "project_id": _SATURATION_PROJECT_ID,
        "activation_digest": _field(context, "activation_digest"),
        "implementation_closure_digest": _field(context, "implementation_closure_digest"),
        "product_tree_scans": 0,
        "init_record_count": len(init_records),
        "init_records": init_records,
        "snapshot_provider_id": provider["provider_id"],
        "snapshot_provider_version": provider["version"],
    }


def _initialize_saturation_workspace(workspace: Path) -> dict[str, Any]:
    workspace.mkdir(parents=True, exist_ok=True)
    if not workspace.is_dir():
        raise SaturationError("saturation workspace is not a directory")
    control_root = workspace / ".promin"
    if control_root.exists():
        if not control_root.is_dir():
            raise SaturationError("saturation control path is not a directory")
        return _validate_saturation_workspace(workspace, status="reused")
    if any(workspace.iterdir()):
        raise SaturationError("new saturation workspace must be empty before initialization")
    try:
        from promin.init import apply_explicit_init_plan as apply_plan
    except ImportError as exc:  # pragma: no cover - distribution fault path
        raise SaturationError(f"production initialization tool is unavailable: {exc}") from exc
    result = apply_plan(workspace, _make_saturation_init_plan(workspace))
    if result.get("status") != "created" or result.get("product_tree_scans") != 0:
        raise SaturationError("fresh saturation initialization was not a zero-scan creation")
    return _validate_saturation_workspace(workspace, status="created")


def _prepare_vcs_snapshot(workspace: Path, *, reuse_product: bool) -> dict[str, str]:
    provider = _snapshot_provider(workspace)
    provider_id = provider["provider_id"]
    executable = provider["executable"]

    if not (workspace / ".git").is_dir():
        _git(workspace, "init", "--quiet", executable=executable)
        _git(workspace, "config", "user.name", "Promin Saturation", executable=executable)
        _git(
            workspace,
            "config",
            "user.email",
            "promin-saturation@invalid.local",
            executable=executable,
        )
    elif reuse_product and _git(
        workspace,
        "status",
        "--porcelain",
        "--",
        "product",
        executable=executable,
    ):
        raise SaturationError("reused physical product differs from its committed VCS snapshot")

    if not reuse_product:
        _git(workspace, "add", "--force", "--", "product", executable=executable)
        _git(
            workspace,
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--quiet",
            "-m",
            "promin saturation product snapshot",
            executable=executable,
        )
    head = _git(workspace, "rev-parse", "HEAD", executable=executable)
    tree = _git(workspace, "rev-parse", "HEAD:product", executable=executable)
    if _git(
        workspace,
        "status",
        "--porcelain",
        "--",
        "product",
        executable=executable,
    ):
        raise SaturationError("physical product is not equal to the committed VCS snapshot")
    tracked_files = len(
        [
            value
            for value in _git(
                workspace,
                "ls-tree",
                "-r",
                "--name-only",
                head,
                "--",
                "product",
                executable=executable,
            ).splitlines()
            if value
        ]
    )
    return {
        "consistency_mode": "immutable-vcs-tree",
        "provider_id": provider_id,
        "repository": str(workspace),
        "treeish": "HEAD",
        "commit_digest": head,
        "tree_digest": tree,
        "tree_file_count": str(tracked_files),
        "provider_version": provider["version"],
    }


def _entry_query(entry: Any) -> str:
    proxy = _field(entry, "semantic_proxy")
    value = _field(proxy, "id")
    if isinstance(value, str) and value:
        return value
    for name in ("proxy_id", "entity_id", "artifact_id", "id", "source_path", "path"):
        value = _field(entry, name)
        if isinstance(value, str) and value:
            return value
    raise SaturationError("inventory entry does not expose a production query identity")


def _physical_product_relative_path(index: int) -> str:
    if index < 0:
        raise SaturationError("physical product index must be non-negative")
    return f"product/bucket-{index // 1000:03d}/record-{index:06d}.txt"


def _physical_artifact_ids(count: int) -> list[str]:
    return [
        "artifact:file:"
        + hashlib.sha256(_physical_product_relative_path(index).encode("utf-8")).hexdigest()[:48]
        for index in range(count)
    ]


_CORPUS_PREFIX = "task:saturation:"
_CORPUS_GRANT_IDS = {
    "grant:saturation:authority",
    "grant:saturation:planner",
    "grant:saturation:executor",
    "grant:saturation:projection-reader",
}


def _semantic_corpus_specs(
    activation_digest: str,
    candidate_digest: str,
    created_at: str,
) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
    specs: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []

    def task(task_id: str, purpose: str) -> dict[str, Any]:
        return {
            "record_type": "Task",
            "task_id": task_id,
            "state": "PLANNED",
            "required_capability": "task.execute",
            "acceptance_predicate": purpose,
            "allowed_paths": ["product/**"],
            "activation_digest": activation_digest,
            "candidate_digest": candidate_digest,
            "created_at": created_at,
        }

    def relation(relation_id: str, source_id: str, target_id: str) -> dict[str, Any]:
        return {
            "record_type": "Relation",
            "relation_id": relation_id,
            "kind": "DEPENDS_ON",
            "source_type": "Task",
            "source_id": source_id,
            "target_type": "Task",
            "target_id": target_id,
            "activation_digest": activation_digest,
            "created_at": created_at,
        }

    for depth in range(13):
        task_id = f"{_CORPUS_PREFIX}depth:{depth:02d}"
        relations = []
        if depth:
            relations.append(
                relation(
                    f"relation:saturation:depth:{depth:02d}",
                    task_id,
                    f"{_CORPUS_PREFIX}depth:{depth - 1:02d}",
                )
            )
        specs.append((task(task_id, f"explicit depth-{depth} semantic fixture"), relations))

    fanout_ids: list[str] = []
    for index in range(16):
        task_id = f"{_CORPUS_PREFIX}fanout:leaf:{index:02d}"
        fanout_ids.append(task_id)
        specs.append((task(task_id, "explicit high-fanout leaf"), []))
    fanout_root = f"{_CORPUS_PREFIX}fanout:root"
    specs.append(
        (
            task(fanout_root, "explicit high-fanout root"),
            [
                relation(
                    f"relation:saturation:fanout:{index:02d}",
                    fanout_root,
                    target_id,
                )
                for index, target_id in enumerate(fanout_ids)
            ],
        )
    )
    specs.extend(
        (
            (
                task(
                    f"{_CORPUS_PREFIX}needle",
                    "exact-ID target; hostile text must not change deterministic ranking",
                ),
                [],
            ),
            (
                task(
                    f"{_CORPUS_PREFIX}needle-shadow",
                    "text mentions task:saturation:needle but is not that exact identity",
                ),
                [],
            ),
        )
    )
    return specs


def _semantic_corpus_manifest(
    activation_digest: str,
    candidate_digest: str,
    created_at: str,
) -> dict[str, Any]:
    specs = _semantic_corpus_specs(activation_digest, candidate_digest, created_at)
    task_ids = [task["task_id"] for task, _relations in specs]
    relations = [relation for _task, selected in specs for relation in selected]
    return {
        "record_type": "SaturationSemanticCorpus",
        "generation": "explicit-authorized-command-events",
        "harness_generated": True,
        "product_acceptance_credit": False,
        "task_count": len(task_ids),
        "relation_count": len(relations),
        "depths": list(range(1, 13)),
        "high_fanout": 16,
        "conflicting_exact_id_text": True,
        "task_ids": task_ids,
        "relation_ids": [relation["relation_id"] for relation in relations],
        "query_ids": [
            f"{_CORPUS_PREFIX}depth:12",
            f"{_CORPUS_PREFIX}fanout:root",
            f"{_CORPUS_PREFIX}needle",
        ],
        "continuation_query_ids": [
            f"{_CORPUS_PREFIX}depth:12",
            f"{_CORPUS_PREFIX}fanout:root",
        ],
    }


def _grant(
    authority: Mapping[str, Any],
    *,
    grant_id: str,
    subject_id: str,
    capability_id: str,
    scope: list[dict[str, str]],
    activation_digest: str,
    issued_at: str,
    expires_at: str,
    issuer: Mapping[str, Any] | None,
) -> dict[str, Any]:
    try:
        from promin.authority import canonical_digest, grant_claim_identity
    except ImportError as exc:
        raise SaturationError("production authority helpers are unavailable") from exc
    value: dict[str, Any] = {
        "record_type": "Grant",
        "grant_id": grant_id,
        "subject_id": subject_id,
        "capability_id": capability_id,
        "scope": [dict(item) for item in scope],
        "activation_digest": activation_digest,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": "nonce-" + grant_id,
    }
    value["claim_digest"] = canonical_digest(grant_claim_identity(value))
    if issuer is None:
        value["trust_proofs"] = [
            {
                "kind": "local-root",
                "root_subject_id": subject_id,
                "authority_init_digest": canonical_digest(authority),
                "signed_claim_digest": value["claim_digest"],
            }
        ]
    else:
        value["trust_proofs"] = [
            {
                "kind": "issuer-grant",
                "issuer_grant_id": issuer["grant_id"],
                "issuer_signed_claim_digest": issuer["claim_digest"],
                "signed_claim_digest": value["claim_digest"],
            }
        ]
    return value


def _command(
    *,
    command_id: str,
    command_kind: str,
    subject_id: str,
    activation_digest: str,
    requested_scope: list[dict[str, str]],
    expected_head_digest: str | None,
    issued_at: str,
    payload: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "record_type": "CommandRequest",
        "command_id": command_id,
        "command_kind": command_kind,
        "subject_id": subject_id,
        "activation_digest": activation_digest,
        "idempotency_key": "idempotency:" + command_id,
        "requested_scope": [dict(item) for item in requested_scope],
        "expected_head_digest": expected_head_digest,
        "issued_at": issued_at,
        "payload": dict(payload),
    }
    value["intent_digest"] = _digest(value)
    value["authorization"] = dict(authorization)
    return value


def _event_records(
    runtime: Any,
    *,
    task_prefixes: tuple[str, ...] | None = None,
    relation_prefixes: tuple[str, ...] | None = None,
    grant_ids: set[str] | None = None,
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
]:
    context = runtime._context()
    store = runtime._event_store(context)
    tasks: dict[str, dict[str, Any]] = {}
    relations: dict[str, dict[str, Any]] = {}
    grants: dict[str, dict[str, Any]] = {}
    for envelope in store.iter_envelopes():
        for event in envelope.get("batch", {}).get("events", ()):
            payload = event.get("payload")
            if not isinstance(payload, dict):
                continue
            if payload.get("record_type") == "Task" and isinstance(payload.get("task_id"), str):
                task_id = payload["task_id"]
                if task_prefixes is None or task_id.startswith(task_prefixes):
                    tasks[task_id] = payload
            elif payload.get("record_type") == "Relation" and isinstance(payload.get("relation_id"), str):
                relation_id = payload["relation_id"]
                if relation_prefixes is None or relation_id.startswith(relation_prefixes):
                    relations[relation_id] = payload
            elif payload.get("record_type") == "Grant" and isinstance(payload.get("grant_id"), str):
                grant_id = payload["grant_id"]
                if grant_ids is None or grant_id in grant_ids:
                    grants[grant_id] = payload
    return tasks, relations, grants


def _inspect_semantic_corpus(
    runtime: Any,
    *,
    activation_digest: str,
    candidate_digest: str,
) -> dict[str, Any] | None:
    manifest = _semantic_corpus_manifest(activation_digest, candidate_digest, "ignored")
    selected_tasks, selected_relations, selected_grants = _event_records(
        runtime,
        task_prefixes=(_CORPUS_PREFIX,),
        relation_prefixes=("relation:saturation:",),
        grant_ids=set(_CORPUS_GRANT_IDS),
    )
    if not selected_tasks and not selected_relations and not selected_grants:
        return None
    if set(selected_tasks) != set(manifest["task_ids"]):
        raise SaturationError("existing explicit semantic corpus Task identities are partial or stale")
    if set(selected_relations) != set(manifest["relation_ids"]):
        raise SaturationError("existing explicit semantic corpus Relation identities are partial or stale")
    if set(selected_grants) != _CORPUS_GRANT_IDS:
        raise SaturationError("existing saturation authority Grants are partial or stale")
    if any(task.get("candidate_digest") != candidate_digest for task in selected_tasks.values()):
        raise SaturationError("existing explicit semantic corpus binds a different Candidate")
    reader = selected_grants["grant:saturation:projection-reader"]
    if (
        reader.get("capability_id") != "projection.read"
        or reader.get("activation_digest") != activation_digest
    ):
        raise SaturationError("saturation query Grant is stale or has the wrong capability")
    return {
        **manifest,
        "reused": True,
        "query_grant": {
            key: reader[key]
            for key in (
                "subject_id",
                "grant_id",
                "claim_digest",
                "capability_id",
                "scope",
                "activation_digest",
                "expires_at",
            )
        },
    }


def _task_requested_scope(scope: list[dict[str, Any]], task_id: str) -> list[dict[str, Any]]:
    task_selector = {"kind": "task", "value": task_id}
    if any(item.get("kind") == "all" for item in scope):
        return [task_selector]
    return [*scope, task_selector]


def _bind_saturation_gate_definition(
    runtime: Any,
    task: Mapping[str, Any],
    *,
    head_digest: str,
    index: int,
) -> dict[str, Any]:
    value = dict(task)
    value.pop("gate_run_definitions", None)
    owner_digest = _digest(
        {key: item for key, item in value.items() if key != "state"}
    )
    context = runtime._context()
    gate_id = f"gate:saturation:{index:02d}"
    definition = {
        "definition_kind": "GateRunDefinition",
        "definition_id": f"definition:{gate_id}",
        "owner_kind": "Task",
        "owner_digest": owner_digest,
        "defined_at_head_digest": head_digest,
        "gate_id": gate_id,
        "run_kind": "validation",
        "expected_evidence_class": "validator",
        "expected_evidence_purpose": "gate",
        "product_credit_required": False,
        "target_kind": "candidate",
        "target_digest": value["candidate_digest"],
        "target_scope": [
            {"kind": "candidate", "value": value["candidate_digest"]}
        ],
        "candidate_digest": value["candidate_digest"],
        "policy_digest": _digest({"policy": "saturation-semantic-corpus"}),
        "tool_digest": _digest({"tool": "promin-saturation"}),
        "implementation_closure_digest": context.implementation_closure_digest,
        "provider_binding_digest": _digest(
            list(context.provider_dispatch.binding_evidence())
        ),
        "input_digests": [_digest({"task": value["task_id"]})],
        "activation_digest": value["activation_digest"],
    }
    value["gate_run_definitions"] = [
        {
            "definition_digest": _digest(definition),
            "definition": definition,
        }
    ]
    return value


def _ensure_semantic_corpus(
    runtime: Any,
    *,
    candidate_digest: str,
    commit_observations: list[dict[str, Any]],
    candidate_record: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    context = runtime._context()
    activation = _plain(_field(context, "activation", {}))
    plans = _plain(_field(context, "plans", {}))
    if not isinstance(activation, Mapping) or not isinstance(plans, Mapping):
        raise SaturationError("Activation context is unavailable for semantic corpus")
    activation_digest = activation.get("activation_digest")
    authority = plans.get("authority.json")
    if not isinstance(activation_digest, str) or not isinstance(authority, Mapping):
        raise SaturationError("semantic corpus lacks Activation or AuthorityInit")
    existing = _inspect_semantic_corpus(
        runtime,
        activation_digest=activation_digest,
        candidate_digest=candidate_digest,
    )
    if existing is not None:
        return existing
    store = runtime._event_store(context)
    if store.head().get("sequence") != 0:
        raise SaturationError(
            "dedicated saturation workspace contains non-corpus events; refusing to mix evidence"
        )
    if authority.get("trust_mode") != "local-owner":
        raise SaturationError("semantic saturation corpus requires a dedicated local-owner workspace")
    roots = authority.get("roots")
    if not isinstance(roots, list) or len(roots) != 1 or not isinstance(roots[0], Mapping):
        raise SaturationError("semantic saturation corpus requires one configured authority root")
    root = roots[0]
    ceiling = root.get("capability_ceiling")
    required_capabilities = {
        "authority.manage",
        "task.plan",
        "task.execute",
        "projection.read",
    }
    if not isinstance(ceiling, list) or not required_capabilities <= set(ceiling):
        raise SaturationError(
            "saturation AuthorityInit ceiling must include authority.manage, "
            "task.plan, task.execute, projection.read"
        )
    subject_id = root.get("subject_id")
    scope = root.get("scope")
    if not isinstance(subject_id, str) or not isinstance(scope, list) or not scope:
        raise SaturationError("saturation authority root identity/scope is invalid")
    scope = [dict(item) for item in scope if isinstance(item, Mapping)]
    if len(scope) != len(root["scope"]):
        raise SaturationError("saturation authority root scope is malformed")
    issued = datetime.now(timezone.utc).replace(microsecond=0)
    issued_at = issued.isoformat().replace("+00:00", "Z")
    expires_at = (issued + timedelta(days=1)).isoformat().replace("+00:00", "Z")
    manager = _grant(
        authority,
        grant_id="grant:saturation:authority",
        subject_id=subject_id,
        capability_id="authority.manage",
        scope=scope,
        activation_digest=activation_digest,
        issued_at=issued_at,
        expires_at=expires_at,
        issuer=None,
    )
    planner = _grant(
        authority,
        grant_id="grant:saturation:planner",
        subject_id=subject_id,
        capability_id="task.plan",
        scope=scope,
        activation_digest=activation_digest,
        issued_at=issued_at,
        expires_at=expires_at,
        issuer=manager,
    )
    executor = _grant(
        authority,
        grant_id="grant:saturation:executor",
        subject_id=subject_id,
        capability_id="task.execute",
        scope=scope,
        activation_digest=activation_digest,
        issued_at=issued_at,
        expires_at=expires_at,
        issuer=manager,
    )
    reader = _grant(
        authority,
        grant_id="grant:saturation:projection-reader",
        subject_id=subject_id,
        capability_id="projection.read",
        scope=scope,
        activation_digest=activation_digest,
        issued_at=issued_at,
        expires_at=expires_at,
        issuer=manager,
    )
    root_authorization = {
        "kind": "root",
        "subject_id": subject_id,
        "proofs": [
            {
                "kind": "local-root-command",
                "subject_id": subject_id,
                "authority_init_digest": _digest(authority),
                "signed_intent_digest": "pending",
            }
        ],
    }
    manager_command = _command(
        command_id="command:saturation:bootstrap-authority",
        command_kind="grant.issue",
        subject_id=subject_id,
        activation_digest=activation_digest,
        requested_scope=scope,
        expected_head_digest=None,
        issued_at=issued_at,
        payload=manager,
        authorization=root_authorization,
    )
    manager_command["authorization"]["proofs"][0]["signed_intent_digest"] = manager_command[
        "intent_digest"
    ]
    head = _record_commit_observation(
        commit_observations,
        runtime.commit(manager_command),
        phase="semantic-corpus",
    )
    for name, grant in (
        ("planner", planner),
        ("executor", executor),
        ("projection-reader", reader),
    ):
        command = _command(
            command_id=f"command:saturation:issue-{name}",
            command_kind="grant.issue",
            subject_id=subject_id,
            activation_digest=activation_digest,
            requested_scope=scope,
            expected_head_digest=head,
            issued_at=issued_at,
            payload=grant,
            authorization={
                "kind": "grant",
                "grant_id": manager["grant_id"],
                "grant_claim_digest": manager["claim_digest"],
            },
        )
        head = _record_commit_observation(
            commit_observations,
            runtime.commit(command),
            phase="semantic-corpus",
        )

    selected_candidate = dict(candidate_record or {})
    if selected_candidate:
        if selected_candidate.get("record_type") != "Candidate":
            raise SaturationError("semantic corpus Candidate record type is invalid")
        if selected_candidate.get("candidate_digest") != candidate_digest:
            raise SaturationError("semantic corpus Candidate digest does not match inventory")
    else:
        selected_candidate = {
            "record_type": "Candidate",
            "candidate_id": "candidate:saturation:primary",
            "candidate_digest": candidate_digest,
            "inventory_digest": _digest(
                {"kind": "saturation-inventory", "candidate": candidate_digest}
            ),
            "product_root_digest": _digest(
                {"kind": "saturation-product-root", "candidate": candidate_digest}
            ),
            "control_excluded": True,
            "candidate_recipe_digest": _digest(plans["project.json"]["candidate_recipe"]),
            "consistency_mode": "observational-best-effort",
            "creditable": False,
            "baseline_kind": "product",
        }
    candidate_command = _command(
        command_id="command:saturation:candidate",
        command_kind="candidate.record",
        subject_id=subject_id,
        activation_digest=activation_digest,
        requested_scope=[
            *scope,
            {"kind": "candidate", "value": selected_candidate["candidate_id"]},
        ],
        expected_head_digest=head,
        issued_at=issued_at,
        payload=selected_candidate,
        authorization={
            "kind": "grant",
            "grant_id": executor["grant_id"],
            "grant_claim_digest": executor["claim_digest"],
        },
    )
    head = _record_commit_observation(
        commit_observations,
        runtime.commit(candidate_command),
        phase="semantic-corpus",
    )

    specs = _semantic_corpus_specs(activation_digest, candidate_digest, issued_at)
    for index, (task, relations) in enumerate(specs):
        task = _bind_saturation_gate_definition(
            runtime,
            task,
            head_digest=head,
            index=index,
        )
        task_scope = _task_requested_scope(scope, task["task_id"])
        command = _command(
            command_id=f"command:saturation:task:{index:02d}",
            command_kind="task.record",
            subject_id=subject_id,
            activation_digest=activation_digest,
            requested_scope=task_scope,
            expected_head_digest=head,
            issued_at=issued_at,
            payload=task,
            authorization={
                "kind": "grant",
                "grant_id": planner["grant_id"],
                "grant_claim_digest": planner["claim_digest"],
            },
        )
        head = _record_commit_observation(
            commit_observations,
            runtime.commit(command, auxiliary_relations=relations),
            phase="semantic-corpus",
        )
    result = _inspect_semantic_corpus(
        runtime,
        activation_digest=activation_digest,
        candidate_digest=candidate_digest,
    )
    if result is None:
        raise SaturationError("explicit semantic corpus was not durably recorded")
    result["reused"] = False
    return result


def _physical_relation_manifest(
    relation_count: int,
    *,
    relations_per_atomic_batch_max: int = _PHYSICAL_RELATIONS_PER_TASK,
) -> dict[str, Any]:
    if relation_count <= 0:
        raise SaturationError("physical relation corpus must contain Relations")
    if relations_per_atomic_batch_max <= 0:
        raise SaturationError(
            "physical relation corpus requires room for at least one Relation per batch"
        )
    task_count = math.ceil(relation_count / _PHYSICAL_RELATIONS_PER_TASK)
    return {
        "record_type": "PhysicalRelationCorpus",
        "generation": "explicit-authorized-command-events",
        "harness_generated": True,
        "product_acceptance_credit": False,
        "task_count": task_count,
        "relation_count": relation_count,
        "relation_kind": "READS",
        "target_type": "Artifact",
        "relations_per_atomic_batch_max": relations_per_atomic_batch_max,
    }


def _physical_relation_task(
    index: int,
    *,
    activation_digest: str,
    candidate_digest: str,
    created_at: str,
) -> dict[str, Any]:
    return {
        "record_type": "Task",
        "task_id": f"{_PHYSICAL_RELATION_TASK_PREFIX}{index:06d}",
        "state": "PLANNED",
        "required_capability": "task.execute",
        "acceptance_predicate": f"verify physical proxy relation group {index:06d}",
        "allowed_paths": ["product/**"],
        "activation_digest": activation_digest,
        "candidate_digest": candidate_digest,
        "created_at": created_at,
    }


def _physical_relation(
    index: int,
    *,
    source_id: str,
    target_id: str,
    activation_digest: str,
    created_at: str,
) -> dict[str, Any]:
    return {
        "record_type": "Relation",
        "relation_id": f"{_PHYSICAL_RELATION_PREFIX}{index:06d}",
        "kind": "READS",
        "source_type": "Task",
        "source_id": source_id,
        "target_type": "Artifact",
        "target_id": target_id,
        "activation_digest": activation_digest,
        "created_at": created_at,
    }


def _inspect_physical_relation_corpus(
    runtime: Any,
    *,
    activation_digest: str,
    candidate_digest: str,
    artifact_ids: list[str],
    relation_count: int,
    relations_per_atomic_batch_max: int,
) -> dict[str, Any] | None:
    manifest = _physical_relation_manifest(
        relation_count,
        relations_per_atomic_batch_max=relations_per_atomic_batch_max,
    )
    tasks, relations, grants = _event_records(
        runtime,
        task_prefixes=(_PHYSICAL_RELATION_TASK_PREFIX,),
        relation_prefixes=(_PHYSICAL_RELATION_PREFIX,),
        grant_ids={"grant:saturation:planner"},
    )
    if not tasks and not relations:
        return None
    if len(tasks) != manifest["task_count"] or len(relations) != relation_count:
        raise SaturationError("existing physical Relation corpus is partial or stale")
    if not artifact_ids or len(artifact_ids) != len(set(artifact_ids)):
        raise SaturationError("physical Relation corpus requires unique Artifact identities")
    for task_index in range(manifest["task_count"]):
        task_id = f"{_PHYSICAL_RELATION_TASK_PREFIX}{task_index:06d}"
        task = tasks.get(task_id)
        if not isinstance(task, Mapping) or task.get("candidate_digest") != candidate_digest:
            raise SaturationError("physical Relation corpus Task identity or Candidate is stale")
    for relation_index in range(relation_count):
        relation_id = f"{_PHYSICAL_RELATION_PREFIX}{relation_index:06d}"
        relation = relations.get(relation_id)
        task_index = relation_index // _PHYSICAL_RELATIONS_PER_TASK
        expected_source = f"{_PHYSICAL_RELATION_TASK_PREFIX}{task_index:06d}"
        expected_target = artifact_ids[relation_index % len(artifact_ids)]
        if (
            not isinstance(relation, Mapping)
            or relation.get("kind") != "READS"
            or relation.get("source_type") != "Task"
            or relation.get("source_id") != expected_source
            or relation.get("target_type") != "Artifact"
            or relation.get("target_id") != expected_target
            or relation.get("activation_digest") != activation_digest
        ):
            raise SaturationError("physical Relation corpus payload differs from its recipe")
    planner = grants.get("grant:saturation:planner")
    if (
        not isinstance(planner, Mapping)
        or planner.get("capability_id") != "task.plan"
        or planner.get("activation_digest") != activation_digest
    ):
        raise SaturationError("physical Relation corpus lacks its exact planner Grant")
    artifact_target_count = len(
        set(relation["target_id"] for relation in relations.values())
    )
    return {
        **manifest,
        "artifact_target_count": artifact_target_count,
        "artifact_target_coverage": artifact_target_count / len(artifact_ids),
        "reused": True,
    }


def _ensure_physical_relation_corpus(
    runtime: Any,
    *,
    candidate_digest: str,
    artifact_ids: list[str],
    relation_count: int = _PHYSICAL_RELATION_COUNT,
    commit_observations: list[dict[str, Any]],
) -> dict[str, Any]:
    context = runtime._context()
    activation = _plain(_field(context, "activation", {}))
    activation_digest = activation.get("activation_digest") if isinstance(activation, Mapping) else None
    if not isinstance(activation_digest, str):
        raise SaturationError("physical Relation corpus lacks Activation")
    if not artifact_ids or len(artifact_ids) != len(set(artifact_ids)):
        raise SaturationError("physical Relation corpus requires unique Artifact identities")
    store = runtime._event_store(context)
    relations_per_atomic_batch_max = min(
        _PHYSICAL_RELATIONS_PER_TASK,
        store.max_events_per_batch - 1,
    )
    if relations_per_atomic_batch_max <= 0:
        raise SaturationError(
            "event batch ceiling cannot carry a Task and one physical Relation"
        )
    existing = _inspect_physical_relation_corpus(
        runtime,
        activation_digest=activation_digest,
        candidate_digest=candidate_digest,
        artifact_ids=artifact_ids,
        relation_count=relation_count,
        relations_per_atomic_batch_max=relations_per_atomic_batch_max,
    )
    if existing is not None:
        return existing
    _tasks, _relations, grants = _event_records(
        runtime,
        task_prefixes=(_PHYSICAL_RELATION_TASK_PREFIX,),
        relation_prefixes=(_PHYSICAL_RELATION_PREFIX,),
        grant_ids={"grant:saturation:planner"},
    )
    planner = grants.get("grant:saturation:planner")
    if not isinstance(planner, Mapping) or planner.get("capability_id") != "task.plan":
        raise SaturationError("physical Relation corpus requires the saturation planner Grant")
    planner_scope = planner.get("scope")
    if not isinstance(planner_scope, list) or not planner_scope:
        raise SaturationError("saturation planner Grant scope is malformed")
    issued_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )
    manifest = _physical_relation_manifest(
        relation_count,
        relations_per_atomic_batch_max=relations_per_atomic_batch_max,
    )
    head = store.head()["batch_digest"]
    for task_index in range(manifest["task_count"]):
        task = _bind_saturation_gate_definition(
            runtime,
            _physical_relation_task(
                task_index,
                activation_digest=activation_digest,
                candidate_digest=candidate_digest,
                created_at=issued_at,
            ),
            head_digest=head,
            index=_SEARCH_FIXTURE_TASK_COUNT + task_index,
        )
        start = task_index * _PHYSICAL_RELATIONS_PER_TASK
        stop = min(start + _PHYSICAL_RELATIONS_PER_TASK, relation_count)
        relations = [
            _physical_relation(
                relation_index,
                source_id=task["task_id"],
                target_id=artifact_ids[relation_index % len(artifact_ids)],
                activation_digest=activation_digest,
                created_at=issued_at,
            )
            for relation_index in range(start, stop)
        ]
        for chunk_index, relation_offset in enumerate(
            range(0, len(relations), relations_per_atomic_batch_max)
        ):
            relation_chunk = relations[
                relation_offset : relation_offset + relations_per_atomic_batch_max
            ]
            command = _command(
                command_id=(
                    "command:physical-relation-saturation:"
                    f"{task_index:06d}:{chunk_index:04d}"
                ),
                command_kind="task.record",
                subject_id=planner["subject_id"],
                activation_digest=activation_digest,
                requested_scope=_task_requested_scope(
                    [dict(item) for item in planner_scope if isinstance(item, Mapping)],
                    task["task_id"],
                ),
                expected_head_digest=head,
                issued_at=issued_at,
                payload=task,
                authorization={
                    "kind": "grant",
                    "grant_id": planner["grant_id"],
                    "grant_claim_digest": planner["claim_digest"],
                },
            )
            head = _record_commit_observation(
                commit_observations,
                runtime.commit(command, auxiliary_relations=relation_chunk),
                phase="physical-relation-corpus",
            )
    result = _inspect_physical_relation_corpus(
        runtime,
        activation_digest=activation_digest,
        candidate_digest=candidate_digest,
        artifact_ids=artifact_ids,
        relation_count=relation_count,
        relations_per_atomic_batch_max=relations_per_atomic_batch_max,
    )
    if result is None:
        raise SaturationError("physical Relation corpus was not durably recorded")
    result["reused"] = False
    return result


def _assert_workcard(card: Any, maximums: Mapping[str, int]) -> tuple[bool, str | None]:
    value = _plain(card)
    if not isinstance(value, Mapping):
        raise SaturationError("search did not return a WorkCard mapping")
    entities = value.get("entities", [])
    relations = value.get("relations", [])
    payload_size = len(_canonical_bytes(value))
    if payload_size > maximums["max_bytes"]:
        raise SaturationError(f"WorkCard exceeded max_bytes: {payload_size}")
    if len(entities) > maximums["max_entities"]:
        raise SaturationError("WorkCard exceeded max_entities")
    if len(relations) > maximums["max_relations"]:
        raise SaturationError("WorkCard exceeded max_relations")
    truncated = bool(value.get("truncated", False))
    continuation = (
        value.get("continuation")
        or value.get("continuation_token")
        or value.get("continuation_query")
    )
    token = continuation.get("token") if isinstance(continuation, Mapping) else continuation
    if truncated and not isinstance(token, str):
        raise SaturationError("truncated WorkCard omitted an explicit continuation token")
    if not truncated and token is not None:
        raise SaturationError("non-truncated WorkCard exposed an unnecessary continuation")
    return truncated, token


def _continuation(card: Any) -> Mapping[str, Any] | None:
    value = _plain(card)
    if not isinstance(value, Mapping):
        raise SaturationError("search did not return a WorkCard mapping")
    continuation = value.get("continuation")
    if continuation is None:
        return None
    if not isinstance(continuation, Mapping):
        raise SaturationError("continuation v2 metadata must be an object")
    return continuation


def _page_atoms(card: Any) -> list[str]:
    value = _plain(card)
    if not isinstance(value, Mapping):
        raise SaturationError("search did not return a WorkCard mapping")
    atoms: list[str] = []
    for namespace, collection, keys in (
        ("entity", value.get("entities", []), ("id", "entity_id")),
        ("relation", value.get("relations", []), ("relation_id", "id")),
        ("evidence", value.get("evidence", value.get("evidence_digests", [])), ("digest", "id")),
    ):
        if not isinstance(collection, list):
            raise SaturationError(f"WorkCard {namespace} collection is not an array")
        for item in collection:
            identity: str | None = item if isinstance(item, str) else None
            if isinstance(item, Mapping):
                for key in keys:
                    selected = item.get(key)
                    if isinstance(selected, str) and selected:
                        identity = selected
                        break
            if not identity:
                raise SaturationError(f"WorkCard {namespace} omitted a stable identity")
            atoms.append(f"{namespace}:{identity}")
    if len(atoms) != len(set(atoms)):
        raise SaturationError("WorkCard page contains duplicate semantic identities")
    return atoms


def _contains_inventory_artifact(card: Any) -> bool:
    value = _plain(card)
    if not isinstance(value, Mapping):
        return False
    entities = value.get("entities")
    if not isinstance(entities, list):
        return False
    return any(
        isinstance(entity, Mapping)
        and isinstance(entity.get("id"), str)
        and entity["id"].startswith("artifact:file:")
        for entity in entities
    )


def _first_entity_id(card: Any) -> str | None:
    value = _plain(card)
    entities = value.get("entities") if isinstance(value, Mapping) else None
    if not isinstance(entities, list) or not entities:
        return None
    first = entities[0]
    if isinstance(first, Mapping) and isinstance(first.get("id"), str):
        return first["id"]
    return None


def _is_empty_miss(card: Any) -> bool:
    value = _plain(card)
    if not isinstance(value, Mapping):
        return False
    return (
        value.get("entities") == []
        and value.get("relations") == []
        and value.get("evidence", value.get("evidence_digests", [])) == []
        and value.get("selected_seed_count") == 0
        and value.get("refinement_required") is False
        and value.get("truncated") is False
        and value.get("silent_truncation") is False
    )


def _mixed_query_case(
    index: int,
    *,
    forced_chains: int,
    artifact_ids: list[str],
    semantic_query_ids: list[str],
    continuation_query_ids: list[str],
) -> tuple[str, str]:
    if index < forced_chains:
        return (
            "forced-continuation",
            continuation_query_ids[index % len(continuation_query_ids)],
        )
    classes = (
        "exact-artifact",
        "content-high-cardinality",
        "content-probe",
        "miss",
        "hostile-content",
        "hostile-exact",
        "broad",
        "exact-semantic",
    )
    selected = classes[(index - forced_chains) % len(classes)]
    sample_index = (index * 9_973) % len(artifact_ids)
    if selected == "exact-artifact":
        query = artifact_ids[sample_index]
    elif selected == "content-high-cardinality":
        query = _REPRESENTATIVE_PHRASES[index % len(_REPRESENTATIVE_PHRASES)]
    elif selected == "content-probe":
        query = "semantic source"
    elif selected == "miss":
        query = f"zzqvabsent{index:06d}"
    elif selected == "hostile-content":
        query = "hostile exact identity"
    elif selected == "hostile-exact":
        query = f"{_CORPUS_PREFIX}needle"
    elif selected == "broad":
        query = "record"
    else:
        query = semantic_query_ids[index % len(semantic_query_ids)]
    return selected, query


def _mixed_query_depth(index: int, query_class: str) -> int:
    if query_class in _PHYSICAL_QUERY_DEPTH_ONE_CLASSES:
        return 1
    return index % 12 + 1


def _mixed_query_budget(ceiling: Mapping[str, int]) -> dict[str, int]:
    selected = dict(ceiling)
    selected["top_k"] = 1
    return selected


def _continuation_state_files(workspace: Path) -> dict[str, int]:
    # Compatibility-only for historical JSON-state tests. The saturation run uses
    # _ContinuationStateObserver and the projection SQLite database below.
    root = workspace / ".promin" / "state" / "continuations"
    if not root.exists():
        return {}
    files: dict[str, int] = {}
    for path in root.iterdir():
        if path.is_symlink() or not path.is_file() or path.suffix != ".json":
            raise SaturationError("continuation state contains a non-regular file")
        files[path.name] = path.stat().st_size
    return files


def _continuation_state_metrics(
    workspace: Path,
    *,
    baseline_files: set[str] | None = None,
) -> dict[str, int]:
    current = _continuation_state_files(workspace)
    excluded = baseline_files or set()
    sizes = [size for name, size in current.items() if name not in excluded]
    return {
        "files": len(sizes),
        "maximum_bytes": max(sizes, default=0),
        "total_bytes": sum(sizes),
        "preexisting_files_excluded": len(set(current).intersection(excluded)),
    }


def _continuation_state_within_limit(metrics: Mapping[str, Any]) -> bool:
    if set(metrics) != {
        "files",
        "maximum_bytes",
        "total_bytes",
        "preexisting_files_excluded",
    }:
        return False
    files = metrics.get("files")
    maximum_bytes = metrics.get("maximum_bytes")
    total_bytes = metrics.get("total_bytes")
    preexisting = metrics.get("preexisting_files_excluded")
    if any(
        not isinstance(value, int) or isinstance(value, bool)
        for value in (files, maximum_bytes, total_bytes, preexisting)
    ):
        return False
    return (
        preexisting >= 0
        and (
            (files == 0 and maximum_bytes == 0 and total_bytes == 0)
            or (
                files >= 1
                and 1 <= maximum_bytes <= 16_384
                and total_bytes >= maximum_bytes
                and files <= total_bytes <= files * maximum_bytes
            )
        )
    )


def _continuation_state_rows(
    workspace: Path,
    *,
    baseline_files: set[str],
) -> list[dict[str, Any]]:
    root = workspace / ".promin" / "state" / "continuations"
    rows: list[dict[str, Any]] = []
    for state_name in _continuation_state_files(workspace):
        if state_name in baseline_files:
            continue
        state_payload = _read_stable_file(root / state_name)
        rows.append(
            {
                "path": state_name,
                "sha256": _sha256_bytes(state_payload),
                "bytes": len(state_payload),
            }
        )
    rows.sort(key=lambda row: row["path"])
    return rows


class _ContinuationStateObserver:
    """Capture bounded SQLite continuation measurements before resume consumes rows."""

    _DATABASE_RELATIVE = ".promin/state/projection/promin.sqlite3"
    _ROW_LOCATOR_PREFIX = _DATABASE_RELATIVE + "#continuations/"
    _HANDLE_BYTES_MAX = 256

    def __init__(self, workspace: Path) -> None:
        self._database = Path(workspace).resolve() / Path(
            ".promin/state/projection/promin.sqlite3"
        )
        self._rows: dict[str, dict[str, Any]] = {}
        self._measurements: list[dict[str, int]] = []
        self._assert_empty_baseline()

    def _open_readonly(self) -> sqlite3.Connection:
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self._database.as_uri() + "?mode=ro",
                uri=True,
                isolation_level=None,
            )
            connection.execute("PRAGMA query_only=ON")
            return connection
        except (OSError, ValueError, sqlite3.Error) as exc:
            if connection is not None:
                connection.close()
            raise SaturationError(
                "continuation projection database cannot be opened read-only"
            ) from exc

    def _assert_empty_baseline(self) -> None:
        connection = self._open_readonly()
        try:
            count = connection.execute("SELECT count(*) FROM continuations").fetchone()
        except sqlite3.Error as exc:
            raise SaturationError("continuation baseline cannot be measured") from exc
        finally:
            connection.close()
        if count != (0,):
            raise SaturationError("physical saturation continuation baseline is not empty")

    @staticmethod
    def _token_locator(continuation: Mapping[str, Any]) -> tuple[str, str]:
        token = continuation.get("token")
        if not isinstance(token, str):
            raise SaturationError("continuation token format is invalid")
        try:
            token_bytes = token.encode("ascii")
        except UnicodeError as exc:
            raise SaturationError("continuation token format is invalid") from exc
        if len(token_bytes) > 256:
            raise SaturationError("continuation token format is invalid")
        parts = token.split(".")
        if len(parts) != 4 or parts[0] != "promin-v2" or not parts[1] or not parts[3]:
            raise SaturationError("continuation token format is invalid")
        digest = _hex_digest(parts[2], "continuation token row digest")
        if digest != parts[2]:
            raise SaturationError("continuation token row digest is noncanonical")
        return parts[1], digest

    def observe(self, continuation: Mapping[str, Any]) -> None:
        if not isinstance(continuation, Mapping):
            raise SaturationError("continuation observation envelope is invalid")
        handle, token_row_digest = self._token_locator(continuation)
        if len(handle.encode("utf-8")) > self._HANDLE_BYTES_MAX:
            raise SaturationError("continuation handle exceeds its byte ceiling")
        connection = self._open_readonly()
        try:
            connection.execute("BEGIN")
            summary = connection.execute(
                "SELECT count(*),"
                "coalesce(max(length(CAST(payload_json AS BLOB))),0),"
                "coalesce(sum(length(CAST(payload_json AS BLOB))),0) "
                "FROM continuations"
            ).fetchone()
            row = connection.execute(
                "SELECT row_digest,length(CAST(payload_json AS BLOB)) "
                "FROM continuations WHERE handle=? LIMIT 1",
                (handle,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise SaturationError("continuation state cannot be measured") from exc
        finally:
            connection.close()
        if (
            not isinstance(summary, tuple)
            or len(summary) != 3
            or any(type(value) is not int or value < 0 for value in summary)
        ):
            raise SaturationError("continuation state summary is invalid")
        row_count, maximum_bytes, total_bytes = summary
        if row_count < 1 or row_count > _CONTINUATION_STATE_ROWS_MAX:
            raise SaturationError("continuation state exceeded its row ceiling")
        if (
            maximum_bytes < 1
            or maximum_bytes > _CONTINUATION_STATE_BYTES_MAX
            or total_bytes < maximum_bytes
            or total_bytes > _CONTINUATION_STATE_TOTAL_BYTES_MAX
        ):
            raise SaturationError("continuation state exceeded its byte ceiling")
        if not isinstance(row, tuple) or len(row) != 2:
            raise SaturationError("continuation state row is missing")
        row_digest, payload_bytes = row
        try:
            digest = _hex_digest(row_digest, "continuation row digest")
        except SaturationError as exc:
            raise SaturationError("continuation state row digest is invalid") from exc
        if digest != token_row_digest:
            raise SaturationError("continuation state row digest differs from token")
        if (
            type(payload_bytes) is not int
            or payload_bytes < 1
            or payload_bytes > _CONTINUATION_STATE_BYTES_MAX
        ):
            raise SaturationError("continuation state row exceeded its byte ceiling")
        locator = self._ROW_LOCATOR_PREFIX + digest
        measured = {"path": locator, "sha256": digest, "bytes": payload_bytes}
        existing = self._rows.get(locator)
        if existing is not None and existing != measured:
            raise SaturationError("continuation observation digest collision")
        if existing is None and len(self._rows) >= _CONTINUATION_STATE_ROWS_MAX:
            raise SaturationError("continuation manifest exceeded its row ceiling")
        if len(self._measurements) >= _CONTINUATION_STATE_OBSERVATIONS_MAX:
            raise SaturationError("continuation measurement exceeded its sample ceiling")
        self._rows[locator] = measured
        self._measurements.append(
            {
                "rows": row_count,
                "maximum_bytes": maximum_bytes,
                "total_bytes": total_bytes,
            }
        )

    def manifest_rows(self) -> list[dict[str, Any]]:
        return [dict(self._rows[path]) for path in sorted(self._rows)]

    def measurement_rows(self) -> list[dict[str, int]]:
        return [dict(measurement) for measurement in self._measurements]

    def metrics(self) -> dict[str, int]:
        sizes = [row["bytes"] for row in self.manifest_rows()]
        return {
            "files": len(sizes),
            "maximum_bytes": max(sizes, default=0),
            "total_bytes": sum(sizes),
            "preexisting_files_excluded": 0,
        }


def _drain_pages(
    runtime: Any,
    first: Any,
    maximums: Mapping[str, int],
    *,
    query_grant: Mapping[str, Any],
    ttl_seconds: int,
    continuation_observer: _ContinuationStateObserver | None = None,
) -> dict[str, Any]:
    current = first
    seen_atoms: set[str] = set()
    seen_tokens: set[str] = set()
    page_digests: list[str] = []
    previous_cursor: int | None = None
    fixed_expiry: str | None = None
    fixed_resume_binding_digest: str | None = None
    first_truncated = False
    continuation_pages = 0
    maximum_token_bytes = 0
    refinement_required: bool | None = None
    refinement_hints: list[str] | None = None
    selected_seed_count: int | None = None
    while True:
        truncated, token = _assert_workcard(current, maximums)
        current_value = _plain(current)
        if not isinstance(current_value, Mapping):
            raise SaturationError("WorkCard page is not an object")
        page_refinement = current_value.get("refinement_required")
        page_hints = current_value.get("refinement_hints")
        page_seed_count = current_value.get("selected_seed_count")
        if (
            not isinstance(page_refinement, bool)
            or not isinstance(page_hints, list)
            or not all(isinstance(value, str) and value for value in page_hints)
            or not isinstance(page_seed_count, int)
            or isinstance(page_seed_count, bool)
            or page_seed_count < 0
            or current_value.get("unselected_matches_traversable") is not False
            or current_value.get("silent_truncation") is not False
            or current_value.get("selected_closure_complete") is not (not truncated)
        ):
            raise SaturationError("WorkCard bounded refinement/closure metadata is invalid")
        if refinement_required is None:
            refinement_required = page_refinement
            refinement_hints = list(page_hints)
            selected_seed_count = page_seed_count
        elif (
            refinement_required != page_refinement
            or refinement_hints != page_hints
            or selected_seed_count != page_seed_count
        ):
            raise SaturationError("WorkCard refinement metadata changed within one page chain")
        if not page_digests:
            first_truncated = truncated
        atoms = _page_atoms(current)
        duplicates = seen_atoms.intersection(atoms)
        if duplicates:
            raise SaturationError(
                f"continuation repeated semantic identities: {sorted(duplicates)[:5]}"
            )
        seen_atoms.update(atoms)
        page_digests.append(_digest(current))
        continuation = _continuation(current)
        if not truncated:
            if continuation is not None:
                raise SaturationError("final continuation page retained continuation metadata")
            break
        if continuation is None or token is None:
            raise SaturationError("truncated WorkCard omitted continuation v2")
        maximum_token_bytes = max(maximum_token_bytes, len(token.encode("utf-8")))
        if (
            current_value.get("continuation_version") != 2
            or current_value.get("next_stream_cursor") != continuation.get("cursor")
        ):
            raise SaturationError("WorkCard continuation stream cursor metadata is inconsistent")
        stream_cursor = current_value.get("stream_cursor")
        if not isinstance(stream_cursor, int) or stream_cursor < 0:
            raise SaturationError("WorkCard stream_cursor is invalid")
        required = {
            "version",
            "traversal",
            "token",
            "cursor",
            "expiry",
            "activation_digest",
            "head_digest",
            "projection_digest",
            "implementation_closure_digest",
            "ranking",
            "depth",
            "budget_digest",
            "resume_binding_digest",
        }
        missing = sorted(required - set(continuation))
        if missing:
            raise SaturationError(f"continuation v2 omitted fields: {missing}")
        unexpected = sorted(set(continuation) - required)
        if unexpected:
            raise SaturationError(
                f"continuation v2 exposed unexpected fields: {unexpected}"
            )
        if continuation.get("version") != 2:
            raise SaturationError("continuation does not identify the authorized v2 envelope")
        resume_binding_digest = continuation.get("resume_binding_digest")
        if (
            _hex_digest(resume_binding_digest, "continuation resume binding digest")
            != resume_binding_digest
        ):
            raise SaturationError(
                "continuation resume binding digest is not canonical lowercase SHA-256"
            )
        if fixed_resume_binding_digest is None:
            fixed_resume_binding_digest = resume_binding_digest
        elif resume_binding_digest != fixed_resume_binding_digest:
            raise SaturationError(
                "continuation authorization binding changed within one page chain"
            )
        cursor = continuation.get("cursor")
        if not isinstance(cursor, int) or cursor < 0:
            raise SaturationError("continuation cursor is not a non-negative integer")
        if previous_cursor is not None and cursor <= previous_cursor:
            raise SaturationError("continuation cursor did not strictly advance")
        previous_cursor = cursor
        expiry = continuation.get("expiry")
        if not isinstance(expiry, str) or not expiry:
            raise SaturationError("continuation expiry is invalid")
        if fixed_expiry is None:
            fixed_expiry = expiry
        elif expiry != fixed_expiry:
            raise SaturationError("continuation expiry changed within one page chain")
        if token in seen_tokens:
            raise SaturationError("continuation token repeated within one page chain")
        seen_tokens.add(token)
        continuation_pages += 1
        if continuation_pages > 10_000:
            raise SaturationError("continuation exceeded the bounded 10000-page safety limit")
        continuation_query = current_value.get("query")
        continuation_depth = current_value.get("depth")
        continuation_budget = current_value.get("budget")
        continuation_ranking = current_value.get("ranking")
        if (
            not isinstance(continuation_query, str)
            or not continuation_query
            or not isinstance(continuation_depth, int)
            or isinstance(continuation_depth, bool)
            or not isinstance(continuation_budget, Mapping)
            or not isinstance(continuation_ranking, str)
            or not continuation_ranking
        ):
            raise SaturationError(
                "continuation source page omitted its exact search binding"
            )
        if continuation_observer is not None:
            continuation_observer.observe(continuation)
        current = runtime.search(
            continuation_query,
            continuation_depth,
            budget=dict(continuation_budget),
            ranking=continuation_ranking,
            continuation_token=token,
            subject_id=query_grant["subject_id"],
            grant_id=query_grant["grant_id"],
            ttl_seconds=ttl_seconds,
        )
    return {
        "atoms": seen_atoms,
        "page_digests": page_digests,
        "pages": len(page_digests),
        "continuation_pages": continuation_pages,
        "first_truncated": first_truncated,
        "fixed_expiry": fixed_expiry,
        "maximum_token_bytes": maximum_token_bytes,
        "refinement_required": refinement_required is True,
        "refinement_hints": refinement_hints or [],
        "selected_seed_count": selected_seed_count or 0,
        "selected_closure_complete": True,
    }


def _raw_page_trace(value: Mapping[str, Any]) -> dict[str, Any]:
    atoms = sorted(value["atoms"])
    return {
        "pages": value["pages"],
        "continuation_pages": value["continuation_pages"],
        "first_truncated": value["first_truncated"],
        "maximum_token_bytes": value["maximum_token_bytes"],
        "selected_closure_complete": value["selected_closure_complete"],
        "atoms": atoms,
        "atoms_count": len(atoms),
        "atoms_digest": _digest(atoms),
        "page_digests": list(value["page_digests"]),
    }


def _snapshot_signal(inventory: Any, descriptor: Mapping[str, str]) -> dict[str, Any]:
    candidate = _plain(_field(inventory, "candidate", {}))
    if not isinstance(candidate, Mapping):
        raise SaturationError("inventory omitted Candidate")
    if candidate.get("consistency_mode") != "immutable-vcs-tree":
        raise SaturationError("physical Candidate is not bound to immutable-vcs-tree")
    if candidate.get("creditable") is not True:
        raise SaturationError("physical Candidate is observational and cannot receive scale credit")
    if candidate.get("snapshot_provider_id") != descriptor["provider_id"]:
        raise SaturationError("Candidate snapshot provider differs from selected adapter")
    snapshot_digest = _hex_digest(
        candidate.get("snapshot_digest"), "creditable Candidate snapshot_digest"
    )
    recipe_digest = _hex_digest(
        candidate.get("candidate_recipe_digest"), "Candidate candidate_recipe_digest"
    )
    invocations = _field(inventory, "provider_invocations", ())
    if not isinstance(invocations, (list, tuple)):
        raise SaturationError("inventory provider invocation evidence is not an array")
    binding = _plain(_field(inventory, "immutable_vcs_binding"))
    if not isinstance(binding, Mapping):
        raise SaturationError("inventory omitted its immutable VCS snapshot binding")
    if binding.get("source_roots") != ["product"]:
        raise SaturationError("physical inventory immutable VCS binding selected unexpected roots")
    entries = _field(inventory, "entries")
    try:
        entry_count = len(entries)
    except TypeError as exc:
        raise SaturationError("inventory entries do not expose a bounded count") from exc
    try:
        from promin import service

        binding_arguments = {
            "repository_tree_object": binding.get("repository_tree_object"),
            "provider_invocations": invocations,
            "candidate_recipe_digest": recipe_digest,
            "source_roots": binding["source_roots"],
            "inventory_digest": candidate.get("inventory_digest"),
            "inventory_stream_digest": _field(inventory, "stream_digest"),
            "inventory_stream_bytes": _field(inventory, "stream_bytes"),
            "inventory_entry_count": entry_count,
        }
        rebuilt_binding = service._immutable_vcs_snapshot_binding(**binding_arguments)
        expected_snapshot_digest = service._immutable_vcs_snapshot_digest(
            **binding_arguments
        )
    except Exception as exc:
        raise SaturationError(f"immutable VCS snapshot binding is invalid: {exc}") from exc
    if dict(binding) != rebuilt_binding:
        raise SaturationError("immutable VCS snapshot binding differs from inventory inputs")
    if snapshot_digest != expected_snapshot_digest:
        raise SaturationError("Candidate snapshot digest differs from immutable VCS binding")
    receipts = [
        dict(rebuilt_binding["tree_object_completion_receipt"]),
        dict(rebuilt_binding["tree_stream_completion_receipt"]),
    ]
    if any(receipt["provider_id"] != descriptor["provider_id"] for receipt in receipts):
        raise SaturationError("immutable VCS receipts differ from the selected snapshot provider")
    return {
        "consistency_mode": candidate["consistency_mode"],
        "creditable": True,
        "snapshot_provider_id": candidate["snapshot_provider_id"],
        "snapshot_digest": snapshot_digest,
        "candidate_recipe_digest": recipe_digest,
        "provider_invocations": receipts,
        "vcs_commit": descriptor["commit_digest"],
        "vcs_tree_digest": descriptor["tree_digest"],
    }


def _release_signal(runtime: Any) -> dict[str, Any]:
    status = runtime.status()
    approval = _plain(_field(status, "approval", {}))
    if not isinstance(approval, Mapping):
        raise SaturationError("status omitted derived current-release approval")
    required = {
        "current_release_eligible",
        "product_acceptance",
        "public_release_approved",
        "historical_release_decision_id",
        "release_closure_digest",
        "current_closure_digest",
        "invalidation_reasons",
    }
    missing = sorted(required - set(approval))
    if missing:
        raise SaturationError(f"status omitted current-release regression signals: {missing}")
    eligible = approval["current_release_eligible"]
    if not isinstance(eligible, bool):
        raise SaturationError("current_release_eligible is not boolean")
    if eligible != approval["product_acceptance"] or eligible != approval["public_release_approved"]:
        raise SaturationError("current release eligibility disagrees with acceptance/public approval")
    if eligible:
        raise SaturationError("saturation workspace unexpectedly has current release eligibility")
    reasons = approval["invalidation_reasons"]
    if not isinstance(reasons, list) or not reasons or not all(isinstance(item, str) for item in reasons):
        raise SaturationError("ineligible current release omitted machine-readable reasons")
    return {
        key: approval[key]
        for key in (
            "current_release_eligible",
            "historical_release_decision_id",
            "release_closure_digest",
            "current_closure_digest",
            "invalidation_reasons",
        )
    }


def _load_ceiling() -> dict[str, int]:
    conformance = json.loads((PACKAGE_ROOT / "core" / "conformance.json").read_text(encoding="utf-8"))
    ceiling = conformance["workcard_hard_ceiling"]
    return {
        "max_bytes": int(ceiling["max_bytes"]),
        "max_entities": int(ceiling["max_entities"]),
        "max_relations": int(ceiling["max_relations"]),
        "max_fanout_per_entity": int(ceiling["max_fanout_per_entity"]),
        "top_k": int(ceiling["top_k"]),
    }


def _load_performance_contract(profile_id: str) -> dict[str, Any]:
    conformance = json.loads(
        (PACKAGE_ROOT / "core" / "conformance.json").read_text(encoding="utf-8")
    )
    reference = conformance.get("reference_benchmarks")
    if not isinstance(reference, Mapping):
        raise SaturationError("Core reference_benchmarks owner is missing")
    profiles = reference.get("performance_profiles")
    if not isinstance(profiles, Mapping) or not isinstance(profiles.get(profile_id), Mapping):
        raise SaturationError(f"unknown canonical performance profile: {profile_id}")
    profile = dict(profiles[profile_id])
    threshold_fields = {
        "p50_ms_max",
        "p95_ms_max",
        "p99_ms_max",
        "peak_rss_bytes_max",
        "database_bytes_max",
        "projection_amplification_max",
        "semantic_inflation_max",
        "commit_p95_ms_max",
        "commit_p99_ms_max",
        "commit_bytes_per_changed_record_max",
        "runtime_checkpoint_count_max",
        "semantic_ingestion_seconds_max",
    }
    missing = sorted(threshold_fields - set(profile))
    if missing:
        raise SaturationError(f"performance profile omits thresholds: {missing}")
    for field in threshold_fields:
        value = profile[field]
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
            raise SaturationError(f"performance profile threshold is invalid: {field}")
    compatible = profile.get("compatible_platforms")
    current_system = platform.system().casefold()
    if (
        not isinstance(compatible, list)
        or not compatible
        or not all(isinstance(item, str) and item for item in compatible)
        or current_system not in {item.casefold() for item in compatible}
    ):
        raise SaturationError(
            f"performance profile {profile_id} is not bound to platform {current_system}"
        )
    if profile.get("requires_same_runner_no_degradation") is not True:
        raise SaturationError(
            "performance profile must require same-runner no-degradation evidence"
        )
    exact_contract = {
        "file_count": _EXACT_PHYSICAL_FILES,
        "core_valid_relation_count": _EXACT_CORE_VALID_RELATIONS,
        "raw_file_proxy_ratio": 1,
        "synthetic_task_ratio": 0,
        "inventory_passes": 1,
        "rebuild_product_passes": 0,
        "silent_truncations_max": 0,
        "query_count": _EXACT_RUNTIME_QUERIES,
    }
    for field, expected in exact_contract.items():
        if reference.get(field) != expected:
            raise SaturationError(
                f"Core reference benchmark differs for {field}: {reference.get(field)!r}"
            )
    corpus = reference.get("semantic_corpus")
    expected_corpus = {
        "task_count": _SEARCH_FIXTURE_TASK_COUNT,
        "relation_count": _SEARCH_FIXTURE_RELATION_COUNT,
        "relation_kind": "DEPENDS_ON",
        "depths": list(range(1, 13)),
        "separate_from_raw_inventory": True,
        "expected_counts_source": "fixture-manifest",
    }
    if not isinstance(corpus, Mapping) or any(
        corpus.get(key) != value for key, value in expected_corpus.items()
    ):
        raise SaturationError("Core semantic_corpus manifest differs from the executable fixture")
    physical_relations = reference.get("physical_relation_corpus")
    expected_physical_relations = {
        "artifact_target_coverage": 1,
        "expected_counts_source": "fixture-manifest",
        "generation": "explicit-authorized-command-events",
        "relation_count": _PHYSICAL_RELATION_COUNT,
        "relation_kind": "READS",
        "separate_from_raw_inventory": True,
        "task_count": math.ceil(
            _PHYSICAL_RELATION_COUNT / _PHYSICAL_RELATIONS_PER_TASK
        ),
        "total_core_valid_relations": _EXACT_CORE_VALID_RELATIONS,
    }
    if not isinstance(physical_relations, Mapping) or any(
        physical_relations.get(key) != value
        for key, value in expected_physical_relations.items()
    ):
        raise SaturationError(
            "Core physical_relation_corpus differs from the executable fixture"
        )
    return {
        "profile_id": profile_id,
        "thresholds": {field: profile[field] for field in sorted(threshold_fields)},
        "compatible_platforms": list(profile["compatible_platforms"]),
        "requires_same_runner_no_degradation": True,
        "core_contract": exact_contract,
        "semantic_corpus": expected_corpus,
        "physical_relation_corpus": expected_physical_relations,
    }


def _inventory_stream_bytes(workspace: Path, inventory: Any) -> int:
    path_value = _field(inventory, "stream_path")
    digest = _field(inventory, "stream_digest")
    reported_bytes = _field(inventory, "stream_bytes")
    if not isinstance(path_value, Path) or not isinstance(digest, str) or len(digest) != 64:
        raise SaturationError("InventoryResult omitted its verified stream descriptor")
    path = path_value.resolve()
    expected_root = (workspace / ".promin" / "state" / "inventory").resolve()
    try:
        path.relative_to(expected_root)
    except ValueError as exc:
        raise SaturationError("InventoryResult stream escapes runtime-owned state") from exc
    if path.is_symlink() or not path.is_file():
        raise SaturationError("runtime-owned immutable inventory stream is unavailable")
    payload = _read_stable_file(path)
    size = len(payload)
    if (
        size <= 0
        or reported_bytes != size
        or _sha256_bytes(payload) != digest
    ):
        raise SaturationError("runtime-owned inventory stream descriptor is inconsistent")
    return size


def _projection_database_bytes(workspace: Path) -> int:
    path = workspace / ".promin" / "state" / "projection" / "promin.sqlite3"
    if path.is_symlink() or not path.is_file():
        raise SaturationError("projection database is unavailable or is a symlink")
    size = path.stat().st_size
    if size <= 0:
        raise SaturationError("projection database is empty")
    return size


def _projection_entity_type_counts(workspace: Path) -> dict[str, int]:
    path = workspace / ".promin" / "state" / "projection" / "promin.sqlite3"
    if path.is_symlink() or not path.is_file():
        raise SaturationError("projection database is unavailable or is a symlink")
    uri = path.resolve(strict=True).as_uri() + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
        try:
            rows = connection.execute(
                "SELECT entity_type,count(*) FROM entities "
                "GROUP BY entity_type ORDER BY entity_type"
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise SaturationError(f"projection entity type count query failed: {exc}") from exc
    counts: dict[str, int] = {}
    for entity_type, count in rows:
        if (
            not isinstance(entity_type, str)
            or not entity_type
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
        ):
            raise SaturationError("projection entity type count row is invalid")
        counts[entity_type] = count
    if not counts:
        raise SaturationError("projection entity type counts are empty")
    return counts


def _projection_inventory_integrity(workspace: Path, expected_files: int) -> dict[str, int]:
    path = workspace / ".promin" / "state" / "projection" / "promin.sqlite3"
    uri = path.resolve(strict=True).as_uri() + "?mode=ro"
    try:
        connection = sqlite3.connect(uri, uri=True)
        try:
            raw_total = int(
                connection.execute(
                    "SELECT count(*) FROM entities WHERE data_class='untrusted-source'"
                ).fetchone()[0]
            )
            raw_artifacts = int(
                connection.execute(
                    "SELECT count(*) FROM entities "
                    "WHERE data_class='untrusted-source' AND entity_type='Artifact'"
                ).fetchone()[0]
            )
            synthetic_inventory_tasks = int(
                connection.execute(
                    "SELECT count(*) FROM entities "
                    "WHERE data_class='untrusted-source' AND entity_type='Task'"
                ).fetchone()[0]
            )
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise SaturationError(f"projection inventory integrity query failed: {exc}") from exc
    if raw_total != expected_files or raw_artifacts != expected_files or synthetic_inventory_tasks != 0:
        raise SaturationError("durable projection did not force raw proxy provenance to Artifact/untrusted-source")
    return {
        "untrusted_source_entities": raw_total,
        "untrusted_source_artifacts": raw_artifacts,
        "untrusted_source_tasks": synthetic_inventory_tasks,
    }


def _performance_result(
    contract: Mapping[str, Any],
    *,
    p50_ms: float,
    p95_ms: float,
    p99_ms: float,
    peak_rss_bytes: int,
    database_bytes: int,
    projection_amplification: float,
    semantic_inflation: float,
    commit_p95_ms: float,
    commit_p99_ms: float,
    commit_bytes_per_changed_record: float,
    runtime_checkpoint_count: int,
    runtime_checkpoint_writes: int,
    semantic_ingestion_seconds: float,
) -> dict[str, Any]:
    observed = {
        "p50_ms": round(p50_ms, 6),
        "p95_ms": round(p95_ms, 6),
        "p99_ms": round(p99_ms, 6),
        "peak_rss_bytes": peak_rss_bytes,
        "database_bytes": database_bytes,
        "projection_amplification": round(projection_amplification, 9),
        "semantic_inflation": round(semantic_inflation, 9),
        "commit_p95_ms": round(commit_p95_ms, 6),
        "commit_p99_ms": round(commit_p99_ms, 6),
        "commit_bytes_per_changed_record": round(
            commit_bytes_per_changed_record, 6
        ),
        "runtime_checkpoint_count": runtime_checkpoint_count,
        "runtime_checkpoint_writes": runtime_checkpoint_writes,
        "semantic_ingestion_seconds": round(semantic_ingestion_seconds, 6),
    }
    thresholds = contract["thresholds"]
    predicates = {
        "p50_within_profile": observed["p50_ms"] <= thresholds["p50_ms_max"],
        "p95_within_profile": observed["p95_ms"] <= thresholds["p95_ms_max"],
        "p99_within_profile": observed["p99_ms"] <= thresholds["p99_ms_max"],
        "peak_rss_within_profile": observed["peak_rss_bytes"]
        <= thresholds["peak_rss_bytes_max"],
        "database_within_profile": observed["database_bytes"]
        <= thresholds["database_bytes_max"],
        "projection_amplification_within_profile": observed["projection_amplification"]
        <= thresholds["projection_amplification_max"],
        "semantic_inflation_within_profile": observed["semantic_inflation"]
        <= thresholds["semantic_inflation_max"],
        "commit_p95_within_profile": observed["commit_p95_ms"]
        <= thresholds["commit_p95_ms_max"],
        "commit_p99_within_profile": observed["commit_p99_ms"]
        <= thresholds["commit_p99_ms_max"],
        "commit_bytes_per_changed_record_within_profile": observed[
            "commit_bytes_per_changed_record"
        ]
        <= thresholds["commit_bytes_per_changed_record_max"],
        "runtime_checkpoint_count_within_profile": observed[
            "runtime_checkpoint_count"
        ]
        <= thresholds["runtime_checkpoint_count_max"],
        "semantic_ingestion_within_profile": observed[
            "semantic_ingestion_seconds"
        ]
        <= thresholds["semantic_ingestion_seconds_max"],
    }
    return {
        "profile_id": contract["profile_id"],
        "platform_binding": _platform_binding(),
        "compatible_platforms": contract["compatible_platforms"],
        "requires_same_runner_no_degradation": contract[
            "requires_same_runner_no_degradation"
        ],
        "thresholds": dict(thresholds),
        "observed": observed,
        "predicates": predicates,
        "all_within_profile": all(predicates.values()),
    }


def _guard_storage_run(operation: Any) -> Any:
    @functools.wraps(operation)
    def guarded(
        workspace: Path,
        output: Path,
        *,
        archive: Path | None = None,
        files: int = _EXACT_PHYSICAL_FILES,
        queries: int = _EXACT_RUNTIME_QUERIES,
        reuse_product: bool = False,
        performance_profile: str = "portable-local-v1",
    ) -> dict[str, Any]:
        if files != _EXACT_PHYSICAL_FILES:
            raise SaturationError("physical saturation requires exactly 100000 files")
        if queries != _EXACT_RUNTIME_QUERIES:
            raise SaturationError("search saturation requires exactly 600 actual queries")
        workspace = Path(workspace).resolve()
        output = Path(output).resolve()
        performance_contract = _load_performance_contract(performance_profile)
        telemetry = _StorageRunTelemetry(
            workspace,
            output,
            archive=archive,
            performance_contract=performance_contract,
            files=files,
            queries=queries,
            reuse_product=reuse_product,
        )
        token = _ACTIVE_STORAGE_TELEMETRY.set(telemetry)
        try:
            telemetry.prepare()
            return operation(
                workspace,
                output,
                archive=archive,
                files=files,
                queries=queries,
                reuse_product=reuse_product,
                performance_profile=performance_profile,
            )
        except BaseException as exc:
            if isinstance(exc, TerminalPublicationError):
                raise
            failure_code = telemetry.failure_code(exc)
            if failure_code is not None:
                receipt_path: Path | None = None
                try:
                    receipt_path = telemetry.publish_failure(exc, failure_code)
                except Exception:
                    pass
                if not isinstance(exc, StorageBudgetError):
                    receipt_suffix = (
                        f"; terminal receipt: {receipt_path}"
                        if receipt_path is not None
                        else "; terminal receipt could not be persisted"
                    )
                    raise StorageBudgetError(
                        f"saturation failed closed on {failure_code}: {exc}{receipt_suffix}",
                        failure_code=failure_code,
                    ) from exc
            elif isinstance(exc, (OSError, ValueError, SaturationError)):
                try:
                    telemetry.publish_rejection(exc)
                except Exception:
                    pass
            raise
        finally:
            telemetry.stop(suppress_identity_error=telemetry._terminal_observed)
            _ACTIVE_STORAGE_TELEMETRY.reset(token)

    return guarded


def _publish_completed_saturation_result(
    output: Path,
    evidence: dict[str, Any],
    *,
    candidate_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Publish a sealed completed run after pass-neutral structural validation."""

    result_path = output / "saturation-result.json"
    validated = validate_saturation_evidence(
        evidence,
        candidate_binding=candidate_binding,
        source_path=result_path,
        evidence_root=output,
        require_pass=False,
    )
    if _canonical_bytes(validated) != _canonical_bytes(evidence):
        raise SaturationError("live saturation validation changed the sealed result")
    _write_json_create_only(result_path, evidence)
    return evidence


@_guard_storage_run
def run(
    workspace: Path,
    output: Path,
    *,
    archive: Path | None = None,
    files: int = _EXACT_PHYSICAL_FILES,
    queries: int = _EXACT_RUNTIME_QUERIES,
    reuse_product: bool = False,
    performance_profile: str = "portable-local-v1",
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
    if files != _EXACT_PHYSICAL_FILES:
        raise SaturationError("physical saturation requires exactly 100000 files")
    if queries != _EXACT_RUNTIME_QUERIES:
        raise SaturationError("search saturation requires exactly 600 actual queries")
    performance_contract = _load_performance_contract(performance_profile)
    artifact_binding = build_artifact_binding(PACKAGE_ROOT, archive)

    try:
        from promin import service
    except ImportError as exc:
        raise SaturationError(f"production promin.service is unavailable: {exc}") from exc

    workspace = workspace.resolve()
    workspace_initialization = _initialize_saturation_workspace(workspace)
    runtime = service.ProminService(workspace)
    release_before = _release_signal(runtime)
    _snapshot_provider(workspace)
    product = workspace / "product"
    generation_seconds: float | None
    if reuse_product:
        _verify_physical_product_recipe(workspace, files)
        generation_seconds = None
    else:
        generation_seconds = _create_physical_product(product, files)
    snapshot_descriptor = _prepare_vcs_snapshot(workspace, reuse_product=reuse_product)
    if int(snapshot_descriptor["tree_file_count"]) != files:
        raise SaturationError(
            f"immutable VCS tree contains {snapshot_descriptor['tree_file_count']} product files, "
            f"expected {files}"
        )
    _measure_storage_phase("physical-generation")

    inventory_started = time.perf_counter()
    inventory, inventory_rss, inventory_rss_samples = _measure_rss(
        lambda: service.inventory_candidate(
            workspace,
            ["product"],
            snapshot_descriptor={
                key: snapshot_descriptor[key]
                for key in ("consistency_mode", "provider_id", "repository", "treeish")
            },
        )
    )
    inventory_seconds = time.perf_counter() - inventory_started
    snapshot_signal = _snapshot_signal(inventory, snapshot_descriptor)
    if int(_field(inventory, "product_tree_passes", -1)) != 1:
        raise SaturationError("inventory did not perform exactly one product-tree pass")
    inventory_stream_bytes = _inventory_stream_bytes(workspace, inventory)
    candidate_digest = _field(_field(inventory, "candidate", {}), "candidate_digest")
    if not isinstance(candidate_digest, str) or len(candidate_digest) != 64:
        raise SaturationError("InventoryResult omitted its Candidate digest")
    _measure_storage_phase("inventory")
    semantic_commit_observations: list[dict[str, Any]] = []
    semantic_ingestion_started = time.perf_counter()
    search_corpus = _ensure_semantic_corpus(
        runtime,
        candidate_digest=candidate_digest,
        candidate_record=_plain(_field(inventory, "candidate", {})),
        commit_observations=semantic_commit_observations,
    )
    entries = _field(inventory, "entries")
    if entries is None:
        raise SaturationError("inventory result omitted one-shot entries")
    entry_count = len(entries)
    if entry_count != files:
        raise SaturationError(f"inventory produced {entry_count} entries, expected {files}")
    artifact_ids = _physical_artifact_ids(files)
    if len(artifact_ids) != len(set(artifact_ids)):
        raise SaturationError("inventory Artifact proxy identities are not unique")
    physical_relation_corpus = _ensure_physical_relation_corpus(
        runtime,
        candidate_digest=candidate_digest,
        artifact_ids=artifact_ids,
        commit_observations=semantic_commit_observations,
    )
    semantic_ingestion_seconds = _semantic_ingestion_elapsed_seconds(
        semantic_ingestion_started,
        time.perf_counter(),
    )
    if not semantic_commit_observations:
        raise SaturationError(
            "physical run did not execute independently measured semantic commits"
        )
    semantic_corpus = {
        **search_corpus,
        "task_count": search_corpus["task_count"]
        + physical_relation_corpus["task_count"],
        "relation_count": search_corpus["relation_count"]
        + physical_relation_corpus["relation_count"],
        "search_fixture": {
            key: search_corpus[key]
            for key in ("task_count", "relation_count", "depths", "high_fanout")
        },
        "physical_relation_fixture": {
            key: physical_relation_corpus[key]
            for key in (
                "task_count",
                "relation_count",
                "relation_kind",
                "target_type",
                "artifact_target_count",
                "artifact_target_coverage",
                "relations_per_atomic_batch_max",
            )
        },
        "reused": search_corpus["reused"] and physical_relation_corpus["reused"],
        "search_fixture_reused": search_corpus["reused"],
        "physical_relation_fixture_reused": physical_relation_corpus["reused"],
    }
    if any(
        semantic_corpus[field] is not False
        for field in (
            "reused",
            "search_fixture_reused",
            "physical_relation_fixture_reused",
        )
    ):
        raise SaturationError(
            "physical saturation cannot reuse semantic corpus state"
        )
    _measure_storage_phase("semantic-ingestion")

    rebuild_started = time.perf_counter()
    first_rebuild, rebuild_rss, rebuild_rss_samples = _measure_rss(
        lambda: runtime.rebuild(inventory)
    )
    rebuild_seconds = time.perf_counter() - rebuild_started
    if int(_field(first_rebuild, "inventory_passes", -1)) != 1:
        raise SaturationError("initial projection build did not consume exactly one inventory pass")
    if int(_field(first_rebuild, "product_passes", -1)) != 0:
        raise SaturationError("projection build performed a hidden product pass")
    proxy_count = int(_field(first_rebuild, "inventory_proxies", -1))
    inventory_relation_count = int(_field(first_rebuild, "inventory_relations", -1))
    synthetic_task_count = int(_field(first_rebuild, "synthetic_task_count", -1))
    raw_file_proxy_ratio = float(_field(first_rebuild, "raw_file_proxy_ratio", -1.0))
    synthetic_task_ratio = float(_field(first_rebuild, "synthetic_task_ratio", -1.0))
    relation_count = int(_field(first_rebuild, "relation_count", -1))
    entity_count = int(_field(first_rebuild, "entity_count", -1))
    if proxy_count != files or raw_file_proxy_ratio != 1.0:
        raise SaturationError("projection did not preserve exact one-Artifact-per-raw-file identity")
    if (
        synthetic_task_count != 0
        or synthetic_task_ratio != 0.0
        or inventory_relation_count != 0
    ):
        raise SaturationError("raw inventory synthesized Task or Relation semantics")
    if relation_count != semantic_corpus["relation_count"]:
        raise SaturationError(
            "projection relation count differs from the explicit semantic corpus manifest"
        )
    if relation_count != _EXACT_CORE_VALID_RELATIONS:
        raise SaturationError(
            f"projection produced {relation_count} Core-valid Relations; "
            f"exactly {_EXACT_CORE_VALID_RELATIONS} required"
        )
    expected_entity_type_counts = {
        "Artifact": files,
        "Candidate": 1,
        "Grant": len(_CORPUS_GRANT_IDS),
        "Task": semantic_corpus["task_count"],
    }
    expected_entity_count = sum(expected_entity_type_counts.values())
    if entity_count != expected_entity_count:
        raise SaturationError(
            f"projection entity count {entity_count} differs from exact fixture count "
            f"{expected_entity_count}"
        )

    semantic_digest = _field(first_rebuild, "semantic_digest")
    if not isinstance(semantic_digest, str):
        raise SaturationError("projection build omitted semantic_digest")
    implementation_closure_digest = _field(first_rebuild, "implementation_closure_digest")
    if (
        not isinstance(implementation_closure_digest, str)
        or len(implementation_closure_digest) != 64
        or any(character not in "0123456789abcdef" for character in implementation_closure_digest)
    ):
        raise SaturationError("projection build omitted implementation closure identity")
    second_rebuild = runtime.rebuild()
    if int(_field(second_rebuild, "inventory_passes", -1)) != 1:
        raise SaturationError("rebuild did not consume exactly one verified persisted inventory stream")
    if int(_field(second_rebuild, "product_passes", -1)) != 0:
        raise SaturationError("rebuild scanned product files")
    if _field(second_rebuild, "semantic_digest") != semantic_digest:
        raise SaturationError("projection rebuild semantic digest differs from initial build")
    if _field(second_rebuild, "implementation_closure_digest") != implementation_closure_digest:
        raise SaturationError("projection rebuild implementation closure differs from initial build")
    if int(_field(second_rebuild, "entity_count", -1)) != entity_count:
        raise SaturationError("projection rebuild entity count differs from initial build")
    entity_type_counts = _projection_entity_type_counts(workspace)
    if entity_type_counts != expected_entity_type_counts:
        raise SaturationError(
            "projection entity type counts differ from exact fixture contour: "
            f"observed={entity_type_counts!r} expected={expected_entity_type_counts!r}"
        )
    if sum(entity_type_counts.values()) != entity_count:
        raise SaturationError("projection entity type counts do not sum to entity_count")
    database_bytes = _projection_database_bytes(workspace)
    reported_database_bytes = int(_field(second_rebuild, "projection_db_bytes", -1))
    if reported_database_bytes != database_bytes:
        raise SaturationError("projection-reported database bytes differ from the durable SQLite file")
    inventory_integrity = _projection_inventory_integrity(workspace, files)
    projection_amplification = database_bytes / inventory_stream_bytes
    reported_projection_amplification = float(
        _field(first_rebuild, "inventory_projection_amplification", -1.0)
    )
    if (
        int(_field(first_rebuild, "inventory_stream_bytes", -1)) != inventory_stream_bytes
        or reported_projection_amplification < 0.0
        or not math.isclose(
            reported_projection_amplification,
            projection_amplification,
            rel_tol=1e-9,
            abs_tol=1e-9,
        )
    ):
        raise SaturationError("projection omitted verified inventory storage amplification metrics")
    inventory_pipeline_peak_rss_bytes = max(
        inventory_rss["peak_bytes"],
        rebuild_rss["peak_bytes"],
    )
    inventory_pipeline_incremental_peak_bytes = max(
        inventory_rss["incremental_peak_bytes"],
        rebuild_rss["incremental_peak_bytes"],
    )
    inventory_absolute_rss_amplification = (
        inventory_pipeline_peak_rss_bytes / inventory_stream_bytes
    )
    inventory_incremental_memory_amplification = (
        inventory_pipeline_incremental_peak_bytes / inventory_stream_bytes
    )
    memory_amplification_within_threshold = (
        inventory_incremental_memory_amplification <= 32.0
    )
    semantic_inflation = (entity_count + relation_count) / files
    release_after = _release_signal(runtime)
    if (
        release_after["current_release_eligible"] is not False
        or release_after["historical_release_decision_id"]
        != release_before["historical_release_decision_id"]
    ):
        raise SaturationError("inventory/rebuild improperly changed release eligibility/history")
    _measure_storage_phase("projection")

    query_grant = semantic_corpus.get("query_grant")
    query_ids = semantic_corpus.get("query_ids")
    continuation_query_ids = semantic_corpus.get("continuation_query_ids")
    if (
        not isinstance(query_grant, Mapping)
        or query_grant.get("capability_id") != "projection.read"
        or not isinstance(query_ids, list)
        or len(query_ids) < 3
        or not all(isinstance(query_id, str) for query_id in query_ids)
        or not isinstance(continuation_query_ids, list)
        or len(continuation_query_ids) < 2
        or not all(isinstance(query_id, str) for query_id in continuation_query_ids)
        or len(set(continuation_query_ids)) != len(continuation_query_ids)
        or not set(continuation_query_ids).issubset(query_ids)
    ):
        raise SaturationError("explicit semantic corpus omitted its projection.read query binding")
    ceiling = _load_ceiling()
    query_latencies_ms: list[float] = []
    result_digests: list[str] = []
    explicit_truncations = 0
    continuations_checked = 0
    forced_chains = min(queries, max(12, queries // 50))
    forced_union_matches = 0
    forced_depths: set[int] = set()
    total_search_calls = 0
    total_pages = 0
    maximum_continuation_token_bytes = 0
    selected_closure_chains = 0
    query_mix_counts: dict[str, int] = {}
    query_class_latencies_ms: dict[str, list[float]] = {}
    query_depth_counts: dict[int, int] = {}
    query_class_depths: dict[str, set[int]] = {}
    broad_checks: list[bool] = []
    high_cardinality_checks: list[bool] = []
    content_checks: list[bool] = []
    miss_checks: list[bool] = []
    hostile_content_checks: list[bool] = []
    hostile_exact_checks: list[bool] = []
    exact_artifact_checks: list[bool] = []
    query_budget = _mixed_query_budget(ceiling)
    forced_budget = {
        "max_bytes": ceiling["max_bytes"],
        "max_entities": 1,
        "max_relations": 1,
        "max_fanout_per_entity": 1,
        "top_k": 1,
    }
    continuation_observer = _ContinuationStateObserver(workspace)
    query_results: list[dict[str, Any]] = []
    search_started = time.perf_counter()
    for index in range(queries):
        query_class, query = _mixed_query_case(
            index,
            forced_chains=forced_chains,
            artifact_ids=artifact_ids,
            semantic_query_ids=query_ids,
            continuation_query_ids=continuation_query_ids,
        )
        depth = _mixed_query_depth(index, query_class)
        query_mix_counts[query_class] = query_mix_counts.get(query_class, 0) + 1
        query_depth_counts[depth] = query_depth_counts.get(depth, 0) + 1
        query_class_depths.setdefault(query_class, set()).add(depth)
        started = time.perf_counter()
        card = runtime.search(
            query,
            depth,
            budget=query_budget,
            subject_id=query_grant["subject_id"],
            grant_id=query_grant["grant_id"],
            ttl_seconds=_SATURATION_CONTINUATION_TTL_SECONDS,
        )
        total_search_calls += 1
        elapsed_query_ms = (time.perf_counter() - started) * 1000.0
        query_latencies_ms.append(elapsed_query_ms)
        query_class_latencies_ms.setdefault(query_class, []).append(elapsed_query_ms)
        card_value = _plain(card)
        class_result_verified = True
        if query_class == "broad":
            class_result_verified = (
                isinstance(card_value, Mapping)
                and card_value.get("refinement_required") is True
                and isinstance(card_value.get("refinement_hints"), list)
                and 0 < len(card_value["refinement_hints"]) <= 4
                and card_value.get("unselected_matches_traversable") is False
            )
            broad_checks.append(class_result_verified)
        elif query_class == "content-high-cardinality":
            class_result_verified = (
                isinstance(card_value, Mapping)
                and card_value.get("refinement_required") is True
                and isinstance(card_value.get("selected_seed_count"), int)
                and 0 < card_value["selected_seed_count"] <= ceiling["top_k"]
                and card_value.get("unselected_matches_traversable") is False
                and _contains_inventory_artifact(card)
            )
            high_cardinality_checks.append(class_result_verified)
        elif query_class == "content-probe":
            class_result_verified = _contains_inventory_artifact(card)
            content_checks.append(class_result_verified)
        elif query_class == "miss":
            class_result_verified = _is_empty_miss(card)
            miss_checks.append(class_result_verified)
        elif query_class == "hostile-content":
            class_result_verified = _contains_inventory_artifact(card)
            hostile_content_checks.append(class_result_verified)
        elif query_class == "hostile-exact":
            class_result_verified = _first_entity_id(card) == f"{_CORPUS_PREFIX}needle"
            hostile_exact_checks.append(class_result_verified)
        elif query_class == "exact-artifact":
            class_result_verified = _first_entity_id(card) == query
            exact_artifact_checks.append(class_result_verified)
        reference = _drain_pages(
            runtime,
            card,
            ceiling,
            query_grant=query_grant,
            ttl_seconds=_SATURATION_CONTINUATION_TTL_SECONDS,
            continuation_observer=continuation_observer,
        )
        if reference["selected_closure_complete"]:
            selected_closure_chains += 1
        maximum_continuation_token_bytes = max(
            maximum_continuation_token_bytes,
            reference["maximum_token_bytes"],
        )
        total_pages += reference["pages"]
        continuations_checked += reference["continuation_pages"]
        if reference["first_truncated"]:
            explicit_truncations += 1
        result_digests.extend(reference["page_digests"])
        forced_trace: dict[str, Any] | None = None
        if index < forced_chains:
            forced_depths.add(depth)
            forced_first = runtime.search(
                query,
                depth,
                budget=forced_budget,
                subject_id=query_grant["subject_id"],
                grant_id=query_grant["grant_id"],
                ttl_seconds=_SATURATION_CONTINUATION_TTL_SECONDS,
            )
            total_search_calls += 1
            forced = _drain_pages(
                runtime,
                forced_first,
                forced_budget,
                query_grant=query_grant,
                ttl_seconds=_SATURATION_CONTINUATION_TTL_SECONDS,
                continuation_observer=continuation_observer,
            )
            if forced["selected_closure_complete"]:
                selected_closure_chains += 1
            maximum_continuation_token_bytes = max(
                maximum_continuation_token_bytes,
                forced["maximum_token_bytes"],
            )
            total_pages += forced["pages"]
            continuations_checked += forced["continuation_pages"]
            if not forced["first_truncated"] or forced["continuation_pages"] < 1:
                raise SaturationError("forced bounded query did not exercise continuation v2")
            explicit_truncations += 1
            if forced["atoms"] != reference["atoms"]:
                missing = sorted(reference["atoms"] - forced["atoms"])
                extra = sorted(forced["atoms"] - reference["atoms"])
                raise SaturationError(
                    f"continuation page union differs from reference closure: "
                    f"missing={missing[:5]} extra={extra[:5]}"
                )
            forced_union_matches += 1
            result_digests.extend(forced["page_digests"])
            forced_trace = _raw_page_trace(forced)
            forced_trace["union_matches_reference"] = True
        query_results.append(
            {
                "record_type": "SaturationQueryObservation",
                "index": index,
                "query_class": query_class,
                "query": query,
                "depth": depth,
                "elapsed_ms": round(elapsed_query_ms, 6),
                "first_page": dict(card_value),
                "first_page_digest": _digest(card_value),
                "class_result_verified": class_result_verified,
                "reference": _raw_page_trace(reference),
                "forced": forced_trace,
            }
        )
    search_seconds = time.perf_counter() - search_started
    broad_query_refinement_required = bool(broad_checks) and all(broad_checks)
    high_cardinality_terms_verified = bool(high_cardinality_checks) and all(
        high_cardinality_checks
    )
    content_search_verified = bool(content_checks) and all(content_checks)
    miss_behavior_verified = bool(miss_checks) and all(miss_checks)
    hostile_proxy_content_verified = (
        bool(hostile_content_checks)
        and all(hostile_content_checks)
        and bool(hostile_exact_checks)
        and all(hostile_exact_checks)
    )
    exact_artifact_search_verified = bool(exact_artifact_checks) and all(
        exact_artifact_checks
    )
    required_query_classes = {
        "exact-artifact",
        "content-high-cardinality",
        "content-probe",
        "miss",
        "hostile-content",
        "hostile-exact",
        "broad",
        "exact-semantic",
    }
    mixed_query_classes_complete = all(
        query_mix_counts.get(name, 0) >= max(1, queries // 12)
        for name in required_query_classes
    )
    if forced_union_matches != forced_chains or forced_depths != set(range(1, 13)):
        raise SaturationError("forced continuation did not cover every depth 1-12")
    if explicit_truncations < forced_chains or continuations_checked < forced_chains:
        raise SaturationError("bounded queries did not prove explicit truncation and continuation")
    if set(query_depth_counts) != set(range(1, 13)):
        raise SaturationError("mixed runtime queries did not cover every depth 1-12")
    continuation_state = continuation_observer.metrics()
    continuation_rows = continuation_observer.manifest_rows()
    if continuation_state["files"] < 1:
        raise SaturationError(
            "physical saturation did not observe transient SQLite continuation state"
        )
    if not _continuation_state_within_limit(continuation_state):
        raise SaturationError(
            "physical saturation continuation state exceeded its verified byte ceiling"
        )
    final_artifact_binding = build_artifact_binding(PACKAGE_ROOT, archive)
    if final_artifact_binding["binding_digest"] != artifact_binding["binding_digest"]:
        raise SaturationError("exact package/archive identity changed during saturation")
    _measure_storage_phase("runtime-queries")

    p50_ms = _percentile(query_latencies_ms, 0.50)
    p95_ms = _percentile(query_latencies_ms, 0.95)
    p99_ms = _percentile(query_latencies_ms, 0.99)
    peak_rss_bytes = _peak_rss_bytes()
    commit_latencies_ms = [
        float(value["duration_ms"]) for value in semantic_commit_observations
    ]
    commit_changed_records = sum(
        int(value["changed_records"]) for value in semantic_commit_observations
    )
    commit_payload_bytes = sum(
        int(value["physical_payload_bytes"])
        for value in semantic_commit_observations
    )
    if commit_changed_records < 1:
        raise SaturationError("semantic ingestion did not change any projected records")
    commit_bytes_per_changed_record = commit_payload_bytes / commit_changed_records
    runtime_checkpoint_count = max(
        int(value["checkpoint_count"]) for value in semantic_commit_observations
    )
    runtime_checkpoint_writes = sum(
        value["checkpoint_written"] is True
        for value in semantic_commit_observations
    )
    commit_p95_ms = _percentile(commit_latencies_ms, 0.95)
    commit_p99_ms = _percentile(commit_latencies_ms, 0.99)
    expected_semantic_commit_count = (
        len(_CORPUS_GRANT_IDS) + 1 + semantic_corpus["task_count"]
    )
    performance = _performance_result(
        performance_contract,
        p50_ms=p50_ms,
        p95_ms=p95_ms,
        p99_ms=p99_ms,
        peak_rss_bytes=peak_rss_bytes,
        database_bytes=database_bytes,
        projection_amplification=projection_amplification,
        semantic_inflation=semantic_inflation,
        commit_p95_ms=commit_p95_ms,
        commit_p99_ms=commit_p99_ms,
        commit_bytes_per_changed_record=commit_bytes_per_changed_record,
        runtime_checkpoint_count=runtime_checkpoint_count,
        runtime_checkpoint_writes=runtime_checkpoint_writes,
        semantic_ingestion_seconds=semantic_ingestion_seconds,
    )
    contract_predicates = {
        "raw_file_proxy_ratio_exact": raw_file_proxy_ratio == 1.0,
        "synthetic_task_ratio_zero": synthetic_task_ratio == 0.0,
        "core_valid_relations_exact": relation_count
        == _EXACT_CORE_VALID_RELATIONS,
        "physical_relation_artifact_coverage_complete": physical_relation_corpus[
            "artifact_target_coverage"
        ]
        == 1.0,
        "inventory_passes_exact": int(_field(first_rebuild, "inventory_passes", -1)) == 1,
        "rebuild_product_passes_zero": int(_field(second_rebuild, "product_passes", -1)) == 0,
        "rebuild_digest_equal": _field(second_rebuild, "semantic_digest") == semantic_digest,
        "runtime_queries_exact": len(query_latencies_ms)
        == _EXACT_RUNTIME_QUERIES,
        "runtime_depths_1_through_12": set(query_depth_counts) == set(range(1, 13)),
        "runtime_query_budget_bounded": (
            query_budget["max_bytes"] == ceiling["max_bytes"]
            and query_budget["max_entities"] <= ceiling["max_entities"]
            and query_budget["max_relations"] <= ceiling["max_relations"]
            and query_budget["max_fanout_per_entity"]
            <= ceiling["max_fanout_per_entity"]
            and query_budget["top_k"] == 1
        ),
        "continuation_union_complete": forced_union_matches == forced_chains,
        "selected_closure_union_complete": selected_closure_chains
        == queries + forced_chains,
        "inventory_incremental_memory_amplification_at_most_32": (
            memory_amplification_within_threshold
        ),
        "broad_query_refinement_required": broad_query_refinement_required,
        "high_cardinality_terms_verified": high_cardinality_terms_verified,
        "content_search_verified": content_search_verified,
        "miss_behavior_verified": miss_behavior_verified,
        "hostile_proxy_content_verified": hostile_proxy_content_verified,
        "exact_artifact_search_verified": exact_artifact_search_verified,
        "mixed_query_classes_complete": mixed_query_classes_complete,
        "semantic_commit_count_exact": len(semantic_commit_observations)
        == expected_semantic_commit_count,
        "silent_truncations_zero": True,
        "continuation_token_bytes_at_most_256": maximum_continuation_token_bytes <= 256,
        "continuation_state_bytes_at_most_16384": _continuation_state_within_limit(
            continuation_state
        ),
        "continuation_token_overhead_at_most_10_percent": (
            maximum_continuation_token_bytes * 10 <= ceiling["max_bytes"]
        ),
        "exact_artifact_binding_unchanged": True,
    }
    status = (
        "pass"
        if all(contract_predicates.values()) and performance["all_within_profile"]
        else "fail"
    )
    storage_telemetry = _ACTIVE_STORAGE_TELEMETRY.get()
    if storage_telemetry is None:
        raise StorageBudgetError(
            "storage telemetry is unavailable before evidence publication",
            failure_code="storage-telemetry-unavailable",
        )
    storage_telemetry.stop_for_publication()
    evidence = {
        "record_type": "SaturationEvidence",
        "status": status,
        "candidate_binding_digest": artifact_binding["candidate_binding_digest"],
        "physical_files": files,
        "core_valid_relations": relation_count,
        "core_valid_relations_exact_198999": relation_count
        == _EXACT_CORE_VALID_RELATIONS,
        "runtime_queries": queries,
        "silent_truncations": 0,
        "selected_closure_union_completeness": (
            selected_closure_chains / (queries + forced_chains)
            if queries + forced_chains
            else 0.0
        ),
        "memory_amplification_at_most_32": memory_amplification_within_threshold,
        "broad_query_refinement_required": broad_query_refinement_required,
        "high_cardinality_terms_verified": high_cardinality_terms_verified,
        "content_search_verified": content_search_verified,
        "miss_behavior_verified": miss_behavior_verified,
        "hostile_proxy_content_verified": hostile_proxy_content_verified,
        "exact_artifact_search_verified": exact_artifact_search_verified,
        "mixed_query_classes_complete": mixed_query_classes_complete,
        "continuation_token_bytes_at_most_256": maximum_continuation_token_bytes <= 256,
        "continuation_state_bytes_at_most_16384": _continuation_state_within_limit(
            continuation_state
        ),
        "continuation_token_overhead_at_most_10_percent": (
            maximum_continuation_token_bytes * 10 <= ceiling["max_bytes"]
        ),
        "pass_credit": False,
        "artifact_binding": artifact_binding,
        "artifact_binding_unchanged": True,
        "runtime_binding": {
            "activation_digest": _field(first_rebuild, "activation_digest"),
            "implementation_closure_digest": implementation_closure_digest,
            "platform_binding_digest": artifact_binding["platform"]["binding_digest"],
        },
        "workspace_initialization": workspace_initialization,
        "physical": {
            "files": files,
            "raw_files": files,
            "semantic_proxies": proxy_count,
            "raw_file_proxies": proxy_count,
            "raw_file_proxy_ratio": raw_file_proxy_ratio,
            "synthetic_tasks": synthetic_task_count,
            "synthetic_task_count": synthetic_task_count,
            "synthetic_task_ratio": synthetic_task_ratio,
            "inventory_relations": inventory_relation_count,
            "relations": relation_count,
            "explicit_semantic_corpus": {
                key: semantic_corpus[key]
                for key in (
                    "record_type",
                    "generation",
                    "harness_generated",
                    "product_acceptance_credit",
                    "task_count",
                    "relation_count",
                    "depths",
                    "high_fanout",
                    "conflicting_exact_id_text",
                    "query_ids",
                    "continuation_query_ids",
                    "reused",
                    "search_fixture",
                    "physical_relation_fixture",
                    "search_fixture_reused",
                    "physical_relation_fixture_reused",
                )
            },
            "generation_elapsed_ms": None if generation_seconds is None else round(generation_seconds * 1000),
            "reused_product": reuse_product,
            "vcs_commit": snapshot_descriptor["commit_digest"],
            "vcs_tree_digest": snapshot_descriptor["tree_digest"],
            "vcs_tree_files": int(snapshot_descriptor["tree_file_count"]),
            "vcs_provider_version": snapshot_descriptor["provider_version"],
        },
        "inventory": {
            "passes": 1,
            "entries": entry_count,
            "stream_bytes": inventory_stream_bytes,
            "elapsed_ms": round(inventory_seconds * 1000),
            "candidate_digest": candidate_digest,
            "snapshot": snapshot_signal,
        },
        "projection": {
            "initial_inventory_passes": int(_field(first_rebuild, "inventory_passes", -1)),
            "initial_product_passes": 0,
            "rebuild_inventory_passes": int(
                _field(second_rebuild, "inventory_passes", -1)
            ),
            "rebuild_product_passes": 0,
            "equal_semantic_digest": True,
            "semantic_digest": semantic_digest,
            "implementation_closure_digest": implementation_closure_digest,
            "entity_count": entity_count,
            "entity_type_counts": entity_type_counts,
            "relation_count": relation_count,
            "database_bytes": database_bytes,
            "projection_amplification": round(projection_amplification, 9),
            "inventory_projection_amplification": round(
                reported_projection_amplification,
                9,
            ),
            "semantic_inflation": round(semantic_inflation, 9),
            "inventory_integrity": inventory_integrity,
            "elapsed_ms": round(rebuild_seconds * 1000),
        },
        "query_authorization": dict(query_grant),
        "search": {
            "runtime_ingress": "promin.service.ProminService",
            "actual_runtime_queries": queries,
            "promin_service_search_calls": total_search_calls,
            "promin_service_continuation_calls": continuations_checked,
            "pages_observed": total_pages,
            "depth_min": min(query_depth_counts),
            "depth_max": max(query_depth_counts),
            "depth_counts": {
                str(depth): count for depth, count in sorted(query_depth_counts.items())
            },
            "query_class_depths": {
                query_class: sorted(depths)
                for query_class, depths in sorted(query_class_depths.items())
            },
            "runtime_query_budget": query_budget,
            "forced_query_budget": forced_budget,
            "forced_continuation_chains": forced_chains,
            "forced_union_matches": forced_union_matches,
            "continuation_union_complete": forced_union_matches == forced_chains,
            "continuation_union_completeness": (
                forced_union_matches / forced_chains if forced_chains else 0.0
            ),
            "forced_depths": sorted(forced_depths),
            "explicit_truncations": explicit_truncations,
            "continuations_checked": continuations_checked,
            "silent_truncations": 0,
            "maximum_continuation_token_bytes": maximum_continuation_token_bytes,
            "continuation_state": continuation_state,
            "continuation_token_overhead_at_most_10_percent": (
                maximum_continuation_token_bytes * 10 <= ceiling["max_bytes"]
            ),
            "selected_closure_chains": selected_closure_chains,
            "selected_closure_union_completeness": (
                selected_closure_chains / (queries + forced_chains)
                if queries + forced_chains
                else 0.0
            ),
            "broad_query_refinement_required": broad_query_refinement_required,
            "high_cardinality_terms_verified": high_cardinality_terms_verified,
            "content_search_verified": content_search_verified,
            "miss_behavior_verified": miss_behavior_verified,
            "hostile_proxy_content_verified": hostile_proxy_content_verified,
            "exact_artifact_search_verified": exact_artifact_search_verified,
            "mixed_query_classes_complete": mixed_query_classes_complete,
            "query_mix": dict(sorted(query_mix_counts.items())),
            "query_class_latency_ms": {
                query_class: {
                    "count": len(latencies),
                    "p50": round(_percentile(latencies, 0.50), 6),
                    "p95": round(_percentile(latencies, 0.95), 6),
                    "p99": round(_percentile(latencies, 0.99), 6),
                }
                for query_class, latencies in sorted(query_class_latencies_ms.items())
            },
            "p50_ms": round(p50_ms, 6),
            "p95_ms": round(p95_ms, 6),
            "p99_ms": round(p99_ms, 6),
            "result_digest": _digest(result_digests),
        },
        "resources": {
            "peak_rss_bytes": peak_rss_bytes,
            "inventory_stage_rss": inventory_rss,
            "projection_stage_rss": rebuild_rss,
            "inventory_pipeline_peak_rss_bytes": inventory_pipeline_peak_rss_bytes,
            "inventory_pipeline_incremental_peak_bytes": (
                inventory_pipeline_incremental_peak_bytes
            ),
            "inventory_absolute_rss_amplification": round(
                inventory_absolute_rss_amplification,
                9,
            ),
            "inventory_incremental_memory_amplification": round(
                inventory_incremental_memory_amplification,
                9,
            ),
            "memory_amplification_metric": {
                "metric_id": "inventory-incremental-peak-over-stream-bytes",
                "numerator": "inventory_pipeline_incremental_peak_bytes",
                "denominator": "inventory_stream_bytes",
                "numerator_bytes": inventory_pipeline_incremental_peak_bytes,
                "denominator_bytes": inventory_stream_bytes,
                "ratio": round(inventory_incremental_memory_amplification, 9),
                "threshold_max": 32.0,
                "within_threshold": memory_amplification_within_threshold,
            },
        },
        "performance": performance,
        "contract_predicates": contract_predicates,
        "current_release_regression": {
            "before": release_before,
            "after": release_after,
            "eligibility_remained_false": True,
            "historical_decision_preserved": True,
        },
        "claim_scope": (
            "exact-ZIP physical runtime saturation and harness-generated semantic corpus; "
            "product acceptance remains false"
        ),
        "acceptance_pass": False,
        "product_acceptance_pass": False,
        "public_release_approved": False,
        "producer": release_evidence_producer(
            PACKAGE_ROOT,
            "tools/promin_saturation.py",
            version=artifact_binding["standard_candidate_binding"]["version"],
        ),
        "invocation": release_evidence_invocation(
            invocation_id=f"saturation:{uuid.uuid4().hex}",
            operation="physical-saturation",
            arguments={
                "archive_sha256": artifact_binding["archive"]["sha256"],
                "files": files,
                "performance_profile": performance_profile,
                "queries": queries,
                "reuse_product": reuse_product,
                "workspace_recipe": _PHYSICAL_CORPUS_RECIPE,
            },
            started_at=started_at,
            completed_at=datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            exit_code=0 if status == "pass" else 1,
            platform_binding=artifact_binding["platform"]["binding_digest"][7:],
        ),
    }
    inventory_stream_path = _field(inventory, "stream_path")
    inventory_stream_digest = _field(inventory, "stream_digest")
    if (
        not isinstance(inventory_stream_path, Path)
        or not inventory_stream_path.is_file()
        or not isinstance(inventory_stream_digest, str)
    ):
        raise SaturationError("verified inventory stream is unavailable for raw evidence")
    inventory_stream_payload = _read_stable_file(inventory_stream_path)
    if _sha256_bytes(inventory_stream_payload) != inventory_stream_digest:
        raise SaturationError("verified inventory stream changed before raw evidence publication")
    _write_bytes(output / "raw" / "inventory-stream.jsonl", inventory_stream_payload)
    _write_jsonl(output / "raw" / "query-results.jsonl", query_results)
    process_samples = {
        "record_type": "SaturationProcessSamples",
        "sample_interval_ms": 50,
        "lifetime_peak_rss_bytes": peak_rss_bytes,
        "phases": [
            {
                "phase": "inventory",
                "summary": inventory_rss,
                "samples": inventory_rss_samples,
            },
            {
                "phase": "projection",
                "summary": rebuild_rss,
                "samples": rebuild_rss_samples,
            },
        ],
    }
    _write_json(output / "raw" / "process-samples.json", process_samples)
    _write_jsonl(
        output / "raw" / "continuation-state-manifest.jsonl",
        continuation_rows,
    )
    phase_log = [
        {
            "order": 1,
            "phase": "physical-generation",
            "status": "reused" if generation_seconds is None else "completed",
            "elapsed_ms": None
            if generation_seconds is None
            else round(generation_seconds * 1000),
            "storage": storage_telemetry.bound_phase_payload("physical-generation"),
        },
        {
            "order": 2,
            "phase": "inventory",
            "status": "completed",
            "elapsed_ms": round(inventory_seconds * 1000),
            "storage": storage_telemetry.bound_phase_payload("inventory"),
        },
        {
            "order": 3,
            "phase": "semantic-ingestion",
            "status": "completed",
            "elapsed_ms": round(semantic_ingestion_seconds * 1000),
            "storage": storage_telemetry.bound_phase_payload("semantic-ingestion"),
        },
        {
            "order": 4,
            "phase": "projection",
            "status": "completed",
            "elapsed_ms": round(rebuild_seconds * 1000),
            "storage": storage_telemetry.bound_phase_payload("projection"),
        },
        {
            "order": 5,
            "phase": "runtime-queries",
            "status": "completed",
            "elapsed_ms": round(search_seconds * 1000),
            "storage": storage_telemetry.bound_phase_payload("runtime-queries"),
        },
        {
            "order": 6,
            "phase": "result",
            "status": status,
            "elapsed_ms": 0,
            "process_exit_code": 0 if status == "pass" else 1,
            "invocation_exit_code": evidence["invocation"]["exit_code"],
            "storage": storage_telemetry.bound_phase_payload("result"),
        },
    ]
    _write_jsonl(output / "raw" / "phase-log.jsonl", phase_log)
    operation_metrics = {
        "record_type": "SaturationOperationMetrics",
        "evidence_class": "harness_generated",
        "product_acceptance_credit": False,
        "status": status,
        "process_exit_code": 0 if status == "pass" else 1,
        "invocation_exit_code": evidence["invocation"]["exit_code"],
        "physical": evidence["physical"],
        "inventory": evidence["inventory"],
        "projection": evidence["projection"],
        "search": evidence["search"],
        "resources": evidence["resources"],
        "performance": evidence["performance"],
        "contract_predicates": evidence["contract_predicates"],
        "semantic_ingestion": {
            "record_type": "SemanticIngestionMetrics",
            "elapsed_seconds": round(semantic_ingestion_seconds, 6),
            "commit_count": len(semantic_commit_observations),
            "changed_records": commit_changed_records,
            "physical_payload_bytes": commit_payload_bytes,
            "bytes_per_changed_record": round(
                commit_bytes_per_changed_record, 6
            ),
            "p95_ms": round(commit_p95_ms, 6),
            "p99_ms": round(commit_p99_ms, 6),
            "checkpoint_count": runtime_checkpoint_count,
            "checkpoint_writes": runtime_checkpoint_writes,
            "observations": semantic_commit_observations,
            "result_digest": _digest(semantic_commit_observations),
        },
    }
    _write_json(output / "raw" / "operation-metrics.json", operation_metrics)
    raw_artifacts = [
        _raw_artifact_binding(
            output,
            "raw/inventory-stream.jsonl",
            role="inventory-stream",
            media_type="application/x-ndjson",
            records=entry_count,
        ),
        _raw_artifact_binding(
            output,
            "raw/query-results.jsonl",
            role="query-results",
            media_type="application/x-ndjson",
            records=len(query_results),
        ),
        _raw_artifact_binding(
            output,
            "raw/process-samples.json",
            role="process-samples",
            media_type="application/json",
            records=len(inventory_rss_samples) + len(rebuild_rss_samples),
        ),
        _raw_artifact_binding(
            output,
            "raw/continuation-state-manifest.jsonl",
            role="continuation-state-manifest",
            media_type="application/x-ndjson",
            records=len(continuation_rows),
        ),
        _raw_artifact_binding(
            output,
            "raw/phase-log.jsonl",
            role="phase-log",
            media_type="application/x-ndjson",
            records=len(phase_log),
        ),
        _raw_artifact_binding(
            output,
            "raw/operation-metrics.json",
            role="operation-metrics",
            media_type="application/json",
            records=1,
        ),
    ]
    raw_manifest_identity = {
        "record_type": "SaturationRawArtifactManifest",
        "path_scope": "saturation-result-directory",
        "evidence_class": "harness_generated",
        "product_acceptance_credit": False,
        "artifacts": raw_artifacts,
        "artifact_count": len(raw_artifacts),
        "inventory_stream_digest": inventory_stream_digest,
        "inventory_identity_digest": _field(
            _field(inventory, "candidate", {}),
            "inventory_digest",
        ),
    }
    evidence["raw_artifact_manifest"] = {
        **raw_manifest_identity,
        "manifest_digest": _digest(raw_manifest_identity),
    }
    evidence = seal_release_evidence(evidence)
    return _publish_completed_saturation_result(
        output,
        evidence,
        candidate_binding=artifact_binding["standard_candidate_binding"],
    )


def self_check(performance_profile: str = "portable-local-v1") -> dict[str, Any]:
    contract = _load_performance_contract(performance_profile)
    ceiling = _load_ceiling()
    manifest = _semantic_corpus_manifest("a" * 64, "b" * 64, "2026-01-01T00:00:00Z")
    physical_relations = _physical_relation_manifest(_PHYSICAL_RELATION_COUNT)
    query_plan = [
        (
            query_class,
            _mixed_query_depth(index, query_class),
        )
        for index in range(_EXACT_RUNTIME_QUERIES)
        for query_class, _query in [
            _mixed_query_case(
                index,
                forced_chains=12,
                artifact_ids=["artifact:fixture:000"],
                semantic_query_ids=manifest["query_ids"],
                continuation_query_ids=manifest["continuation_query_ids"],
            )
        ]
    ]
    query_budget = _mixed_query_budget(ceiling)
    expected_entity_type_counts = {
        "Artifact": _EXACT_PHYSICAL_FILES,
        "Candidate": 1,
        "Grant": len(_CORPUS_GRANT_IDS),
        "Task": manifest["task_count"] + physical_relations["task_count"],
    }
    expected_semantic_commit_count = (
        len(_CORPUS_GRANT_IDS)
        + 1
        + manifest["task_count"]
        + physical_relations["task_count"]
    )
    if (
        manifest["task_count"] != _SEARCH_FIXTURE_TASK_COUNT
        or manifest["relation_count"] != _SEARCH_FIXTURE_RELATION_COUNT
        or manifest["continuation_query_ids"]
        != [
            f"{_CORPUS_PREFIX}depth:12",
            f"{_CORPUS_PREFIX}fanout:root",
        ]
        or not set(manifest["continuation_query_ids"]).issubset(manifest["query_ids"])
        or {depth for _query_class, depth in query_plan} != set(range(1, 13))
        or any(
            depth != 1
            for query_class, depth in query_plan
            if query_class in _PHYSICAL_QUERY_DEPTH_ONE_CLASSES
        )
        or query_budget
        != {
            "max_bytes": ceiling["max_bytes"],
            "max_entities": ceiling["max_entities"],
            "max_relations": ceiling["max_relations"],
            "max_fanout_per_entity": ceiling["max_fanout_per_entity"],
            "top_k": 1,
        }
        or physical_relations["task_count"] != 1_567
        or manifest["relation_count"] + physical_relations["relation_count"]
        != _EXACT_CORE_VALID_RELATIONS
        or sum(expected_entity_type_counts.values()) != 101_604
        or expected_semantic_commit_count != 1_604
    ):
        raise SaturationError("executable semantic corpus differs from its canonical counts")
    if _percentile([1.0, 2.0, 3.0, 4.0], 0.95) != 4.0:
        raise SaturationError("nearest-rank percentile implementation is inconsistent")
    return {
        "record_type": "SaturationToolSelfCheck",
        "status": "pass",
        "performance_profile": contract,
        "platform": _platform_binding(),
        "peak_rss_bytes": _peak_rss_bytes(),
        "workcard_ceiling": ceiling,
        "semantic_corpus": {
            key: manifest[key]
            for key in (
                "task_count",
                "relation_count",
                "depths",
                "high_fanout",
                "query_ids",
                "continuation_query_ids",
            )
        },
        "physical_relation_corpus": physical_relations,
        "projection_fixture": {
            "entity_count": sum(expected_entity_type_counts.values()),
            "entity_type_counts": expected_entity_type_counts,
            "semantic_commit_count": expected_semantic_commit_count,
        },
        "mixed_query_plan": {
            "depths": sorted({depth for _query_class, depth in query_plan}),
            "physical_query_depth": 1,
            "physical_query_classes": sorted(_PHYSICAL_QUERY_DEPTH_ONE_CLASSES),
            "runtime_query_budget": query_budget,
        },
        "full_100k_executed": False,
        "acceptance_pass": False,
        "product_acceptance_pass": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the physical Promin 100k runtime saturation route")
    parser.add_argument("workspace", nargs="?", type=Path)
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--archive", type=Path, help="exact promin ZIP under test")
    parser.add_argument("--files", type=int, default=_EXACT_PHYSICAL_FILES)
    parser.add_argument("--queries", type=int, default=_EXACT_RUNTIME_QUERIES)
    parser.add_argument("--reuse-product", action="store_true")
    parser.add_argument("--performance-profile", default="portable-local-v1")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.self_check:
            result = self_check(args.performance_profile)
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.workspace is None or args.output is None or args.archive is None:
            parser.error("workspace, output and --archive are required unless --self-check is used")
        result = run(
            args.workspace,
            args.output,
            archive=args.archive,
            files=args.files,
            queries=args.queries,
            reuse_product=args.reuse_product,
            performance_profile=args.performance_profile,
        )
    except StorageBudgetError as exc:
        print(
            json.dumps(
                {
                    "status": "fail",
                    "failure_code": exc.failure_code,
                    "reason": str(exc),
                    "pass_credit": False,
                    "acceptance_pass": False,
                    "product_acceptance_pass": False,
                    "workload_reduced": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    except (OSError, ValueError, SaturationError) as exc:
        print(json.dumps({"status": "rejected", "reason": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
