"""Bounded local telemetry and heartbeat for promin alpha.

Telemetry is observational only.  It never grants authority or pass credit, and
it deliberately stores aggregate fingerprints instead of one graph node per
repeated event.  The default store is local, ignored by Git, bounded, and
redacts common secret-bearing fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any, Mapping

_MAX_FINGERPRINTS = 512
_MAX_DETAIL_ITEMS = 32
_MAX_LIST_ITEMS = 16
_MAX_STRING = 512
_MAX_DEPTH = 4
_LOCK_WAIT_SECONDS = 0.05
_LOCK_STALE_SECONDS = 30.0
_SECRET_KEYS = {
    "authorization",
    "cookie",
    "credentials",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "session",
    "token",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class OperationTimer:
    """Small monotonic timer used by non-authoritative operation metrics."""

    _started: float = field(default_factory=time.perf_counter)

    @property
    def duration_ms(self) -> float:
        return round((time.perf_counter() - self._started) * 1000.0, 6)


def _sanitize(value: Any, *, key: str | None = None, depth: int = 0) -> Any:
    if key is not None and key.casefold() in _SECRET_KEYS:
        return "[REDACTED]"
    if depth >= _MAX_DEPTH:
        return "[TRUNCATED]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        text = value.replace("\x00", "")
        return text if len(text) <= _MAX_STRING else text[:_MAX_STRING] + "…"
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for index, (raw_key, raw_value) in enumerate(sorted(value.items(), key=lambda item: str(item[0]))):
            if index >= _MAX_DETAIL_ITEMS:
                result["_truncated"] = True
                break
            name = str(raw_key)[:128]
            result[name] = _sanitize(raw_value, key=name, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        result = [_sanitize(item, depth=depth + 1) for item in items[:_MAX_LIST_ITEMS]]
        if len(items) > _MAX_LIST_ITEMS:
            result.append("[TRUNCATED]")
        return result
    return _sanitize(str(value), depth=depth + 1)


def _store_path(root: Path) -> Path:
    return root / ".promin" / "state" / "observations" / "aggregates.json"


def _lock_path(root: Path) -> Path:
    return root / ".promin" / "state" / "observations" / ".lock"


def _acquire_lock(path: Path) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + _LOCK_WAIT_SECONDS
    while True:
        try:
            path.mkdir()
            (path / "owner").write_text(f"{os.getpid()}\n{time.time()}\n", encoding="utf-8")
            return True
        except FileExistsError:
            try:
                age = time.time() - path.stat().st_mtime
                if age > _LOCK_STALE_SECONDS:
                    for child in path.iterdir():
                        if child.is_file():
                            child.unlink(missing_ok=True)
                    path.rmdir()
                    continue
            except OSError:
                pass
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.005)


def _release_lock(path: Path) -> None:
    try:
        for child in path.iterdir():
            if child.is_file():
                child.unlink(missing_ok=True)
        path.rmdir()
    except OSError:
        pass


def _load_store(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {
            "record_type": "ProminTelemetryAggregates",
            "schema_version": 1,
            "observation_count": 0,
            "dropped_observation_count": 0,
            "fingerprints": {},
            "authority": False,
            "pass_credit": False,
        }
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "record_type": "ProminTelemetryAggregates",
            "schema_version": 1,
            "observation_count": 0,
            "dropped_observation_count": 1,
            "fingerprints": {},
            "authority": False,
            "pass_credit": False,
        }
    if not isinstance(value, dict) or not isinstance(value.get("fingerprints"), dict):
        return {
            "record_type": "ProminTelemetryAggregates",
            "schema_version": 1,
            "observation_count": 0,
            "dropped_observation_count": 1,
            "fingerprints": {},
            "authority": False,
            "pass_credit": False,
        }
    return value


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def _fingerprint(kind: str, status: str, details: Mapping[str, Any]) -> str:
    identity = {
        "kind": kind,
        "status": status,
        "component": details.get("component"),
        "reason": details.get("reason"),
        "policy": details.get("policy"),
        "route": details.get("route"),
    }
    raw = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def record_observation(
    project_root: Path | str,
    *,
    kind: str,
    status: str,
    duration_ms: float | int | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Aggregate one local observation.

    Failure to acquire the best-effort telemetry lock never affects the calling
    authoritative operation.
    """

    root = Path(project_root).resolve()
    safe_details = _sanitize(dict(details or {}))
    if not isinstance(safe_details, dict):
        safe_details = {}
    now = utc_now()
    fingerprint = _fingerprint(str(kind), str(status), safe_details)
    lock = _lock_path(root)
    if not _acquire_lock(lock):
        return {
            "record_type": "ProminObservationReceipt",
            "status": "dropped-lock-busy",
            "fingerprint": fingerprint,
            "authority": False,
            "pass_credit": False,
        }
    try:
        path = _store_path(root)
        store = _load_store(path)
        fingerprints = store.setdefault("fingerprints", {})
        current = fingerprints.get(fingerprint)
        measured = float(duration_ms) if duration_ms is not None else None
        if not isinstance(current, dict):
            current = {
                "fingerprint": fingerprint,
                "kind": str(kind)[:128],
                "status": str(status)[:64],
                "first_seen": now,
                "last_seen": now,
                "occurrence_count": 0,
                "duration_total_ms": 0.0,
                "duration_max_ms": 0.0,
                "details": safe_details,
            }
        current["last_seen"] = now
        current["occurrence_count"] = int(current.get("occurrence_count", 0)) + 1
        if measured is not None and measured >= 0:
            current["duration_total_ms"] = round(float(current.get("duration_total_ms", 0.0)) + measured, 6)
            current["duration_max_ms"] = round(max(float(current.get("duration_max_ms", 0.0)), measured), 6)
        current["details"] = safe_details
        fingerprints[fingerprint] = current
        store["observation_count"] = int(store.get("observation_count", 0)) + 1
        store["updated_at"] = now
        store["authority"] = False
        store["pass_credit"] = False
        if len(fingerprints) > _MAX_FINGERPRINTS:
            ordered = sorted(
                fingerprints.items(),
                key=lambda item: (str(item[1].get("last_seen", "")), item[0]),
            )
            remove_count = len(fingerprints) - _MAX_FINGERPRINTS
            for old_key, _ in ordered[:remove_count]:
                fingerprints.pop(old_key, None)
            store["dropped_observation_count"] = int(store.get("dropped_observation_count", 0)) + remove_count
        _atomic_json(path, store)
        return {
            "record_type": "ProminObservationReceipt",
            "status": "aggregated",
            "fingerprint": fingerprint,
            "occurrence_count": current["occurrence_count"],
            "authority": False,
            "pass_credit": False,
        }
    except Exception:
        return {
            "record_type": "ProminObservationReceipt",
            "status": "dropped-write-failed",
            "fingerprint": fingerprint,
            "authority": False,
            "pass_credit": False,
        }
    finally:
        _release_lock(lock)


def heartbeat(project_root: Path | str) -> dict[str, Any]:
    root = Path(project_root).resolve()
    store = _load_store(_store_path(root))
    fingerprints = store.get("fingerprints", {}) if isinstance(store.get("fingerprints"), dict) else {}
    active = [
        item for item in fingerprints.values()
        if isinstance(item, dict) and item.get("status") in {"failed", "blocked", "error", "degraded"}
    ]
    bootstrap_path = root / ".promin" / "generated" / "bootstrap-state.json"
    task_id = None
    if bootstrap_path.is_file():
        try:
            bootstrap = json.loads(bootstrap_path.read_text(encoding="utf-8"))
            if isinstance(bootstrap, dict):
                task_id = bootstrap.get("task_id")
        except (OSError, json.JSONDecodeError):
            pass
    initialized = (root / ".promin" / "init" / "activation.json").is_file()
    human_required = any(
        isinstance(item.get("details"), dict)
        and item["details"].get("human_decision_required") is True
        for item in active
    )
    return {
        "record_type": "ProminHeartbeat",
        "status": "degraded" if active else "ready" if initialized else "not-initialized",
        "initialized": initialized,
        "current_task_id": task_id,
        "observation_count": int(store.get("observation_count", 0)),
        "active_fingerprints": len(active),
        "top_active": [
            {
                "fingerprint": item.get("fingerprint"),
                "kind": item.get("kind"),
                "status": item.get("status"),
                "occurrence_count": item.get("occurrence_count"),
                "last_seen": item.get("last_seen"),
            }
            for item in sorted(
                active,
                key=lambda value: (-int(value.get("occurrence_count", 0)), str(value.get("fingerprint", ""))),
            )[:8]
        ],
        "human_decision_required": human_required,
        "authority": False,
        "pass_credit": False,
        "product_acceptance_pass": False,
    }
