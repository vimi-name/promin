"""Provider-neutral local context projection with an SQLite/FTS5 default.

The Python API is the stable boundary. SQLite is a rebuildable implementation,
not normative state; a deterministic JSONL fallback is used when FTS5 is not
available. Only bounded documentation/reference content is indexed here. Source
code semantics continue to belong to the main Promin inventory/projection.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .canonical import digest_value
from .gitpolicy import estimate_tokens
from .platform_paths import filesystem_path, sqlite_path

_DB_PATH = Path(".promin/state/projection/context.sqlite3")
_JSONL_PATH = Path(".promin/state/projection/context.jsonl")
_STATE_PATH = Path(".promin/state/projection/context-index.json")
_MAX_RECORD_BYTES = 64 * 1024
_MAX_INDEX_BYTES = 32 * 1024 * 1024
_DEFAULT_RESULT_BYTES = 8 * 1024
_DEFAULT_LIMIT = 12
_TOKEN_RE = re.compile(r"[\w./:@+-]+", flags=re.UNICODE)


class ContextIndexError(RuntimeError):
    pass


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _atomic_bytes(path: Path, payload: bytes) -> None:
    os.makedirs(filesystem_path(path.parent), exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with open(filesystem_path(temporary), "xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(filesystem_path(temporary), filesystem_path(path))


def _load_json(path: Path) -> dict[str, Any] | None:
    if not os.path.isfile(filesystem_path(path)) or os.path.islink(filesystem_path(path)):
        return None
    try:
        with open(filesystem_path(path), encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _sqlite_fts5_available() -> bool:
    try:
        connection = sqlite3.connect(":memory:")
        try:
            connection.execute("CREATE VIRTUAL TABLE probe USING fts5(value)")
        finally:
            connection.close()
        return True
    except sqlite3.DatabaseError:
        return False


def _record(
    *, record_id: str, unit_id: str | None, path: str, kind: str, title: str, content: str,
    source_sha256: str | None = None, trust_class: str = "generated-non-authoritative"
) -> dict[str, Any]:
    payload = content.encode("utf-8")[:_MAX_RECORD_BYTES]
    decoded = payload.decode("utf-8", errors="ignore")
    identity = {
        "record_id": record_id,
        "unit_id": unit_id,
        "path": path,
        "kind": kind,
        "title": title,
        "content": decoded,
        "source_sha256": source_sha256 or hashlib.sha256(decoded.encode("utf-8")).hexdigest(),
        "trust_class": trust_class,
        "truncated": len(content.encode("utf-8")) > len(payload),
    }
    return {**identity, "record_digest": digest_value(identity)}


def compile_context_records(plan: Mapping[str, Any], reference_records: Sequence[Mapping[str, Any]] = ()) -> list[dict[str, Any]]:
    """Compile deterministic bounded records from one resolved plan."""

    records: list[dict[str, Any]] = []
    summary = {
        "goal": plan.get("goal"),
        "project_mode": plan.get("project_mode"),
        "profile_layers": plan.get("profile_layers", []),
        "autonomy": plan.get("autonomy"),
        "success_criteria": plan.get("success_criteria", []),
        "constraints": plan.get("constraints", []),
        "references": plan.get("references", []),
        "work_sources": plan.get("work_sources", []),
    }
    records.append(
        _record(
            record_id="plan:project",
            unit_id=None,
            path=".promin/docs/project-brief.json",
            kind="project-plan",
            title=str(plan.get("goal") or "project plan"),
            content=json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2),
        )
    )
    workspace = plan.get("workspace_map", {})
    for unit in workspace.get("units", []):
        if not isinstance(unit, Mapping):
            continue
        unit_id = str(unit.get("unit_id"))
        content = json.dumps(
            {
                "path": unit.get("path"),
                "kind": unit.get("kind"),
                "technologies": unit.get("technology_ids", []),
                "profiles": unit.get("profile_layers", []),
                "manifests": unit.get("manifests", []),
                "confidence": unit.get("confidence"),
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        records.append(
            _record(
                record_id=f"unit:{unit_id}",
                unit_id=unit_id,
                path=str(unit.get("path", ".")),
                kind="workspace-unit",
                title=f"{unit_id} {unit.get('kind', '')}",
                content=content,
            )
        )
    for raw in reference_records:
        if not isinstance(raw, Mapping):
            continue
        record_id = raw.get("record_id")
        path = raw.get("path")
        if not isinstance(record_id, str) or not isinstance(path, str):
            continue
        records.append(
            _record(
                record_id=record_id,
                unit_id=str(raw.get("unit_id")) if raw.get("unit_id") is not None else None,
                path=path,
                kind=str(raw.get("kind") or "reference-file"),
                title=str(raw.get("title") or Path(path).name),
                content=str(raw.get("content") or ""),
                source_sha256=str(raw.get("source_sha256")) if raw.get("source_sha256") else None,
                trust_class=str(raw.get("trust_class") or "untrusted-project-source"),
            )
        )
    # One owner per record ID; references replace older duplicates deterministically.
    deduplicated = {record["record_id"]: record for record in records}
    return [deduplicated[key] for key in sorted(deduplicated)]


def _build_sqlite(path: Path, records: Sequence[Mapping[str, Any]]) -> int:
    os.makedirs(filesystem_path(path.parent), exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    try:
        os.unlink(filesystem_path(temporary))
    except FileNotFoundError:
        pass
    connection = sqlite3.connect(sqlite_path(temporary))
    try:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute(
            "CREATE TABLE records (record_id TEXT PRIMARY KEY, unit_id TEXT, path TEXT NOT NULL, kind TEXT NOT NULL, title TEXT NOT NULL, content TEXT NOT NULL, source_sha256 TEXT NOT NULL, trust_class TEXT NOT NULL, record_digest TEXT NOT NULL) STRICT"
        )
        # Store document text once in `records`. FTS5 keeps only the inverted
        # index and resolves columns through the external-content table.
        connection.execute(
            "CREATE VIRTUAL TABLE records_fts USING fts5(path, title, content, content='records', content_rowid='rowid', tokenize='unicode61 remove_diacritics 2')"
        )
        rows = [
            (
                record["record_id"], record.get("unit_id"), record["path"], record["kind"],
                record["title"], record["content"], record["source_sha256"], record["trust_class"], record["record_digest"],
            )
            for record in records
        ]
        connection.executemany("INSERT INTO records VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", rows)
        connection.execute("INSERT INTO records_fts(records_fts) VALUES ('rebuild')")
        connection.execute("CREATE INDEX records_unit_path ON records(unit_id, path)")
        connection.execute("PRAGMA user_version=2")
        connection.commit()
    finally:
        connection.close()
    if os.stat(filesystem_path(temporary)).st_size > _MAX_INDEX_BYTES:
        try:
            os.unlink(filesystem_path(temporary))
        except FileNotFoundError:
            pass
        raise ContextIndexError("context projection exceeds alpha size budget")
    os.replace(filesystem_path(temporary), filesystem_path(path))
    return os.stat(filesystem_path(path)).st_size


def _build_jsonl(path: Path, records: Sequence[Mapping[str, Any]]) -> int:
    payload = b"".join(_json_bytes(record) for record in records)
    if len(payload) > _MAX_INDEX_BYTES:
        raise ContextIndexError("context fallback exceeds alpha size budget")
    _atomic_bytes(path, payload)
    return len(payload)


def sync_context_index(
    project_root: Path | str,
    plan: Mapping[str, Any],
    *,
    reference_records: Sequence[Mapping[str, Any]] = (),
    apply: bool = True,
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    records = compile_context_records(plan, reference_records)
    input_identity = {
        "plan_digest": plan.get("plan_digest"),
        "workspace_map_digest": plan.get("workspace_map", {}).get("workspace_map_digest"),
        "record_digests": [record["record_digest"] for record in records],
        "implementation": "python-context-adapter-v2-external-content",
        "documentation_snapshot_digest": (
            (_load_json(root / ".promin/cache/documentation/documentation-state.json") or {}).get(
                "documentation_snapshot_digest"
            )
        ),
    }
    input_digest = digest_value(input_identity)
    previous = _load_json(root / _STATE_PATH) or {}
    selected_backend = "sqlite-fts5" if _sqlite_fts5_available() else "jsonl-linear"
    current_path = root / (_DB_PATH if selected_backend == "sqlite-fts5" else _JSONL_PATH)
    if previous.get("input_digest") == input_digest and previous.get("backend") == selected_backend and current_path.is_file():
        return {
            "record_type": "ContextIndexSyncResult",
            "status": "current",
            "backend": selected_backend,
            "record_count": len(records),
            "input_digest": input_digest,
            "bytes": current_path.stat().st_size,
            "authority": False,
            "pass_credit": False,
        }
    if not apply:
        return {
            "record_type": "ContextIndexSyncResult",
            "status": "stale",
            "backend": selected_backend,
            "record_count": len(records),
            "input_digest": input_digest,
            "authority": False,
            "pass_credit": False,
        }
    if selected_backend == "sqlite-fts5":
        size = _build_sqlite(root / _DB_PATH, records)
        (root / _JSONL_PATH).unlink(missing_ok=True)
    else:
        size = _build_jsonl(root / _JSONL_PATH, records)
        (root / _DB_PATH).unlink(missing_ok=True)
    state_identity = {
        "record_type": "ContextIndexState",
        "backend": selected_backend,
        "input_digest": input_digest,
        "record_count": len(records),
        "plan_digest": plan.get("plan_digest"),
        "workspace_map_digest": plan.get("workspace_map", {}).get("workspace_map_digest"),
        "bytes": size,
        "documentation_snapshot_digest": input_identity.get("documentation_snapshot_digest"),
        "rebuildable": True,
        "authoritative": False,
        "pass_credit": False,
    }
    state = {**state_identity, "state_digest": digest_value(state_identity)}
    _atomic_bytes(root / _STATE_PATH, _json_bytes(state))
    return {"record_type": "ContextIndexSyncResult", "status": "updated", **state}


def context_index_status(project_root: Path | str, plan: Mapping[str, Any] | None = None) -> dict[str, Any]:
    root = Path(project_root).resolve()
    state = _load_json(root / _STATE_PATH)
    if state is None:
        return {"record_type": "ContextIndexStatus", "status": "missing", "repair_command": "promin doctor --repair", "authority": False, "pass_credit": False}
    path = root / (_DB_PATH if state.get("backend") == "sqlite-fts5" else _JSONL_PATH)
    stale = not path.is_file()
    if plan is not None:
        documentation = _load_json(root / ".promin/cache/documentation/documentation-state.json") or {}
        if (
            state.get("input_digest") is None
            or state.get("plan_digest") != plan.get("plan_digest")
            or state.get("workspace_map_digest") != plan.get("workspace_map", {}).get("workspace_map_digest")
            or state.get("documentation_snapshot_digest") != documentation.get("documentation_snapshot_digest")
        ):
            stale = True
    return {
        "record_type": "ContextIndexStatus",
        "status": "stale" if stale else "current",
        "backend": state.get("backend"),
        "record_count": state.get("record_count"),
        "bytes": path.stat().st_size if path.is_file() else 0,
        "repair_command": "promin doctor --repair",
        "authority": False,
        "pass_credit": False,
    }


def _fts_expression(query: str) -> str:
    tokens = [token for token in _TOKEN_RE.findall(query) if token.strip("./:@+-")]
    if not tokens:
        return ""
    # Quoted prefix terms avoid FTS operator injection while retaining useful recall.
    return " OR ".join('"' + token.replace('"', '""') + '"*' for token in tokens[:12])


def _rows_sqlite(path: Path, query: str, unit_id: str | None, limit: int) -> list[dict[str, Any]]:
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    try:
        if unit_id:
            exact = connection.execute(
                "SELECT record_id, unit_id, path, kind, title, content, source_sha256, trust_class, record_digest FROM records WHERE (record_id=? OR path=?) AND unit_id=? ORDER BY record_id LIMIT ?",
                (query, query, unit_id, limit),
            ).fetchall()
        else:
            exact = connection.execute(
                "SELECT record_id, unit_id, path, kind, title, content, source_sha256, trust_class, record_digest FROM records WHERE record_id=? OR path=? ORDER BY record_id LIMIT ?",
                (query, query, limit),
            ).fetchall()
        if exact:
            return [dict(row) | {"rank": 0.0, "match_kind": "exact"} for row in exact]
        expression = _fts_expression(query)
        if not expression:
            sql = "SELECT record_id, unit_id, path, kind, title, content, source_sha256, trust_class, record_digest FROM records"
            params: list[Any] = []
            if unit_id:
                sql += " WHERE unit_id=?"
                params.append(unit_id)
            sql += " ORDER BY kind, path, record_id LIMIT ?"
            params.append(limit)
            return [dict(row) | {"rank": None, "match_kind": "browse"} for row in connection.execute(sql, params)]
        sql = (
            "SELECT r.record_id, r.unit_id, r.path, r.kind, r.title, r.content, r.source_sha256, r.trust_class, r.record_digest, bm25(records_fts, 0.3, 1.2, 1.0) AS rank "
            "FROM records_fts JOIN records r ON r.rowid=records_fts.rowid WHERE records_fts MATCH ?"
        )
        params = [expression]
        if unit_id:
            sql += " AND r.unit_id=?"
            params.append(unit_id)
        sql += " ORDER BY rank, r.path, r.record_id LIMIT ?"
        params.append(limit)
        return [dict(row) | {"match_kind": "fts"} for row in connection.execute(sql, params)]
    finally:
        connection.close()


def _rows_jsonl(path: Path, query: str, unit_id: str | None, limit: int) -> list[dict[str, Any]]:
    terms = [item.casefold() for item in _TOKEN_RE.findall(query)[:12]]
    scored: list[tuple[int, str, dict[str, Any]]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if unit_id and record.get("unit_id") != unit_id:
                continue
            haystack = " ".join(str(record.get(key, "")) for key in ("record_id", "path", "title", "content")).casefold()
            score = sum(haystack.count(term) for term in terms) if terms else 1
            if score:
                scored.append((-score, str(record.get("path", "")), record))
    scored.sort(key=lambda item: (item[0], item[1], str(item[2].get("record_id", ""))))
    return [record | {"rank": -score, "match_kind": "linear"} for score, _, record in scored[:limit]]


def query_context(
    project_root: Path | str,
    query: str = "",
    *,
    unit_id: str | None = None,
    limit: int = _DEFAULT_LIMIT,
    max_bytes: int = _DEFAULT_RESULT_BYTES,
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    state = _load_json(root / _STATE_PATH)
    if state is None:
        raise ContextIndexError("context index is missing; run promin doctor --repair")
    backend = str(state.get("backend"))
    path = root / (_DB_PATH if backend == "sqlite-fts5" else _JSONL_PATH)
    if not path.is_file():
        raise ContextIndexError("context index payload is missing; run promin doctor --repair")
    bounded_limit = max(1, min(int(limit), 64))
    bounded_bytes = max(1024, min(int(max_bytes), 64 * 1024))
    rows = _rows_sqlite(path, query, unit_id, bounded_limit * 2) if backend == "sqlite-fts5" else _rows_jsonl(path, query, unit_id, bounded_limit * 2)
    results: list[dict[str, Any]] = []
    used = 0
    truncated = False
    for row in rows:
        content = str(row.get("content", ""))
        snippet = content if len(content.encode("utf-8")) <= 2048 else content.encode("utf-8")[:2048].decode("utf-8", errors="ignore") + "…"
        item = {
            "record_id": row.get("record_id"),
            "unit_id": row.get("unit_id"),
            "path": row.get("path"),
            "kind": row.get("kind"),
            "title": row.get("title"),
            "trust_class": row.get("trust_class", "untrusted-project-source"),
            "snippet": snippet,
            "rank": row.get("rank"),
            "match_kind": row.get("match_kind"),
        }
        size = len(_json_bytes(item))
        if results and (used + size > bounded_bytes or len(results) >= bounded_limit):
            truncated = True
            break
        results.append(item)
        used += size
    retrieval_tokens = estimate_tokens(json.dumps(results, ensure_ascii=False))
    policy = _load_json(root / ".promin/docs/context-policy.json") or {}
    startup_tokens = int(policy.get("agent_entry_estimated_tokens") or 0)
    cost = context_cost_model(
        startup_tokens=startup_tokens,
        query_tokens=retrieval_tokens,
        query_probability=0.7,
    )
    identity = {
        "record_type": "ContextQueryResult",
        "query": query,
        "unit_id": unit_id,
        "backend": backend,
        "results": results,
        "result_count": len(results),
        "result_bytes": used,
        "estimated_tokens": retrieval_tokens,
        "context_cost": cost,
        "truncated": truncated or len(rows) > len(results),
        "continuation_hint": "refine the query or select a unit" if truncated or len(rows) > len(results) else None,
        "authority": False,
        "pass_credit": False,
    }
    return {**identity, "query_digest": digest_value(identity)}


def context_cost_model(*, startup_tokens: int, query_tokens: int, query_probability: float = 0.7) -> dict[str, Any]:
    probability = max(0.0, min(float(query_probability), 1.0))
    expected = startup_tokens + probability * query_tokens
    return {
        "record_type": "ContextCostModel",
        "formula": "always_loaded + P(query) * retrieved",
        "startup_tokens": startup_tokens,
        "query_tokens": query_tokens,
        "query_probability": probability,
        "expected_tokens_per_session": round(expected, 2),
        "metric_kind": "modeled-not-tokenizer-measured",
        "authority": False,
        "pass_credit": False,
    }
